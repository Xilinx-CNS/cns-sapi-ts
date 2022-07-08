/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-send_dontwait Support of MSG_DONTWAIT flag for sending
 *
 * @objective Check support of @c MSG_DONTWAIT flag for send operations.
 *
 * @type conformance
 *
 * @reference @ref STEVENS section 13.3
 *
 * @param pco_iut   PCO with IUT
 * @param iut_s     Connected stream socket on @p pco_iut
 * @param func      Function to be used in the test to send data
 *                  (@b send(), @b sendto(), @b sendmsg() or @b sendmmsg())
 *
 * @pre Sum of sender and receiver buffers of the connections less
 *      than 100M byte.
 *
 * -# Send 4K byte of data in socket @p sock using @p func function
 *    with @c MSG_DONTWAIT flag.
 * -# If @p func function sent some data (i.e. return value is greater
 *    than 0):
 *      - If total size of sent data is greater than 100M, log error
 *        and exit from test with failure status.
 *      - Otherwise reset number of got @p again counter and go to
 *        the first step.
 * -# If @p func returned @c 0, log error and exit from test with
 *    failure status.
 * -# If @p func returned @c -1, check that @b errno is equal to
 *    @c EWOULDBLOCK or @c EAGAIN and increment @p again counter.
 * -# If @p again counter is less that 5, then go to the first step,
 *    else exit from the test with success status.
 *
 * @post Buffers in direction from tested socket to its pair is filled in.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sendrecv/send_dontwait"

#include "sockapi-test.h"
#include "rpc_sendrecv.h"
#include "iomux.h"

/** Maximum number of send tries */
#define MAX_TRIES           ((100UL << 20) / SOCKTS_BUF_SZ)

/** Number of EAGAIN returns required one by one */
#define TST_AGAIN_NEEDED    5U


static char tx_buf[SOCKTS_BUF_SZ];

int
main(int argc, char *argv[])
{
    /* Environment variables */
    rpc_send_f func;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    /* Auxiliary variables */
    int     iut_s = -1;
    int     tst_s = -1;
    
    unsigned int    tries;
    unsigned int    again;
    ssize_t         len;
    te_bool         done;
    
    TEST_START;
    
    /* Prepare sockets */
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SEND_FUNC(func);
    
    GEN_CONNECTION_FAKE(pco_tst, pco_iut, RPC_SOCK_STREAM, RPC_IPPROTO_TCP,
                        tst_addr, iut_addr, &tst_s, &iut_s);
    
    te_fill_buf(tx_buf, sizeof(tx_buf));

    if (func == rpc_send_func_od_send || func == rpc_send_func_od_send_raw)
        sockts_extend_cong_window(pco_iut, iut_s, pco_tst, tst_s);


    for (again = 0, tries = 0; tries < MAX_TRIES; tries++)
    {
        pco_iut->op = RCF_RPC_CALL;
        func(pco_iut, iut_s, tx_buf, SOCKTS_BUF_SZ, RPC_MSG_DONTWAIT);

        CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
        if (!done)
        {
            MSLEEP(100);
            CHECK_RC(rcf_rpc_server_is_op_done(pco_iut, &done));
            if (!done)
                TEST_VERDICT("Send function with MSG_DONTWAIT "
                             "flag blocks");
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        len = func(pco_iut, iut_s, tx_buf, SOCKTS_BUF_SZ, RPC_MSG_DONTWAIT);

        if (len < 0)
        {
            if (tries == 0)
            {
                TEST_VERDICT("The first send operation failed with %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
            else if (pco_iut->_errno == RPC_EWOULDBLOCK || 
                     pco_iut->_errno == RPC_EAGAIN)
            {
                again++;
                if (again < TST_AGAIN_NEEDED)
                {
                    /* Sleep to allow TCP to push the data */
                    MSLEEP(100);
                }
                else
                {
                    TEST_SUCCESS;
                }
            }
            else
            {
                TEST_VERDICT("Send operation failed unexpectedly with %s",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        else if (len == 0)
        {
            TEST_FAIL("Send function %s() must not return 0 in any case",
                      rpc_send_func_name(func));
        }
        else
        {
            again = 0;
        }
    }
    
    TEST_FAIL("Cannot send enough data to block the sending");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    CHECK_CLEAR_TRANSPARENT(iut_addr, pco_tst, tst_addr);

    TEST_END;
}
