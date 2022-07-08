/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Interoperability of L5 stack with system stack.
 *
 * $Id$
 */

/** @page level5-interop-send_only Usage of system transmit calls with L5 socket
 *
 * @objective Check that it is possible to use system provided @b write()
 *            @b writev() functions on L5 socket.
 *
 * @type interop
 *
 * @param sock_type    Socket type used in the test
 * @param send_func    Send function used in the test
 * @param iut_serv     Whether @p iut_s should be obtained on the server
 *                     side or as a connection client
 *                     (only for @c SOCK_STREAM @p sock_type)
 * @param sys_first    Wheter a first piece of data should be sent via
 *                     system provided @p send_func function or via L5
 * @param delayed_ack  Wheter to send ACK for each segment, or 
 *                     only after sending two segments 
 *                     (only for @c SOCK_STREAM @p sock_type)
 *
 * @par Test sequence:
 * -# This step requires all necessary symbols (@b socket(), 
 *    @b connect(), etc.) to be resolved with L5 library.
 *    Create a connection of type @p sock_type between @p pco_iut and 
 *    @p pco_tst. As the result of this operation we will have two
 *    sockets: @p iut_s and @p tst_s.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p sock_type is @c SOCK_STREAM and @p delayed_ack is @c TRUE,
 *    add static ARP entry on @p pco_tst for @p iut_addr so that 
 *    it has fake MAC address (that is necessary to prevent TCP ACK
 *    from @p tst_s just after the first segment comes to @p tst_s).
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# On @p pco_iut resolve @p send_func depending on @p sys_first
 *    parameter:
 *    - @p sys_first - @c TRUE: Resolve with system (libc) library;
 *    - @p sys_first - @c FALSE: Resolev with L5 library.
 *    .
 * -# Call @p send_func function on @p iut_s socket;
 * -# If @p delayed_ack is @c FALSE, check that the data sent on 
 *    the previous step successfully delivered to @p tst_s socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# On @p pco_iut resolve @p send_func depending on @p sys_first
 *    parameter:
 *    - @p sys_first - @c TRUE: Resolev with L5 library;
 *    - @p sys_first - @c FALSE: Resolve with system (libc) library.
 *    .
 * -# If @p delayed_ack is @c TRUE, delete static ARP entry;
 * -# Check that the data sent on the previous step(s) successfully
 *    delivered to @p tst_s socket.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close created sockets.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/interop/send_only"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

#define TST_VEC  3
#define BUF_LEN  169

#define CHECK_FUNCTION(func_name_, params_...) \
    do {                                                      \
        if (strcmp(send_func, #func_name_) == 0)              \
        {                                                     \
            unknown_func = FALSE;                             \
            rc = rpc_ ## func_name_(pco_iut, iut_s, params_); \
        }                                                     \
    } while (0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *serv_pco;
    rcf_rpc_server *clnt_pco;
    int             iut_s = -1;
    int             tst_s = -1;
    int            *serv_side_s;
    int            *clnt_side_s;
    
    const struct if_nameindex *tst_if;

    rpc_socket_type        sock_type;
    te_bool                unknown_func = TRUE;
    const char            *send_func;
    te_bool                iut_serv = TRUE;
    te_bool                sys_first = FALSE;
    te_bool                delayed_ack = FALSE;
    te_bool                tst_arp_added = FALSE;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *serv_addr;
    const struct sockaddr  *clnt_addr;
    const void            *alien_mac = NULL;
    
    unsigned int      i;
    void             *tx_buf = NULL;
    struct rpc_iovec  tx_vector[TST_VEC];
    rpc_msghdr        tx_msghdr;
    size_t            buf_len = BUF_LEN;
    size_t            tx_bytes = 0;
    uint8_t           rx_buf[BUF_LEN * TST_VEC * 2] = {};


    /*
     * Test preambule.
     */
    TEST_START;

    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(sys_first);
    TEST_GET_STRING_PARAM(send_func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(tst_if);

    if (sock_type == RPC_SOCK_STREAM)
    {
        TEST_GET_LINK_ADDR(alien_mac);
        TEST_GET_BOOL_PARAM(iut_serv);
        TEST_GET_BOOL_PARAM(delayed_ack);
    }

    if (iut_serv)
    {
        serv_pco = pco_iut;
        clnt_pco = pco_tst;
        serv_side_s = &iut_s;
        clnt_side_s = &tst_s;
        serv_addr = iut_addr;
        clnt_addr = tst_addr;
    }
    else
    {
        serv_pco = pco_tst;
        clnt_pco = pco_iut;
        serv_side_s = &tst_s;
        clnt_side_s = &iut_s;
        serv_addr = tst_addr;
        clnt_addr = iut_addr;
    }
    
    GEN_CONNECTION(serv_pco, clnt_pco, sock_type, RPC_PROTO_DEF,
                   serv_addr, clnt_addr, serv_side_s, clnt_side_s);

    /* Prepare data to transmit by means of: */
    /* write(), send(), sendto() */
    tx_buf = te_make_buf_by_len(buf_len);

    /* writev(), all of the vector elements are the same buffer */
    for (i = 0; i < TST_VEC; i++)
    {
        tx_vector[i].iov_base = tx_buf;
        tx_vector[i].iov_len = tx_vector[i].iov_rlen = buf_len;
    }

    /* sendmsg() */
    memset(&tx_msghdr, 0, sizeof(tx_msghdr));
    tx_msghdr.msg_iovlen = tx_msghdr.msg_riovlen = TST_VEC;
    tx_msghdr.msg_iov = tx_vector;
    tx_msghdr.msg_name = (void *)tst_addr;

    /* Start main part of the test */

    if (delayed_ack)
    {
        /* Add fake MAC to protect from delivering ACKs */
        CHECK_RC(tapi_update_arp(pco_tst->ta, tst_if->if_name, NULL, NULL,
                                 iut_addr, CVT_HW_ADDR(alien_mac), TRUE));
        tst_arp_added = TRUE;
    }

    for (i = 0; i < 2; i++)
    {
        /* Prepare library name that should be used in symbol resolving */
        if ((sys_first && i == 0) || (!sys_first && i == 1))
            pco_iut->use_libc_once = TRUE;

        CHECK_FUNCTION(write, tx_buf, buf_len);
        CHECK_FUNCTION(send, tx_buf, buf_len, 0);
        CHECK_FUNCTION(sendto, tx_buf, buf_len, 0, NULL);
        CHECK_FUNCTION(writev, tx_vector, TST_VEC);
        CHECK_FUNCTION(sendmsg, &tx_msghdr, 0);

        if (unknown_func)
            TEST_FAIL("Unknown 'send_func' parameter %s", send_func);

        /* Calculate the number of bytes sent */
        tx_bytes = buf_len;
        if (strcmp(send_func, "writev") == 0 ||
            strcmp(send_func, "sendmsg") == 0)
        {
            tx_bytes *= TST_VEC;
        }
        
        if (rc != (int)tx_bytes)
        {
            TEST_FAIL("%s() returns %d, but expected to return %d",
                      send_func, rc, tx_bytes);
        }

        if (!delayed_ack)
        {
            /* Immeidiately read out the data. */
            rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_bytes, 0);
            if (rc != (int)tx_bytes)
                TEST_FAIL("Expected to receive %d bytes, "
                          "but we receive only %d bytes",
                          (int)tx_bytes, rc);
        }
    }

    if (delayed_ack)
    {
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, iut_addr);
        tst_arp_added = FALSE;
        
        /* 
         * Now try to read out the whole part of data.
         * Here we read rx_buf as it can fit exacty two tx_buf buffers.
         */
        assert(buf_len * TST_VEC * 2 == sizeof(rx_buf));

        rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_bytes * 2, 0);
        if (rc != (int)tx_bytes * 2)
        {
            if (rc != (int)tx_bytes)
                TEST_FAIL("Expected to receive at least %d bytes, "
                          "but we receive only %d bytes",
                          (int)tx_bytes, rc);
            rc = rpc_recv(pco_tst, tst_s, rx_buf, tx_bytes * 2, 0);
            if (rc != (int)tx_bytes)
                TEST_FAIL("Expected to receive exactly %d bytes, "
                          "but we receive only %d bytes",
                          (int)tx_bytes, rc);
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (tst_arp_added)
        tapi_cfg_del_neigh_entry(pco_tst->ta, tst_if->if_name, iut_addr);

    TEST_END;
}
