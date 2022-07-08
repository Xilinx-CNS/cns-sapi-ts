/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-broadcast_no_fragment Broadcast datagrams should not be fragmented
 *
 * @objective Check that kernel does't allow to fragment broadcast
 *            datagrams.
 *
 * @type conformance
 *
 * @reference @ref STEVENS 18.4
 *
 * @note Broadcasting is supported for only datagram sockets and only on 
 *       networks that support the concept of a broadcast messages.
 * 
 * @param pco_iut           PCO on IUT
 * @param pco_tst           PCO on TESTER
 * @param iut_bcast_addr    Broadcast address assigned on @p pco_iut
 *                          interface connected to the same subnetwork 
 *                          as @p pco_tst
 *
 * @par Test sequence:
 *
 * -# Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut;
 * -# Retrieve current interface MTU;
 * -# Create a buffer @p tx_buf of (MTU * 2) bytes;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b getsockopt() on @p iut_s socket to get initial value of the
 *    @c SO_BROADCAST option;
 * -# Check that the function returns @c 0 and the option is disabled;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b setsockopt() on @p iut_s with @c SO_BROADCAST enabling
 *    this option;
 * -# Call @b sendto() on @p iut_s to send @p tx_buf buffer specifying
 *    @p iut_bcast_addr as the value of @a address parameter;
 * -# Check that the function returns @c -1 and sets @b errno to 
 *    @c EMSGSIZE;
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Close @p iut_s socket and delete allocated resources.
 * 
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/broadcast_no_fragment"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"

int
main(int argc, char *argv[])
{

    rcf_rpc_server            *pco_iut = NULL;
    int                        iut_s = -1;

    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *bcast_addr;

    void                      *tx_buf = NULL;
    size_t                     tx_buflen;

    int                        saved_mtu;
    int                        opt_val;

    cfg_val_type               type = CVT_INTEGER;
    const struct if_nameindex *iut_if;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, bcast_addr);
    TEST_GET_IF(iut_if);

    /* Get current if MTU */
    rc = cfg_get_instance_fmt(&type, (void *)&saved_mtu,
                              "/agent:%s/interface:%s/mtu:",
                              pco_iut->ta, iut_if->if_name);
    if (rc != 0)
    {
        TEST_FAIL("Failed to get MTU of %s: %X", iut_if->if_name, rc);
    }
    RING("Current MTU of %s is %d", iut_if->if_name, saved_mtu);

    tx_buflen = saved_mtu * 2;
    tx_buf = te_make_buf_by_len(tx_buflen);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(bcast_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
    if (opt_val == 0)
    {
        RING("SO_BROADCAST socket option is disabled by default");

        opt_val = 1;
        rpc_setsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
        opt_val = 0;
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_BROADCAST, &opt_val);
        if (opt_val == 0)
        {
            TEST_FAIL("The value of SO_BROADCAST socket option is not "
                      "updated by setsockopt() function");
        }
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, tx_buf, tx_buflen, 0, bcast_addr);
    if (rc != -1)
    {
        TEST_VERDICT("sendto() returns positive number of sending datagram "
                     "towards broadcast address on socket with MTU less "
                     "than datagram size, but it is expected to return -1");
    }
    CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE,
            "sendto() returns -1 sending datagram towards broadcast "
            "address on socket with MTU less than datagram size");

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(tx_buf);

    TEST_END;
}
 
