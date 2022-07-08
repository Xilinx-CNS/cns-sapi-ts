/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-errind_conn_not_conn Behaviour of SO_DGRAM_ERRIND option value after connect
 *
 * @objective Check infuence of connect, reconnect, disconnect on value of
 *            @c SO_DGRAM_ERRIND socket option.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket on @p pco_iut of type @c SOCK_DGRAM;
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) and check that option value
 *    is @c 0;
 * -# Call @b connect() on @p iut_s socket;
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) and check that option is set
 *    on;
 * -# Call @b setsockopt(@c SO_DGRAM_ERRIND) to set off @c SO_DGRAM_ERRIND
 *    socket option;
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) and check that option is set
 *    off;
 * -# Call @b connect() once again to connect @p iut_s socket to another
 *    address;
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) and check that option is set
 *    on;
 * -# Call @b connect() with family @c AF_UNSPEC (disconnect);
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) and check that option value is
 *    @c 0 now.
 * -# Close @p iut_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/errind_conn_not_conn"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    struct sockaddr_in     unspec_addr;
    socklen_t              unspec_addr_len = sizeof(unspec_addr);

    uint16_t      opt_val;

    int      iut_s = -1;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    memset(&unspec_addr, 0, unspec_addr_len);
    unspec_addr.sin_family = AF_UNSPEC;

    iut_s = rpc_socket(pco_iut, RPC_AF_INET, 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_getsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    if (rc == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ENOPROTOOPT, 
                        "getsockopt(SO_DGRAM_ERRIND) returned -1, but");
        TEST_VERDICT("getsockopt(SO_DGRAM_ERRIND) returned -1 and set "
                     "errno to ENOPROTOOPT");
    }
    if (opt_val != 0)
        TEST_VERDICT("Default value of SO_DGRAM_ERRIND is %d", opt_val);
    
    rpc_connect(pco_iut, iut_s, iut_addr);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    if (opt_val == 0)
        RING_VERDICT("SO_DGRAM_ERRIND option value is 0 after connect()");
    
    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    if (opt_val != 0)
        RING_VERDICT("setsockopt(SO_DGRAM_ERRIND) can't set option value "
                     "to 0");

    rpc_connect(pco_iut, iut_s, tst_addr);
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    if (opt_val == 0)
        RING_VERDICT("SO_DGRAM_ERRIND option value is 0 after second "
                     "connect()");

    rpc_connect(pco_iut, iut_s, CONST_SA(&unspec_addr));
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);
    if (opt_val != 0)
        RING_VERDICT("SO_DGRAM_ERRIND option value is %d after disconnect",
                     opt_val);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
