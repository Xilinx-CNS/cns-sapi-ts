/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 * 
 * $Id$
 */

/** @page sockopts-errind_conn_disable SO_DGRAM_ERRIND on connected socket after setsockopt
 *
 * @objective Check absence of error indication on connected socket after
 *            disabling of SO_DGRAM_ERRIND option.
 *
 * @type conformance
 *
 * @reference @ref STEVENS, setcion 7.5
 *
 * @param pco_iut       PCO on IUT
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket on @p pco_iut of type @c SOCK_DGRAM;
 * -# Call @b getsockopt(@c SO_DGRAM_ERRIND) to check the defaul value of
 *    the option;
 * -# Connect @p iut_s socket to @p dst_addr;
 * -# Call @b setsockopt(@c SO_DGRAM_ERRIND) to set option value to
 *    @c 0;
 * -# Call @b send() on @p iut_s socket and sleep a while;
 * -# Call @b getsockopt(@c SO_ERROR) and check that option value is @c 0;
 * -# Call @b send() once again to check that it doesn't return error;
 * -# Close @p iut_s socket.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/errind_conn_disable"

#include "sockapi-test.h"

#define DATA_BULK 1024

static uint8_t buf[DATA_BULK]; /**< Auxiliary buffer */

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;

    const struct sockaddr *tst_addr = NULL;

    int      opt_val;

    int      iut_s = -1;

    /* Preambule */
    TEST_START;
  
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_tst, tst_addr);

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

    rpc_connect(pco_iut, iut_s, tst_addr);
    opt_val = 0;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_DGRAM_ERRIND, &opt_val);

    RPC_SEND(rc, pco_iut, iut_s, buf, DATA_BULK, 0);

    SLEEP(1);

    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
        TEST_VERDICT("iut_s socket still indicates errors");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_send(pco_iut, iut_s, buf, DATA_BULK, 0);
    if (rc != DATA_BULK)
        TEST_VERDICT("Second send() returned %d", rc);
    
    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    TEST_END;
}
