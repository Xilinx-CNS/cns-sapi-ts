/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_close Buffers release after socket closing
 *
 * @objective  Check that buffers are released after socket closing
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_close"

#include "sockapi-test.h"
#include "template.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_iut_aux = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    rpc_onload_template_handle  handler2 = 0;
    rpc_onload_template_handle *handlers = NULL;
    int                         handlers_num = 50;
    closing_way                 way;
    rpc_iovec *iov    = NULL;
    int        iut_s1  = -1;
    int        tst_s1  = -1;
    int        iut_s2  = -1;
    int        tst_s2  = -1;
    char      *iovbuf  = NULL;
    char      *rcvbuf = NULL;
    int        iovcnt;
    int        total;
    int        count = 0;
    int        i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_ENUM_PARAM(way, CLOSING_WAY);

    sockts_kill_zombie_stacks(pco_iut);

    rcvbuf = te_calloc_fill(1, total, 0);
    handlers = te_calloc_fill(handlers_num, sizeof(*handlers), 0);

    if (way == CL_EXIT || way == CL_KILL)
    {
        CHECK_RC(tapi_sh_env_set(pco_iut, "EF_NAME", "foo", FALSE, TRUE));
        rcf_rpc_server_fork_exec(pco_iut, "pco_iut_aux", &pco_iut_aux);
    }
    else
        pco_iut_aux = pco_iut;

    TEST_STEP("Create two TCP connections between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s1, &tst_s1);
    TAPI_SET_NEW_PORT(pco_iut, iut_addr);
    TAPI_SET_NEW_PORT(pco_tst, tst_addr);
    GEN_CONNECTION(pco_iut_aux, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s2, &tst_s2);

    TEST_STEP("Initialize a number @p iovcnt vectors with total payload length "
              "@p total.");
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Allocate maximum possible templates number on a one of IUT "
              "sockets.");
    rc = 0;
    for (i = 0; rc == 0; i++)
    {
        if (i == handlers_num)
        {
            handlers_num *= 2;
            handlers = realloc(handlers, handlers_num * sizeof(*handlers));
            memset(handlers + handlers_num / 2, 0,
                   handlers_num / 2 * sizeof(*handlers));
        }

        RPC_AWAIT_IUT_ERROR(pco_iut_aux);
        rc = rpc_onload_msg_template_alloc(pco_iut_aux, iut_s2, iov, iovcnt,
                                           handlers + i, 0);
        if (rc == 0)
            count += total;
    }

    if (RPC_ERRNO(pco_iut_aux) != RPC_ENOMEM)
        TEST_VERDICT("Template allocation failed with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut_aux)));

    TEST_STEP("Make sure that Onload template can not be allocated on the second "
              "socket because all PIO buffers are busy by the first socket, see "
              "SF bug 45714 for details.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_onload_msg_template_alloc(pco_iut, iut_s1, iov, iovcnt,
                                       &handler2, 0);
    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_ENOMEM)
        TEST_VERDICT("Template allocation on the second socket succeed or "
                     "failed with unexpected errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));

    TEST_STEP("Close socket by one of ways in dependence on @p way.");
    sockts_close(pco_iut_aux, pco_iut, &iut_s2, way);
    if (way == CL_EXIT || way == CL_KILL)
        pco_iut_aux = NULL;
    RPC_CLOSE(pco_tst, tst_s2);

    /** It is possible that the next template_alloc() is called before
     * the connection is completely closed, i.e. last FIN/ACK is not
     * received or sent. The buffers freeing does not happen, while
     * connection is not closed because retransmits can be required. So
     * delay is necessary to make sure that the connection is closed. */
    TAPI_WAIT_NETWORK;

    free(iovbuf);
    release_iovec(iov, iovcnt);
    iov = init_iovec(iovcnt, total, &iovbuf);

    TEST_STEP("Try to allocate new template on the second socket, it should be "
              "succeeded now.");
    rpc_onload_msg_template_alloc(pco_iut, iut_s1, iov, iovcnt,
                                  &handler2, 0);

    TEST_STEP("Send the template from the second socket.");
    rc = rpc_onload_msg_template_update(pco_iut, iut_s1, handler2, NULL, 0,
                                        RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    TEST_STEP("Read and verify the template data.");
    if (rpc_recv(pco_tst, tst_s1, rcvbuf, total, 0) != total)
        TEST_VERDICT("Read wrong amount of data with template.");
    if (memcmp(rcvbuf, iovbuf, total) != 0)
        TEST_VERDICT("Send and received template data are not equal");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_iut_aux, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    free(rcvbuf);
    free(iovbuf);
    free(handlers);
    release_iovec(iov, iovcnt);

    TEST_END;
}
