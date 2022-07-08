/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-connect_influence_sendto Influence on sendto() of connect() called on socket of the SOCK_DGRAM type
 *
 * @objective Check a possibility of data delivery by means of sendto() on
 *            @c SOCKET_DGRAM type socket if @c connect() has been applied.
 *
 *
 * @type Conformance, compatibility
 *
 * @param env           Private set of environments:
 *                      - env1: similar to @ref arg_types_env_peer2peer, but
 *                      there is @p tst2_addr = @p tst1_addr.
 *                      - env2 the same as env1 but with IPv6 addresses
 *                      - env3 the same as env1 but @p tst2_addr and @p tst1_addr two
 *                      different unicast addresses.
 *                      - env4 the same as env3 but with IPv6 addresses
 * @param to            Kind of destination address used in sendto() call:
 *                      - itreate with @p env1 and @p env2:
 *                          - null: pass @c NULL;
 *                          - same: exactly the same address where socket was
 *                                  connected to;
 *                      - itreate with @p env3 and @p env4:
 *                          - same_port: the same port the socket connected to
 *                                       but different network address;
 *                          - same_addr: the same network address the socket
 *                                       connected to but different port;
 *                          - another: different destination address
 *
 * @par Scenario:
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/connect_influence_sendto"

#include "sockapi-test.h"

#define TST_BUF_LEN     1000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst1_addr = NULL;
    const struct sockaddr  *tst2_addr = NULL;

    const char             *to = NULL;

    const char             *descr = NULL;

    int                     iut_s = -1;
    int                     tst1_s = -1;
    int                     tst2_s = -1;

    void                   *iut_buf = NULL;
    size_t                  iut_buflen;
    void                   *tst_buf = NULL;
    size_t                  tst_buflen;

    ssize_t                 rcv_tst;
    ssize_t                 snt_iut;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst1_addr);
    TEST_GET_ADDR(pco_tst, tst2_addr);
    TEST_GET_STRING_PARAM(to);

    TEST_STEP("Prepare @p tst2_addr on the base of @p tst1_addr in accordance"
              "with @p to parameter specification.");
    if (strcmp(to, "null") == 0)
    {
        tst2_addr = NULL;
        descr = "NULL destination address";
    }
    else if (strcmp(to, "same") == 0)
    {
        tst2_addr = tst1_addr;
        descr = "the same destination address the socket connected to";
    }
    else if (strcmp(to, "same_port") == 0)
    {
        assert(tst1_addr->sa_family == tst2_addr->sa_family);
        te_sockaddr_set_port(SA(tst2_addr),
                             te_sockaddr_get_port(tst1_addr));
        descr = "the same port the socket connected to but different "
                "network address";
    }
    else if (strcmp(to, "same_addr") == 0)
    {
        assert(tst1_addr->sa_family == tst2_addr->sa_family);
        te_sockaddr_set_netaddr(SA(tst2_addr),
                                te_sockaddr_get_netaddr(tst1_addr));
        descr = "the same network address the socket connected to but "
                "different port";
    }
    else if (strcmp(to, "another") == 0)
    {
        /* Nothing equal */
        descr = "different destination address";
    }
    else
    {
        TEST_FAIL("Unsupported 'to' parameter value '%s'", to);
    }

    TEST_STEP("Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut and"
              "bind it to @p iut_addr.");
    CHECK_NOT_NULL(iut_buf = sockts_make_buf_dgram(&iut_buflen));
    tst_buf = te_make_buf_min(iut_buflen, &tst_buflen);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_iut, iut_s, iut_addr);

    TEST_STEP("Create @p tst1_s socket of type @c SOCK_DGRAM on @p pco_tst and"
              "bind it to @p tst1_addr.");
    tst1_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst1_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst1_s, tst1_addr);

    TEST_STEP("If @p to is neither @c null nor @c same, create @p tst2_s socket"
              "of type @c SOCK_DGRAM on @p pco_tst and bind it to appropriate"
              "address @p tst2_addr.");
    if (tst2_addr != NULL && tst2_addr != tst1_addr)
    {
        tst2_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst2_addr), 
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_bind(pco_tst, tst2_s, tst2_addr);
    }

    TEST_STEP("Call @b rpc_sendto() on @p iut_s socket with @p tst1_addr as"
              "destination. Check that it sends all the data. Receive data"
              "on @p tst1_s socket. Match sent and received data.");
    snt_iut = rpc_sendto(pco_iut, iut_s, iut_buf, iut_buflen, 0, tst1_addr);

    rcv_tst = rpc_recv(pco_tst, tst1_s, tst_buf, tst_buflen, 0);
    if (rcv_tst != snt_iut)
        TEST_FAIL("number of bytes received %d while %d sent",
                  rcv_tst, snt_iut);
    if (memcmp(tst_buf, iut_buf, iut_buflen) != 0)
        TEST_FAIL("'tst_s' data received is corrupted");

    TEST_STEP("Call @b rpc_sendto() on @p iut_s socket with @p tst2_addr as"
              "destination. If @p to is @c null, the function has to returns"
              "@c -1 with @c EDESTADDRREQ errno. If @p to is @c same, receive"
              "data on @p tst1_s socket. Otherwise, receive data on @p tst2_s"
              "socket. Match sent and received data.");
    te_fill_buf(iut_buf, iut_buflen);
    RPC_AWAIT_IUT_ERROR(pco_iut);
    snt_iut = rpc_sendto(pco_iut, iut_s, iut_buf, iut_buflen, 0, tst2_addr);
    if (snt_iut == -1)
    {
        if (tst2_addr != NULL)
            TEST_VERDICT("The second call of sendto() function failed "
                         "unexpectedly with errno %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        if (RPC_ERRNO(pco_iut) == RPC_ENOTCONN)
        {
            RING_VERDICT("Send to not connected socket with NULL "
                         "destination address failed with errno ENOTCONN");
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EDESTADDRREQ,
                            "Send to not connected socket with NULL "
                            "destination address failed");
        }
    }
    else if (tst2_addr == NULL)
    {
        TEST_VERDICT("The second send to not connected socket with NULL "
                     "destination address unexpected returned success");
    }
    else
    {
        if (tst1_addr == tst2_addr)
            rcv_tst = rpc_recv(pco_tst, tst1_s, tst_buf, tst_buflen, 0);
        else
            rcv_tst = rpc_recv(pco_tst, tst2_s, tst_buf, tst_buflen, 0);

        if (rcv_tst != snt_iut)
            TEST_FAIL("number of bytes received %d while %d sent",
                      rcv_tst, snt_iut);
        if (memcmp(tst_buf, iut_buf, iut_buflen) != 0)
            TEST_FAIL("'tst_s' data received is corrupted");
    }

    TEST_STEP("Connect @p iut_s socket to @p tst1_addr.");
    rpc_connect(pco_iut, iut_s, tst1_addr);

    te_fill_buf(iut_buf, iut_buflen);
    RPC_AWAIT_IUT_ERROR(pco_iut);

    TEST_STEP("Call @b rpc_sendto() on @p iut_s socket with @p tst2_addr as"
              "destination. If the function returns failure, errno has to be"
              "set to @c EISCONN. If the function returns success and @p to is"
              "neither @c null nor @c same, receive data on @p tst2_s socket and"
              "check that @p iut_s socket is not reconnected to @p tst2_addr."
              "If the function returns success and @p to is @c null or @c same,"
              "receive data on @p tst1_s socket. Match sent and received data.");
    snt_iut = rpc_sendto(pco_iut, iut_s, iut_buf, iut_buflen, 0, tst2_addr);
    if (snt_iut == -1)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EISCONN,
                        "Send to connected socket fails");

        if (tst2_addr == NULL || tst2_addr == tst1_addr)
            RING_VERDICT("Send to connected socket to %s fails with "
                         "errno EISCONN", descr,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
    }
    else
    {
        if (tst2_addr == tst1_addr || tst2_addr == NULL)
            rcv_tst = rpc_recv(pco_tst, tst1_s, tst_buf, tst_buflen, 0);
        else
            rcv_tst = rpc_recv(pco_tst, tst2_s, tst_buf, tst_buflen, 0);

        if (rcv_tst != snt_iut)
            TEST_FAIL("number of bytes received %d while %d sent",
                      rcv_tst, snt_iut);
        if (memcmp(tst_buf, iut_buf, iut_buflen) != 0)
            TEST_FAIL("'tst_s' data received is corrupted");

        if (tst2_addr != NULL && tst2_addr != tst1_addr)
        {
            struct sockaddr_storage buf;
            socklen_t               buflen = sizeof(buf);

            RING_VERDICT("Sending to connected socket to %s sent data "
                         "to specified (a new) destination", descr);

            rpc_getpeername(pco_iut, iut_s, SA(&buf), &buflen);
            if (te_sockaddrcmp(tst1_addr, te_sockaddr_get_size(tst1_addr),
                               CONST_SA(&buf), buflen) != 0)
            {
                TEST_VERDICT("Sending to connected socket to %s changed "
                             "address the socket is connected to to %s",
                             descr, te_sockaddrcmp(tst2_addr,
                                        te_sockaddr_get_size(tst2_addr),
                                        CONST_SA(&buf), buflen) == 0 ?
                                        "used destination address" :
                                        "some strange address");
            }
        }
    }
    
    TEST_SUCCESS;

cleanup:
    TEST_STEP("Close created sockets.");
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst1_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst2_s);

    free(iut_buf);
    free(tst_buf);

    TEST_END;
}

