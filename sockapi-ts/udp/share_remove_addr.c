/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UDP tests
 */

/** @page udp-share_remove_addr Remove address shared by several UDP sockets
 *
 * @objective  Check what happens when an address removed to which
 *             several UDP sockets are bound with SO_REUSEADDR.
 *
 * @type conformance
 *
 * @param connect_after_remove  Whether to call connect() after
 *                              or before network address removal.
 *
 * @par Test sequence:
 *
 * @ref This test is designed to reproduce SF bug 68937.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "udp/share_remove_addr"

#include "sockapi-test.h"

/**
 * Check sending data from IUT socket.
 *
 * @param pco_iut       RPC server on IUT.
 * @param iut_s         Socket on IUT.
 * @param name          Name associated with socket.
 * @param pco_tst       RPC server on Tester.
 * @param tst_s         Socket on Tester.
 * @param tst_addr      Network address of Tester socket.
 */
static void
check_send(rcf_rpc_server *pco_iut,
           int iut_s,
           const char *name,
           rcf_rpc_server *pco_tst,
           int tst_s,
           const struct sockaddr *tst_addr)
{
    char    snd_buf[SOCKTS_MSG_DGRAM_MAX];
    char    rcv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t  send_len;
    int     rc;

    te_fill_buf(snd_buf, SOCKTS_MSG_DGRAM_MAX);
    send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_sendto(pco_iut, iut_s, snd_buf, send_len,
                    0, tst_addr);

    if (rc == 0)
    {
        ERROR_VERDICT("sendto() returnes zero for %s", name);
    }
    else if (rc > 0)
    {
        WARN_VERDICT("sendto() sent data from %s", name);
        if (rc != (int)send_len)
            TEST_VERDICT("Unexpected value was returned by sendto() for %s",
                         name);

        RPC_AWAIT_ERROR(pco_tst);
        rc = rpc_recv(pco_tst, tst_s, rcv_buf, SOCKTS_MSG_DGRAM_MAX, 0);
        if (rc != (int)send_len || memcmp(rcv_buf, snd_buf, rc) != 0)
            TEST_VERDICT("Wrong data was received from %s", name);
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL &&
             RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
    {
        /* See ST-1860 */
        ERROR_VERDICT("sendto() failed with unexpected errno %r",
                      RPC_ERRNO(pco_iut));
    }
}

/**
 * Check receiving data on IUT sockets.
 *
 * @param pco_iut       RPC server on IUT.
 * @param iut_s1        The first socket on IUT.
 * @param iut_s2        The second socket on IUT.
 * @param iut_s3        The third socket on IUT.
 * @param iut_addr      Network address to which IUT sockets are bound.
 * @param pco_tst       RPC server on Tester.
 * @param tst_s         Socket on Tester.
 */
static void
check_recv(rcf_rpc_server *pco_iut,
           int iut_s1,
           int iut_s2,
           int iut_s3,
           const struct sockaddr *iut_addr,
           rcf_rpc_server *pco_tst,
           int tst_s)
{
#define CHECK_IUT_SOCK(sock_) \
    do {                                                              \
        if (sock_ >= 0)                                               \
        {                                                             \
            RPC_GET_READABILITY(readable, pco_iut, sock_, 0);         \
            if (readable)                                             \
            {                                                         \
                ERROR_VERDICT(#sock_ " received data from Tester");   \
                rc = rpc_recv(pco_iut, sock_, rcv_buf,                \
                              SOCKTS_MSG_DGRAM_MAX, 0);               \
                if (rc != (int)send_len ||                            \
                    memcmp(snd_buf, rcv_buf, send_len) != 0)          \
                    TEST_VERDICT(#sock_ " received wrong data");      \
            }                                                         \
        }                                                             \
    } while (0)

    char    snd_buf[SOCKTS_MSG_DGRAM_MAX];
    char    rcv_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t  send_len;
    te_bool readable;
    int     rc;

    te_fill_buf(snd_buf, SOCKTS_MSG_DGRAM_MAX);
    send_len = rand_range(1, SOCKTS_MSG_DGRAM_MAX);

    rc = rpc_sendto(pco_tst, tst_s, snd_buf, send_len,
                    0, iut_addr);
    if (rc != (int)send_len)
        TEST_FAIL("sendto() on Tester returned strange result");

    TAPI_WAIT_NETWORK;

    CHECK_IUT_SOCK(iut_s1);
    CHECK_IUT_SOCK(iut_s2);
    CHECK_IUT_SOCK(iut_s3);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;

    const struct if_nameindex *iut_if = NULL;

    tapi_env_net  *net = NULL;

    struct sockaddr_storage iut_bind_addr;

    struct sockaddr *iut_addr_aux;
    cfg_handle       iut_addr_handle = CFG_HANDLE_INVALID;

    int iut_s1 = -1;
    int iut_s2 = -1;
    int iut_s3 = -1;
    int tst_s = -1;

    te_bool connect_after_remove;

    rpc_socket_domain iut_domain;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(connect_after_remove);

    iut_domain = rpc_socket_domain_by_addr(iut_addr);

    TEST_STEP("Add a new network address on IUT interface.");
    CHECK_RC(tapi_env_allocate_addr(net,
                                    addr_family_rpc2h(
                                      sockts_domain2family(iut_domain)),
                                    &iut_addr_aux, NULL));
    CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr_aux,
                                 &iut_bind_addr));
    free(iut_addr_aux);

    CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                           SA(&iut_bind_addr),
                                           iut_domain == RPC_PF_INET ? net->ip4pfx : net->ip6pfx,
                                           FALSE, &iut_addr_handle));
    CFG_WAIT_CHANGES;

    TEST_STEP("Create UDP socket iut_s1, set SO_REUSEADDR for it, "
              "bind it to the added address.");
    iut_s1 = rpc_socket(pco_iut,
                        iut_domain,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut, iut_s1, SA(&iut_bind_addr));

    TEST_STEP("If @p connect_after_remove is @c FALSE, @b connect() "
              "the socket to @p tst_addr.");
    if (!connect_after_remove)
        rpc_connect(pco_iut, iut_s1, tst_addr);

    TEST_STEP("Create UDP socket iut_s2, set SO_REUSEADDR for it, "
              "bind it to the same address and port.");
    iut_s2 = rpc_socket(pco_iut,
                        iut_domain,
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEADDR, 1);
    rpc_bind(pco_iut, iut_s2, SA(&iut_bind_addr));

    TEST_STEP("If @p connect_after_remove is @c FALSE, "
              "create UDP socket iut_s3, set SO_REUSEADDR for it, "
              "bind it to the same address and port.");
    if (!connect_after_remove)
    {
        iut_s3 = rpc_socket(pco_iut,
                            iut_domain,
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s3, RPC_SO_REUSEADDR, 1);
        rpc_bind(pco_iut, iut_s3, SA(&iut_bind_addr));
    }

    TEST_STEP("Create UDP socket on Tester, bind it to @p tst_addr.");
    tst_s = rpc_socket(pco_tst,
                       rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    TEST_STEP("Remove previously used network address from IUT interface.");
    CHECK_RC(cfg_del_instance(iut_addr_handle,
                              FALSE));
    iut_addr_handle = CFG_HANDLE_INVALID;
    CFG_WAIT_CHANGES;

    if (connect_after_remove)
    {
        TEST_STEP("If @p connect_after_remove is @c TRUE:");

        TEST_SUBSTEP("@b connect() iut_s1 to @p tst_addr, check that "
                     "it fails with @c EINVAL.");
        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_connect(pco_iut, iut_s1, tst_addr);
        if (rc >= 0)
            WARN_VERDICT("connect() succeeded after removing "
                          "bound address");
        else if (RPC_ERRNO(pco_iut) != RPC_EINVAL &&
                 RPC_ERRNO(pco_iut) != RPC_ENETUNREACH)
        {
            /* See ST-1860 */
            ERROR_VERDICT("After removing bound address "
                          "connect() failed with unexpected errno %r",
                          RPC_ERRNO(pco_iut));
        }

        TEST_STEP("Check that data cannot be sent from IUT sockets.");
        check_send(pco_iut, iut_s1, "iut_s1", pco_tst, tst_s, tst_addr);
        check_send(pco_iut, iut_s2, "iut_s2", pco_tst, tst_s, tst_addr);

        TEST_STEP("Check that data cannot be received on IUT sockets.");
        check_recv(pco_iut, iut_s1, iut_s2, iut_s3, iut_addr,
                   pco_tst, tst_s);

        TEST_SUBSTEP("Close iut_s2, then iut_s1.");
        RPC_CLOSE(pco_iut, iut_s2);
        RPC_CLOSE(pco_iut, iut_s1);
    }
    else
    {
        TEST_STEP("Check that data cannot be sent from IUT sockets.");
        check_send(pco_iut, iut_s1, "iut_s1", pco_tst, tst_s, tst_addr);
        check_send(pco_iut, iut_s2, "iut_s2", pco_tst, tst_s, tst_addr);
        check_send(pco_iut, iut_s3, "iut_s3", pco_tst, tst_s, tst_addr);

        TEST_STEP("Check that data cannot be received on IUT sockets.");
        check_recv(pco_iut, iut_s1, iut_s2, iut_s3, iut_addr,
                   pco_tst, tst_s);

        TEST_STEP("If @p connect_after_remove is @c FALSE, "
                  "close iut_s3, then iut_s1.");
        RPC_CLOSE(pco_iut, iut_s3);
        RPC_CLOSE(pco_iut, iut_s1);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s3);

    if (iut_addr_handle != CFG_HANDLE_INVALID)
    {
        CHECK_RC(cfg_del_instance(iut_addr_handle,
                                  FALSE));
        CFG_WAIT_CHANGES;
    }

    TEST_END;
}
