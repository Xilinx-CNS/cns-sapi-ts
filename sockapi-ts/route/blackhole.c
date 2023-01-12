/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-blackhole Test for blackhole routes and similar
 *
 * @objective The test adds a route of non-usual type and
 *            checks that this route is used properly.
 *
 * @param env           Testing environment:
 *                      - @ref two_ifs_variants
 * @param sock_type     Type of connection:
 *                      - udp (test established UDP connection)
 *                      - udp_notconn (create new UDP connection)
 *                      - tcp_active (create new UDP connection from IUT)
 *                      - tcp_passive (create new UDP connection from TST1)
 *                      - tcp_passive_close (test established TCP connection)
 * @param route_type    Type of created blackhole:
 *                      - blackhole
 *                      - unreachable
 *                      - prohibit
 *                      - throw
 * @param connected     Status of initial connection:
 *                      - @c TRUE (check already established connection)
 *                      - @c FALSE (check connection establishing)
 *
 * @par Scenario:
 *
 * @author Daniil Byshenko <Daniil.Byshenko@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/blackhole"

#include "sockapi-test.h"
#include "tapi_cfg.h"

#define CHECK_PCO_ERRNO(pco, route_type, msg) \
    do {                                                        \
        if (strcmp(route_type, "blackhole") == 0)               \
        {                                                       \
            CHECK_RPC_ERRNO(pco, RPC_EINVAL, msg);              \
        }                                                       \
        else if (strcmp(route_type, "unreachable") == 0)        \
        {                                                       \
            CHECK_RPC_ERRNO(pco, RPC_EHOSTUNREACH, msg);        \
        }                                                       \
        else if (strcmp(route_type, "prohibit") == 0)           \
        {                                                       \
            CHECK_RPC_ERRNO(pco, RPC_EACCES, msg);              \
        }                                                       \
        else if (strcmp(route_type, "throw") == 0)              \
        {                                                       \
            CHECK_RPC_ERRNO(pco, RPC_ENETUNREACH, msg);         \
        }                                                       \
        else                                                    \
        {                                                       \
            TEST_FAIL("Unknown route_type: %s", route_type);    \
        }                                                       \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst1 = NULL;

    const struct sockaddr *iut_addr1 = NULL;
    const struct sockaddr *tst1_addr = NULL;

    const char *route_type;
    te_bool connected;

    int opt_val = 1;
    char buf[16] = { 0 };

    sockts_socket_type sock_type;
    rpc_socket_type rpc_sock_type;

    cfg_handle normal_hndl = CFG_HANDLE_INVALID;
    cfg_handle blackhole_hndl = CFG_HANDLE_INVALID;

    int iut_s = -1;
    int tst_s = -1;
    int acc_sock = -1;
    int iut_tmp_sock = -1;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);

    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    SOCKTS_GET_SOCK_TYPE(sock_type);
    TEST_GET_STRING_PARAM(route_type);
    TEST_GET_BOOL_PARAM(connected);

    rpc_sock_type = sock_type_sockts2rpc(sock_type);

    if (!connected)
    {
        TEST_STEP("If @p connected is @c FALSE add a @p route_type route "
                  "on IUT to @p pco_tst1 before connection establishing");
        CHECK_RC(tapi_cfg_add_typed_route(pco_iut->ta, iut_addr1->sa_family,
                                te_sockaddr_get_netaddr(tst1_addr),
                                te_netaddr_get_bitsize(iut_addr1->sa_family),
                                NULL, NULL, NULL, route_type,
                                0, 0, 0, 0, 0, 0, &blackhole_hndl));
        CFG_WAIT_CHANGES;
    }

    TEST_STEP("Establish connection according to @p sock_type. "
              "Check that it fails if @p connected is @c FALSE");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr1),
                       rpc_sock_type, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst1, rpc_socket_domain_by_addr(tst1_addr),
                       rpc_sock_type, RPC_PROTO_DEF);

    rpc_bind(pco_iut, iut_s, iut_addr1);
    rpc_bind(pco_tst1, tst_s, tst1_addr);

    switch (sock_type)
    {
        case SOCKTS_SOCK_UDP:
            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst1_addr);

            if (connected && rc == -1)
            {
                TEST_VERDICT("Failed to establish UDP connection from "
                             "@p pco_iut to @p pco_tst1 without blackhole");
            }

            if (!connected && rc != -1)
            {
                TEST_VERDICT("Failed to block UDP connection from "
                             "@p pco_iut to @p pco_tst1 using blackhole");
            }

            if (!connected)
            {
               CHECK_PCO_ERRNO(pco_iut, route_type, "connect() returns -1, but");
            }

            break;

        case SOCKTS_SOCK_UDP_NOTCONN:
            /* Nothing to do */
            break;

        case SOCKTS_SOCK_TCP_ACTIVE:
            rpc_listen(pco_tst1, tst_s, SOCKTS_BACKLOG_DEF);

            if (connected)
            {
                pco_tst1->op = RCF_RPC_CALL;
                rpc_accept(pco_tst1, tst_s, NULL, NULL);
            }

            RPC_AWAIT_ERROR(pco_iut);
            rc = rpc_connect(pco_iut, iut_s, tst1_addr);

            if (connected)
            {
                pco_tst1->op = RCF_RPC_WAIT;
                RPC_AWAIT_ERROR(pco_tst1);
                acc_sock = rpc_accept(pco_tst1, tst_s, NULL, NULL);

                RPC_CLOSE(pco_tst1, tst_s);
                tst_s = acc_sock;
            }

            if (connected && acc_sock == -1)
            {
                TEST_VERDICT("Failed to establish TCP connection from "
                             "@p pco_iut to @p pco_tst1 without blackhole");
            }

            if (!connected && rc != -1)
            {
                TEST_VERDICT("Failed to block TCP connection from "
                             "@p pco_iut to @p pco_tst1 using blackhole");
            }

            if (!connected)
            {
                CHECK_PCO_ERRNO(pco_iut, route_type,
                                "connect() returns -1, but");
            }

            break;

        case SOCKTS_SOCK_TCP_PASSIVE:
        case SOCKTS_SOCK_TCP_PASSIVE_CL:
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            rpc_ioctl(pco_tst1, tst_s, RPC_FIONBIO, &opt_val);

            if (connected)
            {
                pco_iut->op = RCF_RPC_CALL;
                rpc_accept(pco_iut, iut_s, NULL, NULL);
            }

            RPC_AWAIT_ERROR(pco_tst1);
            rc = rpc_connect(pco_tst1, tst_s, iut_addr1);

            if (connected)
            {
                pco_iut->op = RCF_RPC_WAIT;
                RPC_AWAIT_ERROR(pco_iut);
                acc_sock = rpc_accept(pco_iut, iut_s, NULL, NULL);

                if (sock_type == SOCKTS_SOCK_TCP_PASSIVE_CL)
                    RPC_CLOSE(pco_iut, iut_s);

                iut_tmp_sock = iut_s;
                iut_s = acc_sock;
            }

            if (connected && acc_sock == -1)
            {
                TEST_VERDICT("Failed to establish TCP connection from "
                             "@p pco_tst1 to @p pco_iut without blackhole");
            }

            if (!connected && rc != -1)
            {
                TEST_VERDICT("Failed to block TCP connection from "
                             "@p pco_tst1 to @p pco_iut using blackhole");
            }

            if (!connected)
            {
                CHECK_RPC_ERRNO(pco_tst1, RPC_EINPROGRESS,
                                "connect() returns -1, but");
            }

            break;

        default:
            TEST_FAIL("Unknown sock_type: %d", sock_type);
            break;
    }

    if (connected)
    {
        TEST_STEP("If @p connected is @c TRUE add a @p route_type route "
                  "on IUT to @p pco_tst1 after connection establishing");
        CHECK_RC(tapi_cfg_add_typed_route(pco_iut->ta, iut_addr1->sa_family,
                                te_sockaddr_get_netaddr(tst1_addr),
                                te_netaddr_get_bitsize(iut_addr1->sa_family),
                                NULL, NULL, NULL, route_type,
                                0, 0, 0, 0, 0, 0, &blackhole_hndl));
        CFG_WAIT_CHANGES;

        TEST_STEP("Check that UIT and Tester can't @p send() and @p recv() "
                  "to/from each other because of the new @p route_type route");

        switch (sock_type)
        {
            case SOCKTS_SOCK_UDP:
                RPC_AWAIT_ERROR(pco_iut);
                rc = rpc_send(pco_iut, iut_s, buf, sizeof(buf), 0);
                if (rc != -1)
                {
                    TEST_VERDICT("Failed to block UDP traffic from "
                                 "@p pco_iut to @p pco_tst1 using blackhole");
                }

                CHECK_PCO_ERRNO(pco_iut, route_type, "send() returns -1, but");
                break;

            case SOCKTS_SOCK_UDP_NOTCONN:
                RPC_AWAIT_ERROR(pco_iut);
                rc = rpc_sendto(pco_iut, iut_s, buf, sizeof(buf), 0, tst1_addr);
                if (rc != -1)
                {
                    TEST_VERDICT("Failed to block UDP traffic from "
                                 "@p pco_iut to @p pco_tst1 using blackhole");
                }

                CHECK_PCO_ERRNO(pco_iut, route_type, "send() returns -1, but");
                break;

            case SOCKTS_SOCK_TCP_ACTIVE:
            case SOCKTS_SOCK_TCP_PASSIVE:
            case SOCKTS_SOCK_TCP_PASSIVE_CL:
                rpc_send(pco_iut, iut_s, buf, sizeof(buf), 0);
                rpc_ioctl(pco_tst1, tst_s, RPC_FIONBIO, &opt_val);

                RPC_AWAIT_ERROR(pco_tst1);
                rc = rpc_recv(pco_tst1, tst_s, buf, sizeof(buf), 0);
                if (rc != -1)
                {
                    TEST_VERDICT("Failed to block TCP traffic from @p pco_iut "
                                 "to @p pco_tst1 using blackhole");
                }

                CHECK_RPC_ERRNO(pco_tst1, RPC_EAGAIN, "recv() returns -1, but");
                break;

            default:
                break;
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_tmp_sock);
    CLEANUP_RPC_CLOSE(pco_tst1, tst_s);

    if (blackhole_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&blackhole_hndl));

    if (normal_hndl != CFG_HANDLE_INVALID)
        CLEANUP_CHECK_RC(tapi_cfg_del_route(&normal_hndl));

    TEST_END;
}