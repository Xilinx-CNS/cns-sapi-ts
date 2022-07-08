/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Reuseport
 */

/** @page reuseport-reuseport_del_addr_connect Use SO_REUSEPORT, remove address, call connect, restore address, terminate process.
 *
 * @objective Test what happens when after binding two TCP listeners
 *            with SO_REUSEPORT bind address is removed, then connect()
 *            is called from peer, then bind address is restored, then
 *            process is terminated without accepting connections.
 *
 * @type Use case.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_del_addr_connect"

#include "sockapi-test.h"
#include "reuseport.h"

/** Number of iterations in main loop. */
#define LOOP_ITERS 15

/** Number of sockets on Tester created in each iteration. */
#define TST_SOCKS  5

/** Listen backlog used in this test. */
#define LISTEN_BACKLOG 1

/** How long to wait until delayed connect() from peer resumes. */
#define CONNECT_TIMEOUT 3000

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;

    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;

    tapi_env_net              *net = NULL;

    struct sockaddr_storage iut_bind_addr;
    struct sockaddr_storage tst_bind_addr;

    struct sockaddr *iut_addr_aux;
    cfg_handle       iut_addr_handle = CFG_HANDLE_INVALID;

    int iut_s1;
    int iut_s2;
    int tst_s;

    int i;
    int j;

    TEST_START;
    TEST_GET_NET(net);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    TEST_STEP("In a loop @c LOOP_ITERS times.");
    for (i = 0; i < LOOP_ITERS; i++)
    {
        RING("Loop iteration %d", i + 1);

        TEST_SUBSTEP("Add a new address on IUT.");

        CHECK_RC(tapi_env_allocate_addr(net, AF_INET,
                                        &iut_addr_aux, NULL));
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr_aux,
                                     &iut_bind_addr));
        free(iut_addr_aux);

        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               SA(&iut_bind_addr),
                                               net->ip4pfx,
                                               FALSE, &iut_addr_handle));
        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("Bind two TCP listeners to this address and the same port "
                     "with help of @c SO_REUSEPORT.");

        iut_s1 = rpc_socket(pco_iut,
                            rpc_socket_domain_by_addr(iut_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s1, RPC_SO_REUSEPORT, 1);
        rpc_bind(pco_iut, iut_s1, SA(&iut_bind_addr));
        rpc_listen(pco_iut, iut_s1, LISTEN_BACKLOG);

        iut_s2 = rpc_socket(pco_iut,
                            rpc_socket_domain_by_addr(iut_addr),
                            RPC_SOCK_STREAM, RPC_PROTO_DEF);
        rpc_setsockopt_int(pco_iut, iut_s2, RPC_SO_REUSEPORT, 1);
        rpc_bind(pco_iut, iut_s2, SA(&iut_bind_addr));
        rpc_listen(pco_iut, iut_s2, LISTEN_BACKLOG);

        TEST_SUBSTEP("Remove the address.");

        CHECK_RC(cfg_del_instance(iut_addr_handle,
                                  FALSE));
        iut_addr_handle = CFG_HANDLE_INVALID;
        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("Call @c TST_SOCKS nonblocking connect() calls from "
                     "peer.");

        for (j = 0; j < TST_SOCKS; j++)
        {
            CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr,
                                         &tst_bind_addr));
            tst_s = rpc_socket(pco_tst,
                               rpc_socket_domain_by_addr(tst_addr),
                               RPC_SOCK_STREAM, RPC_PROTO_DEF);
            rpc_bind(pco_tst, tst_s, SA(&tst_bind_addr));

            rpc_fcntl(pco_tst, tst_s, RPC_F_SETFL, RPC_O_NONBLOCK);
            RPC_AWAIT_ERROR(pco_tst);
            rpc_connect(pco_tst, tst_s, SA(&iut_bind_addr));
        }

        TEST_SUBSTEP("Restore the address on IUT.");
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_iut->ta, iut_if->if_name,
                                               SA(&iut_bind_addr),
                                               net->ip4pfx,
                                               FALSE, &iut_addr_handle));
        CFG_WAIT_CHANGES;

        TEST_SUBSTEP("Let delayed connect attempts from peer proceed.");
        MSLEEP(CONNECT_TIMEOUT);

        TEST_SUBSTEP("Remove address again, restart RPC servers.");

        CHECK_RC(cfg_del_instance(iut_addr_handle,
                                  FALSE));
        iut_addr_handle = CFG_HANDLE_INVALID;
        CFG_WAIT_CHANGES;

        CHECK_RC(rcf_rpc_server_restart(pco_iut));
        CHECK_RC(rcf_rpc_server_restart(pco_tst));
    }

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
