/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_hw_filters_tcp_listen Hardware filters exhaustion caused by listen() operation on TCP sockets
 *
 * @objective Check that Level5 library does not return error
 *            when there are no more TCP hardware filters available
 *            when creating listening TCP sockets.
 *
 * @type conformance, robustness
 *
 * @param pco_aux           PCO on IUT
 * @param pco_tst           PCO on Tester
 * @param iut_addr          Local address on IUT
 * @param tst_addr          Remote address for IUT
 * @param iut_ifname        Network interface on the IUT
 * @param iut_if_addr_count Amount of addresses assigned to
 *                          the network interface on the IUT
 * @param ef_no_fail        Whether EF_NO_FAIL is enabled
 * @param wild              Bind IUT socket to wildcard address
 *
 * @par Scenario:
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME \
    "level5/out_of_resources/out_of_hw_filters_tcp_listen"

#include "out_of_resources.h"
#include "onload.h"
#include "tapi_proc.h"

/* Maximum failed attempts number to stop testing. */
#define MAX_ATTEMPTS 200

/* Check attempts number */
#define CHECK_ATTEMPTS_NUMBER \
{                                       \
    (counter)++;                        \
    if (counter > MAX_ATTEMPTS)         \
        break;                          \
    else                                \
    {                                   \
        RPC_CLOSE(pco_iut, iut_s[i]);   \
        RPC_CLOSE(pco_tst, tst_s[i]);   \
        i--;                            \
        continue;                       \
    }                                   \
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_aux = NULL;
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    struct sockaddr         wildcard_addr;
    struct sockaddr         tmp;
    socklen_t               tmplen = sizeof(tmp);
    
    struct sockaddr        *new_addr;
    cfg_handle              new_addr_handle;
    tapi_env_net           *net;

    const struct if_nameindex  *iut_if;
    const struct if_nameindex  *iut_if2;
    const struct if_nameindex  *tst_if;

    int                     hw_filters = -1;
    int                     hw_filters_max;
    int                     iut_if_addr_count;
    int                     addr_id;
    te_bool                 ef_no_fail;
    te_bool                 wild;
    uint16_t                port;
    int loglevel = 0;
    int iut_s_1;
    int iut_s_2;
    int tst_s_2 = -1;
    int tst_s_1 = -1;
    int *iut_s = NULL;
    int *acc_s = NULL;
    int *tst_s = NULL;
    int req_num;
    int sock_num;
    int acc;
    int err = 0;

    TEST_START;

    TEST_GET_PCO(pco_aux);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_NET(net);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(iut_if2);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(iut_if_addr_count);
    TEST_GET_BOOL_PARAM(ef_no_fail);
    TEST_GET_BOOL_PARAM(wild);

    hw_filters_max = get_hw_filters_limit(pco_aux);

    TAPI_SYS_LOGLEVEL_DEBUG(pco_aux, &loglevel);

    CHECK_RC(tapi_sh_env_set_int(pco_aux, "EF_PREFAULT_PACKETS",
                                 30000, TRUE, FALSE));

    /** Each listening socket reserves a one socket in backlog which is
     * limited by @p EF_TCP_BACKLOG_MAX value. */
    tapi_sh_env_set_int(pco_aux, "EF_TCP_BACKLOG_MAX", hw_filters_max,
                        TRUE, TRUE);

    if (iut_if_addr_count == 0)
        TEST_FAIL("Invalid parameter iut_if_addr_count");

    TEST_STEP("Add aux addresses to the IUT interface.");
    for (addr_id = 1; addr_id < iut_if_addr_count; addr_id++)
    {
        CHECK_RC(tapi_env_allocate_addr(net, AF_INET, &new_addr, NULL));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_aux->ta, iut_if->if_name,
                                               new_addr, -1, FALSE,
                                               &new_addr_handle));
    }
    iut_if_addr_count++;

    if (wild)
        CHECK_RC(count_involved_addresses(pco_aux->ta, &iut_if_addr_count));

    TEST_STEP("Create child process and increase RTLIMIT for it.");
    CHECK_RC(rcf_rpc_server_fork(pco_aux, "child", &pco_iut));
    prepare_parent_pco(pco_iut, 2 * hw_filters_max);
    CHECK_RC(rcf_rpc_server_exec(pco_iut));

    TEST_STEP("In the loop create socket on IUT, call bind() and listen() until HW "
              "filters are exhausted. Accept connections if @p wild is @c TRUE. "
              "Calculate number of created and accelerated after all sockets.");
    if (wild)
    {
        char buf[128];
        int i;
        int counter = 0;
        int unacc = 0;

        req_num = hw_filters_max / iut_if_addr_count * 2;

        memcpy(&wildcard_addr, iut_addr, sizeof(*iut_addr));
        te_sockaddr_set_wildcard(&wildcard_addr);

        acc_s = te_calloc_fill(req_num, sizeof(*acc_s), -1);
        iut_s = te_calloc_fill(req_num, sizeof(*iut_s), -1);
        tst_s = te_calloc_fill(req_num, sizeof(*tst_s), -1);

        acc = 0;
        for (i = 0; i < req_num && counter < MAX_ATTEMPTS; i++)
        {
            iut_s[i] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
            tst_s[i] = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);

            rc = 0;
            do {
                if (rc != 0)
                {
                    if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                        TEST_VERDICT("Bind unexpectedly failed with %r",
                                     RPC_ERRNO(pco_iut));
                }

                if ((port = te_sockaddr_get_port(iut_addr) + 1) == 0)
                    port = 30000;

                te_sockaddr_set_port((struct sockaddr *)iut_addr, port);
                te_sockaddr_set_port(&wildcard_addr, port);
                RPC_AWAIT_IUT_ERROR(pco_iut);
            } while ((rc = rpc_bind(pco_iut, iut_s[i], &wildcard_addr)) != 0);

            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_listen(pco_iut, iut_s[i], -1);
            if (rc < 0)
            {
                err++;
                if (!ef_no_fail)
                {
                    if (RPC_ERRNO(pco_iut) != RPC_ENOBUFS)
                        TEST_VERDICT("listen() failed with unexpected "
                                     "errrno %r", RPC_ERRNO(pco_iut));

                    CHECK_ATTEMPTS_NUMBER
                }

                TEST_VERDICT("listen() failed with errno %r",
                             RPC_ERRNO(pco_iut));
            }

            rpc_connect(pco_tst, tst_s[i], iut_addr);
            acc_s[i] = rpc_accept(pco_iut, iut_s[i], NULL, NULL);

            if (tapi_onload_is_onload_fd(pco_iut, acc_s[i]) !=
                TAPI_FD_IS_SYSTEM)
                acc++;
            else
            {
                unacc++;
                CHECK_ATTEMPTS_NUMBER
            }
            counter = 0;

            rpc_send(pco_tst, tst_s[i], buf, sizeof(buf), 0);
            rpc_recv(pco_iut, acc_s[i], buf, sizeof(buf), 0);
        }

        sock_num = i + err + unacc;
        /*
         * If @p wild is @c TRUE number of accelerated sockets
         * cannot be used to check the total number of observed HW filters
         * because the distribution of filters between sockets is unequal.
         */
        hw_filters = get_wild_sock_hw_filters_num(pco_aux);
    }
    else
    {
        req_num = hw_filters_max * HW_FILTERS_MULT;

        pco_iut->timeout = 30000;
        sock_num = rpc_out_of_hw_filters_do(pco_iut, TRUE,
            iut_addr, tst_addr, RPC_SOCK_STREAM,
            RPC_OOR_LISTEN, req_num, &acc, &err, &iut_s_1, &iut_s_2);

        TEST_STEP("Check that the first and the last connections can transmit data.");
        tst_s_1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                             RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
        rpc_getsockname(pco_iut, iut_s_1, &tmp, &tmplen);
        port = te_sockaddr_get_port(&tmp);
        memcpy(&tmp, iut_addr, sizeof(tmp));
        te_sockaddr_set_port(&tmp, port);
        rpc_connect(pco_tst, tst_s_1, &tmp);
        iut_s_1 = rpc_accept(pco_iut, iut_s_1, NULL, NULL);

        tst_s_2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                             RPC_SOCK_STREAM, RPC_IPPROTO_TCP);
        rpc_getsockname(pco_iut, iut_s_2, &tmp, &tmplen);
        port = te_sockaddr_get_port(&tmp);
        memcpy(&tmp, iut_addr, sizeof(tmp));
        te_sockaddr_set_port(&tmp, port);
        rpc_connect(pco_tst, tst_s_2, SA(&tmp));

        iut_s_2 = rpc_accept(pco_iut, iut_s_2, NULL, NULL);

        sockts_test_connection(pco_iut, iut_s_1, pco_tst, tst_s_1);
        sockts_test_connection(pco_iut, iut_s_2, pco_tst, tst_s_2);
    }

    RING("Created sockets number %d/%d/%d", req_num, sock_num, acc);

    TEST_STEP("Check requested, opened and accelerated sockets numbers.");
    hw_filters_check_results(ef_no_fail, req_num, sock_num, acc, err,
                             hw_filters_max, hw_filters);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s_2);

    sockts_close_sockets(pco_tst, tst_s, req_num);
    sockts_close_sockets(pco_iut, acc_s, req_num);
    sockts_close_sockets(pco_iut, iut_s, req_num);

    free(acc_s);
    free(iut_s);
    free(tst_s);

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_aux, loglevel);

    TEST_END;
}
