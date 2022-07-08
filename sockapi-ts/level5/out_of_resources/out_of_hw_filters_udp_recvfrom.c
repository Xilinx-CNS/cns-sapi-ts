/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-out_of_hw_filters_udp_recvfrom Hardware filters exhaustion caused by recvfrom(INADDR_ANY) operation on UDP sockets
 *
 * @objective Check that Level5 library does not return error when there
 *            are no more UDP hardware filters available when creating 
 *            and performing recvfrom operation on UDP socket.
 *
 * @type conformance, robustness
 *
 * @param pco_aux           PCO on IUT
 * @param pco_tst           PCO on Tester
 * @param iut_addr          Local address on IUT
 * @param tst_addr          Remote address for IUT
 * @param iut_ifname        Network interface on the IUT
 * @param iut_addrs_per_if  Amount of addresses assigned to
 *                          the network interface on the IUT
 * @param ef_no_fail        Whether EF_NO_FAIL is enabled
 * @param wild              Bind IUT socket to wildcard address
 *
 * @par Scenario:
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 */

#define TE_TEST_NAME \
    "level5/out_of_resources/out_of_hw_filters_udp_recvfrom"

#include "out_of_resources.h"
#include "onload.h"

/** Length of data to be transmitted */
#define DATA_BULK       32

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
    socklen_t               tmplen;
    struct sockaddr        *new_addr;
    cfg_handle              new_addr_handle;
    tapi_env_net           *net;
    te_bool                 ef_no_fail;
    te_bool                 wild;

    const struct if_nameindex  *iut_if = NULL;
    const struct if_nameindex  *iut_if2 = NULL;
    const struct if_nameindex  *tst_if;

    csap_handle_t           csap = CSAP_INVALID_HANDLE;
    uint8_t                 tx[DATA_BULK];
    uint8_t                 rx[DATA_BULK];
    int                     hw_filters = -1;
    int                     hw_filters_max;
    int                     iut_if_addr_count;
    int                     addr_id;

    int loglevel = 0;
    int iut_s_1;
    int iut_s_2;
    int iut_s_0 = -1;
    int tst_s_0 = -1;
    int *iut_s = NULL;
    int *tst_s = NULL;
    int req_num;
    int sock_num;
    int acc;
    int err = 0;
    int val = 0;

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

    TAPI_SYS_LOGLEVEL_DEBUG(pco_aux, &loglevel);

    hw_filters_max = get_hw_filters_limit(pco_aux);

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


    /* If socket is bound to a wildcard address it consumes
     * @p iut_if_addr_count + 1 HW filters. */
    if (wild)
    {
        uint16_t port = te_sockaddr_get_port(iut_addr);
        int i;
        int counter = 0;
        int unacc = 0;

        TEST_STEP("Create CSAP to listen all incoming UDP packets on IUT.");
        csap = create_listener_csap(pco_iut, iut_if);

        req_num = hw_filters_max / iut_if_addr_count * 2;

        memcpy(&wildcard_addr, iut_addr, sizeof(*iut_addr));
        te_sockaddr_set_wildcard(&wildcard_addr);

        iut_s = te_calloc_fill(req_num, sizeof(*iut_s), -1);
        tst_s = te_calloc_fill(req_num, sizeof(*tst_s), -1);

        acc = 0;
        for (i = 0; i < req_num && counter < MAX_ATTEMPTS; i++)
        {
            TEST_STEP("Create socket on IUT and tester.");
            iut_s[i] = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                                  RPC_SOCK_DGRAM, RPC_PROTO_DEF);
            tst_s[i] = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                                  RPC_SOCK_DGRAM, RPC_PROTO_DEF);

            TEST_STEP("Bind IUT socket to a wildcard address.");
            if ((port = te_sockaddr_get_port(iut_addr) + 1) == 0)
            {
                TAPI_SET_NEW_PORT(pco_iut, iut_addr);
                port = te_sockaddr_get_port(iut_addr);
            }

            te_sockaddr_set_port((struct sockaddr *)iut_addr, port);
            te_sockaddr_set_port(&wildcard_addr, port);
            RPC_AWAIT_IUT_ERROR(pco_iut);
            rc = rpc_bind(pco_iut, iut_s[i], &wildcard_addr);

            if (rc != 0)
            {
                if (RPC_ERRNO(pco_iut) == RPC_ENOBUFS)
                {
                    err++;
                    if (!ef_no_fail)
                    {
                        CHECK_ATTEMPTS_NUMBER
                    }
                }

                if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EADDRINUSE)
                    TEST_VERDICT("Bind unexpectedly failed with %r",
                                 RPC_ERRNO(pco_iut));
                else
                {
                    CHECK_ATTEMPTS_NUMBER
                }
            }
 
             TEST_STEP("Send packet from tester and receive on IUT with "
                       "recvfrom().");
            rpc_sendto(pco_tst, tst_s[i], tx, sizeof(tx), 0, iut_addr);
            tmplen = sizeof(tmp);
            rpc_recvfrom(pco_iut, iut_s[i], rx, sizeof(rx), 0, &tmp, &tmplen);
 
            if (tapi_onload_is_onload_fd(pco_iut, iut_s[i]) !=
                TAPI_FD_IS_SYSTEM)
                acc++;
            else
            {
                unacc++;
                CHECK_ATTEMPTS_NUMBER
            }
            counter = 0;
        }

        TEST_STEP("Get number of packets which were caught by the CSAP, i.e. they "
                  "had non-accelerated path.");
        sock_num = i + err + unacc;
        CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, 0, csap, NULL,
                                      (unsigned int *)&rc));

        if (rc != unacc)
        {
            if (ef_no_fail)
            {
                RING("Number of wild sockets with an incomplete"
                     " set of HW filters is %d", (rc - unacc));
                acc -= rc - unacc;
            }
            else
            {
                RING("CSAP detects packets %d, but unaccelerated "
                     "sockets number is %d", rc, unacc);
            }
        }
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
        tst_s_0 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                           RPC_SOCK_DGRAM, RPC_IPPROTO_UDP);
        rpc_bind(pco_tst, tst_s_0, tst_addr);

        TEST_STEP("In the loop create socket on IUT, call bind() and recvfrom(). "
                  "Calculate number of created and accelerated after all sockets.");
        pco_iut->timeout = 100000;
        sock_num = rpc_out_of_hw_filters_do(pco_iut, TRUE,
            wild ? &wildcard_addr : iut_addr, tst_addr,
            RPC_SOCK_DGRAM, RPC_OOR_RECVFROM, req_num, &acc, &err, &iut_s_1,
            &iut_s_2);

        rpc_ioctl(pco_iut, iut_s_1, RPC_FIONBIO, &val);
        rpc_ioctl(pco_iut, iut_s_2, RPC_FIONBIO, &val);

        TEST_STEP("Check that the first and the last connections can transmit "
                  "data.");
        for (iut_s_0 = iut_s_1; TRUE; iut_s_0 = iut_s_2)
        {
            te_fill_buf(tx, DATA_BULK);
            memset(rx, 0, DATA_BULK);
            memset(&tmp, 0, sizeof(tmp));
            tmplen = sizeof(tmp);
            
            rpc_sendto(pco_iut, iut_s_0, tx, DATA_BULK, 0, tst_addr);
            if (rpc_recvfrom(pco_tst, tst_s_0, rx, DATA_BULK, 0, 
                             &tmp, &tmplen) != DATA_BULK)
            {
                TEST_FAIL("Incorrect length of received datagram");
            }
            if (memcmp(rx, tx, DATA_BULK) != 0)
                TEST_FAIL("Data are corrupted");

            te_fill_buf(tx, DATA_BULK);
            memset(rx, 0, DATA_BULK);

            rpc_sendto(pco_tst, tst_s_0, tx, DATA_BULK, 0, &tmp);
            if (rpc_recvfrom(pco_iut, iut_s_0, rx, DATA_BULK, 0, 
                             &tmp, &tmplen) != DATA_BULK)
                TEST_FAIL("Incorrect length of received datagram");

            if (memcmp(rx, tx, DATA_BULK) != 0)
                TEST_FAIL("Data are corrupted");
            if (te_sockaddrcmp(SA(&tmp), tmplen,
                               tst_addr, te_sockaddr_get_size(tst_addr)) != 0)
                TEST_FAIL("Incorrect address is provided"); 

            if (iut_s_0 == iut_s_2)
                break;
        }
    }

    RING("Created sockets number %d/%d/%d/%d", req_num, sock_num, acc, err);

    TEST_STEP("Check requested, opened and accelerated sockets numbers.");
    hw_filters_check_results(ef_no_fail, req_num, sock_num, acc, err,
                             hw_filters_max, hw_filters);

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_tst, tst_s_0);

    sockts_close_sockets(pco_tst, tst_s, req_num);
    sockts_close_sockets(pco_iut, iut_s, req_num);

    free(iut_s);
    free(tst_s);

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_aux, loglevel);

    TEST_END;
}
