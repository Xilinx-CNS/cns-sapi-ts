/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Level5-specific test reproducing run out of hardware resources
 *
 * $Id$
 */

/** @page level5-out_of_resources-oof_multicast_gradual HW filters exhaustion by joining to lots of multicast groups
 *
 * @objective  Join to multicast groups until OOF state is achieved.
 *
 * @type conformance, robustness
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param iut_addr      Local address on IUT
 * @param tst_addr      Remote address for IUT
 * @param sock_func     Socket creation function for IUT
 * @param ef_no_fail    Whether EF_NO_FAIL is enabled
 * @param bind_before   Bind before join to multicast groups
 * @param portion       Multicast groups number to be joined in one step
 * @param success       Steps number which must be succeeded
 *
 * @par Scenario:
 * -# Do the following actions in loop until OOF state is achieved:
 * -# Join to a one multicast group on each iteration.
 * -# Once in @p portion iterations check if OOF state is achieved,
 *    create new IUT socket if it is not.
 * -# For each IUT socket call @b bind() before join to multicast groups if
 *    @p bind_before is @c TRUE, else - after.
 * -# Portions number which is required for OOF state achieving must be greater
 *    then @p success.
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/out_of_resources/oof_multicast_gradual"

#include "out_of_resources.h"

/* Maxim packet length to be passed. */
#define MAX_DGRAM_LEN 1400

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;

    te_bool bind_before;
    te_bool ef_no_fail;
    int     portion;
    int     success;

    sockts_socket_func    sock_func;

    struct sockaddr_storage  wildcard_addr;
    struct sockaddr_in       mcast_addr;
    struct tarpc_mreqn       mreq;
    csap_handle_t            csap = CSAP_INVALID_HANDLE;
    size_t buf_len;
    char  addr_buf[16] = {0};
    char *tx_buf = NULL;
    char *rx_buf = NULL;
    int  *sock   = NULL;
    int  tst_s = -1;
    int  s     = -1;
    int  limit;
    int  unacc;
    int  i;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    SOCKTS_GET_SOCK_FUNC(sock_func);
    TEST_GET_BOOL_PARAM(bind_before);
    TEST_GET_BOOL_PARAM(ef_no_fail);
    TEST_GET_IF(iut_if);
    TEST_GET_INT_PARAM(portion);
    TEST_GET_INT_PARAM(success);

    limit = get_hw_filters_limit(pco_iut) * 2;

    tx_buf = te_make_buf(1, MAX_DGRAM_LEN, &buf_len);
    rx_buf = te_make_buf_by_len(MAX_DGRAM_LEN);
    sock = te_calloc_fill(limit / portion, sizeof(*sock), -1);

    /** Increase ARP table size. It can be exhausted on old linux versions
     * (tested on 2.6.32-bpo.5-amd64), because of multiple sendto() with
     * multicasts. Modern linux like 2.6.32-431.29.2.el6.x86_64 can work
     * without this. */
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_tst->ta, limit / 2  + 1000, NULL,
                                     "net/ipv4/neigh:default/gc_thresh3"));

    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 10000, NULL,
                                     "net/ipv4/igmp_max_memberships"));
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, 500000, NULL,
                                     "net/core/optmem_max"));

    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    TAPI_SET_NEW_PORT(pco_iut, &mcast_addr);
    memcpy(&wildcard_addr, &mcast_addr,
           te_sockaddr_get_size(SA(&mcast_addr)));
    te_sockaddr_set_wildcard(SA(&wildcard_addr));

    tst_s = rpc_socket(pco_tst, RPC_PF_INET, RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    memset(&mreq, 0, sizeof(mreq));
    mreq.type = OPT_IPADDR;
    memcpy(&mreq.address, te_sockaddr_get_netaddr(tst_addr),
           sizeof(mreq.address));
    rpc_setsockopt(pco_tst, tst_s, RPC_IP_MULTICAST_IF, &mreq);

    csap = create_listener_csap_ext(pco_iut, iut_if, FALSE);

    for (i = 0; i < limit; i++)
    {
        if (i % portion == 0)
        {
            if (s >= 0)
            {
                if (!bind_before)
                {
                    if (!ef_no_fail)
                        RPC_AWAIT_IUT_ERROR(pco_iut);
                    pco_iut->timeout = 2 * pco_iut->def_timeout;
                    rc = rpc_bind(pco_iut, sock[s], SA(&wildcard_addr));
                    if (rc != 0)
                    {
                        if (RPC_ERRNO(pco_iut) == RPC_ENOBUFS)
                            break;
                        TEST_VERDICT("bind() failed with unexpected "
                                     "errno %r", RPC_ERRNO(pco_iut));
                    }
                }

                CHECK_RC(tapi_tad_trrecv_start(pco_iut->ta, 0, csap, NULL,
                                               TAD_TIMEOUT_INF, 0,
                                               RCF_TRRECV_COUNT));

                rpc_sendto(pco_tst, tst_s, tx_buf, buf_len, 0,
                           SA(&mcast_addr));
                rc = rpc_recv(pco_iut, sock[s], rx_buf, MAX_DGRAM_LEN, 0);
                if ((rc != (int)buf_len) ||
                    (memcmp(tx_buf, rx_buf, buf_len) != 0))
                    TEST_FAIL("Bad packet was received on address %s",
                              addr_buf);

                CHECK_RC(tapi_tad_trrecv_stop(pco_iut->ta, 0, csap, NULL,
                                              (unsigned int *)&unacc));

                if (unacc > 0)
                {
                    RING("Unaccelerated packet was captured on "
                         "iteration #%d", i);
                    if (ef_no_fail)
                        break;
                    TEST_VERDICT("Unaccelerated packet was captured");
                }
            }

            s++;
            sock[s] = sockts_socket(sock_func, pco_iut, RPC_PF_INET,
                                    RPC_SOCK_DGRAM, RPC_PROTO_DEF);
            rpc_setsockopt_int(pco_iut, sock[s], RPC_SO_REUSEADDR, 1);

            if (bind_before)
                rpc_bind(pco_iut, sock[s], SA(&wildcard_addr));
        }

        memset(addr_buf, 0, sizeof(addr_buf));
        sprintf(addr_buf, "239.255.%d.%d", (i / 256) + 16, i % 256);
        mcast_addr.sin_addr.s_addr = inet_addr(addr_buf);

        if (!ef_no_fail)
            RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_mcast_join(pco_iut, sock[s], SA(&mcast_addr),
                            iut_if->if_index, TARPC_MCAST_ADD_DROP);
        if (rc != 0)
        {
            if (RPC_ERRNO(pco_iut) == RPC_EBUSY)
                break;
            TEST_VERDICT("Failed to join to multicast group with "
                         "unexpected errno %r", RPC_ERRNO(pco_iut));
        }
    }

    if (s < success)
        TEST_VERDICT("Too less filters were grabbed");

    if (i == limit)
    {
        RING("Iterations limit number %d was achieved", limit);
        TEST_VERDICT("Out of filters condition was not reached");
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_iut->ta, 0, csap));

    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    clean_sockets(pco_iut, sock, s);
    free(tx_buf);
    free(rx_buf);
    TEST_END;
}
