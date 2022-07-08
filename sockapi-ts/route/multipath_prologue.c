/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-multipath_prologue Prologue for multipath routes tests
 *
 * @objective Configure test hosts for multipath routes tests.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_triangle_iut_iut
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/mulitpath_prologue"

#include "sockapi-test.h"
#include "ts_route_mpath.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst = NULL;
    const struct if_nameindex *tst_remote_if = NULL;
    tapi_env_net              *tst_remote_net = NULL;
    const struct sockaddr     *tst_remote_addr = NULL;
    unsigned int               addrs_num;
    unsigned int               i;
    int                        af;
    struct sockaddr           *new_addr = NULL;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(tst_remote_if);
    TEST_GET_NET(tst_remote_net);
    TEST_GET_ADDR(pco_tst, tst_remote_addr);
    TEST_GET_UINT_PARAM(addrs_num);

    af = tst_remote_addr->sa_family;

    /*
     * Allocate and assign addresses here to avoid doing it in
     * every test iteration. This will help to avoid FAILED
     * neighbor entries in case of IPv6 (see OL bug 9774), which
     * can appear after removal of previously used addresses
     * in cleanup and interfere with the next iteration.
     */

    for (i = 0; i < addrs_num; i++)
    {
        CHECK_RC(tapi_cfg_alloc_net_addr((af == AF_INET ?
                                            tst_remote_net->ip4net :
                                            tst_remote_net->ip6net),
                                         NULL,
                                         &new_addr));

        CHECK_RC(tapi_cfg_base_if_add_net_addr(
                    pco_tst->ta, tst_remote_if->if_name,
                    new_addr,
                    (af == AF_INET ? tst_remote_net->ip4pfx :
                                     tst_remote_net->ip6pfx),
                    FALSE,
                    NULL));

        free(new_addr);
        new_addr = NULL;
    }

    TEST_SUCCESS;

cleanup:

    free(new_addr);

    TEST_END;
}
