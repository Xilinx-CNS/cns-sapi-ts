/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Routing table
 */

/** @page route-epilogue Routing package epilogue
 *
 * @objective Restore configuration after running routing tests.
 *
 * @param env   Testing environment:
 *      - @ref arg_types_env_iut_only
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "route/epilogue"

#include "sockapi-test.h"
#include "tapi_namespaces.h"
#include "tapi_host_ns.h"
#include "sockapi-ts_cns.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    sockts_cns_cleanup(pco_iut->ta);

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
