/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue to tweak TCP timeouts
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#define TE_TEST_NAME "tcp/prologue_timeouts_init"

#include "sockapi-test.h"
#include "extensions.h"
#include "onload.h"

/** MSL timeout. */
#define MSL_TIMEOUT 5
#define RETRANSMIT_THRESHOLD 4

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_STEP("Set MSL timeout to decrease waiting in the TIME_WAIT state.");
    CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_TCP_TCONST_MSL",
                                 MSL_TIMEOUT, TRUE, FALSE));

    TEST_STEP("Decrease waiting time for linux as well by setting "
              "@b tcp_orphan_retries value.");
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, RETRANSMIT_THRESHOLD - 1,
                                     NULL, "net/ipv4/tcp_orphan_retries"));
    CHECK_RC(tapi_cfg_sys_ns_set_int(pco_iut->ta, MSL_TIMEOUT, NULL,
                                     "net/ipv4/tcp_fin_timeout"));

    /* It's necessary to restart the RPC server in order
     * to the new settings can take effect.
     */
    rcf_rpc_server_restart(pco_iut);

    CHECK_RC(cfg_synchronize("/:", TRUE));

    TEST_SUCCESS;

cleanup:
    TEST_END;
}
