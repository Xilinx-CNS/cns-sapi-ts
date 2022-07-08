/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue for testing Onload clustering and SO_REUSEPORT option
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "reuseport/reuseport_epilogue"

#include "sockapi-test.h"

/**
 * Rollback environment variable using local subtree from
 * configuration tree.
 *
 * @param rpcs           PCO handle
 * @param env_name       The environment variable name
 *
 * @note Environment variables in /local:Agt_name/env: sebtree are
 *       set in the start of testing run, so it can be used as
 *       the default value.
 *
 * @result Status code
 */
static void
rollback_env_to_default(rcf_rpc_server *rpcs, const char *env_name)
{
    int             val;
    char           *val_str = NULL;
    te_bool         val_ext = FALSE;
    te_errno        rc;
    cfg_val_type    val_type;

    val_type = CVT_STRING;
    rc = cfg_get_instance_fmt(&val_type, &val_str, "/local:%s/env:%s",
                              rpcs->ta, env_name);
    if (rc == 0 && val_str != NULL && val_str[0] != '\0')
    {
        val = atoi(val_str);
        val_ext = TRUE;
        free(val_str);
    }

    rc = tapi_sh_env_rollback_int(rpcs, env_name, val_ext, val, FALSE);
    /*
     * Non-zero returned value is valid only if we expect that
     * default environment variable was undefined.
     * In other words, no need to rollback if nothing was changed.
     */
    if (rc != 0 && val_ext != FALSE)
    {
        TEST_VERDICT("Failed to rollback %s environment variable, error %X",
                     env_name, rc);
    }

}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    rollback_env_to_default(pco_iut, "EF_SCALABLE_FILTERS_ENABLE");
    rollback_env_to_default(pco_iut, "EF_CLUSTER_SIZE");

    sockts_recreate_onload_stack(pco_iut);
    rcf_rpc_server_restart(pco_iut);

    TEST_SUCCESS;
cleanup:
    TEST_END;
}
