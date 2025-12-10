/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "performance/prologue"

#include "sockapi-test.h"
#include "onload.h"

/**
 * Copy sfnt-pingpong binary to test agent.
 *
 * @param ta        Test agent name
 * @param envar     Environment variable which points to the sfnt-pingpong binary
 */
static void
copy_sfnt_pingpong(const char *ta, const char *envar)
{
    const char *sf_ts_pingpong = getenv(envar);
    char *agt_dir = NULL;
    char dst_path[PATH_MAX];

    if (sf_ts_pingpong == NULL || strcmp(sf_ts_pingpong, "") == 0)
        TEST_FAIL("Environment variable %s is not set", envar);

    CHECK_RC(cfg_get_instance_fmt(NULL, &agt_dir, "/agent:%s/dir:", ta));
    TE_SPRINTF(dst_path, "%s/sfnt-pingpong", agt_dir);
    CHECK_RC(rcf_ta_put_file(ta, 0, sf_ts_pingpong, dst_path));
    free(agt_dir);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst;
    rcf_rpc_server *pco_iut;
    te_string       cmd = (te_string)TE_STRING_INIT;
    tarpc_pid_t     pid;

    TEST_START;
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_iut);

    /* We need to be sure that process of netserver does't exist */
    te_string_append(&cmd, "pkill -f netserver");

    CHECK_RC(tapi_onload_copy_sapi_ts_script(pco_iut, PATH_TO_TE_ONLOAD));
    if ((pid = rpc_te_shell_cmd(pco_tst, cmd.ptr, -1, NULL, NULL, NULL)) < 0)
        ERROR("Failed to kill netserver: %s", cmd);

    copy_sfnt_pingpong(pco_iut->ta, "SF_TS_PINGPONG_IUT");
    copy_sfnt_pingpong(pco_tst->ta, "SF_TS_PINGPONG_TST");
    TEST_SUCCESS;

cleanup:
    te_string_free(&cmd);
    TEST_END;
}
