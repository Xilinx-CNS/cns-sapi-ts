/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Epilogue used to restore serial parser state after reset_nic_prologue.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/reset_nic_epilogue"

#include "sockapi-test.h"
#include "reset_nic_prologue.h"

int
main(int argc, char *argv[])
{
    cfg_val_type    inst_type;
    char           *pattern_name = NULL;

    TEST_START;

    TEST_STEP("Add back the pattern into parser tree.");

    inst_type = CVT_STRING;
    rc = cfg_get_instance_str(&inst_type, &pattern_name,
                              CFG_LOCAL_PATTERN_OID);
    if (rc == 0)
    {
        CHECK_RC(cfg_del_instance_fmt(FALSE, CFG_LOCAL_PATTERN_OID));

        cfg_add_instance_fmt(NULL, CVT_STRING, PARSER_PATTERN,
                             PARSER_OID_FMT "/pattern:%s",
                             PARSER_OID_ARGS, pattern_name);
    }
    else if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
    {
        TEST_FAIL("cfg_get_instance_str() returned unexpected error: %r", rc);
    }

    TEST_SUCCESS;

cleanup:
    free(pattern_name);
    TEST_END;
}
