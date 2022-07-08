/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Prologue, used to configure serial parser for reset NIC tests.
 * It removes the pattern, that the reset NIC tests should ignore.
 * See ON-5853.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/reset_nic_prologue"

#include "sockapi-test.h"
#include "reset_nic_prologue.h"

#define FREE_SETNULL(ptr)   \
    do {                    \
        free(ptr);          \
        ptr = NULL;         \
    } while (FALSE)

int
main(int argc, char *argv[])
{
    unsigned int    ptrn_hdls_n = 0;
    cfg_handle     *ptrn_hdls = NULL;
    char           *ptrn_val = NULL;
    char           *ptrn_name = NULL;
    unsigned int    i;

    TEST_START;

    TEST_STEP("Find and remove the pattern from parser tree.");
    CHECK_RC(cfg_find_pattern_fmt(&ptrn_hdls_n, &ptrn_hdls,
                                  PARSER_OID_FMT "/pattern:*",
                                  PARSER_OID_ARGS));
    for (i = 0; i < ptrn_hdls_n; ++i)
    {
        cfg_get_instance(ptrn_hdls[i], NULL, &ptrn_val);

        if (strcmp(ptrn_val, PARSER_PATTERN) == 0)
        {
            CHECK_RC(cfg_get_inst_name(ptrn_hdls[i], &ptrn_name));
            CHECK_RC(cfg_del_instance_fmt(FALSE, PARSER_OID_FMT "/pattern:%s",
                                          PARSER_OID_ARGS, ptrn_name));
            RING("Removed pattern:%s \"%s\"", ptrn_name, ptrn_val);

            /*
             * Save removed pattern name into /local tree in order to
             * restore it in epilogue.
             */
            CHECK_RC(cfg_add_instance_str(CFG_LOCAL_PATTERN_OID, NULL,
                                          CFG_VAL(STRING, ptrn_name)));

            FREE_SETNULL(ptrn_name);
        }

        FREE_SETNULL(ptrn_val);
    }

    TEST_SUCCESS;

cleanup:

    free(ptrn_hdls);
    free(ptrn_name);
    free(ptrn_val);

    TEST_END;
}
