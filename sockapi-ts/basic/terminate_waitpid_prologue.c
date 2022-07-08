/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @file
 *
 * Prologue, used to configure serial parser for basic/terminate_waitpid test
 * to catch Onload messages like "Stack released with lock stuck".
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "basic/terminate_waitpid_prologue"

#include "sockapi-test.h"
#include "tapi_serial_parse.h"
#include "terminate_waitpid_prologue.h"

int
main(int argc, char *argv[])
{
    tapi_parser_id *parser = NULL;
    const char *c_name = NULL;

    TEST_START;

    CHECK_NOT_NULL(c_name = getenv("TE_IUT"));
    parser = tapi_serial_id_init(SERIAL_LOG_PARSER_AGENT, c_name,
                                 SERIAL_LOG_PARSER_NAME);

    /*
     * Set an empty handler name, so Tester will not send signal when the
     * pattern is caught. Parser results are handled inside the test.
     */
    CHECK_RC(tapi_serial_parser_event_add(parser, TERM_WAITPID_PARSER_EVENT,
                                          ""));
    if (tapi_serial_parser_pattern_add(parser, TERM_WAITPID_PARSER_EVENT,
                                       "released with lock stuck") == -1)
    {
        TEST_FAIL("Failed to add pattern");
    }

    TEST_SUCCESS;

cleanup:
    tapi_serial_id_cleanup(parser);
    TEST_END;
}
