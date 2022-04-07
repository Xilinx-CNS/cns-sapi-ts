/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * Tools testing
 */

/**
 * @page tools-prologue Tools package prologue
 *
 * @objective Configure IUT host for tools tests.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_iut_only
 *
 * @par Scenario:
 *
 * @author Pavel Liulchak <Pavel.Liulchak@oktetlabs.ru>
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "tools/prologue"

#include "sockapi-test.h"
#include "onload.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut;

    TEST_START;
    TEST_GET_PCO(pco_iut);

    TEST_STEP("Copy te_onload script to IUT.");
    CHECK_RC(tapi_onload_copy_sapi_ts_script(pco_iut, PATH_TO_TE_ONLOAD));

    TEST_SUCCESS;

cleanup:
    TEST_END;
}