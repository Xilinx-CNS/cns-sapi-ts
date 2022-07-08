/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/**
 * @page bnbvalue-protected_signal Setting signal handler to libc-protected signal
 *
 * @objective Check that a correct error is returned when setting protected
 *            signal handler
 *
 * @param env      Testing environment:
 *      - @ref arg_types_env_iut_only
 * @param func_sig Function used to set a handler for the signal:
 *      - @c sigaction
 *      - @c bsd_signal
 *      - @c sysv_signal
 *
 * @par Scenario:
 *
 * @author Artemii Morozov <Artemii.Morozov@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/protected_signal"

#include "sockapi-test.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    const char *func_sig;
    char *str_rc = NULL;
    DEFINE_RPC_STRUCT_SIGACTION(old_act);
    DEFINE_RPC_STRUCT_SIGACTION(new_act);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_STRING_PARAM(func_sig);

    rpc_sigaction_init(pco_iut, &new_act);
    rpc_sigaction_init(pco_iut, &old_act);

    rc = 0;

    TEST_STEP("Set @c SIG_LIBC_PROTECTED signal hander on @p pco_iut");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (strcmp(func_sig, "sigaction") == 0)
    {
        strcpy(new_act.mm_handler, "SIG_IGN");
        rc = rpc_sigaction(pco_iut, RPC_SIG_LIBC_PROTECTED, &new_act, NULL);
    }
    else if (strcmp(func_sig, "bsd_signal") == 0)
    {
        str_rc = rpc_bsd_signal(pco_iut, RPC_SIG_LIBC_PROTECTED, "SIG_IGN");
    }
    else if (strcmp(func_sig, "sysv_signal") == 0)
    {
        str_rc = rpc_sysv_signal(pco_iut, RPC_SIG_LIBC_PROTECTED, "SIG_IGN");
    }


    TEST_STEP("Check that @p func_sig fails with EINVAL");
    if (rc == 0 && (str_rc == NULL || strcmp(str_rc, "SIG_ERR") != 0))
    {
        TEST_VERDICT("%s() succeeded unexpectedly instead of failing with "
                     "EINVAL", func_sig);
    }
    else
    {
        if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
        {
            TEST_VERDICT("%s() failed with errno %r instead of EINVAL",
                         func_sig, RPC_ERRNO(pco_iut));
        }
    }

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
