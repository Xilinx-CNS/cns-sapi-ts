/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/**
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

/** Logging subsystem entity name */
#define TE_TEST_NAME    "services/prologue"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "services.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    rcf_rpc_server *pco;

    char *library;

    cfg_handle handle;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);

    rc = cfg_get_instance_fmt(NULL, &library, "/local:%s/socklib:",
                              pco_iut->ta);

    if (rc == 0)
    {
        char *library_name = strrchr(library, '/');
        if (library_name != NULL)
            library_name++;
        else
            library_name = library;

#if 0
        CHECK_RC(tapi_sh_env_set(pco_iut, "LD_PRELOAD", library_name,
                                 TRUE, FALSE));
#else
        /* Setting this variable via CS produces incorrect backup restoring */
        CHECK_RC(rcf_ta_set_var(pco_iut->ta, 0, "LD_PRELOAD", RCF_STRING,
                                library_name));
        rpc_setenv(pco_iut, "LD_PRELOAD", library_name, 1);
#endif
    }
    else if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
    {
        ERROR("cfg_get_instance() failed; rc %r", rc);
        return rc;
    }


    CHECK_RC(tapi_sh_env_unset(pco_iut, "EF_PIPE", TRUE, FALSE));
#if 0
    CHECK_RC(tapi_sh_env_set(pco_iut, "LD_LIBRARY_PATH", "/usr/lib/debug",
                             TRUE, FALSE));
#endif

    /* Add all servers on all agents */
    for (pco = pco_iut;
         pco != NULL;
         pco = pco == pco_iut ? pco_tst : pco == pco_tst ? pco_tst2 : NULL)
    {
#define ADD(_daemon) \
        do {                                                \
            rc = cfg_add_instance_fmt(&handle, CVT_STRING,  \
                                      "/agent/" #_daemon,   \
                                      "/agent:%s/rsrc:%s",  \
                                      pco->ta, #_daemon);   \
            if (rc != 0 &&                                  \
                TE_RC_GET_ERROR(rc) != TE_ENOENT)           \
                TEST_FAIL("Failed to add %s daemon: %r",    \
                          (#_daemon), rc);                  \
        } while (0)

#if 0
        ADD(dhcpserver);
        ADD(dnsserver);
        ADD(telnetd);
        ADD(rshd);
        ADD(smtp);
        ADD(vncserver);
#endif
        ADD(ftpserver);

        /* print tree to see what was actually added */
        cfg_tree_print(NULL, TE_LL_RING, "/:");
#undef ADD
    }

    TEST_SUCCESS;

cleanup:
    if (result != 0)
        rcf_rpc_server_restart(pco_iut);

    TEST_END;
}

