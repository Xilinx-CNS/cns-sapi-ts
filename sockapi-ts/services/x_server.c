/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-x_server X server/client interaction
 *
 * @objective Check that X client can interact with the X server.
 *
 * @param pco_iut    IUT PCO for the X server
 * @param pco_tst1   tester PCO for the X client 
 * @param pco_tst2   tester PCO for the additional X client 
 * @param library    transport library to be used on the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Create user te_tester with home directory /tmp/te_tester 
 *    on the @p pco_tst1 and @p pco_tst2.
 * -# Start 
 * \n Xvfb :50 -ac
 * \n on the @p pco_iut.
 * -# Fork @p pco_tst3 from the @p pco_tst1 and @p pco_tst4 from @p pco_tst2.
 * -# Execute command
 * \n DISPLAY=<@p pco_iut IP address>:50 xterm -e "sleep 5; touch /tmp/te.x_srv_clnt"
 * \n on all tester PCOs simultaneously.
 * -# Check that all files, which should arise after commands above
 *    arose on corresponding POCs and remove them.
 * -# Kill Xvfb on the @p pco_tst1 and @p pco_tst2.
 * -# Delete user te_tester from @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @note It is assumed that Xvfb and xterm may be found in @c $PATH.
 *       Some Linux distros do not include paths like /usr/X11R6/bin/ 
 *       to @c $PATH in the case of ssh access.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/x_server"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"


int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst2_addr;

    rcf_rpc_server *pcos[] = { NULL, NULL, NULL, NULL };
    char           *addr[] = { NULL, NULL, NULL, NULL };
    char           *names[] = { NULL, NULL, NULL, NULL };
    tarpc_pid_t     pid[] = { -1, -1, -1, -1 };

    cfg_handle handle = CFG_HANDLE_INVALID;
    int        i;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    USER_CREATE(pco_tst->ta);
    USER_CREATE(pco_tst2->ta);

    pcos[0] = pco_tst;
    pcos[1] = pco_tst2;

    XVFB_ADD(pco_iut->ta);
    SLEEP(5);

    /* Addresses should be the same for processes on the one host */
    addr[0] = addr[2] = strdup(te_sockaddr_get_ipstr(iut_addr));
    addr[1] = addr[3] = strdup(te_sockaddr_get_ipstr(iut_addr2));

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_dup", pcos + 2));
    CHECK_RC(rcf_rpc_server_fork(pco_tst2, "tst2_dup", pcos + 3));

    for (i = 0; i < 4; i++)
    {
        char filename[RCF_MAX_PATH];

        if (i == 2)
            SLEEP(1);
        sprintf(filename, "/tmp/%s", tapi_file_generate_name());
        names[i] = strdup(filename);
        
        pid[i] = rpc_te_shell_cmd(pcos[i],
             "DISPLAY=%s:%d xterm -e \"sleep 5; touch %s\"", 
             USER_UID, NULL, NULL, NULL,
             addr[i], X_SERVER_NUMBER, names[i]);
    }

    for (i = 0; i < 4; i++)
    {
        pcos[i]->timeout = pcos[i]->def_timeout + TE_SEC2MS(5);
        rpc_waitpid(pcos[i], pid[i], NULL, 0);
        pid[i] = -1;
        CHECK_RC(rcf_ta_call(pcos[i]->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                             RCF_STRING, names[i]));
                             
        free(names[i]);
        names[i] = NULL;

        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_FAIL("xterm command did not have effect: "
                      "no file is created");
                      
        if (rc != 0)
            TEST_FAIL("ta_rtn_unlink() returned %X", rc);
    }

    TEST_SUCCESS;

cleanup:
    XVFB_DEL(pco_iut->ta);

    for (i = 0; i < 4; i++)
    {
        if (pid[i] > 0)
            rpc_ta_kill_death(pcos[i], pid[i]);
    }
    
    free(addr[0]);
    free(addr[1]);
    
    for (i = 0; i < 4; i++)
    {
        if (names[i] != NULL)
        {
            rcf_ta_call(pcos[i]->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                        RCF_STRING, names[i]); 
            free(names[i]);
        }
    }
        
    TEST_END;
}

