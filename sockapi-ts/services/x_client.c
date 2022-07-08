/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-x_client X client use case
 *
 * @objective Check that X client can interact with the X server.
 *
 * @param pco_iut    IUT PCO for the X client
 * @param pco_tst1   PCO for the X server
 * @param pco_tst2   tester PCO for the additional X server
 * @param library    transport library to be used on the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Create user te_tester with home directory /tmp/te_tester 
 *    on the @p pco_iut.
 * -# Start 
 * \n Xvfb :50 -ac
 * \n on the @p pco_tst1 and @p pco_tst2.
 * -# Execute commands 
 * \n DISPLAY=<@p pco_tst1 IP address>:50 xterm -e touch /tmp/te.x_client1
 * \n DISPLAY=<@p pco_tst2 IP address>:50 xterm -e touch /tmp/te.x_client2
 * \n on the @p pco_iut.
 * -# Check that /tmp/te.x_client* files arose on corresponding POCs and 
 *    remove them.
 * -# Kill Xvfb on the @p pco_tst1 and @p pco_tst2.
 * -# Delete user te_tester from @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @note It is assumed that Xvfb and xterm may be found in @c $PATH.
 *       Some Linux distros do not include paths like /usr/X11R6/bin/ 
 *       to @c $PATH in the case of ssh access.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/x_client"

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

    const rcf_rpc_server  *srv;
    const struct sockaddr *srv_addr;
    tarpc_pid_t            pid = -1;;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    USER_CREATE(pco_iut->ta);

    for (srv = pco_tst, srv_addr = tst_addr;
         ;
         srv = pco_tst2, srv_addr = tst2_addr)
    {
        cfg_handle handle;
        char       filename[128];
    
        XVFB_ADD(srv->ta);
        SLEEP(5);

        snprintf(filename, sizeof(filename), 
                 "/tmp/%s", tapi_file_generate_name());
        filename[sizeof(filename) - 1] = '\0';

        pid = rpc_te_shell_cmd(pco_iut, 
                               "DISPLAY=%s:%d xterm -e touch %s",
                               USER_UID, NULL, NULL, NULL,
                               te_sockaddr_get_ipstr(srv_addr), 
                               X_SERVER_NUMBER, filename);
        rpc_waitpid(pco_iut, pid, NULL, 0);
        pid = -1;
                 
        CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                             RCF_STRING, filename));

        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_FAIL("xterm command did not have effect: no file is created");
                      
        if (rc != 0)
            TEST_FAIL("ta_rtn_unlink() returned %X", rc);

        if (srv == pco_tst2)
            break;
    }

    TEST_SUCCESS;

cleanup:
    XVFB_DEL(pco_tst->ta);
    XVFB_DEL(pco_tst2->ta);

    if (pid > 0)
        rpc_ta_kill_death((rcf_rpc_server *)srv, pid);
    TEST_END;
}

