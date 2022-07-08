/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-vnc_server VNC server
 *
 * @objective Check that VNC server may act as X server and may accept
 *            connections from VNC client.
 *
 * @param pco_iut    IUT PCO for the VNC server
 * @param pco_tst1   tester PCO for the VNC viewer
 * @param pco_tst2   tester PCO for the additional VNC viewer
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
 * -# Copy file with VNC password to /tmp/te_tester_vnc_passwd 
 *    on the @p pco_tst1 and @p pco_tst2.
 * -# Start 
 * \n vncserver :50 
 * \n on the @p pco_iut.
 * -# Start 
 * \n Xvfb :60 -ac
 * \n on the @p pco_tst1 and @p pco_tst2.
 * -# Fork @p pco_tst3 from the @p pco_tst1 and @p pco_tst4 from @p pco_tst2.
 * -# Execute command
@htmlonly
<pre>
DISPLAY=&lt;pco_tstN IP address&gt;:60 
    vncviewer &lt;pco_iut IP address&gt;:50 -passwd /tmp/te_tester_vnc_passwd</pre>
@endhtmlonly
 * on all tester PCOs simultaneously.
 * -# Check that string "onnected to" appears in output of all commands.
 * -# As te10000, execute command
 * \n DISPLAY=:50 xterm -e "touch /tmp/te_tester/vnc_test.N"
 * on all tester PCOs simultaneously.
 * -# Kill all vncvewers.
 * -# Check that files /tmp/te_tester/vnc_test.N are created on the @p pco_tst1
 *    and @p pco_tst2.
 * -# Kill vncserver on @p pco_iut.
 * -# Kill Xvfb on @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * 
 * @note It is assumed that Xvfb and xterm may be found in @c $PATH.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/vnc_server"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

static char aux_buf[RPC_SHELL_CMDLINE_MAX];

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
    char           *iut_addrs[] = { NULL, NULL, NULL, NULL };
    char           *tst_addrs[] = { NULL, NULL, NULL, NULL };
    

    cfg_handle handle;
    char      *passwd = NULL;
    char      *log = NULL;
    int        i;
    int        pid_viewer[] = { -1, -1, -1, -1 };
    int        pid_client[] = { -1, -1, -1, -1 };

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
    
    pcos[0] = pcos[2] = pco_tst;
    pcos[1] = pcos[3] = pco_tst2;

    TEST_CHECK_SERVICE(pco_iut->ta, vncpasswd);

    /* not sure why this 'add' is here, it's added in prologue? */
    VNCSERVER_ADD(pco_iut->ta);

    CHECK_RC(cfg_get_instance_fmt(NULL, &passwd, 
                                  "/agent:%s/vncpasswd:", pco_iut->ta));
    CHECK_RC(tapi_file_create_ta(pco_tst->ta, USER_HOME "/vnc_passwd", 
                                 "%s", passwd));
    CHECK_RC(tapi_file_create_ta(pco_tst2->ta, USER_HOME "/vnc_passwd", 
                                 "%s", passwd));
                 
    XVFB_ADD(pco_tst->ta);
    XVFB_ADD(pco_tst2->ta);
    SLEEP(2);

    /* Addresses should be the same for processes on the one host */
    iut_addrs[0] = iut_addrs[2] = strdup(te_sockaddr_get_ipstr(iut_addr));
    iut_addrs[1] = iut_addrs[3] = strdup(te_sockaddr_get_ipstr(iut_addr2));

    tst_addrs[0] = tst_addrs[2] = strdup(te_sockaddr_get_ipstr(tst_addr));
    tst_addrs[1] = tst_addrs[3] = strdup(te_sockaddr_get_ipstr(tst2_addr));

    for (i = 0; i < 4; i++)
    {
        snprintf(aux_buf, sizeof(aux_buf),
                "DISPLAY=%s:%d vncviewer %s:%d -passwd %s/vnc_passwd"
                " -shared 2>&1 |tee %s/vnc_log.%d",
                tst_addrs[i], X_SERVER_NUMBER, iut_addrs[i], 
                VNC_SERVER_NUMBER, USER_HOME, USER_HOME, i);
                
        CHECK_RC(rcf_ta_start_task(pcos[i]->ta, 0, 0, "shell", 
                                   pid_viewer + i, 1, TRUE, aux_buf));
    }

    /* Check that VNC server may act as X server */
    for (i = 0; i < 4; i++)
    {
        if (i == 2)
            SLEEP(1);
        pid_client[i] = rpc_te_shell_cmd(pcos[i], 
                 "DISPLAY=%s:%d xterm -e "
                 "\"sleep 5; touch %s/vnc_test.%d\"", 
                 USER_UID, NULL, NULL, NULL,
                 iut_addrs[i], VNC_SERVER_NUMBER, USER_HOME, i);
    }

    /* Check that files are created */
    for (i = 0; i < 4; i++)
    {
        pcos[i]->timeout += 100000;
        rpc_waitpid(pcos[i], pid_client[i], NULL, 0);
        pid_client[i] = -1;
        sprintf(aux_buf, USER_HOME "/vnc_test.%d", i);
        CHECK_RC(rcf_ta_call(pcos[i]->ta, 0, "ta_rtn_unlink", &rc, 1, 
                             FALSE, RCF_STRING, aux_buf));
                             
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_FAIL("xterm command did not have effect: no file is created");
                      
        if (rc != 0)
            TEST_FAIL("ta_rtn_unlink() returned %X", rc);
    }            

    /* Kill all viewers */
    for (i = 0; i < 4; i++)
    {
        if (rcf_ta_kill_task(pcos[i]->ta, 0, pid_viewer[i]) != 0)
        {
            pid_viewer[i] = -1;
            TEST_FAIL("Failed to kill vncviewer task on the %s", pcos[i]->ta);
        }
        pid_viewer[i] = -1;
    }
    
    /* Retrieve the log */
    for (i = 0; i < 4; i++)
    {
        sprintf(aux_buf, USER_HOME "/vnc_log.%d", i);
        if (tapi_file_read_ta(pcos[i]->ta, aux_buf, &log) != 0)
            TEST_STOP;
            
        if (strstr(log, "onnected to") == NULL)
            TEST_FAIL("Cannot find string \"onnected to\" "
                      "in the VNC viewer output: %s", log);
                      
         free(log); log = NULL;                      
    }
    

    TEST_SUCCESS;

cleanup:

    for (i = 0; i < 4; i++)
    {
        if (pid_viewer[i] > 0 && 
            rcf_ta_kill_task(pcos[i]->ta, 0, pid_viewer[i]) != 0)
        {
            ERROR("Failed to kill vncviewer task on the %s", pcos[i]->ta);
            result = -1;
        }

        if (pid_client[i] > 0)
            rpc_ta_kill_death(pcos[i], pid_client[i]);
    }
        
    free(passwd);
    free(log);
    
    TEST_END;
}
