/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-vnc_client VNC client
 *
 * @objective Check that VNC client is able to connect to VNC server.
 *
 * @param pco_iut    IUT PCO for the VNC viewer
 * @param pco_tst1   tester PCO for the VNC server
 * @param pco_tst2   tester PCO for the additional VNC server
 * @param library    transport library to be used on the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Start
 * \n vncserver :50
 * \n on the @p pco_tst1 and @p pco_tst2.
 * -# Start
 * \n Xvfb :60 -ac
 * \n on the @p pco_iut.
 * -# Copy file with VNC password to /tmp/te_tester_vnc_passwd on
 *    the @p pco_iut.
 * -# Execute commands
@htmlonly
<pre>
DISPLAY=&lt;pco_iut IP address&gt;:60
    vncviewer &lt;pco_tst1 IP address&gt;:50 -passwd /tmp/te_tester_vnc_passwd</pre>
DISPLAY=&lt;pco_iut IP address&gt;:60
    vncviewer &lt;pco_tst2 IP address&gt;:50 -passwd /tmp/te_tester_vnc_passwd</pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Check that string "onnected to" appears in output of all commands.
 * -# Kill vncserver on @p pco_tst1 and @p pco_tst2.
 * -# Kill Xvfb on @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @note It is assumed that Xvfb may be found in @c $PATH.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/vnc_client"

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
    const struct sockaddr *clnt_addr;

    cfg_handle handle;
    char      *passwd = NULL;
    char      *log = NULL;
    char      *addr = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    USER_CREATE(pco_iut->ta);

    XVFB_ADD(pco_iut->ta);

    for (srv = pco_tst, srv_addr = tst_addr, clnt_addr = iut_addr;
         ;
         srv = pco_tst2, srv_addr = tst2_addr, clnt_addr = iut_addr2)
    {
        int pid;

        TEST_CHECK_SERVICE(srv->ta, vnc_passwd);

        addr = strdup(te_sockaddr_get_ipstr(srv_addr));

        VNCSERVER_ADD(srv->ta);

        CHECK_RC(cfg_get_instance_fmt(NULL, &passwd,
                                      "/agent:%s/vncpasswd:", srv->ta));

        CHECK_RC(tapi_file_create_ta(pco_iut->ta, USER_HOME "/vnc_passwd",
                                     "%s", passwd));

        SLEEP(2);
        pid = rpc_te_shell_cmd(pco_iut,
                "DISPLAY=%s:%d vncviewer %s:%d -passwd %s/vnc_passwd"
                " -shared >%s/vnc_log 2>&1",
                -1, NULL, NULL, NULL,
                te_sockaddr_get_ipstr(clnt_addr), X_SERVER_NUMBER, addr,
                VNC_SERVER_NUMBER, USER_HOME, USER_HOME);

        SLEEP(2);
        rpc_kill(pco_iut, pid, 0);

        if (tapi_file_read_ta(pco_iut->ta, USER_HOME "/vnc_log", &log) != 0)
            TEST_STOP;

        if (strstr(log, "onnected to") == NULL)
            TEST_FAIL("Cannot find string \"onnected to\" "
                      "in the VNC viewer output: %s", log);

        if (srv == pco_tst2)
            break;

        free(log); log = NULL;

        CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc, 1,
                             FALSE, RCF_STRING, USER_HOME "/vnc_passwd"));

        CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc, 1,
                             FALSE, RCF_STRING, USER_HOME "/vnc_log"));

        free(passwd); passwd = NULL;
    }

    TEST_SUCCESS;

cleanup:
    free(passwd);
    free(log);

    SLEEP(1); /* To get all logs from shell commands */
    TEST_END;
}
