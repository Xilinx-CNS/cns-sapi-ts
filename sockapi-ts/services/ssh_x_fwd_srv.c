/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_x_fwd_srv SSH X forwarding on the server side
 *
 * @objective Check that SSH performs X forwarding properly on the server side.
 *
 * @param pco_iut    IUT PCO for the SSH server 
 * @param pco_tst1   PCO for the SSH client and X server
 * @param pco_tst2   tester PCO for the additional SSH client and X server
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_iut and @p pco_tst1.
 *
 * @pre X forwarding should be enabled in sshd configuration file on the
 *      @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Choose unused port @p P on the @p pco_iut.
 * -# Start 
@htmlonly
<pre>/usr/sbin/sshd -p P </pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Start 
 * \n Xvfb :50 -ac
 * \n on the @p pco_tst1 and @p pco_tst2.
 * -# Create user te_tester with home directory /tmp/te_tester
 *    on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Generate public and private keys for user te_tester on the @p pco_tst1
 *    the using command
@htmlonly
<pre>ssh-keygen -t dsa -N "" -f /tmp/te_tester/.ssh/id_dsa</pre>
@endhtmlonly
 * -# Put public key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/authorized_keys on the @p pco_iut.
 * -# Put private key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/id_dsa on the @p pco_tst2.
 * -# Fork @p pco_tst3 from the @p pco_tst1 and @p pco_tst4 from @p pco_tst2.
 * -# Execute command
@htmlonly
<pre>ssh -o StrictHostKeyChecking=no &lt;pco_iut IP address&gt; -p P
          "xterm -display &lt;pco_tstN IP address&gt;:50 -e 
          'sleep 5; touch /tmp/ssh_x_fwd.N'"</pre>
@endhtmlonly
 * on all tester PCOs simultaneously.
 * @p N should be unique for each command.
 * -# Check that all files are successfully created on the @p pco_iut
 *    and remove them.
 * -# Kill Xvfb on @p pco_iut.
 * -# Kill sshd on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Delete user te_tester from @p pco_iut, @p pco_tst1 and @p pco_tst2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ssh_x_fwd_srv"

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
    
    cfg_handle handle;
    uint16_t   port;
    int        i;
    
    rcf_rpc_server *pcos[] = { NULL, NULL, NULL, NULL };
    char           *iut_addrs[] = { NULL, NULL, NULL, NULL };
    char           *tst_addrs[] = { NULL, NULL, NULL, NULL };
    char           *names[] = { NULL, NULL, NULL, NULL };
    tarpc_pid_t     pid[] = { -1, -1, -1, -1 };
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    
    USER_CREATE(pco_iut->ta);
    USER_CREATE(pco_tst->ta);
    USER_CREATE(pco_tst2->ta);

    pcos[0] = pco_tst;
    pcos[1] = pco_tst2;

    if (tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa.pub",
                          pco_iut->ta, 
                          USER_HOME "/.ssh/authorized_keys") != 0 ||
        tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa",
                          pco_tst2->ta, USER_HOME "/.ssh/id_dsa") != 0 ||
        tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa.pub",
                          pco_tst2->ta, USER_HOME "/.ssh/id_dsa.pub") != 0) 
    {
        TEST_STOP;
    }

    port = ntohs(te_sockaddr_get_port(iut_addr));
    if (cfg_add_instance_fmt(&handle, CVT_NONE, NULL, 
                             "/agent:%s/sshd:%d", pco_iut->ta, port) != 0)
    {
        TEST_FAIL("Cannot configure sshd with port %d on the TA %s",
                  port, pco_iut->ta);
    }

    XVFB_ADD(pco_tst->ta);
    XVFB_ADD(pco_tst2->ta);
    SLEEP(5);

    /* Addresses should be the same for processes on the one host */
    iut_addrs[0] = iut_addrs[2] = strdup(te_sockaddr_get_ipstr(iut_addr));
    iut_addrs[1] = iut_addrs[3] = strdup(te_sockaddr_get_ipstr(iut_addr2));

    tst_addrs[0] = tst_addrs[2] = strdup(te_sockaddr_get_ipstr(tst_addr));
    tst_addrs[1] = tst_addrs[3] = strdup(te_sockaddr_get_ipstr(tst2_addr));

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_dup", pcos + 2));
    CHECK_RC(rcf_rpc_server_fork(pco_tst2, "tst2_dup", pcos + 3));
    
    for (i = 0; i < 4; i++)
    {
        char filename[RCF_MAX_PATH];

        MSLEEP(500);
        sprintf(filename, "/tmp/%s", tapi_file_generate_name());
        names[i] = strdup(filename);

        pid[i] = rpc_te_shell_cmd(pcos[i], 
             "HOME=" USER_HOME " DISPLAY=\":%d\" "
             "ssh -o StrictHostKeyChecking=no %s -X -p %d "
             "xterm -e \"/bin/sh -c \\\"sleep 5; touch %s\\\"\"", 
             USER_UID, NULL, NULL, NULL,
             X_SERVER_NUMBER, iut_addrs[i], port, names[i]);
    }

    for (i = 0; i < 4; i++)
    {
        pcos[i]->timeout += 5000;
        rpc_waitpid(pcos[i], pid[i], NULL, 0);
        pid[i] = -1;
        CHECK_RC(rcf_ta_call(pco_iut->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                             RCF_STRING, names[i]));
                             
        free(names[i]);
        names[i] = NULL;

        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_FAIL("ssh/xterm command did not have effect: "
                      "no file is created");
                      
        if (rc != 0)
            TEST_FAIL("ta_rtn_unlink() returned %X", rc);
    }

    TEST_SUCCESS;

cleanup:
    XVFB_DEL(pco_tst->ta);
    XVFB_DEL(pco_tst2->ta);

    for (i = 0; i < 4; i++)
    {
        if (names[i] != NULL)
        {
            rcf_ta_call(pcos[i]->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                        RCF_STRING, names[i]); 
            free(names[i]);
        }
        if (pid[i] > 0)
            rpc_ta_kill_death(pcos[i], pid[i]);
    }

    if (pcos[2] != NULL)
    {
        if (rcf_rpc_server_destroy(pcos[2]) < 0)
            ERROR("Failed to destroy forked RPC server on the %s", 
                  pco_tst->ta);
    }

    if (pcos[3] != NULL)
    {
        if (rcf_rpc_server_destroy(pcos[3]) < 0)
            ERROR("Failed to destroy forked RPC server on the %s", 
                  pco_tst2->ta);
    }
    
    free(iut_addrs[0]);
    free(iut_addrs[1]);
    free(tst_addrs[0]);
    free(tst_addrs[1]);
    
    TEST_END;
}

