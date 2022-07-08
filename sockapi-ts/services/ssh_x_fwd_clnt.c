/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_x_fwd_clnt SSH X forwarding on the client side
 *
 * @objective Check that SSH performs X forwarding properly on the client side.
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
 * \n on the @p pco_iut.
 * -# Create user te_tester with home directory /tmp/te_tester 
 *    on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Generate public and private keys for user te_tester on the @p pco_iut
 *    using command
@htmlonly
<pre>ssh-keygen -t dsa -N "" -f /tmp/te_tester/.ssh/id_dsa</pre>
@endhtmlonly
 * -# Put public key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/authorized_keys on the @p pco_tst1 and @p pco_tst2.
 * -# Execute commands
@htmlonly
<pre>ssh -o StrictHostKeyChecking=no &lt;pco_tstN IP address&gt; -p P
          "xterm -display &lt;pco_iut IP address&gt;:50 -e touch /tmp/ssh_x_fwd"</pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Check that files are successfully created on the @p pco_tst1 and
 *    @p pco_tst2 and remove them.
 * -# Kill Xvfb on @p pco_iut.
 * -# Kill sshd on the @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Delete user te_tester from @p pco_iut, @p pco_tst1 and @p pco_tst2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ssh_x_fwd_clnt"

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
    cfg_handle             handle;
    
    char       *addr = NULL;
    tarpc_pid_t pid = -1;
    
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

    SLEEP(5);

    for (srv = pco_tst, srv_addr = tst_addr;
         ;
         srv = pco_tst2, srv_addr = tst2_addr)
    {
        uint16_t port = ntohs(te_sockaddr_get_port(srv_addr));
        char     filename[RCF_MAX_PATH];
        
        free(addr);
        addr = strdup(te_sockaddr_get_ipstr(srv_addr));
        
        sprintf(filename, "/tmp/%s", tapi_file_generate_name());
    
        USER_CREATE(srv->ta);
        
        if (cfg_add_instance_fmt(&handle, CVT_NONE, NULL, 
                                 "/agent:%s/sshd:%d",
                                 srv->ta, port) != 0)
        {
            TEST_FAIL("Cannot configure sshd with port %d on the TA %s",
                      port, srv->ta);
        }

        if (tapi_file_copy_ta(pco_iut->ta, USER_HOME "/.ssh/id_dsa.pub",
                              srv->ta, 
                              USER_HOME "/.ssh/authorized_keys") != 0)
        {
            TEST_STOP;
        }

        pid = rpc_te_shell_cmd(pco_iut, 
                "DISPLAY=\":%d\" ssh -o StrictHostKeyChecking=no "
                "%s -X -p %d xterm -e touch %s", 
                USER_UID, NULL, NULL, NULL,
                X_SERVER_NUMBER, addr, port, filename);

        pco_iut->timeout = TE_SEC2MS(100);
        rpc_waitpid(pco_iut, pid, NULL, 0);
        pid = -1;

        CHECK_RC(rcf_ta_call(srv->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                             RCF_STRING, filename));
                             
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
            TEST_FAIL("ssh/xterm command did not have effect: "
                      "no file is created");
                      
        if (rc != 0)
            TEST_FAIL("ta_rtn_unlink() returned %X", rc);

        if (srv == pco_tst2)
            break;
    }

    TEST_SUCCESS;

cleanup:

    XVFB_DEL(pco_iut->ta);

    if (pid > 0)
        rpc_ta_kill_death((rcf_rpc_server *)srv, pid);
    free(addr);

    TEST_END;
}

