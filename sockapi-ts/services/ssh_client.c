/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_client SSH client use case
 *
 * @objective Check that SSH client can connect to the SSH server, login
 *            and execute a command.
 *
 * @param pco_iut    IUT PCO for the SSH client 
 * @param pco_tst1   tester PCO for the SSH server
 * @param pco_tst2   tester PCO for the additional SSH server
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Choose port @p P, which is not used on the @p pco_tst1 and @p pco_tst2.
 * -# Start 
@htmlonly
<pre>/usr/sbin/sshd -p P </pre>
@endhtmlonly
 * on the @p pco_tst1 and @p pco_tst2.
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
<pre>ssh -o StrictHostKeyChecking=no &lt;pco_tst1 IP address&gt; -p P whoami</pre>
<pre>ssh -o StrictHostKeyChecking=no &lt;pco_tst2 IP address&gt; -p P whoami</pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Check that the commands output is "te_tester".
 * -# Kill sshd on the @p pco_tst1 and @p pco_tst2.
 * -# Remove user te_tester on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ssh_client"

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
    char                  *aux_buf = NULL;
    
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
        uint16_t port = ntohs(te_sockaddr_get_port(srv_addr));
    
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

        rpc_shell_get_all(pco_iut, &aux_buf,
                          "ssh -v -o StrictHostKeyChecking=no "
                          "%s -p %d whoami", USER_UID,
                          te_sockaddr_get_ipstr(srv_addr), port);

        aux_buf[strlen(aux_buf) - 1] = '\0';
        if (strcmp(aux_buf, USER_NAME) != 0)
            TEST_FAIL("ssh command returned %s instead " USER_NAME, aux_buf);

        if (srv == pco_tst2)
            break;
    }

    TEST_SUCCESS;

cleanup:

    free(aux_buf);
    TEST_END;
}

