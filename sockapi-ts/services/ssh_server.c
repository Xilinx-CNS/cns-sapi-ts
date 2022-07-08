/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_server SSH server use case
 *
 * @objective Check that SSH server may accept connections from
 *            clients and execute a command.
 *
 * @param pco_iut    IUT PCO for the SSH server
 * @param pco_tst1   tester PCO for the SSH client 
 * @param pco_tst2   tester PCO for the additional SSH client 
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Choose unused port @p P on the @p pco_iut.
 * -# Start 
@htmlonly
<pre>/usr/sbin/sshd -p P </pre>
@endhtmlonly
 * on the @p pco_iut.
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
 * -# As te_tester, execute command
@htmlonly
<pre>ssh -o StrictHostKeyChecking=no &lt;pco_iut IP address&gt; -p P "sleep 5; whoami"</pre>
@endhtmlonly
 * on all tester PCOs simultaneously.
 * -# Wait 5 second.
 * -# Check that the commands output is "te_tester".
 * -# Kill sshd on the @p pco_iut.
 * -# Remove user te_tester on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the PCO, on which it was set.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ssh_server"

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
    
    cfg_handle      handle;
    uint16_t        port;
    char           *addr = NULL;
    char           *addr2 = NULL;
    rcf_rpc_server *pco_tst_dup = NULL;
    rcf_rpc_server *pco_tst2_dup = NULL;
    
    int             fd[] = { -1, -1, -1, -1 };
    tarpc_pid_t     pid[] = { -1, -1, -1, -1 };
    rcf_rpc_server *pcos[] = { NULL, NULL, NULL, NULL };
    char           *addrs[] = { NULL, NULL, NULL, NULL };

    int i;

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
    addr = strdup(te_sockaddr_get_ipstr(iut_addr));
    addr2 = strdup(te_sockaddr_get_ipstr(iut_addr2));
    if (cfg_add_instance_fmt(&handle, CVT_NONE, NULL, 
                             "/agent:%s/sshd:%d", pco_iut->ta, port) != 0)
    {
        TEST_FAIL("Cannot configure sshd with port %d on the TA %s",
                  port, pco_iut->ta);
    }

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_dup", &pco_tst_dup));
    CHECK_RC(rcf_rpc_server_fork(pco_tst2, "tst2_dup", &pco_tst2_dup));

    pcos[0] = pco_tst;
    pcos[1] = pco_tst2;
    pcos[2] = pco_tst_dup;
    pcos[3] = pco_tst2_dup;

    addrs[0] = addrs[2] = addr;
    addrs[1] = addrs[3] = addr2;

    for (i = 0; i < 4; i++)
    {
        pid[i] = rpc_te_shell_cmd(pcos[i],
                "ssh -f -o StrictHostKeyChecking=no %s -p %d whoami", 
                USER_UID, NULL, &fd[i], NULL,
                addrs[i], port);
    }
    
    for (i = 0; i < 4; i++)
    {
        CHECK_WHOAMI_OUTPUT(pcos[i], fd[i], pid[i]);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_tst, fd[0]);
    CLEANUP_RPC_CLOSE(pco_tst2, fd[1]);
    CLEANUP_RPC_CLOSE(pco_tst_dup, fd[2]);
    CLEANUP_RPC_CLOSE(pco_tst2_dup, fd[3]);

    for (i = 0; i < 4; i++)
    {
        if (pid[i] > 0)
            rpc_ta_kill_death(pcos[i], pid[i]);
    }

    if (pco_tst_dup != NULL)
    {
        if (rcf_rpc_server_destroy(pco_tst_dup) < 0)
            ERROR("Failed to destroy forked RPC server on the %s", 
                  pco_tst->ta);
    }

    if (pco_tst2_dup != NULL)
    {
        if (rcf_rpc_server_destroy(pco_tst2_dup) < 0)
            ERROR("Failed to destroy forked RPC server on the %s", 
                  pco_tst2->ta);
    }
    free(addr);
    free(addr2);

    TEST_END;
}

