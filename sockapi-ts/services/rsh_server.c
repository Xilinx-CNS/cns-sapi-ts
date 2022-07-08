/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-rsh_server RSH server use case
 *
 * @objective Check that RSH server may accept connections from the clients
 *            and execute the commands.
 *
 * @param pco_iut    IUT PCO for the RSH server
 * @param pco_tst1   tester PCO for the RSH client
 * @param pco_tst2   tester PCO for the additional RSH client
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_iut and @p pco_tst1.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Enable rsh daemon  on the @p pco_iut.
 * -# Create user te_tester with home directory /tmp/te_tester
 *    on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Create .rhost file in /tmp/te_tester:
 * \n &lt;pco_tst1 IP&gt; te_tester
 * \n &lt;pco_tst2 IP&gt; te_tester
 * \n on the @p pco_iut.
 * -# Fork @p pco_tst3 from the @p pco_tst1 and @p pco_tst4 from @p pco_tst2.
 * -# As te10000, execute command
@htmlonly
<pre>rsh &lt;pco_iut IP address&gt; "sleep 5; whoami"</pre>
@endhtmlonly
 * on all tester PCOs simultaneously.
 * -# Wait 5 seconds.
 * -# Check that the commands output is "te_tester".
 * -# Disable rshd on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove user te_tester on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/rsh_server"

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

    char           *addr = NULL;
    char           *addr2 = NULL;
    char           *tst_ip = NULL;
    char           *tst2_ip = NULL;
    rcf_rpc_server *pco_tst_dup = NULL;
    rcf_rpc_server *pco_tst2_dup = NULL;

    int             fd[]  = { -1, -1, -1, -1 };
    tarpc_pid_t     pid[] = { -1, -1, -1, -1 };
    rcf_rpc_server *pcos[4];
    char           *addrs[] = { NULL, NULL, NULL, NULL };

    char const *cmd;
    int         i;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_CHECK_SERVICE(pco_iut->ta, rshd);

    switch(OS(pco_iut))
    {
        case OS_LINUX:
            cmd = "rsh %s \"sleep 5; whoami\"";
            break;
        case OS_SOLARIS:
            cmd = "rsh %s \"sleep 5; /usr/ucb/whoami\"";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

    USER_CREATE(pco_iut->ta);
    USER_CREATE(pco_tst->ta);
    USER_CREATE(pco_tst2->ta);

    addr = strdup(te_sockaddr_get_ipstr(iut_addr));
    addr2 = strdup(te_sockaddr_get_ipstr(iut_addr2));
    tst_ip = strdup(te_sockaddr_get_ipstr(tst_addr));
    tst2_ip = strdup(te_sockaddr_get_ipstr(tst2_addr));

    /* Restart service on the IUT */
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                  "/agent:%s/rshd:", pco_iut->ta));
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                                  "/agent:%s/rshd:", pco_iut->ta));
    CHECK_RC(tapi_file_create_ta(pco_iut->ta, USER_HOME "/.rhosts",
                                 "%s " USER_NAME "\n%s " USER_NAME "\n",
                                 tst_ip, tst2_ip));

    CHECK_RC(rcf_rpc_server_fork(pco_tst, "tst_dup", &pco_tst_dup));
    CHECK_RC(rcf_rpc_server_fork(pco_tst2, "tst2_dup", &pco_tst2_dup));

    SLEEP(1);

    pcos[0] = pco_tst;
    pcos[1] = pco_tst2;
    pcos[2] = pco_tst_dup;
    pcos[3] = pco_tst2_dup;
    addrs[0] = addrs[2] = addr;
    addrs[1] = addrs[3] = addr2;

    for (i = 0; i < 4; i++)
        pid[i] = rpc_te_shell_cmd(pcos[i], cmd, USER_UID,
                                     NULL, &fd[i], NULL, addrs[i]);

    for (i = 0; i < 4; i++)
        CHECK_WHOAMI_OUTPUT(pcos[i], fd[i], pid[i]);

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

