/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-rsh_client RSH client use case
 *
 * @objective Check that RSH client can connect to the RSH servers
 *            and execute the command.
 *
 * @param pco_iut    IUT PCO for the RSH client
 * @param pco_tst1   tester PCO for the RSH server
 * @param pco_tst2   tester PCO for the additional RSH server
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_iut and @p pco_tst1.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Enable rsh daemon  on the @p pco_tst1 and @p pco_tst2.
 * -# Create user te_tester with home directory /tmp/te_tester
 *    on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Create .rhost file in /tmp/te_tester:
 * \n &lt;pco_iut IP&gt; te_tester
 * \n on the @p pco_tst1 and @p pco_tst2.
 * -# Otherwise, execute commands
@htmlonly
<pre>rsh &lt;pco_tst1 IP address&gt; whoami</pre>
<pre>rsh &lt;pco_tst2 IP address&gt; whoami</pre>
@endhtmlonly
 *    on the @p pco_iut.
 * -# Check that the commands output is "te_tester".
 * -# Disable rshd on the @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Remove user te_tester on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/rsh_client"

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
    const struct sockaddr *clnt_addr;

    char *aux_buf = NULL;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    USER_CREATE(pco_iut->ta);


    for (srv = pco_tst, clnt_addr = iut_addr;
         ;
         srv = pco_tst2, clnt_addr = iut_addr2)
    {
        TEST_CHECK_SERVICE(srv->ta, rshd);

        USER_CREATE(srv->ta);
        CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1),
                                      "/agent:%s/rshd:", srv->ta));
        CHECK_RC(tapi_file_create_ta(srv->ta, USER_HOME "/.rhosts",
                                     "%s %s\n",
                                     te_sockaddr_get_ipstr(clnt_addr),
                                     USER_NAME));
        SLEEP(1);
        rpc_shell_get_all(pco_iut, &aux_buf,
                          "rsh %s whoami", USER_UID,
                          te_sockaddr_get_ipstr(tst_addr));

        aux_buf[strlen(aux_buf) - 1] = '\0';
        if (strcmp(aux_buf, USER_NAME) != 0)
            TEST_FAIL("ssh command returned %s instead %s",
                      aux_buf, USER_NAME);

        if (srv == pco_tst2)
            break;
    }

    TEST_SUCCESS;

cleanup:
    free(aux_buf);

    TEST_END;
}

