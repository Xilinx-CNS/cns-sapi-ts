/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-telnet_client TELNET client use case
 *
 * @objective Check that TELNET client can connect to the TELNET server,
 *            login and execute the command.
 *
 * @param pco_iut    IUT PCO for the TELNET client
 * @param pco_tst1   tester PCO for the TELNET server
 * @param pco_tst2   tester PCO for the additional TELNET server
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Enable telnet daemon on the @p pco_tst1 and @p pco_tst2.
 * -# All user "tester" with password "tester" on the @p pco_tst1 and @p pco_tst2.
 * -# Spawn commands
@htmlonly
<pre>telnet &lt;pco_tst1 IP address&gt;</pre>
<pre>telnet &lt;pco_tst2 IP address&gt;</pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Connect to the standard input of telnet processes, login to the
 *    server as user tester and logout.
 * -# Disable telnetd on the @p pco_tst1 and @p pco_tst2.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Delete user "tester" on the @p pco_tst1 and @p pco_tst2.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/telnet_client"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "tapi_tad.h"
/*
 * FIXME: test is broken - tcl/expect functionality has been disabled, see:
 * OL bug 10742.
 */
#include "tapi_cli.h"
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

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    for (srv = pco_tst, srv_addr = tst_addr;
         ;
         srv = pco_tst2, srv_addr = tst2_addr)
    {
        csap_handle_t handle;

        TEST_CHECK_SERVICE(srv->ta, telnetd);

        USER_CREATE(srv->ta);
        CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                                      "/agent:%s/telnetd:", srv->ta));
        SLEEP(2);

        TELNET_LOGIN(pco_iut, te_sockaddr_get_ipstr(srv_addr), handle);
        TELNET_LOGOUT(pco_iut, handle);
        if (result == -1)
            TEST_STOP;

        if (srv == pco_tst2)
            break;
    }

    TEST_SUCCESS;

cleanup:

    TEST_END;
}

