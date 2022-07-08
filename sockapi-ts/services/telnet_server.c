/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * UNIX daemons and utilities
 *
 * $Id$
 */

/** @page services-telnet_server TELNET server use case
 *
 * @objective Check that TELNET server may accept connections from clients.
 *
 * @param pco_iut    IUT PCO for the TELNET server
 * @param pco_tst1   tester PCO for the TELNET client
 * @param pco_tst2   tester PCO for the additional TELNET client
 * @param library    transport library to be used by the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Enable telnet daemon on the @p pco_iut.
 * -# All user "tester" with password "tester" on the @p pco_iut.
 * -# Fork @p pco_tst3 from the @p pco_tst1 and @p pco_tst4 from @p pco_tst2.
 * -# Spawn command
@htmlonly
<pre>telnet &lt;pco_srv IP address&gt;</pre>
@endhtmlonly
 * on all tester PCOs simultaneously.
 * -# Connect to the standard input of telnet processes, login to the
 *    server as user tester and logout.
 * -# Disable telnetd on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 * -# Delete user "tester" on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/telnet_server"

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

    char           *addr = NULL;
    char           *addr2 = NULL;

    csap_handle_t handle[] = { CSAP_INVALID_HANDLE,
                               CSAP_INVALID_HANDLE,
                               CSAP_INVALID_HANDLE,
                               CSAP_INVALID_HANDLE };

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_CHECK_SERVICE(pco_iut->ta, telnetd);

    USER_CREATE(pco_iut->ta);
    USER_CREATE(pco_tst->ta);
    USER_CREATE(pco_tst2->ta);

    addr = strdup(te_sockaddr_get_ipstr(iut_addr));
    addr2 = strdup(te_sockaddr_get_ipstr(iut_addr2));

    /* Restart service on the IUT */
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)0,
                                  "/agent:%s/telnetd:", pco_iut->ta));
    CHECK_RC(cfg_set_instance_fmt(CVT_INTEGER, (void *)1,
                                  "/agent:%s/telnetd:", pco_iut->ta));
    SLEEP(1);

    TELNET_LOGIN(pco_tst, addr, handle[0]);
    TELNET_LOGIN(pco_tst2, addr2, handle[1]);
    TELNET_LOGIN(pco_tst, addr, handle[2]);
    TELNET_LOGIN(pco_tst2, addr2, handle[3]);

    TEST_SUCCESS;

cleanup:
    TELNET_LOGOUT(pco_tst, handle[0]);
    TELNET_LOGOUT(pco_tst2, handle[1]);
    TELNET_LOGOUT(pco_tst, handle[2]);
    TELNET_LOGOUT(pco_tst2, handle[3]);

    free(addr);
    free(addr2);

    TEST_END;
}
