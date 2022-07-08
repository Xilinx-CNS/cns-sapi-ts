/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ifconfig_a ifconfig with option "-a"
 *
 * @objective Check that "-a" option has effect for "ifconfig".
 *
 * @param pco_iut   IUT PCO 
 * @param pco_tst   Tester PCO
 *
 * @par Scenario
 * -# Retrieve list of network interfaces using "ifconfig".
 * -# Choose the interface @p i connected to the @p pco_tst host and
 *    disable it.
 * -# Retrieve list of network interfaces using "ifconfig" and verify
 *    that it does not contain @p i.
 * -# Retrieve list of network interfaces using "ifconfig -a" and verify
 *    that it contains @p i.
 * -# Enable @p i.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ifconfig_a"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"
#include "ifconfparse.h"

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_ifname = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    
    te_bool         if_down = FALSE;
    char           *buf = NULL;
    struct if_info  info;

    os_t        os;       /**< TA OS type */
    char const *ifconfig; /**< TA 'ifconfig' command string */

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_ifname);

    switch(os = OS(pco_iut))
    {
        case OS_LINUX:
            ifconfig = "ifconfig";
            break;
        case OS_SOLARIS:
            ifconfig = "/sbin/ifconfig -au";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

    /** Retrieve list of up'ed interfaces */
    rpc_shell_get_all(pco_iut, &buf, ifconfig, -1);

    if (get_if_info(iut_ifname->if_name, buf, &info, os) != 0)
       TEST_FAIL("Cannot find information about interface %s using " 
                 "ifconfig", iut_ifname->if_name);
    free(buf); buf = NULL;

    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0), 
                                  "/agent:%s/interface:%s/status:", 
                                  pco_iut->ta, iut_ifname->if_name));
    if_down = TRUE;

    /** Retrieve list of up'ed interfaces again */
    rpc_shell_get_all(pco_iut, &buf, ifconfig, -1);

    if (get_if_info(iut_ifname->if_name, buf, &info, os) == 0)
       TEST_FAIL("Disabled interface %s is listed in " 
                 "ifconfig output", iut_ifname->if_name);
    free(buf); buf = NULL;

    /** Retrieve list of all interfaces */
    rpc_shell_get_all(pco_iut, &buf, "/sbin/ifconfig -a", -1);
    if (get_if_info(iut_ifname->if_name, buf, &info, os) != 0)
       TEST_FAIL("Cannot find information about disabled interface %s "
                 "using ifconfig with option '-a'", iut_ifname->if_name);

    TEST_SUCCESS;

cleanup:
    if (if_down && pco_iut != NULL && iut_ifname != NULL)
    {
        CLEANUP_CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1), 
                                              "/agent:%s/interface:%s/status:", 
                                              pco_iut->ta,
                                              iut_ifname->if_name));
        CFG_WAIT_CHANGES;
    }

    free(buf);        

    TEST_END;
}
