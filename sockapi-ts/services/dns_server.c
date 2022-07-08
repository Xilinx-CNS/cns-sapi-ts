/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-dns_srv  DNS server functionality
 *
 * @objective Check that DNS server may process DNS client requests and
 *            interact with other DNS servers during processing.
 *
 * @param pco_iut    IUT PCO 
 * @param pco_tst    Tester PCO 
 * @param pco_tst2   Tester PCO 
 * @param library    transport library to be used on the IUT
 * @param name       external domain name for resolving 
 * @param use_tcp    Use TCP to make queries
 *
 * @pre Host with @p pco_iut should have two network interfaces.
 *      One should be connected to the host with @p pco_tst1; other - to
 *      the host with @p pco_tst2.
 *
 * @pre DNS server on the @p pco_iut should be able to access root servers.
 *
 * @par Scenario
 * -# Stop DNS server on the @p pco_iut (if it is running).
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Enable recursion on DNS server and specify IP address of the real
 *    DNS server (found in /etc/resolv.conf of @p pco_iut) as forwarder.
 * -# Add route to real DNS server via @p pco_tst1 on @p pco_iut.
 * -# Start DNS server on the @p pco_iut.
 * -# Use utility dig on @p pco_tst1 and @p pco_tst2 with or without "+tcp"
 *    option (according to "use_tcp" parameter)
 *    and @p pco_iut as DNS server to obtain IP address of @p name.
 * -# Stop DNS server on the @p pco_iut.
 * -# Delete the route added on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Artem V. Andreev <Artem.Andreev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/dns_server"

#include "sockapi-test.h"
#include "tapi_file.h"
#include "services.h"
#include "tapi_cfg_base.h"


/** These macros prevents from cleaning up what is not initialized.
 *  The idea is that a guardian variable is associated with every test
 *  which is set to TRUE after the main action is complete.
 */
#define TEST_ACTION(guardian_, action_) \
    do { \
       CHECK_RC(action_); \
       guardian_ = TRUE; \
    } while(0)

#define TEST_CLEANER(guardian_, action_) \
    do {  \
        if (guardian_) \
        { \
           guardian_ = FALSE; \
           CLEANUP_CHECK_RC(action_); \
        } \
    } while(0)

/* Buffer to use in rpc_shell_get_all(). */
static char *outbuf = NULL;

/**
 * Executes "dig" on a given host.
 * The response is considered ok if it has ANSWER SECTION in the output
 */
static int 
use_dig(rcf_rpc_server *rpc, te_bool use_tcp, const char *name,
        const char *dns)
{
    int   rc;

    rpc_shell_get_all(rpc, &outbuf, "dig @%s %s %s", -1,
                      dns, name, use_tcp ? "+tcp" : "");

    RING("dig output for @%s %s (%s):\n%s", dns, name, 
         use_tcp ? "+tcp" : "-tcp", outbuf);    
    rc = strstr(outbuf, "ANSWER SECTION") == NULL ? 
        TE_RC(TE_TAPI, TE_ENOENT) : 0;
    free(outbuf); outbuf = NULL;
    return rc;
}

int
main(int argc, char *argv[])
{
    cfg_val_type     type = CVT_UNSPECIFIED; 
    const char      *name = NULL; 
    struct sockaddr *forwarder = NULL;
#if 0
    te_bool route_added = FALSE; 
#endif

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;
    te_bool         params_acquired = FALSE;
    te_bool         use_tcp = FALSE;

    const struct sockaddr *iut_addr;
    const struct sockaddr *iut_addr2;
    const struct sockaddr *tst_addr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_STRING_PARAM(name);
    TEST_GET_BOOL_PARAM(use_tcp);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    params_acquired = TRUE;

    TEST_CHECK_SERVICE(pco_iut->ta, dnsserver);

    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0),
                                  "/agent:%s/dnsserver:", pco_iut->ta));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0) ,
                                  "/agent:%s/dnsserver:", pco_tst->ta));

    CHECK_RC(tapi_cfg_sys_set_int(pco_tst->ta, 1, NULL,
                                  "net/ipv4/ip_forward"));

    type = CVT_ADDRESS;
    CHECK_RC(cfg_get_instance_fmt(&type, &forwarder,
                                  "/agent:%s/dns:", pco_tst->ta));
    RING("Obtained DNS forwarder for %s is %s", pco_tst->ta, 
         te_sockaddr_get_ipstr(forwarder));
    CHECK_RC(cfg_set_instance_fmt(type, forwarder,
                                  "/agent:%s/dnsserver:/forwarder:", 
                                  pco_tst->ta));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1),
                                  "/agent:%s/dnsserver:/recursive:", 
                                  pco_tst->ta));
    CHECK_RC(cfg_set_instance_fmt(type, tst_addr,
                                  "/agent:%s/dnsserver:/forwarder:", 
                                  pco_iut->ta));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1),
                                  "/agent:%s/dnsserver:/recursive:", 
                                  pco_iut->ta));

#if 0
    TEST_ACTION(route_added, 
                tapi_cfg_add_route_via_gw(pco_iut->ta, AF_INET, 
                                          te_sockaddr_get_netaddr(forwarder), 
                                          32,
                                          te_sockaddr_get_netaddr(tst_addr)));
#endif
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1),
                                  "/agent:%s/dnsserver:", pco_tst->ta));
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 1),
                                  "/agent:%s/dnsserver:", pco_iut->ta));
    SLEEP(60);
    CHECK_RC(use_dig(pco_iut, use_tcp, name, "127.0.0.1"));
    CHECK_RC(use_dig(pco_tst, use_tcp, name,
                     te_sockaddr_get_ipstr(iut_addr)));
    CHECK_RC(use_dig(pco_tst2, use_tcp, name,
                     te_sockaddr_get_ipstr(iut_addr2)));

    TEST_SUCCESS;

cleanup:

    free(outbuf);
    if (params_acquired)
    {
        CLEANUP_CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0),
                                              "/agent:%s/dnsserver:",
                                              pco_iut->ta));
        CLEANUP_CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0),
                                              "/agent:%s/dnsserver:",
                                              pco_tst->ta));
#if 0
        TEST_CLEANER(route_added, 
                     tapi_cfg_del_route_via_gw(pco_iut->ta, AF_INET, 
                         te_sockaddr_get_netaddr(forwarder), 32,
                         te_sockaddr_get_netaddr(tst_addr)));
#endif
    }
    TEST_END;
}
