/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ifconfig_get Retrieving interface information via ifconfig.
 *
 * @objective Check that "ifconfig", "ifconfig -a" and "ifconfig" for
 *            particular device return the same and correct parameters.
 *
 * @param pco_iut   IUT PCO 
 *
 * @par Scenario
 * -# Retrieve list of network interfaces on the @p pco_iut host 
 *    using "ifconfig -a".
 * -# Retrieve list of network interfaces using "ifconfig".
 * -# For each interface from the list:
 *   -# Check that information retrieved using "ifconfig" and "ifconfig -a"
 *      is the same (IP address, mask, broadcast address, MAC address,
 *      flags and MTU).
 *   -# Retrieve information about the interface using "ifconfig" with
 *      interface name as a parameter and check that the information 
 *      is the same as returned by "ifconfig" without parameters.
 *   -# Retrieve information about the interface using @b ioctl() and
 *      verify that it's the same as information returned by "ifconfig".
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ifconfig_get"

#include "sockapi-test.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"
#include "net/if.h"
#include "ifconfparse.h"

#define IFLIST_LEN   1000
#define MAX_NAME_LEN 100

static char iflist[IFLIST_LEN];
static char iflist_a[IFLIST_LEN];

static if_info info_a;
static if_info info;

/** Compare output of different ifconfig calls */
static void
if_info_compare(char *name)
{
    if (info.ip.s_addr != info_a.ip.s_addr)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "IP addresses for %s", name);
    if (info.bcast.s_addr != info_a.bcast.s_addr)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "broadcast addresses for %s", name);
    if (info.mask.s_addr != info_a.mask.s_addr)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "masks for %s", name);
    if (info.mtu != info_a.mtu)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "MTU for %s", name);
    if (info.flags != info_a.flags)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "flags for %s", name);
    if (memcmp(info.mac, info_a.mac, ETHER_ADDR_LEN) != 0)
        TEST_FAIL("'ifconfig -a' and 'ifconfig' returned different "
                  "LL addresses for %s", name);
}

int
main(int argc, char *argv[])
{ 
    rcf_rpc_server *pco_iut = NULL;
    
    const struct if_nameindex *iut_ifname = NULL;
    
    int   iflist_a_len;
    int   iflist_len;
    int   count;
    char *ifconfig       = NULL;
    char *ifconfig_a     = NULL;
    char *name, *name_a;

    os_t        os;             /**< TA OS type */       
    char const *ifconfig_cmd;   /**< TA 'ifconfig' command string */
    char const *ifconfig_a_cmd; /**< TA 'ifconfig -a' command string */
    
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_IF(iut_ifname);

    /* 
     * Change configuration - delete all addresses except one on
     * 'iut_if' interfaces. Since ioctl with (SIOCGxxx)/(SIOCSxxx)
     * is incompatible with netlink (RTM_GETADDR)/(RTM_NEWADDR) 
     * messages output, it is the only chance for test to pass.
     */
    CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta,
                                           iut_ifname->if_name, NULL));

    switch(os = OS(pco_iut))
    {
        case OS_LINUX:
            ifconfig_cmd    = "ifconfig";
            ifconfig_a_cmd  = "ifconfig -a";
            break;
        case OS_SOLARIS:
            ifconfig_cmd    = "/sbin/ifconfig -au";
            ifconfig_a_cmd  = "/sbin/ifconfig -a";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

    rpc_shell_get_all(pco_iut, &ifconfig_a, ifconfig_a_cmd, -1);
    rpc_shell_get_all(pco_iut, &ifconfig, ifconfig_cmd, -1);

    iflist_a_len = iflist_len = IFLIST_LEN;
    CHECK_RC(get_iflist(ifconfig_a, iflist_a, &iflist_a_len, os));
    CHECK_RC(get_iflist(ifconfig,   iflist,   &iflist_len, os));

    count = iflist_a_len;
    name = iflist;
    name_a = iflist_a;

    while (1)
    {
        te_errno rc;

        struct sockaddr_in *addr = NULL;
        struct sockaddr    *ll_addr = NULL;
        
        int mtu, prefix, status;
        
        if (count <= 0)
            break;
            
        memset(&info_a, 0, sizeof(info_a));
        CHECK_RC(get_if_info(name_a, ifconfig_a, &info_a, os));
        
        if (strchr(name_a, ':') != NULL) /* Alias */
            goto if_info;
        
        rc = cfg_get_instance_fmt(NULL, &status,
                                  "/agent:%s/interface:%s/status:",
                                  pco_iut->ta, name_a);
        
        if (rc != 0)
        {
            if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
                TEST_FAIL("cfg_get_instance() failed with error %r", rc);
            
            /* This interface is not accessible for this configuration */
            RING("Interface %s not accessible for the configuration "
                 "is not validated via CS", name_a); 
            goto if_info;
        }
        
        if (status != (int)(info_a.flags & IFF_UP))
            TEST_FAIL("Incorrect flags on the interface %s", name_a);

        CHECK_RC(cfg_get_instance_fmt(NULL, (void *)&mtu,
                                      "/agent:%s/interface:%s/mtu:",
                                      pco_iut->ta, name_a));

        if (info_a.mtu != mtu)
            TEST_FAIL("Incorrect MTU on the interface %s", name_a);

        CHECK_RC(cfg_get_instance_fmt(NULL, (void *)&ll_addr,
                          "/agent:%s/interface:%s/link_addr:",
                          pco_iut->ta, name_a));
                          
        if (memcmp(info_a.mac, ll_addr->sa_data, ETHER_ADDR_LEN) != 0)
            TEST_FAIL("Incorrect LL address on the interface %s", name_a);

        free(ll_addr);
        ll_addr = NULL;
        
        if (strcmp(name_a, iut_ifname->if_name) != 0)
            goto if_info;

        if ((rc = cfg_get_instance_fmt(NULL, (void *)&addr,
                 "/agent:%s/interface:%s/net_addr:%s/broadcast:",
                 pco_iut->ta, name_a, inet_ntoa(info_a.ip))) != 0) 
        {
            if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
                TEST_FAIL("cfg_get_instance() failed with error %r", rc);
        }
        else if (addr->sin_addr.s_addr != info_a.bcast.s_addr)
        {
            TEST_FAIL("Incorrect broadcast address on the interface %s",
                      name_a);
        }
        free(addr);
        addr = NULL;

        CHECK_RC(cfg_get_instance_fmt(NULL, &prefix,
                 "/agent:%s/interface:%s/net_addr:%s",
                 pco_iut->ta, name_a, inet_ntoa(info_a.ip)));

        if ((uint32_t)PREFIX2MASK(prefix) != ntohl(info_a.mask.s_addr))
            TEST_FAIL("Incorrect mask on the interface %s", name_a);

if_info:
        memset(&info, 0, sizeof(info));
        if ((rc = retrieve_if_info(pco_iut, name_a, &info, os)) != 0)
            TEST_FAIL("retrieve_if_info() failed with error %r", rc);
            
        if_info_compare(name_a);

        rc = get_if_info(name_a, ifconfig, &info, os);
        if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        {
            count -= (strlen(name_a) + 1);
            name_a += strlen(name_a) + 1;
            continue;
        }
        if (rc)
            TEST_FAIL("Function get_if_info failed with error %r", rc);
            
        if_info_compare(name_a);
            
        count -= (strlen(name) + 1);
        name += strlen(name) + 1;
        name_a += strlen(name_a) + 1;
    }
    
    TEST_SUCCESS;

cleanup:
    free(ifconfig_a);
    free(ifconfig);

    TEST_END;
}
