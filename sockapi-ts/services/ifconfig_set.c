/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ifconfig_set  Configuring interfaces via "ifconfig"
 *
 * @objective Check that interface parameters may be changed using "ifconfig".
 *
 * @param pco_iut   IUT PCO 
 * @param pco_tst   Tester PCO
 *
 * @par Scenario
 * -# Choose the interface @p i connected to the @p pco_tst host.
 * -# Change IP address, network mask, broadcast address, MTU and
 *    administrative status of the @p i using "ifconfig".
 * -# Check that parameters are really changed using "ifconfig @p i"
 *    and @b ioctl().
 * -# Restore interface configuration.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ifconfig_set"

#include "sockapi-test.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "tapi_cfg_base.h"
#include "services.h"
#include "ifconfparse.h"

/** Auxiliary buffer */
static char aux_buf[RPC_SHELL_CMDLINE_MAX];

int
main(int argc, char *argv[])
{
    const struct if_nameindex *iut_ifname = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    
    char *tmp = aux_buf;
    int   prefix, mtu, status;
    
    struct if_info info0;
    struct if_info info;
    
    struct sockaddr_in *addr = NULL;

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
            ifconfig = "/sbin/ifconfig";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

    /* 
     * Change configuration - delete all addresses except one on
     * 'iut_if' interfaces. Since ioctl with (SIOCGxxx)/(SIOCSxxx)
     * is incompatible with netlink (RTM_GETADDR)/(RTM_NEWADDR) 
     * messages output, it is the only chance for test to pass.
     */
    CHECK_RC(tapi_cfg_del_if_ip4_addresses(pco_iut->ta,
                                           iut_ifname->if_name, NULL));

    if (retrieve_if_info(pco_iut, iut_ifname->if_name, &info0, os) != 0)
        TEST_STOP;
        
    /* 
     * Change all interface parameters via Configurator to provoke
     * restoring of old ones in the case of test failure.
     */
    CHECK_RC(cfg_del_instance_fmt(FALSE, 
                                  "/agent:%s/interface:%s/net_addr:%s",
                                  pco_iut->ta, iut_ifname->if_name,
                                  inet_ntoa(info0.ip)));

    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, info0.mtu - 100),
                                  "/agent:%s/interface:%s/mtu:", 
                                  pco_iut->ta, iut_ifname->if_name));
    CHECK_RC(cfg_get_instance_sync_fmt(NULL, &mtu,
                                       "/agent:%s/interface:%s/mtu:", 
                                       pco_iut->ta,
                                       iut_ifname->if_name));
    if (mtu != info0.mtu - 100)
        TEST_FAIL("Set via Configurator succeed, "
                  "but it does not make an effect");
    
    CHECK_RC(cfg_set_instance_fmt(CFG_VAL(INTEGER, 0), 
                                  "/agent:%s/interface:%s/status:", 
                                  pco_iut->ta, iut_ifname->if_name));
    TAPI_WAIT_NETWORK;

    /* Change parameters via ifconfig to old ones */
    tmp += sprintf(tmp, "%s %s %s ", ifconfig, iut_ifname->if_name,
                   inet_ntoa(info0.ip));
    tmp += sprintf(tmp, "netmask %s ",  inet_ntoa(info0.mask));
    tmp += sprintf(tmp, "broadcast %s ", inet_ntoa(info0.bcast));

    if (os == OS_LINUX)
        tmp += sprintf(tmp, "mtu %d ", info0.mtu);

    tmp += sprintf(tmp, "up >/dev/null");
    rpc_system(pco_iut, aux_buf);
    TAPI_WAIT_NETWORK;

    /* Synchronize configurator database */
    CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s/interface:%s",
                                 pco_iut->ta, iut_ifname->if_name));

    /* 
     * Check that interface parameters are changed from ifconfig
     * point of view.
     */
    if (retrieve_if_info(pco_iut, iut_ifname->if_name, &info, os) != 0)
        TEST_STOP;
     
    if (info0.ip.s_addr != info.ip.s_addr)
        TEST_FAIL("IP address is not really updated by 'ifconfig'");

    if (info0.mask.s_addr != info.mask.s_addr)
        TEST_FAIL("Mask is not really updated by 'ifconfig'");

    if (info0.bcast.s_addr != info.bcast.s_addr)
        TEST_FAIL("Broadcast address is not really updated by 'ifconfig'");
    
    if (os == OS_LINUX)
        if (info0.mtu != info.mtu)
            TEST_FAIL("MTU is not really updated by 'ifconfig'");

    if (info0.flags != info.flags)
        TEST_FAIL("Status is not really updated by 'ifconfig'");
     
    /* 
     * Check that interface parameters are changed from Configurator
     * point of view.
     */
    rc = cfg_get_instance_fmt(NULL, &addr,
             "/agent:%s/interface:%s/net_addr:%s/broadcast:",
             pco_iut->ta, iut_ifname->if_name, inet_ntoa(info.ip));
             
    if (rc != 0)
    {
        if (TE_RC_GET_ERROR(rc) != TE_ENOENT)
            TEST_FAIL("cfg_get_instance() failed for broadcast address"
                      " with rc %x", rc);
            
         TEST_FAIL("IP address is not really updated by 'ifconfig'");
    }
    
    if (addr->sin_addr.s_addr != info.bcast.s_addr)
    {
        ERROR("broadcast for ifconfig %s",
              inet_ntop(AF_INET, &(info.bcast.s_addr),
                        aux_buf, sizeof(aux_buf)));
        ERROR("broadcast for cfg_get_instance_fmt %s",
              inet_ntop(AF_INET, &(addr->sin_addr.s_addr),
                        aux_buf, sizeof(aux_buf)));
        
        TEST_FAIL("Broadcast address is not really updated by 'ifconfig'");
    }

    CHECK_RC(cfg_get_instance_fmt(NULL, &prefix,
             "/agent:%s/interface:%s/net_addr:%s",
             pco_iut->ta, iut_ifname->if_name, inet_ntoa(info.ip)));

    if ((uint32_t)PREFIX2MASK(prefix) != ntohl(info.mask.s_addr))
         TEST_FAIL("Mask is not really updated by 'ifconfig'");

    CHECK_RC(cfg_get_instance_fmt(NULL, &mtu,
                                  "/agent:%s/interface:%s/mtu:", 
                                  pco_iut->ta, iut_ifname->if_name));
    
    if (mtu != info.mtu)
        TEST_FAIL("MTU is not really updated by 'ifconfig'");

    CHECK_RC(cfg_get_instance_fmt(NULL, &status,
                                  "/agent:%s/interface:%s/status:", 
                                  pco_iut->ta, iut_ifname->if_name));
    
    if (status != 1)
         TEST_FAIL("Interface status is not really updated by 'ifconfig'");
         
    TEST_SUCCESS;

cleanup:
    free(addr);

    /* Synchronize state before automatic CS restoring */
    CLEANUP_CHECK_RC(cfg_synchronize_fmt(TRUE, "/agent:%s/interface:%s",
                                         pco_iut->ta, iut_ifname->if_name));

    TEST_END;
}
