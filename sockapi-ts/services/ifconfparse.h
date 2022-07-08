/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** 
 * UNIX daemons and utilities 
 * Utities for parsing of ifconfig output
 * 
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __IFCONFPARSE_H__
#define __IFCONFPARSE_H__

#if HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "te_printf.h"
#include "services.h"

/** Structure with interface information */
typedef struct if_info {
    struct in_addr ip;            /**< Unicast IPv4 address */
    struct in_addr bcast;         /**< Broadcast IP address */
    struct in_addr mask;          /**< Network mask */
    uint8_t        mac[ETHER_ADDR_LEN]; /**< Hardware address */
    uint16_t       mtu;           /**< MTU */
    uint64_t       rx_pkts;       /**< Number of received packets */
    uint64_t       tx_pkts;       /**< Number of transmitted packets */
    uint64_t       rx_bytes;      /**< Number of received bytes */
    uint64_t       tx_bytes;      /**< Number of transmitted bytes */
    uint32_t       flags;         /**< Flags, see /usr/include/net/if.h */
} if_info;

#define CHECK_OS(os_)                                  \
    do {                                               \
        if (os_ != OS_LINUX && os_ != OS_SOLARIS)      \
        {                                              \
            if (os_ == OS_FREEBSD)                     \
                ERROR("FreeBSD is not supported yet"); \
        return TE_EINVAL;                              \
        }                                              \
    } while(0)

/**
 * Parse ifconfig output to retrieve information about one interface.
 * (Linux version)
 *
 * @param name  interface name
 * @param buf   buffer with ifconfig output
 * @param info  location for interface information
 * @param os    OS type
 *
 * @return Status code
 */
extern int
get_if_info(char *name, char *buf, if_info *info, os_t os);

/**
 * Parse ifconfig output to retrieve list of interfaces.
 * Interfaces are placed to the buffer specified by the user and
 * separated by '\0'.
 *
 * @param buf           buffer with ifconfig output
 * @param iflist        location for interface list
 * @param iflist_len    length of the @p iflist buffer (IN) and number
 *                      of bytes filled by the information (OUT)
 * @param os            OS type
 *
 * @return 0 (success) or -1 (failure)
 */
extern int 
get_iflist(char *buf, char *iflist, int *iflist_len, os_t os);

/**
 * Call ifconfig command for the interface and parse ifconfig output.
 *
 * @param name  interface name
 * @param info  location for interface information
 * @param os    OS type
 *
 * @return Status code
 */
static inline int 
retrieve_if_info(rcf_rpc_server *rpcs, char *name, if_info *info, os_t os)
{
    char const *cmd_template = (os == OS_LINUX) ? "ifconfig %s" :
                                                  "/sbin/ifconfig %s";
    char       *buf          = NULL;
    int         rc           = -1;

    CHECK_OS(os);

    /* 
     * @todo there is memory leak in the test here. 
     * We should free(buf) if rpc_shell_get_all fails, but we do not do it.
     * In any case, test failed and will exit soon, so we ignore memory leak.
     */
    rpc_shell_get_all(rpcs, &buf, cmd_template, -1, name);

    if ((rc = get_if_info(name, buf, info, os)) != 0)
    {
       free(buf);
       ERROR("Cannot find information about interface %s using ifconfig", 
             name);
       return rc;
    }
    free(buf);
   
    return 0;
}

static inline void
print_if_info(if_info *info)
{
    printf("IP %s\n", inet_ntoa(info->ip));
    printf("Bcast %s\n", inet_ntoa(info->bcast));
    printf("Mask %s\n", inet_ntoa(info->mask));
    printf("RxPkts %" TE_PRINTF_64 "u TxPkts %" TE_PRINTF_64 "u "
           "RxBytes %" TE_PRINTF_64 "u TxBytes %" TE_PRINTF_64 "u\n", 
           info->rx_pkts, info->tx_pkts, info->rx_bytes, info->tx_bytes);
    printf("MTU %u Flags %x\n", info->mtu, info->flags);
    printf("Hw %02x:%02x:%02x:%02x:%02x:%02x\n", 
           info->mac[0], info->mac[1], info->mac[2], info->mac[3], 
           info->mac[4], info->mac[5]);
}

static inline char *
if_info_str(if_info *info)
{
    char  buf[256];
    char *s = buf;
    
    s += sprintf(s, "IP %s\n", inet_ntoa(info->ip));
    s += sprintf(s, "Bcast %s\n", inet_ntoa(info->bcast));
    s += sprintf(s, "Mask %s\n", inet_ntoa(info->mask));
    s += sprintf(s, "RxPkts %" TE_PRINTF_64 "u TxPkts %" TE_PRINTF_64 "u "
                    "RxBytes %" TE_PRINTF_64 "u TxBytes %" TE_PRINTF_64 "u\n", 
                 info->rx_pkts, info->tx_pkts, info->rx_bytes, info->tx_bytes);
    s += sprintf(s, "MTU %u Flags %x\n", info->mtu, info->flags);
    s += sprintf(s, "Hw %02x:%02x:%02x:%02x:%02x:%02x\n", 
                 info->mac[0], info->mac[1], info->mac[2], info->mac[3], 
                 info->mac[4], info->mac[5]);
    
    return strdup(buf);
}

#endif /*  __IFCONFPARSE_H__ */
