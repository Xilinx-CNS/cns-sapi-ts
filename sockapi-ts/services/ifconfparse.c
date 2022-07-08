/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** 
 * UNIX daemons and utilities 
 * Utities for parsing of ifconfig output
 * 
 * @author Yurij M. Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

#include "sockapi-test.h"
#include "ifconfparse.h"
#include "services.h"


/**
 * Parse ifconfig output to retrieve information about one interface.
 *
 * @param name  interface name
 * @param buf   buffer with ifconfig output
 * @param info  location for interface information
 * @param os    OS type
 *
 * @return Status code
 */
int 
get_if_info(char *name, char *buf, if_info *info, os_t os)
{
    char *tmp;
    char *start = buf;
    char *end = NULL;
    
    if (name == NULL || *name == 0 || buf == NULL || info == NULL)
        return TE_EINVAL;

    CHECK_OS(os);

    /* Look for the record corresponding to the interface */
    while (buf != NULL)
    {
        if ((tmp = buf = strstr(buf, name)) == NULL)
            break;
    
        buf += strlen(name);
        if ((tmp == start || *(tmp - 1) == '\n') &&
            os == OS_LINUX ? isspace(*buf) : *buf == ':')
            break;
    }
    
    if (buf == NULL)
        return TE_ENOENT; /* Interface is not found */
    
    /* Look for the end of the record */
    for (end = strchr(buf, '\n'); 
         end != NULL && isspace(*++end);
         end = strchr(end, '\n'));
    
    if (end  != NULL)
        *--end = '\0';
        
    memset(info, 0, sizeof(*info));
    info->bcast.s_addr = 0xFFFFFFFF;
    
    if ((tmp = strstr(buf, os == OS_LINUX ? "HWaddr " : "ether ")) != NULL)
    {
        int i;
        
        tmp += strlen(os == OS_LINUX ? "HWaddr " : "ether ");
        for (i = 0; i < ETHER_ADDR_LEN; i++, tmp++)
            info->mac[i] = strtoul(tmp, &tmp, 16);
    }
    
    if ((tmp = strstr(buf, os == OS_LINUX ? "inet addr:" : "inet ")) != NULL)
        inet_aton(tmp + strlen(os == OS_LINUX ? "inet addr:" : "inet "), &info->ip);
    
    if ((tmp = strstr(buf, os == OS_LINUX ? "Bcast:" : "broadcast ")) != NULL)
        inet_aton(tmp + strlen(os == OS_LINUX ? "Bcast:" : "broadcast "), &info->bcast);

    if (os == OS_LINUX)
    {
        if ((tmp = strstr(buf, "Mask:")) != NULL)
            inet_aton(tmp + strlen("Mask:"), &info->mask);
    }
    else
        if ((tmp = strstr(buf, "netmask ")) != NULL)
        {
            char *tmp2 = tmp + strlen("netmask ");
            info->mask.s_addr = htonl(strtoul(tmp2, &tmp2, 16));
        }

    if ((tmp = strstr(buf, os == OS_LINUX ? "MTU:" : "mtu ")) != NULL)
        info->mtu = atoi(tmp + strlen(os == OS_LINUX ? "MTU:" : "mtu "));

    if (os == OS_LINUX)
    {
        if ((tmp = strstr(buf, "RX packets:")) != NULL)
            info->rx_pkts = strtoull(tmp + strlen("RX packets:"), NULL, 10);

        if ((tmp = strstr(buf, "TX packets:")) != NULL)
            info->tx_pkts = strtoull(tmp + strlen("RX packets:"), NULL, 10);
    
        if ((tmp = strstr(buf, "RX bytes:")) != NULL)
            info->rx_bytes = strtoull(tmp + strlen("RX bytes:"), NULL, 10);

        if ((tmp = strstr(buf, "TX bytes:")) != NULL)
            info->tx_bytes = strtoull(tmp + strlen("TX bytes:"), NULL, 10);
    }

#define GET_FLAG(f_) \
    do {                                                  \
        char *tmp = (os == OS_LINUX) ? #f_ " " : #f_ ","; \
                                                          \
        if (strstr(buf, tmp) != NULL)                     \
            info->flags |= IFF_##f_;                      \
    } while(0)

    GET_FLAG(UP);
    GET_FLAG(BROADCAST);
    GET_FLAG(MULTICAST);
    GET_FLAG(DEBUG);
    GET_FLAG(LOOPBACK);
    GET_FLAG(POINTOPOINT);
    GET_FLAG(NOTRAILERS);
    GET_FLAG(RUNNING);
    GET_FLAG(NOARP);
    GET_FLAG(PROMISC);
    GET_FLAG(ALLMULTI);
    GET_FLAG(MASTER);
    GET_FLAG(SLAVE);
    GET_FLAG(PORTSEL);
    GET_FLAG(AUTOMEDIA);

#undef GET_FLAG

    if (end != NULL)
        *end = '\n';
    
    return 0;
}

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
int 
get_iflist(char *buf, char *iflist, int *iflist_len, os_t os)
{
    char *s = iflist;
    int   rest;
    
    if (buf == NULL || iflist == NULL || iflist_len == NULL ||
        (rest = *iflist_len) <= 0)
    {
        return TE_EINVAL;
    }

    CHECK_OS(os);

    while (*buf != 0)
    {
        char *tmp = buf;
        char c = *tmp;
        int   len;
        
        if (os == OS_LINUX)
            while (c && !isspace(c)) /** Linux-specific check */
                c = *++tmp;
        else
            while (c && c != ':')    /** Solaris-specific check */
                c = *++tmp;
        
        if ((len = tmp - buf) >= rest)
            return TE_ESMALLBUF;
            
        memcpy(s, buf, len);
        s[len++] = 0;
        
        s += len;
        rest -= len;
        
        for (buf = strchr(buf, '\n'); 
             buf != NULL && isspace(buf[1]);
             buf = strchr(buf + 1, '\n'));
             
        if (buf == NULL)
            break;
            
        buf++;
    }
    *iflist_len = s - iflist;
    
    return 0;
}

