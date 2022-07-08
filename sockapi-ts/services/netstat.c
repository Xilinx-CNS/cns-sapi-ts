/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-netstat  "netstat" functionality.
 *
 * @objective Check that "netstat" utility provides the information about
 *            TCP and UDP servers and TCP connections.
 *
 * @param iut       IUT PCO 
 * @param tst1      tester PCO
 * @param tst2      tester PCO
 *
 * @par Scenario
 * -# Create TCP sockets @p s1, @p s2, @p s3, @p s4, @p s5 and @p s6 and 
 *    UDP sockets @p udp_s1 and @p udp_s2 on the @p pco_iut and bind 
 *    them to the local addresses.
 * -# Create TCP socket @p s7 and UDP socket @p udp_s3 and bind it
 *    to wildcard address.
 * -# Call @b listen() for @p s1, @p s2, @p s3, @p s4 and @p s7.
 * -# Create TCP sockets @p tst_s1 and @p tst_s3 on the @p pco_tst1 and
 *    @p tst_s3 and @p tst_s2 on the @p pco_tst4 and bind them to the 
 *    local addresses.
 * -# Call @b listen() for @p tst_s1 and @p tst_s2.
 * -# Connect @p s5 and @p s6 to @p tst_s1 and @p tst_s2 correspondingly.
 * -# Connect @p tst_s3 and @p tst_s4 to @p s1 and @p s2 correspondingly.
 * -# Call "netstat -tn" on the @p pco_iut and verify that all connections
 *    corresponding to @p s1, @p s2, @p s5 and @p s6 are listed once
 *    and address of their peers are the same as @p tst_s1, @p tst_s2,
 *    @p tst_s3 and @p tst_s4 are bound to.
 * -# Call "netstat -tln" and verify that TCP listeners corresponding to
 *    @p s1, @p s2, @p s3, @p s4 and @p s7 are listed once.
 * -# Call "netstat -uan" on the @p pco_iut and verify that UDP
 *    listeners corresponding to @p udp_s1, @p udp_s2 and @p udp_s3 
 *    are listed once.
 * -# Close all sockets on the @p pco_iut and @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */
 
#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "services/netstat"

#include "sockapi-test.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "tapi_file.h"
#include "services.h"


/** Number of "connections" - do not change! */
#define TDATA_NUM       10

/** Data for one "connection" */
static struct {
    const char      *proto;   /**< "tcp" or "udp" */
    struct sockaddr *local;   /**< Local address */
    struct sockaddr *remote;  /**< Remote address or NULL */
    const char      *state;   /**< State ("ESTABLISHED" or "LISTEN") 
                                   or NULL */
} tdata[TDATA_NUM];

/** 
 * Check that specified "connection" is showed in the netstat exactly once.
 *
 * @param buf           buffer with netstat output
 * @param proto         "tcp" or "udp"
 * @param local         local address and port
 * @param remote        remote peer address or NULL
 * @param state         state ("ESTABLISHED" or "LISTEN") or NULL
 *
 * @return 0 (success) or -1 (failure)
 */
static int
check_presence(char *buf, const char *proto, struct sockaddr *local, 
               struct sockaddr *remote, const char *state, os_t os)
{
    te_bool     match = FALSE;
    char       *s = buf;
    char       *rem = NULL;
    char       *loc;
    int         loclen;
    int         remlen;
    int         statelen;
    int         i;

    if (remote != NULL && (rem = strdup(te_sockaddr2str(remote))) == NULL)
    {
        ERROR("Out of memory");
        return -1;
    }
    loc = (char *)te_sockaddr2str(local);

    if (os == OS_SOLARIS)
    {
#define CONVERT_INTO_SOLARIS_FORMAT(a_) \
    do {                                                                \
        if (a_ != NULL)                                                 \
        {                                                               \
            char *colon = strchr(a_, ':');                              \
            char zzzz[] = "0.0.0.0";                                    \
                                                                        \
            if (colon != NULL)                                          \
                *colon = '.';                                           \
            else                                                        \
            {                                                           \
                ERROR("Implementation of te_sockaddr2str is changed");  \
                free(rem);                                              \
                return -1;                                              \
            }                                                           \
                                                                        \
            if (strncmp(zzzz, a_, sizeof(zzzz) - 1) == 0)               \
            {                                                           \
                *a_ = '*';                                              \
                memmove(a_ + 1, a_ + sizeof(zzzz) - 1,                  \
                        strlen(a_ + sizeof(zzzz) - 1) + 1);             \
            }                                                           \
        }                                                               \
    } while (0)

        CONVERT_INTO_SOLARIS_FORMAT(rem);
        CONVERT_INTO_SOLARIS_FORMAT(loc);

#undef CONVERT_INTO_SOLARIS_FORMAT
    }

    remlen = rem == NULL ? 0 : strlen(rem);
    loclen = strlen(loc);
    statelen = state == NULL ? 0 : strlen(state);

#define FIND_NEXT \
    do {                                                                \
        while (!isspace(*s) && *s != 0 && *s != '\n')                   \
            s++;                                                        \
        while (isspace(*s))                                             \
            s++;                                                        \
        if (*s == '\n' || *s == 0)                                      \
        {                                                               \
            ERROR("Unrecognized format of netstat output:\n%s", buf);   \
            free(rem);                                                  \
            return -1;                                                  \
        }                                                               \
    } while (0)

    for (i = 0; s != NULL && *s != 0; s = strchr(s, '\n'))
    {
        if (*s == '\n')
            s++;

        if (os == OS_LINUX ? strncmp(s, proto, strlen(proto)) != 0 :
                             i++ < 3)
            continue;
            
        if (os == OS_LINUX)
        {
            FIND_NEXT; /* Recv-Q */
            FIND_NEXT; /* Send-Q */
            FIND_NEXT; /* Local address */
        }

        if (os == OS_SOLARIS)
            while (isspace(*s))
                s++;

        if (strncmp(s, loc, loclen) != 0)
            continue;

        FIND_NEXT; /* Remote address */
        if (rem != NULL)
        {
           if (strncmp(s, rem, remlen) != 0)
                continue;
        }

        if (state != NULL)
        {
            if (os == OS_SOLARIS)
            {
                FIND_NEXT; /** Swind */
                FIND_NEXT; /** Send-Q */
                FIND_NEXT; /** Rwind */
                FIND_NEXT; /** Recv-Q */
            }

            FIND_NEXT;     /** State */
            if (strncmp(s, state, statelen) != 0)
            {
                ERROR("Wrong state for %s %s %s in netstat:\n%s",
                       proto, loc, rem == NULL ? "" : rem, buf);
                free(rem);
                return -1;
            }
        }

        if (match)
        {
            ERROR("Connection %s %s %s is present twice in \n%s",
                  proto, loc, rem == NULL ? "" : rem, buf);
            free(rem);
            return -1;
        }
                  
        match = TRUE;
    }
    
    if (!match)
    {
        ERROR("Cannot find connection %s %s %s in \n%s",
              proto, loc, rem == NULL ? "" : rem, buf);
        free(rem);
        return -1;
    }
    
    free(rem);
    return 0;

#undef FIND_NEXT
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *iut_addr2;
    const struct sockaddr *tst_addr;
    const struct sockaddr *tst2_addr;
    
    struct sockaddr_storage from;
    socklen_t               fromlen = sizeof(from);
    char                   *buf = NULL;

    os_t        os;          /**< TA OS type */
    char const *netstat_tn;  /**< TA 'netstat -tn' command string */
    char const *netstat_tln; /**< TA 'netstat -tln' command string */
    char const *netstat_uan; /**< TA 'netstat -uan' command string */


    int i = 0;

    int s1 = -1, s2 = -1, s3 = -1, s4 = -1, s5 = -1, s6 = -1, s7 = -1;
    int udp_s1 = -1, udp_s2 = -1, udp_s3 = -1;
    int tst_s1 = -1, tst_s2 = -1, tst_s3 = -1, tst_s4 = -1;
    int s1_acc = -1, s2_acc = -1, tst_s1_acc = -1, tst_s2_acc = -1;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    switch(os = OS(pco_iut))
    {
        case OS_LINUX:
            netstat_tn = "netstat -tn";
            netstat_tln = "netstat -tln";
            netstat_uan = "netstat -uan";
            break;
        case OS_SOLARIS:
            netstat_tn = "netstat -f inet -P tcp -n";
            netstat_tln = "netstat -f inet -P tcp -an";
            netstat_uan = "netstat -f inet -P udp -an";
            break;
        case OS_FREEBSD:
            TEST_FAIL("FreeBSD is not supported yet");
            break;
        default:
            TEST_FAIL("It seems OS() is updated but test is not aware of");
    }

/** Allocate address/port and bind the socket to it */    
#define ALLOCATE_AND_BIND(_rpcs, _s, _addr)  \
    do {                                                                     \
        struct sockaddr **_location = (_rpcs == pco_iut) ?                   \
                                     &(tdata[i].local) : &(tdata[i].remote); \
        MAKE_ADDRESS(_rpcs, *_location, _addr, _s == s7 || _s == udp_s3);    \
                                                                             \
        rpc_bind(_rpcs, _s, *_location);                                     \
    } while (0)
    
    tdata[i].proto = "tcp";
    tdata[i].state = "ESTABLISHED";
    s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s1, iut_addr);
    rpc_listen(pco_iut, s1, SOCKTS_BACKLOG_DEF);    
    tst_s3 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_tst, tst_s3, tst_addr);
    rpc_connect(pco_tst, tst_s3, tdata[i].local);
    s1_acc = rpc_accept(pco_iut, s1, (struct sockaddr *)&from, &fromlen);
    i++;

    tdata[i].proto = "tcp";
    tdata[i].state = "ESTABLISHED";
    s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s2, iut_addr2);
    rpc_listen(pco_iut, s2, SOCKTS_BACKLOG_DEF);    
    tst_s4 = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_tst2, tst_s4, tst2_addr);
    rpc_connect(pco_tst2, tst_s4, tdata[i].local);
    s2_acc = rpc_accept(pco_iut, s2, (struct sockaddr *)&from, &fromlen);
    i++;

    tdata[i].proto = "tcp";
    tdata[i].state = "ESTABLISHED";
    tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_tst, tst_s1, tst_addr);
    rpc_listen(pco_tst, tst_s1, SOCKTS_BACKLOG_DEF);    
    s5 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s5, iut_addr);
    rpc_connect(pco_iut, s5, tdata[i].remote);
    tst_s1_acc = rpc_accept(pco_tst, tst_s1, (struct sockaddr *)&from, 
               &fromlen);
    i++;

    tdata[i].proto = "tcp";
    tdata[i].state = "ESTABLISHED";
    tst_s2 = rpc_socket(pco_tst2, rpc_socket_domain_by_addr(tst_addr), 
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_tst2, tst_s2, tst2_addr);
    rpc_listen(pco_tst2, tst_s2, SOCKTS_BACKLOG_DEF);    
    s6 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s6, iut_addr2);
    rpc_connect(pco_iut, s6, tdata[i].remote);
    tst_s2_acc = rpc_accept(pco_tst2, tst_s2, (struct sockaddr *)&from, 
               &fromlen);
    i++;
    
    tdata[i].proto = "tcp";
    tdata[i].state = "LISTEN";
    s3 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s3, iut_addr);
    rpc_listen(pco_iut, s3, SOCKTS_BACKLOG_DEF);
    i++;

    tdata[i].proto = "tcp";
    tdata[i].state = "LISTEN";
    s4 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s4, iut_addr2);
    rpc_listen(pco_iut, s4, SOCKTS_BACKLOG_DEF);    
    i++;

    tdata[i].proto = "tcp";
    tdata[i].state = "LISTEN";
    s7 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                    RPC_SOCK_STREAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, s7, iut_addr);
    rpc_listen(pco_iut, s7, SOCKTS_BACKLOG_DEF);
    i++;

    tdata[i].proto = "udp";
    udp_s1 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, udp_s1, iut_addr);
    i++;

    tdata[i].proto = "udp";
    udp_s2 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, udp_s2, iut_addr2);
    i++;

    tdata[i].proto = "udp";
    udp_s3 = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                        RPC_SOCK_DGRAM, RPC_PROTO_DEF);
    ALLOCATE_AND_BIND(pco_iut, udp_s3, iut_addr);
    i++;
    
#undef ALLOCATE_AND_BIND

#define CHECK_PRESENCE \
    do {                                                                \
        if (check_presence(buf, tdata[i].proto, tdata[i].local,         \
                           tdata[i].remote, tdata[i].state, os) != 0)   \
        {                                                               \
            RPC_AWAIT_IUT_ERROR(pco_iut);                               \
            rpc_system(pco_iut, "cat /proc/net/tcp");                   \
            TEST_STOP;                                                  \
        }                                                               \
    } while (0)

    rpc_shell_get_all(pco_iut, &buf, netstat_tn, -1);

    for (i = 0; i < 4; i++)
        CHECK_PRESENCE;

    free(buf); 
    buf = NULL;

    rpc_shell_get_all(pco_iut, &buf, netstat_tln, -1);

    for (; i < 7; i++)
        CHECK_PRESENCE;

    free(buf); 
    buf = NULL;

    rpc_shell_get_all(pco_iut, &buf, netstat_uan, -1);

    for (; i < 10; i++)
        CHECK_PRESENCE;
        
    free(buf); 
    buf = NULL;

#undef CHECK_PRESENCE        

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, s1);
    CLEANUP_RPC_CLOSE(pco_iut, s1_acc);
    CLEANUP_RPC_CLOSE(pco_iut, s2);
    CLEANUP_RPC_CLOSE(pco_iut, s2_acc);
    CLEANUP_RPC_CLOSE(pco_iut, s3);
    CLEANUP_RPC_CLOSE(pco_iut, s4);
    CLEANUP_RPC_CLOSE(pco_iut, s5);
    CLEANUP_RPC_CLOSE(pco_iut, s6);
    CLEANUP_RPC_CLOSE(pco_iut, s7);
    CLEANUP_RPC_CLOSE(pco_iut, udp_s1);
    CLEANUP_RPC_CLOSE(pco_iut, udp_s2);
    CLEANUP_RPC_CLOSE(pco_iut, udp_s3);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1_acc);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s2_acc);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);
    CLEANUP_RPC_CLOSE(pco_tst2, tst_s4);
    
    for (i = 0; i < TDATA_NUM; i++)
    {
        free(tdata[i].local);
        free(tdata[i].remote);
    }
    
    free(buf);

    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
