/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_port_fwd_srv SSH port forwarding on the server side
 *
 * @objective Check that SSH server performs TCP forwarding properly.
 *
 * @param pco_iut    IUT PCO for the SSH server
 * @param pco_tst1   tester PCO for the SSH client
 * @param pco_tst2   tester PCO for the SSH client
 * @param library    transport library to be used on the IUT
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * host with IUT via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @par Scenario
 * -# Set @c LD_PRELOAD environment variable to @p library on the @p pco_iut.
 * -# Choose unused port @p P on the @p pco_iut.
 * -# Start 
@htmlonly
<pre>/usr/sbin/sshd -p P </pre>
@endhtmlonly
 * on the @p pco_iut.
 * -# Create user te_tester with home directory /tmp/te_tester
 *    on the @p pco_iut, @p pco_tst1 and @p pco_tst2.
 * -# Generate public and private keys for user te_tester on the @p pco_tst1
 *    the using command
@htmlonly
<pre>ssh-keygen -t dsa -N "" -f /tmp/te_tester/.ssh/id_dsa</pre>
@endhtmlonly
 * -# Put public key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/authorized_keys on the @p pco_iut.
 * -# Put private key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/id_dsa on the @p pco_tst2.
 * -# Assuming that "L SSH N" means "local port forwarding using tunnel
 * between @p pco_tstN and @p pco_iut" and "R SSH N" means 
 * "remote port forwarding using tunnel between @p pco_tstN and @p pco_iut",
 * setup following secure tunnels:
 *   -# @p pro_tst1, @p P1  -> L SSH 1 -> @p pco_tst2, @p P2
 *   -# @p pro_tst1, @p P3  -> L SSH 1 -> @p pco_iut,  @p P4
 *   -# @p pro_tst2, @p P5  -> L SSH 2 -> @p pco_tst1, @p P6
 *   -# @p pro_tst2, @p P7  -> L SSH 2 -> @p pco_iut,  @p P8
 *   -# @p pro_iut,  @p P9  -> R SSH 1 -> @p pco_tst1, @p P10
 *   -# @p pro_iut,  @p P11 -> R SSH 2 -> @p pco_tst2, @p P12
 *   
 * Tunnel for local port forwarding is started using command:
 * -# Start 
@htmlonly
<pre>ssh -gN -o StrictHostKeyChecking=no 
                        -L port:host:hostport -p @p P</pre>
@endhtmlonly
 * on the @p pco_tst1 or @p pco_tst2.
 * Tunnel for remote port forwarding is started using command:
 * -# Start 
@htmlonly
<pre>ssh -gN -o StrictHostKeyChecking=no 
                        -R port:host:hostport -p @p P</pre>
@endhtmlonly
 * on the @p pco_tst1 or @p pco_tst2.
 * -# Open IPv4 @c STREAM sockets @p pco_tst1 for listening on ports
 *    @p P6 and @p P10.
 * -# Open IPv4 @c STREAM sockets @p pco_tst2 for listening on ports
 *    @p P2 and @p P12.
 * -# Open IPv4 @c STREAM sockets @p pco_iut for listening on ports
 *    @p P4 and @p P8.
 * -# Establish 2 connections per each tunnel: one with the client
 *    on the tester PCO participating in the tunnel and one with the client
 *    on the @p pco_iut (for local forwarding case) or with both clients
 *    on the @p pco_iut (for remote forwarding case).
 * -# Send/receive data via established connections.
 * -# Close all sockets.
 * -# Destroy all tunnels.
 * -# Kill sshd on the @p pco_iut.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_iut.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */
 
#ifndef DOXYGEN_TEST_SPEC

#define TE_TEST_NAME  "services/ssh_port_fwd_srv"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

#define DATA_BULK       128  /**< Size of data to be sent/received */

/* TRUE, if the SSH tunnel is for local port forwarding */
#define REMOTE_FORWARDING(i)     (i >= 4)

/** Data corresponding to one secure tunnel */
struct {
    rcf_rpc_server  *tst;        /**< Tester end of the client */
    rcf_rpc_server  *srv;        /**< TCP server PCO           */
    struct sockaddr *srv_addr;   /**< TCP server address       */
    struct sockaddr *proxy_addr; /**< Proxy address            */
    
    const struct sockaddr *iut_addr; /** IUT address corresponding to tst */
    
    int pid;        /**< Tunnel task PID */
    int s_srv;      /**< Socket for listening on the TCP */
    int s_clnt[2];  /**< Client sockets */
    int s_acc[2];   /**< Socket for accepted connections */
} tdata[6];

static char rx_buf[DATA_BULK + 1];
static char tx_buf[DATA_BULK];

/** Port for SSH server */
static uint16_t ssh_port;

/** IUT PCO */
static rcf_rpc_server *pco_iut;

/** 
 * Create the SSH tunnel for TCP forwarding.
 *
 * @param i     tunnel number
 *
 * @return 0 (success) or -1 (failure)
 */
static int
create_tunnel(int i)
{
    int   result = 0;
    char *host = NULL;
    
    uint16_t proxy_port = ntohs(te_sockaddr_get_port(tdata[i].proxy_addr));
    uint16_t srv_port = ntohs(te_sockaddr_get_port(tdata[i].srv_addr));
    
    if (tdata[i].srv == pco_iut || REMOTE_FORWARDING(i))
        host = strdup("127.0.0.1");
    else
        host = strdup(te_sockaddr_get_ipstr(tdata[i].srv_addr));
        
    if (host == NULL)
        TEST_FAIL("Out of memory");

    tdata[i].pid = rpc_te_shell_cmd(tdata[i].tst,
            "ssh -gN -o StrictHostKeyChecking=no %s %d:%s:%d -p %d %s",
            USER_UID, NULL, NULL, NULL,
            REMOTE_FORWARDING(i) ? "-R" : "-L", proxy_port, host,
            srv_port, ssh_port, te_sockaddr_get_ipstr(tdata[i].iut_addr));

    te_sockaddr_set_wildcard(tdata[i].srv_addr);
    
    if (REMOTE_FORWARDING(i))
    {
        struct sockaddr_in *a = (struct sockaddr_in *)tdata[i].proxy_addr;
        
        assert(a->sin_family == AF_INET);
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    
    free(host);

    return result;    
}

/** 
 * Create TCP connections via the SSH tunnel.
 *
 * @param i     tunnel number
 *
 * @return 0 (success) or -1 (failure)
 */
static int
create_connections(int i)
{
    int result = 0;
    
    struct sockaddr_storage from;
    socklen_t               fromlen = sizeof(from);
    
    rcf_rpc_server *clnt = REMOTE_FORWARDING(i) ? pco_iut : tdata[i].tst;
    
    memset(&from, 0, sizeof(from));

    tdata[i].s_srv = rpc_socket(tdata[i].srv, RPC_AF_INET, 
               RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(tdata[i].srv, tdata[i].s_srv, tdata[i].srv_addr);
    rpc_listen(tdata[i].srv, tdata[i].s_srv, 2);

    tdata[i].s_clnt[0] = rpc_socket(pco_iut, RPC_AF_INET, 
               RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tdata[i].s_clnt[1] = rpc_socket(clnt, 
               RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
               
    rpc_connect(pco_iut, tdata[i].s_clnt[0], tdata[i].proxy_addr);
    rpc_connect(clnt, tdata[i].s_clnt[1], tdata[i].proxy_addr);
                
    tdata[i].s_acc[0] = rpc_accept(tdata[i].srv, tdata[i].s_srv, 
               (struct sockaddr *)&from, &fromlen);
    tdata[i].s_acc[1] = rpc_accept(tdata[i].srv, tdata[i].s_srv, 
               (struct sockaddr *)&from, &fromlen);
    
    return result;    
}

/** 
 * Send/receive data via socket pair over SSH tunnel.
 *
 * @param i     tunnel number
 *
 * @return 0 (success) or -1 (failure)
 */
static int
check_connections(int i)
{
    int result = 0;

    rcf_rpc_server *clnt = REMOTE_FORWARDING(i) ? pco_iut : tdata[i].tst;
    
    DATA_SEND_RECV(pco_iut, tdata[i].s_clnt[0], 
                   tdata[i].srv, tdata[i].s_acc[0]);
    DATA_SEND_RECV(tdata[i].srv, tdata[i].s_acc[0], 
                   pco_iut, tdata[i].s_clnt[0]);
    DATA_SEND_RECV(clnt, tdata[i].s_clnt[1], tdata[i].srv, 
                   tdata[i].s_acc[1]);
    DATA_SEND_RECV(tdata[i].srv, tdata[i].s_acc[1], 
                   clnt, tdata[i].s_clnt[1]);
    
    return result;    
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst = NULL;
    rcf_rpc_server *pco_tst2 = NULL;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *iut_addr2;
    const struct sockaddr  *tst_addr;
    const struct sockaddr  *tst2_addr;
    
    cfg_handle handle;
    int        i;
    
    TEST_START;
    
    for (i = 0; i < 6; i++)
    {
        tdata[i].pid = tdata[i].s_srv = tdata[i].s_clnt[0] = 
        tdata[i].s_clnt[1] = tdata[i].s_acc[0] = tdata[i].s_acc[1] = -1;
    }

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);
    
    USER_CREATE(pco_iut->ta);
    USER_CREATE(pco_tst->ta);
    USER_CREATE(pco_tst2->ta);
    
    if (tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa.pub",
                          pco_iut->ta, 
                          USER_HOME "/.ssh/authorized_keys") != 0 ||
        tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa",
                          pco_tst2->ta, USER_HOME "/.ssh/id_dsa") != 0 ||
        tapi_file_copy_ta(pco_tst->ta, USER_HOME "/.ssh/id_dsa.pub",
                          pco_tst2->ta, USER_HOME "/.ssh/id_dsa.pub") != 0) 
    {
        TEST_STOP;
    }
    
    ssh_port = ntohs(te_sockaddr_get_port(iut_addr));
    if (cfg_add_instance_fmt(&handle, CVT_NONE, NULL, "/agent:%s/sshd:%d",
                             pco_iut->ta, ssh_port) != 0)
    {
        TEST_FAIL("Cannot configure sshd with port %d on the TA %s",
                  ssh_port, pco_iut->ta);
    }
    
    /* Prepare test data */

#define SET_SERVER(_pco) \
     do {                                                                   \
         tdata[i].srv = pco_##_pco;                                         \
         MAKE_ADDRESS(tdata[i].srv, tdata[i].srv_addr, _pco##_addr, FALSE); \
     } while (0)

     i = 0;
     tdata[i].tst = pco_tst; 
     tdata[i].iut_addr = iut_addr;
     SET_SERVER(tst2);
     MAKE_ADDRESS(pco_tst, tdata[i].proxy_addr, tst_addr, FALSE);

     i++;
     tdata[i].tst = pco_tst; 
     tdata[i].iut_addr = iut_addr;
     SET_SERVER(iut);
     MAKE_ADDRESS(pco_tst, tdata[i].proxy_addr, tst_addr, FALSE);
     
     i++;
     tdata[i].tst = pco_tst2; 
     tdata[i].iut_addr = iut_addr2;
     SET_SERVER(tst);
     MAKE_ADDRESS(pco_tst2, tdata[i].proxy_addr, tst2_addr, FALSE);
     
     i++;
     tdata[i].tst = pco_tst2; 
     tdata[i].iut_addr = iut_addr2;
     SET_SERVER(iut);
     MAKE_ADDRESS(pco_tst2, tdata[i].proxy_addr, tst2_addr, FALSE);

     i++;
     tdata[i].tst = pco_tst; 
     tdata[i].iut_addr = iut_addr;
     SET_SERVER(tst);
     MAKE_ADDRESS(pco_iut, tdata[i].proxy_addr, iut_addr, FALSE);

     i++;
     tdata[i].tst = pco_tst2; 
     tdata[i].iut_addr = iut_addr2;
     SET_SERVER(tst2);
     MAKE_ADDRESS(pco_iut, tdata[i].proxy_addr, iut_addr2, FALSE);

#undef SET_SERVER

    /* Open all SSH tunnels */
    for (i = 0; i < 6; i++)
        if (create_tunnel(i) != 0)
            TEST_STOP;

    SLEEP(10);     

    /* Open all SSH tunnels */
    for (i = 0; i < 6; i++)
        if (create_connections(i) != 0)
            TEST_STOP;

    /* Check all connections */
    for (i = 0; i < 6; i++)
        if (check_connections(i) != 0)
            TEST_STOP;

    TEST_SUCCESS;

cleanup:
    for (i = 0; i < 6; i++)
    {
        CLEANUP_RPC_CLOSE(tdata[i].srv, tdata[i].s_srv);
        CLEANUP_RPC_CLOSE(tdata[i].srv, tdata[i].s_acc[0]);
        CLEANUP_RPC_CLOSE(tdata[i].srv, tdata[i].s_acc[1]);
        CLEANUP_RPC_CLOSE(pco_iut, tdata[i].s_clnt[0]);
        CLEANUP_RPC_CLOSE((REMOTE_FORWARDING(i) ? pco_iut : tdata[i].tst), 
                          tdata[i].s_clnt[1]);
        SLEEP(1);
        if (tdata[i].pid > 0)
            rpc_ta_kill_death(tdata[i].tst, tdata[i].pid);
        free(tdata[i].srv_addr);
        free(tdata[i].proxy_addr);
    }
    TEST_END;
}

#endif /* !DOXYGEN_TEST_SPEC */
