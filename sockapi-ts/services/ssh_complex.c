/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * UNIX daemons and utilities
 * 
 * $Id$
 */

/** @page services-ssh_complex SSH complex functionality
 *
 * @objective Check that SSH may perform X forwarding, TCP forwarding and
 *            login/command execution simultaneously.
 *
 * @param pco_iut    PCO for the IUT
 * @param pco_tst    PCO for the TST
 * @param server     Is IUT tested as SSHD server?
 *
 * @par Scenario
 * -# Create user te_tester with home directory /tmp/te_tester 
 *    on the @p pco_clnt and @p pco_srv.
 * -# Generate public and private keys for user te_tester on the @p pco_clnt
 *    using command
@htmlonly
<pre>ssh-keygen -t dsa -N "" -f /tmp/te_tester/.ssh/id_dsa</pre>
@endhtmlonly
 * -# Put public key of the user te_tester to the 
 *    /tmp/te_tester/.ssh/authorized_keys on the @p pco_srv.
 * -# Choose unused ports P1, P2 and P3 on the @p pco_srv.
 * -# Choose unused port P4 and P5 on the @p pco_clnt.
 * -# Start 
@htmlonly
<pre>/usr/sbin/sshd -p P1</pre>
@endhtmlonly
 * on the @p pco_srv.
 * -# Start 
 * \n Xvfb :50 -ac
 * \n on the @p pco_clnt.
 * -# Start 
@htmlonly
<pre>ssh -g -o StrictHostKeyChecking=no 
        -L &lt;P4&gt;:127.0.0.1:&lt;P2&gt; 
        -R &lt;P3&gt;:127.0.0.1:&lt;P5&gt; 
        &lt;pco_srv IP address&gt; -p &lt;P1&gt;
        xterm -display &lt;pco_clnt IP address&gt;:50 -e 
        "sleep 10; touch /tmp/te_tester/ssh_test"</pre>
@endhtmlonly
 * on the @p pco_fwd.
 * -# Open IPv4 @c STREAM socket on the @p pco_srv and bind it to the
 *    port P2.
 * -# Open IPv4 @c STREAM socket on the @p pco_clnt and bind it to the
 *    port P5.
 * -# Open IPv4 @c STREAM socket on @p pco_clnt and connect it to the
 *    localhost:P4.
 * -# Open IPv4 @c STREAM socket on @p pco_srv and connect it to the
 *    localhost:P3.
 * -# Send/receive data via established connections.
 * -# Close all sockets.
 * -# Check, that file /tmp/te_tester/ssh_test arose on @p pco_srv.
 * -# Kill sshd on the @p pco_srv.
 * -# Kill Xvfb on the @p pco_clnt.
 * -# Unset @c LD_PRELOAD environment variable on the @p pco_srv and 
 *    @p pco_clnt.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "services/ssh_complex"

#include "sockapi-test.h"
#include "rcf_api.h"
#include "conf_api.h"
#include "tapi_file.h"
#include "tapi_sockaddr.h"
#include "services.h"

/** Size of data to be sent/received */
#define DATA_BULK       128  

static char tx_buf[DATA_BULK];
static char rx_buf[DATA_BULK + 1];

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    te_bool                server;
    
    rcf_rpc_server  *srv = NULL;
    rcf_rpc_server  *clnt = NULL;
    struct sockaddr *srv_addr;
    struct sockaddr *clnt_addr;
    
    struct sockaddr_storage from;
    socklen_t               fromlen = sizeof(from);
    
    /* Local/remote forwarding server/proxy addresses */
    struct sockaddr *ls_addr = NULL;  
    struct sockaddr *lp_addr = NULL;
    struct sockaddr *rs_addr = NULL;
    struct sockaddr *rp_addr = NULL;
    
    uint16_t ssh_port, ls_port, lp_port, rs_port, rp_port;
    
    cfg_handle      handle;
    char           *addr = NULL;
    tarpc_pid_t     pid = -1;
    
    int ls_s = -1, lc_s = -1, rs_s = -1, rc_s = -1, 
        r_acc_s = -1, l_acc_s = -1; 
    
    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(server);
    
    
    srv = server ? pco_iut : pco_tst;
    clnt = server ? pco_tst : pco_iut;
    srv_addr = (struct sockaddr *)(server ? iut_addr : tst_addr);
    clnt_addr = (struct sockaddr *)(server ? tst_addr : iut_addr);
    
    USER_CREATE(srv->ta);
    USER_CREATE(clnt->ta);

    if (tapi_file_copy_ta(clnt->ta, USER_HOME "/.ssh/id_dsa.pub",
                          srv->ta, USER_HOME "/.ssh/authorized_keys") != 0)
    {
        TEST_STOP;
    }

    ssh_port = ntohs(te_sockaddr_get_port(srv_addr));

    if (cfg_add_instance_fmt(&handle, CVT_NONE, NULL, 
                             "/agent:%s/sshd:%d", srv->ta, ssh_port) != 0)
    {
        TEST_FAIL("Cannot configure sshd with port %d on the TA %s",
                  ssh_port, srv->ta);
    }

    XVFB_ADD(clnt->ta);

    MAKE_ADDRESS(srv, ls_addr, srv_addr, TRUE);
    ls_port = htons(te_sockaddr_get_port(ls_addr));
    MAKE_ADDRESS(srv, lp_addr, clnt_addr, FALSE);
    lp_port = htons(te_sockaddr_get_port(lp_addr));
    MAKE_ADDRESS(clnt, rs_addr, clnt_addr, TRUE);
    rs_port = htons(te_sockaddr_get_port(rs_addr));
    MAKE_ADDRESS(clnt, rp_addr, srv_addr, FALSE);
    rp_port = htons(te_sockaddr_get_port(rp_addr));
    addr = strdup(te_sockaddr_get_ipstr(clnt_addr));

    MSLEEP(500); /* Wait for X server to start. */
    pid = rpc_te_shell_cmd(clnt, 
             "HOME=" USER_HOME " DISPLAY=\":%d\" "
             "ssh -g -o StrictHostKeyChecking=no %s -X -p %d "
             "-L %d:127.0.0.1:%d -R %d:127.0.0.1:%d "
             "xterm -e \"/bin/sh -c \\\"sleep 10; touch %s/ssh_complex\\\"\"", 
             USER_UID, NULL, NULL, NULL,
             X_SERVER_NUMBER, te_sockaddr_get_ipstr(srv_addr), ssh_port, 
             lp_port, ls_port, rp_port, rs_port, 
             USER_HOME);

    SLEEP(5);                   

    ls_s = rpc_socket(srv, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(srv, ls_s, ls_addr);
    rpc_listen(srv, ls_s, SOCKTS_BACKLOG_DEF);
    
    rs_s = rpc_socket(clnt, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rpc_bind(clnt, rs_s, rs_addr);
    rpc_listen(clnt, rs_s, SOCKTS_BACKLOG_DEF);

    lc_s = rpc_socket(clnt, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    rc_s = rpc_socket(srv, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);
    
    assert(lp_addr->sa_family == AF_INET);
    assert(rp_addr->sa_family == AF_INET);
    ((struct sockaddr_in *)(lp_addr))->sin_addr.s_addr = 
    ((struct sockaddr_in *)(rp_addr))->sin_addr.s_addr = 
        htonl(INADDR_LOOPBACK);
    
    rpc_connect(clnt, lc_s, lp_addr);
    rpc_connect(srv, rc_s, rp_addr);
                
    l_acc_s = rpc_accept(srv, ls_s, (struct sockaddr *)&from, &fromlen);
    r_acc_s = rpc_accept(clnt, rs_s, (struct sockaddr *)&from, &fromlen);
    
    DATA_SEND_RECV(srv, l_acc_s, clnt, lc_s);
    DATA_SEND_RECV(clnt, lc_s, srv, l_acc_s);
    DATA_SEND_RECV(clnt, r_acc_s, srv, rc_s);
    DATA_SEND_RECV(srv, rc_s, clnt, r_acc_s);

    rpc_close(srv, ls_s); ls_s = -1;
    rpc_close(clnt, rs_s); rs_s = -1;
    rpc_close(srv, l_acc_s); l_acc_s = -1;
    rpc_close(clnt, r_acc_s); r_acc_s = -1;
    rpc_close(srv, rc_s); rc_s = -1;
    rpc_close(clnt, lc_s); lc_s = -1;

    clnt->timeout += 10000;
    rpc_waitpid(clnt, pid, NULL, 0);
    pid = -1;

    CHECK_RC(rcf_ta_call(srv->ta, 0, "ta_rtn_unlink", &rc, 1, FALSE,
                         RCF_STRING, USER_HOME "/ssh_complex"));

    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        TEST_FAIL("xterm command did not have effect: no file is created");
                  
    if (rc != 0)
        TEST_FAIL("ta_rtn_unlink() returned %X", rc);

    TEST_SUCCESS;

cleanup:
        
    free(addr);
    free(lp_addr);
    free(rp_addr);
    free(ls_addr);
    free(rs_addr);
    
    CLEANUP_RPC_CLOSE(srv, ls_s);
    CLEANUP_RPC_CLOSE(clnt, rs_s);
    CLEANUP_RPC_CLOSE(srv, l_acc_s);
    CLEANUP_RPC_CLOSE(clnt, r_acc_s);
    CLEANUP_RPC_CLOSE(srv, rc_s);
    CLEANUP_RPC_CLOSE(clnt, lc_s);

    if (pid > 0)
        rpc_ta_kill_death(clnt, pid);


    TEST_END;
}

