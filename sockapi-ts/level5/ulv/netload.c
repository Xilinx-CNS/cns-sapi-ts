/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Load IP stack while corrupting data structures.
 * 
 * $Id$
 */

/** @page level5-ulv-netload  Load IP stack while corrupting data structures
 *
 * @objective Check that loading of IP stack do not lead to OS crash if
 *            IP stack structures are corrupted.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param process_num   Number of processes which send/receive data
 * @param udp_num       Number of UDP sockets per process
 * @param tcp_num       Number of TCP sockets per process
 * @param min_len       Minimum packet length
 * @param max_length    Maximum packet length
 * @param rate          Number of packets to be sent per second
 * @param time2run      Time for sending/receiving
 * @param c_script      Corruption program to run; "none" means that no
 *                      corruption should be started and "env" means that
 *                      corruption program should be taken from 
 *                      the environment variable TE_CORRUPTION_SCRIPT
 * @param c_pid         If TRUE, pass information about processes identifiers
 *                      to @p c_script
 * @param c_socks       If TRUE, pass information about sockets to @p c_script
 *
 * @par Scenario
 * -# If @p c_pid is @c FALSE, fork process from @p pco_iut and call
 *    @b system() with @p c_script from it.
 * -# Create @p process_num processes on @p pco_iut and @p pco_tst.
 * -# Create @p udp_num UDP connections and @p tcp_num TCP connections 
 *    between each process pair.
 * -# If @p c_pid is @c TRUE, fork process from @p pco_iut and call
 *    @b system() with @p c_script from it. Process identifiers and
 *    (if @p c_socks is TRUE) socket numbers should be passed to @p c_script.
 * -# Create thread for each connection in each process.
 * -# Start bidirectional traffic flow in each connection according to
 *    @p min_len, @p max_len and @p rate parameters.
 * -# Wait @p time2run seconds.
 * -# Stop traffic sending/receiving.
 * -# Delete all processes.
 * -# Create TCP and UDP connection between @p pco_iut and @p pco_tst
 *    and check that it's possible to send/receive data via the connection.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/netload"

#include "sockapi-test.h"
#include "iomux.h"

/** One sending/receiving engine */
typedef struct engine {
    rcf_rpc_server *father;     /**< Process owning sender and receiver (IUT) */
    rcf_rpc_server *sender;     /**< Traffic sender (IUT) */
    rcf_rpc_server *receiver;   /**< Traffic receiver (IUT) */
    int             iut_s;      /**< Socket on IUT */
} engine;

/** Sockets on Tester */
static int *socks;

/** Array of sending/receiving engines */
static engine *engines;

/** IUT PCO */
static rcf_rpc_server *pco_iut;

/** Tester PCO */
static rcf_rpc_server *pco_tst;

/** IUT host address */
static const struct sockaddr *iut_addr;

/** Tester host address */
static const struct sockaddr *tst_addr;

/** Number of processes to create */
static int process_num;

/** Number of UDP connections per process */
static int udp_num;

/** Number of TCP connections per process */
static int tcp_num;

/** String to run corruption */
static const char *c_script;

/** If TRUE, pass process identifiers to corruption script */
static te_bool     c_pid;

/** If TRUE, pass sockets to corruption script */
static te_bool     c_socks;

/** Command for corruption script */
static char        cmdline[1024];

/** Current command line pointer */
static char       *cmdptr;

/** Remove all engines */
static void
remove_engines()
{
    int     num = process_num * (udp_num + tcp_num);
    int     i;
    engine *e;
    
    /* Prevent second deletion in case of error during cleanup */
    process_num = 0;
    
    for (i = 0, e = engines; i < num; i++, e++)
    {
        CHECK_RC(rcf_rpc_server_destroy(e->sender));
        CHECK_RC(rcf_rpc_server_destroy(e->receiver));
        RPC_CLOSE(e->father, e->iut_s);
        RPC_CLOSE(pco_tst, socks[i]);
    }
    
    for (i = 0; i < num; i += tcp_num + udp_num)
        CHECK_RC(rcf_rpc_server_destroy(engines[i].father));
    
    free(engines);
    free(socks);
    engines = NULL;        
    socks = NULL;
}

/** Create all engines for one process */
static void 
create_process_engines()
{
    static engine  *cur = NULL;
    static int      pnum = 0;
    rcf_rpc_server *father;
    char            name[32];
    rpc_socket_type sock_type = RPC_SOCK_STREAM;;
    int             i;
    
    if (cur == NULL)
        cur = engines;
        
    sprintf(name, "Process_%d", ++pnum);
    CHECK_RC(rcf_rpc_server_create(pco_iut->ta, name, &father));
    
    if (c_pid)
    {
        cmdptr += sprintf(cmdptr, "-p %d %s", rpc_getpid(father), 
                          c_socks ? "-s " : "");
    }                          
    
    for (i = 0; i < tcp_num + udp_num; i++)
    {
        struct sockaddr_storage addr1;
        struct sockaddr_storage addr2;
        
        if (i == tcp_num)
            sock_type = RPC_SOCK_DGRAM;
            
        cur->father = father;
            
        CHECK_RC(tapi_sockaddr_clone(pco_iut, iut_addr, &addr1));
        CHECK_RC(tapi_sockaddr_clone(pco_tst, tst_addr, &addr2));

        GEN_CONNECTION(father, pco_tst, sock_type, RPC_PROTO_DEF,
                       SA(&addr1), SA(&addr2), &cur->iut_s, 
                       socks + (cur - engines));
                       
        if (c_pid & c_socks)
            cmdptr += sprintf(cmdptr, "%d ", cur->iut_s);
        
        sprintf(name, "Sender_for_sock_%d", cur->iut_s);
        CHECK_RC(rcf_rpc_server_thread_create(father, name, &cur->sender));

        sprintf(name, "Receiver_for_sock_%d", cur->iut_s);
        CHECK_RC(rcf_rpc_server_thread_create(father, name, &cur->receiver));

        cur++;
    }
}

int
main(int argc, char *argv[])
{
    int min_length;
    int max_length; 
    int rate;
    int time2run;
    int i;
    int iut_s = -1;
    int tst_s = -1;
    
    tarpc_pid_t pid = -1;
    tarpc_uid_t uid = 0;
    
    uint64_t *rx = NULL, *tx = NULL;

    int loglevel;

    TEST_START;
    
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    
    TEST_GET_INT_PARAM(process_num);
    TEST_GET_INT_PARAM(udp_num);
    TEST_GET_INT_PARAM(tcp_num);
    TEST_GET_INT_PARAM(min_length);
    TEST_GET_INT_PARAM(max_length);
    TEST_GET_INT_PARAM(rate);
    TEST_GET_INT_PARAM(time2run);
    TEST_GET_STRING_PARAM(c_script);
    TEST_GET_BOOL_PARAM(c_pid);
    TEST_GET_BOOL_PARAM(c_socks);

    uid = rpc_getuid(pco_iut);

    /* We do not want a lot of banners on our console! */
    TAPI_SYS_LOGLEVEL_DEBUG(pco_iut, &loglevel);

    if (strcmp(c_script, "env") == 0)
    {
        c_script = getenv("TE_CORRUPTION_SCRIPT");
        if (c_script == NULL)
            c_script = "none";
    }            

    cmdptr = cmdline + sprintf(cmdline, "%s ", c_script);

    CHECK_NOT_NULL(engines = calloc(process_num * (udp_num + tcp_num), 
                                    sizeof(engines[0])));
    CHECK_NOT_NULL(socks = calloc(process_num * (udp_num + tcp_num),
                                    sizeof(int)));
    CHECK_NOT_NULL(tx = calloc(process_num * (udp_num + tcp_num),
                                    sizeof(uint64_t)));
    CHECK_NOT_NULL(rx = calloc(process_num * (udp_num + tcp_num),
                                    sizeof(uint64_t)));

    if (strcmp(c_script, "none") != 0 && !c_pid)
    {   
        RING("Command to run corruption program:\n%s", cmdline);
        pid = rpc_te_shell_cmd(pco_iut, cmdline, uid, NULL, NULL, NULL);
    }
    
    for (i = 0; i < process_num; i++)
        create_process_engines();
        
    if (strcmp(c_script, "none") != 0 && c_pid)
    {   
        RING("Command to run corruption program:\n%s", cmdline);
        pid = rpc_te_shell_cmd(pco_iut, cmdline, uid, NULL, NULL, NULL);
    }

    for (i = 0; i < process_num; i++)
    {
        engines[i].sender->op = engines[i].receiver->op = RCF_RPC_CALL;
        engines[i].sender->def_timeout = engines[i].receiver->def_timeout = 
        time2run + 1;

        rpc_simple_sender(engines[i].sender, engines[i].iut_s, 
                          min_length, max_length, FALSE, 
                          1000000 / rate, 1000000 / rate + 10,
                          TRUE, time2run, tx, TRUE);

        rpc_simple_receiver(engines[i].receiver, engines[i].iut_s, 
                          time2run, rx);
    }
        
    rpc_iomux_echoer(pco_tst, socks, process_num * (tcp_num + udp_num),
                     time2run, IC_DEFAULT, tx, rx);

    if (pid != -1)
    {
        int p = pid;
        
        pid = -1;
        rpc_ta_kill_death(pco_iut, p);
    }

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    
    RPC_CLOSE(pco_iut, iut_s);
    RPC_CLOSE(pco_tst, tst_s);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    sockts_test_connection(pco_iut, iut_s, pco_tst, tst_s);
    
    TEST_SUCCESS;

cleanup:
    if (pid != -1)
    {
        int p = pid;
        
        pid = -1;
        rpc_ta_kill_death(pco_iut, p);
    }
    
    remove_engines();

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    
    free(tx);
    free(rx);

    TAPI_SYS_LOGLEVEL_CANCEL_DEBUG(pco_iut, loglevel);
    
    TEST_END;
}
