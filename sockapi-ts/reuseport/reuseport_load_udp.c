/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reuseport
 *
 * $Id$
 */

/** @page reuseport-reuseport_load_udp Datagrams distribution with SO_REUSEPORT
 *
 * @objective  Test datagrams distribution beteween few sockets which share
 *             address and port with SO_REUSEPORT option.
 *
 * @param pco_iut        PCO on IUT.
 * @param pco_tst        PCO on TST.
 * @param src_addr_num   Maximum src addresses number (on tester)
 * @param sockets_num    IUT sockets number.
 * @param use_ef_force   Use env EF_UDP_FORCE_REUSEPORT to share port.
 * @param thread_process Create aux processes/threads or not.
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "reuseport/reuseport_load_udp"

#include "sockapi-test.h"
#include "reuseport.h"
#include "onload.h"

#define CORES_NUM 4

/**
 * Socket context
 */
typedef struct socket_ctx {
    rcf_rpc_server *rpcs;  /**< RPC server */
    int sock;              /**< Socket */
    size_t num;            /**< Received packets number */
} socket_ctx;

static struct sockaddr **addr_list = NULL;

/**
 * Close all opened IUT sockets and destroy aux threads/processes.
 * 
 * @param sock              IUT sockets array
 * @param sockets_num       Sockets number
 * @param thread_process    Determines are there aux threads or processes
 */
static void
close_sockets(socket_ctx *sock, int sockets_num,
              thread_process_type thread_process)
{
    int i;

    if (sock == NULL)
        return;

    for (i = 0; i < sockets_num; i++)
    {
        RPC_CLOSE(sock[i].rpcs, sock[i].sock);
        if (thread_process != TP_NONE)
            rcf_rpc_server_destroy(sock[i].rpcs);
    }
}

/**
 * Create number @p sockets_num non blocking UDP sockets, bind them to the
 * same address:port with SO_REUSEPORT.
 * 
 * @param rpcs            RPC server
 * @param sockets_num     Number sockets
 * @param iut_addr        IUT address
 * @param use_ef_force    Option EF_UDP_FORCE_REUSEPORT was set
 * @param thread_process  Create aux processes/threads or not
 * 
 * @return Array of opened sockets
 */
static socket_ctx *
create_sockets(rcf_rpc_server *rpcs, int sockets_num,
               const struct sockaddr *iut_addr, te_bool use_ef_force,
               thread_process_type thread_process)
{
    socket_ctx *sock = te_calloc_fill(sockets_num, sizeof(*sock), 0);
    int rc;
    int i;

    for (i = 0; i < sockets_num; i++)
    {
        init_aux_rpcs(rpcs, &sock[i].rpcs, thread_process);
        sock[i].sock = rpc_socket(sock[i].rpcs,
                                  rpc_socket_domain_by_addr(iut_addr),
                                  RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        if (!use_ef_force || !tapi_onload_lib_exists(rpcs->ta))
            rpc_setsockopt_int(sock[i].rpcs, sock[i].sock,
                               RPC_SO_REUSEPORT, 1);
        rpc_fcntl(sock[i].rpcs, sock[i].sock, RPC_F_SETFL, RPC_O_NONBLOCK);
        RPC_AWAIT_IUT_ERROR(sock[i].rpcs);
        rc = rpc_bind(sock[i].rpcs, sock[i].sock, iut_addr);
        if (rc < 0)
            TEST_VERDICT("Bind failed with %r", RPC_ERRNO(sock[i].rpcs));
    }

    return sock;
}

/**
 * Search socket which get a packet and receive it.
 * 
 * @param sock          IUT sockets array
 * @param socket_num    Sockets number
 * @param recvbuf       Buffer to receive packet
 * @param len           Buffer lenght
 */
static void
receive_packet(socket_ctx *sock, int sockets_num, char *recvbuf, int len)
{
    int i;
    int rc;
    int at;

    memset(recvbuf, 0, len);

    for (at = 0; at < 10; at++)
    {
        for (i = 0; i < sockets_num; i++)
        {
            RPC_AWAIT_IUT_ERROR(sock[i].rpcs);
            rc = rpc_recv(sock[i].rpcs, sock[i].sock, recvbuf, len, 0);
            if (rc < 0)
            {
                if (RPC_ERRNO(sock[i].rpcs) == RPC_EAGAIN)
                    continue;
                TEST_FAIL("recv() failed with unexpected errno");
            }
            if (rc != len)
                TEST_VERDICT("IUT received only a part of sent packet");

            sock[i].num++;
            return;
        }

        usleep(100000);
    }

    TEST_VERDICT("IUT did not receive packet, it was lost!");
}

/**
 * Calculate and print statistics.
 * 
 * @param sock          IUT sockets array
 * @param socket_num    Sockets number
 * @param packets_num   Packets number
 */
static void
calc_stats(socket_ctx *sock, int sockets_num, int packets_num)
{
    size_t buflen = sockets_num * 20 + 40;
    char *buf = te_calloc_fill(buflen, 1, 0);
    size_t offt = 0;
    int res;
    int i;
    int count = 0;

    double m = packets_num / sockets_num;
    double deviation = 0;

    res = snprintf(buf, buflen, "Socket   Received packets\n");
    if (res < 0)
        TEST_FAIL("Failed write to buffer.");
    offt += res;

    for (i = 0; i < sockets_num; i++)
    {
        if (sock[i].num == 0)
            count++;

        deviation += (m - sock[i].num) * (m - sock[i].num);

        res = snprintf(buf + offt, buflen - offt, "%-8d %zu\n",
                       sock[i].sock, sock[i].num);
        if (res < 0 || (size_t)res > buflen - offt)
            TEST_FAIL("Failed write to buffer.");
        offt += res;
    }

    deviation = sqrt(deviation / sockets_num);

    /** Onload RSS hash for UDP uses only the couple of values src_ip,
     * dst_ip (SF Bug 48246). So we have not enough different addresses
     * combinations to evaluate real distribution. It is thought it is
     * enough to check that number of different sockets received datagrams
     * is not less then CPU cores number. This number is hardcoded to @c 4
     * for now. */
    if (count > 0 && sockets_num - count < CORES_NUM)
        RING_VERDICT("There are %d/%d sockets, which did not receive "
                     "any packets", count, sockets_num);
    RING("Standard deviation %8.4f", deviation);
    RING("%s", buf);
    free(buf);
}

/**
 * Transmit packets to IUT.
 * 
 * @param sock          IUT sockets array
 * @param socket_num    Sockets number
 * @param pco_tst       Tester RPC server
 * @param iut_addr      IUT address
 * @param src_addr_num  Maximum src addresses number
 * @param packets_num   Packets number
 * @param len           Packets lenght
 */
static void
transmit_data(socket_ctx *sock, int sockets_num, rcf_rpc_server *pco_tst,
              const struct sockaddr *iut_addr,
              int src_addr_num, int packets_num, int len)
{
    struct sockaddr **tst_addr;
    char *recvbuf = malloc(len);
    char *sendbuf = malloc(len);
    int tx_sock;
    int i;

    for (i = 0; i < packets_num; i++)
    {
        /**
         * Re-open tester socket for each packet and bind it to the next
         * address to reach packets distrbution on IUT side.
         */
        tx_sock = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                         RPC_SOCK_DGRAM, RPC_PROTO_DEF);

        tst_addr = addr_list + (i % src_addr_num);
        rpc_bind(pco_tst, tx_sock, *tst_addr);

        /* Resolve ARPs */
        tapi_rpc_provoke_arp_resolution(pco_tst, iut_addr);

        memset(sendbuf, 0xFF - i, len);
        if (rpc_sendto(pco_tst, tx_sock, sendbuf, len, 0, iut_addr) != len)
            TEST_FAIL("Client passed a part of packet");

        receive_packet(sock, sockets_num, recvbuf, len);
        if (memcmp(sendbuf, recvbuf, len) != 0)
            TEST_FAIL("Received data differs from sent");

        RPC_CLOSE(pco_tst, tx_sock);
    }

    calc_stats(sock, sockets_num, packets_num);

    free(recvbuf);
    free(sendbuf);
}

/**
 * Add aux addresses to tester interface.
 * 
 * @param pco_tst       RPC server handler
 * @param net           Network addresses pool
 * @param tst_if        Interface handler
 * @param src_addr_num  Addresses number to be added
 * 
 */
static void
add_tst_addresses(rcf_rpc_server *pco_tst, tapi_env_net *net,
                  const struct if_nameindex *tst_if, int src_addr_num)
{
    int i;
    struct sockaddr **tst_addr;

    addr_list = te_calloc_fill(src_addr_num, sizeof(addr_list), 0);

    for (i = 0; i < src_addr_num; i++)
    {
        tst_addr = addr_list + (i % src_addr_num);

        CHECK_RC(tapi_env_allocate_addr(net, AF_INET, tst_addr, NULL));
        CHECK_RC(tapi_cfg_base_if_add_net_addr(pco_tst->ta, tst_if->if_name,
                                               *tst_addr, -1, FALSE, NULL));
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_tst = NULL;
    rcf_rpc_server            *pco_iut = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct if_nameindex *iut_if = NULL;
    tapi_env_net              *net = NULL;
    thread_process_type        thread_process;
    te_bool                    use_ef_force;
    int                        src_addr_num;
    int                        init_cluster_sz;

    struct sockaddr           *saved_addrs = NULL;
    int                       *saved_prefixes = NULL;
    te_bool                   *saved_broadcasts = NULL;
    int                        saved_count = 0;
    te_bool                    saved_all = FALSE;

    int sockets_num;
    int packets_num;
    int packet_min;
    int packet_max;
    socket_ctx *sock = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_IF(tst_if);
    TEST_GET_IF(iut_if);
    TEST_GET_NET(net);
    TEST_GET_INT_PARAM(sockets_num);
    TEST_GET_INT_PARAM(packets_num);
    TEST_GET_INT_PARAM(packet_min);
    TEST_GET_INT_PARAM(packet_max);
    TEST_GET_BOOL_PARAM(use_ef_force);
    TEST_GET_ENUM_PARAM(thread_process, THREAD_PROCESS);
    TEST_GET_INT_PARAM(src_addr_num);

    if (use_ef_force)
        CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_UDP_FORCE_REUSEPORT",
                       ntohs(te_sockaddr_get_port(iut_addr)), TRUE, FALSE));
    CHECK_RC(tapi_sh_env_save_set_int(pco_iut, "EF_CLUSTER_SIZE", sockets_num,
                                      TRUE, NULL, &init_cluster_sz));

    CHECK_RC(tapi_cfg_save_del_if_ip4_addresses(pco_tst->ta,
                                                tst_if->if_name,
                                                NULL, FALSE,
                                                &saved_addrs,
                                                &saved_prefixes,
                                                &saved_broadcasts,
                                                &saved_count));
    saved_all = TRUE;

    TEST_STEP("Create number @p sockets_num non blocking UDP sockets, bind them to "
              "the same address:port with SO_REUSEPORT.");
    sock = create_sockets(pco_iut, sockets_num, iut_addr, use_ef_force,
                          thread_process);

    TEST_STEP("Add @p src_addr_num aux addresses to the tester interface.");
    add_tst_addresses(pco_tst, net, tst_if, src_addr_num);

    TEST_STEP("Transmit number @p packets_num packets from tester, open new socket "
              "for each packet and bind them to different addresses. It's to reach "
              "packets distribution on IUT. Receive packets on IUT and calculate "
              "statistics. Each IUT socket should receive at least one packet.");
    transmit_data(sock, sockets_num, pco_tst, iut_addr, src_addr_num,
                  packets_num, rand_range(packet_min, packet_max));

    TEST_SUCCESS;

cleanup:
    close_sockets(sock, sockets_num, thread_process);
    free(sock);
    free(addr_list);

    CLEANUP_CHECK_RC(tapi_sh_env_set_int(pco_iut, "EF_CLUSTER_SIZE",
                                         init_cluster_sz, TRUE, TRUE));

    if (saved_all)
    {
        /* Delete all IP addresses except the primary address.
         * It is necessary to avoid problems due to the OL Bug 9368. */
        tapi_cfg_save_del_if_ip4_addresses(pco_tst->ta,
                                           tst_if->if_name,
                                           NULL, TRUE,
                                           NULL, NULL, NULL, NULL);
        /* Delete the primary IP address. */
        tapi_cfg_save_del_if_ip4_addresses(pco_tst->ta,
                                           tst_if->if_name,
                                           NULL, FALSE,
                                           NULL, NULL, NULL, NULL);

        tapi_cfg_restore_if_ip4_addresses(pco_iut->ta, tst_if->if_name,
                                          saved_addrs, saved_prefixes,
                                          saved_broadcasts, saved_count);
    }

    TEST_END;
}
