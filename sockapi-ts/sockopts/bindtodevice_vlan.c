/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-bindtodevice_vlan Usage of SO_BINDTODEVICE with VLAN/MACVLAN/IPVLAN
 *
 * @objective Check that if a socket is bound to a VLAN, MACVLAN or IPVLAN
 *            interface with @c SO_BINDTODEVICE socket option, only
 *            packets received from that particular interface are processed
 *            by the socket.
 *
 * @type conformance
 *
 * @param env           Environment:
 *                      - @ref arg_types_env_peer2peer
 *                      - @ref arg_types_env_peer2peer_ipv6
 * @param vlan1         The first VLAN ID (in case of MACVLAN/IPVLAN will
 *                      be used just as a part of name of the new
 *                      interface).
 * @param vlan2         The second VLAN ID (in case of MACVLAN/IPVLAN will
 *                      be used just as a part of name of the new
 *                      interface).
 * @param if_type       Interface type:
 *                      - @c vlan
 *                      - @c macvlan
 *                      - @c ipvlan
 * @param sock_type     Socket type.
 *
 * @reference MAN 7 socket
 *
 * @par Test sequence:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/bindtodevice_vlan"

#include "sockapi-test.h"
#include "vlan_common.h"
#include "tapi_proc.h"
#include "sockapi-ts_net_conns.h"

/* RPC server handles. */
static rcf_rpc_server             *pco_iut = NULL;
static rcf_rpc_server             *pco_tst = NULL;

/* Network addresses. */
static const struct sockaddr      *iut_addr1 = NULL;
static struct sockaddr            *iut_addr2 = NULL;
static struct sockaddr            *iut_addr3 = NULL;
static struct sockaddr            *tst_addr1 = NULL;
static struct sockaddr            *tst_addr2 = NULL;
static struct sockaddr            *tst_addr3 = NULL;

static peer_name_t peer_names[] = { { &tst_addr1,
                                      "the first Tester address" },
                                    { &tst_addr2,
                                      "the second Tester address" },
                                    { &tst_addr3,
                                      "the third Tester interface" },
                                    { NULL, NULL } };

/* Socket descriptors. */
static int                         iut_s = -1;
static int                         tst_s1 = -1;
static int                         tst_s2 = -1;
static int                         tst_s3 = -1;

/* Buffers to store data to be sent. */
static void     *tst_buf1 = NULL;
static size_t    tst_buf_len1 = 0;
static void     *tst_buf2 = NULL;
static size_t    tst_buf_len2 = 0;
static void     *tst_buf3 = NULL;
static size_t    tst_buf_len3 = 0;

/**
 * Create three UDP sockets on Tester, bind them to tst_addr1,
 * tst_addr2 and tst_addr3, connect them to iut_addr1, iut_addr2
 * and iut_addr3. After that send data from each socket.
 */
static void
send_udp(void)
{
    int rc;

    if (tst_s1 < 0)
    {
        tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr1),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr2),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);
        tst_s3 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr3),
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);

        rpc_bind(pco_tst, tst_s1, tst_addr1);
        rpc_connect(pco_tst, tst_s1, iut_addr1);

        rpc_bind(pco_tst, tst_s2, tst_addr2);
        rpc_connect(pco_tst, tst_s2, iut_addr2);

        rpc_bind(pco_tst, tst_s3, tst_addr3);
        rpc_connect(pco_tst, tst_s3, iut_addr3);
    }

    RPC_SEND(rc, pco_tst, tst_s1, tst_buf1, tst_buf_len1, 0);
    RPC_SEND(rc, pco_tst, tst_s2, tst_buf2, tst_buf_len2, 0);
    RPC_SEND(rc, pco_tst, tst_s3, tst_buf3, tst_buf_len3, 0);
}

/**
 * Make TCP socket nonblocking and call connect().
 *
 * @param rpcs        RPC server handle.
 * @param s           Socket descriptor.
 * @param addr        Address to connect to.
 */
static void
tcp_nonblock_connect(rcf_rpc_server *rpcs,
                     int s, const struct sockaddr *addr)
{
    int rc;

    rpc_fcntl(rpcs, s, RPC_F_SETFL, RPC_O_NONBLOCK);
    RPC_AWAIT_ERROR(rpcs);
    rc = rpc_connect(rpcs, s, addr);
    if (rc < 0 && RPC_ERRNO(rpcs) != RPC_EINPROGRESS)
        TEST_VERDICT("Nonblocking connect() failed "
                     "with unexpected errno %r",
                     RPC_ERRNO(rpcs));
}

/**
 * Create three TCP sockets on Tester, bind them to tst_addr1,
 * tst_addr2 and tst_addr3, make them nonblocking and connect
 * to iut_addr1, iut_addr2 and iut_addr3.
 */
static void
send_tcp(void)
{
    tst_s1 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr1),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s2 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr2),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s3 = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr3),
                        RPC_SOCK_STREAM, RPC_PROTO_DEF);

    rpc_bind(pco_tst, tst_s1, tst_addr1);
    rpc_bind(pco_tst, tst_s2, tst_addr2);
    rpc_bind(pco_tst, tst_s3, tst_addr3);

    tcp_nonblock_connect(pco_tst, tst_s1, iut_addr1);
    tcp_nonblock_connect(pco_tst, tst_s2, iut_addr2);
    tcp_nonblock_connect(pco_tst, tst_s3, iut_addr3);
}

/**
 * Send data or establish connections to IUT addresses.
 *
 * @param sock_type       Socket type.
 */
static void
test_send(rpc_socket_type sock_type)
{
    if (sock_type == RPC_SOCK_DGRAM)
        send_udp();
    else
        send_tcp();
}

/**
 * Perform cleanup after using test_send().
 *
 * @param sock_type     Socket type.
 */
static void
send_cleanup(rpc_socket_type sock_type)
{
    if (sock_type == RPC_SOCK_STREAM)
    {
        RPC_CLOSE(pco_tst, tst_s1);
        RPC_CLOSE(pco_tst, tst_s2);
        RPC_CLOSE(pco_tst, tst_s3);

        CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr1));
        CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr2));
        CHECK_RC(tapi_allocate_set_port(pco_tst, tst_addr3));
    }
}

/**
 * Check that IUT socket receives packet of expected length
 * from expected address.
 *
 * @param exp_addr      Expected address.
 * @param exp_length    Expected length.
 */
static void
check_recv_udp(struct sockaddr *exp_addr,
               size_t exp_length)
{
    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);

    char   *recv_buf = NULL;
    size_t  max_len = tst_buf_len1 + tst_buf_len2 + tst_buf_len3;
    ssize_t rc;

    CHECK_NOT_NULL(recv_buf = te_make_buf_by_len(max_len));

    rc = rpc_recvfrom(pco_iut, iut_s, recv_buf,
                      max_len, 0, SA(&peer_addr), &peer_addrlen);

    CHECK_RETURNED_LEN(rc, exp_length, SA(&peer_addr),
                       exp_addr, TEST_FAIL, TEST_VERDICT,
                       peer_names, NULL, NULL, "IUT socket");

    free(recv_buf);
}

/**
 * Check that IUT socket accepts connection
 * from the expected address.
 *
 * @param exp_addr      Expected address.
 */
static void
check_recv_tcp(struct sockaddr *exp_addr)
{
    struct sockaddr_storage    peer_addr;
    socklen_t                  peer_addrlen = sizeof(peer_addr);

    int iut_s_accepted = -1;

    iut_s_accepted = rpc_accept(pco_iut, iut_s,
                                SA(&peer_addr), &peer_addrlen);
    RPC_CLOSE(pco_iut, iut_s_accepted);

    if (te_sockaddrcmp(exp_addr,
                       te_sockaddr_get_size(exp_addr),
                       SA(&peer_addr),
                       te_sockaddr_get_size(SA(&peer_addr))) != 0)
    {
        TEST_VERDICT("IUT socket accepted connection from %s "
                     "but it is expected to accept it from %s",
                     get_name_by_addr(SA(&peer_addr), peer_names),
                     get_name_by_addr(exp_addr, peer_names));
    }
}

/**
 * Check that IUT socket receives data or accepts
 * connection from expected address.
 *
 * @param sock_type     Socket type.
 * @param exp_addr      Expected address.
 * @param exp_length    Expected length.
 */
static void
check_recv(rpc_socket_type sock_type,
           struct sockaddr *exp_addr,
           size_t exp_length)
{
    if (sock_type == RPC_SOCK_DGRAM)
        check_recv_udp(exp_addr, exp_length);
    else
        check_recv_tcp(exp_addr);
}

int
main(int argc, char **argv)
{
    int                         vlan1;
    int                         vlan2;
    const struct sockaddr      *iut_addr = NULL;
    const struct sockaddr      *tst_addr = NULL;
    struct sockaddr_storage     tst_addr_copy;
    rpc_socket_type             sock_type;

    const struct if_nameindex  *iut_if;
    const struct if_nameindex  *tst_if;

    struct sockaddr_storage     aux_addr;
    uint16_t                    iut_port;

    te_bool   readable;
    int       opt_error;

    te_interface_kind if_type;
    sockts_net_conns  conns = SOCKTS_NET_CONNS_INIT;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(vlan1);
    TEST_GET_INT_PARAM(vlan2);
    TEST_GET_TE_INTERFACE_KIND_PARAM(if_type);
    TEST_GET_SOCK_TYPE(sock_type);

    CHECK_NOT_NULL(tst_buf1 = sockts_make_buf_dgram(&tst_buf_len1));
    CHECK_NOT_NULL(tst_buf2 = sockts_make_buf_dgram(&tst_buf_len2));
    CHECK_NOT_NULL(tst_buf3 = sockts_make_buf_dgram(&tst_buf_len3));

    TEST_STEP("Create two interfaces of type @p if_type on IUT, assign "
              "new IP addresses from new networks to each of them. If it "
              "is VLAN, create corresponding interfaces on Tester and "
              "assign addresses from the same networks to them. Otherwise "
              "assign such addresses to the single existing Tester "
              "interface.");

    sockts_configure_net_conns(pco_iut, pco_tst, iut_if, tst_if,
                               vlan1, vlan2, iut_addr->sa_family,
                               if_type, &conns);

    CFG_WAIT_CHANGES;

    TEST_STEP("Let @b iut_addr1 be the addess assigned to base IUT interface, "
              "and @b tst_addr1 - the address assigned to a peer interface on "
              "Tester.");
    TEST_STEP("Let @b iut_addr2 be the addess assigned to the first newly created "
              "IUT interface, and @b tst_addr2 - address assigned to a peer "
              "interface on Tester.");
    TEST_STEP("Let @b iut_addr3 be the addess assigned to the second newly created "
              "IUT interface, and @b tst_addr3 - address assigned to a peer "
              "interface on Tester.");

    iut_addr1 = iut_addr;

    tapi_sockaddr_clone_exact(tst_addr, &tst_addr_copy);
    tst_addr1 = SA(&tst_addr_copy);

    iut_addr2 = conns.conn1.iut_addr;
    tst_addr2 = conns.conn1.tst_addr;
    iut_addr3 = conns.conn2.iut_addr;
    tst_addr3 = conns.conn2.tst_addr;

    TEST_STEP("Set the same port for all three IUT addresses.");
    iut_port = te_sockaddr_get_port(iut_addr);
    te_sockaddr_set_port(iut_addr2, iut_port);
    te_sockaddr_set_port(iut_addr3, iut_port);

    TEST_STEP("Create a socket @b iut_s on IUT according to @p sock_type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    TEST_STEP("Bind @b iut_s to a wildcard address with the same port "
              "as in IUT addresses.");
    tapi_sockaddr_clone_exact(iut_addr, &aux_addr);
    te_sockaddr_set_wildcard(SA(&aux_addr));
    rpc_bind(pco_iut, iut_s, SA(&aux_addr));

    if (sock_type == RPC_SOCK_STREAM)
        rpc_listen(pco_iut, iut_s, -1);

    TEST_STEP("Use setsockopt(@c SO_BINDTODEVICE) to bind @b iut_s "
              "to the first newly created interface.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                            conns.conn1.iut_new_if.if_name,
                            (strlen(conns.conn1.iut_new_if.if_name) + 1));
    if (rc != 0)
    {
        TEST_VERDICT("setsockopt(SO_BINDTODEVICE) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Send three packets (in case of UDP) or connection requests "
              "(in case of TCP) from Tester: from @b tst_addr1 to @b iut_addr1, "
              "from @b tst_addr2 to @b iut_addr2 and from @b tst_addr3 to @b "
              "iut_addr3.");

    test_send(sock_type);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that IUT socket processes only the packet (connection "
              "request) sent from @b tst_addr2 to @b iut_addr2.");

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    if (!readable)
        TEST_VERDICT("'iut_s' socket bound to the second IUT interface "
                     "is not readable");

    check_recv(sock_type, tst_addr2, tst_buf_len2);

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    if (readable)
    {
        TEST_VERDICT("The first check: 'iut_s' socket remained readable "
                     "after processing expected data or connection");
    }

    TEST_STEP("Check that if @c SO_ERROR option is nonzero for "
              "@b tst_s1 and @b tst_s3, it is @c ECONNREFUSED.");

    rpc_getsockopt(pco_tst, tst_s1, RPC_SO_ERROR, &opt_error);
    RING("Attempt to send data to peer bound to another interface "
         "returns error (SO_ERROR) %s", errno_rpc2str(opt_error));
    if (opt_error != 0 && opt_error != RPC_ECONNREFUSED)
    {
        TEST_FAIL("Unexpected error %s occured on 'tst_s1' socket, "
                  "but expected 0 or ECONNREFUSED",
                  errno_rpc2str(opt_error));
    }

    rpc_getsockopt(pco_tst, tst_s3, RPC_SO_ERROR, &opt_error);
    RING("Attempt to send data to peer bound to another interface "
         "returns error (SO_ERROR) %s", errno_rpc2str(opt_error));
    if (opt_error != 0 && opt_error != RPC_ECONNREFUSED)
    {
        TEST_FAIL("Unexpected error %s occured on 'tst_s3' socket, "
                  "but expected 0 or ECONNREFUSED",
                  errno_rpc2str(opt_error));
    }

    send_cleanup(sock_type);

    TEST_STEP("Use setsockopt(@c SO_BINDTODEVICE) to bind @b iut_s "
              "to the base IUT interface.");

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_raw(pco_iut, iut_s, RPC_SO_BINDTODEVICE,
                            iut_if->if_name, (strlen(iut_if->if_name) + 1));
    if (rc != 0)
    {
        TEST_VERDICT("setsockopt(SO_BINDTODEVICE) failed with errno %s",
                     errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

    TAPI_WAIT_NETWORK;

    TEST_STEP("Again send three packets (in case of UDP) or connection requests "
              "(in case of TCP) from Tester: from @b tst_addr1 to @b iut_addr1, "
              "from @b tst_addr2 to @b iut_addr2 and from @b tst_addr3 to @b "
              "iut_addr3.");

    test_send(sock_type);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Check that now IUT socket processes only the packet (connection "
              "request) sent from @b tst_addr1 to @b iut_addr1.");

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    if (!readable)
        TEST_VERDICT("'iut_s' socket bound to master interface is not "
                     "readable");

    check_recv(sock_type, tst_addr1, tst_buf_len1);

    RPC_GET_READABILITY(readable, pco_iut, iut_s, 1);
    if (readable)
    {
        TEST_VERDICT("The second check: 'iut_s' socket remained readable "
                     "after processing expected data or connection");
    }


    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s3);

    CLEANUP_CHECK_RC(sockts_destroy_net_conns(&conns));

    free(tst_buf1);
    free(tst_buf2);
    free(tst_buf3);

    if (iut_addr != NULL && iut_addr->sa_family == AF_INET6)
    {
        /* Avoid FAILED neigbor entries on IPv6, see OL bug 9774 */
        CLEANUP_CHECK_RC(sockts_ifs_down_up(pco_iut, iut_if,
                                            pco_tst, tst_if, NULL));
    }

    TEST_END;
}
