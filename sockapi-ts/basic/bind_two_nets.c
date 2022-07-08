/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-bind_two_nets Bind function in two nets on one link environment
 *
 * @objective Check that @b bind and @b send/ @b sendto/ @b sendmsg
 *            functions correctly handles the situation when there are two
 *            nets on one link, socket is bound to the address from one net
 *            and send operation is performed to the address from another
 *            net.
 *
 * @type Conformance, compatibility
 *
 * @param env   Private testing environment similar to
 *              @ref arg_types_env_peer2peer.
 * @param sock_type   Socket type:
 *                    - SOCK_STREAM
 *                    - SOCK_DGRAM
 * @param func        Tested function:
 *                    - @b sock_type=SOCK_STREAM:
 *                        - getpeername()
 *                    - @b sock_type=SOCK_DGRAM:
 *                        - send()
 *                        - sendto()
 *                        - sendmsg()
 *                        - sendmmsg()
 *                        - onload_zc_send()
 *                   @c SOCK_STREAM socket) to use in the test.
 *                   (@c send/ @c sendto/ @c sendmsg/ @c sendmmsg /
 *                    @c getpeername / @c onload_zc_send)
 *
 * @par Test sequence:
 *
 * -# Add @p iut_addr1 and iut_addr2 network addresses to @p IUT;
 * -# Add @p tst_addr1 and tst_addr2 network addresses to @p TESTER;
 * -# Create @p sock_type sockets @p iut_s on @p pco_iut and @p tst_s on
 *    @p pco_tst;
 * -# Bind socket @p tst_s to @p tst_addr1 and @p iut_s to @p iut_addr2;
 * -# If @p sock_type is @c SOCK_STREAM make connection between @p iut_s
 *    and @p tst_s;
 * -# If @p func is @c send connect @p iut_s socket to @p tst_addr1;
 * -# If @p sock_type is @c SOCK_DGRAM send data from @p iut_s socket to
 *    @p tst_s socket using the function according to @p func parameter;
 * -# If @p func is @c getpeername validate local address on @p iut_s using
 *    @b getpeername() and @b getsockname() fucntions;
 * -# if @p func is @c send/ @c sendto / @c sendmsg / @c sendmmsg
 *    call @b recvfrom() on @p tst_s socket and check that packet is
 *    from @p iut_addr2;
 * -# Close all the sockets;
 * -# Delete the addresses.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/bind_two_nets"

#include "sockapi-test.h"

#define BUF_LEN 1024
int
main(int argc, char *argv[])
{
    char                    tx_buf[BUF_LEN];
    char                    rx_buf[BUF_LEN];
    const char             *func;

    tapi_env_net           *net1 = NULL;
    tapi_env_host          *host1 = NULL;
    tapi_env_host          *host2 = NULL;

    rpc_socket_type         sock_type;

    rcf_rpc_server         *pco_iut;
    rcf_rpc_server         *pco_tst;
    int                     iut_s = -1;
    int                     acc_s = -1;
    int                     tst_s = -1;

    const struct sockaddr  *tst_addr1;
    struct sockaddr        *iut_addr2;
    struct sockaddr        *tst_addr2;

    struct sockaddr_storage snd_addr;
    struct sockaddr_storage rcv_addr;
    socklen_t               rcv_addrlen;

    tapi_cfg_net_assigned  net_handle = {CFG_HANDLE_INVALID, NULL};

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_NET(net1);
    TEST_GET_HOST(host1);
    TEST_GET_HOST(host2);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_STRING_PARAM(func);

    CHECK_RC(tapi_cfg_net_assign_ip(tst_addr1->sa_family, net1->cfg_net,
                                    &net_handle));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net1, host1, tst_addr1->sa_family,
                                        &net_handle, &iut_addr2, NULL));
    CHECK_RC(tapi_env_get_net_host_addr(&env, net1, host2, tst_addr1->sa_family,
                                        &net_handle, &tst_addr2, NULL));
    CFG_WAIT_CHANGES;

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr2),
                       sock_type, RPC_PROTO_DEF); 

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr1),
                       sock_type, RPC_PROTO_DEF); 

    rpc_bind(pco_iut, iut_s, iut_addr2);

    rpc_bind(pco_tst, tst_s, tst_addr1);

    if (strcmp(func, "send") == 0)
    {
        rpc_connect(pco_iut, iut_s, tst_addr1);
        RPC_SEND(rc, pco_iut, iut_s, tx_buf, BUF_LEN, 0);
    }
    else if (strcmp(func, "getpeername") == 0)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_iut, iut_s, tst_addr1);
        acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);
    }
    else if (strcmp(func, "sendto") == 0)
    {
        RPC_SENDTO(rc, pco_iut, iut_s, tx_buf, BUF_LEN, 0, tst_addr1);
    }
    else if (strcmp(func, "sendmsg") == 0 ||
             strcmp(func, "onload_zc_send") == 0 ||
             strcmp(func, "onload_zc_send_user_buf") == 0 ||
             strcmp(func, "sendmmsg") == 0)
    {
        struct rpc_iovec  tx_buf_vec = {tx_buf, BUF_LEN, BUF_LEN};
        struct rpc_msghdr msg;

        memset(&msg, 0, sizeof(msg));
        tapi_sockaddr_clone_exact(tst_addr1, &snd_addr);
        msg.msg_name = &snd_addr;
        msg.msg_namelen = te_sockaddr_get_size(CONST_SA(&snd_addr));
        msg.msg_iov = &tx_buf_vec;
        msg.msg_iovlen = 1;
        msg.msg_riovlen = 1;

        RPC_AWAIT_ERROR(pco_iut);
        if (strcmp(func, "sendmsg") == 0)
        {
            rc = rpc_sendmsg(pco_iut, iut_s, &msg, 0);
        }
        else if (strcmp(func, "sendmmsg") == 0)
        {
            rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &msg, 0);
        }
        else if (strcmp(func, "onload_zc_send") == 0)
        {
            rc = rpc_simple_zc_send(pco_iut, iut_s, &msg, 0);
        }
        else
        {
            rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, &msg, 0, -1,
                                            TRUE);
        }

        if (rc < 0)
        {
            TEST_VERDICT("%s() failed with unexpected error " RPC_ERROR_FMT,
                         func, RPC_ERROR_ARGS(pco_iut));
        }
        else if (rc != BUF_LEN)
        {
            ERROR("%s() returned %d instead of %d", func, rc, BUF_LEN);
            TEST_VERDICT("%s() returned unexpected number of bytes", func);
        }
    }
    else
    {
        TEST_FAIL("Incorrect value of 'func' parameter");
    }

    if (sock_type == RPC_SOCK_STREAM)
    {
        if (sockts_compare_sock_peer_name(pco_iut, iut_s, pco_tst, acc_s)
            != 0)
            TEST_FAIL("iut_s socket local address is not validated");
    }
    else
    {
        rcv_addrlen = sizeof(rcv_addr);
        rc = rpc_recvfrom(pco_tst, (acc_s == -1) ? tst_s : acc_s, rx_buf,
                          BUF_LEN, 0, SA(&rcv_addr), &rcv_addrlen);

        if (te_sockaddrcmp_no_ports(
                CONST_SA(&rcv_addr),
                te_sockaddr_get_size(CONST_SA(&rcv_addr)),
                CONST_SA(iut_addr2),
                te_sockaddr_get_size(CONST_SA(iut_addr2))) != 0)
        {
            TEST_FAIL("Recieved packet has incorrect 'src' address");
        }

        if (rc != BUF_LEN || memcmp(tx_buf, rx_buf, BUF_LEN) != 0)
            TEST_FAIL("'tst_s' data received is corrupted");
    }
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}

