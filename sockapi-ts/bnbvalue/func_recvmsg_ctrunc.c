/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-func_recvmsg_ctrunc Passing short buffer under ancillary data in recvmsg() function
 *
 * @objective Check that @b recvmsg() function sets @c MSG_CTRUNC flag in
 *            @a msg_flags field of @c msghdr structure if ancillary data
 *            was truncated: the kernel has more ancillary data to return
 *            than the process has allocated room for (@c msg_controllen).
 *
 * @type conformance, robustness
 *
 * @reference @ref STEVENS, section 13.5
 *
 * @param recv_f  Function to receive data and control data
 *                 - recvmsg
 *                 - recvmmsg
 *                 - onload_zc_recv
 * @param env     Test environment
 *                 - @ref arg_types_env_peer2peer_all_ipv4_ipv6
 *
 * @par Scenario:
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/func_recvmsg_ctrunc"

#include "sockapi-test.h"

/* Real length of msg_control buffer */
#define REAL_CONTROLLEN 500

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int                 tst_s = -1;
    int                 sockopt = 1;
    struct rpc_msghdr  *rx_msghdr = NULL;
    void               *tx_buf = NULL;
    size_t              tx_buf_len;
    ssize_t             tmp_int;

    const struct sockaddr  *iut_addr;

    rpc_msg_read_f recv_f;


    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_MSG_READ_FUNC(recv_f);

    tx_buf = sockts_make_buf_dgram(&tx_buf_len);

    tmp_int = tx_buf_len;
    if (strcmp(rpc_msg_read_func_name(recv_f), "onload_zc_recv") == 0)
        CHECK_NOT_NULL(rx_msghdr = sockts_make_msghdr(0, 1, &tmp_int,
                                                      REAL_CONTROLLEN));
    else
        CHECK_NOT_NULL(rx_msghdr = sockts_make_msghdr(0, -1, &tmp_int,
                                                      REAL_CONTROLLEN));

    rx_msghdr->real_msg_controllen = REAL_CONTROLLEN;
    rx_msghdr->msg_controllen = rpc_get_sizeof(pco_iut, "struct cmsghdr");
    rx_msghdr->msg_cmsghdr_num = 0;

    tx_buf_len = (size_t)tmp_int;
    rx_msghdr->msg_flags_mode = RPC_MSG_FLAGS_NO_CHECK;

    TEST_STEP("Create a socket of type @c SOCK_DGRAM on @p pco_iut "
              "and bind it to @p iut_addr");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);

    TEST_STEP("Create a socket of type @c SOCK_DGRAM on @p pco_tst.");
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_DGRAM, RPC_PROTO_DEF);

    TEST_STEP("Set sockopt @c IP_RECVTTL for IPv4 or @c IPV6_RECVHOPLIMIT "
              "for IPV6 to enable receiving ancillary data on the IUT "
              "socket.");
    if (iut_addr->sa_family == AF_INET)
        rpc_setsockopt(pco_iut, iut_s, RPC_IP_RECVTTL, &sockopt);
    else if (iut_addr->sa_family == AF_INET6)
        rpc_setsockopt(pco_iut, iut_s, RPC_IPV6_RECVHOPLIMIT, &sockopt);
    else
        TEST_FAIL("Unsupported address family");

    TEST_STEP("Send a packet from the Tester socket to @p iut_addr");
    RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0, iut_addr);

    TEST_STEP("Call @b recvmsg() on the IUT socket, supplying msghdr "
              "structure with too short msg_controllen.");
    rc = recv_f(pco_iut, iut_s, rx_msghdr, 0);

    TEST_STEP("Check that @b recvmsg() retrieves the same data as was sent "
              "from peer.");
    if ((size_t)rc != tx_buf_len)
    {
        ERROR_VERDICT("%s() received fewer bytes than expected",
                     rpc_msg_read_func_name(recv_f));
        TEST_FAIL("It was expected to receive %u bytes but %u bytes were "
                  "received", (size_t)rc, tx_buf_len);
    }

    if (!sockts_iovec_buf_cmp_start(rx_msghdr->msg_iov,
                                    rx_msghdr->msg_iovlen,
                                    tx_buf,
                                    tx_buf_len))
    {
        TEST_VERDICT("%s() received unexpected data",
                     rpc_msg_read_func_name(recv_f));
    }

    TEST_STEP("Check that @a msg_flags has @c MSG_CTRUNC flag set.");
    sockts_check_msg_flags(rx_msghdr, RPC_MSG_CTRUNC);
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_free_msghdr(rx_msghdr);
    free(tx_buf);

    TEST_END;
}
