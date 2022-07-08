/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-incorrect_family Behavior of sendmsg(), sendmmsg() and sendto() functions when address with incorrect family passed
 *
 * @objective Check that @c sendmsg(), sendmmsg() and @c sendto()
 *            functions correctly process incorrect family in
 *            passed address
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param func          function for testing
 *                      (@c sendmsg()/sendmmsg()/sendto())
 * @param net_addr      create ipv4 or ipv6 network address
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/incorrect_family"

#include "sockapi-test.h"

#define REMOTE_PEER_4ADDR   "192.168.111.111"
#define REMOTE_PEER_6ADDR   "ff:ff::f0"
#define REMOTE_PEER_PORT    29876

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;

    int             iut_s = -1;

    const char        *func;
    const char        *net_addr;

    const struct sockaddr     *iut_addr;

#define BUF_SIZE 100
    struct sockaddr_storage addr;
    socklen_t               addr_len = sizeof(addr);
    unsigned char           buf[BUF_SIZE];
    struct rpc_iovec        iov[] = {
        { buf, sizeof(buf), sizeof(buf) }
    };

    rpc_msghdr  msg = {
        .msg_name = &addr,
        .msg_namelen = addr_len,
        .msg_iov = iov,
        .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
        .msg_rnamelen = addr_len,
        .msg_riovlen = sizeof(iov) / sizeof(iov[0]),
        .msg_cmsghdr_num = 0,
        .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
    };


    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(net_addr);

    /* Call function and check that it reports  error */
    TEST_STEP("Create and bind a socket @b iut_s of @c SOCK_DGRAM type on "
              "@p pco_iut;");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);

    TEST_STEP("Create an address @b addr to connect according to "
              "@p net_addr parametr;");
    memset(&addr, 0, addr_len);

    if (strcmp(net_addr, "v4") == 0)
    {
        SIN(&addr)->sin_port = htons(REMOTE_PEER_PORT);

        rc = inet_pton(PF_INET, REMOTE_PEER_4ADDR,
                       (void *)&(SIN(&addr)->sin_addr));
        if (rc <= 0)
        {
            TEST_FAIL("PF_INET address(%s) convertation failure",
                      REMOTE_PEER_4ADDR);
        }
    }
    else if (strcmp(net_addr, "v6") == 0)
    {
        SIN6(&addr)->sin6_port = htons(REMOTE_PEER_PORT);

        rc = inet_pton(PF_INET6, REMOTE_PEER_6ADDR,
                       (void *)&(SIN6(&addr)->sin6_addr));
        if (rc <= 0)
        {
            TEST_FAIL("PF_INET6 address(%s) convertation failure",
                      REMOTE_PEER_6ADDR);
        }
    }
    else
    {
       TEST_FAIL("Unexpected address type");
    }

    if (rpc_socket_domain_by_addr(iut_addr) == RPC_PF_INET)
        SA(&addr)->sa_family = AF_INET6;
    else
        SA(&addr)->sa_family = AF_INET;

    TEST_STEP("Call @p func function on @b iut_s socket with @b add;");
    RPC_AWAIT_ERROR(pco_iut);
    if (strcmp(func, "sendto") == 0)
    {
        rc = rpc_sendto(pco_iut, iut_s, &buf, BUF_SIZE, 0, SA(&addr));
    }
    else if (strcmp(func, "sendmsg") == 0)
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
    else if (strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, &msg, 0,
                                        -1, TRUE);
    }
    else
    {
        TEST_FAIL("Unexpected function for checking");
    }

    TEST_STEP("Check that the function returns @c -1 and sets @b errno to "
              "@c EAFNOSUPPORT;");
    if (rc != -1)
    {
        RING("%s() called on 'iut_s' socket "
             "returns %d instead of -1", func, rc);
        TEST_VERDICT(
            "Sending from %s socket to %s address was successful",
            SA(iut_addr)->sa_family == AF_INET ? "AF_INET" : "AF_INET6",
            SA(&addr)->sa_family == AF_INET ? "AF_INET" : "AF_INET6");
    }

    CHECK_RPC_ERRNO(pco_iut, RPC_EAFNOSUPPORT, "%s() called on 'iut_s' "
                    "socket with incorrect domain family, returns -1, but",
                    func);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
