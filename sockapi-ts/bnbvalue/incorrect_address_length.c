/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page bnbvalue-incorrect_address_length Behavior of the sendto(), sendmsg() and sendmmsg() functions if an incorrect length of the target address parameter passed
 *
 * @objective Check that @b sendto(), @b sendmsg()
 *            and @b sendmmsg() functions correctly process invalid
 *            length value of the target address parameter.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param func          tested function (@b sendmsg() / @b sendmmsg() /
 *                                       @b sendto())
 * @param corrupt       String contains length of corrupt value or
 *                      range for random corrupt value from range.
 *                      The range is set as "value1-value2", where value1
 *                      is the minimum value, and value2 is either the
 *                      maximum value or '?' which is the maximum value
 *                      for a given address family.
 *
 * @par Test sequence:
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/incorrect_address_length"

#include "sockapi-test.h"
#include <ctype.h>

#define TST_TXBUF_LEN  300

int
main(int argc, char *argv[])
{
    rcf_rpc_server    *pco_iut = NULL;
    rcf_rpc_server    *pco_tst = NULL;
    int                iut_s = -1;
    const char        *func;
    const char        *corrupt;

    const struct sockaddr  *iut_addr;
    const struct sockaddr  *tst_addr;

    void                   *tx_buf = NULL;
    size_t                  txbuf_len = TST_TXBUF_LEN;

    struct rpc_iovec        tx_vector[1];
    size_t                  iovec_len = 1;
    rpc_msghdr              tx_msghdr;

    struct sockaddr    *addr = NULL;
    tarpc_sa           *rpc_sa = NULL;

    char               *dash;

    /* Preambule */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_STRING_PARAM(corrupt);

    tx_buf = te_make_buf_by_len(TST_TXBUF_LEN);

    /* all of the vector elements are the same buffer */
    tx_vector[0].iov_base = tx_buf;
    tx_vector[0].iov_len = tx_vector[0].iov_rlen = txbuf_len;

    /* recvmsg() */
    memset(&tx_msghdr, 0, sizeof(tx_msghdr));
    tx_msghdr.msg_iovlen = tx_msghdr.msg_riovlen = iovec_len;
    tx_msghdr.msg_iov = tx_vector;
    tx_msghdr.msg_control = NULL;
    tx_msghdr.msg_name = (void *)tst_addr;

    TEST_STEP("Create @b iut_s socket of @c SOCK_DGRAM type on @p pco_iut; "
              "@b bind() @p iut_s to the local address;");
    iut_s = rpc_create_and_bind_socket(pco_iut, RPC_SOCK_DGRAM,
                                       RPC_PROTO_DEF, TRUE, FALSE,
                                       iut_addr);

    te_fill_buf(tx_buf, txbuf_len);

    TEST_STEP("Call @p func function on @p iut_s with prepared destination "
              "address and valid address length;");
    RPC_AWAIT_ERROR(pco_iut);
    if (strcmp(func, "sendto") == 0)
    {
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, txbuf_len, 0, tst_addr);
    }
    else if (strcmp(func, "sendmsg") == 0)
    {
        rc = rpc_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "sendmmsg") == 0)
    {
        rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "onload_zc_send") == 0)
    {
        rc = rpc_simple_zc_send(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, &tx_msghdr, 0,
                                        -1, TRUE);
    }
    else
    {
        TEST_FAIL("Unknown 'func' parameter %s", func);
    }

    TEST_STEP("Check that @p func function returns without any errors;");
    if (rc != TST_TXBUF_LEN)
    {
        if (rc < 0)
            TEST_VERDICT("Unexpected behaviour, %s() failed with "
                         "errno %s", func,
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        else
            TEST_FAIL("Unexpected behaviour, %s() returned %d "
                      "instead of %d", func, rc, TST_TXBUF_LEN);
    }

    TEST_STEP("Prepare invalid lenght of destination address parameter;");
    CHECK_NOT_NULL(addr = sockaddr_to_te_af(tst_addr, &rpc_sa));
    rpc_sa->flags &= ~TARPC_SA_LEN_AUTO;
    rpc_sa->len = rpc_get_sizeof(pco_iut,
        addr_family_sockaddr_str(addr_family_h2rpc(tst_addr->sa_family)));
    dash = strchr(corrupt, '-');
    if (dash == NULL)
    {
        int tmp_corrupt;
        size_t i;
        for (i = 0; i < strlen(corrupt); i++)
            if (!isdigit(corrupt[i]))
                TEST_FAIL("Invalid 'corrupt' parametr %s", corrupt);
        tmp_corrupt = atoi(corrupt);
        rpc_sa->len = rpc_sa->len - tmp_corrupt;
    }
    else
    {
        int a, b;
        char *c;
        for (c = (char *)corrupt; c < dash; c++)
            if (!isdigit(*c))
                TEST_FAIL("Invalid 'corrupt' parametr %s", corrupt);
        a = atoi(corrupt);
        if (*(dash + 1) == '?')
        {
            b = rpc_sa->len - 1;
        }
        else
        {
            for (c = dash + 1; c < (corrupt + strlen(corrupt)); c++)
                if (!isdigit(*c))
                    TEST_FAIL("Invalid 'corrupt' parametr %s", corrupt);
            b = atoi(dash + 1);
        }
        if (a >= b)
            TEST_FAIL("Invalid 'corrupt' parametr %s", corrupt);
        rpc_sa->len = rand_range(rpc_sa->len - b, rpc_sa->len - a);
    }

    tx_msghdr.msg_name = addr;
    tx_msghdr.msg_namelen = tx_msghdr.msg_rnamelen = rpc_sa->len;

    TEST_STEP("Call @p func function on @p iut_s with prepared destination "
              "address and address length value;");
    RPC_AWAIT_ERROR(pco_iut);
    if (strcmp(func, "sendto") == 0)
    {
        rc = rpc_sendto(pco_iut, iut_s, tx_buf, txbuf_len, 0, addr);
    }
    else if (strcmp(func, "sendmsg") == 0)
    {
        rc = rpc_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "sendmmsg") == 0)
    {
        rc = rpc_sendmmsg_as_sendmsg(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "onload_zc_send") == 0)
    {
        rc = rpc_simple_zc_send(pco_iut, iut_s, &tx_msghdr, 0);
    }
    else if (strcmp(func, "onload_zc_send_user_buf") == 0)
    {
        rc = rpc_simple_zc_send_gen_msg(pco_iut, iut_s, &tx_msghdr, 0,
                                        -1, TRUE);
    }

    TEST_STEP("Check that @p func function returns @c -1 and sets @b errno to"
              "@c EINVAL;");
    if (rc != -1)
        TEST_VERDICT("Unexpected behaviour, %s() unexpectedly succeed", func);

    CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                    "%s() function called on 'iut_s' returns -1, but",
                    func);

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    free(tx_buf);

    TEST_END;
}
