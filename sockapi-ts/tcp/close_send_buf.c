/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 * This test package contains tests for special cases of TCP protocol, such
 * as ICMP and routing table handling, small and zero window, fragmentation
 * of TCP packets, etc.
 */

/**
 * @page tcp-close_send_buf Close socket with non-empty send buffer.
 *
 * @objective  Close a socket while there is data in send buffer, check that
 *             all data can be successfully read by the peer after that.
 *
 * @param full  Completely overfill IUT send buffer if @c TRUE.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/close_send_buf"

#include "sockapi-test.h"
#include "tapi_mem.h"

#define RECV_BUF_LEN 10000

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    te_bool full;

    int iut_s = -1;
    int tst_s = -1;

    uint64_t sent;
    char    *buf = NULL;
    int      len = RECV_BUF_LEN;
    int      rlen = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(full);

    buf = tapi_malloc(len);

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Overfill IUT send buffer.");
    rpc_overfill_buffers(pco_iut, iut_s, &sent);

    TEST_STEP("If @p full is @c FALSE read a part of send buffer volume by "
              "tester.");
    if (!full)
        rlen = sockts_tcp_read_part_of_send_buf(pco_tst, tst_s, sent);

    TEST_STEP("Close IUT socket.");
    RPC_CLOSE(pco_iut, iut_s);

    TEST_STEP("Read all data by tester, check no data loss.");
    len = sent - rlen;
    do {
        rc = rpc_read(pco_tst, tst_s, buf, RECV_BUF_LEN);
        len -= rc;
    } while (rc != 0);

    if (len != 0)
    {
        ERROR("Sent data amount %llu, rest unread %d", sent, len);
        TEST_VERDICT("Incorrect data amount was read on tester");
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
