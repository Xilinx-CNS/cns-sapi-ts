/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Timestamps
 *
 * $Id$
 */

/** @page timestamps-ts_opt_tsonly Timestamping flag SOF_TIMESTAMPING_OPT_TSONLY usage
 *
 * @objective  Check if flag SOF_TIMESTAMPING_OPT_TSONLY is used packet
 *             payload is not returned with timestamps.
 *
 * @param pco_iut    PCO on IUT
 * @param pco_tst    PCO on TST
 * @param sock_type  Socket type
 * @param onload_ext Onload extension TCP timestamps
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "timestamps/ts_opt_tsonly"

#include "sockapi-test.h"
#include "timestamps.h"

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    rpc_socket_type sock_type;
    te_bool         onload_ext;

    char           *sndbuf = NULL;
    size_t          length;
    rpc_msghdr      msg = {.msg_iov = NULL, .msg_control = NULL};
    struct timespec ts;
    struct timespec ts_h;
    tarpc_timeval   tv_h = {.tv_sec = 0, .tv_usec = 0};

    te_bool         zero_reported;

    int flags;
    int iut_s = -1;
    int tst_s = -1;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(onload_ext);

    sndbuf = sockts_make_buf_stream(&length);
    ts_init_msghdr(TRUE, &msg, length + 300);

    TEST_STEP("Create connection between IUT and tester.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Enable hardware timestamping.");
    flags = RPC_SOF_TIMESTAMPING_SYS_HARDWARE |
        RPC_SOF_TIMESTAMPING_RAW_HARDWARE | RPC_SOF_TIMESTAMPING_SOFTWARE |
        RPC_SOF_TIMESTAMPING_TX_HARDWARE | RPC_SOF_TIMESTAMPING_TX_SOFTWARE |
        RPC_SOF_TIMESTAMPING_OPT_TSONLY;

    if (!tapi_onload_run())
        flags |= RPC_SOF_TIMESTAMPING_OPT_TX_SWHW;

    if (onload_ext)
        flags |= RPC_ONLOAD_SOF_TIMESTAMPING_STREAM;

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_TIMESTAMPING, flags);
    if (rc < 0)
        TEST_VERDICT("setsockopt() call failed with %r", RPC_ERRNO(pco_iut));

    TEST_STEP("Send a packet from IUT.");
    rpc_gettimeofday(pco_iut, &tv_h, NULL);
    rpc_send(pco_iut, iut_s, sndbuf, length, 0);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Retrieve and check timestamp, payload data should not be returned.");
    TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
    if (!ts_any_event(TRUE, sock_type) && !onload_ext)
        RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_ERRQUEUE);
    if (!ts_any_event(TRUE, sock_type) && !onload_ext)
    {
        if (rc != -1 || RPC_ERRNO(pco_iut) != RPC_EAGAIN)
            TEST_VERDICT("recvmsg() had to fail with EAGAIN");
        TEST_SUCCESS;
    }
    if (rc != 0)
        TEST_VERDICT("recvmsg() returned non-zero value");

    ts_check_cmsghdr(&msg, rc, onload_ext ? length : 0, sndbuf, TRUE,
                     sock_type, onload_ext, FALSE, &ts, &ts_h);
    ts_check_deviation(&ts, &ts_h, 0, 100000);
    TIMEVAL_TO_TIMESPEC(&tv_h, &ts_h);
    ts_check_second_cmsghdr(pco_iut, iut_s, NULL, &ts_h, NULL, NULL, FALSE,
                            &zero_reported, NULL);

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    sockts_release_msghdr(&msg);
    free(sndbuf);

    TEST_END;
}
