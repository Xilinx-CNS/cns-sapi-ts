/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/** @page extension-od_overfill_sndbuf  Overfill send buffer with OD send API
 *
 * @objective  Check send buffer overfilling is correctly handled
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param raw_send      Use @b oo_raw_send() function to transmit data
 * @param small_portion Determines data portion size to attempt send with
 *                      OD send API
 *
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 * @author Denis Pryazhennikov <Denis.Pryazhennikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/od_overfill_sndbuf"

#include "sockapi-test.h"
#include "onload_rpc.h"
#include "od_send.h"
#include "sockapi-ta.h"
#include "tapi_sockets.h"

/** Data amount to be passed in one portion with OD send API if
 * @p small_portion is @c FALSE. */
#define BIG_PORTION 50000

/** Data amount to be passed in one portion with OD send API if
 * @p small_portion is @c TRUE. */
#define SMALL_PORTION 1000

/** How long wait for data, milliseconds. */
#define WAIT_FOR_DATA 2000

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    te_bool                    raw_send = TRUE;
    te_bool                    small_portion = TRUE;

    struct     onload_delegated_send ods;
    uint8_t    headers[OD_HEADERS_LEN];
    rpc_iovec  iov[2];

    te_bool    eagain = FALSE;
    char      *sendbuf  = NULL;
    char      *recvbuf  = NULL;
    int        recvbuf_len = 4096;
    size_t     length = 50000;
    int        iut_s  = -1;
    int        tst_s  = -1;
    int        raw_socket = -1;
    uint64_t   sent = 0;
    uint64_t   total_sent = 0;
    uint64_t   read = 0;
    uint64_t   read_total = 0;
    int        sendq;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(raw_send);
    TEST_GET_BOOL_PARAM(small_portion);

    length = small_portion ? SMALL_PORTION : BIG_PORTION;
    recvbuf = te_make_buf_by_len(recvbuf_len);

    if (raw_send)
    {
        raw_socket = rpc_socket(pco_iut, RPC_AF_PACKET, RPC_SOCK_RAW,
                                RPC_IPPROTO_RAW);
    }

    TEST_STEP("Establish TCP connection.");
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    TEST_STEP("Send data flow from IUT to increase congestion window.");
    sockts_extend_cong_window(pco_iut, iut_s, pco_tst, tst_s);

    TEST_STEP("Set small send buffer on IUT.");
    rpc_setsockopt_int(pco_iut, iut_s, RPC_SO_SNDBUF, 3000);
    rpc_ioctl(pco_iut, iut_s, RPC_SIOCOUTQ, &sendq);
    TAPI_WAIT_NETWORK;

    sendbuf = te_make_buf_by_len(length);
    TEST_STEP("Send data with OD send API until IUT send buffer is"
              " overfilled.");
    do {
        memset(&ods, 0, sizeof(ods));
        ods.headers_len = OD_HEADERS_LEN;
        ods.headers = headers;

        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_delegated_send_prepare(pco_iut, iut_s, length, 0,
                                               &ods);
        if (rc != 0)
        {
            if (rc == ONLOAD_DELEGATED_SEND_RC_NOWIN ||
#ifdef HAVE_DECL_ONLOAD_DELEGATED_SEND_RC_NOCWIN
                /* Supported from the Onload branch eol6 */
                rc == ONLOAD_DELEGATED_SEND_RC_NOCWIN ||
#endif
                rc == ONLOAD_DELEGATED_SEND_RC_SENDQ_BUSY)
                break;
            TEST_VERDICT("OD _prepare failed with unexpected code %s",
                         ods_prepare_err2string(rc));
        }

        sent = 0;
        while (sent < length)
        {
            iov[0].iov_len = ods.headers_len;
            iov[0].iov_base = ods.headers;
            iov[1].iov_base = (void *)sendbuf + sent;
            iov[1].iov_len = od_get_min(&ods);
            if (iov[1].iov_len == 0)
                break;

            rpc_onload_delegated_send_tcp_update(pco_iut, &ods,
                                                 iov[1].iov_len, TRUE);

            if (raw_send)
            {
                rc = tapi_sock_raw_tcpv4_send(pco_iut, iov, 2,
                                              iut_if->if_index, raw_socket,
                                              TRUE);
            }
            rpc_onload_delegated_send_tcp_advance(pco_iut, &ods,
                                                  iov[1].iov_len);

            sent += iov[1].iov_len;
        }

        iov[0].iov_base = (void *)sendbuf;
        iov[0].iov_len = sent;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_delegated_send_complete(pco_iut, iut_s, iov, 1, 0);

        if (rc > 0)
            total_sent += rc;
    } while (rc > 0);

    if (rc < 0)
    {
        if (RPC_ERRNO(pco_iut) != RPC_EAGAIN)
        {
            RING_VERDICT("_complete() call failed with unexpected errno %r",
                         RPC_ERRNO(pco_iut));
        }
        else
        {
            eagain = TRUE;
        }
    }

    TEST_STEP("Read all data on tester.");
    TEST_STEP("Wait two seconds for possible packets.");
    RPC_AWAIT_IUT_ERROR(pco_tst);
    rc = rpc_drain_fd(pco_tst, tst_s, recvbuf_len, WAIT_FOR_DATA, &read);
    if (rc != -1 || RPC_ERRNO(pco_tst) != RPC_EAGAIN)
        TEST_FAIL("RPC call drain_fd() returned unexpected result");
    read_total += read;

    TEST_STEP("If onload_delegated_send_complete() failed with EAGAIN,"
              " we have to call it again to finilize data transmission. It"
              " should pass now.");
    if (eagain)
    {
        iov[0].iov_base = (void *)sendbuf;
        iov[0].iov_len = sent;
        if (sent < length)
            iov[0].iov_len = sent;
        else
            iov[0].iov_len = length;

        iov[0].iov_rlen = iov[0].iov_len;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_onload_delegated_send_complete(pco_iut, iut_s, iov, 1, 0);
        if (rc < 0)
            TEST_VERDICT("onload_delegated_send_complete() unexpectedly "
                         "failed");
        total_sent += rc;

        if (rc < (long int)length)
            rpc_onload_delegated_send_cancel(pco_iut, iut_s);

        rpc_drain_fd_simple(pco_tst, tst_s, &read);
        read_total += read;
    }

    RING("Total sent %"TE_PRINTF_64"u, received %"TE_PRINTF_64"u",
         total_sent, read_total);

    TEST_STEP("Total sent and received data amount should be equal.");
    if (read_total != total_sent)
        TEST_VERDICT("Sent and received data amount differ");

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    if (raw_send)
        CLEANUP_RPC_CLOSE(pco_iut, raw_socket);

    free(sendbuf);
    free(recvbuf);

    TEST_END;
}
