/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-od_send_peer_close Behavior of ODS functions when peer closes its socket
 *
 * @objective Check behavior of ODS functions when peer closes its socket
 *
 * @param env           Testing environment:
 *      - @ref arg_types_env_peer2peer
 * @param first_call    First function to call:
 *      - od_send (call onload delegated send)
 *      - od_send_raw (call onload delegated raw send)
 *      - no_ods (call @p aux_func)
 * @param second_call   Second function to call:
 *      - od_send (call onload delegated send)
 *      - od_send_raw (call onload delegated raw send)
 *      - no_ods (call @p aux_func)
 * @param overfill      Overfill IUT send buffer if @c TRUE:
 *      - TRUE
 *      - FALSE
 * @param aux_func      I/O function to call if @p first_call
 *                      or @p second_call is @b no_ods:
 *      - send
 *      - sendto
 *      - sendmsg
 *      - sendmmsg
 *      - write
 *      - writev
 *      - recv
 *      - recvfrom
 *      - recvmsg
 *      - recvmmsg
 *      - read
 *      - readv
 *      - none
 * @param get_err_first Get SO_ERROR before second I/O function call if @c TRUE,
 *                      else - after:
 *      - TRUE
 *      - FALSE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/od_send_peer_close"

#include "sockapi-test.h"
#include "sockapi-ta.h"
#include "tapi_sockets.h"

typedef enum ods_call
{
    OD_SEND,
    OD_SEND_RAW,
    NO_ODS
} ods_call;

#define ODS_CALL_MAPPING_LIST \
    {"od_send", OD_SEND}, \
    {"od_send_raw", OD_SEND_RAW}, \
    {"no_ods", NO_ODS}

typedef struct
{
    te_bool prepare_must_fail;
    int     prepare_error;
    te_bool complete_must_fail;
    int     complete_error;
} ods_exp_fail;

#define IOCALL(pco, s, buf, len)                            \
    aux_func_is_send ?                                      \
             ((rpc_send_f)aux_func)(pco, s, buf, len, 0) :  \
             ((rpc_recv_f)aux_func)(pco, s, buf, len, 0)

#define FIRST_SEND (ods_first || aux_func_is_send)

/**
 * Send data using delegated send API.
 *
 * @param pco_iut       RPC server handler
 * @param iut_s         Socket
 * @param sendbuf       Data buffer to be sent
 * @param length        The buffer length
 * @param raw_send      Use raw send API to send data
 * @param ifindex       Interface index to send packet for raw sending
 *                      if @p raw_send is @c TRUE
 * @param exp_fail      Structure describing expected ODS errors
 * @param msg           Message to print in verdict
 */
static void
test_od_send(rcf_rpc_server *pco_iut, int iut_s, const void *sendbuf,
            int length, te_bool raw_send, int ifindex,
            ods_exp_fail *exp_fail, char *msg)
{
    struct onload_delegated_send ods;

    uint8_t     headers[OD_HEADERS_LEN];
    rpc_iovec   iov[2];
    int         sent = 0;
    int         rc;
    int         raw_socket;
    te_bool     failed = FALSE;

    memset(&ods, 0, sizeof(ods));
    ods.headers_len = OD_HEADERS_LEN;
    ods.headers = headers;

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_onload_delegated_send_prepare(pco_iut, iut_s, length, 0,
                                           &ods);
    if (exp_fail->prepare_must_fail)
    {
        if (rc == 0)
        {
            TEST_VERDICT("%s: delagated send prepare call returned 0 "
                         "instead of %s", msg,
                         ods_prepare_err2string(exp_fail->prepare_error));
        }
        else if (rc != exp_fail->prepare_error)
        {
            TEST_VERDICT("%s: delagated send prepare call returned -1 "
                         " but error is %s instead of %s", msg,
                         ods_prepare_err2string(rc),
                         ods_prepare_err2string(exp_fail->prepare_error));
        }

        rpc_onload_delegated_send_cancel(pco_iut, iut_s);
        return;
    }
    else
    {
        if (rc != 0)
        {
            TEST_VERDICT("%s: delagated send prepare call failed "
                         "with error %s", msg,
                         ods_prepare_err2string(rc));
        }
    }

    if (raw_send)
    {
        raw_socket = rpc_socket(pco_iut, RPC_AF_PACKET, RPC_SOCK_RAW,
                                RPC_IPPROTO_RAW);
    }

    while (sent < length)
    {
        iov[0].iov_len = ods.headers_len;
        iov[0].iov_base = ods.headers;
        iov[1].iov_base = (void *)sendbuf + sent;
        iov[1].iov_len = od_get_min(&ods);
        if (iov[1].iov_len == 0)
            break;

        /*
         * We have to call O_D_S_update() before raw send, because
         * otherwise "total length" field of IPv4 header has incorrect
         * value (equal to MSS). O_D_S_udpdate() updates header with
         * correct data length.
         */
        rpc_onload_delegated_send_tcp_update(pco_iut, &ods,
                                             iov[1].iov_len, TRUE);
        if (raw_send)
        {
            CHECK_RC(tapi_sock_raw_tcpv4_send(pco_iut, iov, 2, ifindex,
                                              raw_socket, TRUE));
        }
        rpc_onload_delegated_send_tcp_advance(pco_iut, &ods,
                                              iov[1].iov_len);

        sent += iov[1].iov_len;
    }

    iov[0].iov_base = (void *)sendbuf;
    iov[0].iov_len = sent;

    if (raw_send)
        TAPI_WAIT_NETWORK;

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_onload_delegated_send_complete(pco_iut, iut_s, iov, 1, 0);

    if (exp_fail->complete_must_fail)
    {
        if (rc != -1)
        {
            failed = TRUE;
            ERROR_VERDICT("%s: delegated send complete unexpectedly "
                          "succeed", msg);
        }
        else
        {
            CHECK_RPC_ERRNO_NOEXIT(pco_iut, exp_fail->complete_error, failed,
                                   "%s: delegated send complete call "
                                   "returned -1, but", msg);
        }
    }
    else
    {
        if (rc == -1)
        {
            TEST_VERDICT("%s: delagated send complete call failed "
                         "with error %r", msg, RPC_ERRNO(pco_iut));
        }
    }

    rpc_onload_delegated_send_cancel(pco_iut, iut_s);

    if (raw_send)
        RPC_CLOSE(pco_iut, raw_socket);

    if (failed)
        TEST_STOP;
}

/**
 * Check SO_ERROR value.
 *
 * @param rpcs              RPC server handler
 * @param sock              Socket descriptor
 * @param got_epipe         Did the process get EPIPE error
 * @param got_econnreset    Did the process get ECONNRESET error
 */
static void
check_so_error(rcf_rpc_server *rpcs, int sock, te_bool got_epipe,
               te_bool got_econnreset)
{
    int err;

    rpc_getsockopt(rpcs, sock, RPC_SO_ERROR, &err);

    if (got_epipe && TE_RC_GET_ERROR(err) == EPIPE)
        TEST_VERDICT("getsockopt(SO_ERROR) unexpectedly returned EPIPE");

    if (got_econnreset && TE_RC_GET_ERROR(err) == ECONNRESET)
        TEST_VERDICT("getsockopt(SO_ERROR) unexpectedly returned ECONNRESET");
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server              *pco_iut = NULL;
    rcf_rpc_server              *pco_tst = NULL;
    const struct sockaddr       *iut_addr;
    const struct sockaddr       *tst_addr;
    const struct if_nameindex   *iut_if = NULL;

    int             iut_s = -1;
    int             tst_s = -1;
    ods_call        first_call;
    ods_call        second_call;
    te_bool         overfill;
    te_bool         ods_first = FALSE;
    te_bool         ods_second = FALSE;
    te_bool         get_err_first;
    void           *aux_func = NULL;
    te_bool         aux_func_is_send;
    char           *sendbuf  = NULL;
    int             length = 1;
    ods_exp_fail    exp;
    te_bool         got_epipe = FALSE;
    te_bool         got_econnreset = FALSE;
    te_bool         first_raw = FALSE;
    te_bool         second_raw = FALSE;

    TEST_START;

    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_BOOL_PARAM(overfill);
    TEST_GET_ENUM_PARAM(first_call, ODS_CALL_MAPPING_LIST);
    TEST_GET_ENUM_PARAM(second_call, ODS_CALL_MAPPING_LIST);
    TEST_GET_BOOL_PARAM(get_err_first);
    if (first_call == NO_ODS || second_call == NO_ODS)
        TEST_GET_FUNC(aux_func, aux_func_is_send);

    if (first_call != NO_ODS)
    {
        if (first_call == OD_SEND_RAW)
            first_raw = TRUE;

        ods_first = TRUE;
    }

    if (second_call != NO_ODS)
    {
        if (second_call == OD_SEND_RAW)
            second_raw = TRUE;

        ods_second = TRUE;
    }

    TEST_STEP("Establish a TCP connection between IUT and tester.");
    SOCKTS_CONNECTION(pco_iut, pco_tst, iut_addr, tst_addr,
                      SOCKTS_SOCK_TCP_ACTIVE, &iut_s, &tst_s, FALSE);

    TEST_STEP("Overfill IUT send buffer if @p overfill is @c TRUE.");
    if (overfill)
        rpc_overfill_buffers(pco_iut, iut_s, NULL);

    TEST_STEP("Close tester socket.");
    RPC_CLOSE(pco_tst, tst_s);
    /* Timeout is required to make sure FIN/RST packet is delivered. */
    TAPI_WAIT_NETWORK;

    sendbuf = te_make_buf_by_len(length);

    TEST_STEP("Call I/O function for the first time according to "
              "@p first_call and @p aux_func parameters.");
    if (ods_first)
    {
        exp.prepare_must_fail = overfill ? TRUE : FALSE;
        exp.prepare_error = ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET;
        exp.complete_must_fail = first_raw ? TRUE : FALSE;
        exp.complete_error = RPC_EPIPE;
        test_od_send(pco_iut, iut_s, sendbuf, length, first_raw,
                     iut_if->if_index, &exp, "First call");
        if (!exp.prepare_must_fail && exp.complete_must_fail)
            got_epipe = TRUE;
    }
    else
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = IOCALL(pco_iut, iut_s, sendbuf, length);
        if (overfill)
        {
            if (rc != -1)
            {
                TEST_VERDICT("First call: peer closed its socket with not "
                             "empty Rx queue, I/O function unexpectedly "
                             "succeed");
            }
            CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                            "First call: peer closed its socket with not "
                            "empty Rx queue, I/O function returned -1, but");
            got_econnreset = TRUE;
        }
        else if (rc == -1)
        {
            TEST_VERDICT("First call: I/O function failed with %r",
                         RPC_ERRNO(pco_iut));
        }
    }

    /*
     * Timeout is required after send operation to make sure a reply packet
     * is delivered.
     */
    if (FIRST_SEND)
        TAPI_WAIT_NETWORK;

    TEST_STEP("Check SO_ERROR if @p get_err_first is @c TRUE.");
    if (get_err_first)
        check_so_error(pco_iut, iut_s, got_epipe, got_econnreset);

    TEST_STEP("Call I/O function a second time according to "
              "@p second_call and @p aux_func parameters.");
    if (ods_second)
    {
        exp.prepare_must_fail = (overfill || FIRST_SEND) ? TRUE : FALSE;
        exp.prepare_error = ONLOAD_DELEGATED_SEND_RC_BAD_SOCKET;
        exp.complete_must_fail = second_raw ? TRUE : FALSE;
        exp.complete_error = RPC_EPIPE;
        test_od_send(pco_iut, iut_s, sendbuf, length, second_raw,
                     iut_if->if_index, &exp, "Second call");
        if (!exp.prepare_must_fail && exp.complete_must_fail)
            got_epipe = TRUE;
    }
    else
    {
        RPC_AWAIT_ERROR(pco_iut);
        rc = IOCALL(pco_iut, iut_s, sendbuf, length);
        if (overfill && !get_err_first)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_ECONNRESET,
                            "Second call: peer closed its socket with not "
                            "empty Rx queue, I/O function returned -1, but");
        }
        else
        {
            if (aux_func_is_send)
            {
                TEST_SUBSTEP("Check that TX function fails with @c EPIPE.");
                if (rc != -1)
                {
                    TEST_VERDICT("Second call: I/O function unexpectedly "
                                 "succeed");
                }
                CHECK_RPC_ERRNO(pco_iut, RPC_EPIPE, "Second call: "
                                "I/O function returned -1, but");
                got_epipe = TRUE;
            }
            else
            {
                TEST_SUBSTEP("Check that RX function returns 0.");
                if (rc != 0)
                {
                    TEST_VERDICT("Second call: I/O function returned %d "
                                 "instead of 0 and set errno to %r",
                                 rc, RPC_ERRNO(pco_iut));
                }
            }
        }
    }

    TEST_STEP("Check SO_ERROR if @p get_err_first is @c FALSE.");
    if (!get_err_first)
    {
        TAPI_WAIT_NETWORK;
        check_so_error(pco_iut, iut_s, got_epipe, got_econnreset);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(sendbuf);

    TEST_END;
}
