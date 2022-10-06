/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcp_cork_aux TCP_CORK socket option used with TCP_MAXSEG or sendfile()
 *
 * @objective Check that when the @c TCP_CORK option is set on the socket and some data are transmitted, it is transmitted in the packets of size equal to @c MSS.
 *
 * @type conformance
 *
 * @reference MAN 7 tcp
 *
 * @param pco_iut          PCO on IUT
 * @param pco_tst          PCO on TESTER
 * @param iut_if           Network interface on @p pco_iut
 * @param iut_addr         Network address on @p pco_iut
 * @param tst_addr         Network address on @p pco_tst
 * @param set_maxseg       Should we set MSS before testing?
 * @param connection_mss   @c MSS, that should be set for the connection
 *                         (if set_maxseg is TRUE)
 * @param ts_option_length Length of the timestamp option
 * @param send_size        Size of data transmitted with one call of send()
 * @param packets_number   Number of packets to be sent (if we use
 *                         rpc_many_send)
 * @param remove_cork      Should we remove TCP_CORK option to push the
 *                         last packet (boolean)?
 * @param first_func       "send" if we should call @b send() firstly in @b
 *                         sendfile() test, "sendfile" if we should call @b
 *                         sendfile() in this case
 * @param second_func      "send" if we should call @b send() secondly in @b
 *                         sendfile() test, "sendfile" if we should call @b
 *                         sendfile() in this case. If both first_func and
 *                         second_func are "send", @b rpc_many_send() is used.
 *
 * @par Test sequence:
 * -# Create file(s) if we test @b sendfile().
 * -# Create @p iut_s socket of type @c SOCK_STREAM on @p pco_iut.
 * -# Disable TCP and generic segmentation offload on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_STREAM on @p pco_tst.
 * -# If @p set_maxseg, set @c MSS to @p connection_mss using the
 *    @c TCP_MAXSEG socket option for @p iut_s socket.
 * -# Establish TCP connection between @p iut_s and @p tst_s. @p acc_s
 *    will be accepted socket on the @p pco_tst.
 * -# If @p set_maxseg, check that the @c MSS value on the @p iut_s is
 *    (@p connection_mss - @p ts_option_length).
 * -# Set the @c TCP_CORK socket option on the @p iut_s.
 * -# If both firs_func and second_func are "send", send @p packets_number
 *    packets of the size @p send_size bytes each from the @p iut_s to the
 *    @p acc_s.
 * -# If at least one of first_func, second_func is "sendfile", call
 *    functions defined by first_func and second_func.
 * -# If @p remove_cork, unset TCP_CORK for @p iut_s socket.
 * -# Receive all the data sent through @p acc_s socket.
 * -# Check, that all received packets on @p acc_s have @c MSS size
 *    (excepting zero-sized ACKs and the last packet which can be less).
 *    Also check, that TCP_PSH flag in received packets is set
 *    properly.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Konstantin Ushakov <Konstantin.Ushakov@oketlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcp_cork_aux"

#include "sockapi-test.h"

#include "tapi_ip4.h"
#include "tapi_udp.h"
#include "tapi_tcp.h"

#include "ndn_eth.h"
#include "ndn_ipstack.h"

#include "sendfile_common.h"

#include "te_ethtool.h"

#define TST_BUF_LEN        150000
#define SENT_DATA_SIZE     10000
#define TCP_HEADER_LENGTH  20
#define IP_HDR_LEN         20
#define MAX_PACKETS_NUM    500
#define FILENAME1          "sendfile1.pco_iut"
#define FILENAME2          "sendfile2.pco_iut"
#define MAX_CFG_STR_LEN    1000

#define FUNC_SEND          1
#define FUNC_SENDFILE      2
#define FUNC_PARAM         {"send", FUNC_SEND}, {"sendfile", FUNC_SENDFILE}

static unsigned int     packets_received = 0;
static uint64_t         total_sent;
static unsigned int     ts_option_length = 12;
static unsigned int     packets_bytes_received = 0;
static unsigned int     fail_counter = 0;
static unsigned int     psh_counter = 0;

/**
 * User callback, which is passed to the tapi_tad_trrecv_start()
 * function to handle captured packets.
 *
 * @param pkt       Packet to be handled.
 * @param userdata  The mss value, that should be checked.
 */
static void
user_pkt_handler(const tcp4_message *pkt, void *userdata)
{
    unsigned int length = 0;

    assert(*((int *)userdata) > 0);
    length = pkt->payload_len;

    RING("Packet with %d bytes received, packet number is %d "
         "length = %d, mss = %d",
         length, packets_received, length, *((int *) userdata));

    packets_received++;

    /*
     * Zero-size packets with only ACK and/or PSH flags set are not
     * considered as error when testing TCP_CORK (error is mainly
     * non-zero-size packet with size is not equal to MSS).
     * But unexpected TCP_PSH flag occurrence is noted in verdict
     * later.
     */
    if (!(length == 0 && (pkt->flags == TCP_ACK_FLAG ||
          pkt->flags == (TCP_ACK_FLAG | TCP_PSH_FLAG))))
    {
        if ((total_sent - packets_bytes_received) >=
            (*((unsigned int *)userdata)) &&
            length != *((unsigned int *)userdata))
        {
            RING("Packet #%u has unexpected length: length=%d, "
                 "expected=%d", packets_received, length,
                 *((int *)userdata));
            fail_counter++;
        }
        else if (total_sent - packets_bytes_received < (*((unsigned int *) userdata))
                 && length != total_sent - packets_bytes_received)
        {
            RING("Packet #%u has unexpected length: length=%d, "
                 "expected=%d", packets_received, length,
                 total_sent % *((int *)userdata));
            fail_counter++;
        }
    }
    packets_bytes_received += length;

    if (((pkt->flags & TCP_PSH_FLAG) != 0) &&
        (packets_bytes_received != total_sent))
    {
        RING("Unexpected TCP_PSH flag is encountered in packet %u",
             packets_received);
        psh_counter++;
    }
    else if (((pkt->flags & TCP_PSH_FLAG) == 0) &&
             (packets_bytes_received == total_sent))
        RING_VERDICT("TCP_PSH flag in the last fragment is missed");

    return;
}

int
main(int argc, char *argv[])
{
    int             sid;

    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;
    int             acc_s = -1;

    const struct sockaddr     *tst_addr = NULL;
    const struct if_nameindex *tst_if = NULL;
    const struct sockaddr     *iut_addr = NULL;
    const struct if_nameindex *iut_if = NULL;
    uint8_t                    rx_buf[TST_BUF_LEN] = { 0, };

    unsigned int               mss = 0;
    unsigned int               cork = 1;
    unsigned int               connection_mss = 0;
    unsigned int               bytes_received = 0;
    unsigned int               send_size = 0;
    unsigned int               packets_number = 0;
    csap_handle_t              csap = CSAP_INVALID_HANDLE;
    unsigned int               received_packets_number = 0;
    unsigned int               i;
    tarpc_size_t               send_length[MAX_PACKETS_NUM];
    uint64_t                   sent;
    te_bool                    remove_cork = FALSE;
    te_bool                    set_maxseg = FALSE;

    te_bool                    created_iut_file1 = FALSE;
    te_bool                    created_iut_file2 = FALSE;
    char                      *file_iut1 = FILENAME1;
    char                      *file_iut2 = FILENAME2;
    unsigned long int          file1_length = 0;
    unsigned long int          file2_length = 0;
    int                        file1_fd = -1;
    int                        file2_fd = -1;

    int first_func = 0;
    int second_func = 0;
    int percents = 0;

    te_bool is_failed = FALSE;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);
    TEST_GET_IF(tst_if);
    TEST_GET_BOOL_PARAM(set_maxseg);
    TEST_GET_INT_PARAM(ts_option_length);
    TEST_GET_INT_PARAM(send_size);
    TEST_GET_BOOL_PARAM(remove_cork);

    TEST_GET_ENUM_PARAM(first_func, FUNC_PARAM);
    TEST_GET_ENUM_PARAM(second_func, FUNC_PARAM);

    if (first_func == FUNC_SEND && second_func == FUNC_SEND)
    {
        TEST_GET_INT_PARAM(packets_number);
        if (packets_number > MAX_PACKETS_NUM)
            TEST_FAIL("Too big number of packets");
    }
 
    if (set_maxseg)
        TEST_GET_INT_PARAM(connection_mss);

    if (first_func == FUNC_SENDFILE && second_func == FUNC_SENDFILE)
    {
        /*
         * Sended data is divided into two files. May be it is
         * not important but to make two files not of the same size 60% of
         * data is placed in the first file.
         */

        if (send_size > SENT_DATA_SIZE / 2)
            TEST_FAIL("Too big send_size parameter.");

        file1_length = (SENT_DATA_SIZE) * 0.6;
        file2_length = SENT_DATA_SIZE - file1_length;
    }
    else
    {
        if (send_size >= SENT_DATA_SIZE)
            TEST_FAIL("Too big send_size parameter.");

        file1_length = file2_length = SENT_DATA_SIZE - send_size;
    }

    if (first_func == FUNC_SENDFILE)
    {
        CREATE_REMOTE_FILE(pco_iut->ta, file_iut1, 'Y', file1_length);
        created_iut_file1 = TRUE;
    }

    if (second_func == FUNC_SENDFILE)
    {
        CREATE_REMOTE_FILE(pco_iut->ta, file_iut2, 'Y', file2_length);
        created_iut_file2 = TRUE;
    }

    /* Prepare CSAP */
    CHECK_RC(rcf_ta_create_session(pco_tst->ta, &sid));

    INFO("Test: Created session: %d", sid);

    rc = tapi_tcp_ip4_eth_csap_create(pco_tst->ta, sid, tst_if->if_name,
                                      TAD_ETH_RECV_HOST |
                                      TAD_ETH_RECV_NO_PROMISC,
                                      NULL, NULL,
                                      htonl(INADDR_ANY), htonl(INADDR_ANY),
                                      -1, -1, &csap);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /*
     * TCP and Generic segmentation offload must be disabled to prevent
     * observing packets of 2 * MSS, 3 * MSS and so on size.
     */
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                            pco_iut->ta, iut_if->if_name,
                                            "tx-tcp-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                            pco_iut->ta, iut_if->if_name,
                                            "tx-generic-segmentation", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                            pco_tst->ta, tst_if->if_name,
                                            "rx-gro", 0));
    CHECK_RC(tapi_cfg_if_feature_set_all_parents(
                                            pco_tst->ta, tst_if->if_name,
                                            "rx-lro", 0));

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (set_maxseg)
    {
        mss = connection_mss;
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_setsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
        if (rc != 0)
            TEST_VERDICT("setsockopt(SOL_TCP, TCP_MAXSEG) failed with "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        INFO("Setting MSS value to %d", mss);
    }

    rpc_bind(pco_tst, tst_s, tst_addr);
    rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
    rpc_connect(pco_iut, iut_s, tst_addr);
    CHECK_SOCKET_STATE(pco_iut, iut_s, pco_tst, tst_s, STATE_CONNECTED);
    acc_s = rpc_accept(pco_tst, tst_s, NULL, NULL);

    rpc_getsockopt(pco_iut, iut_s, RPC_TCP_MAXSEG, &mss);
    if (set_maxseg && mss != connection_mss - ts_option_length)
    {
        ERROR_VERDICT("The MSS value is %d instead of %d",
                      mss, connection_mss - ts_option_length);
        is_failed = TRUE;
    }

    /* Data transmission */
    rpc_setsockopt(pco_iut, iut_s, RPC_TCP_CORK, &cork);

    if (first_func == FUNC_SEND && second_func == FUNC_SEND)
        total_sent = send_size * packets_number;
    else
        total_sent = SENT_DATA_SIZE;

    if (total_sent > TST_BUF_LEN)
        TEST_FAIL("Too many data to send.");

    /* CSAP manipulation */
    rc = tapi_tad_trrecv_start(pco_tst->ta, sid, csap, NULL,
                               TAD_TIMEOUT_INF,
                               0,
                               RCF_TRRECV_PACKETS);
    if (rc != 0)
        TEST_FAIL("Failed to start receiving on the CSAP, rc = %X, "
                  "csap id %d", rc, csap);

    if (first_func == FUNC_SEND && second_func == FUNC_SEND)
    {
        for (i = 0; i < packets_number; i++)
        {
            send_length[i] = send_size;
        }

        rpc_many_send(pco_iut, iut_s, 0, send_length, packets_number, &sent);

        if (sent != total_sent)
            TEST_FAIL("many_send didn't send all the data required.");
    }
    else
    {
        if (first_func == FUNC_SEND)
        {
            rpc_send(pco_iut, iut_s, rx_buf, send_size, 0);
        }
        else
        {
            RPC_FOPEN_D(file1_fd, pco_iut, file_iut1, RPC_O_RDONLY, 0);
            sent = rpc_sendfile(pco_iut, iut_s, file1_fd, NULL,
                                file1_length, FALSE);
            if (sent != file1_length)
            {
                TEST_FAIL("Unexpected number of sent bytes in rpc_sendfile(): "
                          "sent bytes:%d, expected:%d", sent, file1_length);
            }
        }

        if (second_func == FUNC_SEND)
        {
            rpc_send(pco_iut, iut_s, rx_buf, send_size, 0);
        }
        else
        {
            RPC_FOPEN_D(file2_fd, pco_iut, file_iut2, RPC_O_RDONLY, 0);
            sent = rpc_sendfile(pco_iut, iut_s, file2_fd, NULL,
                                file2_length, FALSE);
            if (sent != file2_length)
            {
                TEST_FAIL("Unexpected number of sent bytes in rpc_sendfile(): "
                          "sent bytes:%d, expected:%d", sent, file2_length);
            }
        }
    }

    if (remove_cork)
    {
        cork = 0;
        rpc_setsockopt(pco_iut, iut_s, RPC_TCP_CORK, &cork);
    }

    SLEEP(1);
    bytes_received = 0;
    while (bytes_received != total_sent)
        bytes_received += rpc_recv(pco_tst, acc_s, rx_buf, mss, 0);

    INFO("%d bytes received", bytes_received);

    if (tapi_tad_trrecv_stop(pco_tst->ta, sid, csap,
                             tapi_tcp_ip4_eth_trrecv_cb_data(user_pkt_handler,
                                                             &mss),
                             &received_packets_number))
    {
        TEST_FAIL("Failed to receive packets");
    }

    if (psh_counter > 1)
    {
        percents = psh_counter * 100 / received_packets_number;
        RING("Unexpected TCP_PSH flag value was encountered in %d%%"
             " of packets", percents);
        /* Allow 1 unexpected packet with PSH flag. */
        if (psh_counter == 2)
        {
            WARN("One unexpected TCP_PSH flag value was encountered");
        }
        else
        {
            RING_VERDICT("More than one unexpected TCP_PSH flag values"
                         "were encountered");
        }
    }

    if (fail_counter > 0)
    {
        percents = fail_counter * 100 / received_packets_number;
        if (percents > 50)
        {
            ERROR("Coalescing missing in %d%% of packets",
                  percents);
            TEST_VERDICT("Coalescing missing in the most part of packets",
                         percents);
        }
        else
            RING("Coalescing missing in %d%% of packets",
                 percents);

        RING_VERDICT("Coalescing missing few times");
    }

    if (is_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    if (created_iut_file1 == TRUE)
    {
        rpc_close(pco_iut, file1_fd);
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut1);
    }
    if (created_iut_file2 == TRUE)
    {
        rpc_close(pco_iut, file2_fd);
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut2);
    }

    if (pco_tst != NULL && csap != CSAP_INVALID_HANDLE &&
        tapi_tad_csap_destroy(pco_tst->ta, sid, csap))
        ERROR("Failed to destroy CSAP");

    CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
