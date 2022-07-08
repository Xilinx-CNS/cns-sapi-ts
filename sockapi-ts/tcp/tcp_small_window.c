/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 *
 * $Id$
 */

/** @page tcp_small_window Operability when peer announces small TCP window
 *
 * @objective Check possibility of TCP data transfer when peer has small
 *            SO_RCVBUF (and, as result, announces small TCP window).
 *
 * @type Conformance, compatibility
 *
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on Tester
 * @param tst_rcvbuf    SO_RCVBUF value to be set on @p pco_tst.
 * @param active        does IUT perform acitve open?
 * @param early         set SO_RCVBUF before connect/listen
 * @param cache_socket  Create cached socket to be reused.
 *
 * @par Scenario:
 *
 * -# If @p cache_socket is @c TRUE, create cached socket in this case.
 * -# Create a socket on @p pco_tst. If @p early is @c true, set 
 *    @c SO_RCVBUF socket option to @p tst_rcvbuf value.
 * -# Create a TCP connection between IUT and Tester, with IUT making passive
 *    or active open depending on @p active and using previously created
 *    socket on Tester.
 * -# If @p early is @c false, set @c SO_RCVBUF socket option to @p tst_rcvbuf
 *    value on connected socket on Tester side.
 * -# Check that this connection may be used to transfer data from IUT to
 *    Tester.
 * -# Close created sockets.
 *
 * @author Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "tcp/tcp_small_window"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "sendfile_common.h"
#include "tcp_test_macros.h"
#include "iomux.h"

/* Size of data to be sent */
//#define DATA_SIZE (1500 * 5)
#define DATA_SIZE 1500
/* Timeout to wait for new data on receive side */
#define TIMEOUT  12000

#define FILENAME   "sendfile.pco_iut"

static void 
set_rcvbuf(rcf_rpc_server *pco, int s, int rcvbuf)
{
    int     optval;

    rpc_setsockopt(pco, s, RPC_SO_RCVBUF, &rcvbuf);
    rpc_getsockopt(pco, s, RPC_SO_RCVBUF, &optval);
    RING("SO_RCVBUF on %s was set to %d, getting value %d", pco->name,
         rcvbuf, optval);
}

int 
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;

    int             iut_s = -1;
    int             acc_s = -1;
    int             tst_s = -1;
    int             tst_conn;
    int             iut_conn;
    te_bool         active;
    te_bool         early;
    int             tst_rcvbuf;

    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    char                    snd_buf[DATA_SIZE];
    char                    rcv_buf[DATA_SIZE];
    int                     i;
    te_bool                 use_sendfile = FALSE;
    char                   *file_iut = FILENAME;
    te_bool                 created_iut_file =FALSE;
    int                     file_fd = -1;
    te_bool                 cache_socket;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_BOOL_PARAM(active);
    TEST_GET_BOOL_PARAM(early);
    TEST_GET_INT_PARAM(tst_rcvbuf);
    TEST_GET_BOOL_PARAM(use_sendfile);
    TEST_GET_BOOL_PARAM(cache_socket);

    TEST_STEP("If @p cache_socket and @p acitve are TRUE - create "
              "cached socket.");
    if (active)
    {
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr,
                                    -1, TRUE, cache_socket);
    }

    if (use_sendfile)
    {
        CREATE_REMOTE_FILE(pco_iut->ta, file_iut, 'Y', DATA_SIZE);
        created_iut_file = TRUE;
    }
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr), 
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);

    if (active)
        rpc_bind(pco_tst, tst_s, tst_addr);
    else
        rpc_bind(pco_iut, iut_s, iut_addr);

    if (early)
        set_rcvbuf(pco_tst, tst_s, tst_rcvbuf);

    if (active)
    {
        rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        rpc_connect(pco_iut, iut_s, tst_addr);
        acc_s = rpc_accept(pco_tst, tst_s, NULL, 0);
        tst_conn = acc_s;
        iut_conn = iut_s;
    }
    else
    {
        rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        sockts_create_cached_socket(pco_iut, pco_tst, iut_addr, tst_addr,
                                    iut_s, FALSE, cache_socket);
        rpc_connect(pco_tst, tst_s, iut_addr);
        acc_s = rpc_accept(pco_iut, iut_s, NULL, 0);
        tst_conn = tst_s;
        iut_conn = acc_s;
    }

    if (!early)
        set_rcvbuf(pco_tst, tst_conn, tst_rcvbuf);

    /* Send data. */
    if (use_sendfile)
    {
        RPC_FOPEN_D(file_fd, pco_iut, file_iut, RPC_O_RDONLY, 0);
        pco_iut->op = RCF_RPC_CALL;
        rpc_sendfile(pco_iut, iut_conn, file_fd, NULL, DATA_SIZE, FALSE);
    }
    else
    {
        memset(snd_buf, 0xAD, DATA_SIZE);
        pco_iut->op = RCF_RPC_CALL;
        rpc_send(pco_iut, iut_conn, snd_buf, DATA_SIZE, 0);
    }

    /* Receive data. */
    i = 0;
    do {
        i += rpc_read(pco_tst, tst_conn, rcv_buf + i, DATA_SIZE - i);
        rc = iomux_call_default_simple(pco_tst, tst_conn, EVT_RD, NULL,
                                       TIMEOUT);
    } while (rc == 1);

    /* Check that data is sent */
    if (use_sendfile)
        rc = rpc_sendfile(pco_iut, iut_conn, file_fd, NULL, DATA_SIZE,
                          FALSE);
    else
        rc = rpc_send(pco_iut, iut_conn, snd_buf, DATA_SIZE, 0);
    if (rc < DATA_SIZE)
        RING("Failed to send %d bytes of data, write() returned %d", 
             DATA_SIZE, rc);

    /* Check data. */
    if (i < DATA_SIZE)
        TEST_FAIL("Failed to receive %d bytes of data: got only %d", 
                  DATA_SIZE, i);

    if (memcmp(snd_buf, rcv_buf, DATA_SIZE) != 0)
    {
        for (i = 0; i < DATA_SIZE; i++)
        {
            if (((snd_buf[i] != rcv_buf[i]) && !use_sendfile) &&
                ((rcv_buf[i] != 'Y') && use_sendfile))
                TEST_FAIL("Byte %d differs in send and receive buffers: "
                          "%d != %d", i, use_sendfile ? 'Y' : snd_buf[i],
                          rcv_buf[i]);
        }
    }

    TEST_SUCCESS;

cleanup:
    if (created_iut_file == TRUE)
    {
        rpc_close(pco_iut, file_fd);
        REMOVE_REMOTE_FILE(pco_iut->ta, file_iut);
    }
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    if (active)
        CLEANUP_RPC_CLOSE(pco_tst, acc_s);
    else
        CLEANUP_RPC_CLOSE(pco_iut, acc_s);

    TEST_END;
}

