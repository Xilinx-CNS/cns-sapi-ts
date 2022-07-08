/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-default_bufs System wide default values preset for receive and send buffers lengths.
 *
 * @objective Check that default lengths of send and receive socket buffers
 *            are set according to system wide appropriate values.
 *
 * @type conformance
 *
 * @param pco_iut    PCO on IUT
 * @param pco_native PCO on IUT host, but TESTER type
 * @param pco_tst    PCO on TESTER
 * @param type       Socket type: @c SOCK_DGRAM or @c SOCK_STREAM
 * @param server     TRUE if IUT side socket is a server else FALSE
 * @param change_val Whether to change system wide default values
 *                   for reveive and send buffers lengths or not
 *
 * @par Test sequence:
 *
 * -# Retrieve system wide default values preset for
 *    send and receive buffers of the type @p type socket.
 * -# If @p change_val, try decrease system wide default
 *    values for send and receive buffers lengths and
 *    restart @p pco_iut.
 * -# Create @p exp_s socket of the specified @p type on the
 *    @p pco_native and retrieve send and receive buffers lengths
 *    to check that they are equal to system wide defaults ones.
 * -# Create @p iut_s on @p pco_iut and @p tst_s on @p pco_tst
 *    and establish connection between them. Check default system
 *    wide values with ones returned by means of
 *    @b getsockopt(@c SO_SNDBUF/@c SO_RCVBUF) in each socket state.
 * -# Close created sockets, return to the original configuration.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/default_bufs"

#include "sockapi-test.h"
#include "tapi_cfg.h"

/**
 * Check whether current SO_SNDBUF/SO_RCVBUF value for a socket
 * matches system-wide default value.
 *
 * @param _pco_             RPC server handle.
 * @param _stage_           String identifying when measurement is done,
 *                          to be printed in verdict (after socket
 *                          creation, after connect(), etc).
 * @param _sock_            Socket descriptor.
 * @param _tolerate_inc_    If TRUE, do not complain about increased
 *                          SO_SNDBUF/SO_RCVBUF value.
 */
#define CHECK_DEFAULT_LEN(_pco_, _stage_, _sock_, _tolerate_inc_) \
    do {                                                                \
        rpc_getsockopt(_pco_, _sock_, RPC_SO_SNDBUF, &sock_snddef);     \
        rpc_getsockopt(_pco_, _sock_, RPC_SO_RCVBUF, &sock_rcvdef);     \
        if (sock_snddef != swide_sndbuf_def &&                          \
            !(_tolerate_inc_ && sock_snddef > swide_sndbuf_def))        \
            RING_VERDICT("(%s) SO_SNDBUF default socket option value "  \
                         "differentiates from system wide one",         \
                         _stage_);                                      \
                                                                        \
        if (sock_rcvdef != swide_rcvbuf_def &&                          \
            !(_tolerate_inc_ && sock_rcvdef > swide_rcvbuf_def))        \
            RING_VERDICT("(%s) SO_RCVBUF default socket option value "  \
                         "differentiates from system wide one",         \
                         _stage_);                                      \
    } while (0)

#define SET_AND_CHECK(def_, val_) \
    do {                                                            \
        /* Decrease system wide snd/rcv buffer max value */         \
        val_ /= 2;                                                  \
        RING("Attempt to set %s to %d", def_, val_);                \
        CHECK_RC(tapi_cfg_sys_ns_set_int(pco_native->ta, val_,      \
                                         NULL, def_));              \
        changed_ ## val_ = TRUE;                                    \
        /* Check that system wide values set correctly */           \
        CHECK_RC(tapi_cfg_sys_ns_get_int(pco_native->ta, &def_aux,  \
                                         def_));                    \
        if (def_aux != val_)                                        \
        {                                                           \
            if (def_aux == init_ ## val_)                           \
                RING_VERDICT("%s was not changed", def_);           \
            else                                                    \
                RING_VERDICT("%s was not set to value specified",   \
                             def_);                                 \
        }                                                           \
        val_ = def_aux;                                             \
    } while(0)

int
main(int argc, char *argv[])
{
    rcf_rpc_server             *pco_iut = NULL;
    rcf_rpc_server             *pco_native = NULL;
    rcf_rpc_server             *pco_tst = NULL;

    rpc_socket_type             sock_type;

    int                         iut_s = -1;
    int                         exp_s = -1;
    int                         tst_s = -1;
    int                         acc_s = -1;

    te_bool                     server = FALSE;
    te_bool                     change_val = FALSE;

    const struct sockaddr      *tst_addr = NULL;
    const struct sockaddr      *iut_addr = NULL;

    int                         swide_sndbuf_def = 0;
    int                         swide_rcvbuf_def = 0;
    int                         init_swide_sndbuf_def = 0;
    int                         init_swide_rcvbuf_def = 0;
    te_bool                     changed_swide_sndbuf_def = FALSE;
    te_bool                     changed_swide_rcvbuf_def = FALSE;
    int                         def_aux = 0;
    char                       *snd_buf_def;
    char                       *rcv_buf_def;

    int                         sock_snddef = 0;
    int                         sock_rcvdef = 0;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_native);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_BOOL_PARAM(server);
    TEST_GET_BOOL_PARAM(change_val);

    if (sock_type == RPC_SOCK_STREAM)
    {
        snd_buf_def = "net/ipv4/tcp_wmem:1";
        rcv_buf_def = "net/ipv4/tcp_rmem:1";
    }
    else if (sock_type == RPC_SOCK_DGRAM)
    {
        snd_buf_def = "net/core/wmem_default";
        rcv_buf_def = "net/core/rmem_default";
    }
    else
        TEST_FAIL("Unsupported socket type");

    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_native->ta, &swide_sndbuf_def,
                                     snd_buf_def));
    CHECK_RC(tapi_cfg_sys_ns_get_int(pco_native->ta, &swide_rcvbuf_def,
                                     rcv_buf_def));

    init_swide_sndbuf_def = swide_sndbuf_def;
    init_swide_rcvbuf_def = swide_rcvbuf_def;

    if (change_val)
    {
        SET_AND_CHECK(snd_buf_def, swide_sndbuf_def);
        SET_AND_CHECK(rcv_buf_def, swide_rcvbuf_def);

        rcf_rpc_server_restart(pco_iut);
    }

    /* Create socket to get default snd/rcv buffer values */
    exp_s = rpc_socket(pco_native,
                       rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    CHECK_DEFAULT_LEN(pco_native, "created pco_native",
                      exp_s, FALSE);

    /*
     * Create a new socket on IUT to check influence of system wide
     * default values on snd/recv buffers when socket is in
     * different states.
     */
    RING("Checking influence new system wide default values "
         "on a new created socket");
    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);
    CHECK_DEFAULT_LEN(pco_iut, "created pco_iut socket", iut_s, FALSE);

    rpc_bind(pco_iut, iut_s, iut_addr);
    CHECK_DEFAULT_LEN(pco_iut, "bound pco_iut socket", iut_s, FALSE);

    tst_s = rpc_socket(pco_tst, rpc_socket_domain_by_addr(tst_addr),
                       sock_type, RPC_PROTO_DEF);
    rpc_bind(pco_tst, tst_s, tst_addr);

    if (server == TRUE)
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
            CHECK_DEFAULT_LEN(pco_iut, "listening pco_iut socket",
                              iut_s, FALSE);
        }

        rpc_connect(pco_tst, tst_s, iut_addr);

        if (sock_type == RPC_SOCK_STREAM)
        {
            acc_s = rpc_accept(pco_iut, iut_s, NULL, NULL);
            CHECK_DEFAULT_LEN(pco_iut, "accepted pco_iut socket",
                              acc_s, TRUE);
        }
    }
    else
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            rpc_listen(pco_tst, tst_s, SOCKTS_BACKLOG_DEF);
        }
        rpc_connect(pco_iut, iut_s, tst_addr);
        CHECK_DEFAULT_LEN(pco_iut, "connected pco_iut socket",
                          iut_s, TRUE);
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, acc_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    CLEANUP_RPC_CLOSE(pco_native, exp_s);

    if (changed_swide_sndbuf_def)
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_native->ta, init_swide_sndbuf_def,
                                    NULL, snd_buf_def));
    if (changed_swide_rcvbuf_def)
        CLEANUP_CHECK_RC(
            tapi_cfg_sys_ns_set_int(pco_native->ta, init_swide_rcvbuf_def,
                                    NULL, rcv_buf_def));

    if (changed_swide_sndbuf_def || changed_swide_rcvbuf_def)
        rcf_rpc_server_restart(pco_iut);

    TEST_END;
}
