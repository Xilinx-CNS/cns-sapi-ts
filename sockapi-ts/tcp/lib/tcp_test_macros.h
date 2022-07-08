/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TCP Test Suite
 *
 * TCP test suite useful macros and inline functions
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_TCP_TEST_MACROS_H__
#define __TS_TCP_TEST_MACROS_H__

#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
#include "tapi_cfg.h"
#include "tapi_test.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCP_MAX_ATTEMPTS 125
#define MSEC_BEFORE_NEXT_ATTEMPT 1000

/* Create fds for select() function call */
#define TCP_TEST_CREATE_FDS(_l) \
    do {                                         \
        fds_##_l = rpc_fd_set_new(pco_iut);      \
        rpc_do_fd_zero(pco_iut, fds_##_l);       \
        rpc_do_fd_set(pco_iut, iut_s, fds_##_l); \
    } while (0)

/**
 * Resolve parameter, containing string representation of error,
 * prepare test conditions accordingly.
 */
#define TCP_TEST_RESOLVE_ERROR(_error, _err_code, _conn_addr) \
    do {                                                                \
        if (strcmp(_error, "ETIMEDOUT") == 0)                           \
        {                                                               \
            RING("Checking for ETIMEDOUT");                             \
            update_arp(pco_tst, tst_if, NULL, NULL, gw_tst_addr,        \
                       alien_link_addr, TRUE);                          \
            _err_code = RPC_ETIMEDOUT;                                  \
            _conn_addr = tst_addr;                                      \
            CFG_WAIT_CHANGES;                                           \
        }                                                               \
        else if (strcmp(_error, "EHOSTUNREACH") == 0)                   \
        {                                                               \
            RING("Checking for EHOSTUNREACH");                          \
            _err_code = RPC_EHOSTUNREACH;                               \
            _conn_addr = gw_fake_addr;                                  \
        }                                                               \
        else if (strcmp(_error, "ECONNREFUSED") == 0)                   \
        {                                                               \
            RING("Checking for ECONNREFUSED");                          \
            _err_code = RPC_ECONNREFUSED;                               \
            _conn_addr = tst_addr;                                      \
        }                                                               \
        else                                                            \
            TEST_FAIL("Unexpected error parameter value, %s", _error);  \
    } while(0)

/* Check send/recv functions */
#define TCP_TEST_CHECK_SEND_RECV(_func) \
    do {                                                            \
        te_bool is_connect = strcmp(_func, "connect") == 0;         \
                                                                    \
        TAPI_CALL_CHECK_RC(pco_iut, send, -1, RPC_EPIPE,            \
                           iut_s, data_buf, DATA_BULK, 0);          \
                                                                    \
        /* Linux is crazy. Socket state depends on which function   \
         * really failed.  Adopt this test for other OSes           \
         * if necessary. */                                         \
        TAPI_CALL_CHECK_RC(pco_iut, recv, is_connect ? -1 : 0,      \
                           RPC_ENOTCONN, iut_s, data_buf,           \
                           DATA_BULK, 0);                           \
    } while(0)

/**
 * Call a send function determined by its name.
 * 
 * @param func      The function name
 * @param rpcs      RPC server handler
 * @param sock      Socket
 * @param data_buf  Data buffer
 * @param len       The buffer length
 * @param err       Expected error code
 */
static inline void
call_send_function(const char *func, rcf_rpc_server *rpcs, int sock,
                   uint8_t *data_buf, int len, int err)
{
    rpc_send_f send_f;
    int rc;

    send_f = rpc_send_func_by_string(func);
    if (send_f == NULL)
        TEST_FAIL("Function %s is unsupported by the test", func);

    RPC_AWAIT_IUT_ERROR(rpcs);
    rc = send_f(rpcs, sock, data_buf, len, 0);
    if (rc != -1)
        TEST_VERDICT("Unexpected code was returned: %d", rc);
    if (RPC_ERRNO(rpcs) != err)
        TEST_VERDICT("Function %s() failed with unexpected errno: %r", func,
                     RPC_ERRNO(rpcs));
}

/**
 * Call function, check rc, if errors received, call send/recv,
 * check their errors.
 */
#define TCP_TEST_CHECK_FUNCTION(_func, _err_code) \
    do {                                                                \
        te_bool error_received = FALSE;                                 \
                                                                        \
        if (strcmp(_func, "connect") == 0)                              \
        {                                                               \
            TAPI_CALL_CHECK_RC(pco_iut, connect, -1, _err_code,         \
                               iut_s, conn_addr);                       \
            error_received = TRUE;                                      \
        }                                                               \
        else if (strcmp(_func, "recv") == 0)                            \
        {                                                               \
            TAPI_CALL_CHECK_RC(pco_iut, recv, -1, _err_code,            \
                               iut_s, data_buf, DATA_BULK, 0);          \
            error_received = TRUE;                                      \
        }                                                               \
        else if (strcmp(_func, "recvmsg") == 0 ||                       \
                 strcmp(_func, "onload_zc_recv") == 0 ||                \
                 strcmp(_func, "onload_zc_hlrx_recv_zc") == 0 ||        \
                 strcmp(_func, "onload_zc_hlrx_recv_copy") == 0)        \
        {                                                               \
            rpc_msghdr msg;                                             \
            struct rpc_iovec vector;                                    \
            memset(&msg, 0, sizeof(msg));                               \
            vector.iov_base = data_buf;                                 \
            vector.iov_len = vector.iov_rlen = DATA_BULK;               \
            msg.msg_iov = &vector;                                      \
            msg.msg_iovlen = msg.msg_riovlen = 1;                       \
                                                                        \
            if (strcmp(_func, "onload_zc_recv") == 0)                   \
            {                                                           \
                TAPI_CALL_CHECK_RC(pco_iut, simple_zc_recv,             \
                                   -1, _err_code,                       \
                                   iut_s, &msg, 0);                     \
            }                                                           \
            else if (strcmp(_func, "onload_zc_hlrx_recv_zc") == 0)      \
            {                                                           \
                TAPI_CALL_CHECK_RC(pco_iut, simple_hlrx_recv_zc,        \
                                   -1, _err_code,                       \
                                   iut_s, &msg, 0, TRUE);               \
            }                                                           \
            else if (strcmp(_func, "onload_zc_hlrx_recv_copy") == 0)    \
            {                                                           \
                TAPI_CALL_CHECK_RC(pco_iut, simple_hlrx_recv_copy,      \
                                   -1, _err_code,                       \
                                   iut_s, &msg, 0, TRUE);               \
            }                                                           \
            else                                                        \
            {                                                           \
                TAPI_CALL_CHECK_RC(pco_iut, recvmsg, -1, _err_code,     \
                                   iut_s, &msg, 0);                     \
            }                                                           \
            error_received = TRUE;                                      \
        }                                                               \
        else if (strcmp(_func, "select") == 0)                          \
        {                                                               \
            int revt = FALSE;                                           \
            int wevt = FALSE;                                           \
            int eevt = FALSE;                                           \
                                                                        \
            rpc_fd_set_p fds_r = RPC_NULL;                              \
            rpc_fd_set_p fds_w = RPC_NULL;                              \
            rpc_fd_set_p fds_e = RPC_NULL;                              \
                                                                        \
            tarpc_timeval           tv = { 2, 0 };                      \
                                                                        \
            TCP_TEST_CREATE_FDS(r);                                     \
            TCP_TEST_CREATE_FDS(w);                                     \
            TCP_TEST_CREATE_FDS(e);                                     \
                                                                        \
            if ((rc = rpc_select(pco_iut, iut_s + 1, fds_r, fds_w,      \
                                 fds_e, &tv)) != 2)                     \
                RING_VERDICT("select() returned %d", rc);               \
                                                                        \
            revt = rpc_do_fd_isset(pco_iut, iut_s, fds_r);              \
            wevt = rpc_do_fd_isset(pco_iut, iut_s, fds_w);              \
            eevt = rpc_do_fd_isset(pco_iut, iut_s, fds_e);              \
            if ((!revt) && (!wevt) && eevt)                             \
                RING_VERDICT("select() returned %d with "               \
                             "%s%s%s%sevent(s)", rc,                    \
                            (revt) ? "EVT_RD " : "",                    \
                            (wevt) ? "EVT_WR " : "",                    \
                            (eevt) ? "EVT_EXC " : "",                   \
                            (!(revt || wevt || eevt)) ? "no " : "");    \
        }                                                               \
        else if (strcmp(_func, "getsockopt") == 0)                      \
        {                                                               \
            int opt_val;                                                \
            rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);     \
            if (opt_val != _err_code)                                   \
                RING_VERDICT("getsockopt(SO_ERROR) returned %r optval", \
                             opt_val);                                  \
            error_received = TRUE;                                      \
        }                                                               \
        else if (strcmp(_func, "poll") == 0)                            \
        {                                                               \
            struct rpc_pollfd   fds[1];                                 \
            int exp = RPC_POLLIN | RPC_POLLOUT |                        \
                      RPC_POLLERR | RPC_POLLHUP;                        \
            fds[0].fd = iut_s;                                          \
            fds[0].events = (RPC_POLLIN | RPC_POLLOUT);                 \
            fds[0].revents = 0;                                         \
                                                                        \
            RING("Expected events: %s", poll_event_rpc2str(exp));       \
            if ((rc = rpc_poll(pco_iut, fds, 1, POLL_TIMEOUT)) != 1)    \
                RING_VERDICT("poll() returned %d", rc);                 \
            else if (fds[0].revents != exp)                             \
                RING_VERDICT("poll() returned %d and sets "             \
                             "events to %s", rc,                        \
                             poll_event_rpc2str(fds[0].revents));       \
        }                                                               \
        else                                                            \
        {                                                               \
            call_send_function(_func, pco_iut, iut_s, data_buf,         \
                               DATA_BULK, _err_code);                   \
            error_received = TRUE;                                      \
        }                                                               \
                                                                        \
        if (error_received)                                             \
            TCP_TEST_CHECK_SEND_RECV(_func);                            \
    } while(0)

/**
 * Determines if it is active or passive connection opening way, if passive
 * determines when listener socket should be closed.
 */
typedef enum {
    OL_ACTIVE = 0,      /**< Active open */
    OL_PASSIVE_OPEN,    /**< Passive open, close listener after opening */
    OL_PASSIVE_CLOSE,   /**< Passive open, close listener just after closing
                             accepted socket */
    OL_PASSIVE_END,     /**< Passive open, close listener in the end of
                             test */
} opening_listener;

#define OPENING_LISTENER  \
    { "active", OL_ACTIVE },  \
    { "passive_open", OL_PASSIVE_OPEN },    \
    { "passive_close", OL_PASSIVE_CLOSE },    \
    { "passive_end", OL_PASSIVE_END }

#define CLOSE_LISTENER(_pos, _sock) \
do {                                \
    if (_pos == opening)            \
        RPC_CLOSE(pco_iut, _sock);  \
} while (0)

#define TSA_CHECK_RC(_ss, _rc)  \
do {                                                                    \
    if ((_rc) != 0)                                                     \
        TEST_VERDICT("%s is not observable when achieved from %s",      \
                     tcp_state_rpc2str(tsa_state_to(_ss)),              \
                     tcp_state_rpc2str(tsa_state_from(_ss)));           \
} while(0)

/**
 * Check socket state during some time, it should be changed to TCP_CLOSE.
 * 
 * @param ss            TSA session
 * @param time_to_wait  Time to wait before the next attempt
 * @param attempts      Number of attempts before giving up
 */
extern void tcp_test_wait_for_tcp_close(tsa_session *ss,
                                        unsigned int time_to_wait,
                                        unsigned int attempts);

/**
 * Get active or passive path to open connection.
 * 
 * @param state     State to be achieved
 * @param active    Determines active or passive path should be chosen
 * 
 * @return String with the path.
 */
extern const char *tcp_test_get_path(rpc_tcp_state state, te_bool active);

/**
 * Change ARP table on IUT to pass packets to TST with actual ethernet
 * address.
 * 
 * @param ss                TSA session
 * @param tst_addr          TST IP address
 * @param alien_link_addr   Alien mac address or @c NULL
 */
extern void test_change_mac(tsa_session *ss,
                            const struct sockaddr *tst_addr,
                            struct sockaddr *alien_link_addr);

/**
 * Get TCP listenq length from Onload stackdump, this function works only
 * with Onload.
 * 
 * @param rpcs  RPC server handler
 * 
 * @return Listen queue length.
 */
extern int get_tcp_listenq(rcf_rpc_server *rpcs);


/**
 * Move tcp socket to the required state with TSA session.
 *
 * @param ss            TSA session
 * @param state_to      Tested socket state
 * @param opening       Determines passive or active socket should be and
 *                      listener behavior
 * @param cache_socket  Create cached socket on the listener.
 *                      Only for passive open TCP socket.
 */
extern void tcp_move_to_state(tsa_session *ss, rpc_tcp_state state_to,
                              opening_listener opening,
                              te_bool cache_socket);

/** In which direction between two addresses a packet is sent */
typedef enum {
    SOCKTS_ADDRS_FORWARD,   /**< From the first address to the second one */
    SOCKTS_ADDRS_BACKWARD,  /**< From the second address to the first one */
    SOCKTS_ADDRS_NO_MATCH,  /**< Packet addresses do not match the provided
                                 ones */
} sockts_addrs_direction;

/**
 * Check how source and destination address/port of the TCP packet
 * captured by a CSAP match a given pair of addresses/ports
 * (whether it is sent from the first address/port to the second one,
 * or vice versa, or it is from another connection).
 *
 * @param pkt       Captured packet.
 * @param addr1     The first address/port.
 * @param addr2     The second address/port.
 * @param dir       On return tells how packet addresses/ports match the
 *                  given ones (see @ref sockts_addrs_direction).
 *
 * @return Status code.
 */
extern te_errno sockts_tcp_asn_addrs_match(asn_value *pkt,
                                           const struct sockaddr *addr1,
                                           const struct sockaddr *addr2,
                                           sockts_addrs_direction *dir);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
