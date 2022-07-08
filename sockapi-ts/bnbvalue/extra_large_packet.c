/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/**
 * @page bnbvalue-extra_large_packet Try to send/receive extra large packet via TCP/UDP connection
 *
 * @objective Call send()/recv()/sendto()/recvfrom() with very big packet length.
 *
 * @param env       Testing environment:
 *      - @ref arg_types_env_peer2peer
 *      - @ref arg_types_env_peer2peer_ipv6
 * @param conn_type Connection type:
 *      - udp
 *      - udp_notconn
 *      - tcp_active
 *      - tcp_passive
 * @param direction Data flow direction to test:
 *      - to (@b send()/sendto() functions are tested)
 *      - from (@b recv()/recvfrom() functions are tested)
 * @param len       Packet length:
 *      - 0x7FFFFF00
 *      - 0xFFFFFF00
 * @param tst_send  Send or not data from tester before call @b recv() on IUT:
 *      - TRUE
 *      - FALSE
 *
 * @par Scenario:
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#define TE_TEST_NAME "bnbvalue/extra_large_packet"

#include "sockapi-test.h"

/**
 * Data flow direction types.
 */
typedef enum {
    DIR_TO,         /**< Direction IUT -> Tester */
    DIR_FROM        /**< Direction Tester -> IUT */
} direction_t;

/**
 * List of data flow direction types, can be passed to
 * macro @b TEST_GET_ENUM_PARAM.
 */
#define DIRECTION           \
    { "to",     DIR_TO },   \
    { "from",   DIR_FROM }

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    sockts_socket_type     conn_type;
    direction_t            direction;
    te_bool                tst_send;

    int     iut_s = -1;
    int     iut_l = -1;
    int     tst_s = -1;
    te_bool is_readable = FALSE;
    size_t  len;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_UINT_PARAM(len);
    SOCKTS_GET_SOCK_TYPE(conn_type);
    TEST_GET_ENUM_PARAM(direction, DIRECTION);
    TEST_GET_BOOL_PARAM(tst_send);


    /*- Create connection according to @p conn_type. */
    sockts_connection(pco_iut, pco_tst, iut_addr, tst_addr, conn_type,
                      FALSE, FALSE, NULL, &iut_s, &tst_s, &iut_l,
                      SOCKTS_SOCK_FUNC_SOCKET);

    /*- Check data transmission between tester and iut. */
    sockts_test_connection_ext(pco_iut, iut_s, pco_tst, tst_s, tst_addr,
                               conn_type);

    /*- If @p direction = to */
    /*-- For UDP connection */
    /*--- Try to send packet with @p len size via @b send()/sendto() function
     *    according to @p conn_type. */
    /*--- Check return value and errno (should be @c EMSGSIZE). */
    /*--- Check readability of tst socket (it should be unreadable). */
    /*-- For TCP connection */
    /*--- Try to send packet with @p len size via @b send() function in
     *    non-blocking mode. */
    /*--- Check return value. */
    /*--- Check readability of tst socket (it should be readable). */
    if (direction == DIR_TO)
    {
        RPC_AWAIT_ERROR(pco_iut);
        if (sock_type_sockts2rpc(conn_type) == RPC_SOCK_DGRAM)
        {
            rc = rpc_send_var_size(pco_iut,
                                   conn_type == SOCKTS_SOCK_UDP_NOTCONN ?
                                                TARPC_SEND_FUNC_SENDTO :
                                                TARPC_SEND_FUNC_SEND,
                                   iut_s, len, 0, tst_addr);
            if (rc >= 0)
                TEST_VERDICT("rpc_send_var_size() unexpectedly succeed.");
            CHECK_RPC_ERRNO(pco_iut, RPC_EMSGSIZE, "rpc_send_var_size()");
            RPC_GET_READABILITY(is_readable, pco_tst, tst_s, 1000);
            if (is_readable)
                TEST_VERDICT("Tester received data, although it must not.");
        }
        else
        {
            rc = rpc_send_var_size(pco_iut, TARPC_SEND_FUNC_SEND,
                                   iut_s, len, RPC_MSG_DONTWAIT, NULL);
            if (rc < 0)
                TEST_VERDICT("Sending function with TCP socket failed with "
                             "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));

            RPC_GET_READABILITY(is_readable, pco_tst, tst_s, 1000);
            if (!is_readable)
                TEST_VERDICT("Tester did not receive data, although it must.");
        }
    }
    /*- Else (if @p direction = from) */
    /*-- Send some data from tester, if @p tst_send = @c TRUE. */
    /*-- If @p conn_type = udp_notconn */
    /*--- Try to receive packet with @p len size via @b recvfrom(). */
    /*-- Else */
    /*--- Try to receive packet with @p len size via @b recv(). */
    /*-- Check retval and errno. */
    else
    {
        if (tst_send)
        {
            char   *tx_buf = NULL;
            size_t  tx_buflen;
            int     len;
            tx_buf = sockts_make_buf_stream(&tx_buflen);
            len = rand_range(1, tx_buflen);
            RPC_AWAIT_IUT_ERROR(pco_tst);
            if ((rc = rpc_send(pco_tst, tst_s, tx_buf, len, 0)) != len)
            {
                free(tx_buf);
                if (rc == -1)
                    TEST_VERDICT("send() unexpectedly failed with error %s",
                                 errno_rpc2str(RPC_ERRNO(pco_tst)));
                else
                    TEST_VERDICT("send() returned %d instead %u", rc,
                                 tx_buflen);
            }
            free(tx_buf);
            TAPI_WAIT_NETWORK;
        }

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_recv_var_size(pco_iut,
                               conn_type == SOCKTS_SOCK_UDP_NOTCONN ?
                                            TARPC_RECV_FUNC_RECVFROM :
                                            TARPC_RECV_FUNC_RECV,
                               iut_s, len, RPC_MSG_DONTWAIT);

        if (tst_send && rc < 0)
            TEST_VERDICT("rpc_recv_var_size() failed with error - %s",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        if (!tst_send)
        {
            if (rc >= 0)
                TEST_VERDICT("rpc_recv_var_size() unexpectedly succeed.");
            CHECK_RPC_ERRNO(pco_iut, RPC_EAGAIN, "rpc_recv_var_size()");
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_iut, iut_l);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);
    TEST_END;
}
