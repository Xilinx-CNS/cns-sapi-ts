/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#ifndef __OL_HELPERS_H__
#define __OL_HELPERS_H__

/**
 * Connection type.
 */
typedef enum {
    OL_CONNECT_ACTIVE,  /**< Active opening connection. */
    OL_CONNECT_PASSIVE  /**< Passive opening connection. */
} ol_connection_type;

/**
 * Set @c TCP_NODELAY option on a socket.
 * Print error message if setsockopt() call fails.
 *
 * @param s         The socket on which to call setsockopt().
 * @param app_name  Application name (for logging purpose).
 *
 * @return @c 0, or @c -1 in case of error.
 */
int ol_enable_tcp_no_delay_opt(int s, const char *app_name);

/**
 * Connect the socket @p s to a peer specified by @p port and @p host,
 * actively or passively according to @p conn_type.
 *
 * @param s             The socket.
 * @param conn_type     Type of connection (active/passive).
 * @param port          Port number in host byte order to bind/connect in
 *                      passive/active case accordingly.
 * @param host          String containing IP address to connect (ignored in
 *                      case of passive connection opening).
 * @param app_name      Application name (for logging purpose).
 *
 * @return socket descriptor (accepted one in case of passive connection
 *         opening, or @p s in case of active), or @c -1 in case of error.
 */
int ol_connect_socket(int s, ol_connection_type conn_type, int port,
                      const char* host, const char* app_name);

/**
 * Create a connection of a type @p conn_type.
 *
 * @param conn_type     Type of connection (active/passive).
 * @param sock_type     Socket type, corresponding to @b type argument of
 *                      @b socket() system call.
 * @param port          Port number in host byte order to bind/connect in
 *                      passive/active case accordingly.
 * @param host          String containing IP address to connect (ignored in
 *                      case of passive connection opening).
 * @param app_name      Application name (for logging purpose).
 *
 * @return connected socket descriptor or @c -1 in case of error.
 */
int ol_create_and_connect_socket(ol_connection_type conn_type,
                                 int sock_type,
                                 int port,
                                 const char* host,
                                 const char* app_name);

/**
 * Print to stdout a diff of two buffers.
 *
 * @param ex_pkt    Expected buffer.
 * @param rx_pkt    Actual (received) buffer the same size as the expected one.
 * @param size      Length of a buffer.
 */
void ol_hex_diff_dump(const uint8_t *ex_pkt, const uint8_t *rx_pkt,
                      size_t size);

#endif /* __OL_HELPERS_H__ */
