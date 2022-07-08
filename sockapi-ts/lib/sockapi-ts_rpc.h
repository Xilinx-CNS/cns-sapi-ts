/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API - RPC
 *
 * Definition of TAPI for remote calls
 *
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __SOCKAPI_TS_RPC_H__
#define __SOCKAPI_TS_RPC_H__

#include "rcf_rpc.h"
#include "te_rpc_types.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_socket.h"
#include "tapi_rpc_misc.h"
#include "tapi_rpc_mman.h"
#include "iomux.h"

/** Possible actions on created sockets for out_of_resource tests. */
typedef enum out_of_res_acts {
    RPC_OOR_CONNECT = 1, /**< Perform connect() */
    RPC_OOR_LISTEN,      /**< Perform listen() */
    RPC_OOR_RECVFROM,    /**< Perform recvfrom() */
    RPC_OOR_BIND,        /**< Perform bind() only */
} out_of_res_acts;

struct rpc_onload_zc_mmsg {
    struct rpc_msghdr msg; /**< Message */
    int               rc;  /**< Result of send operation */
    int               fd;  /**< socket to send on */

    te_bool keep_recv_bufs;   /**< If @c TRUE, keep Onload buffers for
                                   this message with help of
                                   @c ONLOAD_ZC_KEEP flag */
    rpc_ptr saved_recv_bufs;  /**< If Onload buffers were kept, here
                                   RPC pointer to array of buffers is
                                   returned */

    tarpc_onload_zc_buf_spec *buf_specs;  /**< Array of per-iovec
                                               structures describing
                                               how to allocate ZC
                                               buffers. If @c NULL,
                                               all buffers are allocated
                                               according to @b use_reg_bufs
                                               parameter of
                                               @b rpc_simple_zc_send_gen() */
};

/**
 * Get host value of sizeof(type_name).
 *
 * @param handle      RPC server
 * @param type_name   Name of the type
 *
 * @return          Size of the type or 
 *                  -1 if such a type does not exist.
 */
extern tarpc_ssize_t rpc_sapi_get_sizeof(rcf_rpc_server *rpcs,
                                         const char *type_name);

/**
 * Send traffic. Send UDP datagrams from different sockets
 * toward different addresses.
 *
 * @param handle        RPC server
 * @param num           number of UDP datagrams to being sent
 * @param s             list of sockets (num)
 * @param buf           buffer to being sent
 * @param len           buffer size
 * @param flags         flags passed to sendto()
 * @param to            list of sockaddr-s (num)
 * 
 * @return 0 in case of success, -1 in case of failure
 */ 
extern int rpc_send_traffic(rcf_rpc_server *handle, int num, int *s,
                            const void *buf, size_t len, int flags,
                            struct sockaddr *to);

/**
 * Execute a number of send() operation each after other with no delay.
 *
 *
 * @param handle        RPC server
 * @param sock          socket for sending
 * @param nops          The number of send() operation should be executed
 *                      (the length of len_array)
 * @param vector        array of lenghts for appropriate send() operation
 * @param sent          total bytes are sent on exit
 *
 * @return   -1 in the case of failure or 0 on success
 */
extern int rpc_many_send(rcf_rpc_server *handle, int sock, int flags,
                         const int *vector, int nops, uint64_t *sent);

/**
 * Execute a number of sendto() operation each after other with no delay.
 *
 * @param handle        RPC server
 * @param num           Number of sendto() calles
 * @param s             socket for sending
 * @param len           Lenght of sending packets
 * @param flags         Flags for sendto() function
 * @param to            Destination address
 * @param sent          total bytes are sent on exit
 *
 * @return   -1 in the case of failure or 0 on success
 */
extern int rpc_many_sendto(rcf_rpc_server *rpcs, int num, int s, size_t len,
                           int flags, const struct sockaddr *to,
                           uint64_t *sent);
/**
 * For each address from addresses list routine sends UDP datagram,
 * receives it back and check that it happens within determined
 * period of time. sendmsg() and recvmsg() are used.
 *
 * @param rpcs          RPC server
 * @param sock_num      Number of sockets
 * @param s             DGRAM sockets list to send/receive UDP datagram
 * @param size          Size of UDP datagram
 * @param vector_len    iovec_len in msghdr structure
 * @param timeout       routine waiting for UDP datagram coming back
 *                      within timeout given (passed to select)
 * @param time2wait     UDP datagram must be sent and received within
 *                      time2wait period
 * @param flags         flags passed to sendmsg(recvmsg)
 * @param addr_num      number of addresses
 * @param to            addresses list
 *
 * @return 
 *     0 - success
 *     ROUND_TRIP_ERROR_SEND - sendmsg() failed
 *     ROUND_TRIP_ERROR_RECV - recvmsg() failed
 *     ROUND_TRIP_ERROR_TIMEOUT - select() returned because
 *                                timeout expired
 *     ROUND_TRIP_ERROR_TIME_EXPIRED - time2wait expired
 *     ROUND_TRIP_ERROR_OTHER - some other error occured 
 *                             (memory allocation etc.)
 */ 
extern int rpc_timely_round_trip(rcf_rpc_server *rpcs, int sock_num, int *s,
                                 size_t size, size_t vector_len,
                                 uint32_t timeout, uint32_t time2wait,
                                 int flags, int addr_num, 
                                 struct sockaddr *to);
 
/**
 * For each DGRAM socket in socket list routine determines 
 * if the socket is readable, if it so, routine called recvmsg() 
 * to receive UDP datagram, and sends it back using recvmsg().
 *
 * @param rpcs           RPC server
 * @param sock_num       number of sockets in sockets list
 * @param s              DGRAM sockets list
 * @param addr_num       number of addresses passed to rpc_timely_round_trip
 * @param size           Size of UDP datagram
 * @param vector_len     iovec_len in msghdr structure
 * @param timeout        routine waiting for UDP daragram coming
 *                       withing timeout given (passed to select)
 * @param flags          flags passed to recvmsg(sendmsg)
 *
 * @return
 *     0 - success
 *     ROUND_TRIP_ERROR_SEND - sendmsg() failed
 *     ROUND_TRIP_ERROR_RECV - recvmsg() failed
 *     ROUND_TRIP_ERROR_TIMEOUT - select() returned because
 *                                timeout expired
 *     ROUND_TRIP_ERROR_OTHER - some other error occured
 *                              (memory allocation etc.)
 */ 
extern int rpc_round_trip_echoer(rcf_rpc_server *rpcs, int sock_num, int *s,
                                 int addr_num, size_t size, 
                                 size_t vector_len,
                                 uint32_t timeout, int flags);

/**
 * For given list of accepted sockets close some of them
 * and accept again pending connections.
 *
 * @param rpcs         RPC server
 * @param listening    listening socket
 * @param conns        number of connections
 * @param s            list of accepted sockets
 * @param state        mask to close/open connections
 * 
 * @return 0 on success or -1 in the case of failure
 */ 
extern int rpc_close_and_accept(rcf_rpc_server *rpcs, 
                                int listening, int conns,
                                int *s, uint16_t state);

/**
 * For given socket close it and reopen immediately
 * with the same fd.
 *
 * @param rpcs      RPC server
 * @param fd        socket
 * @param domain    communication domain.
 *                  Select the protocol family used for communication
 *                  supported protocol families are difined in 
 *                  te_rpc_sys_socket.h
 * @param type      defines the semantic of communication. Current defined 
 *                  types can be found in te_rpc_sys_socket.h
 * @param protocol  specifies the protocol to be used. If @b protocol is 
 *                  set to RPC_PROTO_DEF, the system selects the default 
 *                  protocol number for the socket domain and type 
 *                  specified.
 * 
 * @return 0 on success or -1 in the case of failure
 */ 
extern int rpc_close_and_socket(rcf_rpc_server *rpcs, int fd, 
                                rpc_socket_domain domain, 
                                rpc_socket_type type,
                                rpc_socket_proto protocol);


/**
 * Emulate blocking reading using AIO requests.
 *
 * @param rpcs    RPC server handle
 * @param s       socket descriptor
 * @param buf     pointer to buffer which store received messages
 * @param len     buffer length passed to recv()
 * @param rbuflen size of the buffer @b buf
 * @param mode     blocking emulation mode
 *
 * @return  number of bytes read, otherwise -1 on error.
 */
extern ssize_t rpc_aio_read_blk_gen(rcf_rpc_server *rpcs,
                                    int s, void *buf, size_t len,
                                    tarpc_blocking_aio_mode mode, 
                                    size_t rbuflen);

/**
 * Emulate blocking reading using AIO requests.
 *
 * @param rpcs  RPC server handle
 * @param s     socket descriptor
 * @param buf   pointer to buffer which store received messages
 * @param len   size of the buffer @b buf
 * @param mode  blocking emulation mode
 *
 * @return Number of bytes received, otherwise -1 when error occured
 */
static inline ssize_t
rpc_aio_read_blk(rcf_rpc_server *rpcs,
                 int s, void *buf, size_t len, tarpc_blocking_aio_mode mode)
{
    return rpc_aio_read_blk_gen(rpcs, s, buf, len, mode, len);
}

/**
 * Emulate blocking writing using AIO requests.
 *
 * @param rpcs  RPC server handle
 * @param s     socket descriptor
 * @param buf   pointer to buffer which store received messages
 * @param len   size of the buffer @b buf
 * @param mode  blocking emulation mode
 *
 * @return Number of bytes received, otherwise -1 when error occured
 */
extern ssize_t rpc_aio_write_blk(rcf_rpc_server *rpcs,
                                 int s, const void *buf, size_t len, 
                                 tarpc_blocking_aio_mode mode);

/**
 * Function for producing array of callbacks from callback list.
 *
 * @param rpcs  RPC server handle
 * @param arr   pointer to the array of callbacks
 * @param len   number of slots in array (IN) or 
 *              number of elements in array (OUT)
 */ 
extern void rpc_get_callback_list(rcf_rpc_server *rpcs, tarpc_callback_item *arr,
                                  uint32_t *len);

/**
 * Auxiliary function for aio/nested_requests test.
 *
 * @param rpcs     RPC server handle
 * @param s        connected socket
 * @param req_num  number of write AIO requests
 *
 * @return 0 (success) or -1 (failure)
 */ 
extern int rpc_nested_requests_test(rcf_rpc_server *rpcs, 
                                    int s, int req_num);

/**
 * Performs continuous writing to the file.
 *
 * @param rpcs          RPC server handle
 * @param fd            file descriptor
 * @param buf           pointer to buffer with data to write
 * @param buflen        size of data to write
 * @param offset        offset in the file
 * @param time          duration of writing
 *
 * @return size of data written
 */
extern void rpc_write_at_offset_continuous(rcf_rpc_server *rpcs, int fd,
                                           char* buf, size_t buflen,
                                           off_t offset, uint64_t time);

#if 0
extern int rpc_onload_hw_filters_limit(rcf_rpc_server *rpcs,
                                       const struct sockaddr *addr);
#endif

/** 
 * Create, bind and connect @p sock_num sockets.
 *
 * @param rpcs                  RPC server handle
 * @param do_bind               bind socket before connect
 * @param bind_addr             address to bind
 * @param connect_addr          address to connect
 * @param sock_type             socket type
 * @param action                action to perform on the opened sockets
 * @param sock_num              number of sockets to create
 * @param acc_num               accelerated sockets number
 * @param err_num               fails number
 * @param sock1                 location for descriptor of the first
 *                              created socket
 * @param sock2                 location for the last created socket
 *
 * @note It is assumed that RPC server is started so that it uses
 *       L5 functions by default.
 * 
 * @return Opened sockets number
 */
extern int rpc_out_of_hw_filters_do(rcf_rpc_server *rpcs, te_bool do_bind,
                                    const struct sockaddr *bind_addr,
                                    const struct sockaddr *connect_addr,
                                    int sock_type, out_of_res_acts action,
                                    int sock_num, int *acc_num,
                                    int *err_num, int *sock1, int *sock2);

/**
 * See description of function @b rpc_many_accept. The only difference is
 * that this function provides opportunity to get last iteration number in
 * case of failure.
 */
extern int rpc_many_accept_gen(rcf_rpc_server *rpcs, int s, int sock_num,
                               int data_len, int send_count,
                               int *sock1, int *sock2, rpc_ptr *handler,
                               int *iteration);

/** 
 * Accept huge number of connections. Always use function @b rpc_many_close
 * (even if call failed) to close sockets and free memory.
 *
 * @param rpcs       RPC server handle
 *
 * @param s          listening socket
 * @param sock_num   number of connections to accept
 * @param data_len   bytes to send
 * @param send_count number of times to call send
 * @param sock1      location for descriptor of the first accepted socket
 * @param sock2      location for the last accepted socket
 * @param handle     pointer to the sockets array, that must by passed to
 *                   @ref rpc_many_close function
 * 
 * @return Opened sockets number
 */
static inline int
rpc_many_accept(rcf_rpc_server *rpcs, int s, int sock_num,
                int data_len, int send_count, int *sock1, int *sock2,
                rpc_ptr *handler)
{
    return rpc_many_accept_gen(rpcs, s, sock_num, data_len, send_count,
                               sock1, sock2, handler, NULL);
}


/** 
 * Create a lot of TCP sockets and connect them. Always use function
 * @b rpc_many_close (even if call failed) to close sockets and free memory.
 *
 * @param rpcs       RPC server handle
 * @param addr       address to connect
 * @param sock_num   number of connections
 * @param data_len   bytes to send
 * @param send_count number of times to call send
 * @param sock1      location for descriptor of the first socket
 * @param sock2      location for the last socket
 * @param handle     pointer to the sockets array, that must by passed to
 *                   @ref rpc_many_close function
 * 
 * @return Opened sockets number
 */
extern int rpc_many_connect(rcf_rpc_server *rpcs,
                            const struct sockaddr *addr, int sock_num,
                            int data_len, int send_count,
                            int *sock1, int *sock2, rpc_ptr *handler);

/** 
 * Create a lot of TCP sockets. Always use function @b rpc_many_close (even
 * if call failed) to close sockets and free memory.
 *
 * @param rpcs   RPC server handle
 * @param domain Communication domain
 * @param num    Sockets number
 * @param handle Pointer to the sockets array, that must by passed to
 *               @ref rpc_many_close function
 * 
 * @return Opened sockets number
 */
extern int rpc_many_socket(rcf_rpc_server *rpcs, rpc_socket_domain domain,
                           int num, rpc_ptr *handler);

/**
 * Close opened with @b rpc_many_accept, @b rpc_many_connect or
 * @b rpc_many_socket sockets and free memory.
 * 
 * @param rpcs    RPC server
 * @param handle  The sockets array handler
 * @param num     Sockets number
 * 
 * @return Status code
 */
extern int rpc_many_close(rcf_rpc_server *rpcs, rpc_ptr handler, int num);

/**
 * Perform add-then-delete @b epoll_ctl() operations for sockets,
 * opened by @ref rpc_many_accept(), @ref rpc_many_connect() or
 * @ref rpc_many_socket(), and check whether an event is reported
 * by @b epoll_wait() (if the corresponding flag is set).
 *
 * @param rpcs              RPC server
 * @param socks_arr         Sockets array handle, obtained from the
 *                          rpc_many_* call
 * @param socks_num         Number of sockets
 * @param epfd              Epoll instance
 * @param events            Bit mask of the event types (@ref rpc_epoll_evt)
 * @param check_epoll_wait  Call @b epoll_wait() after each @b epoll_ctl()
 *                          and check that an event is reported after adding
 *                          a socket to epoll set, otherwise there are no
 *                          events
 * @param time2run          How long to run, in milliseconds.
 *
 * @return Status code.
 */
extern int rpc_many_epoll_ctl_add_del(rcf_rpc_server *rpcs, rpc_ptr socks_arr,
                                      int socks_num, int epfd, uint32_t events,
                                      te_bool check_epoll_wait, int time2run);

/**
 * Close opened with @b rpc_many_accept, @b rpc_many_connect or
 * @b rpc_many_socket sockets and free memory, calculate cached sockets
 * number.
 * 
 * @param rpcs    RPC server
 * @param handle  The sockets array handler
 * @param num     Sockets number
 * @param cached  OUT argument with sockets number which were cached
 * 
 * @return Status code
 */
extern int rpc_many_close_cache(rcf_rpc_server *rpcs, rpc_ptr handle,
                                int num, int *cached);

/**
 * Get a socket from an array returned by rpc_many_accept() or
 * rpc_many_connect().
 *
 * @param rpcs      RPC server handle.
 * @param handle    Handle of a sockets array.
 * @param idx       Index in the array.
 * @param s         Where to save socket FD.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_get_socket_from_array(rcf_rpc_server *rpcs, rpc_ptr handle,
                                     unsigned int idx, int *s);

/**
 * Receive packets with function @b recv() until @p num packets are received
 * or packet, which is equal to @p last_packet, is received.
 * 
 * @param rpcs            RPC server
 * @param sock            Socket
 * @param length          Packets length
 * @param num             Packets number or @c -1 for unlimited number
 * @param duration        How long receive packets or @c -1
 * @param last_packet     Last packet or @c NULL
 * @param last_packet_len Last packet length
 * @param count_fails     Don't stop on fail
 * @param fails           Fails number (OUT) or @c NULL
 * 
 * @return Received packets number or @c -1 in case of failure
 */
extern int rpc_many_recv(rcf_rpc_server *rpcs, int sock, size_t length, 
                         int num, int duration, void *last_packet,
                         size_t last_packet_len, te_bool count_fails,
                         int *fails_num);


/**
 * Send @p num packets with arbitrary send function.
 * 
 * @param rpcs            RPC server
 * @param sock            Socket
 * @param length_min      Minimum packets length
 * @param length_max      Maximum packets length
 * @param num             Packets number or @c -1 for unlimited number
 * @param duration        How long send packets or @c -1
 * @param func_name       Function name to send data
 * @param check_len       Check data length of each sent packet
 * @param count_fails     Don't stop on fail
 * @param fails           Fails number (OUT) or @c NULL
 * 
 * @return Sent packets number or @c -1 in case of failure
 */
extern int rpc_many_send_num_func(rcf_rpc_server *rpcs, int sock,
                                  size_t length_min, size_t length_max,
                                  int num, int duration,
                                  const char *func_name, te_bool check_len,
                                  te_bool count_fails, int *fails_num);

/**
 * Send @p num packets with function @b send().
 * 
 * @param rpcs            RPC server
 * @param sock            Socket
 * @param length          Packets length
 * @param num             Packets number or @c -1 for unlimited number
 * @param duration        How long send packets or @c -1
 * @param check_len       Check data length of each sent packet
 * @param count_fails     Don't stop on fail
 * @param fails           Fails number (OUT) or @c NULL
 * 
 * @return Sent packets number or @c -1 in case of failure
 */
static inline int
rpc_many_send_num(rcf_rpc_server *rpcs, int sock, size_t length, int num,
                  int duration, te_bool check_len, te_bool count_fails,
                  int *fails_num)
{
    return rpc_many_send_num_func(rpcs, sock, length, length, num, duration,
                                  "send", check_len, count_fails, fails_num);
}

/** 
 * Function preparing conditions for out_of_netifs test. 
 * It creates child of the RPC server and initiates process creation or 
 * exec() inside it. 
 *
 * @param rpcs        RPC server handle
 * @param sock_num    number of sockets to create
 * @param sock_type   type of sockets to create
 * @param num         Successfully performed iterations number (out)
 * @param acc         Accelerated sockets number (out)
 *
 * @return return code, 0 or -1
 *
 * @note It is assumed that RPC server is started so that it uses
 *       L5 functions by default.
 */
extern int rpc_out_of_netifs(rcf_rpc_server *rpcs, int sock_num,
                             rpc_socket_type sock_type, int *num, int *acc);

/** 
 * Start traffic processor.
 *
 * @param rpcs        RPC server handle
 * @param sock        socket for traffic transferring
 * @param snd         if TRUE, send traffic; otherwise receive traffic
 * @param bytes       location for transferred bytes pointer
 * @param stop        location for stop flag
 *
 * @note Memory for bytes and stop flag is allocated by the function
 *       and should be freed by rpc_free().
 */
extern void rpc_traffic_processor(rcf_rpc_server *rpcs, 
                                  int sock, te_bool snd,
                                  rpc_ptr *bytes, rpc_ptr *stop);

/** 
 * Get number of transferred bytes.
 *
 * @param rpcs          RPC server handle (server should belong to
 *                      same process which traffic processor belongs to)
 * @param bytes         bytes pointer returned by rpc_traffic_processor()
 *
 * @return Number of transferred bytes.
 */
static inline uint64_t
rpc_traffic_processor_get_bytes(rcf_rpc_server *rpcs, rpc_ptr bytes)
{
    uint32_t buf[2];
    
    rpc_get_buf(rpcs, bytes, 8, (uint8_t *)buf);
    
    return (uint64_t)(ntohl(buf[0])) + (uint64_t)ntohl(buf[1]);
}

/** 
 * Stop traffic processor.
 *
 * @param rpcs          RPC server handle (server should belong to
 *                      same process which traffic processor belongs to)
 * @param bytes         bytes pointer returned by rpc_traffic_processor()
 *                      or RPC_NULL
 * @param stop          stop pointer returned by rpc_traffic_processor()
 *
 * @note Memory allocated for bytes and stop is released.
 */
static inline void
rpc_traffic_processor_stop(rcf_rpc_server *rpcs, 
                           rpc_ptr bytes, rpc_ptr stop)
{
    uint8_t true_byte = TRUE;
    te_bool await_error = RPC_AWAITING_ERROR(rpcs);
    
    rpc_set_buf(rpcs, &true_byte, 1, stop);
    if (bytes != RPC_NULL)
    {
        if (await_error)
            RPC_AWAIT_IUT_ERROR(rpcs);
        rpc_free(rpcs, bytes);
    }
    if (await_error)
        RPC_AWAIT_IUT_ERROR(rpcs);
    rpc_free(rpcs, stop);
}

/**
 * Perform close() system call via interrupt 0x80.
 *
 * @param rpcs          RPC server handle
 * @param fd            Stream descriptor
 *
 * @return              0 if success,
 *                      -1 if any error occured.
 */
extern int rpc_close_interrupt(rcf_rpc_server *rpcs, int fd);

/**
 * Perform close() system call using syscall CPU command.
 *
 * @param rpcs          RPC server handle
 * @param fd            Stream descriptor
 *
 * @return              0 if success,
 *                      -1 if any error occured.
 */
extern int rpc_close_syscall(rcf_rpc_server *rpcs, int fd);

/**
 * Perform close() system call using sysenter CPU command.
 *
 * @param rpcs          RPC server handle
 * @param fd            Stream descriptor
 *
 * @return              0 if success,
 *                      -1 if any error occured.
 */
extern int rpc_close_sysenter(rcf_rpc_server *rpcs, int fd);

/**
 * Perform close() system call using specified method.
 *
 * @param rpcs          RPC server handle
 * @param fd            Stream descriptor
 * @param method        Method: libc, interrupt, syscall, sysenter
 *
 * @return              0 if success,
 *                      -1 if any error occured.
 */
static inline int
rpc_close_alt(rcf_rpc_server *rpcs, int fd, const char *method)
{
    if (strcmp(method, "libc") == 0)
    {
        return rpc_close(rpcs, fd);
    }
    else if (strcmp(method, "interrupt") == 0)
    {
        return rpc_close_interrupt(rpcs, fd);
    }
    else if (strcmp(method, "syscall") == 0)
    {
        return rpc_close_syscall(rpcs, fd);
    }
    else if (strcmp(method, "sysenter") == 0)
    {
        return rpc_close_sysenter(rpcs, fd);
    }
    ERROR("Incorrect method for system call specified");
    return -1;
}

/**
 * Incorrect CRC sendig test.
 *
 * @param rpcs      RPC server handle
 * @param ifname    ethernet interface symbolic name
 * @param dest_addr destination host hadware address
 * @param dest_sa   destination socket address
 *
 * @note Send ethernet frames with incorrect CRC.
 */
extern int rpc_incorrect_crc_send_test(rcf_rpc_server        *rpcs, 
                                       const char            *ifname, 
                                       const uint8_t         *dest_addr,
                                       const struct sockaddr *dest_sa);

/**
 * Non-block receiver start.
 * Starts permanent Non-Block receiver on socket supposed to be empty
 * (no data is transferred), and check that each recv() returns -1 with
 * errno set to EAGAIN.  
 *
 * @param rpcs              RPC server
 * @param s                 a socket to be user for receiving
 * @param handle            Pointer to receiver control field
 *                          (required to stop the NB-receiver)
 *
 * @return 0 on success or -1 in the case of failure
 */
extern int rpc_nb_receiver_start(rcf_rpc_server *rpcs,
                                 int s, rpc_ptr handle);

/**
 * Non-block receiver stop.
 *
 * @param rpcs              RPC server
 * @param s                 a socket to be user for receiving
 * @param handle            Pointer to receiver control field
 *                          (required to stop the NB-receiver)
 *
 * @return 0 on success or -1 in the case of failure
 */
extern int rpc_nb_receiver_stop(rcf_rpc_server *rpcs,
                                rpc_ptr handle);


/**
 * Call onload_set_stackname.
 *
 * Parameters - private onload.
 */
extern int rpc_onload_set_stackname(rcf_rpc_server *rpcs,
                                    int who,
                                    int scope,
                                    const char *name);

/**
 * Call onload_stackname_save.
 *
 * @return 0 on success, <0 on failure
 */
extern int rpc_onload_stackname_save(rcf_rpc_server *rpcs);

/**
 * Call onload_stackname_restore.
 *
 * @return 0 on success, <0 on failure
 */
extern int rpc_onload_stackname_restore(rcf_rpc_server *rpcs);

/**
 * Call onload_move_fd.
 * Function tries to move a given fd to the current Onload stack.
 *
 * Parameters - private onload.
 */
extern int rpc_onload_move_fd(rcf_rpc_server *rpcs, int fd);
/**
 * Call onload_is_present.
 * Function reports if current library used is a dummy or
 * an actual onload library.
 *
 * Parameters - private onload.
 */
extern int rpc_onload_is_present(rcf_rpc_server *rpcs);

/**
 * Call onload_fd_stat.
 * Function reports some OOL internal info about given fd.
 */
extern int rpc_onload_fd_stat(rcf_rpc_server *rpcs, int fd,
                              tarpc_onload_stat *buf);


/** Remove file-flag before using sighandler_createfile. */
extern void
rpc_sighandler_createfile_cleanup(rcf_rpc_server *rpcs, int sig);

/** Check existence and remove file created by sighandler_createfile.
 *
 * @return TRUE if the file was here
 */
extern te_bool
rpc_sighandler_createfile_exists_unlink(rcf_rpc_server *rpcs, int sig);

/** Check existence and remove file created by sighandler_createfile
 * from another RPC server.
 *
 * @return TRUE if the file was here
 */
extern te_bool
rpc_thrd_sighnd_crtfile_exists_unlink(rcf_rpc_server *rpcs, int sig,
                                      tarpc_pid_t pid,
                                      tarpc_pthread_t tid);

/**
 * Allocate Onload Zero Copy API buffers.
 *
 * @param rpcs          RPC server
 * @param fd            Socket descriptor
 * @param iovecs        ID of memory allocated with help of
 *                      @b rpc_malloc().
 * @param iovecs_len    Number of elements of type struct onload_zc_iovec
 *                      placed in allocated memory
 * @param flags         Flags
 */
extern int rpc_onload_zc_alloc_buffers(rcf_rpc_server *rpcs,
                                       int fd,
                                       rpc_ptr iovecs,
                                       int iovecs_len,
                                       tarpc_onload_zc_buffer_type_flags
                                                                    flags);
/**
 * Free Onload Zero Copy API buffers.
 *
 * @param rpcs          RPC server
 * @param fd            Socket descriptor
 * @param iovecs        ID of memory allocated with help of
 *                      @b rpc_malloc().
 * @param iovecs_len    Number of elements of type struct onload_zc_iovec
 *                      placed in allocated memory
 */
extern int rpc_free_onload_zc_buffers(rcf_rpc_server *rpcs,
                                      int fd,
                                      rpc_ptr iovecs,
                                      int iovecs_len);

/** RPC definition of opaque pointer to ZC buffer metadata */
typedef rpc_ptr rpc_onload_zc_handle;

/**
 * This should be used as default value for addr_space argument
 * of rpc_onload_zc_register_buffers(), telling it to use the
 * process's local address space. It is equal to EF_ADDRSPACE_LOCAL
 * defined in ef_vi.h.
 */
#define SOCKTS_EF_ADDRSPACE_LOCAL ((uint64_t)-1)

/**
 * Call onload_zc_register_buffers().
 *
 * @param rpcs          RPC server handle.
 * @param fd            Socket FD.
 * @param addr_space    Address space (use @c SOCKTS_EF_ADDRSPACE_LOCAL
 *                      to send from the process's local address space).
 * @param base_ptr      RPC pointer for buffer to be registered.
 * @param off           Offset to add to @p base_ptr (nonzero makes sense
 *                      only for checking buffer pointer which is not
 *                      page-aligned).
 * @param len           Buffer length.
 * @param flags         Currently not used, must be @c 0.
 * @param handle        Where to save @b onload_zc_handle pointer.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_onload_zc_register_buffers(rcf_rpc_server *rpcs,
                                          int fd, uint64_t addr_space,
                                          rpc_ptr base_ptr, uint64_t off,
                                          uint64_t len, int flags,
                                          rpc_onload_zc_handle *handle);

/**
 * Call onload_zc_unregister_buffers().
 *
 * @param rpcs          RPC server handle.
 * @param fd            Socket FD.
 * @param handle        RPC pointer for @b onload_zc_handle.
 * @param flags         Currently not used, must be @c 0.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_onload_zc_unregister_buffers(rcf_rpc_server *rpcs,
                                            int fd,
                                            rpc_onload_zc_handle handle,
                                            int flags);

/**
 * Transmit 2 messages to socket descriptor @b s on RPC server side by 
 * using 2 send calls. The first send call transmit first @b first_len
 * bytes of @b buf with @c MSG_MORE flag, the second send call transmit
 * next @b second_len bytes of @b buf with zero flag. This operation 
 * takes place on RPC server side and buffer is stored on the same side.
 * @b onload_zc_send() is used to send data.
 *
 * @param rpcs          RPC server handle
 * @param s             Socket descriptor
 * @param buf           RPC pointer to buffer containing the message to
 *                      be sent
 * @param first_len     Length of the first message in bytes
 * @param second_len    Length of the second message in bytes
 * @param first_zc      If @c TRUE, use @b onload_zc_send() for the first
 *                      packet; otherwise use @b send().
 * @param second_zc     If @c TRUE, use @b onload_zc_send() for the second
 *                      packet; otherwise use @b send().
 * @param use_reg_bufs  If @c TRUE, use buffer registered with
 *                      @b onload_zc_register_buffers(); otherwise
 *                      use buffers allocated with
 *                      @b onload_zc_alloc_buffers()
 * @param set_nodelay   If @c TRUE, enable @c TCP_NODELAY socket option
 *                      between the send calls.
 *
 * @return On succes, number of bytes actually sent, otherwise -1.
 */
extern ssize_t rpc_onload_zc_send_msg_more(rcf_rpc_server *rpcs, int s,
                                           rpc_ptr buf, size_t first_len,
                                           size_t second_len,
                                           te_bool first_zc,
                                           te_bool second_zc,
                                           te_bool use_reg_bufs,
                                           te_bool set_nodelay);

/**
 * Allocate a queue to keep track of ZC buffers for which completion
 * messages should be received.
 *
 * @param rpcs          RPC server handle.
 *
 * @return RPC pointer to the head of allocated queue.
 */
extern rpc_ptr rpc_sockts_alloc_zc_compl_queue(rcf_rpc_server *rpcs);

/**
 * Release memory occupied by a queue allocated with
 * rpc_sockts_alloc_zc_compl_queue().
 *
 * @param rpcs          RPC server handle.
 * @param qhead         RPC pointer to the head of the queue.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_free_zc_compl_queue(rcf_rpc_server *rpcs,
                                          rpc_ptr qhead);

/**
 * Receive and process completion messages for sent ZC buffers
 * registered in a completion queue. For each received
 * completion message, matching element is removed from a
 * queue and memory is released.
 *
 * @param rpcs          RPC server handle.
 * @param qhead         RPC pointer to the head of the queue.
 * @param timeout       Polling timeout when waiting for completion
 *                      messages (in milliseconds; negative value
 *                      means infinite timeout).
 *
 * @return @c 1 if some buffers are still not completed,
 *         @c 0 if all buffers were completed,
 *         @c -1 on failure.
 */
extern int rpc_sockts_proc_zc_compl_queue(rcf_rpc_server *rpcs,
                                          rpc_ptr qhead, int timeout);

/**
 * Call @b onload_zc_send() on TA.
 *
 * @param rpcs            RPC server handle.
 * @param mmsgs           Messages to send.
 * @param mlen            Number of messages to send.
 * @param flags           Flags to pass to @b onload_zc_send().
 * @param add_sock        If not negative, this FD will be used for
 *                        allocating/registering buffers instead of FD
 *                        which is used for sending data.
 * @param use_reg_bufs    If @c TRUE, use @b onload_zc_register_buffers(),
 *                        otherwise @b onload_zc_alloc buffers().
 * @param compl_queue     External queue for sent ZC buffers for which
 *                        completion messages have not been received yet.
 *                        If not @c RPC_NULL, this function will add sent
 *                        buffers to this queue and terminate immediately
 *                        instead of waiting for completion messages. Use
 *                        rpc_sockts_proc_zc_compl_queue() to process
 *                        completion messages after that.
 *                        With external queue you should also allocate
 *                        and register user buffers yourself, since they
 *                        should not be unregistered and released before
 *                        all the sent buffers are completed. See
 *                        @b buf_specs field of @ref rpc_onload_zc_mmsg
 *                        and @b rpc_onload_zc_register_buffers().
 * @param send_duration   Where to save time taken by the send call
 *                        itself (in mircoseconds), not taking into account
 *                        time spent waiting for completion events for
 *                        instance. Will be set to a negative number if
 *                        gettimeofday() fails.
 *
 * @return Number of sent messages on success, negative value on failure.
 */
extern int rpc_simple_zc_send_gen(rcf_rpc_server *rpcs,
                                  struct rpc_onload_zc_mmsg *msgs, int mlen,
                                  rpc_send_recv_flags flags, int add_sock,
                                  te_bool use_reg_bufs, rpc_ptr compl_queue,
                                  int64_t *send_duration);

/**
 * A version of rpc_simple_zc_send_gen() accepting single rpc_msghdr
 * instead of array of rpc_onload_zc_mmsg structures.
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket FD.
 * @param msg           Message to send.
 * @param flags         Flags to pass to @b onload_zc_send().
 * @param add_sock      If not negative, this FD will be used for
 *                      allocating/registering buffers instead of FD
 *                      which is used for sending data.
 * @param use_reg_bufs  If @c TRUE, use @b onload_zc_register_buffers(),
 *                      otherwise @b onload_zc_alloc buffers().
 *
 * @return Number of sent bytes on success, negative value on failure.
 */
static inline int
rpc_simple_zc_send_gen_msg(rcf_rpc_server *rpcs,
                           int s, struct rpc_msghdr *msg,
                           rpc_send_recv_flags flags, int add_sock,
                           te_bool use_reg_bufs)
{
    struct rpc_onload_zc_mmsg   msgs;
    struct rpc_msghdr          *tmp_msg = &msgs.msg;

    memset(&msgs, 0, sizeof(msgs));
    memcpy(tmp_msg, msg, sizeof(*msg));
    msgs.fd = s;

    if (rpc_simple_zc_send_gen(rpcs, &msgs, 1, flags, add_sock,
                               use_reg_bufs, RPC_NULL, NULL) < 0)
    {
        return -1;
    }

    memcpy(msg, tmp_msg, sizeof(*msg));

    if (msgs.rc < 0)
    {
        rpcs->_errno = -msgs.rc;
        return -1;
    }
    return msgs.rc;
}

/**
 * Send a single message with @b onload_zc_send() (using buffers
 * allocated with @b onload_zc_alloc_buffers()).
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket FD.
 * @param msg           Message to send.
 * @param flags         Flags to pass to @b onload_zc_send().
 *
 * @return Number of sent bytes on success, negative value on failure.
 */
static inline int
rpc_simple_zc_send(rcf_rpc_server *rpcs, int s,
                   struct rpc_msghdr *msg,
                   rpc_send_recv_flags flags)
{
    return rpc_simple_zc_send_gen_msg(rpcs, s, msg, flags, -1, FALSE);
}

/**
 * Send a single message with @b onload_zc_send() (using buffer
 * registered with @b onload_zc_register_buffers()).
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket FD.
 * @param msg           Message to send.
 * @param flags         Flags to pass to @b onload_zc_send().
 *
 * @return Number of sent bytes on success, negative value on failure.
 */
static inline int
rpc_simple_zc_send_user_buf(rcf_rpc_server *rpcs, int s,
                            struct rpc_msghdr *msg,
                            rpc_send_recv_flags flags)
{
    return rpc_simple_zc_send_gen_msg(rpcs, s, msg, flags, -1, TRUE);
}

/**
 * Same as @b rpc_simple_zc_send(), but allows to use different FD
 * for buffers allocation or registering.
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket FD.
 * @param msg           Message to send.
 * @param flags         Flags to pass to @b onload_zc_send().
 * @param add_sock      If not negative, this FD will be used for
 *                      allocating/registering buffers instead of FD
 *                      which is used for sending data.
 *
 * @return Number of sent bytes on success, negative value on failure.
 */
static inline int
rpc_simple_zc_send_sock(rcf_rpc_server *rpcs, int s,
                        struct rpc_msghdr *msg,
                        rpc_send_recv_flags flags, int add_sock)
{
    return rpc_simple_zc_send_gen_msg(rpcs, s, msg, flags, add_sock, FALSE);
}

/**
 * Same as @b rpc_simple_zc_send_sock(), but uses
 * @b onload_zc_register_buffers() instead of
 * @b onload_zc_alloc_buffers().
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket FD.
 * @param msg           Message to send.
 * @param flags         Flags to pass to @b onload_zc_send().
 * @param add_sock      If not negative, this FD will be used for
 *                      allocating/registering buffers instead of FD
 *                      which is used for sending data.
 *
 * @return Number of sent bytes on success, negative value on failure.
 */
static inline int
rpc_simple_zc_send_sock_user_buf(rcf_rpc_server *rpcs, int s,
                                 struct rpc_msghdr *msg,
                                 rpc_send_recv_flags flags, int add_sock)
{
    return rpc_simple_zc_send_gen_msg(rpcs, s, msg, flags, add_sock, TRUE);
}

/**
 * Call @b onload_zc_recv(fd, NULL).
 *
 * @param rpcs  RPC server
 * @param s     Socket descriptor
 *
 * @return Status code
 */
extern int rpc_simple_zc_recv_null(rcf_rpc_server *rpcs, int s);

/**
 * Call onload_zc_recv() on TA.
 *
 * @param rpcs              RPC server handle.
 * @param s                 Socket FD.
 * @param mmsg              Array of messages (to be filled with data
 *                          passed to onload_zc_recv() callback).
 * @param vlen              Number of messages in array.
 * @param args_msg          If not @c NULL, args.msg.msghdr passed to
 *                          onload_zc_recv() will be initialized from this
 *                          parameter, and on return it will contain value
 *                          updated by onload_zc_recv(). If @c NULL,
 *                          args.msg.msghdr will be initialized from the first
 *                          message.
 * @param flags             Flags to pass to onload_zc_recv().
 * @param cb_flags          Array of flags passed for each message to
 *                          receive callback (to be filled on return). May be
 *                          @c NULL.
 * @param os_inline         If @c TRUE, @c ONLOAD_MSG_RECV_OS_INLINE flag
 *                          should be passed to onload_zc_recv().
 *
 * @return Number of received messages on success, negative value on
 *         failure.
 */
extern int
rpc_simple_zc_recv_gen(rcf_rpc_server *rpcs, int s,
                       struct rpc_onload_zc_mmsg *mmsg,
                       unsigned int vlen, struct rpc_msghdr *args_msg,
                       rpc_send_recv_flags flags,
                       int *cb_flags, te_bool os_inline);

/**
 * Wrapper for rpc_simple_zc_recv_gen() taking array of rpc_mmsghdr
 * instead of array of rpc_onload_zc_mmsg.
 */
static inline int
rpc_simple_zc_recv_gen_mmsg(rcf_rpc_server *rpcs, int s,
                            struct rpc_mmsghdr *mmsg,
                            unsigned int vlen,
                            struct rpc_msghdr *args_msg,
                            rpc_send_recv_flags flags,
                            int *cb_flags, te_bool os_inline)
{
    struct rpc_onload_zc_mmsg ommsg[RCF_RPC_MAX_MSGHDR];
    unsigned int i;
    int rc;

    if (vlen > RCF_RPC_MAX_MSGHDR)
    {
        ERROR("%s(): up to %u messages are supported", __FUNCTION__,
              RCF_RPC_MAX_MSGHDR);
        rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
        return -1;
    }

    memset(ommsg, 0, sizeof(ommsg));
    for (i = 0; i < vlen; i++)
    {
        memcpy(&ommsg[i].msg, &mmsg[i].msg_hdr, sizeof(rpc_msghdr));
    }

    rc = rpc_simple_zc_recv_gen(rpcs, s, ommsg, vlen, args_msg, flags,
                                cb_flags, os_inline);
    if (rc < 0)
        return -1;

    for (i = 0; i < vlen; i++)
    {
        memcpy(&mmsg[i].msg_hdr, &ommsg[i].msg, sizeof(rpc_msghdr));
        mmsg[i].msg_len = ommsg[i].rc;
    }

    return rc;
}

/**
 * Wrapper for rpc_simple_zc_recv_gen() taking pointer to single rpc_msghdr
 * instead of array of rpc_onload_zc_mmsg.
 */
static inline int
rpc_simple_zc_recv_gen_msg(rcf_rpc_server *rpcs, int s,
                           struct rpc_msghdr *msg,
                           struct rpc_msghdr *args_msg,
                           rpc_send_recv_flags flags,
                           int *cb_flags, te_bool os_inline)
{
    struct rpc_onload_zc_mmsg mmsg;

    memset(&mmsg, 0, sizeof(mmsg));
    memcpy(&mmsg.msg, msg, sizeof(*msg));
    if (rpc_simple_zc_recv_gen(rpcs, s, &mmsg, 1, args_msg, flags, cb_flags,
                               os_inline) < 0)
        return -1;
    memcpy(msg, &mmsg.msg, sizeof(*msg));

    return mmsg.rc;
}

/**
 * Wrapper for rpc_simple_zc_recv_gen() taking pointer to single rpc_msghdr
 * instead of array of rpc_onload_zc_mmsg and omitting some other
 * arguments. Passes @c ONLOAD_MSG_RECV_OS_INLINE flag to
 * @b onload_zc_recv().
 */
static inline int
rpc_simple_zc_recv(rcf_rpc_server *rpcs, int s, struct rpc_msghdr *msg,
                   rpc_send_recv_flags flags)
{
    return rpc_simple_zc_recv_gen_msg(rpcs, s, msg, NULL, flags, NULL,
                                      TRUE);
}

/**
 * Wrapper for rpc_simple_zc_recv_gen() taking pointer to single rpc_msghdr
 * instead of array of rpc_onload_zc_mmsg and omitting some other
 * arguments. It does not pass @c ONLOAD_MSG_RECV_OS_INLINE flag to
 * @b onload_zc_recv().
 */
static inline int
rpc_simple_zc_recv_acc(rcf_rpc_server *rpcs, int s, struct rpc_msghdr *msg,
                       rpc_send_recv_flags flags)
{
    return rpc_simple_zc_recv_gen_msg(rpcs, s, msg, NULL, flags, NULL,
                                      FALSE);
}

/**
 * Receive data with onload_zc_hlrx_recv_zc().
 *
 * @note This function does not pass to onload_zc_hlrx_recv_zc()
 *       exactly the IOVs requested here, but it fills them with
 *       the data that function returned.
 *
 * @param rpcs              RPC server handle.
 * @param s                 Socket FD.
 * @param msg               Where to save received message.
 * @param flags             Flags to pass to onload_zc_hlrx_recv_zc().
 * @param os_inline         If @c TRUE, pass @c ONLOAD_MSG_RECV_OS_INLINE
 *                          flag to the function.
 *
 * @return Number of received bytes on success, @c -1 on failure.
 */
extern ssize_t rpc_simple_hlrx_recv_zc(rcf_rpc_server *rpcs,
                                       int s, struct rpc_msghdr *msg,
                                       rpc_send_recv_flags flags,
                                       te_bool os_inline);

/**
 * Receive data with onload_zc_hlrx_recv_copy().
 *
 * @param rpcs              RPC server handle.
 * @param s                 Socket FD.
 * @param msg               Where to save received message.
 * @param flags             Flags to pass to onload_zc_hlrx_recv_copy().
 * @param os_inline         If @c TRUE, pass @c ONLOAD_MSG_RECV_OS_INLINE
 *                          flag to the function.
 *
 * @return Number of received bytes on success, @c -1 on failure.
 */
extern ssize_t rpc_simple_hlrx_recv_copy(rcf_rpc_server *rpcs,
                                         int s, struct rpc_msghdr *msg,
                                         rpc_send_recv_flags flags,
                                         te_bool os_inline);

/**
 * Configure capturing packets via UDP-RX filter. Captured packets
 * can be retrieved with @b rpc_sockts_recv_filtered_pkt().
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket descriptor.
 * @param flags         Flags to pass to @b onload_set_recv_filter().
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_onload_set_recv_filter_capture(rcf_rpc_server *rpcs, int s,
                                              int flags);

/**
 * Receive a packet captured by UDP-RX filter on a given socket.
 * Packets are retrieved in the same order in which they were passed
 * to UDP-RX filter callback.
 *
 * @param rpcs          RPC server handle.
 * @param s             Socket descriptor.
 * @param buf           Buffer where to save data.
 * @param len           Length of the buffer.
 *
 * @return Number of bytes in packet on success, @c -1 on failure.
 */
extern ssize_t rpc_sockts_recv_filtered_pkt(rcf_rpc_server *rpcs, int s,
                                            char *buf, size_t len);

/**
 * Clear a queue of packets captured with UDP-RX filter.
 *
 * @param rpcs          RPC server handle.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_recv_filtered_pkts_clear(rcf_rpc_server *rpcs);

extern int
rpc_simple_set_recv_filter(rcf_rpc_server *rpcs, int s, const void *buf,
                           size_t len, int flags);

/** RPC definition of opaque pointer to the template metadata */
typedef rpc_ptr rpc_onload_template_handle;

/** RPC definition of flags for use with onload_msg_template_update */
typedef enum rpc_onload_template_flags {
  RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW = 0x1,  /**< Send the packet now */
  RPC_ONLOAD_TEMPLATE_FLAGS_PIO_RETRY = 0x2, /**< Retry acquiring PIO */
  RPC_ONLOAD_TEMPLATE_FLAGS_DONTWAIT = 0x40, /**< Non-blocking call */
} rpc_onload_template_flags;

/** 
 * RPC implelemtation of structure for single template update.
 * See onload/extensions_zc.h for details
 */
typedef struct rpc_onload_template_msg_update_iovec {
    void*     otmu_base;         /**< Pointer to new data */
    size_t    otmu_len;          /**< Length of new data */
    size_t    otmu_rlen;         /**< Actual length of update */
    off_t     otmu_offset;       /**< Offset within template to update */
    uint32_t  otmu_flags;        /**< For future use. Must be set to 0 */
} rpc_onload_template_msg_update_iovec;

/**
 * Take an array of iovecs to specify the initial bulk of the packet data,
 * allow to pass wrong lenght of the iovecs array.
 * See onload/extensions_zc.h for details
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param iov       Array of iovecs
 * @param iovcnt    Length of the iovecs array to pass in function
 * @param riovcnt   Actual length of the iovecs array
 * @param handle    ID of pointer to opaque structure to manage templates
 * @param flags     Auxiliary flags
 * 
 * @return Status code
 */
extern int rpc_onload_msg_template_alloc_gen(rcf_rpc_server *rpcs, int fd,
                                         rpc_iovec* iov,
                                         size_t iovcnt, size_t riovcnt,
                                         rpc_onload_template_handle *handle,
                                         int flags);

/**
 * Take an array of iovecs to specify the initial bulk of the packet data.
 * See onload/extensions_zc.h for details
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param iov       Array of iovecs
 * @param iovcnt    Length of the iovecs array to pass in function
 * @param handle    ID of pointer to opaque structure to manage templates
 * @param flags     Auxiliary flags
 * 
 * @return Status code
 */
static inline int
rpc_onload_msg_template_alloc(rcf_rpc_server *rpcs, int fd, rpc_iovec* iov,
                              size_t iovcnt, 
                              rpc_onload_template_handle *handle, int flags)
{
    size_t i;

    for (i = 0; i < iovcnt; i++)
        iov[i].iov_rlen = iov[i].iov_len;

    return rpc_onload_msg_template_alloc_gen(rpcs, fd, iov, iovcnt, iovcnt,
                                             handle, flags);
}

/**
 * Update an array of iovecs with new packet data, allow to pass wrong
 * lenght of the updates array.
 * See onload/extensions_zc.h for details
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param handle    ID of pointer to opaque structure to manage templates
 * @param updates   Array of iovecs updates
 * @param iovcnt    Length of the updates array to pass in function
 * @param riovcnt   Actual length of the updates array
 * @param flags     Auxiliary flags
 * 
 * @return Status code
 */
extern int rpc_onload_msg_template_update_gen(rcf_rpc_server *rpcs, int fd,
                              rpc_onload_template_handle handle,
                              rpc_onload_template_msg_update_iovec *updates,
                              size_t iovcnt, size_t riovcnt,
                              int flags);

/**
 * Update an array of iovecs with new packet data.
 * See onload/extensions_zc.h for details
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param handle    ID of pointer to opaque structure to manage templates
 * @param updates   Array of iovecs updates
 * @param iovcnt    Length of the updates array to pass in function
 * @param flags     Auxiliary flags
 * 
 * @return Status code
 */
static inline int
rpc_onload_msg_template_update(rcf_rpc_server *rpcs, int fd,
                              rpc_onload_template_handle handle,
                              rpc_onload_template_msg_update_iovec *updates,
                              size_t iovcnt, int flags)
{
    size_t i;

    for (i = 0; i < iovcnt; i++)
        updates[i].otmu_rlen = updates[i].otmu_len;

    return rpc_onload_msg_template_update_gen(rpcs, fd, handle, updates,
                                              iovcnt, iovcnt, flags);
}


/**
 * Abort a templated send without sending and free allocated memory.
 * See onload/extensions_zc.h for details
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param handle    ID of pointer to opaque structure to manage templates
 * 
 * @return Status code
 */
extern int rpc_onload_msg_template_abort(rcf_rpc_server *rpcs, int fd,
                                         rpc_onload_template_handle handle);

/**
 * Allocate buffers with provided array of iovecs and send them.
 * 
 * @param rpcs      RPC server
 * @param fd        Socket with Onload
 * @param iov       Array of iovecs
 * @param iovcnt    Length of the iovecs array to pass in function
 * @param riovcnt   Actual length of the iovecs array
 * @param flags     Auxiliary flags
 * 
 * @return Status code
 */
extern int rpc_template_send(rcf_rpc_server *rpcs, int fd, rpc_iovec* iov,
                             size_t iovcnt, size_t riovcnt, int flags);

/**
 * Repeatedly call functios popen()-fread()-pclose() in multiple threads.
 *
 * @param rpcs          RPC server
 * @param threads       Maximum number of parallel threads
 * @param iterations    Summary number of threads to be launced
 * @param popen_iter    Iterations number of internal loop of a thread
 * @param sync          @c TRUE to start flooder
 *                      when @b rpc_popen_flooder_toggle() enables it
 *
 * @return Number of started threads or @c -1 in case of failure
 */
extern int rpc_popen_flooder(rcf_rpc_server *rpcs, int threads,
                             int iterations, int popen_iter, te_bool sync);

/**
 * Toggle to start/stop popen flooders work. It is for synchronous
 * start/finish of popen flooders in all threads of the agent.
 *
 * @param rpcs          RPC server
 * @param enable        @c TRUE to enable popen flooder
 */
extern void rpc_popen_flooder_toggle(rcf_rpc_server *rpcs, te_bool enable);

/** 
 * RPC implelemtation of structure for wire order delivery via epoll.
 * See onload/extensions.h for details
 */
typedef struct rpc_onload_ordered_epoll_event {
    struct timespec ts;   /**< The hardware timestamp of the first readable
                               data */
    int bytes;            /**< Number of bytes that may be read to respect
                               ordering */
} rpc_onload_ordered_epoll_event;

/**
 * RPC call for Onload extension function @b onload_ordered_epoll_wait
 * 
 * @param rpcs      RPC server
 * @param epfd      Epoll fd
 * @param event     Array for epoll events
 * @param oo_events Array for extension epoll events
 * @param rmaxev    Actual number of events
 * @param maxevents Events number to be passed to the function
 * @param timeout   Awaitnig timeout
 * 
 * @return Events number or @c -1 in case of errors
 */
extern int rpc_onload_ordered_epoll_wait_gen(rcf_rpc_server *rpcs, int epfd,
                              struct rpc_epoll_event *events,
                              rpc_onload_ordered_epoll_event *oo_events,
                              int rmaxev, int maxevents, int timeout);

/**
 * Wrapper for @b rpc_onload_ordered_epoll_wait_gen call for generic case.
 * There is only disticntion that this call doesn't have @p rmaxev, because
 * it's equal to @p maxevents in generic case.
 */
static inline int
rpc_onload_ordered_epoll_wait(rcf_rpc_server *rpcs, int epfd,
                              struct rpc_epoll_event *events,
                              rpc_onload_ordered_epoll_event *oo_events,
                              int maxevents, int timeout)
{
    return rpc_onload_ordered_epoll_wait_gen(rpcs, epfd, events, oo_events,
                                             maxevents, maxevents, timeout);
}

/**
 * Convert structure rpc_iovec to tarpc_iovec to be used in RPC.
 * 
 * @param iov_arr    RPC vecors array
 * @param iov        User vectors array
 * @param iovcnt     User vectors array length
 * @param strbuf     Buffer for the string representation
 * @param strbuf_len The string buffer length
 */
extern void iov_h2rpc(struct tarpc_iovec* iov_arr, const rpc_iovec* iov,
                      size_t iovcnt, char *strbuf, int strbuf_len);

/**
 * Send data from one or two sockets for a while, sometimes passing
 * @c ONLOAD_MSG_WARM flag to send function.
 *
 * @note If both sockets are specified, this function will
 *       use nonblocking send.
 *
 * @param rcps          RPC server pointer.
 * @param func_name     Name of send function to use.
 * @param fd1           First socket (not used if negative).
 * @param fd2           Second socket (not used if negative).
 * @param buf_size_min  Minimum number of bytes to pass to
 *                      send function at once.
 * @param buf_size_max  Maximum number of bytes to pass to
 *                      send function at once.
 * @param time2run      How long to send data, in seconds.
 * @param sent1         Where to save number of bytes sent
 *                      from the first socket.
 * @param sent2         Where to save number of bytes sent
 *                      from the second socket.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_send_msg_warm_flow(rcf_rpc_server *rpcs,
                                  const char *func_name,
                                  int fd1, int fd2,
                                  size_t buf_size_min,
                                  size_t buf_size_max,
                                  unsigned int time2run,
                                  uint64_t *sent1, uint64_t *sent2);

/**
 * Send data @p send_num number times use delays between calls if required.
 * In the final data transmission is triggered using socket options
 * TCP_CORK or TCP_NODELAY.
 *
 * @param rcps          RPC server pointer.
 * @param fd            Socket descriptor.
 * @param fd_aux        Auxiliary socket descriptor used (if not negative)
 *                      to notify peer that sending data will soon begin.
 * @param size_min      Minimum data amount to send by one call.
 * @param size_max      Maximum data amount to send by one call.
 * @param send_num      Send calls number.
 * @param length        How much data to send (by all send calls
 *                      combined).
 * @param send_usleep   Sleep between @c send() calls if non-negative,
 *                      microseconds.
 * @param tcp_nodelay   Use option TCP_NODELAY to force data transmission
 *                      if @c TRUE, otherwise - TCP_CORK.
 * @param no_trigger    If @c TRUE, do not force final data transmission.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_many_send_cork(rcf_rpc_server *rpcs, int fd, int fd_aux,
                              size_t size_min, size_t size_max,
                              size_t send_num, size_t length,
                              int send_usleep, te_bool tcp_nodelay,
                              te_bool no_trigger);

/**
 * Receive specified number of bytes from a socket, calling recv()
 * multiple times on TA if necessary. Measure time it took to receive
 * all the requested data.
 *
 * @param rpcs      RPC server handle.
 * @param fd        Socket descriptor.
 * @param fd_aux    Auxiliary socket descriptor. If not negative,
 *                  the function will firstly wait until some data arrives
 *                  on it, and then will start to receive data from the main
 *                  socket and to measure duration.
 * @param length    How many bytes should be received.
 * @param duration  Where to save measured duration (in microseconds).
 *
 * @return Length of data actually received on success, or @c -1 in case of
 *         failure.
 */
extern ssize_t rpc_recv_timing(rcf_rpc_server *rpcs, int fd, int fd_aux,
                               size_t length, uint64_t *duration);

/**
 * Call epoll_wait() in a loop until it returns non-zero (expect at most
 * one event).
 *
 * @param rpcs        RPC server handle.
 * @param epfd        Epoll file descriptor.
 * @param event       Event reported by epoll_wait().
 * @param timeout     Timeout in milliseconds.
 *
 * @return Result of epoll_wait() or @c -1 in case of failure (check
 *         RPC_ERRNO() to distinguish between epoll_wait() and TE failure).
 */
extern int rpc_epoll_wait_loop(rcf_rpc_server *rpcs, int epfd,
                               struct rpc_epoll_event *event,
                               int timeout);

/**
 * Wait for disappearance of TCP socket from output of tools like netstat.
 * Measure time it took.
 *
 * @param rpcs              RPC server handle.
 * @param loc_addr          Local address.
 * @param rem_addr          Remote address.
 * @param last_state        Where to save the last state in which
 *                          TCP socket was observed.
 * @param last_state_time   Where to save time during which the socket
 *                          was observed in its last state, in
 *                          milliseconds.
 * @param close_time        Where to save time during which the socket
 *                          was in one of the closing states (those
 *                          after TCP_ESTABLISHED in states diagram),
 *                          in milliseconds.
 *
 * @return @c 0 on success, @c -1 in case of failure.
 */
extern int rpc_wait_tcp_socket_termination(rcf_rpc_server *rpcs,
                                           const struct sockaddr *loc_addr,
                                           const struct sockaddr *rem_addr,
                                           rpc_tcp_state *last_state,
                                           int *last_state_time,
                                           int *close_time);

/**
 * Send @p msg_len packets @p msg_size bytes each with dummy data
 * from connected or non-connected socket with help of @b sendmmsg()
 * function in non-blocking mode. Socket will be closed according to
 * @p disconn_way right after @b sendmmsg() call.
 *
 * @note If socket is successfully closed, -1 is assigned to socket
 *       descriptor.
 *
 * @param rpcs            RPC server handle
 * @param fd              pointer to socket descriptor
 * @param msg_size        size of one packet
 * @param msg_len         number of packets
 * @param disconn_way     how to disconnect the socket
 * @param connect_to_addr address to connect to in case when @p disconn_way
 *                        is @c DISCONNECT (may be @c NULL)
 *
 * @return Number of sent packets (zero in case @p disconn_way == @c EXIT,
 * just to show the function call was succesfull), or -1 when an error occured.
 */
extern int rpc_sendmmsg_disconnect(rcf_rpc_server *rpcs, int *fd,
                                   unsigned int msg_size,
                                   unsigned int msg_len,
                                   tarpc_disconn_way disconn_way,
                                   const struct sockaddr *connect_to_addr);

/**
 * Get TCP socket state from netstat-like tools.
 *
 * @param rpcs          RPC server handle.
 * @param loc_addr      Local address/port.
 * @param rem_addr      Remote address/port.
 * @param state         Where to save TCP state.
 * @param found         Will be set to @c TRUE if socket was found.
 *
 * @return @c 0 on success, @c -1 in case of failure.
 */
extern int rpc_get_tcp_socket_state(rcf_rpc_server *rpcs,
                                    const struct sockaddr *loc_addr,
                                    const struct sockaddr *rem_addr,
                                    rpc_tcp_state *state,
                                    te_bool *found);

/**
 * Try to send packet with size @p len from socket @p s via the function
 * determined by @p send_func.
 *
 * This function is to check behavior of transmitting function
 * with various buffer size passed, e.g. extra large (over 2^31).
 *
 * @note Only TARPC_SEND_FUNC_SEND and TARPC_SEND_FUNC_SENDTO are supported.
 *
 * @param rpcs          RPC server handle.
 * @param send_func     Transmitting function.
 * @param s             Socket descriptor.
 * @param len           Size of datagram (can be any within size_t type).
 * @param flags         bitwise OR of zero or more of the following flags:
 *                      - RPC_MSG_OOB send out-of-band data if supported.
 *                      - RPC_MSG_DONTWAIT enable non-blocking operation.
 *                      Other supported flags can be found in
 *                      te_rpc_sys_socket.h.
 * @param addr          Destination address.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
extern int rpc_send_var_size(rcf_rpc_server *rpcs,
                             tarpc_send_function send_func,
                             int s, size_t len,
                             rpc_send_recv_flags flags,
                             const struct sockaddr *addr);

/**
 * Try to receive packet with size @p len from socket @p s via the function
 * determined by @p recv_func.
 *
 * This function is to check behavior of receiving function
 * with various buffer size passed, e.g. extra large (over 2^31).
 *
 * @param rpcs          RPC server handle.
 * @param recv_func     Receiving function.
 * @param s             Socket descriptor.
 * @param len           Size of packet (can be any within size_t type).
 * @param flags         bitwise OR of zero or more of the following flags:
 *                      - RPC_MSG_OOB send out-of-band data if supported.
 *                      - RPC_MSG_DONTWAIT enable non-blocking operation.
 *                      Other supported flags can be found in
 *                      te_rpc_sys_socket.h.
 *
 * @return Number of bytes received on success, @c -1 on failure.
 */
extern int rpc_recv_var_size(rcf_rpc_server *rpcs,
                             tarpc_recv_function recv_func,
                             int s, size_t len,
                             rpc_send_recv_flags flags);

/**
 * Allocate context which should be passed on TA side to functions like
 * tarpc_send_func_onload_zc_send(). These functions can be passed together
 * with context pointer to rpc_pattern_sender().
 *
 * @note If you call this function with use_libc = @c TRUE, send function
 *       will be resolved from libc.
 *
 * @param rpcs      RPC server handle.
 *
 * @return RPC pointer to allocated context on success, @c RPC_NULL on
 *         failure.
 */
extern rpc_ptr rpc_sockts_alloc_send_func_ctx(rcf_rpc_server *rpcs);

/**
 * Allocate and register ZC buffer and completion queue for
 * onload_zc_send(). This should be done if you want to use
 * tarpc_send_func_onload_zc_send_user_buf() with rpc_pattern_sender().
 *
 * @param rpcs          RPC server handle.
 * @param ctx           RPC pointer to sending function context.
 * @param fd            Socket FD.
 * @param buf_size      Minimum size of the buffer to allocate
 *                      (more may be actually allocated as the size should
 *                       be a multiple of system page size).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_send_func_ctx_init_zc_buf(rcf_rpc_server *rpcs,
                                                rpc_ptr ctx, int fd,
                                                size_t buf_size);

/**
 * Clean ZC-related fields of sending function context set with
 * rpc_sockts_send_func_ctx_init_zc_buf().
 * Wait for remaining completion messages; unregister and free
 * ZC buffer.
 *
 * @param rpcs          RPC server handle.
 * @param ctx           RPC pointer to sending function context.
 * @param fd            Socket FD.
 * @param timeout       How long to wait for completion messages,
 *                      in milliseconds. If not all the expected
 *                      completion messages arrived, this function
 *                      will still unregister and release ZC buffer
 *                      and then report an error.
 *                      Negative value means infinite timeout.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_send_func_ctx_clean_zc_buf(rcf_rpc_server *rpcs,
                                                 rpc_ptr ctx, int fd,
                                                 int timeout);

/**
 * Enable flag @b use_syscall for pco_iut.
 *
 * @param rpcs  RPC server handle.
 */
extern void use_syscall_rpc_server_hook(rcf_rpc_server *rpcs);


/**
 * Call functions connect-send-close in multiple threads for @c SOCK_STREAM
 * in for the @duration time.
 *
 * @param rpcs          RPC server.
 * @param threads_num   Number of threads.
 * @param dest_addr     Destination address, to use with @b connect().
 * @param src_addr      Array of source addresses with @c threads_num items.
 * @param duration      Duration of send, in seconds.
 * @param [out] sent    Array of sent bytes by each thread.
 *
 * @return Number of started threads or @c -1 in case of failure
 */
extern int rpc_connect_send_dur_time(rcf_rpc_server *rpcs,
                                     int threads_num,
                                     const struct sockaddr *dst_addr,
                                     const struct sockaddr_storage *src_addr,
                                     uint64_t duration,
                                     uint64_t *sent);

/**
 * Call iomux function multiple times in a loop. Iomux function is expected
 * to terminate due to timeout here; calling it multiple times helps to
 * check whether timeout works as expected for small timeout values.
 *
 * @param rpcs            RPC server.
 * @param iomux           Iomux function to call.
 * @param fds             Array of tarpc_pollfd structures describing
 *                        which events to wait on which FDs.
 * @param nfds            Number of elements in @p fds.
 * @param timeout         Timeout for @p iomux (in milliseconds).
 * @param n_calls         Number of times to call @p iomux.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_iomux_timeout_loop(rcf_rpc_server *rpcs,
                                         iomux_call_type iomux,
                                         struct tarpc_pollfd *fds,
                                         unsigned int nfds,
                                         int timeout, unsigned int n_calls);

/**
 * Receive from a TCP peer data generated by fill_buff_with_sequence_lcg(),
 * check that it matches the expectation. When receiving, often pass
 * @c MSG_PEEK flag to recv() to re-read the same data with the next call.
 *
 * @param rpcs        RPC server handle.
 * @param s           Socket FD.
 * @param time2run    Time to run (in milliseconds).
 * @param time2wait   Time to wait for the next packet (in milliseconds;
 *                    if this time expires, the function returns even
 *                    if @p time2run is not expired yet).
 * @param gen_arg     Argument for fill_buff_with_sequence_lcg(),
 *                    must be the same as the argument passed on peer.
 * @param received    Where to save number of received bytes.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
extern int rpc_sockts_peek_stream_receiver(rcf_rpc_server *rpcs, int s,
                                           int time2run, int time2wait,
                                           tarpc_pat_gen_arg *gen_arg,
                                           uint64_t *received);

#endif /* !__SOCKAPI_TS_RPC_H__ */
