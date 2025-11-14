/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief sapi-ts RPC
 *
 * Definition of RPC structures and functions for sapi-ts
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

/* sapi_get_sizeof() */
struct tarpc_sapi_get_sizeof_in {
    struct tarpc_in_arg common;

    string typename<>;
};

struct tarpc_sapi_get_sizeof_out {
    struct tarpc_out_arg common;

    tarpc_ssize_t size;
};

struct tarpc_send_traffic_in {
    struct tarpc_in_arg common;
    tarpc_int           num;    /**< Number of packets to be sent */
    tarpc_int           fd<>;   /**< List of sockets */
    uint8_t             buf<>;  /**< Buffer */
    tarpc_size_t        len;    /**< Buffer length */
    tarpc_int           flags;  /**< Flags */ 
    struct tarpc_sa     to<>;   /**< List of addresses */
};
typedef struct tarpc_ssize_t_retval_out tarpc_send_traffic_out;


/* many_send() */
struct tarpc_many_send_in {
    struct tarpc_in_arg common;

    tarpc_int       sock;
    tarpc_int       flags;
    tarpc_size_t    vector<>;
};

struct tarpc_many_send_out {
    struct tarpc_out_arg common;

    tarpc_int   retval;     /**< 0 (success) or -1 (failure) */

    uint64_t    bytes;      /**< Number of sent bytes */
};

struct tarpc_many_sendto_in {
    struct tarpc_in_arg common;
    tarpc_int           num;   /**< Number of packets to be sent */
    tarpc_int           sock;  /**< Socket for packets sending */
    tarpc_size_t        len;   /**< Buffer length */
    tarpc_int           flags; /**< Flags */
    struct tarpc_sa     to;    /**< Destanation address */
};

struct tarpc_many_sendto_out {
    struct tarpc_out_arg common;

    tarpc_int   retval;     /**< 0 (success) or -1 (failure) */

    uint64_t    sent;      /**< Number of sent bytes */
};

struct tarpc_close_and_accept_in {
    struct tarpc_in_arg common;
    tarpc_int           listening;  /**< Listening socket */
    tarpc_int           conns;      /**< Number of connections */
    tarpc_int           fd<>;       /**< Accepted sockets list */
    uint16_t            state;      /**< Mask to close sockets and 
                                         to call accept again */
};

struct tarpc_close_and_accept_out {
   struct tarpc_out_arg  common;
   tarpc_int             fd<>;      /**< Accepted sockets list */
   tarpc_ptr             mem_ptr;
   tarpc_int             retval;    /**< Returned value */
};

struct tarpc_close_and_socket_in {
    struct tarpc_in_arg common;
    tarpc_int           fd;
    tarpc_int           domain;
    tarpc_int           type;
    tarpc_int           protocol;
};

struct tarpc_close_and_socket_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
};

struct tarpc_timely_round_trip_in {
    struct tarpc_in_arg common;
    tarpc_int           sock_num;    /**< Number of sockets */
    tarpc_int           fd<>;        /**< Socket */
    tarpc_size_t        size;        /**< Buffer length */
    tarpc_size_t        vector_len;  /**< Vector length */
    uint32_t            timeout;     /**< Timeout passed to select */
    uint32_t            time2wait;   /**< Time during for a roundtrip 
                                          should be performed */
    tarpc_int           flags;       /**< Flags */
    tarpc_int           addr_num;    /**< Number of addresses */
    struct tarpc_sa     to<>;        /**< Adresses list */
};    

enum round_trip_error {
    ROUND_TRIP_ERROR_OTHER = 1,
    ROUND_TRIP_ERROR_SEND = 2,
    ROUND_TRIP_ERROR_RECV = 3,
    ROUND_TRIP_ERROR_TIMEOUT = 4,
    ROUND_TRIP_ERROR_TIME_EXPIRED = 5
};    

struct tarpc_timely_round_trip_out {
    struct tarpc_out_arg  common;
    tarpc_int             retval;
    tarpc_int             index;  /**< Index in addresses list
                                       for which address 
                                       error occured */
};


struct tarpc_round_trip_echoer_in {
    struct tarpc_in_arg common;
    tarpc_int           sock_num;    /**< Number of sockets */
    tarpc_int           fd<>;        /**< Sockets list */
    tarpc_int           addr_num;    /**< Number of addresses for which echo
                                          must be done */
    tarpc_size_t        size;        /**< Buffer length */
    tarpc_size_t        vector_len;  /**< Vector length */
    uint32_t            timeout;     /**< Timeout passed to select */
    tarpc_int           flags;       /**< Flags */
};

struct tarpc_round_trip_echoer_out {
    struct tarpc_out_arg  common;
    tarpc_int             retval;
    tarpc_int             index;  /**< How many times echoes 
                                       were done */
};

struct tarpc_get_callback_list_in {
    struct tarpc_in_arg common;
};

struct tarpc_callback_item {
    tarpc_int    callback_num; /* Number of the callback function */
    tarpc_signum signo;        /* Signal number or 0 for SIGEV_THREAD */
    tarpc_int    val;          /* Value passed to callback */
};

struct tarpc_get_callback_list_out {
    struct tarpc_out_arg       common;
    struct tarpc_callback_item list<>; /* Array of callbacks. */
};

/* Register talib completion callbacks */
struct tarpc_register_callbacks_in {
    struct tarpc_in_arg common;
};

struct tarpc_register_callbacks_out {
    struct tarpc_out_arg common;
};


/** Modes for blocking emulation while read/write using AIO requests */
enum tarpc_blocking_aio_mode {
    TARPC_AIO_BLK_SUSPEND,  /** Wait using aio_suspend() */
    TARPC_AIO_BLK_POLL,     /** Poll periodically using aio_error() */
    TARPC_AIO_BLK_SIGNAL,   /** Block until signal is received using 
                                 sigsuspend() */
    TARPC_AIO_BLK_CALLBACK  /** Wait until callback is called */
};

/* Function for emulation of blocking read/write using AIO requests */

struct tarpc_aio_read_blk_in {
    struct tarpc_in_arg common;

    tarpc_int       fd;     /* File descriptor */
    uint8_t         buf<>;  /* Data location */
    tarpc_size_t    len;    /* Length to be passed to request */
    int             mode;   /* TARPC_BLK_* */
};

struct tarpc_aio_read_blk_out {
    struct tarpc_out_arg    common;

    tarpc_ssize_t   retval;

    uint8_t         buf<>;
};

struct tarpc_aio_write_blk_in {
    struct tarpc_in_arg common;

    tarpc_int       fd;     /* File descriptor */
    uint8_t         buf<>;  /* Data */
    tarpc_size_t    len;    /* Length to be passed to request */
    int             mode;   /* TARPC_BLK_* */
};

typedef struct tarpc_ssize_t_retval_out tarpc_aio_write_blk_out;


/* nested_requests test */

struct tarpc_nested_requests_test_in {
    struct tarpc_in_arg common;

    tarpc_int s;        
    tarpc_int req_num;
};

struct tarpc_nested_requests_test_out {
    struct tarpc_out_arg common;

    tarpc_int retval;
};

struct tarpc_device_io_control_test_in {
    struct tarpc_in_arg common;

    string              code<>;
};

struct tarpc_device_io_control_test_out {
    struct tarpc_out_arg common;

    tarpc_int            retval;
};

struct tarpc_event_select_bnb_value_in {
    struct tarpc_in_arg common;
    tarpc_int       fd;           /**< TA-local socket */
    tarpc_wsaevent  hevent;       /**< Event object to be associated
                                       with set of network events */
    uint32_t        event;        /**< Bitmask that specifies the set
                    of network events */
};

typedef struct tarpc_int_retval_out tarpc_event_select_bnb_value_out;

enum async_select_bnb_value_usage {
    USE_CLOSED_WINDOW = 1,
    USE_OTHER_GDI_HANDLE = 2,
    USE_INVALID_EVENT_MASK = 3
};    

struct tarpc_async_select_bnb_value_in {
    struct tarpc_in_arg common;
    tarpc_int       fd;           /**< TA-local socket */
    tarpc_hwnd      hwnd;         /**< Window for messages receiving */
    uint32_t        event;        /**< Bitmask that specifies the set
                    of network events */
    async_select_bnb_value_usage
                    usage;        /**< Which invalid parameter should be used
                                       in WSAAsyncSelect() call */
};

typedef struct tarpc_int_retval_out tarpc_async_select_bnb_value_out;

/* rpc_write_at_offset() */
struct tarpc_write_at_offset_continuous_in {
    struct tarpc_in_arg   common;
    tarpc_int             fd;
    uint8_t               buf<>;
    tarpc_off_t           offset;
    uint64_t              time;
};

struct tarpc_write_at_offset_continuous_out {
    struct tarpc_out_arg  common;
};


struct tarpc_onload_hw_filters_limit_in {
    struct tarpc_in_arg common;
    struct tarpc_sa  addr;        /**< Address to bind */
};

struct tarpc_onload_hw_filters_limit_out {
    struct tarpc_out_arg common;
    tarpc_int retval;             /**< Maximum HW filters number */
};

enum tarpc_out_of_res_acts {
    TARPC_OOR_CONNECT = 1,
    TARPC_OOR_LISTEN = 2,
    TARPC_OOR_RECVFROM = 3,
    TARPC_OOR_BIND = 4
};

struct tarpc_out_of_hw_filters_do_in {
    struct tarpc_in_arg common;
    
    tarpc_bool       do_bind;          /**< Bind socket before connect */
    struct tarpc_sa  bind_addr;        /**< Address to bind */
    struct tarpc_sa  connect_addr;     /**< Address to connect */
    tarpc_int        sock_num;         /**< Number of sockets to create */
    tarpc_int        action;           /**< Action to perform on the
                                            created sockets */
    tarpc_int        type;             /**< Scoket type */
};

struct tarpc_out_of_hw_filters_do_out {
    struct tarpc_out_arg common;
    tarpc_int            acc_num;      /**< accelerated sockets number */
    tarpc_int            err_num;      /**< fails number */
    tarpc_int            sock1;        /**< First created socket */
    tarpc_int            sock2;        /**< Last created socket */
    tarpc_int            retval;       /**< Number of the created sockets */
};

/* 
 * Accept many connections on the socket, auxiliary RPC for 
 * out_of_hw_filters_tcp test.
 */
struct tarpc_many_accept_in {
    struct tarpc_in_arg common;
    
    tarpc_int  s;          /**< Listening socket */
    tarpc_int  sock_num;   /**< Number of connections to accept */
    tarpc_int  data_len;   /**< Length of data to send */
    tarpc_int  send_count; /**< How many times to send @p data_len */
};    

struct tarpc_many_accept_out {
    struct tarpc_out_arg common;
    tarpc_int sock1;     /**< First accepted socket */
    tarpc_int sock2;     /**< Last accepted socket */
    tarpc_ptr handle;    /**< Pointer to the sockets array */
    tarpc_int iteration; /**< Number of the last iteration */
    tarpc_int retval;    /**< Number of the created sockets */
};

struct tarpc_many_connect_in {
    struct tarpc_in_arg common;
    struct tarpc_sa addr;  /**< Address to connect */
    tarpc_int  sock_num;   /**< Sockets number */
    tarpc_int  data_len;   /**< Length of data to send */
    tarpc_int  send_count; /**< How many times to send @p data_len */
};    

struct tarpc_many_connect_out {
    struct tarpc_out_arg common;
    tarpc_int sock1;    /**< First socket */
    tarpc_int sock2;    /**< Last socket */
    tarpc_ptr handle;   /**< Pointer to the sockets array */
    tarpc_int retval;   /**< Number of the created sockets */
};

struct tarpc_many_socket_in {
    struct tarpc_in_arg common;
    tarpc_int num;      /**< Sockets number */
    tarpc_int domain;   /**< TA-independent domain */
};

struct tarpc_many_socket_out {
    struct tarpc_out_arg common;
    tarpc_ptr handle;  /**< Pointer to the sockets array */
    tarpc_int retval;
};

struct tarpc_many_close_in {
    struct tarpc_in_arg common;
    tarpc_ptr handle;   /**< Pointer to the sockets array */
    tarpc_int num;      /**< Sockets number */
};

struct tarpc_many_close_out {
    struct tarpc_out_arg common;
    tarpc_int retval;
};

struct tarpc_many_epoll_ctl_add_del_in {
    struct tarpc_in_arg common;
    tarpc_ptr socks_arr;          /**< Pointer to the sockets array */
    tarpc_int socks_num;          /**< Sockets number */
    tarpc_int epfd;               /**< Epoll descriptor */
    uint32_t events;              /**< Bitmask of event types */
    tarpc_bool check_epoll_wait;  /**< Call epoll_wait() after each
                                       epoll_ctl() */
    tarpc_int time2run;           /**< How long to run, in ms */
};

typedef struct tarpc_int_retval_out tarpc_many_epoll_ctl_add_del_out;

struct tarpc_many_close_cache_in {
    struct tarpc_in_arg common;
    tarpc_ptr handle;   /**< Pointer to the sockets array */
    tarpc_int num;      /**< Sockets number */
};

struct tarpc_many_close_cache_out {
    struct tarpc_out_arg common;
    tarpc_int cached;   /**< Cached sockets number */
    tarpc_int retval;
};

struct tarpc_get_socket_from_array_in {
    struct tarpc_in_arg common;

    tarpc_ptr   handle;   /**< Pointer to the sockets array */
    tarpc_uint  idx;      /**< Sockets number */
};

struct tarpc_get_socket_from_array_out {
    struct tarpc_out_arg common;

    tarpc_int s;        /**< Socket */
    tarpc_int retval;   /**< Return value */
};

struct tarpc_many_recv_in {
    struct tarpc_in_arg common;
    tarpc_int     sock;          /**< Socket */
    tarpc_int     num;           /**< Packets number to receive */
    tarpc_int     duration;      /**< Handover duration */
    tarpc_size_t  length;        /**< Packet length */
    uint8_t       last_packet<>; /**< Last packet template */
    tarpc_bool    count_fails;   /**< Dont stop on fail */
};

struct tarpc_many_recv_out {
    struct tarpc_out_arg common;
    tarpc_int fails_num; /**< Fails number */
    tarpc_int retval;    /**< Received packets number or @c -1 */
};

struct tarpc_recv_timing_in {
    struct tarpc_in_arg common;   /**< Common IN arguments */

    tarpc_int     fd;             /**< Socket descriptor */
    tarpc_int     fd_aux;         /**< Auxiliary socket descriptor */
    tarpc_size_t  length;         /**< How much bytes should be
                                       received */
};

struct tarpc_recv_timing_out {
    struct tarpc_out_arg common;   /**< Common OUT arguments */

    uint64_t       duration;       /**< Time in microseconds it took to
                                        receive all the data */
    tarpc_ssize_t  retval;         /**< Number of bytes received or
                                        @c -1 */
};

struct tarpc_many_send_num_in {
    struct tarpc_in_arg common;
    tarpc_int     sock;          /**< Socket */
    tarpc_int     num;           /**< Sockets number */
    tarpc_int     duration;      /**< Handover duration */
    tarpc_size_t  length_min;    /**< Minimum packets length */
    tarpc_size_t  length_max;    /**< Maximum packets length */
    string        func_name<>;   /**< Function name */
    tarpc_bool    check_len;     /**< Check sent data length */
    tarpc_bool    count_fails;   /**< Dont stop on fail */
};

struct tarpc_many_send_num_out {
    struct tarpc_out_arg common;
    tarpc_int fails_num; /**< Fails number */
    tarpc_int retval;    /**< Sent packets number or @c -1 */
};

/* 
 * out_of_netifs test 
 */
struct tarpc_out_of_netifs_in {
    struct tarpc_in_arg common;
    
    tarpc_int  sock_type; /**<  Type of socket to create (stream/dgram) */
    tarpc_int  sock_num;  /**< Number of sockets to create */
};    

struct tarpc_out_of_netifs_out {
    struct tarpc_out_arg common;
    tarpc_int num;  /**< Successfully performed iterations number */
    tarpc_int acc;  /**< Accelerated sockets number */

    tarpc_int rc; /**< Return code */
};    

/* 
 * Traffic processor (sender/receiver).
 */
struct tarpc_traffic_processor_in {
    struct tarpc_in_arg common;
    
    tarpc_int  sock;  /**< Socket for sending/receiving */
    tarpc_bool snd;   /**< If TRUE, send traffic */
    tarpc_ptr  bytes; /**< Location for transferred bytes */
    tarpc_ptr  stop;  /**< Location for stop flag */
};    

struct tarpc_traffic_processor_out {
    struct tarpc_out_arg common;
};

/* Register talib completion callbacks */
struct tarpc_incorrect_crc_send_test_in {
    struct tarpc_in_arg common;
    
    string    ifname<>;    /** name of ethernet interface */
    uint8_t   dest_addr<>; /** destination MAC address of 
                               ethernet NIC */
    tarpc_sa  dest_sa<>; /** destination socket address */
};

struct tarpc_incorrect_crc_send_test_out {
    struct tarpc_out_arg common;
    tarpc_int retval;
};

struct tarpc_nb_receiver_start_in {
    struct tarpc_in_arg common;
    
    tarpc_int           s;      /**< Socket to be used */
    tarpc_ptr           handle; /**< Handle to start/stop the infinite
                                     loop of the receiver */
};

struct tarpc_nb_receiver_start_out {
    struct tarpc_out_arg common;
    tarpc_int            retval; /**< 0 (success) or -1 (failure) */
};

struct tarpc_nb_receiver_stop_in {
    struct tarpc_in_arg common;

    tarpc_ptr           handle; /**< Handle to start/stop the infinite
                                     loop of the receiver */
};

struct tarpc_nb_receiver_stop_out {
    struct tarpc_out_arg common;
    tarpc_int            retval; /**< 0 (success) or -1 (failure) */
};

/** struct onload_zc_iovec */
struct tarpc_onload_zc_iovec {
    tarpc_ptr       iov_base;
    tarpc_size_t    iov_len;
    tarpc_ptr       buf;
    tarpc_uint      iov_flags;
};

enum tarpc_onload_zc_buffer_type_flags {
    TARPC_ONLOAD_ZC_BUFFER_HDR_NONE = 0x0,
    TARPC_ONLOAD_ZC_BUFFER_HDR_UDP = 0x1,
    TARPC_ONLOAD_ZC_BUFFER_HDR_TCP = 0x2
};

struct tarpc_onload_zc_alloc_buffers_in {
    struct tarpc_in_arg common;

    tarpc_int                           fd;
    tarpc_ptr                           iovecs;
    tarpc_int                           iovecs_len;
    tarpc_onload_zc_buffer_type_flags   flags;
};

struct tarpc_onload_zc_alloc_buffers_out {
    struct tarpc_out_arg common;

    tarpc_int            retval;
};

struct tarpc_free_onload_zc_buffers_in {
    struct tarpc_in_arg common;

    tarpc_int                           fd;
    tarpc_ptr                           iovecs;
    tarpc_int                           iovecs_len;
};

struct tarpc_free_onload_zc_buffers_out {
    struct tarpc_out_arg common;

    tarpc_int            retval;
};

struct tarpc_onload_zc_register_buffers_in {
    struct tarpc_in_arg                 common;

    tarpc_int                           fd;
    uint64_t                            addr_space;
    tarpc_ptr                           base_ptr;
    uint64_t                            off;
    uint64_t                            len;
    tarpc_int                           flags;
};

struct tarpc_onload_zc_register_buffers_out {
    struct tarpc_out_arg common;

    tarpc_ptr            handle;
    tarpc_int            retval;
};

struct tarpc_onload_zc_unregister_buffers_in {
    struct tarpc_in_arg                 common;

    tarpc_int                           fd;
    tarpc_ptr                           handle;
    tarpc_int                           flags;
};

struct tarpc_onload_zc_unregister_buffers_out {
    struct tarpc_out_arg common;

    tarpc_int            retval;
};

struct tarpc_onload_set_stackname_in {
    struct tarpc_in_arg common;

    tarpc_int    who;
    tarpc_int    scope;
    string       name<>;
    tarpc_bool   name_null;
};

struct tarpc_onload_set_stackname_out {
    struct tarpc_out_arg common;

    tarpc_int            retval; /**< 0 (success) or -1 (failure) */
};

struct tarpc_onload_stackname_save_in {
    struct tarpc_in_arg common;
};

struct tarpc_onload_stackname_save_out {
    struct tarpc_out_arg common;

    tarpc_int            retval; /**< 0 (success) or <0 (failure) */
};

struct tarpc_onload_stackname_restore_in {
    struct tarpc_in_arg common;
};

struct tarpc_onload_stackname_restore_out {
    struct tarpc_out_arg common;

    tarpc_int            retval; /**< 0 (success) or <0 (failure) */
};

struct tarpc_onload_move_fd_in {
    struct tarpc_in_arg common;

    tarpc_int fd;
};

struct tarpc_onload_move_fd_out {
    struct tarpc_out_arg common;

    tarpc_int            retval; /**< 0 (success) or <0 (failure) */
};

struct tarpc_onload_is_present_in {
    struct tarpc_in_arg common;
};

struct tarpc_onload_is_present_out {
    struct tarpc_out_arg common;

    tarpc_int            retval;
};

struct tarpc_onload_fd_stat_in {
    struct tarpc_in_arg common;

    tarpc_int fd;
};

struct tarpc_onload_stat {
    int32_t   stack_id;
    string    stack_name<>;
    tarpc_bool stack_name_null;
    int32_t   endpoint_id;
    int32_t   endpoint_state;
};

typedef struct tarpc_onload_stat tarpc_onload_stat;

struct tarpc_onload_fd_stat_out {
    struct tarpc_out_arg common;

    struct tarpc_onload_stat buf;
    tarpc_int retval;
};

/** Type of ZC buffer allocation */
enum tarpc_onload_zc_buf_type {
    TARPC_ONLOAD_ZC_BUF_NEW_ALLOC,    /**< New buffer allocated with
                                           @b onload_zc_alloc_buffers() */
    TARPC_ONLOAD_ZC_BUF_NEW_REG,      /**< New buffer registered with
                                           @b onload_zc_register_buffers() */
    TARPC_ONLOAD_ZC_BUF_EXIST_ALLOC,  /**< Existing buffer allocated with
                                           @b onload_zc_alloc_buffers() */
    TARPC_ONLOAD_ZC_BUF_EXIST_REG     /**< Existing buffer registered with
                                           @b onload_zc_register_buffers() */
};

/** Structure describing how to allocate ZC buffer */
struct tarpc_onload_zc_buf_spec {
    tarpc_onload_zc_buf_type    type; /**< Allocation type */

    tarpc_ptr     existing_buf;   /**< RPC pointer to existing buffer(s) */
    tarpc_uint    buf_index;      /**< Index of the buffer in array
                                       allocated with
                                       @b onload_zc_alloc_buffers() */
    uint64_t      buf_offset;     /**< Offset of the buffer in memory
                                       registered with
                                       @b onload_zc_register_buffers() */
    uint64_t      buf_handle;     /**< Onload handle of the buffer */
};

struct tarpc_onload_zc_mmsg {
    struct tarpc_msghdr msg;
    tarpc_int           rc;
    tarpc_int           fd;

    tarpc_bool  keep_recv_bufs;   /**< If @c TRUE, use @c ONLOAD_ZC_KEEP
                                       flag to keep buffers for this
                                       message */
    tarpc_ptr   saved_recv_bufs;  /**< If @b keep_recv_bufs is @c TRUE,
                                       RPC pointer to array of kept Onload
                                       buffers should be stored here on
                                       return */

    tarpc_onload_zc_buf_spec buf_specs<>; /**< Per-iovec allocation specs.
                                               May be empty, in which case
                                               @p use_reg_bufs parameter of
                                               @b simple_zc_send()
                                               determines allocation
                                               type. */
};

typedef struct tarpc_void_in tarpc_sockts_alloc_zc_compl_queue_in;

struct tarpc_sockts_alloc_zc_compl_queue_out {
    struct tarpc_out_arg    common;
    tarpc_ptr               retval;
};

struct tarpc_sockts_free_zc_compl_queue_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               qhead;
};

struct tarpc_sockts_free_zc_compl_queue_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
};

struct tarpc_sockts_proc_zc_compl_queue_in {
    struct tarpc_in_arg     common;
    tarpc_ptr               qhead;
    tarpc_int               timeout;
};

struct tarpc_sockts_proc_zc_compl_queue_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
};

struct tarpc_simple_zc_send_in {
    struct tarpc_in_arg common;

    tarpc_int                   mlen;
    struct tarpc_onload_zc_mmsg msgs<>;
    tarpc_int                   flags;
    tarpc_int                   zc_rc<>;
    tarpc_int                   add_sock;
    tarpc_bool                  use_reg_bufs;
    tarpc_ptr                   compl_queue;
};

struct tarpc_simple_zc_send_out {
    struct tarpc_out_arg common;

    tarpc_int                   retval;
    tarpc_int                   zc_rc<>;
    int64_t                     send_duration;
};

struct tarpc_simple_zc_recv_in {
    struct tarpc_in_arg common;

    struct tarpc_onload_zc_mmsg mmsg<>;
    tarpc_uint                  vlen;

    tarpc_int            s;
    tarpc_msghdr         args_msg<>;
    tarpc_int            flags;
    tarpc_int            cb_flags<>;
    tarpc_bool           os_inline;
    tarpc_bool           explicit_release;
};

struct tarpc_simple_zc_recv_out {
    struct tarpc_out_arg    common;

    tarpc_ssize_t           retval;

    struct tarpc_onload_zc_mmsg mmsg<>;
    tarpc_msghdr                args_msg<>;

    tarpc_int               cb_flags<>;
};

struct tarpc_simple_zc_recv_null_in {
    struct tarpc_in_arg common;

    tarpc_int            s;
};

struct tarpc_simple_zc_recv_null_out {
    struct tarpc_out_arg    common;

    tarpc_ssize_t           retval;
};

struct tarpc_simple_hlrx_recv_zc_in {
    struct tarpc_in_arg common;

    tarpc_int            s;
    struct tarpc_msghdr  msg<>;
    tarpc_int            flags;
    tarpc_bool           os_inline;
};

struct tarpc_simple_hlrx_recv_zc_out {
    struct tarpc_out_arg    common;

    tarpc_ssize_t           retval;
    struct tarpc_msghdr     msg<>;
};

struct tarpc_simple_hlrx_recv_copy_in {
    struct tarpc_in_arg common;

    tarpc_int            s;
    struct tarpc_msghdr  msg<>;
    tarpc_int            flags;
    tarpc_bool           os_inline;
};

struct tarpc_simple_hlrx_recv_copy_out {
    struct tarpc_out_arg    common;

    tarpc_ssize_t           retval;
    struct tarpc_msghdr     msg<>;
};

struct tarpc_simple_set_recv_filter_in {
    struct tarpc_in_arg common;

    tarpc_int       fd;
    uint8_t         buf<>;
    tarpc_size_t    len;
    tarpc_int       flags;
};

typedef struct tarpc_int_retval_out tarpc_simple_set_recv_filter_out;

struct tarpc_onload_set_recv_filter_capture_in {
    struct tarpc_in_arg common;

    tarpc_int       fd;
    tarpc_int       flags;
};

typedef struct tarpc_int_retval_out tarpc_onload_set_recv_filter_capture_out;

struct tarpc_sockts_recv_filtered_pkt_in {
    struct tarpc_in_arg common;

    tarpc_int     fd;
    tarpc_size_t  len;
};

struct tarpc_sockts_recv_filtered_pkt_out {
    struct tarpc_out_arg common;

    uint8_t       buf<>;
    tarpc_ssize_t retval;
};


typedef struct tarpc_void_in tarpc_sockts_recv_filtered_pkts_clear_in;

typedef struct tarpc_int_retval_out tarpc_sockts_recv_filtered_pkts_clear_out;

/* Different ways to perform close() system call */

typedef tarpc_close_in tarpc_close_interrupt_in;
typedef tarpc_close_out tarpc_close_interrupt_out;

typedef tarpc_close_in tarpc_close_sysenter_in;
typedef tarpc_close_out tarpc_close_sysenter_out;

typedef tarpc_close_in tarpc_close_syscall_in;
typedef tarpc_close_out tarpc_close_syscall_out;

/* sighandler_createfile_* */
struct tarpc_sighandler_createfile_in {
    struct tarpc_in_arg common;

    tarpc_int   sig;
};

struct tarpc_thrd_sighandler_createfile_in {
    struct tarpc_in_arg common;

    tarpc_int       sig;
    tarpc_pid_t     pid;
    tarpc_pthread_t tid;
};

typedef struct tarpc_sighandler_createfile_in
    tarpc_sighandler_createfile_cleanup_in;
typedef struct tarpc_void_out tarpc_sighandler_createfile_cleanup_out;
typedef struct tarpc_sighandler_createfile_in
    tarpc_sighandler_createfile_exists_unlink_in;
typedef struct tarpc_int_retval_out
    tarpc_sighandler_createfile_exists_unlink_out;

typedef struct tarpc_thrd_sighandler_createfile_in
    tarpc_thrd_sighnd_crtfile_exists_unlink_in;
typedef struct tarpc_int_retval_out
    tarpc_thrd_sighnd_crtfile_exists_unlink_out;

/* onload_zc_send_msg_more() */

struct tarpc_onload_zc_send_msg_more_in {
    struct tarpc_in_arg common;

    tarpc_int       fd;
    tarpc_ptr       buf;
    tarpc_size_t    first_len;
    tarpc_size_t    second_len;
    tarpc_bool      first_zc;
    tarpc_bool      second_zc;
    tarpc_bool      use_reg_bufs;
    tarpc_bool      set_nodelay;
};

typedef struct tarpc_ssize_t_retval_out tarpc_onload_zc_send_msg_more_out;

enum tarpc_onload_template_flags {
    TARPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW = 0x1,
    TARPC_ONLOAD_TEMPLATE_FLAGS_PIO_RETRY = 0x2,
    TARPC_ONLOAD_TEMPLATE_FLAGS_DONTWAIT = 0x40
};

struct tarpc_onload_msg_template_alloc_in {
    struct tarpc_in_arg common;
    tarpc_int           fd;
    struct tarpc_iovec  vector<>;
    tarpc_size_t        iovcnt;
    tarpc_ptr           handle;
    tarpc_int           flags;
};
struct tarpc_onload_msg_template_alloc_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
    tarpc_ptr               handle;
};

struct tarpc_onload_msg_template_abort_in {
    struct tarpc_in_arg common;
    tarpc_ptr           handle;
    tarpc_int           fd;
};
typedef struct tarpc_int_retval_out tarpc_onload_msg_template_abort_out;

struct tarpc_onload_template_msg_update_iovec {
    uint8_t             otmu_base<>;
    tarpc_size_t        otmu_len;
    tarpc_off_t         otmu_offset;
    tarpc_uint          otmu_flags;
};

struct tarpc_onload_msg_template_update_in {
    struct tarpc_in_arg                             common;
    tarpc_ptr                                       handle;
    struct tarpc_onload_template_msg_update_iovec   updates<>;
    tarpc_size_t                                    iovcnt;
    tarpc_int                                       flags;
    tarpc_int                                       fd;
};
typedef struct tarpc_int_retval_out tarpc_onload_msg_template_update_out;

typedef struct tarpc_onload_msg_template_alloc_in tarpc_template_send_in;
typedef struct tarpc_int_retval_out tarpc_template_send_out;

struct tarpc_popen_flooder_in {
    struct tarpc_in_arg common;
    tarpc_int           threads;
    tarpc_int           iterations;
    tarpc_int           popen_iter;
    tarpc_bool          sync;
};

typedef struct tarpc_int_retval_out tarpc_popen_flooder_out;

struct tarpc_popen_flooder_toggle_in {
    struct tarpc_in_arg common;
    tarpc_bool          enable;
};

typedef struct tarpc_void_out tarpc_popen_flooder_toggle_out;

struct tarpc_onload_ordered_epoll_event {
    int32_t         bytes;
    tarpc_timespec  ts;
};

struct tarpc_onload_ordered_epoll_wait_in {
    struct tarpc_in_arg common;

    tarpc_int                               epfd;
    struct tarpc_epoll_event                events<>;
    struct tarpc_onload_ordered_epoll_event oo_events<>;
    tarpc_int                               maxevents;
    tarpc_int                               timeout;
};

struct tarpc_onload_ordered_epoll_wait_out {
    struct tarpc_out_arg    common;

    tarpc_int               retval;

    struct tarpc_epoll_event                events<>;
    struct tarpc_onload_ordered_epoll_event oo_events<>;
};

struct tarpc_onload_delegated_send {
    uint8_t   headers<>;
    tarpc_int headers_len;
    tarpc_int mss;
    tarpc_int send_wnd;
    tarpc_int cong_wnd;
    tarpc_int user_size;
    tarpc_int tcp_seq_offset;
    tarpc_int ip_len_offset;
    tarpc_int ip_tcp_hdr_len;
    tarpc_int reserved<>;
};

struct tarpc_onload_delegated_send_prepare_in {
    struct tarpc_in_arg common;
    tarpc_int           fd;
    tarpc_int           size;
    tarpc_uint          flags;
    tarpc_onload_delegated_send ods;
};

struct tarpc_onload_delegated_send_prepare_out {
    struct tarpc_out_arg    common;
    tarpc_int               retval;
    tarpc_onload_delegated_send ods;
};

struct tarpc_onload_delegated_send_tcp_update_in {
    struct tarpc_in_arg common;
    tarpc_onload_delegated_send ods;
    tarpc_int           bytes;
    tarpc_int           push;
};

struct tarpc_onload_delegated_send_tcp_update_out {
    struct tarpc_out_arg    common;
    tarpc_onload_delegated_send ods;
};

struct tarpc_onload_delegated_send_tcp_advance_in {
    struct tarpc_in_arg common;
    tarpc_onload_delegated_send ods;
    tarpc_int           bytes;
};

struct tarpc_onload_delegated_send_tcp_advance_out {
    struct tarpc_out_arg    common;
    tarpc_onload_delegated_send ods;
};

struct tarpc_onload_delegated_send_complete_in {
    struct tarpc_in_arg common;
    tarpc_int           fd;
    struct tarpc_iovec  vector<>;
    tarpc_int           iovlen;
    tarpc_int           flags;
};

typedef struct tarpc_int_retval_out
    tarpc_onload_delegated_send_complete_out;

struct tarpc_onload_delegated_send_cancel_in {
    struct tarpc_in_arg common;
    tarpc_int           fd;
};

typedef struct tarpc_int_retval_out
    tarpc_onload_delegated_send_cancel_out;

struct tarpc_od_send_in {
    struct tarpc_in_arg common;
    tarpc_int       fd;
    tarpc_int       flags;
    tarpc_bool      raw_send;

    struct tarpc_iovec iov<>;
    tarpc_size_t iov_len;
};

typedef struct tarpc_int_retval_out tarpc_od_send_out;

struct tarpc_send_msg_warm_flow_in {
    struct tarpc_in_arg common;

    char            func_name<>;
    tarpc_int       fd1;
    tarpc_int       fd2;
    tarpc_size_t    buf_size_min;
    tarpc_size_t    buf_size_max;
    uint32_t        time2run;
};

struct tarpc_send_msg_warm_flow_out {
    struct tarpc_out_arg    common;

    tarpc_int   retval;
    uint64_t    sent1;
    uint64_t    sent2;
};

struct tarpc_many_send_cork_in {
    struct tarpc_in_arg common;
    tarpc_int       fd;
    tarpc_int       fd_aux;
    tarpc_size_t    size_min;
    tarpc_size_t    size_max;
    tarpc_size_t    length;
    tarpc_size_t    send_num;
    tarpc_int       send_usleep;
    tarpc_bool      tcp_nodelay;
    tarpc_bool      no_trigger;
};

struct tarpc_many_send_cork_out {
    struct tarpc_out_arg    common;
    tarpc_int retval;
};

struct tarpc_onload_socket_unicast_nonaccel_in {
    struct tarpc_in_arg common;

    tarpc_int   domain; /**< TA-independent domain */
    tarpc_int   type;   /**< TA-independent socket type */
    tarpc_int   proto;  /**< TA-independent socket protocol */
};

struct tarpc_onload_socket_unicast_nonaccel_out {
    struct tarpc_out_arg common;

    tarpc_int   fd;     /**< TA-local socket */
};

struct tarpc_epoll_wait_loop_in {
    struct tarpc_in_arg       common;

    tarpc_int                 epfd;
    tarpc_int                 timeout;
};

struct tarpc_epoll_wait_loop_out {
    struct tarpc_out_arg      common;

    tarpc_int                 retval;
    /*
     * Have to use array here, or there will be failure
     * to encode out parameters in case of RCF_RPC_CALL.
     */
    struct tarpc_epoll_event  events<>;
};

struct tarpc_wait_tcp_socket_termination_in {
    struct tarpc_in_arg common;
    struct tarpc_sa     loc_addr;
    struct tarpc_sa     rem_addr;
};

struct tarpc_wait_tcp_socket_termination_out {
    struct tarpc_out_arg common;

    tarpc_int   last_state;
    tarpc_int   last_state_time;
    tarpc_int   close_time;
    tarpc_int   retval;
};

struct tarpc_get_tcp_socket_state_in {
    struct tarpc_in_arg common;
    struct tarpc_sa     loc_addr;
    struct tarpc_sa     rem_addr;
};

struct tarpc_get_tcp_socket_state_out {
    struct tarpc_out_arg common;

    tarpc_int   state;
    tarpc_bool  found;
    tarpc_int   retval;
};

enum tarpc_disconn_way {
    CLOSE,
    EXIT,
    DISCONNECT
};

struct tarpc_sendmmsg_disconnect_in {
    struct tarpc_in_arg     common;

    tarpc_int               fd;
    tarpc_int               msg_size;
    tarpc_uint              msg_len;
    tarpc_disconn_way       disconn_way;
    struct tarpc_sa         connect_to_addr;
};

struct tarpc_sendmmsg_disconnect_out {
    struct tarpc_out_arg    common;

    tarpc_int               retval;
    tarpc_int               fd;
};

struct tarpc_send_var_size_in {
    struct tarpc_in_arg common;

    tarpc_int           fd;
    tarpc_size_t        len;
    tarpc_int           flags;
    struct tarpc_sa     addr;
    tarpc_send_function send_func;
};

typedef struct tarpc_ssize_t_retval_out tarpc_send_var_size_out;

enum tarpc_recv_function {
    TARPC_RECV_FUNC_RECV = 1,
    TARPC_RECV_FUNC_RECVFROM
};

struct tarpc_recv_var_size_in {
    struct tarpc_in_arg common;

    tarpc_int           fd;
    tarpc_size_t        len;
    tarpc_int           flags;
    tarpc_recv_function recv_func;
};

typedef struct tarpc_ssize_t_retval_out tarpc_recv_var_size_out;

typedef struct tarpc_void_in tarpc_sockts_alloc_send_func_ctx_in;

struct tarpc_sockts_alloc_send_func_ctx_out {
    struct tarpc_out_arg common;
    tarpc_ptr            ctx_ptr;
};

struct tarpc_sockts_send_func_ctx_init_zc_buf_in {
    struct tarpc_in_arg common;

    tarpc_ptr ctx;
    tarpc_int fd;
    tarpc_size_t buf_size;
};

typedef struct tarpc_int_retval_out
                      tarpc_sockts_send_func_ctx_init_zc_buf_out;

struct tarpc_sockts_send_func_ctx_clean_zc_buf_in {
    struct tarpc_in_arg common;

    tarpc_ptr ctx;
    tarpc_int fd;
    tarpc_int timeout;
};

typedef struct tarpc_int_retval_out
                      tarpc_sockts_send_func_ctx_clean_zc_buf_out;

struct tarpc_connect_send_dur_time_in {
    struct tarpc_in_arg common;
    tarpc_int           threads_num;
    struct tarpc_sa     dst_addr;
    struct tarpc_sa     src_addr<>;
    uint64_t            duration;
};

struct tarpc_connect_send_dur_time_out {
    struct tarpc_out_arg            common;
    tarpc_int                       retval;
    uint64_t                        sent<>; /**< Bytes sent by each thread */
};

struct tarpc_sockts_iomux_timeout_loop_in {
    struct tarpc_in_arg common;

    iomux_func          iomux;
    tarpc_bool          oo_epoll;
    struct tarpc_pollfd fds<>;
    tarpc_int           timeout;
    tarpc_uint          n_calls;
};

typedef struct tarpc_int_retval_out tarpc_sockts_iomux_timeout_loop_out;

struct tarpc_sockts_peek_stream_receiver_in {
    struct tarpc_in_arg common;

    tarpc_int fd;
    tarpc_int time2run;
    tarpc_int time2wait;
    tarpc_pat_gen_arg gen_arg;
};

struct tarpc_sockts_peek_stream_receiver_out {
    struct tarpc_out_arg common;

    tarpc_pat_gen_arg gen_arg;
    uint64_t received;
    tarpc_int retval;
};

struct tarpc_get_stat_from_orm_json_in {
    struct tarpc_in_arg common;

    string stat_name<>;
};

struct tarpc_get_stat_from_orm_json_out {
    struct tarpc_out_arg common;

    tarpc_int stat_value;
    tarpc_int retval;
};

struct tarpc_get_n_listenq_from_orm_json_in {
    struct tarpc_in_arg common;

    struct tarpc_sa loc_addr;
};

struct tarpc_get_n_listenq_from_orm_json_out {
    struct tarpc_out_arg common;

    tarpc_int n_listenq;
    tarpc_int retval;
};

program sapits
{
    version ver0
    {
        RPC_DEF(send_traffic)
        RPC_DEF(many_send)
        RPC_DEF(many_sendto)
        RPC_DEF(many_send_num)
        RPC_DEF(close_and_accept)
        RPC_DEF(close_and_socket)
        RPC_DEF(timely_round_trip)
        RPC_DEF(round_trip_echoer)
        RPC_DEF(get_callback_list)
        RPC_DEF(nested_requests_test)
        RPC_DEF(aio_read_blk)
        RPC_DEF(aio_write_blk)
        RPC_DEF(register_callbacks)
        RPC_DEF(device_io_control_test)        
        RPC_DEF(event_select_bnb_value)
        RPC_DEF(async_select_bnb_value)
        RPC_DEF(write_at_offset_continuous)
        RPC_DEF(onload_hw_filters_limit)
        RPC_DEF(out_of_hw_filters_do)
        RPC_DEF(out_of_netifs)
        RPC_DEF(incorrect_crc_send_test)
        RPC_DEF(many_accept)
        RPC_DEF(many_connect)
        RPC_DEF(many_close)
        RPC_DEF(many_close_cache)
        RPC_DEF(many_socket)
        RPC_DEF(many_epoll_ctl_add_del)
        RPC_DEF(get_socket_from_array)
        RPC_DEF(many_recv)
        RPC_DEF(traffic_processor)
        RPC_DEF(nb_receiver_start)
        RPC_DEF(nb_receiver_stop)
        RPC_DEF(close_interrupt)
        RPC_DEF(close_sysenter)
        RPC_DEF(close_syscall)
        RPC_DEF(onload_set_stackname)
        RPC_DEF(onload_stackname_save)
        RPC_DEF(onload_stackname_restore)
        RPC_DEF(onload_move_fd)
        RPC_DEF(onload_is_present)
        RPC_DEF(onload_fd_stat)
        RPC_DEF(sighandler_createfile_cleanup)
        RPC_DEF(sighandler_createfile_exists_unlink)
        RPC_DEF(thrd_sighnd_crtfile_exists_unlink)
        RPC_DEF(sockts_alloc_zc_compl_queue)
        RPC_DEF(sockts_free_zc_compl_queue)
        RPC_DEF(sockts_proc_zc_compl_queue)
        RPC_DEF(simple_zc_send)
        RPC_DEF(simple_zc_recv)
        RPC_DEF(simple_hlrx_recv_zc)
        RPC_DEF(simple_hlrx_recv_copy)
        RPC_DEF(simple_set_recv_filter)
        RPC_DEF(onload_set_recv_filter_capture)
        RPC_DEF(sockts_recv_filtered_pkt)
        RPC_DEF(sockts_recv_filtered_pkts_clear)
        RPC_DEF(onload_zc_alloc_buffers)
        RPC_DEF(free_onload_zc_buffers)
        RPC_DEF(onload_zc_register_buffers)
        RPC_DEF(onload_zc_unregister_buffers)
        RPC_DEF(sapi_get_sizeof)
        RPC_DEF(simple_zc_recv_null)
        RPC_DEF(onload_zc_send_msg_more)
        RPC_DEF(onload_msg_template_alloc)
        RPC_DEF(onload_msg_template_abort)
        RPC_DEF(onload_msg_template_update)
        RPC_DEF(template_send)
        RPC_DEF(popen_flooder)
        RPC_DEF(popen_flooder_toggle)
        RPC_DEF(onload_ordered_epoll_wait)
        RPC_DEF(od_send)
        RPC_DEF(onload_delegated_send_prepare)
        RPC_DEF(onload_delegated_send_tcp_update)
        RPC_DEF(onload_delegated_send_tcp_advance)
        RPC_DEF(onload_delegated_send_complete)
        RPC_DEF(onload_delegated_send_cancel)
        RPC_DEF(send_msg_warm_flow)
        RPC_DEF(many_send_cork)
        RPC_DEF(onload_socket_unicast_nonaccel)
        RPC_DEF(recv_timing)
        RPC_DEF(epoll_wait_loop)
        RPC_DEF(wait_tcp_socket_termination)
        RPC_DEF(sendmmsg_disconnect)
        RPC_DEF(get_tcp_socket_state)
        RPC_DEF(send_var_size)
        RPC_DEF(recv_var_size)
        RPC_DEF(sockts_alloc_send_func_ctx)
        RPC_DEF(sockts_send_func_ctx_init_zc_buf)
        RPC_DEF(sockts_send_func_ctx_clean_zc_buf)
        RPC_DEF(connect_send_dur_time)
        RPC_DEF(sockts_iomux_timeout_loop)
        RPC_DEF(sockts_peek_stream_receiver)
        RPC_DEF(get_stat_from_orm_json)
        RPC_DEF(get_n_listenq_from_orm_json)
    } = 1;
} = 2;
