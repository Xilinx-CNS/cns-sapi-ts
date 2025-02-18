/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Definitions of functions and auxiliary structures used for I/O Multiplexing.
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 * @author Konstantin Abramenko <Konstantin.Abramenko@oktetlabs.ru>
 *
 * $Id$
 */

#include "te_config.h"

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "te_defs.h"
#include "rcf_rpc.h"
#include "te_rpc_types.h"
#include "tapi_iomux.h"

#ifndef __LIB_IOMUX_H__
#define __LIB_IOMUX_H__

/**
 * The list of values allowed for parameter of type 'tapi_iomux_type'
 */
#define IOMUX_FUNC_MAPPING_LIST \
    { "select", (int)IC_SELECT },     \
    { "pselect", (int)IC_PSELECT },   \
    { "poll", (int)IC_POLL }, \
    { "ppoll", (int)IC_PPOLL }, \
    { "epoll", (int)IC_EPOLL }, \
    { "epoll_pwait", (int)IC_EPOLL_PWAIT }, \
    { "epoll_pwait2", (int)IC_EPOLL_PWAIT2 }, \
    { "oo_epoll", (int)IC_OO_EPOLL }

/* Poll and select differ.  Let's find what kind of iomux it is. */
#define IOMUX_IS_POLL_LIKE(iomux) \
    ((iomux) == IC_POLL || (iomux) == IC_PPOLL || (iomux) == IC_EPOLL || \
     (iomux) == IC_EPOLL_PWAIT || (iomux) == IC_EPOLL_PWAIT2 || \
     (iomux) == IC_OO_EPOLL)
#define IOMUX_IS_SELECT_LIKE(iomux) \
    ((iomux) == IC_SELECT || (iomux) == IC_PSELECT)
/* Check for pselect, ppoll, epoll_pwait, epoll_pwait2. */
#define IOMUX_IS_P_IOMUX(iomux) \
    ((iomux) == IC_PSELECT || (iomux) == IC_PPOLL || \
     (iomux) == IC_EPOLL_PWAIT || (iomux) == IC_EPOLL_PWAIT2)

/**
 * Get the value of parameter of type 'tapi_iomux_type'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter of type 'tapi_iomux_type' (OUT)
 */
#define TEST_GET_IOMUX_FUNC(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, IOMUX_FUNC_MAPPING_LIST) 

/* Aliases to keep compatibility with the old code in the test suite.
 * tapi_iomux_* or sockts_iomux_* API should be used in new code. */
#define iomux_call_type     tapi_iomux_type
#define iomux_evt           tapi_iomux_evt
#define iomux_event_rpc2str tapi_iomux_event_rpc2str
#define iomux_call_en2str   sockts_iomux_call_en2str
#define iomux_call_str2en   sockts_iomux_call_str2en
#define IC_UNKNOWN          TAPI_IOMUX_UNKNOWN
#define IC_SELECT           TAPI_IOMUX_SELECT
#define IC_PSELECT          TAPI_IOMUX_PSELECT
#define IC_POLL             TAPI_IOMUX_POLL
#define IC_PPOLL            TAPI_IOMUX_PPOLL
#define IC_EPOLL            TAPI_IOMUX_EPOLL
#define IC_EPOLL_PWAIT      TAPI_IOMUX_EPOLL_PWAIT
#define IC_EPOLL_PWAIT2     TAPI_IOMUX_EPOLL_PWAIT2
#define IC_OO_EPOLL         TAPI_IOMUX_RESERVED
#define IC_DEFAULT          TAPI_IOMUX_DEFAULT

/**
 * Get default iomux function. 
 *
 * @return default iomux call. 
 */
extern tapi_iomux_type iomux_call_get_default();

/**
 * Convert string name of iomux function to enum constant, @b oo_epoll
 * is also supported by the function.
 *
 * @param iomux         name of function: "select", "pselect", or "poll".
 *
 * @return respecive value from tapi_iomux_type enum.
 */
extern tapi_iomux_type sockts_iomux_call_str2en(const char *iomux);

/**
 * Convert constant from #tapi_iomux_type to human string,
 * @b TAPI_IOMUX_OO_EPOLL is also supported by the function.
 *
 * @param iomux_type    Value to be converted
 *
 * @return static character string
 */
extern const char *sockts_iomux_call_en2str(tapi_iomux_type iomux_type);

/* Open Onload epoll is placed in TE as 'reserved'. */
#define TAPI_IOMUX_OO_EPOLL TAPI_IOMUX_RESERVED

/**
 * Structure for event request entry for iomux_call function
 */
typedef struct {
    int fd;             /**< File descriptor */
    uint16_t events;    /**< Requested events */
    uint16_t revents;   /**< Returned events */
} iomux_evt_fd;

/** 
 * Call 'iomux' function - select, pselect, poll, ppoll, epoll_wait, epoll_pwait
 * and epoll_pwait2 - with specified events, timeout and signal
 * This function does not process quantity of events greater then
 * standard system macro FD_SETSIZE.
 *
 * @param call_type     Type of function to be called
 * @param rpcs          RPC server, where the @b iomux() function is called
 * @param events        Array of event request records
 * @param n_evts        Length of @a events
 * @param timeout       Timeout of operation, may be NULL
 * @param sigmask       Signal mask, may be NULL
 *
 * @return -1 in case of incorrect input parameters or internal TE or RPC error,
 *         zero in case of timeout, or number of events occured. 
 */
extern int iomux_call_gen(iomux_call_type call_type,
                          rcf_rpc_server *rpcs,
                          iomux_evt_fd *events, size_t n_evts,
                          struct tarpc_timeval *timeout,
                          rpc_sigset_p sigmask,
                          uint64_t *duration);

static inline int iomux_call_signal(iomux_call_type call_type,
                                    rcf_rpc_server *rpcs,
                                    iomux_evt_fd *events, size_t n_evts,
                                    struct tarpc_timeval *timeout,
                                    rpc_sigset_p sigmask)
{
    return iomux_call_gen(call_type, rpcs, events, n_evts, timeout,
                          sigmask, NULL);
}

extern int iomux_call(iomux_call_type call_type,
                      rcf_rpc_server *rpcs,
                      iomux_evt_fd *events, size_t n_evts,
                      struct tarpc_timeval *timeout);

/** 
 * Call 'iomux_call' function with default 'iomux' function.
 *
 * @param rpcs          RPC server, where the @b iomux() function is called
 * @param sock          Socket for iomux function
 * @param evt           Requested events to be passed to @b iomux_call().
 * @param revt          Returned events from @b iomux_call().
 * @param timeout       Timeout in milliseconds
 *
 * @return -1 in case of incorrect input parameters or internal TE or RPC error,
 *         zero in case of timeout, or number of events occured. 
 */
extern int iomux_call_default_simple(rcf_rpc_server *rpcs, int sock,
                                     iomux_evt evt, iomux_evt *revt,
                                     int timeout);

/**
 * Timeout passed to iomux_call function
 */
typedef enum iomux_timeout_t {
    IOMUX_TIMEOUT_ZERO,     /**< Zero timeout   */
    IOMUX_TIMEOUT_RAND,     /**< Random timeout */
} iomux_timeout_t;

/**
 * Enum for iomux functions plus @b recv().
 * This enum is used in some epoll tests which need to receive input data
 * in different ways, i.e. use 'iomux' function or use 'recv()' function.
 */
typedef enum function_type_e {
    FUNCTION_TYPE_NONE = TAPI_IOMUX_UNKNOWN,
    FUNCTION_TYPE_SELECT = TAPI_IOMUX_SELECT,
    FUNCTION_TYPE_PSELECT = TAPI_IOMUX_PSELECT,
    FUNCTION_TYPE_POLL = TAPI_IOMUX_POLL,
    FUNCTION_TYPE_PPOLL = TAPI_IOMUX_PPOLL,
    FUNCTION_TYPE_EPOLL = TAPI_IOMUX_EPOLL,
    FUNCTION_TYPE_EPOLL_PWAIT = TAPI_IOMUX_EPOLL_PWAIT,
    FUNCTION_TYPE_EPOLL_PWAIT2 = TAPI_IOMUX_EPOLL_PWAIT2,
    FUNCTION_TYPE_OO_EPOLL = TAPI_IOMUX_OO_EPOLL,
    FUNCTION_TYPE_RECV
} function_type_t;

/**
 * The list of values allowed for parameter of type 'function_type_t'
 */
#define FUNCTION_TYPE_MAPPING_LIST                    \
    {"select", FUNCTION_TYPE_SELECT},                 \
    {"pselect", FUNCTION_TYPE_PSELECT},               \
    {"poll", FUNCTION_TYPE_POLL},                     \
    {"ppoll", FUNCTION_TYPE_PPOLL},                   \
    {"epoll", FUNCTION_TYPE_EPOLL},                   \
    {"epoll_pwait", FUNCTION_TYPE_EPOLL_PWAIT},       \
    {"epoll_pwait2", FUNCTION_TYPE_EPOLL_PWAIT2}, \
    {"oo_epoll", FUNCTION_TYPE_OO_EPOLL},             \
    {"recv", FUNCTION_TYPE_RECV}

/**
 * Get parameter value of 'function_type_t' type
 *
 * @param var_name_ Variable name used to get "var_name_" parameter value
 *                  of 'function_type_t' type (OUT)
 */
#define TEST_GET_FUNCTION_TYPE(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, FUNCTION_TYPE_MAPPING_LIST)

/** Enum for @p epoll_flags */
typedef enum epoll_flags_e {
    EPOLL_FLAGS_NONE = EVT_NONE,
    EPOLL_FLAGS_ET = EVT_ET,
    EPOLL_FLAGS_ONESHOT = EVT_ONESHOT
} epoll_flags_t;

/**
 * The list of values allowed for parameter of type 'epoll_flags_t'
 */
#define EPOLL_FLAGS_MAPPING_LIST        \
    {"et", EPOLL_FLAGS_ET},             \
    {"oneshot", EPOLL_FLAGS_ONESHOT},   \
    {"none", EPOLL_FLAGS_NONE}

/**
 * Get parameter value of 'epoll_flags_t' type
 *
 * @param var_name_ Variable name used to get "var_name_" parameter value
 *                  of 'epoll_flags_t' type (OUT)
 */
#define TEST_GET_EPOLL_FLAGS(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, EPOLL_FLAGS_MAPPING_LIST)

/**
 * The same as iomux_write_while_writable(), but it consequently
 * fills send buffer and returns total bytes sent.
 *
 * @param rpcs      RPC server handle
 * @param sock      socket
 * @param iomux     I/O multiplexing function
 * @param ts        total bytes sent
 *
 * @retval 0        Success.
 * @retval -1       Failure.
 */
extern int iomux_fill_io_buffers(rcf_rpc_server *rpcs, int sock,
                                 iomux_call_type iomux, ssize_t *ts);
/**
 * This function is used in a group of tests from I/O Multiplexing package
 * to help implementing them.
 * 
 * The function does the following steps:
 * -# If @p fill_buffer parameter is @c TRUE, the function fills in recieve 
 *    buffer of @p tst_s socket and transmit buffer of @p iut_s socket, so 
 *    that @p iut_s socket becomes "not writable";
 * -# Call @b iomux() function waiting for user specified events, passed
 *    in @p events parameter. Timeout is chosen as a random value if 
 *    @p iomux_timeval equals to @c IOMUX_TIMEOUT_RAND, otherwise 
 *    (@p iomux_timeout = @c IOMUX_TIMEOUT_ZERO) it is set to zero;
 * -# If @p how parameter is not equal to RPC_SHUT_NONE imediately after
 *    calling @b iomux() function @b shutdown(@p tst_s, @p how) function 
 *    is called;
 * -# If all steps are passed function writes the return value of @b 
 *    iomux() function to @p iomux_ret_val parameter. Than it writes type of 
 *    returned events to @p events parameter;
 *
 * 
 * @param iomux          Name of @b iomux() function (@b select(), @b 
 *                       pselect() or @b poll())
 * @param iut            PCO, where the @b iomux() function is called.
 * @param iut_s          Descriptor of the socket on which @b iomux()
 *                       function is called (located at @p iut)
 * @param events         On IN events we want @b iomux() function to wait for.
 *                       On OUT events, returned by @b iomux() function (IN/OUT)
 *                       Possible values:
 *                        - @c EVT_NONE
 *                        - @c EVT_RD
 *                        - @c EVT_WR
 *                        - @c EVT_RDWR
 * @param timeout        Type of timeout with which @b iomux() function 
 *                       should be called. Possible values:
 *                        - @c IOMUX_TIMEOUT_ZERO
 *                        - @c IOMUX_TIMEOUT_RAND
 * @param fill_buffer    If @c TRUE, function makes @p iut_s socket 
 *                       "not writable"
 * @param tst            PCO, where @b shutdown() function is called
 * @param tst_s          Descriptor of the socket on which @b shutdown()
 *                       function is called (located at @p tst)
 * @param how            This parameter is passed to @b shutdown() function
 *                       Possible values:
 *                        - RPC_SHUT_NONE - @b shutdown() function isn't called
 *                        - RPC_SHUT_RD
 *                        - RPC_SHUT_WR
 *                        - RPC_SHUT_RDWR
 * @param iomux_ret_val  In this parameter function writes the return value of 
 *                       @b iomux() function (OUT)
 * @return                0 - all steps are passed successfully
 *                       -1 - otherwise
 * */

extern int
iomux_common_steps(iomux_call_type iomux, rcf_rpc_server *iut, int iut_s,
           iomux_evt *events, iomux_timeout_t timeout,
           te_bool fill_buffer, rcf_rpc_server *tst, int tst_s,
           rpc_shut_how how, int *iomux_ret_val);

/* Call epoll_wait(), epoll_pwait() or epoll_pwait2() function. All
 * arguments as in epoll_wait() function.
 */
extern int
iomux_epoll_call(iomux_call_type call_type, rcf_rpc_server *rpcs, int epfd,
                 struct rpc_epoll_event *events, int maxevents,
                 int timeout);

/** This structure describes state of current working session */
typedef struct iomux_state {
    rpc_fd_set_p    read_fds;     /**< Set of fds to be read */
    rpc_fd_set_p    write_fds;    /**< Set of fds to be write */
    rpc_fd_set_p    exc_fds;      /**< Set of fds on which exception
                                       occured */
    rcf_rpc_server *srv_current;  /**< Current RPC server */

    struct rpc_pollfd       poll_fd_array[FD_SETSIZE];   /**< Array of
                                                              poll()
                                                              fds */
    /* TODO: FD_SETSIZE is constant for poll(). Substitute it by correct
     * constant for epoll().*/
    struct rpc_epoll_event  epoll_evt_array[FD_SETSIZE]; /**< Array of
                                                              epoll()
                                                              events */

    /* Descriptor that is used by iomux_call() function in case of IC_EPOLL.
     * This descriptor is nessesary when someone calls iomux_call() with
     * RCF_RPC_WAIT, because the descriptor created by epoll_create() in
     * RCF_RPC_CALL call of this function should be used by epoll_wait() in
     * RCF_RPC_WAIT call.
     */
    int                     epfd;                        /**< Epoll fd */
    rpc_sigset_p            iomux_call_sigmask;          /**< Sigmask of
                                                              iomux call */
} iomux_state;

/** Function to change current state pointer.
 *
 *  @param      new_state     New current state pointer
 *
 *  @return     State pointer before this change 
 */
extern iomux_state *iomux_switch_state(iomux_state *new_state);

/**
 * Check that iomux fucmtion returns zero.
 * 
 * @param _x    Iomux function call
 */
#define IOMUX_CHECK_ZERO(_x) \
do {                                                                \
    static te_bool _reported = FALSE;                               \
    if (!_reported && (_x) != 0)                                    \
    {                                                               \
        ERROR_VERDICT("Iomux function returned non-zero value");    \
        _reported = TRUE;                                           \
    }                                                               \
} while (0)

/**
 * Check an iomux call return code and event.
 * 
 * @param _exp_rc   Expected return code
 * @param _exp      Expected events
 * @param _ev       The event context
 * @param _x        Iomux function call
 */
#define IOMUX_CHECK_EXP(_exp_rc, _exp, _ev, _x) \
do {                                                                \
    static te_bool _reported = FALSE;                               \
    if ((_x) != _exp_rc && !_reported)                              \
    {                                                               \
        ERROR_VERDICT("Iomux function returned unexpected value");  \
        _reported = TRUE;                                           \
    }                                                               \
    else if (!_reported && (_ev).revents != _exp)                   \
    {                                                               \
        ERROR_VERDICT("Iomux function returned unexpected events"); \
        _reported = TRUE;                                           \
    }                                                               \
} while (0)

/**
 * Check an iomux return code and event for one fd. Note, the macro reports
 * a verdict and jumps to cleanup in case of fail.
 *
 * @param _rc       Iomux return code.
 * @param _rc_exp   Expected return code.
 * @param _evts     Pointer to returned events.
 * @param _exp      Expected events value.
 * @param _msg_tail Extra message to be added in the tail of the verdict.
 */
#define SOCKTS_CHECK_IOMUX_EVENTS(_rc, _rc_exp, _evts, _exp, _msg_tail) \
    do {                                                                \
        if (_rc != _rc_exp)                                             \
            TEST_VERDICT("Iomux returned unexpected code %d "           \
                         "instead of %d%s", _rc, _rc_exp, _msg_tail);   \
        if ((_evts)->revents != _exp)                                   \
            TEST_VERDICT("Unexpected events %s instead of %s%s",        \
                         tapi_iomux_event_rpc2str((_evts)->revents),    \
                         tapi_iomux_event_rpc2str(_exp), _msg_tail);    \
    } while (0)

/**
 * Initialize @p event to expect (RD | PRI) event and return expected
 * events in accordance to iomux function type.
 * 
 * @param event             Initialized events context
 * @param iut_s             Socket expecting the event, note it should be
 *                          initialized
 * @param iomux             I/O multiplexing function type
 * @param select_err_queue  If socket option SO_SELECT_ERR_QUEUE is set
 * @param rc                Expected return code or @c NULL
 * 
 * @return Expected events.
 */
extern int iomux_init_rd_error(iomux_evt_fd *event, int iut_s,
                               iomux_call_type iomux,
                               te_bool select_err_queue, int *rc);

/**
 * Create a multiplexer. This call expands @c tapi_iomux_create() supporting
 * Onload ordered epoll type @c TAPI_IOMUX_OO_EPOLL.
 *
 * @note See also the description of TE function @c tapi_iomux_create().
 *
 * @param rpcs  RPC server handle.
 * @param type  The multiplexer type.
 *
 * @return The multiplexer handle.
 */
extern tapi_iomux_handle * sockts_iomux_create(rcf_rpc_server *rpcs,
                                               tapi_iomux_type type);

#endif
