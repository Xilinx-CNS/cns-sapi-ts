/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Enhanced functions for CSAPs for multicast package.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_MCAST_LIB_H__
#define __TS_MCAST_LIB_H__

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_ip4.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Structure describing listener state */
typedef struct mcast_listener_struct {
    csap_handle_t   listener_handle;  /**< CSAP handle */
    in_addr_t       src_addr;         /**< Source address */
    in_addr_t       dst_addr;         /**< Destination address */
    int             use_src;          /**< Use source address to determine
                                           whether captured packets are
                                           proper ones or not */
    int             packets_received; /**< Number of received multicast
                                           packets */
} *mcast_listener_t;

/**
 * Create IP4 CSAP and store destination and source address for
 * mcast_listen_stop() function.
 *
 * @param rpcs         RPC server
 * @param interface    Interface to listen on
 * @param dst_addr     Destination address of packets which listener will
 *                     try to catch
 * @param src_addr     Source address of packets which listener will
 *                     try to catch
 * @param in           Catch incoming or outgoing packets
 *
 * @return Created IP4 CSAP on success. Jumps to cleanup on failure.
 */
extern mcast_listener_t mcast_listener_init(rcf_rpc_server *rpcs,
                                        const struct if_nameindex *iterface,
                                        const struct sockaddr *dst_addr,
                                        const struct sockaddr *src_addr,
                                        int in);

/**
 * Start recieving operation on IP4 CSAP.
 *
 * @param rpcs         RPC server
 * @param listener     IP4 CSAP
 */
extern void mcast_listen_start(rcf_rpc_server *rpcs,
                               mcast_listener_t listener);

/**
 * Stop recieving operation on IP4 CSAP.
 *
 * @param rpcs         RPC server
 * @param listener     IP4 CSAP
 * @param cb_data      Callback for tapi_tad_trrecv_stop() function. In
 *                     case of NULL default callback is uses. Default
 *                     callback counts number of packets with dst_addr and
 *                     src_addr which were defined by mcast_listener_init()
 *                     function.
 *
 * @return Number of cathed packets or -1 in case of failure.
 */
extern int mcast_listen_stop(rcf_rpc_server *rpcs,
                             mcast_listener_t listener,
                             tapi_tad_trrecv_cb_data *cb_data);

/**
 * Destroy IP4 CSAP.
 *
 * @param rpcs         RPC server
 * @param listener     IP4 CSAP
 */
extern void mcast_listener_fini(rcf_rpc_server *rpcs,
                                mcast_listener_t listener);

/**
 * Recieve data packet with help of @b onload_zc_recv().
 *
 * @param pco_          RPC server
 * @param s_            Socket
 * @param buf_          Buffer for received data
 * @param flags_        Flags
 * @param peer_addr_    Buffer to store address of peer
 * @param peer_addrlen_ Bufer to store length of peer address
 * @param check_detect_ Check whether data was processed by system
 *                      or not
 * @param detected_     Set to TRUE if received data was processed by
 *                      system
 * @param verd_txt_     Text of verdict about discovering the fact
 *                      that data was processed by system
 */
#define RECV_VIA_ZC(pco_, s_, buf_, len_, flags_, \
                    peer_addr_, peer_addrlen_, \
                    check_detect_, detected_, check_notempty_err_, \
                    verd_txt_...) \
    do {                                                            \
            rpc_msghdr          msg_;                               \
            struct rpc_iovec    vector_;                            \
                                                                    \
            memset(&msg_, 0, sizeof(msg_));                         \
            vector_.iov_base = buf_;                                \
            vector_.iov_len = vector_.iov_rlen = len_;              \
            msg_.msg_iov = &vector_;                                \
            msg_.msg_iovlen = msg_.msg_riovlen = 1;                 \
            if (ptr_is_not_null(peer_addr_) &&                      \
                ptr_is_not_null(peer_addrlen_))                     \
            {                                                       \
                msg_.msg_name = SA(peer_addr_);                     \
                msg_.msg_namelen = msg_.msg_rnamelen =              \
                                       *((int *)peer_addrlen_);     \
            }                                                       \
            if (check_detect_)                                      \
            {                                                       \
                RPC_AWAIT_IUT_ERROR(pco_);                          \
                rc = rpc_simple_zc_recv_acc(pco_, s_, &msg_,        \
                                            flags_);                \
                if (rc < 0 && RPC_ERRNO(pco_) != RPC_EAGAIN)        \
                {                                                   \
                    if (check_notempty_err_)                        \
                        CHECK_RPC_ERRNO(pco_, RPC_ENOTEMPTY,        \
                                        "onload_zc_recv() returns " \
                                        "%d, but", rc);             \
                                                                    \
                    if (RPC_ERRNO(pco_) == RPC_ENOTEMPTY)           \
                    {                                               \
                        rc = rpc_simple_zc_recv(pco_, s_, &msg_,    \
                                                flags_);            \
                        if (rc > 0)                                 \
                        {                                           \
                            if (ptr_is_not_null(detected_) &&       \
                                !(*((te_bool *)detected_)))         \
                                *(te_bool *)detected_ = TRUE;       \
                                                                    \
                            RING_VERDICT(verd_txt_);                \
                        }                                           \
                    }                                               \
                }                                                   \
            }                                                       \
            else                                                    \
                rc = rpc_simple_zc_recv(pco_, s_, &msg_, flags_);   \
                                                                    \
            if (ptr_is_not_null(peer_addrlen_))                     \
                *((int *)peer_addrlen_) = msg_.msg_namelen;         \
    } while (0)

/**
 * Receive data and check for correctness; collect error messages in
 * specified array.
 *
 * @param failed_       Set this variable to @c TRUE is something
 *                      is wrong
 * @param msgs_         Array of error messages
 * @param max_msg_len_  Maximum length of error message
 * @param max_msg_num_  Maximum number of error messages
 * @param msg_n_        Current message number
 * @param pco_          RPC server
 * @param s_            Socket
 * @param rx_buf_       Receiving buffer
 * @param tx_buf_       Sending buffer
 * @param buf_len_      Buffers length
 */
#define RECV_AND_CHECK(failed_, msgs_, max_msg_len_, max_msg_num_, \
                       msg_n_, pco_, s_, rx_buf_, \
                       tx_buf_, buf_len_) \
    do {                                                    \
        RPC_AWAIT_IUT_ERROR(pco_);                          \
        rc = rpc_recv(pco_, (s_), rx_buf_, buf_len_, 0);    \
        if (rc < 0)                                         \
        {                                                   \
            if (msg_n_ == max_msg_num_)                     \
                TEST_FAIL("Too many error messages");       \
            snprintf(msgs_[msg_n_++], max_msg_len_,         \
                     "Trying to receive data on %s "        \
                     "resulted in %s", #s_,                 \
                     errno_rpc2str(RPC_ERRNO(pco_)));       \
            ERROR(msgs_[msg_n_ - 1]);                       \
            failed_ = TRUE;                                 \
        }                                                   \
        else if (rc == 0)                                   \
        {                                                   \
            if (msg_n_ == max_msg_num_)                     \
                TEST_FAIL("Too many error messages");       \
            snprintf(msgs_[msg_n_++], max_msg_len_,         \
                     "Nothing was actually "                \
                     "received on %s", #s_);                \
            ERROR(msgs_[msg_n_ - 1]);                       \
            failed_ = TRUE;                                 \
        }                                                   \
        else if (rc != (int)buf_len_)                       \
        {                                                   \
            if (msg_n_ == max_msg_num_)                     \
                TEST_FAIL("Too many error messages");       \
            snprintf(msgs_[msg_n_++], max_msg_len_,         \
                     "Data of unexpected length "           \
                     "was received on %s", #s_);            \
            ERROR(msgs_[msg_n_ - 1]);                       \
            failed_ = TRUE;                                 \
        }                                                   \
        else if (memcmp(tx_buf_, rx_buf_, buf_len_) != 0)   \
        {                                                   \
            if (msg_n_ == max_msg_num_)                     \
                TEST_FAIL("Too many error messages");       \
            snprintf(msgs_[msg_n_++], max_msg_len_,         \
                     "Incorrect data was received "         \
                     "on %s", #s_);                         \
            ERROR(msgs_[msg_n_ - 1]);                       \
            failed_ = TRUE;                                 \
        }                                                   \
    } while (0)

/**
 * Define and initialize variables used to collect per packet
 * error messages.
 *
 * @param pref_       Variable prefix
 */
#define MSGS_INIT(pref_) \
    char             ***pref_ ## msgs;                          \
    int                 pref_ ## msg_n = 0;                     \
    int                *pref_ ## msgs_show;                     \
    char                pref_ ## msg[MAX_MSG_LEN];              \
                                                                \
    pref_ ## msgs =                                             \
            TE_ALLOC(packet_number * sizeof(char **));          \
    pref_ ## msgs_show =                                        \
                TE_ALLOC(packet_number * sizeof(int));          \
    do {                                                        \
        int i_;                                                 \
        int j_;                                                 \
        for (i_ = 0; i_ < packet_number; i_++)                  \
        {                                                       \
            pref_ ## msgs[i_] =                                 \
                      TE_ALLOC(MAX_MSG_NUM * sizeof(char *));   \
            for (j_ = 0; j_ < MAX_MSG_NUM; j_++)                \
                pref_ ## msgs[i_][j_] = TE_ALLOC(MAX_MSG_LEN *  \
                                               sizeof(char));   \
        }                                                       \
    } while (0)

/**
 * Free variables used to collect per packet error messages.
 *
 * @param pref_       Variable prefix
 */
#define MSGS_FREE(pref_) \
    do {                                        \
        int i_;                                 \
        int j_;                                 \
        for (i_ = 0; i_ < packet_number; i_++)  \
        {                                       \
            for (j_ = 0; j_ < MAX_MSG_NUM;      \
                 j_++)                          \
                free(pref_ ## msgs[i_][j_]);    \
            free(pref_ ## msgs[i_]);            \
        }                                       \
        free(pref_ ## msgs);                    \
        free(pref_ ## msgs_show);               \
    } while (0)

/**
 * Print collected per packet error messages as verdicts.
 *
 * @param pref_       Variable prefix
 */
#define MSGS_PRINT_VERDICTS(pref_) \
    do {                                                            \
        int i_;                                                     \
        int j_;                                                     \
        int k_;                                                     \
        for (i_ = 0; i_ < packet_number - 1; i_++)                  \
        {                                                           \
            if (pref_ ## msgs_show[i_] == -1)                       \
                continue;                                           \
                                                                    \
            snprintf(pref_ ## msg, MAX_MSG_LEN,                     \
                     "Packet(s) %d", i_ + 1);                       \
            for (j_ = i_ + 1; j_ < packet_number; j_++)             \
            {                                                       \
                for (k_ = 0; k_ < MAX_MSG_NUM; k_++)                \
                    if (strcmp(pref_ ## msgs[i_][k_],               \
                               pref_ ## msgs[j_][k_]) != 0)         \
                        break;                                      \
                if (k_ == MAX_MSG_NUM)                              \
                {                                                   \
                    snprintf(pref_ ## msg + strlen(pref_ ## msg),   \
                             MAX_MSG_LEN - strlen(pref_ ## msg),    \
                             ",%d", j_ + 1);                        \
                    pref_ ## msgs_show[j_] = -1;                    \
                }                                                   \
            }                                                       \
                                                                    \
            for (k_ = 0; k_ < MAX_MSG_NUM; k_++)                    \
            {                                                       \
                if (strlen(pref_ ## msgs[i_][k_]) == 0)             \
                    break;                                          \
                                                                    \
                ERROR_VERDICT("%s: %s", pref_ ## msg,               \
                              pref_ ## msgs[i_][k_]);               \
            }                                                       \
        }                                                           \
    } while (0)

/**
 * Create UDP socket, bind it and join to multicast group.
 * 
 * @param rpcs       RPC server
 * @param iface      Intreface context
 * @param bind_addr  Local address to bind
 * @param mcast_addr Multicast address to join
 * @param method     How to join to multicast group
 * 
 * @return Socket desriptor
 */
extern int create_joined_socket(rcf_rpc_server *rpcs,
                                const struct if_nameindex *iface,
                                const struct sockaddr *bind_addr,
                                const struct sockaddr *mcast_addr,
                                tarpc_joining_method method);

/**
 * Create UDP socket, bind it and join to multicast group.
 *
 * @param sock_func  Function to use for socket creation
 * @param rpcs       RPC server
 * @param iface      Intreface context
 * @param bind_addr  Local address to bind
 * @param mcast_addr Multicast address to join
 * @param method     How to join to multicast group
 *
 * @return Socket desriptor
 */
extern int create_joined_socket_ext(sockts_socket_func sock_func,
                                    rcf_rpc_server *rpcs,
                                    const struct if_nameindex *iface,
                                    const struct sockaddr *bind_addr,
                                    const struct sockaddr *mcast_addr,
                                    tarpc_joining_method method);

/**
 * Check readability and read packet if it's allowed.
 * 
 * @param rpcs      RPC server
 * @param sock      Socket
 * @param sendbuf   Buffer with transmitted data to compair with
 * @param buflen    @p sendbuf length
 * 
 * @return @c TRUE if socket is readable
 */
extern int read_check_pkt(rcf_rpc_server *rpcs, int sock, char *sendbuf,
                          int buflen);

/** 
 * Structure to keep expected and actual obtained results.
 */
typedef struct cmp_results_type {
    te_bool exp;    /**< Expected result */
    te_bool got;    /**< Has packet been gotten? */
} cmp_results_type;

/**
 * Compair packet reading result with expected and generate verdict if it's
 * necessary.
 * 
 * @param res       Expected value and actual obtained result
 * @param receiver  Receiver name
 */
extern void cmp_exp_results(cmp_results_type *res, const char *receiver);


/**
 * Check multicast hash collision on an interface.
 * This function is a wrapper over check_multicast_hash_collision()
 * which does not require existing Tester socket, as it creates it itself.
 *
 * @param rpcs_iut     RPC server on IUT
 * @param rpcs_tst     RPC server on tester
 * @param interface    Interface to check
 * @param tst_addr     Address on a Tester interface
 *                     from which to send a packet
 * @param mcast_addr   Multicast address
 *
 * @return @c TRUE if hash collision was detected, @c FALSE otherwise.
 *
 * @note Jumps to cleanup on failure.
 */
extern te_bool check_mcast_hash_collision_create_sock(
    rcf_rpc_server *rpcs_iut, rcf_rpc_server *rpcs_tst,
    const struct if_nameindex *interface, const struct sockaddr *tst_addr,
    const struct sockaddr *mcast_addr);

/**
 * Check multicast hash collision on particular interface.
 * The function tries to catch multicast packets by CSAP,
 * if it succeeds, it means the filter is already set to receive
 * packets with the given mcast address.
 *
 * @param rpcs_iut     RPC server on IUT
 * @param rpcs_tst     RPC server on tester
 * @param interface    Interface to check
 * @param sock         Socket on @p rpcs_tst to send data for checking
 * @param mcast_addr   Multicast address
 *
 * @return @c TRUE if hash collision was detected, @c FALSE otherwise.
 *
 * @note Jumps to cleanup on failure.
 */
extern te_bool check_mcast_hash_collision(rcf_rpc_server *rpcs_iut,
                                          rcf_rpc_server *rpcs_tst,
                                          const struct if_nameindex *interface,
                                          int sock,
                                          const struct sockaddr *mcast_addr);

/**
 * Wrapper over check_mcast_hash_collision() which calls this function
 * only if the interface belongs to IUT network in environment. Should be
 * used only from main(); @p interface_ should be the variable used
 * in TEST_GET_IF().
 */
#define CHECK_MCAST_HASH_COLLISION(rpcs_iut_, rpcs_tst_, interface_, \
                                   sock_, mcast_addr_) \
    do {                                                                  \
        if (sockts_iface_is_iut(&env, #interface_))                       \
        {                                                                 \
            check_mcast_hash_collision(rpcs_iut_, rpcs_tst_, interface_,  \
                                       sock_, mcast_addr_);               \
        }                                                                 \
        else                                                              \
        {                                                                 \
            RING("Interface %s is not IUT, do not check for multicast "   \
                 "hash collision on it", interface_->if_name);            \
        }                                                                 \
    } while (0)

/**
 * Wrapper over check_mcast_hash_collision_create_sock() which calls this
 * function only if the interface belongs to IUT network in environment.
 * Should be used only from main(); @p interface_ should be the variable
 * used in TEST_GET_IF().
 */
#define CHECK_MCAST_HASH_COLLISION_CREATE_SOCK(rpcs_iut_, rpcs_tst_, \
                                               interface_, \
                                               tst_addr_, mcast_addr_) \
    do {                                                                  \
        if (sockts_iface_is_iut(&env, #interface_))                       \
        {                                                                 \
            check_mcast_hash_collision_create_sock(rpcs_iut_, rpcs_tst_,  \
                                                   interface_,            \
                                                   tst_addr_,             \
                                                   mcast_addr_);          \
        }                                                                 \
        else                                                              \
        {                                                                 \
            RING("Interface %s is not IUT, do not check for multicast "   \
                 "hash collision on it", interface_->if_name);            \
        }                                                                 \
    } while (0)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_MCAST_LIB_H__ */
