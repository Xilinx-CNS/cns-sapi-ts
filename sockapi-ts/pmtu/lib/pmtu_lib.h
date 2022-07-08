/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * ced functions for creation and releasing of vectors.
 *
 * @author Alexander Kukuta <Alexander.Kukuta@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_PMTU_LIB_H__
#define __TS_PMTU_LIB_H__

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <pcap-bpf.h>
#include <pcap.h>

#include "te_stdint.h"
#include "te_errno.h"
#include "rcf_api.h"
#include "logger_api.h"

#include "conf_api.h"

#include "te_defs.h"
#include "rcf_api.h"
#include "tapi_rpc.h"
#include "ndn_pcap.h"
#include "tad_common.h"

#include "tapi_tad.h"
#include "tapi_eth.h"
#include "tapi_tcp.h"
#include "tapi_udp.h"
#include "tapi_rpc.h"
#include "tapi_pcap.h"

#include "sockapi-test.h"
#include "tapi_test.h"


#ifdef __cplusplus
extern "C" {
#endif

/** Path for file placing on Test Agent side */
#define TA_TMP_PATH     "/tmp/"

/** Path for file placing on Test Engine side */
#define TST_TMP_PATH    getenv("TE_TMP")

/** Timeout for read to be set via SO_RCVTIMEO */
#define PMTU_RECV_TIMEOUT           5
/** How may times timeout is allowed */
#define PMTU_RECV_RETRIES_MAX       12


/**
 * Add route on TA via the gateway.
 *
 * @param ta_           Test Agent
 * @param family_       Address family
 * @param dst_addr_     Destination address
 * @param pfx_len_      Prefix length
 * @param gw_addr_      Gateway address
 */
#define PMTU_ADD_ROUTE(ta_, family_, dst_addr_, pfx_len_, gw_addr_) \
    do {                                                            \
        VERB("PMTU_ADD_ROUTE(%s, %s, %s)", ta_,                     \
            #dst_addr_, #gw_addr_);                                 \
        if (tapi_cfg_add_route_via_gw((ta_),                        \
                addr_family_rpc2h(family_),                         \
                te_sockaddr_get_netaddr(dst_addr_), pfx_len_,       \
                te_sockaddr_get_netaddr(gw_addr_)) != 0)            \
        {                                                           \
            TEST_FAIL("Cannot add route on %s", (ta_));             \
        }                                                           \
    } while (0)


/**
 * Set MTU on the TA to new value
 *
 * @param ta_           Test Agent
 * @param ifname_       Network Interface name to set MTU on
 * @param mtu_          New MTU value to be set
 */
#define PMTU_SET_MTU(ta_, ifname_, mtu_) \
    do                                                              \
    {                                                               \
        VERB("PMTU_SET_MTU(%s, %s, %d)", ta_, ifname_, mtu_);       \
                                                                    \
        rc = cfg_set_instance_fmt(CFG_VAL(INTEGER, mtu_),           \
                                  "/agent:%s/interface:%s/mtu:",    \
                                   (ta_), (ifname_));               \
        if (rc != 0)                                                \
        {                                                           \
            TEST_FAIL("Failed to set new MTU of %s: %X",            \
                      (ifname_), rc);                               \
        }                                                           \
    } while (0)

/**
 * Get MTU value on the TA
 *
 * @param ta_           Test Agent
 * @param ifname_       Network Interface name to get MTU on
 * @param mtu_          Returned MTU value
 */
#define PMTU_GET_MTU(ta_, ifname_, mtu_) \
    do                                                              \
    {                                                               \
        cfg_val_type type = CVT_INTEGER;                            \
                                                                    \
        rc = cfg_get_instance_fmt(&type, (void *)(mtu_),            \
                                  "/agent:%s/interface:%s/mtu:",    \
                                   (ta_), (ifname_));               \
        if (rc != 0)                                                \
        {                                                           \
            TEST_FAIL("Failed to set new MTU of %s: %X",            \
                      (ifname_), rc);                               \
        }                                                           \
                                                                    \
        VERB("PMTU_GET_MTU(%s, %s) = %d", ta_,                      \
             ifname_, *(int *)(mtu_));                              \
    } while (0)

/**
 * Set MTU value on the TA to new value and check that it is set correctly
 *
 * @param ta_           Test Agent
 * @param ifname_       Network Interface name to set MTU on
 * @param mtu_          New MTU value to be set
 */
#define PMTU_SET_CHECK_MTU(ta_, ifname_, mtu_) \
    do {                                                            \
        int assigned_mtu;                                           \
        PMTU_SET_MTU((ta_), (ifname_), (mtu_));                     \
        PMTU_GET_MTU((ta_), (ifname_), &assigned_mtu);              \
        if ((mtu_) != assigned_mtu)                                 \
        {                                                           \
            TEST_FAIL("Retrieved MTU value %d is not the same "     \
                      "as desired %d", assigned_mtu, (mtu_));       \
        }                                                           \
    } while (0)


/**
 * Type of PMTU sending scenario sequence entry
 */
typedef enum {
    PMTU_SEND_DATA_TYPE_NONE = 0,   /**< Uninitialized entry */
    PMTU_SEND_DATA_TYPE_SLEEP,      /**< Sleeping entry */
    PMTU_SEND_DATA_TYPE_SEND,       /**< Send entry */
    PMTU_SEND_DATA_TYPE_SENDFILE,   /**< Sendfile entry */
    PMTU_SEND_DATA_TYPE_WRITE,      /**< Write entry */
    PMTU_SEND_DATA_TYPE_WRITEV,     /**< WriteV entry */
    PMTU_SEND_DATA_TYPE_INVALID,    /**< Invalid entry */
} pmtu_send_data_t;

#if 1
/**
 * PMTU ICMP message structure
 */
typedef struct pmtu_icmp_message_s {
    int      icmp_len;      /**< Length of the ICMP packet */
    uint8_t *icmp_buf;      /**< ICMP packet data */

    int      next_hop_mtu;  /**< Next hop MTU value */

#if 0
    uint16_t src_port;      /**< Source port */
    uint16_t dst_port;      /**< Destination port */
#endif
} pmtu_icmp_message_t;
#endif

/**
 * PMTU sending scenario sequence entry structure
 */
typedef struct pmtu_send_seq_entry_s {
    pmtu_send_data_t        data_type;  /**< Type of data to send
                                             (send/sendfile/write/writev) */
    int                     count;      /**< Total size of data to send */
    union {
        uint8_t            *buf;        /**< Buffer for send()/write() operations */
        char               *fname;      /**< Filename for sendfile() operation */
        struct rpc_iovec   *vector;     /**< IO vector for writev() operation */
    }                       data;       /**< Union containing data to send */
    te_bool                 sys_call;   /**< Force using of system call instead of
                                             default call */
} pmtu_send_seq_entry_t;

struct pmtu_send_scenario_s;

/**
 * PMTU sending scenario sequence structure
 */
typedef struct pmtu_send_seq_s {
    struct pmtu_send_scenario_s *scenario; /**< Sending scenario that includes
                                                this sending sequence */
    int                    s_id;           /**< Sequence Id */

    int                    size;           /**< Sending sequence length */
    pmtu_send_seq_entry_t *entries;        /**< Sending sequence payload */

    int volatile           bytes_received; /**< Total amounts of bytes already
                                                received in the sequence */
    int volatile           bytes_sent;     /**< Total amounts of bytes already
                                                sent in the sequence */
    int volatile           bytes_total;    /**< Total amounts of bytes to be
                                                sent/received in the sequence */

    pthread_t              thread;         /**< Sending thread  */

    int                    src_sock;       /**< Socket on the sending side */
    rcf_rpc_server        *pco_src_dup;    /**< RPC server specially for
                                                sending data */
} pmtu_send_seq_t;

/**
 * PMTU sending scenario structure
 */
typedef struct pmtu_send_scenario_s {
    int                 size;           /**< Amount of sending sequences
                                             in the scenario */
    pmtu_send_seq_t    *seqs;           /**< Array of sending sequences */

    te_bool volatile    error_occured;  /**< Sending scenario error happened */

    int volatile        bytes_received; /**< Total amounts of bytes already
                                             received in the scenario */
    int volatile        bytes_sent;     /**< Total amounts of bytes already
                                             sent in the scenario */
    int volatile        bytes_total;    /**< Total amounts of bytes to be
                                             sent/received in the scenario */
    int volatile        seqs_started;   /**< Total amounts of sequences that are
                                             already filling send/recv buffers
                                             of the connection */
    int volatile        seqs_finished;  /**< Total amounts of sequences that are
                                             already finished sending data via
                                             the connection */
    uint8_t            *rx_data;        /**< Receive buffer used by the
                                             receiving thread for verification
                                             of the received data */
    int                 rx_data_len;    /**< Actual size of data to verify
                                             in the receive buffer */
    rcf_rpc_server     *pco_src;        /**< RPC server on the sending side */
    rcf_rpc_server     *pco_dst;        /**< RPC server on the receiving side */

    int                 src_sock;       /**< Socket on the sending side */
    int                 dst_sock;       /**< Socket on the receiving side */
    
    rpc_fd_set_p        readfds;        /**< Read fd_set */

#if 1
    pmtu_icmp_message_t icmp_message;   /**< ICMP message used
                                             for some PMTU tests */
#endif
} pmtu_send_scenario_t;

/**
 * Parse MTU change string (due to tester limitation MTU is a string parameter).
 *
 * @param mtu_param             MTU parameter string
 * @param mtu_start             MTU on start of sending data
 * @param mtu_finish            MTU on finish of sending data
 */
extern void pmtu_parse_mtu_param(const char *mtu_param,
                                int *mtu_start, int *mtu_finish);

/**
 * Parse MTU change sequence string
 * (due to tester limitation MTU is a string parameter).
 *
 * @param mtu_param             MTU parameter string
 * @param mtu_seq               Location for sequence of MTU values
 * @param mtu_seq_size          Length of MTU values sequence
 *
 * @return status code
 */
extern int pmtu_parse_mtu_sequence_param(const char *mtu_param,
                                         int **mtu_seq, int *mtu_seq_size);

/**
 * Parse scenario description from test parameter of type string.
 *
 * @param param                 Scenario description
 * @param scenario              Sending scenario
 */
extern void pmtu_parse_send_scenario_params(const char *param,
                                           pmtu_send_scenario_t *scenario);

/**
 * Prepare data for sending scenario. Allocate buffers and
 * fill them with pattern.
 *
 * @param scenario              Sending scenario
 */
extern void pmtu_prepare_send_scenario_data(pmtu_send_scenario_t *scenario);

/**
 * Release data allocated for sending scenario.
 *
 * @param scenario              Sending scenario
 */
extern void pmtu_release_send_scenario_data(pmtu_send_scenario_t *scenario);

/**
 * Start sending scenario. Spawn additional sending threads on Tester and
 * RPC servers on Test Agents per each sending sequence.
 *
 * @param scenario              Sending scenario
 */
extern void pmtu_start_send_scenario(pmtu_send_scenario_t *scenario);

/**
 * Receive part of data on the receiving side.
 * Check data consistency (independently per sending sequence).
 *
 * @param scenario              Sending scenario
 * @param retries               Number of retries already done
 *
 * @return status code
 */
extern int pmtu_recv_data(pmtu_send_scenario_t *scenario, int *retries);

#if 1

/**
 * Wait for "ICMP ERROR: Need Frag" message.
 * Check data consistency (independently per sending sequence).
 *
 * @return status code
 */
extern int pmtu_recv_icmp_start(char *ta, int sid, char *ifname,
                                int *icmp_csap_p);

/**
 * Create eth_csap on the network interface
 *
 * @param ta            Test Agent name
 * @param sid           Session ID
 * @param ifname        Network interface name
 * @param eth_csap_p    Returned CSAP ID
 *
 * @return status code
 */
extern int pmtu_prepare_eth_csap(char *ta, int sid, char *ifname,
                                 int *eth_csap_p);

/**
 * Wait for "ICMP ERROR: Need Frag" message.
 * Check data consistency (independently per sending sequence).
 *
 * @param scenario              Sending scenario
 *
 * @return status code
 */
extern void pmtu_wait_for_icmp_need_frag(pmtu_send_scenario_t *scenario);

/**
 * Change the MTU field value in the ICMP message.
 *
 * @param icmp_packet       ICMP packet data
 * @param new_mtu           New value of MTU field to set
 *
 * @return status code
 */
extern int pmtu_change_icmp_mtu_field(uint8_t *icmp_packet, uint16_t new_mtu);

/**
 * Get the MTU field value from the ICMP message.
 *
 * @param icmp_packet       ICMP packet data
 * @param new_mtu           Returned MTU value
 *
 * @return status code
 */
extern int pmtu_get_icmp_mtu_field(uint8_t *icmp_packet, uint16_t *new_mtu);

/**
 * Send ICMP message via the Ethernet CSAP
 *
 * @param ta            Test Agent name
 * @param sid           Session ID
 * @param eth_csap      Ethernet CSAP ID
 * @param icmp_message  ICMP message structure
 *
 * @return status code
 */
extern void pmtu_icmp_send(char *ta, int sid, int eth_csap, 
                          pmtu_icmp_message_t *icmp_message);

/**
 * This function complies with tapi_pcap_recv_callback prototype.
 */
extern void pmtu_icmp_recv_cb(const int filter_id, const uint8_t *pkt_data,
                              const uint16_t pkt_len, void *userdata);

#endif

/** Structure to pass all parameters to PMTU thread entry point. */
typedef struct pmtu_thread {
    int id;                     /**< Id of this thread */

    uint64_t volatile      queued;   /**< Number of bytes currently passed
                                          to a sending function which has
                                          not returned yet */
    uint64_t volatile      sent;     /**< Number of bytes sent */
    uint64_t volatile      received; /**< Number of bytes received */
    struct pmtu_scenario  *scenario; /**< Pointer to the upper structure */

    void           *func;       /**< Function to use for sending */
    char           *func_name;  /**< Function name for debugging messages */
    pthread_t       thread;     /**< Thread handle */
    rcf_rpc_server *pco_send;   /**< RPC server to use when sending data */
    char           *filename;   /**< Filename to use with sendfile() */

    te_bool volatile  stopped;    /**< Set to @c TRUE if the thread
                                       terminated */

    pthread_mutex_t   lock;       /**< Lock protecting some fields that
                                       the thread can update here:
                                       sent, queued, stopped */
} pmtu_thread;

/** Structure to keep status of sending threads and their shared data */
typedef struct pmtu_scenario {
    int send_s;         /**< sending socket */
    int recv_s;         /**< receiving socket */
    int rcvbuf;         /**< receive buf size */
    int sndbuf;         /**< send buf size */
    int threads_num;    /**< number of sending threads */

    uint64_t start;     /**< Time when first RPC should be called on
                             threads sending data (in milliseconds since
                             Epoch; @c 0 if it should be called
                             immediately) */
    uint64_t timeout;   /**< Time after which the receiver shall finish
                             operation (in seconds; @c 0 for work without
                             restriction) */

    volatile te_bool  stop;     /**< All sending threads should stop */
    rcf_rpc_server   *pco_recv; /**< RPC server to use when receiving data */
    pmtu_thread      *threads;  /**< array of per-thread structure */

    te_bool           partial_send; /**< Will be set to @c TRUE if partial
                                         send is detected */
    pthread_mutex_t   lock;         /**< Mutex protecting fields which
                                         can be updated from threads
                                         (like partial_send) */
} pmtu_scenario;

/**
 * Create a TCP connection and start threads sending data in accordance 
 * with @p send_params.
 *
 * @param pco_send      PCO to send data
 * @param snd_addr      address to send from
 * @param rcv_addr      address to receive on
 * @param send_params   list of functions to be used when sending data
 * @param scenario      status of the process to return to user
 * @param passive       Use or do not use passive connection
 */
extern void pmtu_start_sending_threads(rcf_rpc_server *pco_iut, 
                                       const struct sockaddr *snd_addr,
                                       const struct sockaddr *rcv_addr,
                                       char **send_params,
                                       pmtu_scenario *scenario,
                                       te_bool passive);

/**
 * Receive data and check it correctness.
 *
 * @param scenario  state of send/receive scenario
 * @param buf       buffer to use for receiving
 * @param buflen    length of the buffer
 * @param mask      bitmask with threads which received data (OUT)
 *
 * @return amount of received data
 */
extern int pmtu_recv_and_check(pmtu_scenario *scenario, char *buf, 
                               int buflen, uint32_t *mask);

/**
 * Receive some data from each sending thread and check the data
 * correctness.
 *
 * @param scenario  state of send/receive scenario
 * @param amount    minimum amount of data to be received
 */
extern void pmtu_recv_some_data(pmtu_scenario *scenario, uint64_t amount);

/**
 * Stop all sending threads, receive all data and destroy RPC servers.
 *
 * @param scenario  state of send/receive scenario
 *
 * @return zero on success, non-zero on failure
 */
extern void pmtu_finish(pmtu_scenario *scenario);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_PMTU_LIB_H__ */
