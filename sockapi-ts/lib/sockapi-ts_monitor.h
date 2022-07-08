/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Traffic acceleration monitor
 *
 * Test API to monitor traffic acceleration.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#ifndef __TS_SOCKAPI_TS_MONITOR_H__
#define __TS_SOCKAPI_TS_MONITOR_H__

#include "sockapi-test.h"

/**
 * Determine whether interface belongs to IUT network
 * (in which case it is Solarflare interface if this
 * is IUT TA).
 *
 * @param env       Pointer to environment structure.
 * @param ta        Test Agent name.
 * @param if_name   Interface name.
 *
 * @return TRUE if interface belongs to IUT network,
 *         or FALSE otherwise.
 */
extern te_bool sockts_if_iut(const tapi_env *env,
                             const char *ta,
                             const char *if_name);

/**
 * Determine whether traffic over an interface should
 * be accelerated (makes sense only for an interface
 * on IUT TA).
 *
 * @param env       Pointer to environment structure.
 * @param ta        Test Agent name.
 * @param if_name   Interface name.
 *
 * @return TRUE if traffic should be accelerated, FALSE otherwise.
 */
extern te_bool sockts_if_accelerated(const tapi_env *env,
                                     const char *ta,
                                     const char *if_name);

/**
 * Structure describing a monitor checking traffic
 * which passes via a given interface.
 */
typedef struct sockts_if_monitor {
    char ta[RCF_MAX_NAME];          /**< Test agent on a host where
                                         an interface resides. */
    char if_name[IFNAMSIZ];         /**< Interface name. */

    csap_handle_t csap_in;      /**< CSAP capturing incoming packets. */
    csap_handle_t csap_out;     /**< CSAP capturing outgoing packets. */
} sockts_if_monitor;

/** Initializer for sockts_if_monitor structure. */
#define SOCKTS_IF_MONITOR_INIT \
    { "", "", CSAP_INVALID_HANDLE, CSAP_INVALID_HANDLE }

/**
 * Create two CSAPs on a given interface, start capturing packets.
 *
 * @param monitor         Pointer to sockts_if_monitor stucture.
 * @param ta              Test Agent name.
 * @param if_name         Interface name.
 * @param af              Address family.
 * @param sock_type       Defines whether to capture TCP or UDP
 *                        packets.
 * @param loc_addr        Local IP address.
 * @param rem_addr        Remote IP address.
 * @param monitor_in      Whether to capture incoming packets.
 * @param monitor_out     Whether to capture outgoing packets.
 *
 * @return Status code.
 */
extern te_errno sockts_if_monitor_init(sockts_if_monitor *monitor,
                                       const char *ta,
                                       const char *if_name,
                                       int af, rpc_socket_type sock_type,
                                       const struct sockaddr *loc_addr,
                                       const struct sockaddr *rem_addr,
                                       te_bool monitor_in,
                                       te_bool monitor_out);

/**
 * Check whether new packets were detected on monitored interface.
 *
 * @param out_ignore_first      Ignore the first outgoing packet
 *                              (useful when checking whether
 *                               traffic is accelerated - the first
 *                               packet may be not accelerated due
 *                               to ARP issues).
 * @param in_detected           Will be set to @c TRUE if incoming
 *                              packets were detected.
 * @param out_detected          Will be set to @c TRUE if outgoing
 *                              packets were detected.
 *
 * @return Status code.
 */
extern te_errno sockts_if_monitor_check(sockts_if_monitor *monitor,
                                        te_bool out_ignore_first,
                                        te_bool *in_detected,
                                        te_bool *out_detected);

/**
 * Check whether incoming packets were detected.
 *
 * @param monitor     Pointer to sockts_if_monitor structure.
 *
 * @return @c TRUE if packets were detected, @c FALSE otherwise.
 */
extern te_bool sockts_if_monitor_check_in(sockts_if_monitor *monitor);

/**
 * Check whether outgoing packets were detected.
 *
 * @param monitor         Pointer to sockts_if_monitor structure.
 * @param ignore_first    Ignore the first outgoing packet
 *                        (useful when checking whether
 *                         traffic is accelerated - the first
 *                         packet may be not accelerated due
 *                         to ARP issues).
 *
 * @return @c TRUE if packets were detected, @c FALSE otherwise.
 */
extern te_bool sockts_if_monitor_check_out(sockts_if_monitor *monitor,
                                           te_bool ignore_first);

/**
 * Release resources allocated for interface monitor.
 *
 * @param monitor   Pointer to sockts_if_monitor structure.
 *
 * @return Status code.
 */
extern te_errno sockts_if_monitor_destroy(sockts_if_monitor *monitor);


/**
 * Check whether a packet captured by IP/Ethernet CSAP has VLAN tag.
 * Usually such packets should be filtered out because they should be
 * accounted for on a VLAN interface (where they are captured with VLAN
 * tag removed), not on its parent.
 *
 * @param packet        Captured packet.
 *
 * @return @c TRUE if the packet has VLAN tag, @c FALSE otherwise.
 */
extern te_bool sockts_ip_eth_pkt_is_vlan(asn_value *packet);

/**
 * Check whether a packet captured by TCP or UPD IP/Ethernet CSAP has VLAN tag.
 * Usually such packets should be filtered out because they should be
 * accounted for on a VLAN interface (where they are captured with VLAN
 * tag removed), not on its parent.
 *
 * @param packet        Captured packet.
 *
 * @return @c TRUE if the packet has VLAN tag, @c FALSE otherwise.
 */
extern te_bool sockts_tcp_udp_ip_eth_pkt_is_vlan(asn_value *packet);

/**
 * Check an interface for new incoming packets, print verdict and
 * stop testing if results are not expected.
 *
 * @param m_      Monitor for the interface.
 * @param exp_    Whether incoming packets are expected on
 *                the interface.
 * @param msg_    Message to print in verdicts.
 */
#define CHECK_IF_IN(m_, exp_, msg_) \
    do {                                                                \
        te_bool unexp_result_ = FALSE;                                  \
                                                                        \
        if (sockts_if_monitor_check_in(m_) != exp_)                     \
        {                                                               \
            unexp_result_ = TRUE;                                       \
            ERROR_VERDICT("%s: incoming packets were%s "                \
                          "detected unexpectedly ",                     \
                          msg_, exp_ ? " not" : "");                    \
        }                                                               \
                                                                        \
        if (unexp_result_)                                              \
            TEST_STOP;                                                  \
    } while (0)

/**
 * Check two interfaces for new incoming packets, print verdict and
 * stop testing if results are not expected.
 *
 * @param m1_     Monitor for the first interface.
 * @param m2_     Monitor for the second interface.
 * @param exp1_   Whether incoming packets are expected on
 *                the first interface.
 * @param exp2_   Whether incoming packets are expected on
 *                the second interface.
 * @param msg_    Message to print in verdicts.
 */
#define CHECK_TWO_IFS_IN(m1_, m2_, exp1_, exp2_, msg_) \
    do {                                                                \
        te_bool unexp_result_ = FALSE;                                  \
                                                                        \
        if (sockts_if_monitor_check_in(m1_) != exp1_)                   \
        {                                                               \
            unexp_result_ = TRUE;                                       \
            ERROR_VERDICT("%s: packets were%s detected unexpectedly "   \
                          "on the first interface", msg_,               \
                          exp1_ ? " not" : "");                         \
        }                                                               \
                                                                        \
        if (sockts_if_monitor_check_in(m2_) != exp2_)                   \
        {                                                               \
            unexp_result_ = TRUE;                                       \
            ERROR_VERDICT("%s: packets were%s detected unexpectedly "   \
                          "on the second interface", msg_,              \
                          exp2_ ? " not" : "");                         \
        }                                                               \
                                                                        \
        if (unexp_result_)                                              \
            TEST_STOP;                                                  \
    } while (0)

/**
 * Check whether outgoing traffic is accelerated or not as expected
 * on an IUT interface.
 *
 * @param env_        Pointer to tapi_env structure.
 * @param m_          Monitor for the interface.
 * @param msg_        Message to print in verdicts.
 */
#define CHECK_IF_ACCELERATED(env_, m_, msg_) \
    do {                                                                  \
        te_bool if_acc_;                                                  \
                                                                          \
        if_acc_ = sockts_if_accelerated(env_, (m_)->ta,                   \
                                        (m_)->if_name);                   \
                                                                          \
        if (sockts_if_monitor_check_out(m_, TRUE) != !if_acc_)            \
        {                                                                 \
            TEST_VERDICT("%s%s over IUT interface is %s"                  \
                         "accelerated",                                   \
                         msg_,                                            \
                         (strlen(msg_) == 0 ? "Traffic" : ": traffic"),   \
                         (if_acc_ ? "not " : ""));                        \
        }                                                                 \
    } while (0)

/**
 * Check whether outgoing traffic is accelerated or not as expected
 * on two IUT interfaces, taking into account that socket bound
 * to non-accelerated interface becomes system one for which
 * traffic is never accelerated on any interface.
 *
 * @param m1_         Monitor for the first interface.
 * @param m2_         Monitor for the second interface.
 * @param handover_   If @c TRUE, it is expected that if the
 *                    first interace is not accelerated, socket is
 *                    system one and traffic is not accelerated
 *                    on both interfaces. This expectation is
 *                    correct only if the socket is bound
 *                    (explicitly or by a connect() call) to an
 *                    address on the first interface.
 * @param msg_        Message to print in verdicts.
 */
#define CHECK_TWO_IFS_ACCELERATED_EXT(m1_, m2_, handover_, msg_) \
    do {                                                                  \
        te_bool if1_acc_ = FALSE;                                         \
        te_bool if2_acc_ = FALSE;                                         \
        te_bool unexp_result_ = FALSE;                                    \
                                                                          \
        if1_acc_ = sockts_if_accelerated(&env, (m1_)->ta,                 \
                                         (m1_)->if_name);                 \
                                                                          \
        if (if1_acc_ || !handover_)                                       \
            if2_acc_ = sockts_if_accelerated(&env, (m2_)->ta,             \
                                             (m2_)->if_name);             \
                                                                          \
        if (sockts_if_monitor_check_out((m1_), TRUE) != !if1_acc_)        \
        {                                                                 \
            ERROR_VERDICT("%s%s over the first IUT interface is %s"       \
                          "accelerated",                                  \
                          msg_,                                           \
                          (strlen(msg_) == 0 ? "Traffic" : ": traffic"),  \
                          (if1_acc_ ? "not " : ""));                      \
            unexp_result_ = TRUE;                                         \
        }                                                                 \
                                                                          \
        if (sockts_if_monitor_check_out(m2_, TRUE) != !if2_acc_)          \
        {                                                                 \
            ERROR_VERDICT("%s%s over the second IUT interface is %s"      \
                          "accelerated",                                  \
                          msg_,                                           \
                          (strlen(msg_) == 0 ? "Traffic" : ": traffic"),  \
                          (if2_acc_ ? "not " : ""));                      \
            unexp_result_ = TRUE;                                         \
        }                                                                 \
                                                                          \
        if (unexp_result_)                                                \
            TEST_STOP;                                                    \
    } while (0)

/**
 * Check whether outgoing traffic is accelerated or not as expected
 * on two IUT interfaces.
 *
 * @param m1_         Monitor for the first interface.
 * @param m2_         Monitor for the second interface.
 * @param msg_        Message to print in verdicts.
 */
#define CHECK_TWO_IFS_ACCELERATED(m1_, m2_, msg_) \
    CHECK_TWO_IFS_ACCELERATED_EXT(m1_, m2_, FALSE, msg_)

/**
 * Declare monitors to check traffic in tests with two interfaces.
 */
#define DECLARE_TWO_IFS_MONITORS \
    sockts_if_monitor tst1_if_monitor = SOCKTS_IF_MONITOR_INIT; \
    sockts_if_monitor tst2_if_monitor = SOCKTS_IF_MONITOR_INIT; \
    sockts_if_monitor iut_if1_monitor = SOCKTS_IF_MONITOR_INIT; \
    sockts_if_monitor iut_if2_monitor = SOCKTS_IF_MONITOR_INIT

/**
 * Initialize monitors to check traffic in tests with two interfaces.
 *
 * @param tst_addr_       Address to which packets will be sent from IUT.
 * @param af_             Address family.
 * @param rt_sock_type_   Socket type (from sockts_socket_type enum).
 * @param check_tst_out_  Whether outgoing traffic should be checked
 *                        on Tester (incoming traffic is always checked).
 * @param check_iut_in_   Whether incoming traffic should be checked
 *                        on IUT (outgoing traffic is always checked).
 */
#define INIT_TWO_IFS_MONITORS_EXT(tst_addr_, af_, rt_sock_type_, \
                                  check_tst_out_, \
                                  check_iut_in_) \
    do {                                                                  \
        CHECK_RC(sockts_if_monitor_init(                                  \
                                &tst1_if_monitor,                         \
                                pco_tst1->ta, tst1_if->if_name, af_,      \
                                sock_type_sockts2rpc(rt_sock_type_),      \
                                tst_addr_, NULL,                          \
                                TRUE, check_tst_out_));                   \
                                                                          \
        CHECK_RC(sockts_if_monitor_init(                                  \
                                &tst2_if_monitor,                         \
                                pco_tst2->ta, tst2_if->if_name, af_,      \
                                sock_type_sockts2rpc(rt_sock_type_),      \
                                tst_addr_, NULL,                          \
                                TRUE, check_tst_out_));                   \
                                                                          \
        CHECK_RC(sockts_if_monitor_init(                                  \
                                &iut_if1_monitor,                         \
                                pco_iut->ta, iut_if1->if_name, af_,       \
                                sock_type_sockts2rpc(rt_sock_type_),      \
                                NULL, tst_addr_,                          \
                                check_iut_in_, TRUE));                    \
                                                                          \
        CHECK_RC(sockts_if_monitor_init(                                  \
                                &iut_if2_monitor,                         \
                                pco_iut->ta, iut_if2->if_name, af_,       \
                                sock_type_sockts2rpc(rt_sock_type_),      \
                                NULL, tst_addr_,                          \
                                check_iut_in_, TRUE));                    \
    } while (0)

/**
 * Initialize monitors to check traffic in tests with two interfaces.
 *
 * @param tst_addr_       Address to which packets will be sent from IUT.
 * @param af_             Address family.
 * @param rt_sock_type_   Socket type (from sockts_rt_sock_type enum).
 */
#define INIT_TWO_IFS_MONITORS(tst_addr_, af_, rt_sock_type_) \
    INIT_TWO_IFS_MONITORS_EXT(tst_addr_, af_, rt_sock_type_, FALSE, FALSE)

/**
 * Destroy monitors to check traffic in tests with two interfaces.
 */
#define CLEANUP_TWO_IFS_MONITORS \
    do {                                                                  \
        CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&tst1_if_monitor));    \
        CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&tst2_if_monitor));    \
        CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_if1_monitor));    \
        CLEANUP_CHECK_RC(sockts_if_monitor_destroy(&iut_if2_monitor));    \
    } while (0)

#endif /* __TS_SOCKAPI_TS_MONITOR_H__ */
