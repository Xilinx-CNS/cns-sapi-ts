/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common defines for socket option tests
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#ifndef __TS_SOCKOPTS_COMMON_H__
#define __TS_SOCKOPTS_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sockapi-test.h"


/**
 * Check that ip error queue is empty
 *
 * @param pco           RPC server handle.
 * @param pco_s         Socket on pco.
 * @param msghdr        Store info about message.
 * @param msg           Verdict message prefix if error occurs or
 *                      queue is not empty.
 */
extern void check_iperrque_is_empty(rcf_rpc_server *pco, int pco_s,
                                    rpc_msghdr *msghdr, const char *msg);

/**
 * Check whether IUT address is still in use after closing TCP socket with
 * zero linger, fail test with verdict if it is not expected.
 *
 * @param pco_iut           RPC server.
 * @param iut_addr          Address:port to which IUT socket was bound.
 * @param time_wait_state   Whether closed socket was in @c TCP_TIME_WAIT
 *                          state.
 */
extern void zero_linger_check_addr_free(rcf_rpc_server *rpcs,
                                        const struct sockaddr *addr,
                                        te_bool time_wait_state);

/**
 * Convert struct in_pktinfo to string.
 *
 * @note Pointer to statically allocated buffer is returned which
 *       is overwritten by every call of this function.
 *
 * @param p       Pointer to in_pktinfo structure.
 *
 * @return Pointer to buffer with string.
 */
extern const char *in_pktinfo2str(struct in_pktinfo *p);

/**
 * Convert struct in6_pktinfo to string.
 *
 * @note Pointer to statically allocated buffer is returned which
 *       is overwritten by every call of this function.
 *
 * @param p       Pointer to in6_pktinfo structure.
 *
 * @return Pointer to buffer with string.
 */
extern const char *in6_pktinfo2str(struct in6_pktinfo *p);

/**
 * Get pointer to struct in_pktinfo stored in a control message.
 *
 * @param _cmsg     Pointer to control message.
 */
#define SOCKTS_PKTINFO(_cmsg) (struct in_pktinfo *)CMSG_DATA(_cmsg)

/**
 * Get pointer to struct in6_pktinfo stored in a control message.
 *
 * @param _cmsg     Pointer to control message.
 */
#define SOCKTS_PKTINFO6(_cmsg) (struct in6_pktinfo *)CMSG_DATA(_cmsg)

/**
 * Check whether struct in_pktinfo has correct field values.
 * This function will print verdicts in case of problems.
 *
 * @param info              Pointer to struct in_pktinfo.
 * @param dst_addr          Address to which a packet was sent.
 * @param dst_unicast       Whether destination address is unicast.
 * @param primary_addr      Primary address assigned to a receiving
 *                          interface.
 * @param if_index          Expected interface index.
 * @param parent_if_index   Index of parent interface - makes sense for
 *                          things like MACVLAN/IPVLAN, used for
 *                          making verdicts more precice. Set to @c 0
 *                          if you do not need it.
 * @param vpref             Prefix to print in verdicts (may be empty
 *                          or @c NULL).
 *
 * @return Status code.
 */
extern te_errno sockts_check_in_pktinfo(const struct in_pktinfo *info,
                                        const struct sockaddr *dst_addr,
                                        te_bool dst_unicast,
                                        const struct sockaddr *primary_addr,
                                        unsigned int if_index,
                                        unsigned int parent_if_index,
                                        const char *vpref);

/**
 * Check whether struct in6_pktinfo has correct field values.
 * This function will print verdicts in case of problems.
 *
 * @param info              Pointer to struct in6_pktinfo.
 * @param dst_addr          Address to which a packet was sent.
 * @param if_index          Expected interface index.
 * @param parent_if_index   Index of parent interface - makes sense for
 *                          things like MACVLAN/IPVLAN, used for
 *                          making verdicts more precice. Set to @c 0
 *                          if you do not need it.
 * @param vpref             Prefix to print in verdicts (may be empty
 *                          or @c NULL).
 *
 * @return Status code.
 */
extern te_errno sockts_check_in6_pktinfo(const struct in6_pktinfo *info,
                                         const struct sockaddr *dst_addr,
                                         unsigned int if_index,
                                         unsigned int parent_if_index,
                                         const char *vpref);

/**
 * Get index of the parent interface for a given interface.
 *
 * @param rpcs          RPC server handle.
 * @param if_name       Interface name.
 * @param parent_ifidx  Will be set to index of the parent interface or
 *                      to @c 0 if parent is not known.
 *
 * @return Status code.
 */
extern te_errno sockts_get_if_parent_index(rcf_rpc_server *rpcs,
                                           const char *if_name,
                                           unsigned int *parent_ifidx);

/**
 * Send data from Tester, receive it on IUT, check whether @c IP_PKTINFO
 * and/or @c IPV6_PKTINFO control message was received with expected
 * fields values.
 *
 * @param pco_tst               RPC server on Tester.
 * @param tst_s                 Tester socket FD.
 * @param pco_iut               RPC server on IUT.
 * @param iut_s                 IUT socket FD.
 * @param iut_addr              The first IPv4 address assigned to
 *                              IUT interface.
 * @param dst_addr              The address to which to send a packet
 *                              from Tester.
 * @param if_index              Expected interface index.
 * @param parent_if_index       Index of the parent interface (or
 *                              @c 0).
 * @param ip_pktinfo            Whether @c IP_PKTINFO option is enabled.
 * @param ipv6_recvpktinfo      Whether @c IPV6_RECVPKTINFO option is
 *                              enabled.
 * @param vpref                 Prefix to print in verdicts (may be empty
 *                              or @c NULL).
 *
 * @return Status code.
 */
extern te_errno sockts_send_recv_check_pktinfo(
                                        rcf_rpc_server *pco_tst, int tst_s,
                                        rcf_rpc_server *pco_iut, int iut_s,
                                        const struct sockaddr *iut_addr,
                                        const struct sockaddr *dst_addr,
                                        sockts_addr_type addr_type,
                                        unsigned int if_index,
                                        unsigned int parent_if_index,
                                        te_bool ip_pktinfo,
                                        te_bool ipv6_recvpktinfo,
                                        const char *vpref);

/**
 * Generate random non-zero traffic class or TOS value.
 *
 * @param precedence_bits     If @c TRUE, set 3 most significant bits to
 *                            non-zero; otherwise set them to zero.
 *
 * @return Generated value.
 */
static inline unsigned int
sockts_random_tclass_or_tos(te_bool precedence_bits)
{
    /*
     * Two least significant bits are reserved for ECN and
     * may be cleared after setting, so let's not use them.
     */
    if (precedence_bits)
        return (rand_range(0x08, 0x3f) << 2);
    else
        return (rand_range(0x01, 0x07) << 2);
}

/**
 * Generate two different random non-zero values for Traffic Class
 * and TOS.
 *
 * @param tclass            Where to save the Traffic Class value.
 * @param tos               Where to save the TOS value.
 * @param tos_prec_bits     If @c TRUE, set 3 most significant bits to
 *                          non-zero in TOS value; otherwise set them to
 *                          zero.
 */
static inline void
sockts_random_tclass_tos(unsigned int *tclass, unsigned int *tos,
                         te_bool tos_prec_bits)
{
    *tclass = sockts_random_tclass_or_tos(FALSE);
    do {
        *tos = sockts_random_tclass_or_tos(tos_prec_bits);
    } while (*tos == *tclass);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_SOCKOPTS_COMMON_H_ */
