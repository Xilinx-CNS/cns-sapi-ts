/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Implementation of traffic acceleration monitor functions.
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#include "sockapi-ts_monitor.h"

#include "ndn_eth.h"
#include "tapi_ip_common.h"
#include "onload.h"

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_if_iut(const tapi_env *env,
              const char *ta,
              const char *if_name)
{
    tapi_env_if   *p = NULL;
    te_bool        found = FALSE;

    CIRCLEQ_FOREACH(p, &env->ifs, links)
    {
        if (strcmp(p->host->ta, ta) == 0 &&
            strcmp(p->if_info.if_name, if_name) == 0)
        {
            found = TRUE;
            break;
        }
    }

    /*
     * Check p == NULL cannot be used here - in case of
     * CIRCLEQ at the end of the loop p will point at queue's
     * head.
     */
    if (!found)
    {
        TEST_FAIL("%s(): failed to find interface "
                  "%s on TA %s in environment",
                  __FUNCTION__, if_name, ta);
    }

    if (p->net->type == TAPI_ENV_IUT)
        return TRUE;

    return FALSE;
}

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_if_accelerated(const tapi_env *env,
                      const char *ta,
                      const char *if_name)
{
    if (sockts_if_iut(env, ta, if_name) &&
        tapi_onload_lib_exists(ta))
        return TRUE;

    return FALSE;
}

/* See description in sockapi-ts_monitor.h */
te_errno
sockts_if_monitor_init(sockts_if_monitor *monitor,
                       const char *ta,
                       const char *if_name,
                       int af, rpc_socket_type sock_type,
                       const struct sockaddr *loc_addr,
                       const struct sockaddr *rem_addr,
                       te_bool monitor_in,
                       te_bool monitor_out)
{
    te_errno rc;

    monitor->csap_in = CSAP_INVALID_HANDLE;
    monitor->csap_out = CSAP_INVALID_HANDLE;

    strncpy(monitor->ta, ta, RCF_MAX_NAME);
    strncpy(monitor->if_name, if_name, IFNAMSIZ);

    if (monitor_in)
    {
        rc = tapi_ip_eth_csap_create(ta, 0, if_name,
                                     TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL, af,
                                     te_sockaddr_get_netaddr(loc_addr),
                                     te_sockaddr_get_netaddr(rem_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                                IPPROTO_TCP : IPPROTO_UDP),
                                     &monitor->csap_in);

        if (rc != 0)
            return rc;

        rc = tapi_tad_trrecv_start(ta, 0, monitor->csap_in, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS);
        if (rc != 0)
            return rc;
    }

    if (monitor_out)
    {
        rc = tapi_ip_eth_csap_create(ta, 0, if_name,
                                     TAD_ETH_RECV_OUT | TAD_ETH_RECV_NO_PROMISC,
                                     NULL, NULL, af,
                                     te_sockaddr_get_netaddr(rem_addr),
                                     te_sockaddr_get_netaddr(loc_addr),
                                     (sock_type == RPC_SOCK_STREAM ?
                                                IPPROTO_TCP : IPPROTO_UDP),
                                     &monitor->csap_out);

        if (rc != 0)
            return rc;

        rc = tapi_tad_trrecv_start(ta, 0, monitor->csap_out, NULL,
                                   TAD_TIMEOUT_INF, 0,
                                   RCF_TRRECV_PACKETS);
        if (rc != 0)
            return rc;
    }

    return 0;
}

/**
 * Check whether a packet has VLAN tag.
 *
 * @param packet        Captured packet.
 * @param labels        Textual ASN.1 labels of subvalue.
 *
 * @return @c TRUE if the packet has VLAN tag, @c FALSE otherwise.
 */
static te_bool
sockts_pkt_is_vlan(asn_value *packet, const char *labels)
{
    const asn_value   *eth_pdu = NULL;
    const asn_value   *tmp = NULL;
    te_errno           rc;

    CHECK_RC(asn_get_descendent(packet,
                                (asn_value **)&eth_pdu,
                                labels));

    rc = asn_get_child_value(eth_pdu, &tmp,
                             PRIVATE, NDN_TAG_VLAN_TAGGED);
    if (rc == 0)
    {
        asn_tag_class   class;
        asn_tag_value   tag;

        rc = asn_get_choice_value(tmp, (asn_value **)&tmp,
                                  &class, &tag);
        if (rc == 0)
        {
            if (tag != NDN_TAG_ETH_UNTAGGED)
                return TRUE;
        }
    }

    return FALSE;
}

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_ip_eth_pkt_is_vlan(asn_value *packet)
{
    return sockts_pkt_is_vlan(packet, "pdus.1.#eth");
}

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_tcp_udp_ip_eth_pkt_is_vlan(asn_value *packet)
{
    return sockts_pkt_is_vlan(packet, "pdus.2.#eth");
}

/**
 * Callback for counting IP packets captured by CSAP.
 * It will ignore packets having VLAN tag, since such packets
 * actually belong to the child VLAN interface (from which
 * they can be received stripped of this tag).
 *
 * @param packet        Packet described in ASN.
 * @param user_data     Pointer to packets counter.
 */
static void
sockts_if_monitor_cb(asn_value *packet,
                     void *user_data)
{
    unsigned int *pkts_num = (unsigned int *)user_data;

    if (sockts_ip_eth_pkt_is_vlan(packet))
        return;

    (*pkts_num)++;
}

/* See description in sockapi-ts_monitor.h */
te_errno
sockts_if_monitor_check(sockts_if_monitor *monitor,
                        te_bool out_ignore_first,
                        te_bool *in_detected,
                        te_bool *out_detected)
{
    unsigned int pkts_num;
    te_errno     rc;

    if (monitor->csap_in != CSAP_INVALID_HANDLE &&
        in_detected != NULL)
    {
        pkts_num = 0;
        rc = tapi_tad_trrecv_get(monitor->ta, 0,
                                 monitor->csap_in,
                                 tapi_tad_trrecv_make_cb_data(
                                    &sockts_if_monitor_cb,
                                    &pkts_num),
                                 NULL);
        if (rc != 0)
            return rc;

        if (pkts_num > 0)
            *in_detected = TRUE;
        else
            *in_detected = FALSE;
    }

    if (monitor->csap_out != CSAP_INVALID_HANDLE &&
        out_detected != NULL)
    {
        pkts_num = 0;
        rc = tapi_tad_trrecv_get(monitor->ta, 0,
                                 monitor->csap_out,
                                 tapi_tad_trrecv_make_cb_data(
                                    &sockts_if_monitor_cb,
                                    &pkts_num),
                                 NULL);

        if (rc != 0)
            return rc;

        if (pkts_num == 0 ||
            (pkts_num == 1 && out_ignore_first))
            *out_detected = FALSE;
        else
            *out_detected = TRUE;
    }

    return 0;
}

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_if_monitor_check_in(sockts_if_monitor *monitor)
{
    te_bool in_detected = FALSE;

    CHECK_RC(sockts_if_monitor_check(monitor, FALSE,
                                     &in_detected, NULL));

    return in_detected;
}

/* See description in sockapi-ts_monitor.h */
te_bool
sockts_if_monitor_check_out(sockts_if_monitor *monitor,
                            te_bool ignore_first)
{
    te_bool out_detected = FALSE;

    CHECK_RC(sockts_if_monitor_check(monitor, ignore_first,
                                     NULL, &out_detected));

    return out_detected;
}

/* See description in sockapi-ts_monitor.h */
te_errno
sockts_if_monitor_destroy(sockts_if_monitor *monitor)
{
    te_errno rc;
    te_errno result = 0;

    if (monitor->csap_in != CSAP_INVALID_HANDLE)
    {
        rc = tapi_tad_csap_destroy(monitor->ta, 0,
                                   monitor->csap_in);
        if (rc != 0)
            result = rc;
    }

    if (monitor->csap_out != CSAP_INVALID_HANDLE)
    {
        rc = tapi_tad_csap_destroy(monitor->ta, 0,
                                   monitor->csap_out);
        if (rc != 0)
            result = rc;
    }

    return result;
}
