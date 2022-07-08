/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to process PCAP files.
 *
 * Implementation of functions for processing PCAP files.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#include "sockapi-ts_pcap.h"
#include "te_errno.h"
#include "te_mi_log.h"

#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

/**
 * Get EtherType value from Ethernet header and offset to the next header.
 * Offset points to the header after VLAN headers if they are.
 *
 * @param[in]  pkt              Pointer to the packet
 * @param[out] nexthdr_offset   Offset to the next header
 *
 * @return EtherType
 */
static uint16_t
sockts_pcap_get_ethertype(const uint8_t *pkt, uint8_t *nexthdr_offset)
{
    /*
     * Declare this structure inside the function because it does
     * not have to be used anywhere else.
     */
    typedef struct vlanhdr {
        __be16 h_vlan_TCI;
        __be16 h_vlan_ethertype;
    } vlanhdr;

    struct ethhdr *eth = (struct ethhdr *)pkt;
    uint16_t eth_type = 0;
    uint8_t offset = 0;

    offset += sizeof(*eth);
    eth_type = eth->h_proto;

    while (eth_type == htons(ETH_P_8021Q) ||
           eth_type == htons(ETH_P_8021AD))
    {
        vlanhdr *vlan_hdr = (vlanhdr *)(pkt + offset);

        offset += sizeof(*vlan_hdr);
        eth_type = vlan_hdr->h_vlan_ethertype;
    }

    *nexthdr_offset = offset;
    return ntohs(eth_type);
}

/** Structure with user data to pass to callback function */
typedef struct sockts_pcap_user_data {
    /**< Highest sequence number that was in TCP connection. */
    uint32_t seq;
    /**< @c TRUE if something went wrong in callback. */
    te_bool is_failed;
    /**< First sequence number in TCP connection */
    uint32_t first_seq;
    /**< Array with TCP retransmissions for chunks */
    int *retrans;
    /**< Size of the array with TCP retransmissions */
    unsigned int retrans_size;
    /**< Last index in the array with retransmissions */
    unsigned int retrans_index;
    /**< Chunk size */
    unsigned int chunk_size;
} sockts_pcap_user_data;

/**
 * Callback function to count number of IPv4/TCP retransimssions.
 *
 * @param args      User data
 * @param header    PCAP packet header
 * @param packet    Pointer to the packet
 */
static void sockts_pcap_retrans_number_handler(u_char *args,
                                               const struct pcap_pkthdr *header,
                                               const u_char *packet)
{
    uint8_t *pkt = (uint8_t *)packet;
    uint16_t ethertype = 0;
    uint8_t offset = 0;
    uint32_t seq;
    uint16_t ip_tot_len;
    uint16_t payload_len = 0;
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = NULL;
    sockts_pcap_user_data *data = (sockts_pcap_user_data *)args;

    ethertype = sockts_pcap_get_ethertype(pkt, &offset);
    if (ethertype != ETH_P_IP)
    {
        ERROR("Unexpected Ethertype: %u", ethertype);
        data->is_failed = TRUE;
        return;
    }

    iph = (struct iphdr *)(pkt + offset);
    ip_tot_len = ntohs(iph->tot_len);
    if (iph->protocol != IPPROTO_TCP)
    {
        ERROR("Unexpected IP protocol: %u", iph->protocol);
        data->is_failed = TRUE;
        return;
    }

    tcph = (struct tcphdr *)((uint8_t *)iph + iph->ihl * 4);
    payload_len = ip_tot_len - (iph->ihl * 4 + tcph->doff * 4);

    seq = ntohl(tcph->seq);
    if (data->first_seq == 0)
    {
        data->first_seq = seq;
        data->seq = seq;
        return;
    }

    /* Don't process packets without payload. They don't increase SEQ and will
     * not be counted as retransmissions.
     */
    if (payload_len == 0)
        return;

    data->retrans_index = (seq - data->first_seq) / data->chunk_size;
    if (data->retrans_index >= data->retrans_size)
    {
        ERROR("Index of the chunk (%u) is more than the size of buffer with TCP "
              "retransmissions (%u).", data->retrans_index, data->retrans_size);
        data->is_failed = TRUE;
        return;
    }

    /* Compare sequence numbers, given that they can overflow */
#define SEQ_LESS(a, b) (((int32_t)(a - b)) < 0)
    if (SEQ_LESS(data->seq, seq))
        data->seq = seq;
    else
        data->retrans[data->retrans_index]++;
#undef SEQ_LESS

    return;
}

/** Size of buffer for TCP retransmissions */
#define SOCKTS_PCAP_RETRANS_BUF_SIZE 10000

/** See definition in sockapi-ts_pcap.h */
te_errno
sockts_pcap_get_retrans(const char *pcap_file,
                        const struct sockaddr *dst_addr,
                        unsigned int chunk_size,
                        int **retrans,
                        unsigned int *retrans_size)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    char filter[1024];
    pcap_t *handle;
    sockts_pcap_user_data data = {0};
    struct bpf_program filter_handle;
    int retrans_buf[SOCKTS_PCAP_RETRANS_BUF_SIZE] = {0};
    unsigned int i;
    te_errno rc = 0;

    handle = pcap_open_offline(pcap_file, error_buffer);

    snprintf(filter, sizeof(filter), "dst %s",
             te_sockaddr_get_ipstr(dst_addr));
    if (pcap_compile(handle, &filter_handle, filter, 1,
                     PCAP_NETMASK_UNKNOWN) == -1)
    {
        ERROR("Failed to compile filter: %s", pcap_geterr(handle));
        pcap_close(handle);
        return TE_EINVAL;
    }

    if (pcap_setfilter(handle, &filter_handle) == -1)
    {
        ERROR("Failed to set filter: %s", pcap_geterr(handle));
        pcap_close(handle);
        return TE_EINVAL;
    }

    data.is_failed = FALSE;
    data.chunk_size = chunk_size;
    data.retrans = retrans_buf;
    data.retrans_size = SOCKTS_PCAP_RETRANS_BUF_SIZE;
    pcap_loop(handle, 0, sockts_pcap_retrans_number_handler, (u_char *)&data);

    pcap_close(handle);

    if (!data.is_failed)
    {
        *retrans_size = data.retrans_index + 1;
        *retrans = TE_ALLOC(*retrans_size * sizeof(int));
        if (*retrans == NULL)
        {
            ERROR("Failed to allocate array with TCP retransmissions");
            return TE_ENOMEM;
        }
        memcpy(*retrans, data.retrans, *retrans_size * sizeof(int));
    }
    else
    {
        rc = TE_EFAIL;
    }

    return rc;
}

/** See definition in sockapi-ts_pcap.h */
te_errno
sockts_pcap_mi_report_retrans(int *retrans, unsigned int retrans_size)
{
    te_mi_logger *logger;
    te_errno      rc;
    unsigned int  i;

    rc = te_mi_logger_meas_create("ol-apprtt", &logger);
    if (rc != 0)
        return rc;

    for (i = 0; i < retrans_size; i++)
    {
        te_mi_logger_add_meas(logger, NULL, TE_MI_MEAS_RETRANS,
                              "TCP retransmissions",
                              TE_MI_MEAS_AGGR_SINGLE, retrans[i],
                              TE_MI_MEAS_MULTIPLIER_PLAIN);
    }

    te_mi_logger_add_meas_view(logger, NULL, TE_MI_MEAS_VIEW_LINE_GRAPH, "",
                               "TCP retransmissions");
    te_mi_logger_meas_graph_axis_add_name(
                                      logger, NULL,
                                      TE_MI_MEAS_VIEW_LINE_GRAPH, "",
                                      TE_MI_GRAPH_AXIS_X,
                                      TE_MI_GRAPH_AUTO_SEQNO);

    te_mi_logger_destroy(logger);
    return 0;
}
