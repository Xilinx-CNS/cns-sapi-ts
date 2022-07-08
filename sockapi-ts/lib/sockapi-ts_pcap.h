/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief TAPI to process PCAP files.
 *
 * Definitions of functions for processing PCAP files.
 *
 * @author Roman Zhukov <Roman.Zhukov@oktetlabs.ru>
 */

#ifndef __SOCKAPI_TS_PCAP_H__
#define __SOCKAPI_TS_PCAP_H__

#include "sockapi-test.h"

/**
 * Get TCP retransmissions for chunks from PCAP file with IPv4/TCP connection.
 * The retransmissions only from one direction of connection are counted.
 *
 * @param[in]   pcap_file       Path to PCAP file
 * @param[in]   dst_addr        Destination address to choose direction of connection
 * @param[in]   chunk_size      Chunk size.
 * @param[out]  retrans         Pointer to array with TCP retansmissions.
 * @param[out]  retrans_size    Pointer to @p retrans size.
 *
 * @note Array with retransmission values @p retrans is allocated in this
 *       function and must be freed after use.
 *
 * @return Status code.
 */
extern te_errno sockts_pcap_get_retrans(const char *pcap_file,
                                        const struct sockaddr *dst_addr,
                                        unsigned int chunk_size,
                                        int **retrans,
                                        unsigned int *retrans_size);

/**
 * Output TCP retransmission values via MI logger in JSON format.
 * This report should be used to draw graph.
 *
 * @param[in] retrans           TCP retransmission values array.
 * @param[in] retrans_size      Size of @p retrans array.
 *
 * @return Status code.
 */
extern te_errno sockts_pcap_mi_report_retrans(int *retrans,
                                              unsigned int retrans_size);

#endif /* __SOCKAPI_TS_PCAP_H__ */
