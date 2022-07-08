/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief ARP Test Suite
 *
 * ARP test suite useful macros
 *
 * @author Renata Sayakhova <Renata.Sayakhova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_ARP_TEST_MACROS_H__
#define __TS_ARP_TEST_MACROS_H__

#include <net/ethernet.h>
#include <netinet/in.h>
#include <net/if.h>
#include "tapi_cfg.h"
#include "tapi_test.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Macro to get ARP entry.
 *
 * @param rpcs_       RPC server
 * @param net_addr_   Protocol address
 * @param dev_        Device
 * @param link_addr_  HW address (OUT)
 * @param flags_      ARP flags (OUT)
 * @param set_        TRUE if entry exists, FALSE otherwise (OUT)
 */ 
#define TEST_GET_ARP_ENTRY(rpcs_, net_addr_, dev_, link_addr_, flags_, set_) \
    do {                                                                  \
        int             sockd_ = -1;                                      \
        struct arpreq   req_;                                             \
        int             rc_ = 0;                                          \
                                                                          \
        if (rpcs_ == NULL || !ptr_is_not_null(net_addr_) ||               \
            !ptr_is_not_null(link_addr_))                                 \
        {                                                                 \
            TEST_FAIL("NULL pointer passed to TEST_GET_ARP_ENTRY");       \
        }                                                                 \
        memset(&req_, 0, sizeof(req_));                                   \
        set_ = TRUE;                                                      \
        sockd_ = rpc_socket(rpcs_,  RPC_AF_INET,                          \
                            RPC_SOCK_DGRAM, RPC_PROTO_DEF);               \
        memcpy(&req_.arp_pa, (net_addr_), sizeof(struct sockaddr));       \
        memcpy(req_.arp_dev, dev_, strlen(dev_) + 1);                     \
        RPC_AWAIT_IUT_ERROR(rpcs_);                                       \
        rc_ = rpc_ioctl(rpcs_, sockd_, RPC_SIOCGARP, &req_);              \
        if ((rc_) &&                                                      \
            (RPC_ERRNO(rpcs_) == RPC_ENXIO))                              \
        {                                                                 \
            WARN("No ARP entry to get ");                                 \
            set_ = FALSE;                                                 \
        }                                                                 \
        else if (rc_)                                                     \
        {                                                                 \
            TEST_FAIL("Failed to get ARP entry, errno %X",                \
                      TE_RC_GET_ERROR(RPC_ERRNO(rpcs_)));                 \
        }                                                                 \
        RPC_CLOSE(rpcs_, sockd_);                                         \
        memcpy(link_addr_, &(req_.arp_ha), sizeof(struct sockaddr));      \
        flags_ = req_.arp_flags;                                          \
    } while (0)

/**
 * Macro to check that ARP entry is deleted.
 * Tests have problems to delete ARP entries, therefore
 * their deletion should be checked.
 * After bugs fixing this code should be removed.
 *
 * @param ta_         Test Agent
 * @param dev_        Device
 * @param net_addr_   Protocol address
 */ 
#define TEST_CHECK_ARP_ENTRY_IS_DELETED(ta_, dev_, net_addr_) \
    do {                                                                  \
        te_errno                rc_;                                      \
        uint8_t                 a_[ETHER_ADDR_LEN];                       \
        te_bool                 is_static_;                               \
        cs_neigh_entry_state    state_;                                   \
                                                                          \
        rc_ = tapi_cfg_get_neigh_entry(ta_, dev_, net_addr_,              \
                                       a_, &is_static_, &state_);         \
                                                                          \
        if (rc_ == 0)                                                     \
        {                                                                 \
            TEST_VERDICT("%d: Test expects no ARP entry being present, "  \
                      "but here it is:\n"                                 \
                      "%s %02x:%02x:%02x:%02x:%02x:%02x %s %s",           \
                      __LINE__, te_sockaddr_get_ipstr(net_addr_),         \
                      a_[0], a_[1], a_[2], a_[3], a_[4], a_[5],           \
                      is_static_ ? "static" : "dynamic",                  \
                      cs_neigh_entry_state2str(state_));                  \
        }                                                                 \
        else if (rc_ != TE_RC(TE_CS, TE_ENOENT))                          \
        {                                                                 \
            TEST_FAIL("Unexpected failure of tapi_cfg_get_neigh_entry():" \
                      " %r", rc_);                                        \
        }                                                                 \
    } while (0)


/**
 * Macro to provoke ARP request sending.
 * Usually the macro is to be used to initiate connection to check that
 * such-and-such ARP entry exists on such-and-such host or it doesn't
 * exist there, so in case of UDP connection data should be sent
 * using that connection.
 *
 * @param srvr_         PCO where server socket is created
 * @param clnt_         PCO where client socket is created
 * @param sock_type_    Socket type used in the connection
 * @param srvr_addr_    Server address to be used as a template
 *                      for @b bind() on server side
 * @param clnt_addr_    Address to bind client to
 * @param exp_ok_       Is successfull delivery of provoked datagram
 *                      expected (for datagram sockets only)?
 */
#define TEST_PROVOKE_ARP_REQ(srvr_, clnt_, sock_type_,                    \
                             srvr_addr_, clnt_addr_, exp_ok_)             \
    do                                                                    \
    {                                                                     \
        int         srvr_s_ = -1;                                         \
        int         clnt_s_ = -1;                                         \
                                                                          \
        int rc_ = 0;                                                      \
                                                                          \
        if (srvr_ == NULL || clnt_ == NULL ||                             \
            srvr_addr_ == NULL || clnt_addr_ == NULL)                     \
        {                                                                 \
            ERROR("NULL pointer passed to TEST_PROVOKE_ARP_REQ");         \
            goto cleanup;                                                 \
        }                                                                 \
                                                                          \
        TAPI_SET_NEW_PORT(srvr_, srvr_addr_);                             \
        TAPI_SET_NEW_PORT(clnt_, clnt_addr_);                             \
        SOCKTS_CONNECTION(srvr_, clnt_, srvr_addr_, clnt_addr_,           \
                          (sock_type_ == RPC_SOCK_DGRAM ?                 \
                             SOCKTS_SOCK_UDP_NOTCONN :                    \
                             SOCKTS_SOCK_TCP_PASSIVE_CL),                 \
                          &srvr_s_, &clnt_s_, NULL);                      \
        if (sock_type_ == RPC_SOCK_DGRAM)                                 \
        {                                                                 \
            void   *tx_buf = NULL;                                        \
            size_t  tx_len;                                               \
                                                                          \
            CHECK_NOT_NULL(tx_buf = sockts_make_buf_dgram(&tx_len));      \
            RPC_SEND(rc_, clnt_, clnt_s_, tx_buf, tx_len, 0);             \
            if (exp_ok_)                                                  \
            {                                                             \
                void   *rx_buf = NULL;                                    \
                size_t  rx_len;                                           \
                                                                          \
                CHECK_NOT_NULL(rx_buf = te_make_buf_min(tx_len, &rx_len));\
                if (rpc_recv(srvr_, srvr_s_, rx_buf, rx_len, 0) !=        \
                        (ssize_t)tx_len)                                  \
                {                                                         \
                    TEST_FAIL("When ARP request is provoked using a "     \
                              "datagram, the datagram is not delivered"); \
                }                                                         \
                free(rx_buf);                                             \
            }                                                             \
            free(tx_buf);                                                 \
        }                                                                 \
        RPC_CLOSE(clnt_, clnt_s_);                                        \
        RPC_CLOSE(srvr_, srvr_s_);                                        \
    } while (0)

/**
 * The list of values allowed for parameter 'arp_flags' 
 */
#define ARP_FLAGS_MAPPING_LIST \
                        { "C", (int) ATF_COM },               \
                        { "M", (int) ATF_PERM },              \
                        { "CM", (int) (ATF_COM | ATF_PERM) }, \
                        { "!", (int) ATF_DONTPUB },           \
                        { "T", (int) ATF_USETRAILERS},        \
                        { "A", ATF_MAGIC},                    \
                        { "P", ATF_PUBL}

/**
 * Get the value of parameter 'arp_flags'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter 'arp_flags' (OUT)
 */
#define TEST_GET_ARP_FLAGS(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, ARP_FLAGS_MAPPING_LIST)


/**
 * Percents of bytes/packets which are not allowed to lost
 * while UDP datagrams are sending.
 */ 
#define REQUIRED_TO_RECEIVED 60    
    
/**
 * Check that UDP lost less than some predefined above percents 
 * of bytes/datagrams.
 */
#define TEST_CHECK_PKTS_LOST(may_be_lost_, sent_, received_) \
    do {                                                                \
        if (may_be_lost_ == TRUE)                                       \
        {                                                               \
            if ((sent_) * REQUIRED_TO_RECEIVED > (received_) * 100)     \
            {                                                           \
                TEST_FAIL("%u: %d percents of number of bytes/packets " \
                          "sent = %u is greater than "                  \
                          "number of bytes/packets received = %u",      \
                          __LINE__,                                     \
                          REQUIRED_TO_RECEIVED,                         \
                          (unsigned int)sent_,                          \
                          (unsigned int)received_);                     \
            }                                                           \
        }                                                               \
        else                                                            \
        {                                                               \
            if ((sent_) != (received_))                                 \
            {                                                           \
                TEST_FAIL("%u: Number of bytes/packets sent = %u "      \
                          "is not the same as "                         \
                          "number of bytes/packets received = %u",      \
                          __LINE__,                                     \
                          (unsigned int)sent_,                          \
                          (unsigned int)received_);                     \
            }                                                           \
        }                                                               \
    } while (0)

/**
 * Convert link layer address from binary to ascii presentation.
 *
 * @param bin         pointer to binary link layer address
 * @param bin_len     the length of binary link layer address
 * @param lladdr      buffer to save converted link layer address
 * @param lladdr_len  the length of buffer to keep the ascii LL address
 *
 * @return -1 in case of error or 0 on success
 */
static inline int
lladdr_n2a(uint8_t *bin, int bin_len, char *lladdr, int lladdr_len)
{
    int i;
    int l = 0;
    int rc = 0;

    for (i = 0; i < bin_len; i++)
    {
        rc = snprintf(lladdr + l, (lladdr_len - l), "%02x", bin[i]);
        if (rc < 0)
        {
            ERROR("%s: Conversion problem", __FUNCTION__);
            return rc;
        }

        if (i == 0)
        {
            bin_len -= 2;
            l += 2;
        }
        else
        {
            bin_len -= 3;
            l += 3;
        }
    }
    return rc;
}

/**
 * Convert link layer address from ascii to binary presentation.
 *
 * @param lladdr     link layer address in ascii presentation
 * @param bin        buffer to save the converted lladdr
 * @param bin_len    the length of the binary link layer address
 *
 * @return -1 in case of error or number of converted symbols
 */
static inline int
lladdr_a2n(const char *lladdr, uint8_t *bin, int bin_len)
{
    char *arg = NULL;
    char *orig_arg;
    int i;

    if ((lladdr == NULL) || (bin == NULL))
    {
        ERROR("%s: invalid function arguments", __FUNCTION__);
        return -1;
    }

    if ((strlen(lladdr) == 0) || (bin_len == 0))
    {
        ERROR("%s: The one of length parameters is invalid", __FUNCTION__);
        return -1;
    }

    if ((arg = strdup(lladdr)) == NULL)
    {
        ERROR("%s: Insufficient memory", __FUNCTION__);
        return -1;
    }

    orig_arg = arg;

    for (i = 0; i < bin_len; i++)
    {
        unsigned int  temp;
        char         *cp = strchr(arg, ':');
        if (cp)
        {
            *cp = 0;
            cp++;
        }
        if (sscanf(arg, "%x", &temp) != 1)
        {
            ERROR("%s: \"%s\" is invalid lladdr",
                    __FUNCTION__, arg);
            free(orig_arg);
            return -1;
        }
        if (temp > 255)
        {
            ERROR("%s:\"%s\" is invalid lladdr",
                    __FUNCTION__, arg);
            free(orig_arg);
            return -1;
        }

        bin[i] = (uint8_t)temp;
        if (!cp)
            break;
        arg = cp;
    }

    free(orig_arg);
    return i + 1;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif
