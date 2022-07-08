/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common defines for socket option tests
 *
 * @author Damir Mansurov <Damir.Mansurov@oktetlabs.ru>
 */

#include "sockopts_common.h"

/**
 * Maximum length of a string used to represent in_pktinfo/in6_pktinfo
 * structure.
 */
#define MAX_PKTINFO_STR 1024

/* See description in sockopts_common.h */
void
check_iperrque_is_empty(rcf_rpc_server *pco, int pco_s,
                        rpc_msghdr *msghdr, const char *msg)
{
    int res;
    msghdr->msg_controllen = SOCKTS_CMSG_LEN;

    RPC_AWAIT_IUT_ERROR(pco);
    res = rpc_recvmsg(pco, pco_s, msghdr, RPC_MSG_ERRQUEUE);
    if (res < 0)
    {
        int pco_errno = RPC_ERRNO(pco);
        if (pco_errno != RPC_EAGAIN)
            TEST_VERDICT("%s: recvmsg() failed with unexpected error "
                         "%s, expected EAGAIN", msg,
                         errno_rpc2str(pco_errno));
    }
    else
    {
        TEST_VERDICT("%s: ip error queue is not empty", msg);
    }
}

/* See description in sockopts_common.h */
void
zero_linger_check_addr_free(rcf_rpc_server *rpcs,
                            const struct sockaddr *addr,
                            te_bool time_wait_state)
{
    if (is_addr_inuse(rpcs, rpc_socket_domain_by_addr(addr),
                      RPC_SOCK_STREAM, addr))
    {
        if (!time_wait_state)
            TEST_VERDICT("IUT address is busy after closing");
    }
    else
    {
        if (time_wait_state)
        {
            /* This may be a feature rather than a bug. */
            RING_VERDICT("IUT address is free after closing "
                         "TIME_WAIT socket");
        }
    }
}

/* See description in sockopts_common.h */
const char *
in_pktinfo2str(struct in_pktinfo *p)
{
    static char buf[MAX_PKTINFO_STR];
    char        ip_str_buf1[INET_ADDRSTRLEN] = "";
    char        ip_str_buf2[INET_ADDRSTRLEN] = "";

    if (p == NULL)
        return "(null)";

    buf[0] = '\0';
    TE_SPRINTF(buf, ".ipi_ifindex: %d, .ipi_spec_dst: %s, "
               ".ipi_addr: %s", p->ipi_ifindex,
               inet_ntop(AF_INET, &p->ipi_spec_dst,
                         ip_str_buf1, sizeof(ip_str_buf1)),
               inet_ntop(AF_INET, &p->ipi_addr,
                         ip_str_buf2, sizeof(ip_str_buf2)));

    return buf;
}

/* See description in sockopts_common.h */
const char *
in6_pktinfo2str(struct in6_pktinfo *p)
{
    static char buf[MAX_PKTINFO_STR];
    char        ip_str_buf[INET6_ADDRSTRLEN] = "";

    if (p == NULL)
        return "(null)";

    buf[0] = '\0';
    TE_SPRINTF(buf, ".ipi6_ifindex: %d, .ipi6_addr: %s",
               p->ipi6_ifindex,
               inet_ntop(AF_INET6, &p->ipi6_addr,
                         ip_str_buf, sizeof(ip_str_buf)));

    return buf;
}

/* See description in sockopts_common.h */
te_errno
sockts_check_in_pktinfo(const struct in_pktinfo *info,
                        const struct sockaddr *dst_addr,
                        te_bool dst_unicast,
                        const struct sockaddr *primary_addr,
                        unsigned int if_index,
                        unsigned int parent_if_index,
                        const char *vpref)
{
    const char *pref = sockts_prefix(vpref);

    te_errno   ret = 0;
    void      *local_addr = NULL;

    char       ip_str_buf1[INET_ADDRSTRLEN] = "";
    char       ip_str_buf2[INET_ADDRSTRLEN] = "";

    if (dst_addr->sa_family != AF_INET)
    {
        ERROR("%s(): not IPv4 address passed", __FUNCTION__);
        return TE_EINVAL;
    }

    if (memcmp(&(info->ipi_addr), te_sockaddr_get_netaddr(dst_addr),
               sizeof(struct in_addr)) != 0)
    {
        ERROR_VERDICT("%s'ipi_addr' returned in IP_PKTINFO ancillary "
                      "data is different from address to which a packet "
                      "was sent", pref);
        ret = TE_EINVAL;
    }

    if (dst_unicast)
        local_addr = te_sockaddr_get_netaddr(dst_addr);
    else
        local_addr = te_sockaddr_get_netaddr(primary_addr);

    if (memcmp(&(info->ipi_spec_dst),
               local_addr,
               sizeof(struct in_addr)) != 0)
    {
        ERROR("'ipi_spec_addr' is %s instead of %s",
              inet_ntop(AF_INET, &info->ipi_spec_dst,
                        ip_str_buf1, sizeof(ip_str_buf1)),
              inet_ntop(AF_INET, local_addr,
                        ip_str_buf2, sizeof(ip_str_buf2)));

        ERROR_VERDICT("%s'ipi_spec_dst' returned in IP_PKTINFO "
                      "ancillary data has unexpected value", pref);
        ret = TE_EINVAL;
    }

    if ((unsigned int)info->ipi_ifindex != if_index)
    {
        ERROR("'ipi_ifindex' is %d instead of %u", info->ipi_ifindex,
              if_index);
        if (parent_if_index > 0 &&
            (unsigned int)(info->ipi_ifindex) == parent_if_index)
        {
            ERROR_VERDICT("%s'ipi_ifindex' returned in IP_PKTINFO "
                          "ancillary data was set to the index of "
                          "parent interface", pref);
        }
        else
        {
            ERROR_VERDICT("%s'ipi_ifindex' returned in IP_PKTINFO "
                          "ancillary data has unexpected value", pref);
        }
        ret = TE_EINVAL;
    }

    return ret;
}

/* See description in sockopts_common.h */
te_errno
sockts_check_in6_pktinfo(const struct in6_pktinfo *info,
                         const struct sockaddr *dst_addr,
                         unsigned int if_index,
                         unsigned int parent_if_index,
                         const char *vpref)
{
    const char *pref = sockts_prefix(vpref);

    te_errno                ret = 0;
    struct sockaddr_storage fixed_dst_addr;

    tapi_sockaddr_clone_exact(dst_addr, &fixed_dst_addr);
    if (dst_addr->sa_family == AF_INET)
        te_sockaddr_ip4_to_ip6_mapped(SA(&fixed_dst_addr));

    if (memcmp(&(info->ipi6_addr),
               te_sockaddr_get_netaddr(SA(&fixed_dst_addr)),
               sizeof(struct in6_addr)) != 0)
    {
        ERROR_VERDICT("%s'ipi6_addr' returned in IPV6_PKTINFO ancillary "
                      "data is different from address to which a packet "
                      "was sent", pref);
        ret = TE_EINVAL;
    }

    if (info->ipi6_ifindex != if_index)
    {
        ERROR("'ipi6_ifindex' is %u instead of %u", info->ipi6_ifindex,
              if_index);
        if (parent_if_index > 0 &&
            (unsigned int)(info->ipi6_ifindex) == parent_if_index)
        {
            ERROR_VERDICT("%s'ipi6_ifindex' returned in IPV6_PKTINFO "
                          "ancillary data was set to the index of "
                          "parent interface", pref);
        }
        else
        {
            ERROR_VERDICT("%s'ipi6_ifindex' returned in IPV6_PKTINFO "
                          "ancillary data has unexpected value", pref);
        }
        ret = TE_EINVAL;
    }

    return ret;
}

/* See description in sockopts_common.h */
te_errno
sockts_get_if_parent_index(rcf_rpc_server *rpcs,
                           const char *if_name,
                           unsigned int *parent_ifidx)
{
    char            parent_ifname[IF_NAMESIZE] = "";
    te_errno        rc;

    rc = tapi_cfg_get_if_parent(rpcs->ta, if_name,
                                parent_ifname,
                                sizeof(parent_ifname));
    if (rc != 0)
        return rc;

    if (parent_ifname[0] == '\0')
    {
        *parent_ifidx = 0;
        return 0;
    }

    *parent_ifidx = rpc_if_nametoindex(rpcs, parent_ifname);
    return 0;
}


/* See description in sockopts_common.h */
te_errno
sockts_send_recv_check_pktinfo(rcf_rpc_server *pco_tst, int tst_s,
                               rcf_rpc_server *pco_iut, int iut_s,
                               const struct sockaddr *iut_addr,
                               const struct sockaddr *dst_addr,
                               sockts_addr_type addr_type,
                               unsigned int if_index,
                               unsigned int parent_if_index,
                               te_bool ip_pktinfo,
                               te_bool ipv6_recvpktinfo,
                               const char *vpref)
{
    const char *pref = sockts_prefix(vpref);

    struct msghdr   hmsg;
    struct cmsghdr *cmsg = NULL;

    uint8_t     tx_buf[SOCKTS_MSG_DGRAM_MAX];
    size_t      tx_buf_len;
    int         rc;
    te_errno    ret = 0;
    rpc_msghdr  msg;

    te_bool             exp_info4 = FALSE;
    te_bool             exp_info6 = FALSE;
    struct in_pktinfo  *pkt_info4 = NULL;
    struct in6_pktinfo *pkt_info6 = NULL;
    te_bool             extra_cmsg = FALSE;
    te_bool             readable = FALSE;

    tx_buf_len = rand_range(1, sizeof(tx_buf));
    te_fill_buf(tx_buf, tx_buf_len);

    sockts_init_msghdr(&msg, sizeof(tx_buf) * 2);

    RPC_SENDTO(rc, pco_tst, tst_s, tx_buf, tx_buf_len, 0, dst_addr);
    RPC_GET_READABILITY(readable, pco_iut, iut_s, TAPI_WAIT_NETWORK_DELAY);
    if (!readable)
    {
        ERROR_VERDICT("%sIUT socket did not become readable", pref);
        ret = TE_EAGAIN;
        goto cleanup;
    }

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_recvmsg(pco_iut, iut_s, &msg, RPC_MSG_DONTWAIT);
    if (rc < 0)
    {
        ERROR_VERDICT("%srecvmsg() unexpectedly failed with errno %r",
                      pref, RPC_ERRNO(pco_iut));
        ret = RPC_ERRNO(pco_iut);
        goto cleanup;
    }

    if (rc != (int)tx_buf_len ||
        memcmp(msg.msg_iov->iov_base, tx_buf, tx_buf_len) != 0)
    {
        ERROR_VERDICT("%srecvmsg() returned unexpected data", pref);
        ret = TE_EFAIL;
        goto cleanup;
    }

    memset(&hmsg, 0, sizeof(hmsg));
    hmsg.msg_control = msg.msg_control;
    hmsg.msg_controllen = msg.msg_controllen;

    for (cmsg = CMSG_FIRSTHDR(&hmsg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&hmsg, cmsg))
    {
        RING("Control message: level %d, type %d: %s",
             cmsg->cmsg_level, cmsg->cmsg_type,
             sockopt_rpc2str(cmsg_type_h2rpc(cmsg->cmsg_level,
                                             cmsg->cmsg_type)));

        if (cmsg->cmsg_level == SOL_IP &&
            cmsg->cmsg_type == IP_PKTINFO)
        {
            RING("Returned in_pktinfo: %s",
                 in_pktinfo2str(SOCKTS_PKTINFO(cmsg)));

            if (pkt_info4 == NULL)
            {
                pkt_info4 = SOCKTS_PKTINFO(cmsg);
                if (dst_addr->sa_family == AF_INET &&
                    sockts_check_in_pktinfo(pkt_info4, dst_addr,
                                            (addr_type == SOCKTS_ADDR_SPEC),
                                            iut_addr, if_index,
                                            parent_if_index, vpref) != 0)
                {
                    ret = TE_EINVAL;
                }
            }
            else
            {
                extra_cmsg = TRUE;
            }
        }
        else if (cmsg->cmsg_level == SOL_IPV6 &&
                 cmsg->cmsg_type == IPV6_PKTINFO)
        {
            RING("Returned in6_pktinfo: %s",
                 in6_pktinfo2str(SOCKTS_PKTINFO6(cmsg)));

            if (pkt_info6 == NULL)
            {
                pkt_info6 = SOCKTS_PKTINFO6(cmsg);
                if (sockts_check_in6_pktinfo(pkt_info6, dst_addr,
                                             if_index,
                                             parent_if_index,
                                             vpref) != 0)
                {
                    ret = TE_EINVAL;
                }
            }
            else
            {
                extra_cmsg = TRUE;
            }
        }
        else
        {
            extra_cmsg = TRUE;
        }
    }

    if (extra_cmsg)
    {
        ERROR_VERDICT("%sExtra control message(s) was obtained", pref);
        ret = TE_EFAIL;
    }

    exp_info4 = ip_pktinfo && (dst_addr->sa_family == AF_INET);
    exp_info6 = ipv6_recvpktinfo;

    if (pkt_info4 != NULL && !exp_info4)
    {
        ERROR_VERDICT("%sIP_PKTINFO control message was obtained "
                      "unexpectedly", pref);
        ret = TE_EFAIL;
    }
    else if (pkt_info4 == NULL && exp_info4)
    {
        ERROR_VERDICT("%sIP_PKTINFO control message was not received",
                      pref);
        ret = TE_EFAIL;
    }

    if (pkt_info6 != NULL && !exp_info6)
    {
        ERROR_VERDICT("%sIPV6_PKTINFO control message was obtained "
                      "unexpectedly", pref);
        ret = TE_EFAIL;
    }
    else if (pkt_info6 == NULL && exp_info6)
    {
        ERROR_VERDICT("%sIPV6_PKTINFO control message was not received",
                      pref);
        ret = TE_EFAIL;
    }

cleanup:

    sockts_release_msghdr(&msg);
    return ret;
}
