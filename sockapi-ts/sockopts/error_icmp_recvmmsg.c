/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 */

/** @page sockopts-error_icmp_recvmmsg Usage of SO_ERROR socket option after reporting the pending error from recvmmsg function
 *
 * @objective Check that @b recvmmsg() function reports about pending
 *            errors received by incoming ICMP messages, and that
 *            the value of @c SO_ERROR socket option is reset to zero
 *            after reporting it with @b recvmmsg() function.
 *
 * @type conformance
 *
 * @param env               Testing environments:
 *                          - @ref arg_types_env_peer2peer
 *                          - @ref arg_types_env_peer2peer_tst
 *                          - @ref arg_types_env_peer2peer_ipv6
 *                          - @ref arg_types_env_peer2peer_tst_ipv6
 * @param ip_recverr        Use @c IP_RECVERR option if @c TRUE
 * @param icmp_type         Type of @b ICMP message to check
 * @param icmp_code         Code of @b ICMP message to check
 * @param exp_errno         Expected error code
 * @param send_error        Send @b ICMP message:
 *                          - @b before
 *                          - @b during
 *                          - @b after
 * @param vlen              @p vlen value for @b rpc_recvmmsg_alt()
 * @param timeout           @p timeout value for @b rpc_recvmmsg_alt()
 * @param pack_num          Number of packets to send
 * @param data_size         Length of each packet
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/error_icmp_recvmmsg"

#include "sockapi-test.h"

#include <linux/types.h>
#include <linux/errqueue.h>

#include "tapi_tad.h"
#include "tapi_cfg.h"
#include "tapi_eth.h"
#include "tapi_icmp.h"
#include "icmp_send.h"

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#define MIN_BUF_LEN 256
#define MAX_BUF_LEN 1024
#define MAX_IOV_LEN 16

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;

    int             iut_s = -1;
    int             tst_s = -1;

    rpc_errno          exp_errno;
    uint8_t            icmp_type;
    uint8_t            icmp_code;
    te_bool            ip_recverr;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *iut_lladdr;

    const struct if_nameindex *tst_if;
    const struct sockaddr     *tst_addr;
    const struct sockaddr     *tst_lladdr;

    int                    opt_val;

    csap_handle_t  tst_icmp_csap = CSAP_INVALID_HANDLE;
    asn_value     *icmp_pkt = NULL;
    int            ret;
    int            timeout;
    int            data_size;
    int            vlen;
    int            pack_num;
    int            i;

    ssize_t          buf_len[RCF_RPC_MAX_MSGHDR];
    int              iov_len[RCF_RPC_MAX_MSGHDR];
    size_t           tmp;
    char             buffer[MAX_BUF_LEN];
    
    struct tarpc_timespec     to;

#define BUF_SIZE 100
    unsigned char    pkt_buf[BUF_SIZE] = {0, };

    struct rpc_mmsghdr mmsghdr[RCF_RPC_MAX_MSGHDR];
    rpc_msghdr        *msghdr;

    const char        *send_error;
    te_bool            use_wildcard;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_LINK_ADDR(iut_lladdr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(tst_lladdr);
    TEST_GET_IF(tst_if);
    TEST_GET_INT_PARAM(icmp_type);
    TEST_GET_INT_PARAM(icmp_code);
    TEST_GET_ERRNO_PARAM(exp_errno);
    TEST_GET_BOOL_PARAM(ip_recverr);
    TEST_GET_STRING_PARAM(send_error);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_INT_PARAM(pack_num);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(vlen);

    if (data_size > MAX_BUF_LEN)
        TEST_FAIL("data_size parameter is too big, increase MAX_BUF_LEN");

    /*
     * Bug 44608: Onload has different behaviour on UDP sockets bound to
     * INADDR_ANY and to TST address, even when sending/receiving to/from
     * TST only. So we should use wildcard addresses when it possible.
     */
    use_wildcard = TRUE;
    if (ip_recverr == FALSE)
    {
        if (iut_addr->sa_family == AF_INET)
        {
            if ((icmp_type == ICMP_DEST_UNREACH /* 3 */ &&
                    (icmp_code == ICMP_PROT_UNREACH /* 2 */ ||
                     icmp_code == ICMP_PORT_UNREACH /* 3 */)) ||
                icmp_type == ICMP_PARAMETERPROB /* 12 */)
            {
                use_wildcard = FALSE;
            }
        }
        else
        {
            if ((icmp_type == ICMP6_DST_UNREACH /* 1 */ &&
                    icmp_code == ICMP6_DST_UNREACH_NOPORT /* 4 */) ||
                icmp_type == ICMP6_PARAM_PROB /* 4 */)
            {
                use_wildcard = FALSE;
            }
        }
    }

    /* Prepare mmsghdr */
    memset(mmsghdr, 0, sizeof(mmsghdr));
    for (i = 0; i < vlen; i++)
    {
        msghdr = &mmsghdr[i].msg_hdr;

        msghdr->msg_namelen = sizeof(struct sockaddr_storage);
        CHECK_NOT_NULL(msghdr->msg_name =
                        te_make_buf_min(msghdr->msg_namelen, &tmp));
        msghdr->msg_rnamelen = tmp;

        iov_len[i] = rand_range(1, MAX_IOV_LEN);
        buf_len[i] = rand_range(data_size, MAX_BUF_LEN);
        msghdr->msg_iov = sockts_make_iovec(&iov_len[i], &buf_len[i]);
        msghdr->msg_iovlen = msghdr->msg_riovlen = iov_len[i];

        msghdr->msg_controllen = 0;
        msghdr->msg_control = NULL;
    }

    TEST_STEP("Create CSAP for sending ICMP messages from @b Tester.");
    rc = tapi_udp_ip_icmp_ip_eth_csap_create(pco_tst->ta, 0,
             tst_if->if_name, TAD_ETH_RECV_DEF | TAD_ETH_RECV_NO_PROMISC,
             (uint8_t *)tst_lladdr->sa_data,
             (uint8_t *)iut_lladdr->sa_data,
             tst_addr, iut_addr,
             iut_addr, tst_addr,
             iut_addr->sa_family, &tst_icmp_csap);
    if (rc != 0)
    {
        TEST_FAIL("Cannot create Ethernet CSAP on Tester");
    }

    TEST_STEP("Create a connection of @c SOCK_DGRAM type between @b IUT and "
              "@p Tester.");
    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, use_wildcard);

    TEST_STEP("Enable @c IP_RECVERR/IPV6_RECVERR socket option on @p iut_s if "
              "@p ip_recverr is @c TRUE.");
    if (ip_recverr)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        opt_val = 1;
        ret = rpc_setsockopt(pco_iut, iut_s, iut_addr->sa_family == AF_INET ?
                                             RPC_IP_RECVERR : RPC_IPV6_RECVERR,
                             &opt_val);
        if (ret != 0)
        {
            TEST_VERDICT("setsockopt(IP%s_RECVERR) failed with errno %s",
                         iut_addr->sa_family == AF_INET6 ? "V6" : "",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
    }

    TEST_STEP("Prepare ICMP message to send from @b Tester CSAP to @b IUT "
              "with speciefied @p icmp_type and @p icmp_code fields and "
              "containing as the payload IP datagram with UDP content that "
              "could be sent from @b IUT to @b Tester.");
    rc = tapi_icmp_error_msg_pdu((uint8_t *)tst_lladdr->sa_data,
                                 (uint8_t *)iut_lladdr->sa_data,
                                 tst_addr, iut_addr,
                                 icmp_type, icmp_code,
                                 iut_addr, tst_addr,
                                 IPPROTO_UDP, pkt_buf, 10,
                                 iut_addr->sa_family, &icmp_pkt);

#define SEND_ERROR(when) \
    do {                                                             \
        if (strcmp(send_error, when) == 0 &&                         \
            tapi_tad_trsend_start(pco_tst->ta, 0, tst_icmp_csap,     \
                                  icmp_pkt, RCF_MODE_BLOCKING) != 0) \
        {                                                            \
            TEST_FAIL("Cannot send a frame from the CSAP");          \
        }                                                            \
                                                                     \
        SLEEP(1);                                                    \
    } while(0);

    TEST_STEP("Send ICMP message if @p send_error is @b before.");
    SEND_ERROR("before");

    TEST_STEP("Call @b rpc_recvmmsg_alt() with @c RCF_RPC_CALL on @b IUT with "
              "@p vlen and @p timeout.");
    to.tv_sec = timeout;
    to.tv_nsec = 0;
    pco_iut->op = RCF_RPC_CALL;
    rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, 0, &to);

    TAPI_WAIT_NETWORK;
    TEST_STEP("Send ICMP message if @p send_error is @b during.");
    SEND_ERROR("during");

    TEST_STEP("Send @p pack_num packets from @b Tester to @b IUT where "
              "each packet has @p data_size length.");
    for (i = 0; i < pack_num; i++)
    {
        RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
        SLEEP(1);
    }

    TAPI_WAIT_NETWORK;
    TEST_STEP("Send ICMP message if @p send_error is @b after.");
    SEND_ERROR("after");

    SLEEP(timeout - pack_num + 1);

    TEST_STEP("Send single packet from @b Tester to @b IUT with "
              "@p data_size length.");
    RPC_WRITE(rc, pco_tst, tst_s, buffer, data_size);
    TAPI_WAIT_NETWORK;

    TEST_STEP("Call @b rpc_recvmmsg_alt() with @c RCF_RPC_WAIT on @b IUT and "
              "check return code @p rc in next steps.");
    RPC_AWAIT_IUT_ERROR(pco_iut);
    pco_iut->op = RCF_RPC_WAIT;
    rc = rpc_recvmmsg_alt(pco_iut, iut_s, mmsghdr, vlen, 0, &to);

    /* In this case the last packet should be received */
    if (exp_errno == 0)
        pack_num++;

    if (strcmp(send_error, "after") == 0 || exp_errno == 0)
    {
        TEST_STEP("In case of @p send_error is 'after' or @p exp_errno is "
                  "zero:");
        TEST_SUBSTEP("check that @p rc is equal to @p pack_num if @p exp_errno "
                     "is 0 or @p rc is equal to @p (pack_num + 1) if @p "
                     "exp_errno is non-zero;");
        if (rc == -1)
        {
            TEST_VERDICT("recvmmsg() functon unexpectedly failed with "
                         "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
        }
        if (rc != pack_num)
        {
            RING("%d packets got, %d packets expected", rc, pack_num);
            TEST_VERDICT("recvmmsg() returned unexpected number "
                         "of packets");
        }

        TEST_SUBSTEP("when @p send_error is 'after' and @p exp_errno is "
                     "non-zero call @c getsockopt(SO_ERROR) on @p iut_s and "
                     "check that @p opt_val is equal to @p exp_errno;");
        if (strcmp(send_error, "after") == 0 && exp_errno != 0)
        {
            rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
            if (opt_val != (int)exp_errno)
            {
                TEST_VERDICT("SO_ERROR socket option has unexpected value "
                             "%s when ICMP error (%d,%d) was sent by peer",
                             errno_rpc2str(opt_val),
                             icmp_type, icmp_code);
            }
        }
        TEST_SUBSTEP("call @c getsockopt(SO_ERROR) on @p iut_s and check "
                     "that @p opt_val is equial to zero;");
        rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
        if (opt_val != 0)
        {
            TEST_VERDICT("SO_ERROR socket option has unexpected value "
                         "%s when ICMP error (%d,%d) was sent by peer",
                         errno_rpc2str(RPC_ERRNO(pco_iut)),
                         icmp_type, icmp_code);
        }

        TEST_SUBSTEP("test passed if all checks above are successful.");
        TEST_SUCCESS;
    }

    TEST_STEP("Otherwise check that @p rc is equal @c -1 and @b errno "
              "is equal to @p exp_errno.");
    if (rc == pack_num)
    {
        TEST_VERDICT("Receive functon returned success instead of failure");
    }
    else if (rc != -1)
    {
        RING("expected result -1, but %d packets got", rc);
        TEST_VERDICT("recvmmsg() function unexpectedly successeed");
    }

    CHECK_RPC_ERRNO(pco_iut, exp_errno,                    
                    "recvmmsg() returned -1 when there is a "
                    "pending ICMP error (%d,%d) on the socket, but",
                    icmp_type, icmp_code);


    TEST_STEP("Check that @c SO_ERROR on @p iut_s is reset to zero.");
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_ERROR, &opt_val);
    if (opt_val != 0)
    {
        TEST_VERDICT("SO_ERROR socket option is not reset to zero after "
                     "reporting the error in recvmmsg()");
    }
#undef SEND_ERROR

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_tad_csap_destroy(pco_tst->ta, 0, tst_icmp_csap));

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    asn_free_value(icmp_pkt);

    TEST_END;
}
