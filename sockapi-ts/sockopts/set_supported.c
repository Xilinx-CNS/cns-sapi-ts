/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-set_supported Checking for support of the @b setsockopt operation
 *
 * @objective Check that @b setsockopt() of the option level/name is
 *            supported in expected way for specified type of socket.
 *            Do not explore option semantic.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param domain        Domain to be used for socket creation
 * @param sock_type     @c SOCK_DGRAM or @c SOCK_STREAM
 * @param opt_level     Level where option can be used
 * @param opt_name      Option to be tested
 * @param exp_errno     Expected errno value
 *
 * @par Test sequence:
 * -# Create a socket @p iut_fd from @p domain, @p sock_type type
 *    on @p pco_iut;
 * -# Call @b setsockopt() with appropriate @p opt_name and @p opt_level
 * -# Check that @b getsockopt() returns @p exp_errno;
 * -# Close @p iut_fd.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/set_supported"

#include "sockapi-test.h"
#include <netinet/ip.h>


int
main(int argc, char *argv[])
{
    const struct sockaddr *mcast_addr = NULL;
    const struct sockaddr *iut_addr = NULL;
    rcf_rpc_server     *pco_iut = NULL;
    rpc_socket_domain   domain;
    rpc_socket_type     sock_type;
    rpc_socklevel       opt_level;
    rpc_sockopt         opt_name;
    te_bool             is_pipe;
    te_bool             write_end;

    int                 iut_fd = -1;
    int                 pipefds[2] = {-1, -1};

    rpc_sockopt_value   opt_val;


    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_iut, mcast_addr);
    TEST_GET_SOCKOPT(opt_name);
    TEST_GET_BOOL_PARAM(is_pipe);
    if (!is_pipe)
    {
        TEST_GET_DOMAIN(domain);
        TEST_GET_SOCK_TYPE(sock_type);
    }
    else
        TEST_GET_BOOL_PARAM(write_end);

    opt_level = rpc_sockopt2level(opt_name);

    memset(&opt_val, 0, sizeof(opt_val));
    switch (opt_name)
    {
        case RPC_SO_SNDBUF:
        case RPC_SO_RCVBUF:
            opt_val.v_int = 1000;
            break;

        case RPC_SO_SNDLOWAT:
        case RPC_SO_RCVLOWAT:
            opt_val.v_int = 1;
            break;

        case RPC_TCP_KEEPCNT:
        case RPC_TCP_KEEPIDLE:
        case RPC_TCP_KEEPINTVL:
        case RPC_TCP_SYNCNT:
        case RPC_IP_MULTICAST_TTL:
        case RPC_IP_TTL:
            opt_val.v_int = 10;
            break;

        case RPC_TCP_MAXSEG:
            opt_val.v_int = 500;
            break;

        case RPC_IPV6_ADDRFORM:
            opt_val.v_int = AF_INET;
            break;

        case RPC_IP_ADD_MEMBERSHIP:
        case RPC_IP_DROP_MEMBERSHIP:
        case RPC_IP_MULTICAST_IF:
            opt_val.v_mreqn.type = OPT_MREQN;
            memcpy(&opt_val.v_mreqn.multiaddr,
                   te_sockaddr_get_netaddr(mcast_addr),
                   sizeof(opt_val.v_mreqn.multiaddr));
            memcpy(&(opt_val.v_mreqn.address),
                   te_sockaddr_get_netaddr(iut_addr),
                   sizeof(opt_val.v_mreqn.address));
            break;

        case RPC_IP_ADD_SOURCE_MEMBERSHIP:
        case RPC_IP_DROP_SOURCE_MEMBERSHIP:
        case RPC_IP_BLOCK_SOURCE:
        case RPC_IP_UNBLOCK_SOURCE:
            opt_val.v_mreq_source.type =
                OPT_MREQ_SOURCE;
            memcpy(&opt_val.v_mreq_source.multiaddr,
                   te_sockaddr_get_netaddr(mcast_addr),
                   sizeof(opt_val.v_mreq_source.multiaddr));
            memcpy(&(opt_val.v_mreq_source.interface),
                   te_sockaddr_get_netaddr(iut_addr),
                   sizeof(opt_val.v_mreq_source.interface));
            memcpy(&(opt_val.v_mreq_source.sourceaddr),
                   te_sockaddr_get_netaddr(iut_addr),
                   sizeof(opt_val.v_mreq_source.sourceaddr));
            break;

        default:
            ;
    }

    if (!is_pipe)
        iut_fd = rpc_socket(pco_iut, domain, sock_type,
                            RPC_PROTO_DEF);
    else
    {
        rpc_pipe(pco_iut, pipefds);
        iut_fd = write_end ? pipefds[1] : pipefds[0];
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    if (opt_name == RPC_SO_BINDTODEVICE)
        rc = rpc_setsockopt_raw(pco_iut, iut_fd, opt_name,
                                &opt_val, IFNAMSIZ);
    else if (opt_name == RPC_IP_OPTIONS)
    {
        uint8_t buf[] = { IPOPT_NOP, IPOPT_NOP, IPOPT_NOP, IPOPT_EOL };

        rc = rpc_setsockopt_raw(pco_iut, iut_fd, opt_name,
                                buf, sizeof(buf));
    }
    else
        rc = rpc_setsockopt(pco_iut, iut_fd, opt_name, &opt_val);

    if (rc != 0)
    {
        int err = RPC_ERRNO(pco_iut);

        TEST_VERDICT("setsockopt(%s, %s) unexpectedly failed with errno "
                     "%s", socklevel_rpc2str(opt_level),
                     sockopt_rpc2str(opt_name), errno_rpc2str(err));
    }
    TEST_SUCCESS;

cleanup:
    if (!is_pipe)
        CLEANUP_RPC_CLOSE(pco_iut, iut_fd);
    else
    {
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
        CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);
    }
    TEST_END;
}

