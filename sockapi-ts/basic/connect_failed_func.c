/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Basic Socket API
 */

/** @page basic-connect_failed_func Call function after failed connect
 *
 * @objective Check that @b listen(), @b bind(), @b getsockname() and 
 *            @b getpeername() work correctly when it is called after
 *            failed connect.
 *
 * @param env   Testing environment:
 *              - @ref arg_types_env_peer2peer_fake
 * @param howto How connect() function fails:
 *              - port: incorrect destination port
 *              - host: unknown destination address
 *              - timeout: connection attempt is timed out
 * @param bind  How to bind IUT socket:
 *              - no: do not bind
 *              - unspecified: @b bind() to unspecified port
 *              - specified: @b bind() to specified port
 * @param func  Tested function:
 *              - bind()
 *              - listen()
 *              - getsockname()
 *              - getpeername()
 *              - connect()
 *
 * @par Scenario:
 *
 * -# Create socket @p iut_s on @p pco_iut of the @c SOCK_STREAM type.
 * -# @b bind() @p iut_s according to the @p bind parameter.
 * -# Call @b connect() on @p iut_s socket with unused port and check that
 *    it fails.
 * -# Call @p func on @p iut_s socket according to the @p func parameter.
 * -# If @p paremeter is @c listen check that obtained state of @p iut_s is
 *    the @c STATE_LISTENING. In other case check errors.
 * -# If @p bind parameter is not @p specified, check that @p func call
 *    changed the port this socket is bound to.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "basic/connect_failed_func"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

/* Timeout should be >3 min */
#define TST_CONNECT_TIMEOUT       (7 * 60 * 1000)

/* Wait for EHOSTUNREASH not more then 15 seconds */
#define WAITHOSTUNREACH 15

int
main(int argc, char *argv[])
{
    rcf_rpc_server            *pco_iut = NULL;
    rcf_rpc_server            *pco_tst = NULL;

    const struct if_nameindex *iut_if = NULL;

    const struct sockaddr     *iut_addr;
    const struct sockaddr     *tst_addr; 
    const struct sockaddr     *fake_addr;
    struct sockaddr_storage    aux_addr;

    struct sockaddr_storage    bind_addr1;
    struct sockaddr_storage    bind_addr2;
    socklen_t                  bind_addrlen;

    te_bool                    arp_entry_added = FALSE;
    const void                *alien_link_addr;

    int                        iut_s = -1;
    const char                *bind;
    const char                *howto;
    const char                *func;

    struct sockaddr_storage    ret_addr;
    socklen_t                  ret_addrlen;

    int                        ret;
    int                        counter = WAITHOSTUNREACH;
    te_bool                    op_done = FALSE;
    uint64_t                   first_duration;
    uint64_t                   second_duration;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_ADDR(pco_tst, fake_addr);
    TEST_GET_LINK_ADDR(alien_link_addr);
    TEST_GET_STRING_PARAM(bind);
    TEST_GET_STRING_PARAM(howto);
    TEST_GET_STRING_PARAM(func);
    TEST_GET_IF(iut_if);

    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM, RPC_IPPROTO_TCP);

    memcpy(&aux_addr, iut_addr, te_sockaddr_get_size(iut_addr));
    if (strcmp(bind,"unspecified") == 0)
        te_sockaddr_set_port(SA(&aux_addr), 0);
    if (strcmp(bind, "no") != 0)
        rpc_bind(pco_iut, iut_s, SA(&aux_addr)); 
    
    if(strcmp(howto,"timeout") == 0)
    {
        if (tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                            fake_addr, CVT_HW_ADDR(alien_link_addr),
                            TRUE) != 0)
            TEST_FAIL("Cannot add ARP entry to imitate server "
                      "problems");
        arp_entry_added = TRUE;
        CFG_WAIT_CHANGES;
        pco_iut->timeout = TST_CONNECT_TIMEOUT;
    }

    RPC_AWAIT_IUT_ERROR(pco_iut);
    rc = rpc_connect(pco_iut, iut_s,
                     strcmp(howto,"port") == 0 ? tst_addr : fake_addr);
    if (rc != -1)
        TEST_FAIL("connect() returns %d instead of -1 when "
                      "server can not satisfy connection request", rc);
    first_duration = pco_iut->duration;

    if (strcmp(howto,"port") == 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                        "connect() on IUT socket failed");
    }
    else if (strcmp(howto, "host") == 0)
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_EHOSTUNREACH,
                        "connect() returns -1, but");
    }
    else
    {
        CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                        "connect() returns -1, but");
    }

    bind_addrlen = sizeof(bind_addr1);
    rpc_getsockname(pco_iut, iut_s, SA(&bind_addr1), &bind_addrlen);
    if (strcmp(bind, "no") == 0)
    {
        if (!te_sockaddr_is_wildcard(SA(&bind_addr1)))
        {
            TEST_VERDICT("Address was not set to wildcard after "
                         "failed connect() without bind()");
        }
    }
    else
    {
        if (te_sockaddrcmp_no_ports(SA(&bind_addr1), bind_addrlen,
                                    SA(&aux_addr), sizeof(aux_addr)) != 0)
        {
            TEST_VERDICT("Address was not set to bound one after "
                         "failed connect()");
        }
    }

    if (strcmp(func, "bind") == 0)
    {
        TAPI_SET_NEW_PORT(pco_iut, &aux_addr);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        ret = rpc_bind(pco_iut, iut_s, SA(&aux_addr)); 
        if (strcmp(bind, "specified") != 0)
        {
            if (ret != 0)
            {
                TEST_VERDICT("bind() after failed connect() on %s "
                             "unexpectedly failed with errno %s",
                             strcmp(bind, "no") == 0 ? "not bound socket" :
                                 "socket bound to wildcard port",
                             errno_rpc2str(RPC_ERRNO(pco_iut)));
            }
        }
        else
        {
            if (rc == -1)
                CHECK_RPC_ERRNO(pco_iut, RPC_EINVAL,
                                "RPC bind on iut_s failed with unexpected"
                                " errno.");
            else
                TEST_FAIL("bind() returns %d instead of -1", rc);
        }
    }
    else if (strcmp(func, "listen") == 0)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_listen(pco_iut, iut_s, SOCKTS_BACKLOG_DEF);
        if (rc < 0)
            TEST_VERDICT("listen() after failed connect() on %s "
                         "unexpectedly failed with errno %s",
                         strcmp(bind, "no") == 0 ? "not bound socket" :
                                 "bound socket",
                         errno_rpc2str(RPC_ERRNO(pco_iut)));
        CHECK_SOCKET_STATE(pco_iut, iut_s, NULL, -1, STATE_LISTENING);
    }
    else if (strcmp(func, "connect") == 0)
    {
        if(strcmp(howto,"timeout") == 0)
        {
            pco_iut->timeout = TST_CONNECT_TIMEOUT;
        }
        pco_iut->op = RCF_RPC_CALL;
        rpc_connect(pco_iut, iut_s,
                    strcmp(howto,"port") == 0 ? tst_addr : fake_addr);
        if (strcmp(howto, "host") == 0)
        {
            while (!op_done)
            {
                SLEEP(1);
                counter--;
                rcf_rpc_server_is_op_done(pco_iut, &op_done);
            }
            if (counter < 0)
            {
                ERROR("Connect() hangs for about %d seconds",
                      WAITHOSTUNREACH - counter);
                RING_VERDICT("Connect() hangs for too much time");
            }
        }

        RPC_AWAIT_IUT_ERROR(pco_iut);
        pco_iut->op = RCF_RPC_WAIT;
        rc = rpc_connect(pco_iut, iut_s,
                         strcmp(howto,"port") == 0 ? tst_addr : fake_addr);
        if (rc != -1)
            TEST_FAIL("connect() returns %d instead of -1 when "
                      "server can not satisfy connection request", rc);

        second_duration = pco_iut->duration;
        RING("The first connect() took %llu microseconds, the "
             "second connect() took %llu microseconds",
             first_duration, second_duration);

        if (first_duration > TST_TIME_INACCURACY ||
            second_duration > TST_TIME_INACCURACY)
        {
            if (first_duration == 0)
                first_duration = 1;
            if (second_duration == 0)
                second_duration = 1;

            if (second_duration / first_duration >= 2)
                RING_VERDICT("The second connect() call takes "
                             "significantly more time than the first one");
            else if (first_duration / second_duration >= 2)
                RING_VERDICT("The second connect() call takes "
                             "significantly less time than the first one");
        }

        if (strcmp(howto,"port") == 0)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_ECONNREFUSED,
                            "connect() on IUT socket failed");
        }
        else if (strcmp(howto, "host") == 0)
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_EHOSTUNREACH,
                            "connect() returns -1, but");
        }
        else
        {
            CHECK_RPC_ERRNO(pco_iut, RPC_ETIMEDOUT,
                            "connect() returns -1, but");
        }
    }
    else if (strcmp(func, "getsockname") == 0)
    {
        ret_addrlen = sizeof(ret_addr);
        rpc_getsockname(pco_iut, iut_s, SA(&ret_addr), &ret_addrlen);

        if (strcmp(bind, "no") != 0)
        {
            if (strcmp(bind, "unspecified") == 0)
                te_sockaddr_clear_port(SA(&ret_addr));
            rc = te_sockaddrcmp(SA(&ret_addr), ret_addrlen,
                                SA(&aux_addr),
                                te_sockaddr_get_size(SA(&aux_addr)));
            if(rc != 0)
            {
                TEST_VERDICT("getsockname() after failed connect() on %s "
                             "returned unexpected address/port",
                             strcmp(bind, "no") == 0 ? "not bound socket" :
                                 "socket bound to wildcard port");
            }
        }
    }
    else
    {
        ret_addrlen = sizeof(ret_addr);
        RPC_AWAIT_IUT_ERROR(pco_iut);
        rc = rpc_getpeername(pco_iut, iut_s, SA(&ret_addr), &ret_addrlen);
        if (rc == -1)
            CHECK_RPC_ERRNO(pco_iut, RPC_ENOTCONN,
                            "getpeername() on IUT socket returned -1, but");
    }
    
    if (strcmp(bind, "specified") != 0)
    {
        bind_addrlen = sizeof(bind_addr1);
        rpc_getsockname(pco_iut, iut_s, SA(&bind_addr2), &bind_addrlen);

        if (strcmp(func, "getpeername") != 0 &&
            strcmp(func, "getsockname") != 0)
        {
            if (te_sockaddr_get_port(SA(&bind_addr1)) == 
                te_sockaddr_get_port(SA(&bind_addr2)))
            {
                TEST_VERDICT("Local port is not updated after "
                             "implicit bind call via %s() function",
                             func);
            }
        }
        if (strcmp(bind, "unspecified") == 0 &&
            memcmp(te_sockaddr_get_netaddr(SA(&bind_addr1)), 
                   te_sockaddr_get_netaddr(SA(&bind_addr2)), 
                   te_netaddr_get_size(iut_addr->sa_family)))
        {
            TEST_VERDICT("getsockname() returned incorrect address "
                         "when bound to specified address and "
                         "unspecified port");
        }
    }

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    if (arp_entry_added &&
        tapi_cfg_del_neigh_entry(pco_iut->ta, iut_if->if_name,
                                 fake_addr) != 0)
    {
        ERROR("Cannot delete ARP entry while cleanup");
        result = EXIT_FAILURE;
    }

    TEST_END;
}
