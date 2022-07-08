/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * epoll functionality
 */

/** @page epoll-epfd_change_stack Changing home stack of epoll fd
 *
 * @objective Check that epoll functions correctly handle changing of home
 *            stack of epoll fd.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      @ref arg_types_env_peer2peer_2addr
 *                      @ref arg_types_env_peer2peer_2addr_tst
 *                      @ref arg_types_env_peer2peer_2addr_lo
 *                      @ref arg_types_env_peer2peer_2addr_ipv6
 *                      @ref arg_types_env_peer2peer_2addr_tst_ipv6
 *                      @ref arg_types_env_peer2peer_2addr_lo_ipv6.
 * @param sock_type1    Type of the first socket
 * @param sock_type2    Type of the second socket
 * @param data_size     The amount of data to be sent
 * @param iomux         Type of epoll function
 * @param evts1         Events for the first socket. Value is one of
 *                      @c in, @c out or @c inout
 * @param evts2         Events for the second socket. Value is one of
 *                      @c in, @c out or @c inout
 * @param do_modify     Modify the second socket before removing
 * @param evts_mod      Events for modifying for the second socket
 *
 * @par Test sequence:
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "epoll/epfd_change_stack"

#include "sockapi-test.h"
#include "epoll_common.h"
#include "iomux.h"
#include "tapi_mem.h"

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;

    const struct sockaddr  *iut_addr1 = NULL;
    const struct sockaddr  *tst_addr1 = NULL;
    const struct sockaddr  *iut_addr2 = NULL;
    const struct sockaddr  *tst_addr2 = NULL;

    int                     iut_s1 = -1;
    int                     tst_s1 = -1;
    int                     iut_s2 = -1;
    int                     tst_s2 = -1;

    rpc_socket_type         sock_type1 = RPC_SOCK_UNKNOWN;
    rpc_socket_type         sock_type2 = RPC_SOCK_UNKNOWN;

    const char             *evts1;
    const char             *evts2;
    const char             *evts_mod;

    int                     data_size;
    unsigned char          *buffer = NULL;

    int                     epfd = -1;
    struct rpc_epoll_event  events[2];
    int                     maxevents = 2;
    uint32_t                ev1;
    uint32_t                ev2;
    uint32_t                ev_mod;
    uint32_t                exp_ev;

    iomux_call_type         iomux;

    te_bool                 do_modify;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_STRING_PARAM(evts1);
    TEST_GET_STRING_PARAM(evts2);
    TEST_GET_BOOL_PARAM(do_modify);
    if (do_modify)
        TEST_GET_STRING_PARAM(evts_mod);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst, tst_addr1);
    TEST_GET_ADDR(pco_tst, tst_addr2);
    TEST_GET_SOCK_TYPE(sock_type1);
    TEST_GET_SOCK_TYPE(sock_type2);
    TEST_GET_IOMUX_FUNC(iomux);

    PARSE_EVTS(evts1, ev1, exp_ev);
    PARSE_EVTS(evts2, ev2, exp_ev);
    if (do_modify)
        PARSE_EVTS(evts_mod, ev_mod, exp_ev);

    buffer = (unsigned char *)tapi_malloc(data_size);
    te_fill_buf(buffer, data_size);

    TEST_STEP("Create @p socket_type connection between IUT and Tester."
              "@p iut_s1 and @p tst_s1 sockets will be obtained.");
    if (!te_str_is_null_or_empty(pco_iut->nv_lib))
    {
        rpc_onload_set_stackname(pco_iut,
                                 ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL,
                                 "test1");
    }
    GEN_CONNECTION(pco_iut, pco_tst, sock_type1, RPC_PROTO_DEF,
                   iut_addr1, tst_addr1, &iut_s1, &tst_s1);

    TEST_STEP("Change stack name on @p pco_iut if it is not pure "
              "Linux testing.");
    if (!te_str_is_null_or_empty(pco_iut->nv_lib))
    {
        rpc_onload_set_stackname(pco_iut,
                                 ONLOAD_ALL_THREADS,
                                 ONLOAD_SCOPE_GLOBAL,
                                 "test2");
    }
    TEST_STEP("Create @p socket_type connection between IUT and Tester."
              "@p iut_s2 and @p tst_s2 sockets will be obtained.");
    GEN_CONNECTION(pco_iut, pco_tst, sock_type2, RPC_PROTO_DEF,
                   iut_addr2, tst_addr2, &iut_s2, &tst_s2);

    TEST_STEP("Generate @c EPOLLIN event on @p iut_s1 and @p iut_s2.");
    RPC_WRITE(rc, pco_tst, tst_s1, buffer, data_size);
    RPC_WRITE(rc, pco_tst, tst_s2, buffer, data_size);

    TEST_STEP("Create epoll fd and add @p iut_s1 and @p iut_s2 sockets to "
              "it with @p evts1 and @p evts2 events respectively.");
    epfd = rpc_epoll_create(pco_iut, 1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s1, ev1);
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD, iut_s2, ev2);

    TEST_STEP("Call @p iomux() function and check that it returns events "
              "for both sockets.");
    TAPI_WAIT_NETWORK;
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
    if (rc != 2)
    {
        TEST_VERDICT("Incorrect number of events: %d instead of 2", rc);
    }
    else if ((events[0].data.fd != iut_s1 ||
              events[1].data.fd != iut_s2) &&
             (events[0].data.fd != iut_s2 ||
              events[1].data.fd != iut_s1))
    {
        TEST_VERDICT("%s() returned incorrect fds %d, %d instead of "
                     "%d and %d", iomux_call_en2str(iomux),
                     events[0].data.fd, events[1].data.fd,
                     iut_s1, iut_s2);
    }
    else
    {
        te_bool s1_first = (events[0].data.fd == iut_s1) ? TRUE : FALSE;
        if (s1_first)
        {
            if (events[0].events != ev1 || events[1].events != ev2)
                TEST_VERDICT("epoll_wait returned incorrect events");
        }
        else
        {
            if (events[1].events != ev1 || events[0].events != ev2)
                TEST_VERDICT("epoll_wait returned incorrect events");
        }
    }

    TEST_STEP("Delete @p iut_s1 socket from epoll fd.");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL,
                         iut_s1, ev1);
    TEST_STEP("Call @p iomux() and check that it returns events only "
              "for @p iut_s2.");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
    epoll_check_single_event(pco_iut, iomux, rc, events, 1, RPC_EOK,
                             iut_s2, ev2,
                             "The first socket has been just removed "
                             "from to epfd");

    TEST_STEP("If @p do_modify is @c TRUE modify events in epoll fd "
              "for @p iut_s2 to @p evts_mod. Call @p iomux() to check "
              "that it returns only @p evts_mod for @p iut_s2.");
    if (do_modify)
    {
        rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_MOD,
                             iut_s2, ev_mod);

        rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
        epoll_check_single_event(pco_iut, iomux, rc, events, 1, RPC_EOK,
                                 iut_s2, ev_mod,
                                 "After events modification for the second"
                                 " socket ");
    }
    TEST_STEP("Delete @p iut_s2 for epoll fd.");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_DEL,
                         iut_s2, do_modify ? ev_mod : ev2);

    TEST_STEP("Call @p iomux() and check that it returns @c 0.");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
    epoll_check_single_event(pco_iut, iomux, rc, events, 0, RPC_EOK,
                             iut_s2, ev2,
                             "The second socket has been just removed "
                             "from to epfd");

    TEST_STEP("Add @p iut_s1 socket back to epoll fd.");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                         iut_s1, ev1);
    TEST_STEP("Call @b iomux() and check that it returns only @p evts1 "
              "events for @p iut_s1 socket.");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
    epoll_check_single_event(pco_iut, iomux, rc, events, 1, RPC_EOK,
                             iut_s1, ev1,
                             "The first socket has been added "
                             "once again to epfd");
    TEST_STEP("Add @p iut_s2 socket back to epoll fd.");
    rpc_epoll_ctl_simple(pco_iut, epfd, RPC_EPOLL_CTL_ADD,
                         iut_s2, do_modify ? ev_mod : ev2);

    TAPI_WAIT_NETWORK;
    TEST_STEP("Call @b iomux() and check that it returns correct events "
              "for both sockets.");
    rc = iomux_epoll_call(iomux, pco_iut, epfd, events, maxevents, 0);
    if (rc != 2)
    {
        TEST_VERDICT("After adding sockets back: incorrect number of "
                     "events: %d instead of 2", rc);
    }
    else if ((events[0].data.fd != iut_s1 ||
              events[1].data.fd != iut_s2) &&
             (events[0].data.fd != iut_s2 ||
              events[1].data.fd != iut_s1))
    {
        TEST_VERDICT("After adding sockets back: %s() returned incorrect "
                     "fds %d, %d instead of %d and %d",
                     iomux_call_en2str(iomux), events[0].data.fd,
                     events[1].data.fd, iut_s1, iut_s2);
    }
    else
    {
        te_bool s1_first = (events[0].data.fd == iut_s1) ? TRUE : FALSE;
        exp_ev = do_modify ? ev_mod : ev2;
        if (s1_first)
        {
            if (events[0].events != ev1 || events[1].events != exp_ev)
                TEST_VERDICT("After adding sockets back: epoll_wait "
                             "returned incorrect events");
        }
        else
        {
            if (events[1].events != ev1 || events[0].events != exp_ev)
                TEST_VERDICT("After adding sockets back: epoll_wait "
                             "returned incorrect events");
        }
    }
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, epfd);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s1);
    CLEANUP_RPC_CLOSE(pco_iut, iut_s2);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s1);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s2);

    free(buffer);

    TEST_END;
}
