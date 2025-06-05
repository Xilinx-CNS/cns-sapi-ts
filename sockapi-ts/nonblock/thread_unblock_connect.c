/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * NONBLOCK Requests
 *
 * $Id$
 */

/** @page nonblock-thread_unblock_connect FIONBIO/NONBLOCK from thread when connect() operation is blocked
 *
 * @objective Try @c FIONBIO / @c NONBLOCK from thread
 *            when @b connect() operation is blocked in another thread.
 *
 * @param pco_iut       PCO on IUT
 * @param iut_addr      IUT IP address
 * @param tst_addr      tester IP address
 * @param iut_if        IUT ifnameindex
 * @param alien_hwaddr  invalid MAC address
 * @param nonblock_func Function used to get socket with NONBLOCK flag
 *                      ("fcntl", "ioctl")
 * @param use_libc      Use libc implementation of @b fcntl() or @b ioctl()
 *                      intead of Onload implementaion to set nonblocking state.
 *
 * @par Test sequence:
 * -# Create stream socket @p iut_s on @p pco_iut.
 * -# Run RPC server @p pco_iut_thread in thread on @p pco_iut.
 * -# Bind @p iut_s to @p iut_addr.
 * -# Add invalid static ARP entry for @p tst_addr
 *    with @p alien_hwaddr on @p pco_iut @p iut_if interface.
 * -# Call @b connect(@p iut_s, @p tst_addr, ...) on @p pco_iut_thread.
 * -# Call @b ioctl() or @b fcntl() on @p iut_s socket to set nonblock state
 *    from @p pco_iut_thread.
 * -# Check that @b connect(@p iut_s, ...) on @p pco_iut_thread is not done.
 * -# Check that @b connect(@p iut_s, ...) on @p pco_iut fails
 *    with @b errno EALREADY.
 * -# Destroy rpc server @p pco_iut_thread.
 * -# Remove invalid static ARP entry on @p pco_iut @p iut_if interface
 *
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "nonblock/thread_unblock_connect"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_route_gw.h"

int
main(int argc, char **argv)
{
    rcf_rpc_server                  *pco_iut = NULL;
    rcf_rpc_server                  *pco_tst = NULL;
    rcf_rpc_server                  *pco_iut_thread = NULL;
    const struct if_nameindex       *iut_if;
    const struct sockaddr           *iut_addr;
    const struct sockaddr           *tst_addr;
    const struct sockaddr           *alien_hwaddr;
    int                              iut_s = -1;
    te_bool                          is_done;

    te_bool use_libc = TRUE;
    fdflag_set_func_type_t nonblock_func = UNKNOWN_SET_FDFLAG;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_IF(iut_if);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_LINK_ADDR(alien_hwaddr);
    TEST_GET_FDFLAG_SET_FUNC(nonblock_func);
    TEST_GET_BOOL_PARAM(use_libc);

    CHECK_RC(rcf_rpc_server_thread_create(pco_iut,
                                          "IUT_thread",
                                          &pco_iut_thread));

    iut_s = rpc_socket(pco_iut,
                       rpc_socket_domain_by_addr(iut_addr),
                       RPC_SOCK_STREAM,
                       RPC_IPPROTO_TCP);

    rpc_bind(pco_iut, iut_s, iut_addr);

    CHECK_RC(tapi_update_arp(pco_iut->ta, iut_if->if_name, NULL, NULL,
                             tst_addr, CVT_HW_ADDR(alien_hwaddr),
                             TRUE));

    CFG_WAIT_CHANGES;

    pco_iut_thread->op = RCF_RPC_CALL;
    rpc_connect(pco_iut_thread, iut_s, tst_addr);
    set_sock_non_block(pco_iut, iut_s, nonblock_func == FCNTL_SET_FDFLAG,
                       use_libc, TRUE);
    MSLEEP(10);

    CHECK_RC(rcf_rpc_server_is_op_done(pco_iut_thread, &is_done));
    if (!is_done)
    {
        RPC_AWAIT_IUT_ERROR(pco_iut);
        if (rpc_connect(pco_iut, iut_s, tst_addr) == 0)
            TEST_VERDICT("connect() on non-blocking socket does not fail");
        CHECK_RPC_ERRNO(pco_iut, RPC_EALREADY,
                        "connect() on non-blocking socket failed "
                        "because of invalid static ARP entry");
    }
    else
    {
        pco_iut_thread->op = RCF_RPC_WAIT;
        RPC_AWAIT_IUT_ERROR(pco_iut_thread);
        if (rpc_connect(pco_iut_thread, iut_s, tst_addr) == 0)
        {
            TEST_VERDICT("Unexpected success of connect() to "
                         "unreachable host");
        }
        if (RPC_ERRNO(pco_iut_thread) != RPC_ECONNREFUSED &&
            RPC_ERRNO(pco_iut_thread) != RPC_EINPROGRESS)
        {
            TEST_VERDICT("connect() to unreachable host was made "
                         "non-blocking, but it fails with errno %s "
                         "(neither ECONNREFUSED or EINPROGRESS)",
                         errno_rpc2str(RPC_ERRNO(pco_iut_thread)));
        }
    }

    TEST_SUCCESS;

cleanup:

    if (pco_iut_thread != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_iut_thread));

    CLEANUP_CHECK_RC(tapi_cfg_del_neigh_entry(pco_iut->ta,
                                              iut_if->if_name, tst_addr));
    /* Calling close() on the socket does not really close the socket in
     * this case for OOL. So reboot PCO.
     */
    CLEANUP_CHECK_RC(rcf_rpc_server_restart(pco_iut));

    TEST_END;
}
