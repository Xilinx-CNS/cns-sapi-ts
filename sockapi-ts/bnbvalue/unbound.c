/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Bad Parameters and Boundary Values
 */

/** @page bnbvalue-unbound Behavior of unbound socket
 *
 * @objective Check that just-created socket is
 *            correctly handled by various functions.
 *
 * @type conformance
 *
 * @param env           Testing environment:
 *                      - @ref arg_types_env_iut_only
 * @param sock_type     Socket type used in the test
 * @param is_iomux      Is the function we are testing iomux or not.
 * @param func          Non-iomux function to check:
 *                      - @ref arg_types_send_func_with_sys (excluding
 *                        @b od_send_raw())
 *                      - @ref arg_types_recv_func_with_sys
 * @param iomux         Type of I/O Multiplexing function. Only
 *                      specified when @p is_iomux is @c TRUE.
 * @param sys_call      Whether system provided @p func function
 *                      should be used instead of vendor-specific one
 *                      (This parameter only has sense when we have
 *                      alternative TCP/IP stack that provides
 *                      socket API, along with system "libc" library)
 *                      Set it to TRUE when you want to use @p func
 *                      from "libc".
 * @param domain        @c PF_INET or @c PF_INET6
 *
 * @par Scenario:
 *
 * @author Nikita Rastegaev <Nikita.Rastegaev@oktetlabs.ru>
 */

#define TE_TEST_NAME  "bnbvalue/unbound"

#include "sockapi-test.h"
#include "tapi_cfg.h"
#include "tapi_cfg_base.h"
#include "iomux.h"

#define DATA_BULK           1024

int
main(int argc, char *argv[])
{
    int                     iut_s = -1;
    rcf_rpc_server         *pco_iut = NULL;
    te_bool                 is_iomux;
    iomux_call_type         iomux;
    const char             *func;
    te_bool                 sys_call = FALSE;
    rpc_socket_type         sock_type;
    rpc_socket_domain       domain;
    char                    buf[DATA_BULK];
    struct rpc_iovec        iov[] = {
            { buf, sizeof(buf), sizeof(buf) }
    };
    struct rpc_mmsghdr      mmsg = {
        {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = iov,
            .msg_iovlen = sizeof(iov) / sizeof(iov[0]),
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
            .msg_rnamelen = 0,
            .msg_riovlen = sizeof(iov) / sizeof(iov[0]),
            .msg_cmsghdr_num = 0,
            .msg_flags_mode = RPC_MSG_FLAGS_SET_CHECK
        },
        .msg_len = 0
    };
    struct rpc_msghdr      *msg = &mmsg.msg_hdr;
    tarpc_timeval           tv = { 1, 0 };
    tarpc_timeval           opt_val;
    iomux_evt_fd            event;
    tarpc_timeval           timeout = { 0, 0 };
    int                     ret;
    te_bool                 supported = FALSE;

    /* Test preambule */
    TEST_START;
    TEST_GET_BOOL_PARAM(is_iomux);
    if (is_iomux)
    {
        TEST_GET_BOOL_PARAM(sys_call);
        TEST_GET_IOMUX_FUNC(iomux);
    }
    else
        TEST_GET_STRING_PARAM(func);
    TEST_GET_PCO(pco_iut);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOMAIN(domain);

    if (!is_iomux && strcmp(func, "template_send") == 0)
        sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create socket @p iut_s of type @p sock_type on IUT.");
    iut_s = rpc_socket(pco_iut, domain, sock_type, RPC_PROTO_DEF);

    TEST_STEP("Set @c RCVTIMEO socket option in order to test blocking read "
              "functions.");
    opt_val = tv;
    RPC_AWAIT_IUT_ERROR(pco_iut);
    ret = rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVTIMEO, &opt_val);
    if (ret != 0)
    {
        TEST_VERDICT("setsockopt(SO_RCVTIMEO) failed with "
                     "errno %s", errno_rpc2str(RPC_ERRNO(pco_iut)));
    }

#define CALL_CHECK_RC_WRAP(func__, rc__, errno__, params__...) \
    do {                                                                \
        supported = TRUE;                                               \
        TAPI_CALL_CHECK_RC(pco_iut, func__, rc__, errno__, params__);   \
    } while (0)

#define CHECK_FUNCTION(func_, rc_, errno_, params_...) \
    do {                                                                \
        pco_iut->_errno = 0;                                            \
        if (strcmp(func, #func_) == 0)                                  \
            CALL_CHECK_RC_WRAP(func_, rc_, errno_, params_);            \
    } while (0)

    TEST_STEP("If @p sys_call parameter is @c TRUE, set use_libc_once to call "
              "libc function for the next IUT RPC call");
    pco_iut->use_libc_once = sys_call;

    TEST_STEP("Depending on @p is_iomux parameter call @p func or "
              "@p iomux function with @p iut_s socket.");
    TEST_STEP("Check return code and errno.");
    if (!is_iomux)
    {
        if (sock_type == RPC_SOCK_STREAM)
        {
            CHECK_FUNCTION(read, -1, RPC_ENOTCONN, iut_s,
                           buf, sizeof(buf));
            if (strcmp(func, "sys_read") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(read, -1, RPC_ENOTCONN, iut_s,
                                   buf, sizeof(buf));
            }
            CHECK_FUNCTION(readv, -1, RPC_ENOTCONN, iut_s, iov,
                           sizeof(iov) / sizeof(iov[0]));
            if (strcmp(func, "sys_readv") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(readv, -1, RPC_ENOTCONN, iut_s,
                                   iov, sizeof(iov) / sizeof(iov[0]));
            }
            CHECK_FUNCTION(recv, -1, RPC_ENOTCONN, iut_s,
                           buf, sizeof(buf), 0);
            CHECK_FUNCTION(recvfrom, -1, RPC_ENOTCONN, iut_s, buf,
                           sizeof(buf), 0, NULL, NULL);
            CHECK_FUNCTION(recvmsg, -1, RPC_ENOTCONN, iut_s, msg, 0);
            CHECK_FUNCTION(write, -1, RPC_EPIPE, iut_s, buf, sizeof(buf));
            if (strcmp(func, "sys_write") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(write, -1, RPC_EPIPE, iut_s,
                                   buf, sizeof(buf));
            }
            CHECK_FUNCTION(writev, -1, RPC_EPIPE, iut_s, iov,
                           sizeof(iov) / sizeof(iov[0]));
            if (strcmp(func, "sys_writev") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(writev, -1, RPC_EPIPE, iut_s,
                                   iov, sizeof(iov) / sizeof(iov[0]));
            }
            CHECK_FUNCTION(send, -1, RPC_EPIPE, iut_s, buf, sizeof(buf), 0);
            CHECK_FUNCTION(od_send, -1, RPC_EPIPE, iut_s, buf, sizeof(buf),
                           0);
            CHECK_FUNCTION(od_send_raw, -1, RPC_EPIPE, iut_s, buf,
                           sizeof(buf), 0);
            CHECK_FUNCTION(sendto, -1, RPC_EPIPE, iut_s, buf,
                           sizeof(buf), 0, NULL);
            CHECK_FUNCTION(sendmsg, -1, RPC_EPIPE, iut_s, msg, 0);
            if (strcmp(func, "sendmmsg") == 0)
                CALL_CHECK_RC_WRAP(sendmmsg_alt, -1,
                                   RPC_EPIPE, iut_s, &mmsg, 1, 0);
            if (strcmp(func, "onload_zc_send") == 0)
                CALL_CHECK_RC_WRAP(simple_zc_send, -1, RPC_EPIPE,
                                   iut_s, msg, 0);
            if (strcmp(func, "onload_zc_send_user_buf") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_zc_send_user_buf, -1, RPC_EPIPE,
                                   iut_s, msg, 0);
            }
            if (strcmp(func, "recvmmsg") == 0)
                CALL_CHECK_RC_WRAP(recvmmsg_alt, -1,
                                   RPC_ENOTCONN, iut_s, &mmsg, 1, 0, NULL);
            if (strcmp(func, "onload_zc_recv") == 0)
                CALL_CHECK_RC_WRAP(simple_zc_recv, -1, RPC_ENOTCONN,
                                   iut_s, msg, 0);
            if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_hlrx_recv_zc, -1, RPC_ENOTCONN,
                                   iut_s, msg, 0, TRUE);
            }
            if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_hlrx_recv_copy, -1, RPC_ENOTCONN,
                                   iut_s, msg, 0, TRUE);
            }
            CHECK_FUNCTION(template_send, -1, RPC_ENOTCONN, iut_s,
                           iov, sizeof(iov) / sizeof(iov[0]),
                           sizeof(iov) / sizeof(iov[0]), 0);
        }
        else
        {
            CHECK_FUNCTION(read, -1, RPC_EAGAIN,  iut_s, buf, sizeof(buf));
            CHECK_FUNCTION(readv, -1, RPC_EAGAIN, iut_s, iov,
                           sizeof(iov) / sizeof(iov[0]));
            if (strcmp(func, "sys_read") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(read, -1, RPC_EAGAIN, iut_s,
                                   buf, sizeof(buf));
            }
            if (strcmp(func, "sys_readv") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(readv, -1, RPC_EAGAIN, iut_s,
                                   iov, sizeof(iov) / sizeof(iov[0]));
            }
            CHECK_FUNCTION(recv, -1, RPC_EAGAIN, iut_s,
                           buf, sizeof(buf), 0);
            CHECK_FUNCTION(recvfrom, -1, RPC_EAGAIN, iut_s, buf,
                           sizeof(buf), 0, NULL, NULL);
            CHECK_FUNCTION(recvmsg, -1, RPC_EAGAIN, iut_s, msg, 0);
            if (strcmp(func, "recvmmsg") == 0)
                CALL_CHECK_RC_WRAP(recvmmsg_alt, -1,
                                   RPC_EAGAIN, iut_s, &mmsg, 1, 0, NULL);
            CHECK_FUNCTION(write, -1, RPC_EDESTADDRREQ, iut_s, buf,
                           sizeof(buf));
            CHECK_FUNCTION(writev, -1, RPC_EDESTADDRREQ, iut_s, iov,
                           sizeof(iov) / sizeof(iov[0]));
            if (strcmp(func, "sys_write") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(write, -1, RPC_EDESTADDRREQ, iut_s,
                                   buf, sizeof(buf));
            }
            if (strcmp(func, "sys_writev") == 0)
            {
                pco_iut->use_libc_once = TRUE;
                CALL_CHECK_RC_WRAP(writev, -1, RPC_EDESTADDRREQ, iut_s,
                                   iov, sizeof(iov) / sizeof(iov[0]));
            }
            CHECK_FUNCTION(send, -1, RPC_EDESTADDRREQ, iut_s, buf,
                           sizeof(buf), 0);
            CHECK_FUNCTION(od_send, -1, RPC_EDESTADDRREQ, iut_s, buf,
                           sizeof(buf), 0);
            CHECK_FUNCTION(od_send_raw, -1, RPC_EDESTADDRREQ, iut_s, buf,
                           sizeof(buf), 0);
            CHECK_FUNCTION(sendto, -1, RPC_EDESTADDRREQ, iut_s, buf,
                           sizeof(buf), 0, NULL);
            CHECK_FUNCTION(sendmsg, -1, RPC_EDESTADDRREQ, iut_s, msg, 0);
            if (strcmp(func, "sendmmsg") == 0)
                CALL_CHECK_RC_WRAP(sendmmsg_alt, -1,
                                   RPC_EDESTADDRREQ, iut_s, &mmsg, 1, 0);
            if (strcmp(func, "onload_zc_send") == 0)
                CALL_CHECK_RC_WRAP(simple_zc_send, -1,
                                   RPC_EDESTADDRREQ, iut_s, msg, 0);
            if (strcmp(func, "onload_zc_send_user_buf") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_zc_send_user_buf, -1,
                                   RPC_EDESTADDRREQ, iut_s, msg, 0);
            }
            if (strcmp(func, "onload_zc_recv") == 0)
                CALL_CHECK_RC_WRAP(simple_zc_recv, -1, RPC_EAGAIN,
                                   iut_s, msg, 0);
            if (strcmp(func, "onload_zc_hlrx_recv_zc") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_hlrx_recv_zc, -1, RPC_EAGAIN,
                                   iut_s, msg, 0, TRUE);
            }
            if (strcmp(func, "onload_zc_hlrx_recv_copy") == 0)
            {
                CALL_CHECK_RC_WRAP(simple_hlrx_recv_copy, -1, RPC_EAGAIN,
                                   iut_s, msg, 0, TRUE);
            }
            CHECK_FUNCTION(template_send, -1, RPC_EAGAIN, iut_s,
                           iov, sizeof(iov) / sizeof(iov[0]),
                           sizeof(iov) / sizeof(iov[0]), 0);
        }
    }
    else
    {
        int expected_rc = IOMUX_IS_POLL_LIKE(iomux) ? 1 :
                          ((sock_type == RPC_SOCK_STREAM) ? 2 : 1);
        supported = TRUE;
        event.fd = iut_s;
        event.events = EVT_RDWR;
        rc = iomux_call(iomux, pco_iut, &event, 1, &timeout);
        if (rc != expected_rc)
        {
            TEST_VERDICT("Function '%s' returns %d, but "
                         "expected to return %d",
                         iomux_call_en2str(iomux), rc, expected_rc);
        }

        TEST_STEP("For iomux functions also check returned events.");
        if (event.events != EVT_RDWR)
            TEST_VERDICT("Function '%s' returns wrong events: %s",
                         iomux_call_en2str(iomux),
                         iomux_event_rpc2str(event.events));
    }

    if (!supported)
        TEST_VERDICT("Function '%s' isn't supported by the test with "
                     "current parameters", func);

    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    TEST_END;
}
