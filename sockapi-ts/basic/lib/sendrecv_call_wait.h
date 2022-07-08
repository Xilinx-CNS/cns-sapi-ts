/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for tests with blocking send/recv calls 
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 *
 * $Id$
 */

/**
 * Call send/recv with RCF_RPC_CALL.
 *
 * @param   _pco        RPC server
 * @param   _func       send/recv function
 * @param   _is_send    Whether it is send() function
 *                      or not
 * @param   _s          Socket
 * @param   _buf_s      Send buffer
 * @param   _buf_s_size Send buffer size
 * @param   _buf_r      Receive buffer
 * @param   _buf_r_size Receive buffer size
 */
#define CALL_SR_FUNC(_pco, _func, _is_send, _s, _buf_s, _buf_s_size, \
                      _buf_r, _buf_r_size) \
    do {                                                                \
        _pco->op = RCF_RPC_CALL;                                        \
        if (_is_send)                                                   \
            ((rpc_send_f)(_func))(_pco, _s, _buf_s, _buf_s_size, 0);    \
        else                                                            \
            ((rpc_recv_f)(_func))(_pco, _s, _buf_r, _buf_r_size, 0);    \
    } while (0)

/**
 * Call send/recv with RCF_RPC_WAIT.
 *
 * @param   _pco        RPC server
 * @param   _func       send/recv function
 * @param   _is_send    Whether it is send() function
 *                      or not
 * @param   _s          Socket
 * @param   _buf_s      Send buffer
 * @param   _buf_s_size Send buffer size
 * @param   _buf_r      Receive buffer
 * @param   _buf_r_size Receive buffer size
 * @param   _exit       Expected return value
 */
#define WAIT_SR_FUNC(_pco, _func, _is_send, _s, _buf_s, _buf_s_size, \
                     _buf_r, _buf_r_size, _exit) \
    do {                                                                \
        te_bool done;                                                   \
                                                                        \
        CHECK_RC(rcf_rpc_server_is_op_done(_pco, &done));               \
        if (!done)                                                      \
        {                                                               \
            TAPI_WAIT_NETWORK;                                          \
            CHECK_RC(rcf_rpc_server_is_op_done(_pco, &done));           \
            if (!done)                                                  \
                TEST_VERDICT("send/recv function has not been "         \
                             "unblocked");                              \
        }                                                               \
                                                                        \
        RPC_AWAIT_IUT_ERROR(_pco);                                      \
                                                                        \
        if (_is_send)                                                   \
            rc = ((rpc_send_f)(_func))(_pco, _s, _buf_s,                \
                                       _buf_s_size, 0);                 \
        else                                                            \
            rc = ((rpc_recv_f)(_func))(_pco, _s, _buf_r,                \
                                       _buf_r_size, 0);                 \
                                                                        \
        if (rc != (_exit))                                              \
            TEST_FAIL("%s function returned rc=%d, instead of %d",      \
                      _is_send ? "Send" : "Receive", rc, _exit);        \
                                                                        \
        if (_is_send && rc == -1)                                       \
            CHECK_RPC_ERRNO(_pco, RPC_EPIPE,                            \
                            "Send function returned -1, but");          \
                                                                        \
        if (!_is_send && rc == -1)                                      \
            CHECK_RPC_ERRNO(_pco, RPC_ECONNABORTED,                     \
                            "Receive function returned -1, but");       \
    } while (0)

