/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API for Onload specific RPC
 *
 * TAPI for Onload specific remote calls
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#include "te_config.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include "tapi_rpc_internal.h"
#include "sockapi-ts_rpc.h"
#include "sockapi-test.h"
#include "sockapi-ta.h"
#include "te_ethernet.h"

#include "onload_rpc.h"

/** Buffer for logging RPC calls */
static char str_buf_1[8192];

#define ASSIGN_VAL(_field) out->_field = in->_field;

/**
 * Conversion @b struct onload_delegated_send to
 * @b tarpc_onload_delegated_send.
 * 
 * @param in    Incoming structure
 * @param out   Location for the conversion result
 */
static void
onload_delegated_send_h2rpc(struct onload_delegated_send *in,
                            tarpc_onload_delegated_send *out)
{
    ASSIGN_VAL(headers_len);
    ASSIGN_VAL(mss);
    ASSIGN_VAL(send_wnd);
    ASSIGN_VAL(cong_wnd);
    ASSIGN_VAL(user_size);
    ASSIGN_VAL(tcp_seq_offset);
    ASSIGN_VAL(ip_len_offset);
    ASSIGN_VAL(ip_tcp_hdr_len);

    out->headers.headers_val = in->headers;
    out->headers.headers_len = in->headers_len;
}

/**
 * Conversion @b tarpc_onload_delegated_send to
 * @b struct onload_delegated_send to.
 * 
 * @param in    Incoming structure
 * @param out   Location for the conversion result
 */
static void
onload_delegated_send_rpc2h(tarpc_onload_delegated_send *in,
                            struct onload_delegated_send *out)
{
    if (in->headers_len > out->headers_len)
        TEST_FAIL("Returned headers length is greater than the local "
                  "buffer size");

    ASSIGN_VAL(headers_len);
    ASSIGN_VAL(mss);
    ASSIGN_VAL(send_wnd);
    ASSIGN_VAL(cong_wnd);
    ASSIGN_VAL(user_size);
    ASSIGN_VAL(tcp_seq_offset);
    ASSIGN_VAL(ip_len_offset);
    ASSIGN_VAL(ip_tcp_hdr_len);

    memcpy(out->headers, in->headers.headers_val, out->headers_len);
}

#undef ASSIGN_VAL

/**
 * Convert @b struct onload_delegated_send to string representation and save
 * result in buffer @a str_buf_1.
 * 
 * @param ods   onload_delegated_send structure.
 */
static void
ods_to_string(struct onload_delegated_send *ods)
{
    size_t offt;
    int num;
    int i;

    offt = snprintf(str_buf_1, sizeof(str_buf_1),
                    "{%p, %d, %d, %d, %d, %d, %d, %d, %d, {",
                    ods->headers,
                    ods->headers_len, ods->mss, ods->send_wnd,
                    ods->cong_wnd, ods->user_size, ods->tcp_seq_offset,
                    ods->ip_len_offset, ods->ip_tcp_hdr_len);
    num = sizeof(ods->reserved)/sizeof(*ods->reserved);

    for (i = 0; i < num; i++)
    {
        offt += snprintf(str_buf_1 + offt, sizeof(str_buf_1) - offt,
                         "%d", ods->reserved[i]);
        if (i < num -1)
            offt += snprintf(str_buf_1 + offt, sizeof(str_buf_1) - offt,
                             ", ");
        else
            offt += snprintf(str_buf_1 + offt, sizeof(str_buf_1) - offt,
                             "}}");
    }
}

/* See description in the onload_rpc.h */
rpc_onload_delegated_send_rc
rpc_onload_delegated_send_prepare(rcf_rpc_server *rpcs, int fd, int size,
                                  unsigned flags,
                                  struct onload_delegated_send *ods)
{
    tarpc_onload_delegated_send_prepare_in  in;
    tarpc_onload_delegated_send_prepare_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.size = size;
    in.flags = flags;
    onload_delegated_send_h2rpc(ods, &in.ods);

    rcf_rpc_call(rpcs, "onload_delegated_send_prepare", &in, &out);

    onload_delegated_send_rpc2h(&out.ods, ods);
    ods_to_string(ods);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_delegated_send_prepare,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_delegated_send_prepare,
                 "%d, %d, 0x%x, %s", "%d (%s)", fd, size, flags, str_buf_1,
                 out.retval, ods_prepare_err2string(out.retval));

    TAPI_RPC_OUT(onload_delegated_send_prepare,
                 (out.retval != ONLOAD_DELEGATED_SEND_RC_OK));
    return out.retval;
}

/* See description in the onload_rpc.h */
void
rpc_onload_delegated_send_tcp_update(rcf_rpc_server *rpcs,
                                     struct onload_delegated_send* ods,
                                     int bytes, int push)
{
    tarpc_onload_delegated_send_tcp_update_in  in;
    tarpc_onload_delegated_send_tcp_update_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.bytes = bytes;
    in.push = push;
    onload_delegated_send_h2rpc(ods, &in.ods);

    rcf_rpc_call(rpcs, "onload_delegated_send_tcp_update", &in, &out);

    onload_delegated_send_rpc2h(&out.ods, ods);
    ods_to_string(ods);
    TAPI_RPC_LOG(rpcs, onload_delegated_send_tcp_update,
                 "%s, %d, %d", "", str_buf_1, bytes, push);

    RETVAL_VOID(onload_delegated_send_tcp_update);
}

/* See description in the onload_rpc.h */
void
rpc_onload_delegated_send_tcp_advance(rcf_rpc_server *rpcs,
                                      struct onload_delegated_send* ods,
                                      int bytes)
{
    tarpc_onload_delegated_send_tcp_advance_in  in;
    tarpc_onload_delegated_send_tcp_advance_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.bytes = bytes;
    onload_delegated_send_h2rpc(ods, &in.ods);

    rcf_rpc_call(rpcs, "onload_delegated_send_tcp_advance", &in, &out);

    onload_delegated_send_rpc2h(&out.ods, ods);
    ods_to_string(ods);
    TAPI_RPC_LOG(rpcs, onload_delegated_send_tcp_advance,
                 "%s, %d", "", str_buf_1, bytes);

    RETVAL_VOID(onload_delegated_send_tcp_advance);
}

/* See description in the onload_rpc.h */
int
rpc_onload_delegated_send_complete_gen(rcf_rpc_server *rpcs, int fd,
                                       rpc_iovec* iov, int riovlen,
                                       int iovlen, int flags)
{
    tarpc_onload_delegated_send_complete_in  in;
    tarpc_onload_delegated_send_complete_out out;
    struct tarpc_iovec  iov_arr[RCF_RPC_MAX_IOVEC];

    if (iovlen > RCF_RPC_MAX_IOVEC)
    {
        ERROR("%s(): argument riovlen value %d exceeds maximum %d",
              __FUNCTION__, riovlen, RCF_RPC_MAX_IOVEC);
        RETVAL_INT(onload_ordered_epoll_wait, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(iov_arr, 0, sizeof(*iov_arr) * RCF_RPC_MAX_IOVEC);

    iov_h2rpc(iov_arr, iov, riovlen, str_buf_1, sizeof(str_buf_1));
    in.fd = fd;
    in.iovlen = iovlen;
    in.vector.vector_val = iov_arr;
    in.vector.vector_len = riovlen;
    in.flags = flags;

    rcf_rpc_call(rpcs, "onload_delegated_send_complete", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_delegated_send_complete,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_delegated_send_complete,
                 "%d, %s, %s", "%d", fd, str_buf_1,
                 send_recv_flags_rpc2str(flags), out.retval);
    RETVAL_INT(onload_delegated_send_complete, out.retval);
}

/* See description in the onload_rpc.h */
int
rpc_onload_delegated_send_cancel(rcf_rpc_server *rpcs, int fd)
{
    tarpc_onload_delegated_send_cancel_in  in;
    tarpc_onload_delegated_send_cancel_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.fd = fd;

    rcf_rpc_call(rpcs, "onload_delegated_send_cancel", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_delegated_send_cancel,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_delegated_send_cancel,
                 "%d", "%d", fd, out.retval);
    RETVAL_INT(onload_delegated_send_cancel, out.retval);
}

/* See description in the onload_rpc.h */
int
rpc_od_send_iov_gen(rcf_rpc_server *rpcs, int fd, rpc_iovec *iov,
                    int riovlen, int iovlen, rpc_send_recv_flags flags,
                    te_bool raw_send)
{
    tarpc_od_send_in  in;
    tarpc_od_send_out out;

    tarpc_iovec *tarpc_iov = NULL;
    te_string str = TE_STRING_INIT_STATIC(1024);

    if (iov != NULL && riovlen > 0)
        tarpc_iov = tapi_calloc(riovlen, sizeof(*tarpc_iov));

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.raw_send = raw_send;
    in.iov_len = iovlen;
    if (rpcs->op != RCF_RPC_WAIT)
    {
        te_iovec_rpc2tarpc(iov, tarpc_iov, riovlen);
        in.iov.iov_val = tarpc_iov;
        in.iov.iov_len = riovlen;
    }
    te_iovec_rpc2str_append(&str, iov, riovlen);
    in.flags = flags;

    rcf_rpc_call(rpcs, "od_send", &in, &out);
    free(tarpc_iov);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(od_send, out.retval);
    TAPI_RPC_LOG(rpcs, od_send, "%d, %s, %u, %s, %s", "%d", fd, str.ptr,
                 (unsigned int)(in.iov_len), send_recv_flags_rpc2str(flags),
                 (raw_send ? "TRUE" : "FALSE"), out.retval);
    RETVAL_INT(od_send, out.retval);
}

/* See description in the onload_rpc.h */
int
rpc_onload_socket_unicast_nonaccel(rcf_rpc_server *rpcs,
                                   rpc_socket_domain domain,
                                   rpc_socket_type type,
                                   rpc_socket_proto protocol)
{
    tarpc_onload_socket_unicast_nonaccel_in  in;
    tarpc_onload_socket_unicast_nonaccel_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_socket_unicast_nonaccel, -1);
    }

    in.domain = domain;
    in.type = type;
    in.proto = protocol;

    rcf_rpc_call(rpcs, "onload_socket_unicast_nonaccel", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_socket_unicast_nonaccel,
                                      out.fd);
    TAPI_RPC_LOG(rpcs, onload_socket_unicast_nonaccel, "%s, %s, %s", "%d",
                 domain_rpc2str(domain), socktype_rpc2str(type),
                 proto_rpc2str(protocol), out.fd);
    RETVAL_INT(onload_socket_unicast_nonaccel, out.fd);
}
