/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Test API for RPC
 *
 * TAPI for remote calls
 *
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
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
#include "te_ethernet.h"
#include "iomux.h"

#include "onload.h"

/** Buffer for logging RPC calls */
static char str_buf_1[8192];

tarpc_ssize_t
rpc_sapi_get_sizeof(rcf_rpc_server *rpcs, const char *type_name)
{
    struct tarpc_sapi_get_sizeof_in  in;
    struct tarpc_sapi_get_sizeof_out out;
    int                         rc;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sapi_get_sizeof, -1);
    }

    if (type_name == NULL)
    {
        ERROR("%s(): NULL type name", __FUNCTION__);
        RETVAL_INT(sapi_get_sizeof, -1);
    }

    in.typename = strdup(type_name);

    rcf_rpc_call(rpcs, "sapi_get_sizeof", &in, &out);

    free(in.typename);
    rc = out.size;

    CHECK_RETVAL_VAR(sapi_get_sizeof, rc, (rc < -1), -1);
    TAPI_RPC_LOG(rpcs, sapi_get_sizeof, "%s", "%d", type_name, rc);
    RETVAL_INT(sapi_get_sizeof, rc);
}

int
rpc_send_traffic(rcf_rpc_server *rpcs, int num,
                 int *s, const void *buf, tarpc_size_t len,
                 int flags, struct sockaddr *to)
{
    tarpc_send_traffic_in  in;
    tarpc_send_traffic_out out;
    
    int i;
    int             *ss    = NULL;
    struct tarpc_sa *addrs = NULL;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(send_traffic, -1);
    }
    if (s == NULL || to == NULL)
    {
        ERROR("%s(): Invalid pointers to sockets and addresses",
              __FUNCTION__);
        RETVAL_INT(send_traffic, -1);
    }

    /* Num */
    in.num = num;
    
    /* Sockets */
    ss = (int *)calloc(num, sizeof(int));
    in.fd.fd_val = (tarpc_int *)ss;
    if (in.fd.fd_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return -1;
    }
    in.fd.fd_len = num;
    for (i = 0; i < num; i++)
        in.fd.fd_val[i] = *(s + i);

    /* Length */
    in.len = len;
    
    /* Adresses */
    in.to.to_val = addrs = calloc(num, sizeof(*addrs));
    if (in.to.to_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return -1;
    }
    in.to.to_len = num;
    if (rpcs->op != RCF_RPC_WAIT)
    {
        for (i = 0; i < num; i++)
        {    
            sockaddr_input_h2rpc(to + i, in.to.to_val + i);
        }
    }
    
    if (buf != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.buf.buf_len = len;
        in.buf.buf_val = (uint8_t *)buf;
    }
    in.flags = flags;

    rcf_rpc_call(rpcs, "send_traffic", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(send_traffic, out.retval);
    TAPI_RPC_LOG(rpcs, send_traffic, "", "%d", out.retval);

    if (RPC_IS_CALL_OK(rpcs))
    {
        for (i = 0; i < num; i++)
        {
            RING("send_traffic to %s - done", te_sockaddr2str(to + i));
        }
    }

    free(addrs);
    free(ss);

    RETVAL_INT(send_traffic, out.retval);
}

int
rpc_many_sendto(rcf_rpc_server *rpcs, int num,
                int s, tarpc_size_t len, int flags,
                const struct sockaddr *to, uint64_t *sent)
{
    tarpc_many_sendto_in  in;
    tarpc_many_sendto_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(many_sendto, -1);
    }
    if (to == NULL)
    {
        ERROR("%s(): Invalid pointers to address",
              __FUNCTION__);
        RETVAL_INT(many_sendto, -1);
    }

    if (rpcs->op != RCF_RPC_WAIT)
    {
        sockaddr_input_h2rpc(to, &in.to);
    }

    in.num = num;
    in.len = len;
    in.sock = s;
    in.flags = flags;

    rcf_rpc_call(rpcs, "many_sendto", &in, &out);

    if (out.retval == 0)
        *sent = out.sent;

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_sendto, out.retval);
    TAPI_RPC_LOG(rpcs, many_sendto, "%d, %d, %d, %d, %s", "%d", num, s,
                 len, flags, sockaddr_h2str(to), out.retval);
    RETVAL_INT(many_sendto, out.retval);
}

int
rpc_many_send(rcf_rpc_server *rpcs, int sock, int flags,
              const tarpc_size_t *vector, int nops, uint64_t *sent)
{
    tarpc_many_send_in  in;
    tarpc_many_send_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(many_send, -1);
    }

    in.sock = sock;
    in.flags = flags;

    if (vector != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.vector.vector_len = nops;
        in.vector.vector_val = (tarpc_size_t *)vector;
    }

    rcf_rpc_call(rpcs, "many_send", &in, &out);

    if (out.retval == 0)
        *sent = out.bytes;

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(many_send, out.retval);
    TAPI_RPC_LOG(rpcs, many_send, "%d, %u, %p", "%d",
                 sock, nops, vector, out.retval);
    RETVAL_INT(many_send, out.retval);
}

int
rpc_close_and_accept(rcf_rpc_server *rpcs, 
                     int listening, int conns,
                     int *s, uint16_t state)
{
    int       *ss; 
    
    tarpc_close_and_accept_in  in;
    tarpc_close_and_accept_out out;

    int              i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(close_and_accept, -1);
    }
    if (s == NULL)
    {
        ERROR("%s(): Invalid sockets list",
              __FUNCTION__);
        RETVAL_INT(close_and_accept, -1);
    }

    in.listening = listening;
    /* Number of sockets */
    in.conns = conns;
    in.state = state;
 
    /* Sockets */
    ss = (int *)calloc(conns, sizeof(tarpc_int));
    in.fd.fd_val = (tarpc_int *)ss;
    if (in.fd.fd_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        RETVAL_INT(close_and_accept, -1);
    }
    in.fd.fd_len = conns;
    for (i = 0; i < conns; i++)
        in.fd.fd_val[i] = *(s + i);

    rcf_rpc_call(rpcs, "close_and_accept", &in, &out);

    if (RPC_IS_CALL_OK(rpcs) && out.fd.fd_val != NULL)
    {
        for (i = 0; i < conns; i++)
        {
            *(s + i) = out.fd.fd_val[i];
        }
    }

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(close_and_accept, out.retval);

    TAPI_RPC_LOG(rpcs, close_and_accept, "%d %d %d", "%d",
                 listening, conns, state, out.retval);
    RETVAL_ZERO_INT(close_and_accept, out.retval);
}

int
rpc_close_and_socket(rcf_rpc_server *rpcs, int fd,
                     rpc_socket_domain domain,
                     rpc_socket_type type,
                     rpc_socket_proto protocol)
{
    tarpc_close_and_socket_in  in;
    tarpc_close_and_socket_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(close_and_accept, -1);
    }

    in.fd       = fd;
    in.domain   = domain;
    in.type     = type;
    in.protocol = protocol;

    rcf_rpc_call(rpcs, "close_and_socket", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(close_and_socket, out.retval);
    TAPI_RPC_LOG(rpcs, close_and_socket, "%d, %s, %s, %s", "%d",
                 in.fd, domain_rpc2str(domain), socktype_rpc2str(type),
                 proto_rpc2str(protocol),
                 out.retval);
    RETVAL_ZERO_INT(close_and_socket, out.retval);
}

int
rpc_timely_round_trip(rcf_rpc_server *rpcs, int sock_num, int *s,
                      tarpc_size_t size, tarpc_size_t vector_len,
                      uint32_t timeout, uint32_t time2wait,
                      int flags, int addr_num, struct sockaddr *to)
{
    int       *ss; 
    
    tarpc_timely_round_trip_in  in;
    tarpc_timely_round_trip_out out;

    struct sockaddr *addrs = NULL;
    int              i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(timely_round_trip, -1);
    }
    if (to == NULL)
    {
        ERROR("%s(): Invalid pointers to addresses",
              __FUNCTION__);
        RETVAL_INT(timely_round_trip, -1);
    }
    if (size == 0 || vector_len == 0)
    {
        ERROR("%s(): Invalid parameters of size and vector_len",
              __FUNCTION__);
        RETVAL_INT(timely_round_trip, -1);
    }

    /* Number of sockets */
    in.sock_num = sock_num;
 
    /* Sockets */
    ss = (int *)calloc(sock_num, sizeof(int));
    in.fd.fd_val = (tarpc_int *)ss;
    if (in.fd.fd_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return -1;
    }
    in.fd.fd_len = sock_num;
    for (i = 0; i < sock_num; i++)
        in.fd.fd_val[i] = *(s + i);

    /* Size */
    in.size = size;
    /* Vector length */
    in.vector_len = vector_len;
    /* Timeout */
    in.timeout = timeout;
    /* time2wait */
    in.time2wait = time2wait;
    /* Flags */
    in.flags = flags;

    /* Adresses */
    in.addr_num = addr_num;

    addrs = (struct sockaddr *)calloc(addr_num, sizeof(struct sockaddr));
    in.to.to_val = (struct tarpc_sa *)addrs;
    if (in.to.to_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return -1;
    }
    in.to.to_len = addr_num;
    if (rpcs->op != RCF_RPC_WAIT)
    {
        for (i = 0; i < addr_num; i++)
        {    
            sockaddr_input_h2rpc(to + i, in.to.to_val + i);
        }
    }

    rcf_rpc_call(rpcs, "timely_round_trip", &in, &out);

    CHECK_RETVAL_VAR(timely_round_trip, out.retval,
                     (out.retval < 0) || 
                     (out.retval > ROUND_TRIP_ERROR_TIME_EXPIRED),
                     -1);
    TAPI_RPC_LOG(rpcs, timely_trip_around, "", "%d", out.retval);
        
    switch (out.retval)
    {
        case ROUND_TRIP_ERROR_SEND:
        {
            ERROR("error occured while sending message to %s", 
                  te_sockaddr2str(to + out.index));
            break;
        }
        case ROUND_TRIP_ERROR_RECV:
        {
            ERROR("error ocuured while receiving message from %s",
                  te_sockaddr2str(to + out.index));
            break;
        }    
        case ROUND_TRIP_ERROR_TIMEOUT:
        {
            ERROR("Timeout occured, no answer from %s",
                  te_sockaddr2str(to + out.index));
            break;
        }
        case ROUND_TRIP_ERROR_TIME_EXPIRED:    
        { 
            ERROR("Time expired while waiting for answer from %s",
                  te_sockaddr2str(to + out.index));
            break;
        }
        default:
        {
            break;
        }
    }

    free(addrs);

    RETVAL_ZERO_INT(timely_round_trip, out.retval);
}
    
int
rpc_round_trip_echoer(rcf_rpc_server *rpcs, int sock_num, int *s,
                      int addr_num, tarpc_size_t size, tarpc_size_t vector_len,
                      uint32_t timeout, int flags)
{
    int       *ss; 
    int        i;
    
    tarpc_round_trip_echoer_in  in;
    tarpc_round_trip_echoer_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(round_trip_echoer, -1);
    }
    if (size == 0 || vector_len == 0)
    {
        ERROR("%s(): Invalid parameters of size and vector_len",
              __FUNCTION__);
        RETVAL_INT(round_trip_echoer, -1);
    }

    /* Number of sockets */
    in.sock_num = sock_num;
 
    /* Sockets */
    ss = (int *)calloc(sock_num, sizeof(int));
    in.fd.fd_val = (tarpc_int *)ss;
    if (in.fd.fd_val == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return -1;
    }
    in.fd.fd_len = sock_num;
    for (i = 0; i < sock_num; i++)
        in.fd.fd_val[i] = *(s + i);

    in.addr_num = addr_num;

    /* Size */
    in.size = size;
    /* Vector length */
    in.vector_len = vector_len;
    /* Timeout */
    in.timeout = timeout;
    /* Flags */
    in.flags = flags;

    rcf_rpc_call(rpcs, "round_trip_echoer", &in, &out);

    CHECK_RETVAL_VAR(round_trip_echoer, out.retval,
                     (out.retval < 0) || 
                     (out.retval > ROUND_TRIP_ERROR_TIMEOUT),
                     -1);

    TAPI_RPC_LOG(rpcs, round_trip_echoer, "", "%d", out.retval);

    switch (out.retval)
    {
        case ROUND_TRIP_ERROR_SEND:
        {
            ERROR("error occured while sending message");
            break;
        }
        case ROUND_TRIP_ERROR_RECV:
        {
            ERROR("error occured while receiving message");
            break;
        }    
        case ROUND_TRIP_ERROR_TIMEOUT:
        {
            ERROR("Timeout occured, no request from peer");
            break;
        }
        default:
        {
            break;
        }
    }

    RETVAL_ZERO_INT(round_trip_echoer, out.retval);
}

static const char *
blk_aio_mode_rpc2str(tarpc_blocking_aio_mode mode)
{
#ifndef DOXYGEN_TEST_SPEC
    switch (mode)
    {
#define MODE2STR(name_) \
    case TARPC_AIO_BLK_ ## name_: return #name_

        MODE2STR(SUSPEND);
        MODE2STR(POLL);
        MODE2STR(SIGNAL);
        MODE2STR(CALLBACK);

#undef MODE2STR    

        default: return "Unknown blocking mode";
    }
#endif /* !DOXYGEN_TEST_SPEC */
}

/**
 * Emulate blocking reading using AIO requests.
 *
 * @param rpcs    RPC server handle
 * @param s       socket descriptor
 * @param buf     pointer to buffer which store received messages
 * @param len     buffer length passed to recv()
 * @param rbuflen size of the buffer @b buf
 * @param mode     blocking emulation mode
 *
 * @return  number of bytes read, otherwise -1 on error.
 */
tarpc_ssize_t
rpc_aio_read_blk_gen(rcf_rpc_server *rpcs,
                     int s, void *buf, tarpc_size_t len,
                     tarpc_blocking_aio_mode mode, tarpc_size_t rbuflen)
{
    tarpc_aio_read_blk_in  in;
    tarpc_aio_read_blk_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(recv, -1);
    }

    if (buf != NULL && len > rbuflen)
    {
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(recv, -1);
    }

    in.fd = s;
    in.len = len;
    if (buf != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.buf.buf_len = rbuflen;
        in.buf.buf_val = buf;
    }
    in.mode = mode;

    rcf_rpc_call(rpcs, "aio_read_blk", &in, &out);

    if (RPC_IS_CALL_OK(rpcs))
    {
        if (buf != NULL && out.buf.buf_val != NULL)
            memcpy(buf, out.buf.buf_val, out.buf.buf_len);
    }

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(recv, out.retval);
    TAPI_RPC_LOG(rpcs, aio_read_blk, "%d, %p[%u], %u, %s", "%d",
                 s, buf, rbuflen, len, blk_aio_mode_rpc2str(mode),
                 out.retval);
    RETVAL_INT(aio_read_blk, out.retval);
}                     

/**
 * Emulate blocking writing using AIO requests.
 *
 * @param rpcs  RPC server handle
 * @param s     socket descriptor
 * @param buf   pointer to buffer which store received messages
 * @param len   size of the buffer @b buf
 * @param mode  blocking emulation mode
 *
 * @return Number of bytes received, otherwise -1 when error occured
 */
tarpc_ssize_t
rpc_aio_write_blk(rcf_rpc_server *rpcs,
                  int s, const void *buf, tarpc_size_t len,
                  tarpc_blocking_aio_mode mode)
{
    tarpc_aio_write_blk_in  in;
    tarpc_aio_write_blk_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(aio_write_blk, -1);
    }

    in.fd = s;
    in.len = len;
    if (buf != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.buf.buf_len = len;
        in.buf.buf_val = (uint8_t *)buf;
    }
    in.mode = mode;

    rcf_rpc_call(rpcs, "aio_write_blk", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(aio_write_blk, out.retval);
    TAPI_RPC_LOG(rpcs, aio_write_blk, "%d, %p, %u, %s", "%d",
                 s, buf, len, blk_aio_mode_rpc2str(mode),
                 out.retval);
    RETVAL_INT(aio_write_blk, out.retval);
}

/**
 * Function for producing array of callbacks from callback list.
 *
 * @param rpcs  RPC server handle
 * @param arr   pointer to the array of callbacks
 * @param len   number of slots in array (IN) or 
 *              number of elements in array (OUT)
 */
void
rpc_get_callback_list(rcf_rpc_server *rpcs,
                      tarpc_callback_item *arr,
                      uint32_t *len)
{
    tarpc_get_callback_list_in  in;
    tarpc_get_callback_list_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_VOID(get_callback_list);
    }

    rcf_rpc_call(rpcs, "get_callback_list", &in, &out);

    if (len != NULL && arr != NULL)
    {
        if (out.list.list_len > *len)
            ERROR("Too small buffer is provided to %s", __FUNCTION__);
        else
            memcpy(arr, out.list.list_val, 
                   sizeof(*arr) * out.list.list_len);
    }
    if (len != NULL)
        *len = out.list.list_len;

    TAPI_RPC_LOG(rpcs, get_callback_list, "", "%d", out.list.list_len);
    RETVAL_VOID(get_callback_list);
}

/**
 * Auxiliary function for aio/nested_requests test.
 *
 * @param rpcs     RPC server handle
 * @param s        connected socket
 * @param req_num  number of write AIO requests
 *
 * @return TE status code
 */ 
int 
rpc_nested_requests_test(rcf_rpc_server *rpcs, int s, int req_num)
{
    tarpc_nested_requests_test_in  in;
    tarpc_nested_requests_test_out out;
    
    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(nested_requests_test, -1);
    }

    in.s = s;
    in.req_num = req_num;

    rcf_rpc_call(rpcs, "nested_requests_test", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(nested_requests_test, out.retval);
    TAPI_RPC_LOG(rpcs, nested_requests_test, "%d %d", "%d",
                 s, req_num, out.retval);
    RETVAL_INT(nested_requests_test, out.retval);
}

void
rpc_write_at_offset_continuous(rcf_rpc_server *rpcs, int fd, char* buf,
                               tarpc_size_t buflen, off_t offset, uint64_t time)
{
    struct tarpc_write_at_offset_continuous_in  in;
    struct tarpc_write_at_offset_continuous_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.buf.buf_len = buflen;
    in.buf.buf_val = (uint8_t *)buf;
    in.offset = offset;
    in.time = time;
    rcf_rpc_call(rpcs, "write_at_offset_continuous", &in, &out);
    TAPI_RPC_LOG(rpcs, write_at_offset_continuous,
                 "file %d at offset %d", "", fd, offset);
    RETVAL_VOID(write_at_offset_continuous);
}

#if 0
int
rpc_onload_hw_filters_limit(rcf_rpc_server *rpcs,
                            const struct sockaddr *addr)
{
    struct tarpc_onload_hw_filters_limit_in  in;
    struct tarpc_onload_hw_filters_limit_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    sockaddr_input_h2rpc(addr, &in.addr);

    rcf_rpc_call(rpcs, "onload_hw_filters_limit", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_hw_filters_limit,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_hw_filters_limit,
                 "%s", "%d", te_sockaddr2str(addr), out.retval);

    RETVAL_INT(onload_hw_filters_limit, out.retval);
}
#endif

int
rpc_out_of_hw_filters_do(rcf_rpc_server *rpcs, te_bool do_bind,
                         const struct sockaddr *bind_addr,
                         const struct sockaddr *connect_addr,
                         int sock_type, out_of_res_acts action,
                         int sock_num, int *acc_num, int *err_num,
                         int *sock1, int *sock2)
{
    struct tarpc_out_of_hw_filters_do_in  in;
    struct tarpc_out_of_hw_filters_do_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.do_bind = do_bind;
    in.sock_num = sock_num;
    in.type = sock_type;
    in.action = action;

    if (rpcs == NULL || connect_addr == NULL || 
        sock1 == NULL || sock2 == NULL)
    {
        ERROR("Invalid parameter is passed to RPC "
              "out_of_hw_filters_do");
        TAPI_JMP_DO(TE_EFAIL);
    }

    sockaddr_input_h2rpc(bind_addr, &in.bind_addr);
    sockaddr_input_h2rpc(connect_addr, &in.connect_addr);

    rcf_rpc_call(rpcs, "out_of_hw_filters_do", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(out_of_hw_filters_do,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, out_of_hw_filters_do,
                 "%s, %s, %s, %d",
                 "%d, accelerated %d, errors %d, sockets %d %d",
                 do_bind ? "bind" : "don't bind",
                 te_sockaddr2str(bind_addr),
                 te_sockaddr2str(connect_addr),
                 sock_num,
                 out.retval, out.acc_num, out.err_num, out.sock1, out.sock2);

    *sock1 = out.sock1;
    *sock2 = out.sock2;
    if (acc_num != NULL)
      *acc_num = out.acc_num;
    if (err_num != NULL)
      *err_num = out.err_num;

    RETVAL_INT(out_of_hw_filters_do, out.retval);
}

int
rpc_many_accept_gen(rcf_rpc_server *rpcs, int s, int sock_num,
                    int data_len, int send_count,
                    int *sock1, int *sock2, rpc_ptr *handle, int *iteration)
{
    struct tarpc_many_accept_in  in;
    struct tarpc_many_accept_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (handle == NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_accept, -1);
    }

    *handle = RPC_NULL;

    in.s = s;
    in.sock_num = sock_num;
    in.data_len = data_len;
    in.send_count = send_count;

    rcf_rpc_call(rpcs, "many_accept", &in, &out);
    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_accept, out.retval);
    TAPI_RPC_LOG(rpcs, many_accept, "%d, %d, %d*%d 0x%x",
                 "%d, sockets %d %d, last iteration %d", s, sock_num,
                 data_len, send_count, handle, out.retval, out.sock1,
                 out.sock2, out.iteration);

    if (sock1 != NULL)
        *sock1 = out.sock1;
    if (sock2 != NULL)
        *sock2 = out.sock2;

    *handle = out.handle;

    if (iteration != NULL)
        *iteration = out.iteration;

    RETVAL_INT(many_accept, out.retval);
}

int
rpc_many_connect(rcf_rpc_server *rpcs, const struct sockaddr *addr,
                 int sock_num, int data_len, int send_count,
                 int *sock1, int *sock2, rpc_ptr *handle)
{
    struct tarpc_many_connect_in  in;
    struct tarpc_many_connect_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (handle == NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_connect, -1);
    }

    *handle = RPC_NULL;

    sockaddr_input_h2rpc(addr, &in.addr);
    in.sock_num = sock_num;
    in.data_len = data_len;
    in.send_count = send_count;

    rcf_rpc_call(rpcs, "many_connect", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_connect, out.retval);
    TAPI_RPC_LOG(rpcs, many_connect, "%s, %d, %d*%d 0x%x",
                 "%d, sockets %d %d", te_sockaddr2str(addr), sock_num,
                 data_len, send_count, handle, out.retval, out.sock1,
                 out.sock2);

    if (sock1 != NULL)
        *sock1 = out.sock1;
    if (sock2 != NULL)
        *sock2 = out.sock2;

    *handle = out.handle;

    RETVAL_INT(many_connect, out.retval);
}

int
rpc_many_close_cache(rcf_rpc_server *rpcs, rpc_ptr handle, int num,
                     int *cached)
{
    struct tarpc_many_close_cache_in  in;
    struct tarpc_many_close_cache_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (handle == RPC_NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_close_cache, -1);
    }

    in.handle = handle;
    in.num = num;

    rcf_rpc_call(rpcs, "many_close_cache", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_close_cache, out.retval);
    TAPI_RPC_LOG(rpcs, many_close_cache, "%d, %d", "%d, cached %d", handle,
                 num, out.retval, out.cached);

    if (cached != NULL)
        *cached = out.cached;

    RETVAL_INT(many_close_cache, out.retval);
}


int
rpc_many_close(rcf_rpc_server *rpcs, rpc_ptr handle, int num)
{
    struct tarpc_many_close_in  in;
    struct tarpc_many_close_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (handle == RPC_NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_close, -1);
    }

    in.handle = handle;
    in.num = num;

    rcf_rpc_call(rpcs, "many_close", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_close, out.retval);
    TAPI_RPC_LOG(rpcs, many_close, "%d, %d", "%d", handle, num, out.retval);

    RETVAL_INT(many_close, out.retval);
}

int
rpc_many_epoll_ctl_add_del(rcf_rpc_server *rpcs, rpc_ptr socks_arr,
                           int socks_num, int epfd, uint32_t events,
                           te_bool check_epoll_wait, int time2run)
{
    tarpc_many_epoll_ctl_add_del_in  in;
    tarpc_many_epoll_ctl_add_del_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (socks_arr == RPC_NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_epoll_ctl_add_del, -1);
    }

    in.socks_arr = socks_arr;
    in.socks_num = socks_num;
    in.epfd = epfd;
    in.events = events;
    in.check_epoll_wait = check_epoll_wait;
    in.time2run = time2run;

    rcf_rpc_call(rpcs, "many_epoll_ctl_add_del", &in, &out);
    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_epoll_ctl_add_del, out.retval);
    TAPI_RPC_LOG(rpcs, many_epoll_ctl_add_del,
                 "socks="RPC_PTR_FMT", socks_num=%d, epfd=%d, evts=%s, "
                 "check_epoll_wait=%s, time2run=%d", "%d",
                 RPC_PTR_VAL(socks_arr), socks_num, epfd,
                 epoll_event_rpc2str(events),
                 (check_epoll_wait ? "TRUE" : "FALSE"),
                 time2run, out.retval);

    RETVAL_INT(many_epoll_ctl_add_del, out.retval);
}

int
rpc_many_socket(rcf_rpc_server *rpcs, rpc_socket_domain domain,
                int num, rpc_ptr *handle)
{
    struct tarpc_many_socket_in  in;
    struct tarpc_many_socket_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (handle == NULL)
    {
        ERROR("%s(): Invalid handle", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        RETVAL_INT(many_socket, -1);
    }

    *handle = RPC_NULL;

    in.num = num;
    in.domain = domain;

    rcf_rpc_call(rpcs, "many_socket", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_socket, out.retval);
    TAPI_RPC_LOG(rpcs, many_socket, "%s, %d 0x%x", "%d",
                 domain_rpc2str(domain), num, handle, out.retval);

    *handle = out.handle;

    RETVAL_INT(many_socket, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_get_socket_from_array(rcf_rpc_server *rpcs, rpc_ptr handle,
                          unsigned int idx, int *s)
{
    struct tarpc_get_socket_from_array_in  in;
    struct tarpc_get_socket_from_array_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.handle = handle;
    in.idx = idx;

    rcf_rpc_call(rpcs, "get_socket_from_array", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(get_socket_from_array,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, get_socket_from_array, "0x%x, %u", "%d s=%d",
                 handle, idx, out.retval, out.s);

    if (s != NULL)
        *s = out.s;

    RETVAL_INT(get_socket_from_array, out.retval);
}

int
rpc_many_recv(rcf_rpc_server *rpcs, int sock, tarpc_size_t length, int num,
              int duration, void *last_packet, tarpc_size_t last_packet_len,
              te_bool count_fails, int *fails_num)
{
    struct tarpc_many_recv_in  in;
    struct tarpc_many_recv_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.sock = sock;
    in.num = num;
    in.duration = duration;
    in.length = length;
    in.last_packet.last_packet_val = last_packet;
    in.last_packet.last_packet_len = last_packet_len;
    in.count_fails = count_fails;

    rcf_rpc_call(rpcs, "many_recv", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_recv, out.retval);
    TAPI_RPC_LOG(rpcs, many_recv,
                 "%d, %td, %d, %d, 0x%x, %td, %d, 0x%x", "%d, fails %d",
                 sock, length, num, duration, last_packet, last_packet_len,
                 count_fails, fails_num, out.retval, out.fails_num);

    if (fails_num != NULL)
        *fails_num = out.fails_num;

    RETVAL_INT(many_recv, out.retval);
}

int
rpc_many_send_num_func(rcf_rpc_server *rpcs, int sock, tarpc_size_t length_min,
                       tarpc_size_t length_max, int num, int duration,
                       const char *func_name, te_bool check_len,
                       te_bool count_fails, int *fails_num)
{
    struct tarpc_many_send_num_in  in;
    struct tarpc_many_send_num_out out;
    const char *sys = "sys_";

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.sock = sock;
    in.length_min = length_min;
    in.length_max = length_max;
    in.num = num;
    in.duration = duration;
    in.check_len = check_len;
    in.count_fails = count_fails;

    if (strncmp(func_name, sys, strlen(sys)) == 0)
    {
        in.func_name = strdup(func_name + strlen(sys));
        rpcs->use_libc_once = TRUE;
    }
    else
        in.func_name = strdup(func_name);

    rcf_rpc_call(rpcs, "many_send_num", &in, &out);
    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_send_num, out.retval);
    TAPI_RPC_LOG(rpcs, many_send_num,
                 "%d, %td, %td, %d, %d, %s, %d, %d, 0x%x", "%d, fails %d",
                 sock, length_min, length_max, num, duration, func_name,
                 check_len, count_fails, fails_num, out.retval,
                 out.fails_num);
    free(in.func_name);

    if (fails_num != NULL)
        *fails_num = out.fails_num;

    RETVAL_INT(many_send_num, out.retval);
}

int 
rpc_out_of_netifs(rcf_rpc_server *rpcs,  int sock_num,
                  rpc_socket_type sock_type, int *num, int *acc)
{
    struct tarpc_out_of_netifs_in  in;
    struct tarpc_out_of_netifs_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.sock_num = sock_num;
    in.sock_type = sock_type;

    if (rpcs == NULL)
    {
        ERROR("Invalid parameter is passed to RPC out_of_netifs");
        TAPI_JMP_DO(TE_EFAIL);
    }

    rcf_rpc_call(rpcs, "out_of_netifs", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(out_of_netifs, out.rc);
    TAPI_RPC_LOG(rpcs, out_of_netifs, "%d", "%d: %d/%d", sock_num, out.rc,
                 out.acc, out.num);

    if (num != NULL)
        *num = out.num;
    if (acc != NULL)
        *acc = out.acc;

    RETVAL_INT(out_of_netifs, out.rc);
}
                  
/** 
 * Start traffic processor.
 *
 * @param rpcs        RPC server handle
 * @param sock        socket for traffic transferring
 * @param snd         if TRUE, send traffic; otherwise receive traffic
 * @param bytes       location for transferred bytes pointer
 * @param stop        location for stop flag
 *
 * @note Memory for bytes and stop flag is allocated by the function
 *       and should be freed by rpc_free().
 */
void 
rpc_traffic_processor(rcf_rpc_server *rpcs, 
                      int sock, te_bool snd,
                      rpc_ptr *bytes, rpc_ptr *stop)
{
    struct tarpc_traffic_processor_in  in;
    struct tarpc_traffic_processor_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    
    if (rpcs == NULL)
    {
        ERROR("Invalid parameter is passed to RPC traffic_processor");
        TAPI_JMP_DO(TE_EFAIL);
    }
    
    if (rpcs->op != RCF_RPC_WAIT)
    {
        rcf_rpc_op op = rpcs->op;;
        
        rpcs->op = RCF_RPC_CALL_WAIT;
        *bytes = rpc_malloc(rpcs, 8);
        *stop = rpc_malloc(rpcs, 1);
        rpcs->op = op;
        
        in.sock = sock;
        in.snd = snd;
        in.bytes = *bytes;
        in.stop = *stop;
    }
    
    rcf_rpc_call(rpcs, "traffic_processor", &in, &out);
    TAPI_RPC_LOG(rpcs, traffic_processor, "%d, %s", "",
                 sock, snd ? "send" : "receive");

    if (RPC_ERRNO(rpcs) != 0 && !RPC_AWAITING_ERROR(rpcs)) 
        TAPI_JMP_DO(TE_EFAIL);
        
    RETVAL_VOID(traffic_processor);
}

/**
 * Generic implementation of TAPI to call RPC close() via specified
 * method.
 *
 * @param _method       Close method
 */
#define RPC_CLOSE_FUNC(_method)                                         \
int                                                                     \
rpc_close_##_method(rcf_rpc_server *rpcs, int fd)                       \
{                                                                       \
    tarpc_close_##_method##_in  in;                                     \
    tarpc_close_##_method##_out out;                                    \
                                                                        \
    memset(&in, 0, sizeof(in));                                         \
    memset(&out, 0, sizeof(out));                                       \
    if (rpcs == NULL)                                                   \
    {                                                                   \
        ERROR("NULL rpc server specified");                             \
        TAPI_JMP_DO(TE_EFAIL);                                          \
    }                                                                   \
    in.fd = fd;                                                         \
    rcf_rpc_call(rpcs, "close_" #_method, &in, &out);                   \
    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(close_##_method, out.retval); \
    TAPI_RPC_LOG(rpcs, close_via, "%d via %s", "%d",                    \
                 fd, #_method, out.retval);                             \
    RETVAL_INT(close_##_method, out.retval);                            \
}

/** TAPI for RPC close() via interrupt */
RPC_CLOSE_FUNC(interrupt);
/** TAPI for RPC close() via syscall */
RPC_CLOSE_FUNC(syscall);
/** TAPI for RPC close() via sysenter */
RPC_CLOSE_FUNC(sysenter);


/**
 * Incorrect CRC sendig test.
 *
 * @param rpcs      RPC server handle
 * @param ifname    ethernet interface symbolic name
 * @param dest_addr destination host hadware address
 * @param dest_sa   destination socket address
 *
 * @return 0 if success or error code.
 *
 * @note Send ethernet frames with incorrect CRC.
 */
int
rpc_incorrect_crc_send_test(rcf_rpc_server *rpcs, const char *ifname, 
                            const uint8_t *dest_addr,
                            const struct sockaddr *dest_sa)
{
    struct tarpc_incorrect_crc_send_test_in  in;
    struct tarpc_incorrect_crc_send_test_out out;
    
    struct tarpc_sa addr;
    
    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    
    if (rpcs == NULL || ifname == NULL || dest_addr == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(incorrect_crc_send_test, out.retval);
    }
    
    in.ifname = strdup(ifname);
    in.dest_addr.dest_addr_val = (void *)dest_addr;
    in.dest_addr.dest_addr_len = ETHER_ADDR_LEN;
    in.dest_sa.dest_sa_val = &addr;
    in.dest_sa.dest_sa_len = 1;
    sockaddr_input_h2rpc(dest_sa, in.dest_sa.dest_sa_val);

    rcf_rpc_call(rpcs, "incorrect_crc_send_test", &in, &out);
        
    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(incorrect_crc_send_test,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, incorrect_crc_send_test,
                 "%s, %02x %02x %02x %02x %02x %02x", "",
                 ifname, 
                 in.dest_addr.dest_addr_val[0],
                 in.dest_addr.dest_addr_val[1], 
                 in.dest_addr.dest_addr_val[2],
                 in.dest_addr.dest_addr_val[3], 
                 in.dest_addr.dest_addr_val[4],
                 in.dest_addr.dest_addr_val[5]); 
    RETVAL_INT(incorrect_crc_send_test, out.retval);
}


/**
 * Non-Block receiver start.
 *
 * @param rpcs            RPC server
 * @param s               a socket to be user for receiving
 * @param handle          pre-allocated pointer to integer to control the receiver
 *
 * @return 0, on success or -1 in the case of failure
 */
int
rpc_nb_receiver_start(rcf_rpc_server *rpcs, int s, rpc_ptr handle)
{
    tarpc_nb_receiver_start_in  in;
    tarpc_nb_receiver_start_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(nb_receiver_start, -1);
    }

    in.s = s;
    in.handle = handle;

    rcf_rpc_call(rpcs, "nb_receiver_start", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(nb_receiver_start, out.retval);
    TAPI_RPC_LOG(rpcs, nb_receiver_start, "%d, %u", "%d",
                 s, handle, out.retval);
    RETVAL_INT(nb_receiver_start, out.retval);
}

/**
 * Non-Block receiver stop.
 *
 * @param rpcs            RPC server
 * @param handle          pre-allocated pointer to integer to control the receiver
 *
 * @return 0, on success or -1 in the case of failure
 */
int
rpc_nb_receiver_stop(rcf_rpc_server *rpcs, rpc_ptr handle)
{
    tarpc_nb_receiver_stop_in   in;
    tarpc_nb_receiver_stop_out  out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(nb_receiver_stop, -1);
    }

    in.handle = handle;

    rcf_rpc_call(rpcs, "nb_receiver_stop", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(nb_receiver_start,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, nb_receiver_stop, "%u", "%d", handle, out.retval);
    RETVAL_INT(nb_receiver_start, out.retval);
}

int
rpc_onload_set_stackname(rcf_rpc_server *rpcs,
                         int who,
                         int scope,
                         const char *name)
{
    struct tarpc_onload_set_stackname_in  in;
    struct tarpc_onload_set_stackname_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_set_stackname, out.retval);
    }

    if (name == NULL)
    {
        in.name_null = TRUE;
        in.name = strdup("");
    }
    else
        in.name = strdup(name);

    in.who = who;
    in.scope = scope;

    rcf_rpc_call(rpcs, "onload_set_stackname", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(onload_set_stackname, out.retval);
    TAPI_RPC_LOG(rpcs, onload_set_stackname,
                 "%s, ONLOAD_SCOPE_%s, %s", "%d",
                 who == ONLOAD_ALL_THREADS ?
                 "ONLOAD_ALL_THREADS" : (who == ONLOAD_THIS_THREAD ?
                                         "ONLOAD_THIS_THREAD" : "UNKNOWN"),
                 tapi_onload_scope2str(scope), name, out.retval);
    RETVAL_INT(onload_set_stackname, out.retval);
}

int
rpc_onload_stackname_save(rcf_rpc_server *rpcs)
{
    struct tarpc_onload_stackname_save_in  in;
    struct tarpc_onload_stackname_save_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_stackname_save, out.retval);
    }

    rcf_rpc_call(rpcs, "onload_stackname_save", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(onload_stackname_save,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, onload_stackname_save,
                 "", "%d", out.retval);
    RETVAL_INT(onload_stackname_save, out.retval);
}

int
rpc_onload_stackname_restore(rcf_rpc_server *rpcs)
{
    struct tarpc_onload_stackname_restore_in  in;
    struct tarpc_onload_stackname_restore_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_stackname_restore, out.retval);
    }

    rcf_rpc_call(rpcs, "onload_stackname_restore", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_NEGATIVE(onload_stackname_restore,
                                         out.retval);
    TAPI_RPC_LOG(rpcs, onload_stackname_restore,
                 "", "%d", out.retval);
    RETVAL_INT(onload_stackname_restore, out.retval);
}

int
rpc_onload_move_fd(rcf_rpc_server *rpcs, int fd)
{
    struct tarpc_onload_move_fd_in  in;
    struct tarpc_onload_move_fd_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_move_fd, out.retval);
    }

    in.fd = fd;

    rcf_rpc_call(rpcs, "onload_move_fd", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_NEGATIVE(onload_move_fd,
                                         out.retval);
    TAPI_RPC_LOG(rpcs, onload_move_fd, "%d", "%d",
                 in.fd, out.retval);
    RETVAL_INT(onload_move_fd, out.retval);
}

int
rpc_onload_is_present(rcf_rpc_server *rpcs)
{
    struct tarpc_onload_is_present_in  in;
    struct tarpc_onload_is_present_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_is_present, out.retval);
    }

    rcf_rpc_call(rpcs, "onload_is_present", &in, &out);

    CHECK_RETVAL_VAR(onload_is_present, out.retval,
                     (out.retval < 0 || out.retval > 1), -1);

    TAPI_RPC_LOG(rpcs, onload_is_present, "", "%s",
                 out.retval == 1 ? "PRESENT" : "NOT PRESENT");
    RETVAL_INT(onload_is_present, out.retval);
}

int
rpc_onload_fd_stat(rcf_rpc_server *rpcs, int fd,
                   tarpc_onload_stat *buf)
{
    struct tarpc_onload_fd_stat_in  in;
    struct tarpc_onload_fd_stat_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL || buf == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_INT(onload_fd_stat, out.retval);
    }

    in.fd = fd;

    rcf_rpc_call(rpcs, "onload_fd_stat", &in, &out);

    /* first copy - then think */
    memcpy(buf, &out.buf, sizeof(out.buf));
    buf->stack_name = out.buf.stack_name_null ?
        NULL : strdup(out.buf.stack_name);

    CHECK_RETVAL_VAR(onload_fd_stat, out.retval,
                     out.retval < 0, -1);
    TAPI_RPC_LOG(rpcs, onload_fd_stat, "%d",
                 "%d stack_id=%u, stack_name=%s endpoint_id=%u "
                 "endpoint_state=0x%x",
                 in.fd, out.retval,
                 buf->stack_id, buf->stack_name, buf->endpoint_id,
                 buf->endpoint_state);
    RETVAL_INT(onload_fd_stat, out.retval);
}


/* sighandler_createfile */

void
rpc_sighandler_createfile_cleanup(rcf_rpc_server *rpcs, int sig)
{
    tarpc_sighandler_createfile_cleanup_in  in;
    tarpc_sighandler_createfile_cleanup_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_VOID(sighandler_createfile_cleanup);
    }

    in.sig = sig;

    rcf_rpc_call(rpcs, "sighandler_createfile_cleanup", &in, &out);
    TAPI_RPC_LOG(rpcs, sighandler_createfile_cleanup, "%s", "",
                 signum_rpc2str(sig));
    RETVAL_VOID(sighandler_createfile_cleanup);
}

te_bool
rpc_sighandler_createfile_exists_unlink(rcf_rpc_server *rpcs, int sig)
{
    tarpc_sighandler_createfile_exists_unlink_in  in;
    tarpc_sighandler_createfile_exists_unlink_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_BOOL(sighandler_createfile_exists_unlink, FALSE);
    }

    in.sig = sig;

    rcf_rpc_call(rpcs, "sighandler_createfile_exists_unlink", &in, &out);
    CHECK_RETVAL_VAR_IS_BOOL(sighandler_createfile_exists_unlink,
                             out.retval);
    TAPI_RPC_LOG(rpcs, sighandler_createfile_exists_unlink, "%s", "%d",
                 signum_rpc2str(sig), out.retval);
    TAPI_RPC_OUT(sighandler_createfile_exists_unlink, FALSE);
    return out.retval; /* no jumps! */
}

te_bool
rpc_thrd_sighnd_crtfile_exists_unlink(rcf_rpc_server *rpcs, int sig,
                                      tarpc_pid_t pid,
                                      tarpc_pthread_t tid)
{
    tarpc_thrd_sighnd_crtfile_exists_unlink_in  in;
    tarpc_thrd_sighnd_crtfile_exists_unlink_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid parameter is passed", __FUNCTION__);
        RETVAL_BOOL(thrd_sighnd_crtfile_exists_unlink, FALSE);
    }

    in.sig = sig;
    in.pid = pid;
    in.tid = tid;

    rcf_rpc_call(rpcs, "thrd_sighnd_crtfile_exists_unlink", &in, &out);

    CHECK_RETVAL_VAR_IS_BOOL(thrd_sighnd_crtfile_exists_unlink,
                             out.retval);
    TAPI_RPC_LOG(rpcs, thrd_sighnd_crtfile_exists_unlink, "%s, %d, %llu",
                 "%d", signum_rpc2str(sig), pid,
                 (unsigned long long int)tid, out.retval);
    TAPI_RPC_OUT(thrd_sighnd_crtfile_exists_unlink, FALSE);
    return out.retval; /* no jumps! */
}

int
rpc_onload_zc_alloc_buffers(rcf_rpc_server *rpcs,
                            int fd,
                            rpc_ptr iovecs,
                            int iovecs_len,
                            tarpc_onload_zc_buffer_type_flags flags)
{
    tarpc_onload_zc_alloc_buffers_in  in;
    tarpc_onload_zc_alloc_buffers_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.iovecs = iovecs;
    in.iovecs_len = iovecs_len;
    in.flags = flags;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_zc_alloc_buffers, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): onload extention function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    rcf_rpc_call(rpcs, "onload_zc_alloc_buffers", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(onload_zc_alloc_buffers,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, onload_zc_alloc_buffers, "%d, 0x%d, %d, %d",
                 "%d", fd, iovecs, iovecs_len, flags, out.retval);
    RETVAL_INT(onload_zc_alloc_buffers, out.retval);
}

int
rpc_free_onload_zc_buffers(rcf_rpc_server *rpcs,
                           int fd,
                           rpc_ptr iovecs,
                           int iovecs_len)
{
    tarpc_free_onload_zc_buffers_in  in;
    tarpc_free_onload_zc_buffers_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.iovecs = iovecs;
    in.iovecs_len = iovecs_len;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(free_onload_zc_buffers, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): onload extention function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    rcf_rpc_call(rpcs, "free_onload_zc_buffers", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(free_onload_zc_buffers,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, free_onload_zc_buffers, "%d, 0x%d, %d",
                 "%d", fd, iovecs, iovecs_len, out.retval);
    RETVAL_INT(free_onload_zc_buffers, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_onload_zc_register_buffers(rcf_rpc_server *rpcs,
                               int fd, uint64_t addr_space,
                               rpc_ptr base_ptr, uint64_t off,
                               uint64_t len, int flags,
                               rpc_onload_zc_handle *handle)
{
    tarpc_onload_zc_register_buffers_in  in;
    tarpc_onload_zc_register_buffers_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_zc_register_buffers, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): Onload extension function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.addr_space = addr_space;
    in.base_ptr = base_ptr;
    in.off = off;
    in.len = len;
    in.flags = flags;

    rcf_rpc_call(rpcs, "onload_zc_register_buffers", &in, &out);

    if (out.retval >= 0)
        *handle = out.handle;

    TAPI_RPC_LOG(rpcs, onload_zc_register_buffers,
                 "%d, %" TE_PRINTF_64"u, " RPC_PTR_FMT ", %"
                 TE_PRINTF_64 "u, %" TE_PRINTF_64 "u, %d",
                 "%d, handle=" RPC_PTR_FMT,
                 fd, addr_space, RPC_PTR_VAL(base_ptr),
                 off, len, flags, out.retval, RPC_PTR_VAL(out.handle));
    RETVAL_INT(onload_zc_register_buffers, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_onload_zc_unregister_buffers(rcf_rpc_server *rpcs,
                                 int fd,
                                 rpc_onload_zc_handle handle,
                                 int flags)
{
    tarpc_onload_zc_unregister_buffers_in  in;
    tarpc_onload_zc_unregister_buffers_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_zc_unregister_buffers, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): Onload extension function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.handle = handle;
    in.flags = flags;

    rcf_rpc_call(rpcs, "onload_zc_unregister_buffers", &in, &out);

    TAPI_RPC_LOG(rpcs, onload_zc_unregister_buffers,
                 "%d, " RPC_PTR_FMT ", %d", "%d",
                 fd, RPC_PTR_VAL(handle), flags,
                 out.retval);
    RETVAL_INT(onload_zc_unregister_buffers, out.retval);
}

/* See description in sockapi-ts_rpc.h */
tarpc_ssize_t
rpc_onload_zc_send_msg_more(rcf_rpc_server *rpcs, int s, rpc_ptr buf,
                            tarpc_size_t first_len, tarpc_size_t second_len,
                            te_bool first_zc, te_bool second_zc,
                            te_bool use_reg_bufs,
                            te_bool set_nodelay)
{
    tarpc_onload_zc_send_msg_more_in  in;
    tarpc_onload_zc_send_msg_more_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_zc_send_msg_more, -1);
    }

    in.fd = s;
    in.first_len = first_len;
    in.second_len = second_len;
    in.first_zc = first_zc;
    in.second_zc = second_zc;
    in.buf = buf;
    in.use_reg_bufs = use_reg_bufs;
    in.set_nodelay = set_nodelay;

    rcf_rpc_call(rpcs, "onload_zc_send_msg_more", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_zc_send_msg_more, out.retval);
    TAPI_RPC_LOG(rpcs, onload_zc_send_msg_more,
                 "%d, %u , %u, %u, first_zc=%s, second_zc=%s, "
                 "use_reg_bufs=%s, set_nodelay=%s", "%d",
                 s, buf, first_len, second_len,
                 (first_zc ? "TRUE" : "FALSE"),
                 (second_zc ? "TRUE" : "FALSE"),
                 (use_reg_bufs ? "TRUE" : "FALSE"),
                 (set_nodelay ? "TRUE" : "FALSE"),
                 out.retval);
    RETVAL_INT(onload_zc_send_msg_more, out.retval);
}

/* See description in sockapi-ts_rpc.h */
rpc_ptr
rpc_sockts_alloc_zc_compl_queue(rcf_rpc_server *rpcs)
{
    tarpc_sockts_alloc_zc_compl_queue_in  in;
    tarpc_sockts_alloc_zc_compl_queue_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_RPC_PTR(sockts_alloc_zc_compl_queue, RPC_NULL);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    rcf_rpc_call(rpcs, "sockts_alloc_zc_compl_queue", &in, &out);

    TAPI_RPC_LOG(rpcs, sockts_alloc_zc_compl_queue, "",
                 RPC_PTR_FMT, RPC_PTR_VAL(out.retval));
    RETVAL_RPC_PTR(sockts_alloc_zc_compl_queue, (rpc_ptr)(out.retval));
}

/* See description in sockapi-ts_rpc.h */
int
rpc_sockts_free_zc_compl_queue(rcf_rpc_server *rpcs, rpc_ptr qhead)
{
    tarpc_sockts_free_zc_compl_queue_in  in;
    tarpc_sockts_free_zc_compl_queue_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sockts_free_zc_compl_queue, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.qhead = qhead;

    rcf_rpc_call(rpcs, "sockts_free_zc_compl_queue", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(sockts_free_zc_compl_queue,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, sockts_free_zc_compl_queue, RPC_PTR_FMT, "%d",
                 RPC_PTR_VAL(qhead), out.retval);
    RETVAL_INT(sockts_free_zc_compl_queue, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_sockts_proc_zc_compl_queue(rcf_rpc_server *rpcs, rpc_ptr qhead,
                               int timeout)
{
    tarpc_sockts_proc_zc_compl_queue_in  in;
    tarpc_sockts_proc_zc_compl_queue_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sockts_proc_zc_compl_queue, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.qhead = qhead;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "sockts_proc_zc_compl_queue", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(sockts_proc_zc_compl_queue,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, sockts_proc_zc_compl_queue, RPC_PTR_FMT ", %d", "%d",
                 RPC_PTR_VAL(qhead), timeout, out.retval);
    RETVAL_INT(sockts_proc_zc_compl_queue, out.retval);
}

/**
 * Obtain string representation of rpc_onload_zc_mmsg structure.
 *
 * @param rpcs      RPC server (used by RPC_PTR_VAL() macro).
 * @param mmsg      Pointer to structure.
 * @param str       Where to append string representation.
 *
 * @return Status code.
 */
static te_errno
onload_zc_mmsg_rpc2str(rcf_rpc_server *rpcs,
                       struct rpc_onload_zc_mmsg *mmsg, te_string *str)
{
    te_errno rc = 0;
    tarpc_size_t i;

    rc = te_string_append(str, "{ ");
    if (rc != 0)
        return rc;

    msghdr_rpc2str(&mmsg->msg, str);

    if (mmsg->buf_specs != NULL)
    {
        tarpc_onload_zc_buf_spec *specs = mmsg->buf_specs;

        rc = te_string_append(str, ", buf_specs = [");
        if (rc != 0)
            return rc;

        for (i = 0; i < mmsg->msg.msg_riovlen; i++)
        {
            if (i > 0)
            {
                rc = te_string_append(str, ", ");
                if (rc != 0)
                    return rc;
            }

            switch (specs[i].type)
            {
                case TARPC_ONLOAD_ZC_BUF_NEW_ALLOC:
                    rc = te_string_append(str, "NEW_ALLOC");
                    break;

                case TARPC_ONLOAD_ZC_BUF_NEW_REG:
                    rc = te_string_append(str, "NEW_REG");
                    break;

                case TARPC_ONLOAD_ZC_BUF_EXIST_ALLOC:
                    rc = te_string_append(
                          str,
                          "EXIST_ALLOC (buf = " RPC_PTR_FMT ", "
                          "index = %u)",
                          RPC_PTR_VAL(specs[i].existing_buf),
                          specs[i].buf_index);
                    break;

                case TARPC_ONLOAD_ZC_BUF_EXIST_REG:
                    rc = te_string_append(
                          str,
                          "EXIST_REG (buf = " RPC_PTR_FMT ", "
                          "offset = % " TE_PRINTF_64 "u)",
                          RPC_PTR_VAL(specs[i].existing_buf),
                          specs[i].buf_offset);
                    break;

                default:
                    rc = te_string_append(str, "<UNKNOWN>");
            }

            if (rc != 0)
                return rc;
        }

        rc = te_string_append(str, "]");
        if (rc != 0)
            return rc;
    }

    rc = te_string_append(str, ", keep_recv_bufs=%s, saved_recv_bufs="
                          RPC_PTR_FMT,
                          (mmsg->keep_recv_bufs ? "TRUE" : "FALSE"),
                          RPC_PTR_VAL(mmsg->saved_recv_bufs));
    if (rc != 0)
        return rc;

    if (mmsg->rc < 0)
    {
        rc = te_string_append(str, ", rc=-error:%s",
                              errno_rpc2str(-mmsg->rc));
    }
    else
    {
        rc = te_string_append(str, ", rc=%d", mmsg->rc);
    }
    if (rc != 0)
        return rc;

    return te_string_append(str, ", fd=%d }", mmsg->fd);
}

/**
 * Obtain string representation of an array of rpc_onload_zc_mmsg
 * structures.
 *
 * @param rpcs      RPC server (used by RPC_PTR_VAL() macro).
 * @param msgs      Pointer to array.
 * @param mlen      Number of elements in the array.
 * @param str       Where to append string representation.
 *
 * @return Status code.
 */
static te_errno
onload_zc_mmsgs_rpc2str(rcf_rpc_server *rpcs,
                        struct rpc_onload_zc_mmsg *msgs,
                        unsigned int mlen, te_string *str)
{
    unsigned int i;
    te_errno rc = 0;

    for (i = 0; i < mlen; i++)
    {
        if (i > 0)
        {
            rc = te_string_append(str, ", ");
            if (rc != 0)
                return rc;
        }

        rc = onload_zc_mmsg_rpc2str(rpcs, &msgs[i], str);
        if (rc != 0)
            return rc;
    }

    return 0;
}

/**
 * Convert array of rpc_onload_zc_mmsg structures to array of
 * tarpc_onload_zc_mmsg structures.
 *
 * @param msgs        Pointer to array of rpc_onload_zc_mmsg
 *                    structures.
 * @param ta_msgs     Pointer to array of tarpc_onload_zc_mmsg
 *                    structures.
 * @param mlen        Number of elements in the arrays.
 * @param recv_call   If @c TRUE, conversion is done for the purposes
 *                    of receiving RPC call.
 *
 * @return Status code.
 */
static te_errno
onload_zc_mmsgs_rpc2tarpc(struct rpc_onload_zc_mmsg *msgs,
                          struct tarpc_onload_zc_mmsg *ta_msgs,
                          int mlen, te_bool recv_call)
{
    struct tarpc_msghdr *ta_msg;
    struct rpc_msghdr *msg;
    te_errno rc;
    int j;
    int k;

    for (j = 0; j < mlen; j++)
    {
        msg = &msgs[j].msg;
        ta_msg = &ta_msgs[j].msg;
        ta_msgs[j].fd = msgs[j].fd;
        ta_msgs[j].rc = msgs[j].rc;

        if (msgs[j].buf_specs != NULL)
        {
            ta_msgs[j].buf_specs.buf_specs_val = msgs[j].buf_specs;
            ta_msgs[j].buf_specs.buf_specs_len = msg->msg_riovlen;
        }

        ta_msgs[j].keep_recv_bufs = msgs[j].keep_recv_bufs;

        rc = msghdr_rpc2tarpc(msg, ta_msg, recv_call);
        if (rc != 0)
        {
            for (k = 0; k <= j; k++)
            {
                ta_msg = &ta_msgs[k].msg;
                tarpc_msghdr_free(ta_msg);
            }
            return rc;
        }
    }

    return 0;
}

/**
 * Convert array of tarpc_onload_zc_mmsg structures to array of
 * rpc_onload_zc_mmsg structures.
 *
 * @param ta_msgs     Pointer to array of tarpc_onload_zc_mmsg
 *                    structures.
 * @param msgs        Pointer to array of rpc_onload_zc_mmsg
 *                    structures.
 * @param mlen        Number of elements in the arrays.
 *
 * @return Status code.
 */
static te_errno
onload_zc_mmsgs_tarpc2rpc(struct tarpc_onload_zc_mmsg *ta_msgs,
                          struct rpc_onload_zc_mmsg *msgs,
                          unsigned int mlen)
{
    unsigned int i;
    te_errno rc;

    for (i = 0; i < mlen; i++)
    {
        rc = msghdr_tarpc2rpc(&ta_msgs[i].msg, &msgs[i].msg);
        if (rc != 0)
            return rc;
        msgs[i].rc = ta_msgs[i].rc;
        msgs[i].saved_recv_bufs = ta_msgs[i].saved_recv_bufs;
    }

    return 0;
}

/**
 * Release resources allocated for an array of tarpc_onload_zc_mmsg
 * structures.
 *
 * @param ta_msgs     Pointer to the array.
 * @param mlen        Number of elements in the array.
 */
static void
clean_tarpc_onload_zc_mmsgs(struct tarpc_onload_zc_mmsg *ta_msgs,
                            unsigned int mlen)
{
    unsigned int i;

    for (i = 0; i < mlen; i++)
    {
        tarpc_msghdr_free(&ta_msgs[i].msg);
    }
}

/* See description in sockapi-ts_rpc.h */
int
rpc_simple_zc_send_gen(rcf_rpc_server *rpcs,
                       struct rpc_onload_zc_mmsg *msgs, int mlen,
                       rpc_send_recv_flags flags, int add_sock,
                       te_bool use_reg_bufs, rpc_ptr compl_queue,
                       int64_t *send_duration)
{
    tarpc_simple_zc_send_in  in;
    tarpc_simple_zc_send_out out;

    struct tarpc_onload_zc_mmsg  rpc_msgs[RCF_RPC_MAX_MSGHDR];
    struct tarpc_msghdr         *rpc_msg;
    int                          zc_rc[RCF_RPC_MAX_MSGHDR];

    te_string    str_msgs = TE_STRING_INIT_STATIC(4096);
    unsigned int j;
    unsigned int k;
    te_errno     rc;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(zc_rc, 0, sizeof(zc_rc));
    memset(rpc_msgs, 0, sizeof(rpc_msgs));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(simple_zc_send, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): onload extention function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    in.mlen = mlen;
    in.flags = flags;
    in.add_sock = add_sock;
    in.use_reg_bufs = use_reg_bufs;
    in.compl_queue = compl_queue;

    if (msgs != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.zc_rc.zc_rc_val = zc_rc;
        in.zc_rc.zc_rc_len = mlen;
        in.msgs.msgs_val = rpc_msgs;
        in.msgs.msgs_len = mlen;

        rc = onload_zc_mmsgs_rpc2tarpc(msgs, rpc_msgs, mlen, FALSE);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            RETVAL_INT(simple_zc_send, -1);
        }
    }

    rcf_rpc_call(rpcs, "simple_zc_send", &in, &out);
    for (k = 0; k < (unsigned int)mlen; k++)
    {
        rpc_msg = &rpc_msgs[k].msg;
        tarpc_msghdr_free(rpc_msg);
    }

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_zc_send, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        msgs != NULL && out.zc_rc.zc_rc_val != NULL)
    {
        for (j = 0; j < (unsigned)mlen; j++)
        {
            msgs[j].rc = out.zc_rc.zc_rc_val[j];

            if (j > 0)
            {
                rc = te_string_append(&str_msgs, ", ");
                if (rc != 0)
                    break;
            }

            rc = onload_zc_mmsg_rpc2str(rpcs, &msgs[j], &str_msgs);
            if (rc != 0)
                break;
        }
    }

    if (send_duration != NULL)
        *send_duration = out.send_duration;

    TAPI_RPC_LOG(rpcs, simple_zc_send, "%p (%s), %d, %s, %d, "
                 "use_reg_bufs=%s, compl_queue=" RPC_PTR_FMT,
                 "%d (send_duration = %" TE_PRINTF_64 "d)",
                 msgs, str_msgs.ptr, mlen, send_recv_flags_rpc2str(flags),
                 add_sock, (use_reg_bufs ? "TRUE" : "FALSE"),
                 RPC_PTR_VAL(compl_queue),
                 out.retval, out.send_duration);

    RETVAL_INT(simple_zc_send, out.retval);
}

int
rpc_simple_zc_recv_null(rcf_rpc_server *rpcs, int s)
{
    tarpc_simple_zc_recv_null_in  in;
    tarpc_simple_zc_recv_null_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.s = s;

    rcf_rpc_call(rpcs, "simple_zc_recv_null", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_zc_recv_null, out.retval);
    TAPI_RPC_LOG(rpcs, simple_zc_recv_null, "%d", "%d",
                 s, out.retval);
    RETVAL_INT(simple_zc_recv_null, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_simple_zc_recv_gen(rcf_rpc_server *rpcs, int s,
                       struct rpc_onload_zc_mmsg *mmsg,
                       unsigned int vlen, struct rpc_msghdr *args_msg,
                       rpc_send_recv_flags flags,
                       int *cb_flags, te_bool os_inline)
{
    tarpc_simple_zc_recv_in  in;
    tarpc_simple_zc_recv_out out;

    te_string             str_msg = TE_STRING_INIT_STATIC(16384);
    te_string             str_args_msg = TE_STRING_INIT_STATIC(4096);
    te_errno              rc;
    struct tarpc_msghdr   tarpc_msg;

    struct tarpc_onload_zc_mmsg  ta_msgs[RCF_RPC_MAX_MSGHDR];

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(simple_zc_recv, -1);
    }

    if (vlen > RCF_RPC_MAX_MSGHDR)
    {
        ERROR("simple_zc_recv() RPC call supports only up to "
              "%u messages", RCF_RPC_MAX_MSGHDR);
        rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
        RETVAL_INT(simple_zc_recv, -1);
    }

    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        ERROR("%s(): onload extention function can't be found in libc",
              __FUNCTION__);
        rpcs->_errno = TE_RC(TE_TAPI, TE_EINVAL);
        RETVAL_INT(simple_zc_recv, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(&tarpc_msg, 0, sizeof(tarpc_msg));
    memset(ta_msgs, 0, sizeof(ta_msgs));

    in.s = s;
    in.flags = flags;
    in.vlen = vlen;
    in.os_inline = os_inline;
    if (rpcs->op != RCF_RPC_WAIT)
    {
        if (cb_flags == NULL)
        {
            in.cb_flags.cb_flags_val = NULL;
            in.cb_flags.cb_flags_len = 0;
        }
        else
        {
            in.cb_flags.cb_flags_val = cb_flags;
            in.cb_flags.cb_flags_len = vlen;
        }
    }

    if (mmsg != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        rc = onload_zc_mmsgs_rpc2tarpc(mmsg, ta_msgs, vlen, TRUE);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            RETVAL_INT(simple_zc_recv, -1);
        }

        in.mmsg.mmsg_val = ta_msgs;
        in.mmsg.mmsg_len = vlen;
    }

    if (args_msg != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        rc = msghdr_rpc2tarpc(args_msg, &tarpc_msg, TRUE);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            clean_tarpc_onload_zc_mmsgs(ta_msgs, vlen);
            RETVAL_INT(simple_zc_recv, -1);
        }

        in.args_msg.args_msg_val = &tarpc_msg;
        in.args_msg.args_msg_len = 1;
    }

    rcf_rpc_call(rpcs, "simple_zc_recv", &in, &out);
    clean_tarpc_onload_zc_mmsgs(ta_msgs, vlen);
    tarpc_msghdr_free(&tarpc_msg);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_zc_recv, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT)
    {
        if (mmsg != NULL && out.mmsg.mmsg_val != NULL)
        {
            if (cb_flags != NULL && out.cb_flags.cb_flags_val != NULL)
            {
                memcpy(cb_flags, out.cb_flags.cb_flags_val,
                       sizeof(*cb_flags) * out.cb_flags.cb_flags_len);
            }

            rc = onload_zc_mmsgs_tarpc2rpc(out.mmsg.mmsg_val, mmsg,
                                           out.mmsg.mmsg_len);
            if (rc != 0)
            {
                rpcs->_errno = TE_RC(TE_TAPI, rc);
                RETVAL_INT(simple_zc_recv, -1);
            }
        }

        if (args_msg != NULL && out.args_msg.args_msg_val != NULL)
        {
            rc = msghdr_tarpc2rpc(out.args_msg.args_msg_val, args_msg);
            if (rc != 0)
            {
                rpcs->_errno = TE_RC(TE_TAPI, rc);
                RETVAL_INT(simple_zc_recv, -1);
            }
        }
    }

    rc = onload_zc_mmsgs_rpc2str(rpcs, mmsg, vlen, &str_msg);
    if (rc != 0)
        ERROR("onload_zc_mmsgs_rpc2str() returned %r", rc);

    TAPI_RPC_LOG(rpcs, simple_zc_recv, "%d, %p (%s), %d, %s, "
                 "os_inline=%s, ", "%d args_msg=%s",
                 s, mmsg, str_msg.ptr,
                 vlen, send_recv_flags_rpc2str(flags),
                 (os_inline ? "TRUE" : "FALSE"),
                 out.retval,
                 msghdr_rpc2str(args_msg, &str_args_msg));
    RETVAL_INT(simple_zc_recv, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
tarpc_ssize_t
rpc_simple_hlrx_recv_zc(rcf_rpc_server *rpcs,
                        int s, struct rpc_msghdr *msg,
                        rpc_send_recv_flags flags,
                        te_bool os_inline)
{
    te_string str_msg = TE_STRING_INIT_STATIC(2048);

    tarpc_simple_hlrx_recv_zc_in  in;
    tarpc_simple_hlrx_recv_zc_out out;

    struct tarpc_msghdr rpc_msg;
    te_errno            rc;

    if (rpcs == NULL)
    {
        ERROR("%s(): invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(simple_hlrx_recv_zc, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): Onload extension function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(&rpc_msg, 0, sizeof(rpc_msg));

    in.s = s;
    in.flags = flags;
    in.os_inline = os_inline;

    if (msg != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.msg.msg_val = &rpc_msg;
        in.msg.msg_len = 1;

        rc = msghdr_rpc2tarpc(msg, &rpc_msg, TRUE);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            tarpc_msghdr_free(&rpc_msg);
            RETVAL_INT(simple_hlrx_recv_zc, -1);
        }
    }

    rcf_rpc_call(rpcs, "simple_hlrx_recv_zc", &in, &out);

    tarpc_msghdr_free(&rpc_msg);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_hlrx_recv_zc, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        msg != NULL && out.msg.msg_val != NULL)
    {
        rc = msghdr_tarpc2rpc(&out.msg.msg_val[0], msg);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            RETVAL_INT(simple_hlrx_recv_zc, -1);
        }
    }

    TAPI_RPC_LOG(rpcs, simple_hlrx_recv_zc, "%d, %p (%s), %s, on_inline=%s",
                 "%" TE_PRINTF_SIZE_T "d",
                 s, msg, msghdr_rpc2str(msg, &str_msg),
                 send_recv_flags_rpc2str(flags),
                 (os_inline ? "TRUE" : "FALSE"),
                 (tarpc_ssize_t)(out.retval));

    RETVAL_INT(simple_hlrx_recv_zc, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
extern tarpc_ssize_t
rpc_simple_hlrx_recv_copy(rcf_rpc_server *rpcs,
                          int s, struct rpc_msghdr *msg,
                          rpc_send_recv_flags flags,
                          te_bool os_inline)
{
    te_string str_msg = TE_STRING_INIT_STATIC(2048);

    tarpc_simple_hlrx_recv_copy_in  in;
    tarpc_simple_hlrx_recv_copy_out out;

    struct tarpc_msghdr rpc_msg;
    te_errno            rc;

    if (rpcs == NULL)
    {
        ERROR("%s(): invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(simple_hlrx_recv_copy, -1);
    }
    if (rpcs->use_libc || rpcs->use_libc_once)
    {
        rpcs->_errno = RPC_ENOENT;
        ERROR("%s(): Onload extension function can't be found in libc",
              __FUNCTION__);
        return -1;
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    memset(&rpc_msg, 0, sizeof(rpc_msg));

    in.s = s;
    in.flags = flags;
    in.os_inline = os_inline;

    if (msg != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.msg.msg_val = &rpc_msg;
        in.msg.msg_len = 1;

        rc = msghdr_rpc2tarpc(msg, &rpc_msg, TRUE);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            tarpc_msghdr_free(&rpc_msg);
            RETVAL_INT(simple_hlrx_recv_copy, -1);
        }
    }

    rcf_rpc_call(rpcs, "simple_hlrx_recv_copy", &in, &out);

    tarpc_msghdr_free(&rpc_msg);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_hlrx_recv_copy, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT &&
        msg != NULL && out.msg.msg_val != NULL)
    {
        rc = msghdr_tarpc2rpc(&out.msg.msg_val[0], msg);
        if (rc != 0)
        {
            rpcs->_errno = TE_RC(TE_TAPI, rc);
            RETVAL_INT(simple_hlrx_recv_copy, -1);
        }
    }

    TAPI_RPC_LOG(rpcs, simple_hlrx_recv_copy,
                 "%d, %p (%s), %s, on_inline=%s",
                 "%" TE_PRINTF_SIZE_T "d",
                 s, msg, msghdr_rpc2str(msg, &str_msg),
                 send_recv_flags_rpc2str(flags),
                 (os_inline ? "TRUE" : "FALSE"),
                 (tarpc_ssize_t)(out.retval));

    RETVAL_INT(simple_hlrx_recv_copy, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_onload_set_recv_filter_capture(rcf_rpc_server *rpcs, int s, int flags)
{
  tarpc_onload_set_recv_filter_capture_in  in;
  tarpc_onload_set_recv_filter_capture_out out;

  memset(&in, 0, sizeof(in));
  memset(&out, 0, sizeof(out));

  if (rpcs == NULL)
  {
      ERROR("%s(): invalid RPC server handle", __FUNCTION__);
      RETVAL_INT(onload_set_recv_filter_capture, -1);
  }

  in.fd = s;
  in.flags = flags;

  rcf_rpc_call(rpcs, "onload_set_recv_filter_capture", &in, &out);

  CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(onload_set_recv_filter_capture,
                                        out.retval);
  TAPI_RPC_LOG(rpcs, onload_set_recv_filter_capture, "%d, %d", "%d",
               s, flags, out.retval);
  RETVAL_INT(onload_set_recv_filter_capture, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
tarpc_ssize_t
rpc_sockts_recv_filtered_pkt(rcf_rpc_server *rpcs, int s,
                             char *buf, tarpc_size_t len)
{
    tarpc_sockts_recv_filtered_pkt_in  in;
    tarpc_sockts_recv_filtered_pkt_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL || buf == NULL)
    {
        ERROR("%s(): invalid arguments", __FUNCTION__);
        RETVAL_INT(sockts_recv_filtered_pkt, -1);
    }

    in.fd = s;
    in.len = len;

    rcf_rpc_call(rpcs, "sockts_recv_filtered_pkt", &in, &out);

    if (RPC_IS_CALL_OK(rpcs) && out.retval > 0)
    {
        assert(out.buf.buf_len <= len);
        memcpy(buf, out.buf.buf_val, out.buf.buf_len);
    }

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(sockts_recv_filtered_pkt,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, sockts_recv_filtered_pkt,
                 "%d, %p, %" TE_PRINTF_SIZE_T "u", "%d",
                 s, buf, len, (int)out.retval);
    RETVAL_INT(sockts_recv_filtered_pkt, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_sockts_recv_filtered_pkts_clear(rcf_rpc_server *rpcs)
{
    tarpc_sockts_recv_filtered_pkts_clear_in  in;
    tarpc_sockts_recv_filtered_pkts_clear_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): invalid arguments", __FUNCTION__);
        RETVAL_INT(sockts_recv_filtered_pkts_clear, -1);
    }

    rcf_rpc_call(rpcs, "sockts_recv_filtered_pkts_clear", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(sockts_recv_filtered_pkts_clear,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, sockts_recv_filtered_pkts_clear,
                 "", "%d", out.retval);
    RETVAL_INT(sockts_recv_filtered_pkts_clear, out.retval);
}

int
rpc_simple_set_recv_filter(rcf_rpc_server *rpcs, int s, const void *buf,
                           tarpc_size_t len, int flags)
{
    tarpc_simple_set_recv_filter_in  in;
    tarpc_simple_set_recv_filter_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(simple_set_recv_filter, -1);
    }

    in.fd = s;
    in.len = len;
    if (buf != NULL && rpcs->op != RCF_RPC_WAIT)
    {
        in.buf.buf_len = len;
        in.buf.buf_val = (uint8_t *)buf;
    }
    in.flags = flags;

    rcf_rpc_call(rpcs, "simple_set_recv_filter", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(simple_set_recv_filter, out.retval);
    TAPI_RPC_LOG(rpcs, simple_set_recv_filter, "%d, %p, %u, %d", "%d",
                 s, buf, len, flags, out.retval);
    RETVAL_INT(simple_set_recv_filter, out.retval);
}

void
iov_h2rpc(struct tarpc_iovec* iov_arr, const rpc_iovec* iov, tarpc_size_t iovcnt,
          char *strbuf, int strbuf_len)
{
    tarpc_size_t i;

    memset(strbuf, 0, strbuf_len);
    snprintf(strbuf, strbuf_len, "{");

    for (i = 0; i < iovcnt; i++)
    {
        iov_arr[i].iov_base.iov_base_val = iov[i].iov_base;
        iov_arr[i].iov_base.iov_base_len = iov[i].iov_rlen;
        iov_arr[i].iov_len = iov[i].iov_len;

        snprintf(strbuf + strlen(strbuf),
                 strbuf_len - strlen(strbuf),
                 "%s{%"TE_PRINTF_SIZE_T"u, %p[%"TE_PRINTF_SIZE_T"u]}",
                 (i == 0) ? "" : ", ", iov[i].iov_len,
                 iov[i].iov_base, iov[i].iov_rlen);
    }

    snprintf(strbuf + strlen(strbuf), strbuf_len - strlen(strbuf), "}");
}

/**
 * Check parameters and initialize argument @a in.
 * 
 * @note See parameters description of rpc_onload_msg_template_alloc().
 *       Function overwrites global buffer @b str_buf_1
 * 
 * @return Status code
 */
static int
rpc_onload_msg_template_in_init(tarpc_onload_msg_template_alloc_in *in,
                                rcf_rpc_server *rpcs, int fd,
                                struct tarpc_iovec *iov_arr, rpc_iovec* iov,
                                tarpc_size_t iovcnt, tarpc_size_t riovcnt,
                                rpc_onload_template_handle* handle,
                                int flags)
{
    memset(in, 0, sizeof(*in));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        return -1;
    }

    if ((iov == NULL && riovcnt != 0) ||
        riovcnt > RCF_RPC_MAX_IOVEC)
    {
        rpcs->_errno = TE_RC(TE_RCF, TE_EINVAL);
        return -1;
    }

    iov_h2rpc(iov_arr, iov, riovcnt, str_buf_1, sizeof(str_buf_1));

    if (handle != NULL)
    {
        if (*handle == 0)
            in->handle = -1;
        else
            in->handle = *handle;
    }

    in->fd = fd;
    in->iovcnt = iovcnt;
    in->vector.vector_val = iov_arr;
    in->vector.vector_len = riovcnt;
    in->flags = flags;

    return 0;
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_onload_msg_template_alloc_gen(rcf_rpc_server *rpcs, int fd,
                              rpc_iovec* iov, tarpc_size_t iovcnt, tarpc_size_t riovcnt,
                              rpc_onload_template_handle* handle,
                              int flags)
{
    tarpc_onload_msg_template_alloc_in  in;
    tarpc_onload_msg_template_alloc_out out;
    struct tarpc_iovec  iov_arr[RCF_RPC_MAX_IOVEC];

    memset(&out, 0, sizeof(out));
    memset(iov_arr, 0, sizeof(*iov_arr) * RCF_RPC_MAX_IOVEC);

    if (rpc_onload_msg_template_in_init(&in, rpcs, fd, iov_arr, iov, iovcnt,
                                        riovcnt, handle, flags) != 0)
        RETVAL_INT(onload_msg_template_alloc, -1);

    rcf_rpc_call(rpcs, "onload_msg_template_alloc", &in, &out);

    if (handle != NULL)
        *handle = out.handle;

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_msg_template_alloc,
                                      out.retval);

    TAPI_RPC_LOG(rpcs, onload_msg_template_alloc,
                 "%d, %s, %d, %x, %d", "%d", fd, str_buf_1, iovcnt, handle,
                 flags, out.retval);
    RETVAL_INT(onload_msg_template_alloc, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_onload_msg_template_abort(rcf_rpc_server *rpcs, int fd,
                              rpc_onload_template_handle handle)
{
    tarpc_onload_msg_template_abort_in  in;
    tarpc_onload_msg_template_abort_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_msg_template_abort, -1);
    }

    in.handle = handle;
    in.fd = fd;

    rcf_rpc_call(rpcs, "onload_msg_template_abort", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_msg_template_abort,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_msg_template_abort, "%d, %x", "%d",
                 fd, handle, out.retval);
    RETVAL_INT(simple_set_recv_filter, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_onload_msg_template_update_gen(rcf_rpc_server *rpcs, int fd,
                              rpc_onload_template_handle handle,
                              rpc_onload_template_msg_update_iovec *updates,
                              tarpc_size_t iovcnt, tarpc_size_t riovcnt, int flags)
{
    tarpc_onload_msg_template_update_in     in;
    tarpc_onload_msg_template_update_out    out;
    tarpc_onload_template_msg_update_iovec  upd_arr[RCF_RPC_MAX_IOVEC];

    tarpc_size_t  i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_msg_template_update, -1);
    }

    memset(str_buf_1, 0, sizeof(str_buf_1));
    snprintf(str_buf_1, sizeof(str_buf_1), "{");

    for (i = 0; i < riovcnt; i++)
    {
        upd_arr[i].otmu_base.otmu_base_val = updates[i].otmu_base;
        upd_arr[i].otmu_base.otmu_base_len = updates[i].otmu_rlen;
        upd_arr[i].otmu_len = updates[i].otmu_len;
        upd_arr[i].otmu_offset = updates[i].otmu_offset;
        upd_arr[i].otmu_flags = updates[i].otmu_flags;

        snprintf(str_buf_1 + strlen(str_buf_1),
                 sizeof(str_buf_1) - strlen(str_buf_1),
                 "%s{%" TE_PRINTF_SIZE_T "u, %p[%"
                 TE_PRINTF_SIZE_T "u], %d, %d}",
                 (i == 0) ? "" : ", ", updates[i].otmu_len,
                 updates[i].otmu_base, updates[i].otmu_rlen,
                 (int)upd_arr[i].otmu_offset, upd_arr[i].otmu_flags);
    }

    snprintf(str_buf_1 + strlen(str_buf_1),
             sizeof(str_buf_1) - strlen(str_buf_1), "}");


    in.handle = handle;
    in.updates.updates_val = upd_arr;
    in.updates.updates_len = riovcnt;
    in.iovcnt = iovcnt;
    in.flags = flags;
    in.fd = fd;

    rcf_rpc_call(rpcs, "onload_msg_template_update", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_msg_template_update,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_msg_template_update, "%d, %x, %s, %d, %d",
                 "%d", fd, handle, str_buf_1, iovcnt, flags, out.retval);
    RETVAL_INT(onload_msg_template_update, out.retval);
}

/* See description in the sockapi-ts_rpc.h */
int
rpc_template_send(rcf_rpc_server *rpcs, int fd, rpc_iovec* iov,
                  tarpc_size_t iovcnt, tarpc_size_t riovcnt, int flags)
{
    tarpc_template_send_in  in;
    tarpc_template_send_out out;
    struct tarpc_iovec  iov_arr[RCF_RPC_MAX_IOVEC];

    memset(&out, 0, sizeof(out));
    memset(iov_arr, 0, sizeof(*iov_arr) * RCF_RPC_MAX_IOVEC);

    if (rpc_onload_msg_template_in_init(&in, rpcs, fd, iov_arr, iov, iovcnt,
                                        riovcnt, NULL, flags) != 0)
        RETVAL_INT(template_send, -1);

    rcf_rpc_call(rpcs, "template_send", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(template_send, out.retval);
    TAPI_RPC_LOG(rpcs, template_send, "%d, %s, %d, %d", "%d",
                 fd, str_buf_1, iovcnt, flags, out.retval);

    RETVAL_INT(template_send, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_popen_flooder(rcf_rpc_server *rpcs, int threads, int iterations,
                  int popen_iter, te_bool sync)
{
    tarpc_popen_flooder_in    in;
    tarpc_popen_flooder_out   out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.threads = threads;
    in.iterations = iterations;
    in.popen_iter = popen_iter;
    in.sync = sync;

    rcf_rpc_call(rpcs, "popen_flooder", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(popen_flooder, out.retval);

    TAPI_RPC_LOG(rpcs, popen_flooder, "%d, %d", "%d", iterations, sync,
                 out.retval);
    RETVAL_INT(popen_flooder, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
void
rpc_popen_flooder_toggle(rcf_rpc_server *rpcs, te_bool enable)
{
    tarpc_popen_flooder_toggle_in    in;
    tarpc_popen_flooder_toggle_out   out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.enable = enable;

    rcf_rpc_call(rpcs, "popen_flooder_toggle", &in, &out);
    TAPI_RPC_LOG(rpcs, popen_flooder_toggle, "%d", "", enable);
}

/**
 * Convert @b onload_ordered_epoll_wait call output values to string
 * representation for logging.
 * 
 * @param evts      Array with epoll events
 * @param oo_events Array with extented WODA data
 * @param n_evts    Events number
 * @param buf       Buffer to save string
 * @param buflen    The buffer length
 */
static void
oo_epollevt2str(struct rpc_epoll_event *evts,
                rpc_onload_ordered_epoll_event *oo_events,
                int n_evts, char *buf, tarpc_size_t buflen)
{
    int i;
    int rc;

    if (evts == NULL || oo_events == NULL || n_evts < 0)
    {
        *buf = '\0';
        return;
    }

    do {
        rc = snprintf(buf, buflen, "{");
        if ((tarpc_size_t)rc > buflen)
            break;
        buflen -= rc;
        buf += rc;
        for (i = 0; i < n_evts; ++i)
        {
            rc = snprintf(buf, buflen,
                          "{sock %d, bytes %d, ts %ld.%ld, %s} ",
                          evts[i].data.fd, oo_events[i].bytes,
                          (long)oo_events[i].ts.tv_sec,
                          oo_events[i].ts.tv_nsec,
                          epoll_event_rpc2str(evts[i].events));
            if ((tarpc_size_t)rc > buflen)
                break;
            buflen -= rc;
            buf += rc;
        }
        rc = snprintf(buf, buflen, "}");
        if ((tarpc_size_t)rc > buflen)
            break;
        buflen -= rc;
        buf += rc;

        return;

    } while (0);

    ERROR("Too small buffer for onload_ordered_epoll_wait events "
          "conversion");
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_onload_ordered_epoll_wait_gen(rcf_rpc_server *rpcs, int epfd,
                                  struct rpc_epoll_event *events,
                                  rpc_onload_ordered_epoll_event *oo_events,
                                  int rmaxev, int maxevents, int timeout)
{
    tarpc_onload_ordered_epoll_wait_in   in;
    tarpc_onload_ordered_epoll_wait_out  out;
    tarpc_onload_ordered_epoll_event    *oo_evts;
    tarpc_epoll_event                   *evts;
    int     i;

    evts = calloc(rmaxev, sizeof(tarpc_epoll_event));
    oo_evts = calloc(rmaxev, sizeof(tarpc_onload_ordered_epoll_event));

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(onload_ordered_epoll_wait, -1);
    }

    in.epfd = epfd;
    in.timeout = timeout;
    in.maxevents = maxevents;
    for (i = 0; i < rmaxev; i++)
    {
        oo_evts[i].bytes = oo_events[i].bytes;
        oo_evts[i].ts.tv_sec = oo_events[i].ts.tv_sec;
        oo_evts[i].ts.tv_nsec = oo_events[i].ts.tv_nsec;
        evts[i].events = events[i].events;
        evts[i].data.type = TARPC_ED_INT;
        evts[i].data.tarpc_epoll_data_u.fd = events[i].data.fd;
    }
    in.events.events_len = rmaxev;
    in.events.events_val = (struct tarpc_epoll_event *)evts;
    in.oo_events.oo_events_len = rmaxev;
    in.oo_events.oo_events_val = oo_evts;

    if ((timeout > 0) && (rpcs->timeout == RCF_RPC_UNSPEC_TIMEOUT))
        rpcs->timeout = TE_SEC2MS(TAPI_RPC_TIMEOUT_EXTRA_SEC) + timeout;

    rcf_rpc_call(rpcs, "onload_ordered_epoll_wait", &in, &out);

    if (RPC_IS_CALL_OK(rpcs))
    {
        if (events != NULL && out.events.events_val != NULL)
        {
            for (i = 0; i < out.retval; i++)
            {
                oo_events[i].bytes = out.oo_events.oo_events_val[i].bytes;
                oo_events[i].ts.tv_sec =
                    out.oo_events.oo_events_val[i].ts.tv_sec;
                oo_events[i].ts.tv_nsec =
                    out.oo_events.oo_events_val[i].ts.tv_nsec;

                events[i].events = out.events.events_val[i].events;
                events[i].data.fd =
                    out.events.events_val[i].data.tarpc_epoll_data_u.fd;
            }
        }

        oo_epollevt2str(events, oo_events, out.retval, str_buf_1,
                        sizeof(str_buf_1));
    }
    else
    {
        *str_buf_1 = '\0';
    }
    free(evts);
    free(oo_evts);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(onload_ordered_epoll_wait,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, onload_ordered_epoll_wait, "%d, %p, %d, %d", "%d %s",
                 epfd, events, maxevents, timeout, out.retval, str_buf_1);

    RETVAL_INT(onload_ordered_epoll_wait, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int rpc_send_msg_warm_flow(rcf_rpc_server *rpcs,
                           const char *func_name,
                           int fd1, int fd2,
                           tarpc_size_t buf_size_min,
                           tarpc_size_t buf_size_max,
                           unsigned int time2run,
                           uint64_t *sent1, uint64_t *sent2)
{
    tarpc_send_msg_warm_flow_in  in;
    tarpc_send_msg_warm_flow_out out;

    char *func_name_dup;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    func_name_dup = strdup(func_name);
    if (func_name_dup == NULL)
    {
        ERROR("%s(): out of memory", __FUNCTION__);
        rpcs->_errno = TE_RC(TE_RCF, TE_ENOMEM);
        return -1;
    }

    in.func_name.func_name_len = strlen(func_name_dup) + 1;
    in.func_name.func_name_val = func_name_dup;
    in.fd1 = fd1;
    in.fd2 = fd2;
    in.buf_size_min = buf_size_min;
    in.buf_size_max = buf_size_max;
    in.time2run = time2run;

    rcf_rpc_call(rpcs, "send_msg_warm_flow", &in, &out);
    free(func_name_dup);

    if (sent1 != NULL)
        *sent1 = out.sent1;
    if (sent2 != NULL)
        *sent2 = out.sent2;

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(send_msg_warm_flow, out.retval);

    TAPI_RPC_LOG(rpcs, send_msg_warm_flow,
                 "%s, %d, %d, %" TE_PRINTF_SIZE_T "u, "
                 "%" TE_PRINTF_SIZE_T "u, %d, "
                 "%" TE_PRINTF_64 "u, %" TE_PRINTF_64 "u", "%d",
                 func_name, fd1, fd2, buf_size_min, buf_size_max,
                 time2run, out.sent1, out.sent2, out.retval);

    RETVAL_INT(send_msg_warm_flow, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_many_send_cork(rcf_rpc_server *rpcs, int fd, int fd_aux,
                   tarpc_size_t size_min, tarpc_size_t size_max, tarpc_size_t send_num,
                   tarpc_size_t length, int send_usleep, te_bool tcp_nodelay,
                   te_bool no_trigger)
{
    tarpc_many_send_cork_in  in;
    tarpc_many_send_cork_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.fd_aux = fd_aux;
    in.size_min = size_min;
    in.size_max = size_max;
    in.length = length;
    in.send_num = send_num;
    in.send_usleep = send_usleep;
    in.tcp_nodelay = tcp_nodelay;
    in.no_trigger = no_trigger;

    rcf_rpc_call(rpcs, "many_send_cork", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(many_send_cork, out.retval);

    TAPI_RPC_LOG(rpcs, many_send_cork,
                 "%d, %d, %" TE_PRINTF_SIZE_T "u, %" TE_PRINTF_SIZE_T "u, %"
                 TE_PRINTF_SIZE_T "u, %" TE_PRINTF_SIZE_T"u, %d, %d, %s",
                 "%d",
                 fd, fd_aux, size_min, size_max, send_num, length,
                 send_usleep, tcp_nodelay, (no_trigger ? "true" : "false"),
                 out.retval);

    RETVAL_INT(many_send_cork, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
tarpc_ssize_t
rpc_recv_timing(rcf_rpc_server *rpcs, int fd, int fd_aux,
                tarpc_size_t length, uint64_t *duration)
{
    tarpc_recv_timing_in  in;
    tarpc_recv_timing_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = fd;
    in.fd_aux = fd_aux;
    in.length = length;

    rcf_rpc_call(rpcs, "recv_timing", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(recv_timing, out.retval);

    TAPI_RPC_LOG(rpcs, recv_timing,
                 "%d, %d, %" TE_PRINTF_SIZE_T "u",
                 "%d duration %" TE_PRINTF_64 "u",
                 fd, fd_aux, length, out.retval, out.duration);

    if (duration != NULL)
        *duration = out.duration;

    RETVAL_INT(recv_timing, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_epoll_wait_loop(rcf_rpc_server *rpcs, int epfd,
                    struct rpc_epoll_event *event,
                    int timeout)
{
    tarpc_epoll_wait_loop_in  in;
    tarpc_epoll_wait_loop_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.epfd = epfd;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "epoll_wait_loop", &in, &out);

    if (out.events.events_len > 0)
    {
        event->events = out.events.events_val[0].events;
        event->data.fd =
              out.events.events_val[0].data.tarpc_epoll_data_u.fd;
    }

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(epoll_wait_loop, out.retval);
    TAPI_RPC_LOG(rpcs, epoll_wait_loop, "%d, %d", "%d %s",
                 epfd, timeout, out.retval,
                 (out.retval > 0 ?
                        epoll_event_rpc2str(event->events) : ""));
    RETVAL_INT(epoll_wait_loop, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_wait_tcp_socket_termination(rcf_rpc_server *rpcs,
                                const struct sockaddr *loc_addr,
                                const struct sockaddr *rem_addr,
                                rpc_tcp_state *last_state,
                                int *last_state_time,
                                int *close_time)
{
    tarpc_wait_tcp_socket_termination_in  in;
    tarpc_wait_tcp_socket_termination_out out;

    char loc_buf[TE_SOCKADDR_STR_LEN];
    char rem_buf[TE_SOCKADDR_STR_LEN];

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    sockaddr_input_h2rpc(loc_addr, &in.loc_addr);
    sockaddr_input_h2rpc(rem_addr, &in.rem_addr);

    rcf_rpc_call(rpcs, "wait_tcp_socket_termination", &in, &out);

    if (last_state != NULL)
        *last_state = out.last_state;
    if (last_state_time != NULL)
        *last_state_time = out.last_state_time;
    if (close_time != NULL)
        *close_time = out.close_time;

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(wait_tcp_socket_termination,
                                          out.retval);

    TAPI_RPC_LOG(rpcs, wait_tcp_socket_termination,
                 "%s, %s",
                 "%d last_state=%s last_state_time=%d ms close_time=%d ms",
                 SOCKADDR_H2STR_SBUF(loc_addr, loc_buf),
                 SOCKADDR_H2STR_SBUF(rem_addr, rem_buf),
                 out.retval, tcp_state_rpc2str(out.last_state),
                 out.last_state_time, out.close_time);

    RETVAL_INT(wait_tcp_socket_termination, out.retval);
}

static const char *
disconn_way2str(tarpc_disconn_way way)
{
    switch (way)
    {
        case CLOSE:
            return "close";
        case EXIT:
            return "exit";
        case DISCONNECT:
            return "disconnect";
        default:
            return "<unknown>";
    }
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_sendmmsg_disconnect(rcf_rpc_server *rpcs, int *fd,
                        unsigned int msg_size,
                        unsigned int msg_len,
                        tarpc_disconn_way disconn_way,
                        const struct sockaddr *connect_to_addr)
{
    tarpc_sendmmsg_disconnect_in  in;
    tarpc_sendmmsg_disconnect_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sendmmsg_disconnect, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    sockaddr_input_h2rpc(connect_to_addr, &in.connect_to_addr);

    in.msg_size = msg_size;
    in.msg_len = msg_len;
    in.disconn_way = disconn_way;

    if (fd != NULL && rpcs->op != RCF_RPC_WAIT)
        in.fd = *fd;

    rcf_rpc_call(rpcs, "sendmmsg_disconnect", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(sendmmsg_disconnect, out.retval);

    if (RPC_IS_CALL_OK(rpcs) && rpcs->op != RCF_RPC_WAIT && fd != NULL)
        *fd = out.fd;

    TAPI_RPC_LOG(rpcs, sendmmsg_disconnect, "%d, %d, %d, %s", "%d, fd=%d",
                 in.fd, msg_size, msg_len, disconn_way2str(disconn_way),
                 out.retval, out.fd);
    RETVAL_INT(sendmmsg_disconnect, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_get_tcp_socket_state(rcf_rpc_server *rpcs,
                         const struct sockaddr *loc_addr,
                         const struct sockaddr *rem_addr,
                         rpc_tcp_state *state,
                         te_bool *found)
{

    tarpc_get_tcp_socket_state_in  in;
    tarpc_get_tcp_socket_state_out out;

    char loc_buf[TE_SOCKADDR_STR_LEN];
    char rem_buf[TE_SOCKADDR_STR_LEN];

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    sockaddr_input_h2rpc(loc_addr, &in.loc_addr);
    sockaddr_input_h2rpc(rem_addr, &in.rem_addr);

    rcf_rpc_call(rpcs, "get_tcp_socket_state", &in, &out);

    if (state != NULL)
        *state = out.state;
    if (found != NULL)
        *found = out.found;

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(get_tcp_socket_state,
                                          out.retval);

    TAPI_RPC_LOG(rpcs, get_tcp_socket_state,
                 "%s, %s",
                 "%d state=%s found=%s",
                 SOCKADDR_H2STR_SBUF(loc_addr, loc_buf),
                 SOCKADDR_H2STR_SBUF(rem_addr, rem_buf),
                 out.retval, tcp_state_rpc2str(out.state),
                 (out.found ? "TRUE" : "FALSE"));

    RETVAL_INT(get_tcp_socket_state, out.retval);
}

static const char *send_func2str(tarpc_send_function f)
{
    switch (f)
    {
        case TARPC_SEND_FUNC_WRITE:
            return "write";
        case TARPC_SEND_FUNC_WRITEV:
            return "writev";
        case TARPC_SEND_FUNC_SEND:
            return "send";
        case TARPC_SEND_FUNC_SENDTO:
            return "sendto";
        case TARPC_SEND_FUNC_SENDMSG:
            return "sendmsg";
        default:
            return "<unknown>";
    }
}

static const char *recv_func2str(tarpc_recv_function f)
{
    switch (f)
    {
        case TARPC_RECV_FUNC_RECV:
            return "recv";
        case TARPC_RECV_FUNC_RECVFROM:
            return "recvfrom";
        default:
            return "<unknown>";
    }
}

/* See description in sockapi-ts_rpc.h */
int
rpc_send_var_size(rcf_rpc_server *rpcs,
                  tarpc_send_function send_func,
                  int s, tarpc_size_t len,
                  rpc_send_recv_flags flags,
                  const struct sockaddr *addr)
{
    tarpc_send_var_size_in in;
    tarpc_send_var_size_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(send_var_size, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = s;
    in.len = len;
    if (rpcs->op != RCF_RPC_WAIT)
        sockaddr_input_h2rpc(addr, &in.addr);
    in.flags = flags;
    in.send_func = send_func;

    rcf_rpc_call(rpcs, "send_var_size", &in, &out);
    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(send_var_size, out.retval);
    TAPI_RPC_LOG(rpcs, send_var_size, "%d, %" TE_PRINTF_SIZE_T "u"
                 ", %s, %s, %s", "%d", in.fd, in.len,
                 send_recv_flags_rpc2str(flags),
                 sockaddr_h2str(addr),
                 send_func2str(send_func), out.retval);
    RETVAL_INT(send_var_size, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_recv_var_size(rcf_rpc_server *rpcs,
                  tarpc_recv_function recv_func,
                  int s, tarpc_size_t len,
                  rpc_send_recv_flags flags)
{
    tarpc_recv_var_size_in in;
    tarpc_recv_var_size_out out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(recv_var_size, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = s;
    in.len = len;
    in.flags = flags;
    in.recv_func = recv_func;

    rcf_rpc_call(rpcs, "recv_var_size", &in, &out);
    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(recv_var_size, out.retval);
    TAPI_RPC_LOG(rpcs, recv_var_size, "%d, %" TE_PRINTF_SIZE_T "u"
                 ", %s, %s", "%d", in.fd, in.len,
                 send_recv_flags_rpc2str(flags),
                 recv_func2str(recv_func), out.retval);
    RETVAL_INT(recv_var_size, out.retval);
}

/* See description in sockapi-ts_rpc.h */
rpc_ptr
rpc_sockts_alloc_send_func_ctx(rcf_rpc_server *rpcs)
{
    tarpc_sockts_alloc_send_func_ctx_in     in;
    tarpc_sockts_alloc_send_func_ctx_out    out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_RPC_PTR(sockts_alloc_send_func_ctx, RPC_NULL);
    }

    rcf_rpc_call(rpcs, "sockts_alloc_send_func_ctx", &in, &out);

    TAPI_RPC_LOG(rpcs, sockts_alloc_send_func_ctx, "", RPC_PTR_FMT,
                 RPC_PTR_VAL(out.ctx_ptr));
    RETVAL_RPC_PTR(sockts_alloc_send_func_ctx, (rpc_ptr)out.ctx_ptr);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_sockts_send_func_ctx_init_zc_buf(rcf_rpc_server *rpcs,
                                     rpc_ptr ctx, int fd,
                                     tarpc_size_t buf_size)
{
    tarpc_sockts_send_func_ctx_init_zc_buf_in     in;
    tarpc_sockts_send_func_ctx_init_zc_buf_out    out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sockts_send_func_ctx_init_zc_buf, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.ctx = ctx;
    in.fd = fd;
    in.buf_size = buf_size;

    rcf_rpc_call(rpcs, "sockts_send_func_ctx_init_zc_buf", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(sockts_send_func_ctx_init_zc_buf,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, sockts_send_func_ctx_init_zc_buf,
                 RPC_PTR_FMT ", %d, %" TE_PRINTF_SIZE_T "u", "%d",
                 RPC_PTR_VAL(ctx), fd, buf_size, out.retval);
    RETVAL_INT(sockts_send_func_ctx_init_zc_buf, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_sockts_send_func_ctx_clean_zc_buf(rcf_rpc_server *rpcs,
                                      rpc_ptr ctx, int fd,
                                      int timeout)
{
    tarpc_sockts_send_func_ctx_clean_zc_buf_in     in;
    tarpc_sockts_send_func_ctx_clean_zc_buf_out    out;

    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
        RETVAL_INT(sockts_send_func_ctx_clean_zc_buf, -1);
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.ctx = ctx;
    in.fd = fd;
    in.timeout = timeout;

    rcf_rpc_call(rpcs, "sockts_send_func_ctx_clean_zc_buf", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(sockts_send_func_ctx_clean_zc_buf,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, sockts_send_func_ctx_clean_zc_buf,
                 RPC_PTR_FMT ", %d, %d", "%d",
                 RPC_PTR_VAL(ctx), fd, timeout, out.retval);
    RETVAL_INT(sockts_send_func_ctx_clean_zc_buf, out.retval);
}

/* See description in sockapi-ts_rpc.h */
void use_syscall_rpc_server_hook(rcf_rpc_server *rpcs)
{
    const char *str_env_use_syscall;
    if (rpcs == NULL)
    {
        ERROR("%s(): Invalid RPC server handle", __FUNCTION__);
    }
    else
    {
        str_env_use_syscall = getenv("ST_USE_SYSCALL");
        if (str_env_use_syscall != NULL &&
            strcmp(str_env_use_syscall, "yes") == 0 &&
            strcmp(rpcs->name, "pco_iut") == 0
            )
        {
            rpcs->use_syscall = TRUE;
        }
    }
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_connect_send_dur_time(rcf_rpc_server *rpcs,
                          int threads_num,
                          const struct sockaddr *dst_addr,
                          const struct sockaddr_storage *src_addr,
                          uint64_t duration,
                          uint64_t *sent)
{
    tarpc_connect_send_dur_time_in    in;
    tarpc_connect_send_dur_time_out   out;
    struct tarpc_sa *addrs = NULL;
    int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.threads_num = threads_num;
    sockaddr_input_h2rpc(dst_addr, &in.dst_addr);

    in.src_addr.src_addr_val = addrs = TE_ALLOC(sizeof(*addrs) * threads_num);
    in.src_addr.src_addr_len = threads_num;
    if (rpcs->op != RCF_RPC_WAIT)
    {
        for (i = 0; i < threads_num; i++)
            sockaddr_input_h2rpc(SA(src_addr + i), in.src_addr.src_addr_val + i);
    }
    in.duration = duration;

    rcf_rpc_call(rpcs, "connect_send_dur_time", &in, &out);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(connect_send_dur_time, out.retval);

    TAPI_RPC_LOG(rpcs, connect_send_dur_time, "%d, %p, %p, %u, %p", "%d",
                 threads_num, dst_addr, src_addr, duration, sent, out.retval);
    if (out.sent.sent_val != NULL)
        memcpy(sent, out.sent.sent_val, sizeof(*sent) * threads_num);

    free(addrs);
    RETVAL_INT(connect_send_dur_time, out.retval);
}

/* See decription in sockapi-ts_rpc.h */
int
rpc_sockts_iomux_timeout_loop(rcf_rpc_server *rpcs, iomux_call_type iomux,
                              struct tarpc_pollfd *fds, unsigned int nfds,
                              int timeout, unsigned int n_calls)
{
    tarpc_sockts_iomux_timeout_loop_in in;
    tarpc_sockts_iomux_timeout_loop_out out;

    te_string log_str = TE_STRING_INIT_STATIC(2048);
    unsigned int i;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.iomux = iomux;
    if (iomux == IC_OO_EPOLL)
    {
        in.oo_epoll = TRUE;
        in.iomux = IC_EPOLL;
    }
    in.fds.fds_val = fds;
    in.fds.fds_len = nfds;
    in.timeout = timeout;
    in.n_calls = n_calls;

    rcf_rpc_call(rpcs, "sockts_iomux_timeout_loop", &in, &out);

    for (i = 0; i < nfds; i++)
    {
        te_string_append(&log_str, "{ %d, %s }, ",
                         fds[i].fd, poll_event_rpc2str(fds[i].events));
    }
    te_string_cut(&log_str, 2);

    CHECK_RETVAL_VAR_IS_GTE_MINUS_ONE(sockts_iomux_timeout_loop,
                                      out.retval);
    TAPI_RPC_LOG(rpcs, sockts_iomux_timeout_loop,
                 "%s(), fds=%p[%s], nfds=%u, timeout=%d, n_calls=%u", "%d",
                 iomux_call_en2str(iomux), fds, log_str.ptr, nfds, timeout,
                 n_calls, out.retval);
    RETVAL_INT(sockts_iomux_timeout_loop, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_sockts_peek_stream_receiver(rcf_rpc_server *rpcs, int s,
                                int time2run, int time2wait,
                                tarpc_pat_gen_arg *gen_arg,
                                uint64_t *received)
{
    tarpc_sockts_peek_stream_receiver_in in;
    tarpc_sockts_peek_stream_receiver_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.fd = s;
    in.time2run = time2run;
    in.time2wait = time2wait;
    memcpy(&in.gen_arg, gen_arg, sizeof(*gen_arg));

    rcf_rpc_call(rpcs, "sockts_peek_stream_receiver", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(sockts_peek_stream_receiver,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, sockts_peek_stream_receiver,
                 "time2run=%d, time2wait=%d, gen_arg=["
                 TARPC_PAT_GEN_ARG_FMT "], received=%llu",
                 "%d", time2run, time2wait,
                 TARPC_PAT_GEN_ARG_VAL(*gen_arg),
                 (long long unsigned int)(out.received), out.retval);

    if (rpcs->op != RCF_RPC_WAIT)
    {
        memcpy(gen_arg, &out.gen_arg, sizeof(*gen_arg));
        if (received != NULL)
            *received = out.received;
    }

    RETVAL_INT(sockts_peek_stream_receiver, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_get_stat_from_orm_json(rcf_rpc_server *rpcs, const char *stat_name,
                           int *stat_value)
{
    tarpc_get_stat_from_orm_json_in in;
    tarpc_get_stat_from_orm_json_out out;

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    in.stat_name = strdup(stat_name);

    rcf_rpc_call(rpcs, "get_stat_from_orm_json", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(get_stat_from_orm_json,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, get_stat_from_orm_json, "stat_name=%s, stat_value=%d",
                 "%d", stat_name, out.stat_value, out.retval);

    if (stat_value != NULL)
        *stat_value = out.stat_value;

    RETVAL_INT(get_stat_from_orm_json, out.retval);
}

/* See description in sockapi-ts_rpc.h */
int
rpc_get_n_listenq_from_orm_json(rcf_rpc_server *rpcs,
                                const struct sockaddr *loc_addr,
                                int *n_listenq)
{
    tarpc_get_n_listenq_from_orm_json_in in;
    tarpc_get_n_listenq_from_orm_json_out out;
    char loc_buf[TE_SOCKADDR_STR_LEN];

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));

    sockaddr_input_h2rpc(loc_addr, &in.loc_addr);

    rcf_rpc_call(rpcs, "get_n_listenq_from_orm_json", &in, &out);

    CHECK_RETVAL_VAR_IS_ZERO_OR_MINUS_ONE(get_n_listenq_from_orm_json,
                                          out.retval);
    TAPI_RPC_LOG(rpcs, get_n_listenq_from_orm_json, "loc_addr=%s, n_listenq=%d",
                 "%d", SOCKADDR_H2STR_SBUF(loc_addr, loc_buf),
                 out.n_listenq, out.retval);

    if (n_listenq != NULL)
        *n_listenq = out.n_listenq;

    RETVAL_INT(get_n_listenq_from_orm_json, out.retval);
}
