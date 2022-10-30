/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief sapi-ts Test Agent Library
 *
 * sockapi-ts-specific RPC routines implementation 
 *
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

#define TE_LGR_USER     "SF_RPC"

#include "te_config.h"

#include "logger_ta_lock.h"
#include "rpc_server.h"
#include "rpcs_msghdr.h"
#include "rpcs_conv.h"
#include "iomux.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif 

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h> 
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_EXTENSIONS_ZC_HLRX_H
#include "extensions_zc_hlrx.h"
#endif

#include <ifaddrs.h>

#include "extensions.h"
#include "extensions_zc.h"

#include "te_sleep.h"
#include "te_alloc.h"
#include "te_bufs.h"
#include "te_queue.h"
#include "sockapi-ta.h"
#include "agentlib.h"
#include "tad_common.h"
#include "te_ipstack.h"
#include "te_time.h"

/** Test Agent executable name */ 
extern const char *ta_execname;

#ifdef __linux__
/** Test Agent vsyscall page entrance */
extern const void *vsyscall_enter;
#endif

#if defined(PRINT)
#undef PRINT
#endif

#include "te_sockaddr.h"

#include "syscall_close.h"

#define DEST_PORT       1000

/**
 * Try to find function with tarpc_find_func(); in case of failure
 * set RPC error with te_rpc_error_set() and return @c -1.
 *
 * @param _libflags   Value of type tarpc_lib_flags telling how
 *                    to resolve function name.
 * @param _fname      Function name.
 * @param _fp         Where to save function pointer.
 */
#define TRY_FIND_FUNC(_libflags, _fname, _fp) \
    do {                                                        \
        te_errno _err;                                          \
                                                                \
        _err = tarpc_find_func(_libflags, _fname,               \
                              (api_func *)_fp);                 \
        if (_err != 0)                                          \
        {                                                       \
            te_rpc_error_set(_err, "Failed to find function "   \
                             "\"%s\"", _fname);                 \
            return -1;                                          \
        }                                                       \
    } while (0)

/**
 * Resolve dynamically a function from inside an accessor function
 * defined for it.
 *
 * @param _var      Variable where to save resolved function
 *                  pointer (set to @c NULL in case of failure).
 * @param _name     Name of the function to resolve.
 */
#define RESOLVE_ACC_FUNC(_var, _name) \
    do {                                                          \
        if (tarpc_find_func(TARPC_LIB_DEFAULT, #_name,            \
                            (api_func *)&_var) != 0 ||            \
            (void *)_var == (void *)&_name)                       \
        {                                                         \
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),        \
                             "failed to resolve %s()",            \
                             #_name);                             \
            _var = NULL;                                          \
        }                                                         \
    } while (0)

/*-------------- get_sizeof() -------------------------------*/
#define MAX_TYPE_NAME_SIZE 30
typedef struct {
    char           type_name[MAX_TYPE_NAME_SIZE];
    tarpc_ssize_t  type_size;
} type_info_t;

static type_info_t type_info[] =
{
    {"struct onload_zc_iovec", sizeof(struct onload_zc_iovec)},
};

bool_t
_sapi_get_sizeof_1_svc(tarpc_sapi_get_sizeof_in *in,
                       tarpc_sapi_get_sizeof_out *out,
                       struct svc_req *rqstp)
{
    uint32_t i;

    UNUSED(rqstp);

    out->size = -1;

    if (in->typename == NULL)
    {
        ERROR("Name of type not specified");
        return FALSE;
    }

    if (in->typename[0] == '*')
    {
        out->size = sizeof(void *);
        return TRUE;
    }

    for (i = 0; i < sizeof(type_info) / sizeof(type_info_t); i++)
    {
        if (strcmp(in->typename, type_info[i].type_name) == 0)
        {
            out->size = type_info[i].type_size;
            return TRUE;
        }
    }

    ERROR("Unknown type (%s)", in->typename);
#if 0
    out->common._errno = TE_RC(TE_TA_UNIX, TE_EINVAL);
#endif
    return TRUE;
}
/*------------------- onload extensions ---------------*/

/**
 * Convert Onload ZC buffer allocation flags to native value.
 *
 * @param f     Flags
 *
 * @return native representation of flags
 */
static inline enum onload_zc_buffer_type_flags
onload_zc_buffer_type_flags_tarpc2h(tarpc_onload_zc_buffer_type_flags f)
{
    return (!!(f & TARPC_ONLOAD_ZC_BUFFER_HDR_NONE) *
               ONLOAD_ZC_BUFFER_HDR_NONE) |
           (!!(f & TARPC_ONLOAD_ZC_BUFFER_HDR_UDP) *
               ONLOAD_ZC_BUFFER_HDR_UDP) |
           (!!(f & TARPC_ONLOAD_ZC_BUFFER_HDR_TCP) *
               ONLOAD_ZC_BUFFER_HDR_TCP);
}

TARPC_FUNC(onload_zc_alloc_buffers, {},
{
    struct onload_zc_iovec  *iovecs;

    iovecs = (struct onload_zc_iovec *)
                rcf_pch_mem_get(in->iovecs);
    MAKE_CALL(out->retval =
                  func(in->fd, iovecs, in->iovecs_len,
                       onload_zc_buffer_type_flags_tarpc2h(in->flags)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
})

/**
 * Release Onload ZC buffers.
 *
 * @param saved_func    Pointer to onload_zc_release_buffers()
 *                      (if NULL, it will be resolved by this function).
 * @param fd            Socket descriptor
 * @param iovecs        Pointer to an array of onload_zc_iovec structures
 * @param iovecs_len    Number of elements in the array
 *
 * @return @c 0 on success, @c -1 on falure.
 */
int
free_onload_zc_buffers(api_func saved_func,
                       int fd, struct onload_zc_iovec *iovecs,
                       int iovecs_len)
{
    int          i;
    int          rc = 0;
    api_func     func_release = saved_func;

    if (func_release == NULL)
    {
        if ((rc = tarpc_find_func(TARPC_LIB_DEFAULT,
                                  "onload_zc_release_buffers",
                                  &func_release) != 0))
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                             "failed to find function "
                             "\"onload_zc_release_buffers\"");
            return -1;
        }
    }

    for (i = 0; i < iovecs_len; i++)
    {
        rc = func_release(fd, &iovecs[i].buf, 1);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                             "onload_zc_release_buffers() failed");
            return -1;
        }
    }

    return 0;
}

TARPC_FUNC(free_onload_zc_buffers, {},
{
    struct onload_zc_iovec  *iovecs;

    iovecs = (struct onload_zc_iovec *)
                rcf_pch_mem_get(in->iovecs);

    MAKE_CALL(out->retval =
                  func(NULL, in->fd, iovecs, in->iovecs_len));
})

TARPC_FUNC(onload_set_stackname, {}, 
{
    MAKE_CALL(out->retval = func(in->who, in->scope,
                                 in->name_null ? NULL : in->name));
}
)

TARPC_FUNC(onload_stackname_save, {}, 
{
    MAKE_CALL(out->retval = ((api_func_void)func)());
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
}
)

TARPC_FUNC(onload_stackname_restore, {}, 
{
    MAKE_CALL(out->retval = ((api_func_void)func)());
}
)

TARPC_FUNC(onload_move_fd, {}, 
{
    MAKE_CALL(out->retval = ((api_func)func)(in->fd));
}
)

/**
 * File descriptor to be supplied to onload_move_fd()
 * when it is called from a signal handler.
 */
int onload_move_fd_fd;

/**
 * Return value of onload_move_fd() called from
 * a signal handler.
 */
int onload_move_fd_rc;

/**
 * Special signal handler that calls onload_move_fd().
 *
 * @param signum  Received signal
 */
void sighandler_onload_move_fd(int signum)
{
    api_func  func_onload_move_fd;

    UNUSED(signum);

    tarpc_find_func(TARPC_LIB_DEFAULT, "onload_move_fd",
                    &func_onload_move_fd);

    onload_move_fd_rc = func_onload_move_fd(onload_move_fd_fd);
    RING("onload_move_fd(%d) called from a signal handler returned %d",
         onload_move_fd_fd, onload_move_fd_rc);
}

TARPC_FUNC(onload_is_present, {}, 
{
    MAKE_CALL(out->retval = ((api_func_void)func)());
}
)

static inline api_func
get_onload_fd_stat_func(void)
{
    api_func func;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "onload_fd_stat",
                        (api_func *)&func) != 0 ||
        (void *)func == onload_fd_stat)
    {
        ERROR("Failed to find O function " "\"onload_fd_stat\"");
        return NULL;
    }

    return func;
}

int
onload_fd_stat(int fd, struct onload_stat* stat)
{
    api_func func = get_onload_fd_stat_func();

    if (func == NULL)
        return -1;

    return func(fd, stat);
}

TARPC_FUNC(onload_fd_stat, {}, 
{
    struct onload_stat buf;

    memset(&buf, 0, sizeof(buf));
    buf.stack_name = NULL;
    buf.stack_id = -1;
    MAKE_CALL(out->retval = onload_fd_stat(in->fd, &buf));

    out->buf.stack_id = buf.stack_id;
    if (buf.stack_name != NULL)
    {
        out->buf.stack_name = strdup(buf.stack_name);
        free(buf.stack_name);
        out->buf.stack_name_null = FALSE;
    }
    else
    {
        out->buf.stack_name=strdup("");
        out->buf.stack_name_null = TRUE;
    }
}
)

static const char *
msghdr2str(const struct msghdr *msg)
{
    static char buf[256];

    char   *buf_end = buf + sizeof(buf);
    char   *p = buf;
    int     i;

    p += snprintf(p, buf_end - p, "{name={0x%lx,%u},{",
                  (long unsigned int)msg->msg_name, msg->msg_namelen);
    if (p >= buf_end)
        return "(too long)";
    for (i = 0; i < (int)msg->msg_iovlen; ++i)
    {
        p += snprintf(p, buf_end - p, "%s{0x%lx,%u}",
                      (i == 0) ? "" : ",",
                      (long unsigned int)msg->msg_iov[i].iov_base,
                      (unsigned int)msg->msg_iov[i].iov_len);
        if (p >= buf_end)
            return "(too long)";
    }
    p += snprintf(p, buf_end - p, "},control={0x%lx,%u},flags=0x%x}",
                  (unsigned long int)msg->msg_control,
                  (unsigned int)msg->msg_controllen,
                  (unsigned int)msg->msg_flags);
    if (p >= buf_end)
        return "(too long)";

    return buf;
}

struct mmsghdr_alt {
    struct msghdr msg_hdr;  /**< Message header */
    unsigned int  msg_len;  /**< Number of received bytes for header */
    int           s;        /**< Socket fd */

    te_bool                 keep_iovs;      /**< If @c TRUE, keep Onload
                                                 buffers using
                                                 @c ONLOAD_ZC_KEEP flag */
    struct onload_zc_iovec *saved_iovs;     /**< Where to save kept Onload
                                                 buffers */
    rpc_ptr                 saved_iovs_ptr; /**< RPC pointer to array of
                                                 kept Onload buffers */

    onload_zc_handle          zc_buf;        /**< Handle of the first buffer
                                                  allocated by
                                                  onload_zc_recv() */
};

static const char *
mmsghdr2str(const struct mmsghdr_alt *mmsg, int len)
{
    int          i;
    static char  buf[256];
    char        *buf_end = buf + sizeof(buf);
    char        *p = buf;

    for (i = 0; i < len; i++)
    {
        p += snprintf(p, buf_end - p, "%s{%s, %d}%s%s",
                      (i == 0) ? "{" : "",
                      msghdr2str(&mmsg[i].msg_hdr), mmsg[i].msg_len,
                      (i == 0) ? "" : ",", (i == len - 1) ? "" : "}");
        if (p >= buf_end)
            return "(too long)";
    }
    return buf;
}

static const char *
onload_zc_mmsg2str(struct onload_zc_mmsg *mmsg, int len)
{
    int          i;
    static char  buf[256];
    char        *buf_end = buf + sizeof(buf);
    char        *p = buf;

    for (i = 0; i < len; i++)
    {
        p += snprintf(p, buf_end - p, "%s{%s, %d, %d}%s%s",
                      (i == 0) ? "{" : "",
                      msghdr2str(&mmsg[i].msg.msghdr), mmsg[i].rc,
                      mmsg[i].fd,
                      (i == 0) ? "" : ",", (i == len - 1) ? "" : "}");
        if (p >= buf_end)
            return "(too long)";
    }
    return buf;
}

static inline int
calculate_msg_controllen(struct tarpc_msghdr *rpc_msg)
{
    unsigned int i;
    int          len = 0;

    for (i = 0; i < rpc_msg->msg_control.msg_control_len; i++)
        len += CMSG_SPACE(rpc_msg->msg_control.msg_control_val[i].
                          data.data_len);

    return len;
}

/**
 * Data passed to onload_zc_recv() callback.
 */
typedef struct zc_recv_cb_data {
    unsigned int zc_vlen;             /**< Maximum number of messages to
                                           receive */
    unsigned int zc_cnt;              /**< Number of received messages */
    int zc_rlen[RCF_RPC_MAX_MSGHDR];  /**< Number of IOVs allocated for
                                           every message */
    int cb_flags[RCF_RPC_MAX_MSGHDR]; /**< Where to save flags passed
                                           to each callback invocation */

    struct mmsghdr_alt  *mmsgs;             /**< Where to save received
                                                 messages */
} zc_recv_cb_data;

enum onload_zc_callback_rc
simple_cb(struct onload_zc_recv_args *args, int flags)
{
    int                     i;
    struct iovec           *iov;
    struct onload_zc_iovec *ol_iov;
    unsigned                min;
    struct mmsghdr_alt     *mmsg;
    struct msghdr          *msg;
    int                     keep_flag = 0;

    zc_recv_cb_data        *cb_data;

    if (args == NULL || args->user_ptr == NULL || args->msg.iov == NULL)
        return ONLOAD_ZC_TERMINATE;

    cb_data = (zc_recv_cb_data *)(args->user_ptr);

    if (cb_data->zc_vlen == 0)
        return ONLOAD_ZC_TERMINATE;

    if (cb_data->zc_cnt > RCF_RPC_MAX_MSGHDR)
    {
        ERROR("simple_cb(): Too many packets.");
        return ONLOAD_ZC_TERMINATE;
    }

    mmsg = &cb_data->mmsgs[cb_data->zc_cnt];
    msg = &(mmsg->msg_hdr);
    if (msg->msg_iov == NULL)
        return ONLOAD_ZC_TERMINATE;

    if (mmsg->keep_iovs)
        keep_flag = ONLOAD_ZC_KEEP;

    min = (args->msg.msghdr.msg_iovlen > msg->msg_iovlen) ?
        msg->msg_iovlen : args->msg.msghdr.msg_iovlen;
    msg->msg_flags = args->msg.msghdr.msg_flags;

    for (i = 0; (unsigned)i < min; i++)
    {
        iov = &(msg->msg_iov[i]);
        ol_iov = &(args->msg.iov[i]);
        if (ol_iov->iov_len > iov->iov_len)
        {
            ERROR("Obtained buffer is bigger than provided one");
            return ONLOAD_ZC_TERMINATE;
        }
        if (ol_iov->iov_base == NULL)
                iov->iov_base = NULL;
        else
        {
            memcpy(iov->iov_base, ol_iov->iov_base, ol_iov->iov_len);
            if (ol_iov->iov_len > iov->iov_len)
            {
                ERROR("zc buffer is longer than provided in msg_iov");
                return ONLOAD_ZC_TERMINATE;
            }
            iov->iov_len = ol_iov->iov_len;
        }
    }

    msg->msg_iovlen = args->msg.msghdr.msg_iovlen;
    if (msg->msg_namelen >= args->msg.msghdr.msg_namelen)
        msg->msg_namelen = args->msg.msghdr.msg_namelen;
    if (msg->msg_name != NULL && args->msg.msghdr.msg_name != NULL)
        memcpy(msg->msg_name, args->msg.msghdr.msg_name, msg->msg_namelen);

    if (msg->msg_controllen >= args->msg.msghdr.msg_controllen)
        msg->msg_controllen = args->msg.msghdr.msg_controllen;
    if (msg->msg_control != NULL && args->msg.msghdr.msg_control != NULL)
        memcpy(msg->msg_control, args->msg.msghdr.msg_control,
               msg->msg_controllen);
    cb_data->cb_flags[cb_data->zc_cnt] = flags;

    if (args->msg.iov != NULL)
    {
        if (args->msg.msghdr.msg_iovlen > 0)
            mmsg->zc_buf = args->msg.iov[0].buf;

        if (args->msg.msghdr.msg_iovlen >
                    (unsigned)(cb_data->zc_rlen[cb_data->zc_cnt]))
        {
            ERROR("simple_cb() returned too many iovec structures");
            return ONLOAD_ZC_TERMINATE;
        }
        mmsg->msg_len = 0;
        for (i = 0; (unsigned)i < msg->msg_iovlen; i++)
            mmsg->msg_len += msg->msg_iov[i].iov_len;
    }

    cb_data->zc_cnt++;

    if (mmsg->keep_iovs)
    {
        memcpy(mmsg->saved_iovs, args->msg.iov,
               args->msg.msghdr.msg_iovlen *
                          sizeof(struct onload_zc_iovec));
    }

    if (cb_data->zc_cnt >= cb_data->zc_vlen)
        return ONLOAD_ZC_TERMINATE | keep_flag;

    return ONLOAD_ZC_CONTINUE | keep_flag;
}

/**
 * Call onload_zc_recv().
 *
 * @param fd              Socket FD.
 * @param cb_data         Pointer to pass to callback in args.user_ptr.
 * @param args_msg        If not @c NULL, args.msg.msghdr passed to
 *                        onload_zc_recv() will be initialized from
 *                        this parameter, and on return it will contain
 *                        value updated by onload_zc_recv().
 * @param flags           Flags to pass to onload_zc_recv().
 * @param os_inline       If @c TRUE, @c ONLOAD_MSG_RECV_OS_INLINE flag
 *                        should be passed to onload_zc_recv().
 *
 * @return Number of received messages on success, negative value on
 *         failure.
 */
int
simple_zc_recv(int fd, zc_recv_cb_data *cb_data,
               struct msghdr *args_msg, int flags,
               int os_inline)
{
    struct onload_zc_recv_args   args;
    api_func                     func_zc_recv;
    int                          rc;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "onload_zc_recv",
                        &func_zc_recv) != 0)
    {
        ERROR("Failed to find function \"onload_zc_recv\"");
        return -1;
    }

    memset(&args, 0, sizeof(args));

    if (args_msg != NULL)
        memcpy(&(args.msg.msghdr), args_msg, sizeof(struct msghdr));

    args.msg.msghdr.msg_iovlen = 0;
    args.msg.msghdr.msg_iov = NULL;
    args.cb = simple_cb;
    args.user_ptr = (void *)cb_data;
    args.flags = (os_inline) ? flags | ONLOAD_MSG_RECV_OS_INLINE : flags;

    rc = func_zc_recv(fd, &args);

    if (args_msg != NULL)
        memcpy(args_msg, &(args.msg.msghdr), sizeof(struct msghdr));

    if (rc < 0)
    {
        errno = -rc;
        return -1;
    }

    return cb_data->zc_cnt;
}

/**
 * Call onload_zc_recv(fd, NULL).
 *
 * @param fd    Socket descriptor
 *
 * @return Status code
 */
int
simple_zc_recv_null(int fd)
{

    api_func     func_zc_recv;
    int          rc;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "onload_zc_recv",
                        &func_zc_recv) != 0)
    {
        ERROR("Failed to find function \"onload_zc_recv\"");
        return -1;
    }

    rc = func_zc_recv(fd, NULL);

    if (rc < 0)
        errno = -rc;

    return rc;
}

TARPC_FUNC(simple_zc_recv_null,{},
{
    MAKE_CALL(out->retval = func(in->s));
})

TARPC_FUNC(simple_zc_recv,
{
    if (in->mmsg.mmsg_val != NULL &&
        in->mmsg.mmsg_len > RCF_RPC_MAX_MSGHDR)
    {
        ERROR("Too long mmsghdr is provided");
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        return TRUE;
    }
    COPY_ARG(mmsg);
    COPY_ARG(args_msg);
    COPY_ARG(cb_flags);
},
{
    struct mmsghdr_alt  mmsg[RCF_RPC_MAX_MSGHDR];
    struct msghdr       args_msg;
    rpcs_msghdr_helper  helpers[RCF_RPC_MAX_MSGHDR];
    rpcs_msghdr_helper  helper;
    te_errno            rc;
    int                 err;
    unsigned int        j;

    struct zc_recv_cb_data cb_data;

    api_func            func_zc_release = NULL;

    memset(&cb_data, 0, sizeof(cb_data));
    memset(mmsg, 0, sizeof(mmsg));
    memset(&args_msg, 0, sizeof(args_msg));
    memset(helpers, 0, sizeof(helpers));
    memset(&helper, 0, sizeof(helper));

    if ((rc = tarpc_find_func(TARPC_LIB_DEFAULT,
                              "onload_zc_release_buffers",
                              &func_zc_release)) != 0)
    {
        te_rpc_error_set(
            TE_RC(TE_TA_UNIX, rc),
            "Failed to find function \"onload_zc_release_buffers\"");
        out->retval = -1;
        goto finish;
    }

    if (out->args_msg.args_msg_val != NULL)
    {
        rc = rpcs_msghdr_tarpc2h(RPCS_MSGHDR_CHECK_ARGS_RECV,
                                 out->args_msg.args_msg_val,
                                 &helper, &args_msg, arglist, "args_msg");
        if (rc != 0)
        {
            out->common._errno = TE_RC(TE_TA_UNIX, rc);
            out->retval = -1;
            goto finish;
        }
    }

    cb_data.zc_vlen = in->vlen;
    cb_data.zc_cnt = 0;

    if (out->mmsg.mmsg_val == NULL)
    {
        cb_data.mmsgs = NULL;
        MAKE_CALL(out->retval = func(in->s, &cb_data, &args_msg,
                                     send_recv_flags_rpc2h(in->flags),
                                     in->os_inline));
    }
    else
    {
        struct tarpc_msghdr *rpc_msg;
        struct tarpc_onload_zc_mmsg *rpc_mmsg;

        for (j = 0; j < out->mmsg.mmsg_len; j++)
        {
            rpc_msg = &(out->mmsg.mmsg_val[j].msg);
            rc = rpcs_msghdr_tarpc2h(RPCS_MSGHDR_CHECK_ARGS_NONE,
                                     rpc_msg, &helpers[j],
                                     &mmsg[j].msg_hdr, arglist,
                                     "mmsg[%u].msg_hdr", j);
            if (rc != 0)
            {
                out->common._errno = TE_RC(TE_TA_UNIX, rc);
                out->retval = -1;
                goto finish;
            }

            cb_data.zc_rlen[j] = rpc_msg->msg_iov.msg_iov_len;
            mmsg[j].msg_len = out->mmsg.mmsg_val[j].rc;

            rpc_mmsg = &out->mmsg.mmsg_val[j];
            if (rpc_mmsg->keep_recv_bufs)
            {
                mmsg[j].saved_iovs =
                    calloc(mmsg[j].msg_hdr.msg_iovlen,
                           sizeof(struct onload_zc_iovec));
                if (mmsg[j].saved_iovs == NULL)
                {
                    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                     "Failed to allocate array for kept "
                                     "onload_zc_iovec buffers");
                    out->retval = -1;
                    goto finish;
                }

                mmsg[j].saved_iovs_ptr =
                      rcf_pch_mem_alloc(mmsg[j].saved_iovs);
                if (mmsg[j].saved_iovs_ptr == RPC_NULL)
                {
                    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                     "rcf_pch_mem_alloc() failed");
                    out->retval = -1;
                    goto finish;
                }

                mmsg[j].keep_iovs = TRUE;
            }
        }

        if (out->mmsg.mmsg_len > 0)
        {
            if (out->args_msg.args_msg_val == NULL)
            {
                memcpy(&args_msg, &mmsg[0].msg_hdr, sizeof(struct msghdr));
                args_msg.msg_control = NULL;
                args_msg.msg_name = NULL;

                /*
                 * If no separate args_msg was provided, for msg_control and
                 * msg_namelen fields of args.msg.msghdr allocate buffers of
                 * the same lengths as those specified for the first
                 * message.
                 */

                if (mmsg[0].msg_hdr.msg_control != NULL)
                {
                    args_msg.msg_control =
                            calloc(1, helpers[0].real_controllen);
                    if (args_msg.msg_control == NULL)
                    {
                        te_rpc_error_set(
                             TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "Failed to allocate memory for control data");
                        out->retval = -1;
                        goto finish;
                    }
                    memcpy(args_msg.msg_control,
                           mmsg[0].msg_hdr.msg_control,
                           helpers[0].real_controllen);

                    INIT_CHECKED_ARG(args_msg.msg_control,
                                     helpers[0].real_controllen,
                                     args_msg.msg_controllen);
                }

                if (mmsg[0].msg_hdr.msg_name != NULL)
                {
                    args_msg.msg_name =
                            calloc(1, helpers[0].addr_rlen);
                    if (args_msg.msg_name == NULL)
                    {
                        te_rpc_error_set(
                             TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "Failed to allocate memory for address data");
                        out->retval = -1;
                        goto finish;
                    }
                    memcpy(args_msg.msg_name,
                           mmsg[0].msg_hdr.msg_name,
                           helpers[0].addr_rlen);

                    INIT_CHECKED_ARG(args_msg.msg_name,
                                     helpers[0].addr_rlen,
                                     args_msg.msg_namelen);
                }
            }
        }

        cb_data.mmsgs = mmsg;
        VERB("simple_zc_recv(): in mmsg=%s",
             mmsghdr2str(mmsg, out->mmsg.mmsg_len));
        MAKE_CALL(out->retval = func(in->s, &cb_data,
                                     &args_msg,
                                     send_recv_flags_rpc2h(in->flags),
                                     in->os_inline));
        VERB("simple_zc_recv(): out mmsg=%s",
             mmsghdr2str(mmsg, out->retval));

        if (out->cb_flags.cb_flags_val != NULL &&
            out->cb_flags.cb_flags_len != 0)
            memcpy(out->cb_flags.cb_flags_val, cb_data.cb_flags,
                   sizeof(*(cb_data.cb_flags)) * cb_data.zc_cnt);

        if (out->args_msg.args_msg_val != NULL)
        {
            rc = rpcs_msghdr_h2tarpc(&args_msg, &helper,
                                     out->args_msg.args_msg_val);
            if (rc != 0)
            {
                out->common._errno = TE_RC(TE_TA_UNIX, rc);
                out->retval = -1;
                goto finish;
            }
        }

        for (j = 0; j < out->mmsg.mmsg_len; j++)
        {
            rc = rpcs_msghdr_h2tarpc(&mmsg[j].msg_hdr, &helpers[j],
                                     &(out->mmsg.mmsg_val[j].msg));
            if (rc != 0)
            {
                out->common._errno = TE_RC(TE_TA_UNIX, rc);
                out->retval = -1;
                goto finish;
            }

            out->mmsg.mmsg_val[j].rc = mmsg[j].msg_len;
        }
    }

finish:

    if (cb_data.zc_cnt > 0 && out->retval < 0)
    {
        for (j = 0; j < cb_data.zc_cnt; j++)
        {
            if (mmsg[j].keep_iovs &&
                mmsg[j].msg_hdr.msg_iovlen > 0 &&
                mmsg[j].saved_iovs[0].buf != NULL)
            {
                err = func_zc_release(in->s, &mmsg[j].saved_iovs[0].buf, 1);
                if (err < 0)
                {
                    te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -err),
                                     "onload_zc_release_buffers() failed");
                    out->retval = -1;
                }
            }
        }
    }

    for (j = (out->retval < 0 ? 0 : cb_data.zc_cnt);
         j < out->mmsg.mmsg_len; j++)
    {
        if (mmsg[j].keep_iovs)
        {
            rcf_pch_mem_free(mmsg[j].saved_iovs_ptr);
            free(mmsg[j].saved_iovs);
        }
    }

    if (out->retval >= 0)
    {
        for (j = 0; j < cb_data.zc_cnt; j++)
        {
            if (out->mmsg.mmsg_val[j].keep_recv_bufs)
            {
                out->mmsg.mmsg_val[j].saved_recv_bufs =
                                      mmsg[j].saved_iovs_ptr;
            }
        }
    }

    for (j = 0; j < out->mmsg.mmsg_len; j++)
        rpcs_msghdr_helper_clean(&helpers[j], &mmsg[j].msg_hdr);

    if (out->args_msg.args_msg_val == NULL)
    {
        free(args_msg.msg_control);
        free(args_msg.msg_name);
    }
    else
    {
        rpcs_msghdr_helper_clean(&helper, &args_msg);
    }
}
)

typedef struct simple_filter_cb_data {
    void  *buf;
    size_t len;
} simple_filter_cb_data;

enum onload_zc_callback_rc
simple_filter_cb(struct onload_zc_msg* msg, void *arg, int flags)
{
    size_t                  i = 0;
    void                   *buf;
    size_t                  len;
    struct onload_zc_iovec *ol_iov;
    size_t                  total_size = 0;
    size_t                  tmp_len;
    uint8_t                *tmp_ptr;

    UNUSED(flags);

    if (arg == NULL)
        return ONLOAD_ZC_CONTINUE;

    buf = ((simple_filter_cb_data *)arg)->buf;
    len = ((simple_filter_cb_data *)arg)->len;
    tmp_ptr = (uint8_t *)buf;

    if (msg->msghdr.msg_iovlen > 0 && buf == NULL)
        return ONLOAD_ZC_CONTINUE;

    while (i < msg->msghdr.msg_iovlen && total_size < len)
    {
        ol_iov = &(msg->iov[i]);
        tmp_len = len - total_size;
        tmp_len = (tmp_len > ol_iov->iov_len) ? ol_iov->iov_len : tmp_len;
        if (memcmp(tmp_ptr, ol_iov->iov_base, tmp_len) != 0)
            return ONLOAD_ZC_TERMINATE;
        tmp_ptr += tmp_len;
        total_size += tmp_len;
        i++;
    }

    if (total_size < len)
        return ONLOAD_ZC_TERMINATE;
    return ONLOAD_ZC_CONTINUE;
}

/** Structure storing a packet captured in UDP-RX filter callback. */
typedef struct recv_filter_pkt {
    int      fd;    /**< Socket descriptor */
    char    *buf;   /**< Buffer with packet data */
    size_t   len;   /**< Length of the data */

    TAILQ_ENTRY(recv_filter_pkt)  links;  /**< Queue links */
} recv_filter_pkt;

/**
 * Type of a head of a queue of packets captured in UDP-RX filter
 * callback.
 */
typedef TAILQ_HEAD(recv_filter_pkts, recv_filter_pkt) recv_filter_pkts;

/** Head of a queue of packets captured in UDP-RX filter callback. */
static recv_filter_pkts filtered_pkts =
                              TAILQ_HEAD_INITIALIZER(filtered_pkts);

/** Mutex protecting filtered_pkts. */
static pthread_mutex_t filtered_pkts_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Obtain the earliest packet captured in UDP-RX filter callback for a
 * given socket. Retrieved packet is removed from a queue of captured
 * packets.
 *
 * @param fd        Socket descriptor.
 * @param buf       Where to save pointer to packet data.
 * @param len       Where to save length of data.
 *
 * @return Packet data length on success, @c -1 on failure.
 */
static ssize_t
sockts_recv_filtered_pkt(int fd, uint8_t **buf, size_t *len)
{
    recv_filter_pkt *pkt = NULL;
    int              rc;

    TAILQ_FOREACH(pkt, &filtered_pkts, links)
    {
        if (pkt->fd == fd)
            break;
    }

    if (pkt == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "No packets are available for fd %d", fd);
        return -1;
    }

    if (pkt->len > *len)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                         "Length of the supplied buffer is too small");
        return -1;
    }

    rc = pthread_mutex_lock(&filtered_pkts_lock);
    if (rc != 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, rc),
                         "pthread_mutex_lock() returned %r",
                         te_rc_os2te(rc));
        return -1;
    }

    *buf = (uint8_t *)pkt->buf;
    pkt->buf = NULL;
    *len = pkt->len;

    TAILQ_REMOVE(&filtered_pkts, pkt, links);
    free(pkt);

    rc = pthread_mutex_unlock(&filtered_pkts_lock);
    if (rc != 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, rc),
                         "pthread_mutex_unlock() returned %r",
                         te_rc_os2te(rc));
        return -1;
    }

    return *len;
}

TARPC_FUNC_STATIC(sockts_recv_filtered_pkt, {},
{
    uint8_t  *buf = NULL;
    size_t    len = in->len;

    MAKE_CALL(out->retval = func(in->fd, &buf, &len));
    if (out->retval >= 0)
    {
        out->buf.buf_val = buf;
        out->buf.buf_len = len;
    }
}
)

/**
 * Remove all packets captured in UDP-RX filter callback from a queue,
 * release memory.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
sockts_recv_filtered_pkts_clear(void)
{
    int              rc;
    recv_filter_pkt *pkt = NULL;
    recv_filter_pkt *pkt_aux = NULL;

    rc = pthread_mutex_lock(&filtered_pkts_lock);
    if (rc != 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, rc),
                         "pthread_mutex_lock() returned %r",
                         te_rc_os2te(rc));
        return -1;
    }

    for (pkt = TAILQ_FIRST(&filtered_pkts); pkt != NULL; pkt = pkt_aux)
    {
        pkt_aux = TAILQ_NEXT(pkt, links);
        TAILQ_REMOVE(&filtered_pkts, pkt, links);
        free(pkt->buf);
        free(pkt);
    }

    rc = pthread_mutex_unlock(&filtered_pkts_lock);
    if (rc != 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, rc),
                         "pthread_mutex_unlock() returned %r",
                         te_rc_os2te(rc));
        return -1;
    }

    return 0;
}

TARPC_FUNC_STATIC(sockts_recv_filtered_pkts_clear, {},
{
    MAKE_CALL(out->retval = func());
}
)

/**
 * UDP-RX filter callback used to capture packets.
 *
 * @param msg           Pointer to Onload message containing packet data.
 * @param arg           Socket descriptor.
 * @param flags         Flags (not used).
 *
 * @return @c ONLOAD_ZC_CONTINUE.
 */
enum onload_zc_callback_rc
recv_filter_cb(struct onload_zc_msg *msg, void *arg, int flags)
{
    recv_filter_pkt *pkt = NULL;
    size_t           total_size = 0;
    unsigned int     i = 0;
    int              fd = (uint8_t *)arg - (uint8_t *)NULL;
    int              rc;

    UNUSED(flags);

    pkt = TE_ALLOC(sizeof(*pkt));
    if (pkt == NULL)
    {
        ERROR("Out of memory when trying to allocate recv_filter_pkt");
        return ONLOAD_ZC_CONTINUE;
    }
    pkt->fd = fd;

    for (i = 0; i < msg->msghdr.msg_iovlen; i++)
    {
        total_size += msg->iov[i].iov_len;
    }

    pkt->buf = TE_ALLOC(total_size);
    if (pkt->buf == NULL)
    {
        free(pkt);
        ERROR("Out of memory when trying to allocate space for "
              "packet data");
        return ONLOAD_ZC_CONTINUE;
    }

    total_size = 0;
    for (i = 0; i < msg->msghdr.msg_iovlen; i++)
    {
        memcpy(pkt->buf + total_size, msg->iov[i].iov_base,
               msg->iov[i].iov_len);
        total_size += msg->iov[i].iov_len;
    }
    pkt->len = total_size;

    rc = pthread_mutex_lock(&filtered_pkts_lock);
    if (rc != 0)
    {
        ERROR("pthread_mutex_lock() returned %r",
              te_rc_os2te(rc));
        free(pkt->buf);
        free(pkt);
        return ONLOAD_ZC_CONTINUE;
    }
    TAILQ_INSERT_TAIL(&filtered_pkts, pkt, links);
    rc = pthread_mutex_unlock(&filtered_pkts_lock);
    if (rc != 0)
    {
        ERROR("pthread_mutex_unlock() returned %r",
              te_rc_os2te(rc));
        return ONLOAD_ZC_CONTINUE;
    }

    return ONLOAD_ZC_CONTINUE;
}

/**
 * Call @b onload_set_recv_filter() to set @b recv_filter_cb()
 * as UDP-RX callback.
 *
 * @param fd        Socket descriptor.
 * @param flags     Flags to pass to @b onload_set_recv_filter().
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
onload_set_recv_filter_capture(int fd, int flags)
{
    /*
     * The following is done to avoid warning about converting
     * integer to pointer.
     */
    void                  *cb_arg = ((uint8_t *)NULL) + fd;
    api_func               func_filter;
    int                    rc;

    rc = tarpc_find_func(TARPC_LIB_DEFAULT, "onload_set_recv_filter",
                         &func_filter);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "Failed to find function "
                         "\"onload_set_recv_filter\"");
        return -1;
    }

    rc = func_filter(fd, recv_filter_cb, cb_arg, flags);
    if (rc < 0)
    {
        errno = -rc;
        return -1;
    }

    return 0;
}

TARPC_FUNC_STATIC(onload_set_recv_filter_capture, {},
{
    MAKE_CALL(out->retval = func(in->fd, in->flags));
}
)

int
simple_set_recv_filter(int fd, void *buf, size_t len, int flags)
{
    simple_filter_cb_data *cb_arg = NULL;
    api_func              func_filter;
    int                   rc;

    if ((cb_arg = (simple_filter_cb_data *)
                    malloc(sizeof(simple_filter_cb_data))) == NULL)
    {
        ERROR("Out of memory");
        return -1;
    }
    memset(cb_arg, 0, sizeof(*cb_arg));
    if (buf != NULL)
    {
        if ((cb_arg->buf = malloc(len)) == NULL)
        {
            ERROR("Out of memory");
            return -1;
        }
        memcpy(cb_arg->buf, buf, len);
    }
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "onload_set_recv_filter",
                        &func_filter) != 0)
    {
        ERROR("Failed to find function \"onload_set_recv_filter\"");
        return -1;
    }
    cb_arg->len = len;

    rc = func_filter(fd, simple_filter_cb, cb_arg, flags);
    if (rc < 0)
    {
        errno = -rc;
        return -1;
    }
    return 0;
}

/*-------------- simple_set_recv_filter() ------------------------------*/

TARPC_FUNC(simple_set_recv_filter, {},
{
    INIT_CHECKED_ARG(in->buf.buf_val, in->buf.buf_len, 0);

    /* TODO: Flags should be converted correctly */
    MAKE_CALL(out->retval = func(in->fd, in->buf.buf_val, in->len,
                                 in->flags));
}
)

/**
 * Set @c TCP_NODELAY socket option.
 *
 * @param s                 Socket FD.
 * @param func_setsockopt   Pointer to setsockopt() function.
 * @param val               Value to set.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
set_tcp_nodelay(int s, api_func func_setsockopt, int val)
{
    socklen_t optlen = sizeof(val);
    int rc;

    rc = func_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &val,
                         optlen);
    if (rc < 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                         "setsockopt() failed to set TCP_NODELAY "
                         "option");
        return -1;
    }

    return 0;
}

/**
 * Call @b onload_zc_send() or @b send() with or without
 * @c ONLOAD_MSG_MORE / @c MSG_MORE flag, check and return result.
 *
 * @param send_zc           Whether @b onload_zc_send() should be used.
 * @param mmsg              Message to send with @b onload_zc_send().
 * @param s                 Socket FD.
 * @param buf               Buffer to send with @b send().
 * @param buf_len           Length of the buffer.
 * @param more_flag         Whether @c ONLOAD_MSG_MORE / @c MSG_MORE should
 *                          be set.
 * @param func_zc_send      Pointer to @b onload_zc_send().
 * @param func_send         Pointer to @b send().
 * @param msg_name          Name of the message (to be used in error
 *                          logging).
 *
 * @return @c -1 on failure, number of bytes sent on success.
 */
static int
send_msg_more_check(te_bool send_zc, struct onload_zc_mmsg *mmsg,
                    int s, const char *buf, size_t buf_len,
                    te_bool more_flag, api_func_ptr func_zc_send,
                    api_func func_send, const char *msg_name)
{
    int rc;

    if (send_zc)
    {
#ifdef ONLOAD_MSG_MORE
        rc = func_zc_send(mmsg, 1, (more_flag ? ONLOAD_MSG_MORE : 0));
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                             "onload_zc_send() failed sending %s "
                             "message", msg_name);
            return -1;
        }
        else if (mmsg->rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, -mmsg->rc),
                             "onload_zc_send() reported failure in mmsg.rc "
                             "after sending %s message", msg_name);
            return -1;
        }

        return mmsg->rc;
#else
        te_rpc_error_set(TE_OS_RC(TE_RPC, EOPNOTSUPP),
                         "ONLOAD_MSG_MORE is not supported");
        return -1;
#endif
    }
    else
    {
        rc = func_send(s, buf, buf_len, (more_flag ? MSG_MORE : 0));
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, errno),
                             "send() failed when sending %s message",
                             msg_name);
        }
        return rc;
    }
}

/*------------ onload_zc_send_msg_more() -----------------*/
/**
 * Allocate Onload ZC API buffers and fill it with data from
 * a given buffer.
 *
 * @param func_alloc    Pointer to onload_zc_alloc_buffers().
 * @param func_release  Pointer to onload_zc_release_buffers().
 * @param fd            Socket descriptor
 * @param onload_iov    Where Onload ZC buffers should be
 *                      placed
 * @param iov_len       Number of elements in allocated IO
 *                      vector
 * @param data          Data to be filled
 * @param len           Length of data
 *
 * @return @c 0 on success, @c -1 on failure.
 */
int
alloc_fill_zc_bufs(api_func func_alloc, api_func func_release,
                   int fd, struct onload_zc_iovec **onload_iov,
                   size_t *iov_len,
                   const char *data, size_t len)
{
    struct onload_zc_iovec  *iov;
    void                    *tmp;
    int                      cur_len;
    int                      rc = 0;

    if (func_alloc == NULL || func_release == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                         "%s(): func_alloc and/or func_release is NULL",
                         __FUNCTION__);
        return -1;
    }

    cur_len = 1;
    iov = calloc(1, sizeof(struct onload_zc_iovec));
    if (iov == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "not enough memory");
        return -1;
    }

    while (1)
    {
        if ((rc = func_alloc(fd, &iov[cur_len - 1], 1,
                             ONLOAD_ZC_BUFFER_HDR_TCP)) != 0)
        {
            ERROR("%s(): Failed to allocate zc buffer for the first "
                  "message on %d socket", __FUNCTION__, fd);
            errno = -rc;
            return -1;
        }

        if (iov[cur_len - 1].iov_len >= len)
        {
            memcpy(iov[cur_len - 1].iov_base, data, len);
            iov[cur_len - 1].iov_len = len;
            break;
        }
        else
        {
            memcpy(iov[cur_len - 1].iov_base, data,
                   iov[cur_len - 1].iov_len);
            len -= iov[cur_len - 1].iov_len;
            data += iov[cur_len - 1].iov_len;
            cur_len++;
            tmp = realloc(iov, sizeof(struct onload_zc_iovec) * cur_len);
            if (tmp == NULL)
            {
                free_onload_zc_buffers(func_release, fd, iov, cur_len);
                free(iov);
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                 "not enough memory");
                return -1;
            }
            else
            {
                iov = tmp;
                memset(&iov[cur_len - 1], 0, sizeof(*iov));
            }
        }
    }

    *onload_iov = iov;
    *iov_len = cur_len;
    return 0;
}

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE

/**
 * Structure used to store information about buffers sent
 * with onload_zc_send(), for which completion events should
 * arrive.
 */
typedef struct zc_compl_buf {
    TAILQ_ENTRY(zc_compl_buf)   links;  /**< Queue links */
    int                         fd;     /**< Socket FD from which the
                                             buffer was sent */

    uint8_t *ptr;                       /**< Pointer to the ZC buffer
                                             (may be not filled) */
    size_t len;                         /**< Length of the ZC buffer
                                             (may be not filled) */
} zc_compl_buf;

/** Type of queue head for buffers sent with onload_zc_send() */
typedef TAILQ_HEAD(zc_compl_bufs, zc_compl_buf) zc_compl_bufs;

/**
 * Remove from queue of zc_compl_buf structures all the elements
 * with a given FD.
 *
 * @param compl_bufs        Queue to process.
 * @param fd                FD to look for.
 * @param free_compl_bufs   If @c TRUE, free a zc_compl_buf structure after
 *                          removing it from the queue.
 *
 * @return Number of removed elements.
 */
static unsigned int
remove_compl_bufs_by_fd(zc_compl_bufs *compl_bufs, int fd,
                        te_bool free_compl_bufs)
{
    zc_compl_buf *p;
    zc_compl_buf *q;
    unsigned int count = 0;

    TAILQ_FOREACH_SAFE(p, compl_bufs, links, q)
    {
        if (p->fd == fd)
        {
            TAILQ_REMOVE(compl_bufs, p, links);
            if (free_compl_bufs)
                free(p);
            count++;
        }
    }

    return count;
}

/**
 * Wait for completion events for all the buffers sent with
 * onload_zc_send().
 *
 * @param sent_bufs         Queue of sent buffers.
 * @param free_compl_bufs   If @c TRUE, free a zc_compl_buf structure after
 *                          removing it from the queue.
 * @param log_result        If @c TRUE, log how many buffers were
 *                          completed at the end.
 * @param timeout           Polling timeout (in milliseconds; negative
 *                          value means infinite timeout).
 *
 * @return @c 0 on success, @c -1 on failure
 */
int
wait_for_zc_completion(zc_compl_bufs *sent_bufs,
                       te_bool free_compl_bufs,
                       te_bool log_result,
                       int timeout)
{
    api_func_ptr      func_poll = NULL;
    api_func          func_recvmsg = NULL;
    api_func          func_getsockopt = NULL;
    struct msghdr     msgc;
    uint8_t           control_data[500];
    struct cmsghdr   *cmsg;
    zc_compl_buf     *sent_buf = NULL;
    struct pollfd     pfd;
    te_bool           failed = FALSE;
    te_bool           add_sleep = FALSE;
    int               rc = 0;
    unsigned int      completed_num = 0;
    int               saved_errno = errno;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "poll", &func_poll);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "recvmsg", &func_recvmsg);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "getsockopt", &func_getsockopt);

    memset(&msgc, 0, sizeof(msgc));
    msgc.msg_control = control_data;
    while (!TAILQ_EMPTY(sent_bufs))
    {
        sent_buf = TAILQ_FIRST(sent_bufs);
        msgc.msg_controllen = sizeof(control_data);

        pfd.fd = sent_buf->fd;
        pfd.events = pfd.revents = 0;
        rc = func_poll(&pfd, 1, timeout);
        if (rc < 0)
        {
            if (errno != EINTR)
            {
                te_rpc_error_set(
                          TE_OS_RC(TE_TA_UNIX, errno),
                          "poll() failed when waiting for completion "
                          "event");
                rc = -1;
                goto finish;
            }
            else
            {
                WARN("%s(): poll() failed with EINTR, resuming",
                     __FUNCTION__);
                continue;
            }
        }
        else if (rc == 0)
        {
            if (timeout < 0)
            {
                te_rpc_error_set(
                          TE_RC(TE_TA_UNIX, TE_EFAIL),
                          "poll() returned zero with negative timeout");
                rc = -1;
            }

            goto finish;
        }
        else if (rc > 1)
        {
            te_rpc_error_set(
                      TE_RC(TE_TA_UNIX, TE_EFAIL),
                      "poll() returned too big number");
            rc = -1;
            goto finish;
        }

        if (pfd.revents != POLLERR)
        {
            WARN("%s(): poll() reported events 0x%x instead of 0x%x for "
                 "socket %d", __FUNCTION__, (int)(pfd.revents), POLLERR,
                 pfd.fd);
        }
        if (pfd.revents & POLLNVAL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                             "poll() returned POLLNVAL event when waiting "
                             "for completion events");

            /* Remove all the structures with the same FD from the queue */
            remove_compl_bufs_by_fd(sent_bufs, sent_buf->fd, free_compl_bufs);
            failed = TRUE;

            /*
             * Add some sleep at the end - we cannot get
             * completion events and therefore are not sure
             * that buffers can be unregistered and freed.
             */
            add_sleep = TRUE;
            continue;
        }
        if (!(pfd.revents & POLLERR))
        {
            if (pfd.revents & POLLHUP)
            {
                /*
                 * POLLHUP is reported when the other end is completely
                 * closed and will not receive any data remained to be
                 * sent.
                 */
                WARN("%s(): poll() returned POLLHUP without POLLERR for "
                     "socket %d, considering all the sent buffers "
                     "completed", __FUNCTION__, pfd.fd);
                completed_num += remove_compl_bufs_by_fd(sent_bufs,
                                                         sent_buf->fd,
                                                         free_compl_bufs);
                add_sleep = TRUE;
            }

            continue;
        }

        rc = func_recvmsg(sent_buf->fd, &msgc, MSG_ERRQUEUE);
        if (rc >= 0)
        {
            rc = 0;
            cmsg = CMSG_FIRSTHDR(&msgc);
            if (cmsg == NULL)
            {
                te_rpc_error_set(
                     TE_OS_RC(TE_TA_UNIX, errno),
                     "recvmsg() returned success but no control message "
                     "can be retrieved");
                rc = -1;
                goto finish;
            }

            for ( ; cmsg != NULL; cmsg = CMSG_NXTHDR(&msgc, cmsg))
            {
                if (cmsg->cmsg_level == SOL_IP &&
                    cmsg->cmsg_type == ONLOAD_SO_ONLOADZC_COMPLETE)
                {
                    zc_compl_buf *compl_buf;
                    zc_compl_buf *buf_aux;
                    te_bool       found;

                    found = FALSE;
                    memcpy(&compl_buf, CMSG_DATA(cmsg), sizeof(compl_buf));

                    TAILQ_FOREACH(buf_aux, sent_bufs, links)
                    {
                        if (buf_aux == compl_buf)
                        {
                            found = TRUE;
                            break;
                        }
                    }

                    if (found)
                    {
                        if (compl_buf->fd != sent_buf->fd)
                        {
                            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                                             "Completion event for buffer "
                                             "sent via another FD was "
                                             "received");
                            failed = TRUE;
                        }
                        TAILQ_REMOVE(sent_bufs, compl_buf, links);
                        if (free_compl_bufs)
                            free(compl_buf);
                        completed_num++;
                    }
                    else
                    {
                        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                                         "Completion event for unknown "
                                         "buffer was received");
                        failed = TRUE;
                    }
                }
                else
                {
                    WARN("%s(): ignored control message with level=%d (%s) "
                         "type=%d (%s) when processing completion events",
                         __FUNCTION__,
                         cmsg->cmsg_level,
                         socklevel_rpc2str(
                                socklevel_h2rpc(cmsg->cmsg_level)),
                         cmsg->cmsg_type,
                         sockopt_rpc2str(
                              sockopt_h2rpc(cmsg->cmsg_level,
                                            cmsg->cmsg_type)));
                }
            }
        }
        else
        {
            if (errno != EINTR)
            {
                if (errno == EAGAIN)
                {
                    socklen_t     opt_len;

                    struct tcp_info info;

                    opt_len = sizeof(info);
                    rc = func_getsockopt(sent_buf->fd, IPPROTO_TCP,
                                         TCP_INFO, &info, &opt_len);
                    if (rc < 0)
                    {
                        te_rpc_error_set(
                             TE_OS_RC(TE_TA_UNIX, errno),
                             "getsockopt() failed when getting "
                             "TCP_INFO option after recvmsg(MSG_ERRQUEUE) "
                             "failed with EAGAIN");
                        rc = -1;
                        goto finish;
                    }
                    else if (info.tcpi_state == TCP_CLOSE)
                    {
                        WARN("getsockopt(TCP_INFO) reports socket to "
                             "be in TCP_CLOSE state after "
                             "recvmsg(MSG_ERRQUEUE) failed with EAGAIN; "
                             "considering all sent buffers as completed");

                        errno = saved_errno;

                        /*
                         * Add some sleep at the end - we cannot get
                         * completion events and therefore are not sure
                         * that buffers can be unregistered and freed.
                         */
                        add_sleep = TRUE;

                        completed_num += remove_compl_bufs_by_fd(
                                                          sent_bufs,
                                                          sent_buf->fd,
                                                          free_compl_bufs);
                    }
                    else
                    {
                        WARN("Socket %d is in state %s (%d)",
                             sent_buf->fd,
                             tcp_state_rpc2str(
                                   tcp_state_h2rpc(info.tcpi_state)),
                             (int)(info.tcpi_state));

                        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EAGAIN),
                                         "recvmsg(MSG_ERRQUEUE) failed "
                                         "with EAGAIN after poll() "
                                         "reported POLLERR event, socket "
                                         "is not closed");
                        rc = -1;
                        goto finish;
                    }
                }
                else
                {
                    te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                                     "recvmsg() failed when getting "
                                     "completion event");
                    rc = -1;
                    goto finish;
                }
            }
            else
            {
                WARN("%s(): recvmsg() failed with EINTR, resuming",
                     __FUNCTION__);
            }
        }
    }

finish:

    if (log_result)
    {
        RING("%s(): %u buffers were completed from queue %p",
             __FUNCTION__, completed_num, sent_bufs);
    }

    if (add_sleep)
    {
        /*
         * Wait for 100ms to make sure that Onload buffers were
         * completed (when it is not possible to get completion
         * messages).
         *
         * FIXME: it may be not safe to unregister buffers
         * after this; should be improved after ON-11725 is
         * fixed.
         */
        usleep(100000);
    }

    if (failed)
        return -1;

    return rc;
}

/** Types of buffer passed to @b onload_zc_register_buffers() */
typedef enum {
    ZC_REG_BUF_UNKNOWN,         /**< Unknown type */
    ZC_REG_BUF_NORMAL_PAGES,    /**< Memory pages of normal size */
    ZC_REG_BUF_HUGE_PAGES,      /**< Huge pages */
    ZC_REG_BUF_HUGE_ALIGNED,    /**< Memory allocated with posix_memalign()
                                     and aligned by huge page size */
} zc_reg_buf_type;

/**
 * Get type of buffer passed to onload_zc_register_buffers() from
 * an environment variable.
 *
 * @return Buffer type.
 */
static zc_reg_buf_type
sockts_zc_reg_buf_type(void)
{
    const char *var = getenv("SOCKTS_ZC_REG_BUF");

    if (var == NULL)
        return ZC_REG_BUF_NORMAL_PAGES;

    if (strcmp(var, "normal_pages") == 0)
        return ZC_REG_BUF_NORMAL_PAGES;
    else if (strcmp(var, "huge_pages") == 0)
        return ZC_REG_BUF_HUGE_PAGES;
    else if (strcmp(var, "huge_aligned") == 0)
        return ZC_REG_BUF_HUGE_ALIGNED;

    ERROR("%s(): unknown buffer type '%s'", __FUNCTION__, var);
    return ZC_REG_BUF_UNKNOWN;
}

/**
 * Allocate a chunk of memory and register it with
 * @b onload_zc_register_buffers().
 *
 * @param fd          Socket FD.
 * @param buf_type    How to allocate registered buffer.
 * @param len         On input, required length. On output,
 *                    actually allocated length (may be more than
 *                    required because it must be a multiple of
 *                    page size).
 * @param mem         Where to save pointer to allocated memory.
 * @param mem_handle  Where to save @c onload_zc_handle returned by
 *                    @b onload_zc_register_buffers().
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
alloc_register_zc_buf(int fd, zc_reg_buf_type buf_type, size_t *len,
                      void **mem, onload_zc_handle *mem_handle)
{
    api_func      func_reg_bufs = NULL;
    long int      page_size;
    size_t        total_size = *len;
    void         *p = MAP_FAILED;
    int           rc = 0;

    uint64_t addr_space = 0;

    /*
     * The following was introduced due to changes under VIRTBLK-16, see
     * also ST-2129.
     */
#ifdef EF_ADDRSPACE_LOCAL
    addr_space = EF_ADDRSPACE_LOCAL;
#endif

    if (buf_type == ZC_REG_BUF_UNKNOWN)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                         "Unknown registered buffer type");
        return -1;
    }

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_register_buffers",
                  &func_reg_bufs);

    if (buf_type == ZC_REG_BUF_NORMAL_PAGES)
    {
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0)
        {
            te_rpc_error_set(
                      TE_OS_RC(TE_TA_UNIX, errno),
                      "sysconf(_SC_PAGESIZE) returned incorrect value");
            return -1;
        }
    }
    else
    {
        /*
         * FIXME: there is no good way to obtain huge page size.
         * May be /proc/meminfo should be parsed or it can be inferred from
         * alignment of an address returned by mmap(MAP_HUGETLB).
         */
        page_size = 1 << 21;
    }

    /* Buffer length must be multiple of page size. */
    if (total_size % page_size != 0)
        total_size = (total_size / page_size + 1) * page_size;

    if (buf_type == ZC_REG_BUF_HUGE_ALIGNED)
    {
        rc = posix_memalign(&p, page_size, total_size);
        if (rc != 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, rc),
                             "posix_memalign() failed");
            return -1;
        }
    }
    else
    {
        p = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE |
                 (buf_type == ZC_REG_BUF_HUGE_PAGES ? MAP_HUGETLB : 0),
                 -1, 0);
        if (p == MAP_FAILED)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "mmap() failed");
            return -1;
        }
    }

    rc = func_reg_bufs(fd,
                       (uint64_t)addr_space, (uint64_t)(uintptr_t)p,
                       (uint64_t)total_size, 0, mem_handle);
    if (rc < 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                         "onload_zc_register_buffers() failed");
        munmap(p, total_size);
        errno = -rc;
        return -1;
    }

    *mem = p;
    *len = total_size;

    return 0;
}

/**
 * Unregister and unmap memory previously registered with
 * @b onload_zc_register_buffers().
 *
 * @param func_unreg_bufs         Pointer to
 *                                @b onload_zc_unregister_buffers().
 * @param fd                      Socket FD.
 * @param mem_handle              Handle of registered buffer.
 * @param mem                     Pointer to mapped memory.
 * @param mem_size                Size of the mapped memory.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
unreg_unmap_zc_rbufs(api_func func_unreg_bufs,
                     int fd, onload_zc_handle mem_handle,
                     void *mem, size_t mem_size)
{
    int rc;
    int res = 0;

    if (mem_handle != NULL)
    {
        rc = func_unreg_bufs(fd, mem_handle, 0);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                             "onload_zc_unregister_buffers() failed");
            errno = -rc;
            res = -1;
        }
    }

    if (mem != MAP_FAILED)
    {
        rc = munmap(mem, mem_size);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "munmap() failed()");
            res = -1;
        }
    }

    return res;
}

/**
 * Send one message with @c MSG_MORE flag and then second
 * message without it. Use @b onload_zc_register_buffers() to
 * register memory storing data passed to onload_zc_send().
 *
 * @param in    Messages parameters
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
onload_zc_send_msg_more_rbufs(tarpc_onload_zc_send_msg_more_in *in)
{
#ifndef ONLOAD_MSG_MORE
    UNUSED(in);
    ERROR("MSG_MORE flag is not supported");
    errno = EOPNOTSUPP;
    return -1;
#else
    api_func_ptr        func_zc_send = NULL;
    api_func            func_unreg_bufs = NULL;
    api_func            func_send = NULL;
    api_func            func_setsockopt = NULL;
    int                 rc = 0;
    int                 rc_aux;

    onload_zc_handle    mem_handle = NULL;
    void               *mem = MAP_FAILED;
    size_t              mem_size;
    char               *buf;

    struct onload_zc_iovec  iovs[2];
    struct onload_zc_mmsg   msg;
    int                     rc1 = 0;
    int                     rc2 = 0;

    zc_compl_buf            compl_bufs[2];
    zc_compl_bufs           sent_bufs = TAILQ_HEAD_INITIALIZER(sent_bufs);

    buf = rcf_pch_mem_get(in->buf);
    if (buf == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Buffer address was not found");
        return -1;
    }

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_send", &func_zc_send);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_unregister_buffers",
                  &func_unreg_bufs);
    if (in->set_nodelay)
        TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "setsockopt", &func_setsockopt);

    if (!in->first_zc || !in->second_zc)
    {
        TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "send", &func_send);
    }

    mem_size = in->first_len + in->second_len;
    rc = alloc_register_zc_buf(in->fd, sockts_zc_reg_buf_type(),
                               &mem_size, &mem, &mem_handle);
    if (rc < 0)
        return rc;

    memcpy(mem, buf, in->first_len + in->second_len);

    memset(compl_bufs, 0, sizeof(compl_bufs));
    memset(iovs, 0, sizeof(iovs));

    iovs[0].iov_base = mem;
    iovs[0].iov_len = in->first_len;
    iovs[0].buf = mem_handle;
    compl_bufs[0].fd = in->fd;
    iovs[0].app_cookie = &compl_bufs[0];

    iovs[1].iov_base = (uint8_t *)mem + in->first_len;
    iovs[1].iov_len = in->second_len;
    iovs[1].buf = mem_handle;
    compl_bufs[1].fd = in->fd;
    iovs[1].app_cookie = &compl_bufs[1];

    memset(&msg, 0, sizeof(msg));
    msg.fd = in->fd;
    msg.msg.msghdr.msg_iovlen = 1;
    msg.msg.iov = &iovs[0];

    rc = send_msg_more_check(in->first_zc, &msg, in->fd,
                             buf, in->first_len, TRUE,
                             func_zc_send, func_send, "the first");
    if (rc < 0)
        goto cleanup;

    rc1 = rc;
    if (in->first_zc)
        TAILQ_INSERT_TAIL(&sent_bufs, &compl_bufs[0], links);

    if (in->set_nodelay)
    {
        if (set_tcp_nodelay(in->fd, func_setsockopt, 1) < 0)
        {
            rc = -1;
            goto cleanup;
        }
    }

    msg.msg.iov = &iovs[1];

    rc = send_msg_more_check(in->second_zc, &msg, in->fd,
                             buf + in->first_len, in->second_len, FALSE,
                             func_zc_send, func_send, "the second");
    if (rc < 0)
        goto cleanup;

    rc2 = rc;
    if (in->second_zc)
        TAILQ_INSERT_TAIL(&sent_bufs, &compl_bufs[1], links);

cleanup:

    if (!TAILQ_EMPTY(&sent_bufs))
    {
        rc_aux = wait_for_zc_completion(&sent_bufs, FALSE, TRUE, -1);
        if (rc_aux < 0)
            rc = -1;
    }

    rc_aux = unreg_unmap_zc_rbufs(func_unreg_bufs, in->fd, mem_handle,
                                  mem, mem_size);
    if (rc_aux < 0)
        rc = -1;

    if (rc >= 0)
        return rc1 + rc2;

    return rc;
#endif
}

#endif /* ONLOAD_SO_ONLOADZC_COMPLETE */

/**
 * Send one message with @c MSG_MORE flag and then second
 * message without it. Use @b onload_zc_alloc_buffers() for
 * Onload buffers allocation.
 *
 * @param in    Messages parameters
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
onload_zc_send_msg_more_abufs(tarpc_onload_zc_send_msg_more_in *in)
{
#ifndef ONLOAD_MSG_MORE
    UNUSED(in);
    ERROR("MSG_MORE flag is not supported");
    errno = EOPNOTSUPP;
    return -1;
#else
    struct onload_zc_iovec *onload_iov1 = NULL;
    struct onload_zc_iovec *onload_iov2 = NULL;
    size_t                  iov_len1;
    size_t                  iov_len2;
    int                     rc;
    struct onload_zc_mmsg   msg;
    ssize_t                 res1 = -1;
    ssize_t                 res2 = -1;
    ssize_t                 res = 0;
    char                   *buf;

    api_func_ptr func_zc_send;
    api_func     func_send;
    api_func     func_alloc;
    api_func     func_release;
    api_func     func_setsockopt;

    buf = rcf_pch_mem_get(in->buf);
    if (buf == NULL)
    {
        ERROR("Buffer address was not found");
        return -1;
    }

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_send", &func_zc_send);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "send", &func_send);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_alloc_buffers",
                  &func_alloc);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_release_buffers",
                  &func_release);
    if (in->set_nodelay)
        TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "setsockopt", &func_setsockopt);

    memset(&msg, 0, sizeof(msg));
    msg.fd = in->fd;

    if (in->first_zc)
    {
        if ((rc = alloc_fill_zc_bufs(func_alloc, func_release,
                                     in->fd, &onload_iov1,
                                     &iov_len1,
                                     buf, in->first_len)) != 0)
        {
            res = -1;
            goto cleanup;
        }
    }

    if (in->second_zc)
    {
        if ((rc = alloc_fill_zc_bufs(func_alloc, func_release,
                                     in->fd, &onload_iov2,
                                     &iov_len2,
                                     buf + in->first_len,
                                     in->second_len)) != 0)
        {
            res = -1;
            goto cleanup;
        }
    }

    msg.msg.iov = onload_iov1;
    msg.msg.msghdr.msg_iovlen = iov_len1;

    res1 = send_msg_more_check(in->first_zc, &msg, in->fd,
                               buf, in->first_len, TRUE,
                               func_zc_send, func_send, "the first");
    if (res1 < 0)
    {
        res = -1;
        goto cleanup;
    }

    if (in->set_nodelay)
    {
        if (set_tcp_nodelay(in->fd, func_setsockopt, 1) < 0)
        {
            res = -1;
            goto cleanup;
        }
    }

    msg.msg.iov = onload_iov2;
    msg.msg.msghdr.msg_iovlen = iov_len2;

    res2 = send_msg_more_check(in->second_zc, &msg, in->fd,
                               buf + in->first_len, in->second_len, FALSE,
                               func_zc_send, func_send, "the second");
    if (res1 < 0)
    {
        res = -1;
        goto cleanup;
    }

    res = res1 + res2;

cleanup:

    if (onload_iov1 != NULL && res1 < 0)
    {
        res1 = free_onload_zc_buffers(func_release, in->fd,
                                      onload_iov1, iov_len1);
        if (res1 < 0)
            res = -1;
    }

    if (onload_iov2 != NULL && res2 < 0)
    {
        res2 = free_onload_zc_buffers(func_release, in->fd,
                                      onload_iov2, iov_len2);
        if (res2 < 0)
            res = -1;
    }

    free(onload_iov1);
    free(onload_iov2);

    return res;
#endif /* ONLOAD_MSG_MORE */
}

/**
 * Send one message with @c MSG_MORE flag and then second
 * message without it.
 *
 * @param in    Messages parameters
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
onload_zc_send_msg_more(tarpc_onload_zc_send_msg_more_in *in)
{
    if (in->use_reg_bufs)
    {
#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
        return onload_zc_send_msg_more_rbufs(in);
#else
        UNUSED(in);
        ERROR("onload_zc_send() with user buffer is not supported");
        errno = EOPNOTSUPP;
        return -1;
#endif
    }
    else
    {
        return onload_zc_send_msg_more_abufs(in);
    }
}

TARPC_FUNC(onload_zc_send_msg_more, {},
{
    MAKE_CALL(out->retval = func_ptr(in));
}
)

/**
 * Call onload_zc_send(), measuring time it took to call it.
 *
 * @param func_zc_send        Pointer to onload_zc_send().
 * @param msgs                Pointer to array of messages.
 * @param mlen                Number of messages.
 * @param send_duration       Where to save time taken by the send call
 *                            itself (in mircoseconds). Will be set to a
 *                            negative number if gettimeofday() fails.
 *
 * @return Value returned by onload_zc_send().
 */
static int
call_zc_send(api_func_ptr func_zc_send, struct onload_zc_mmsg *msgs,
             int mlen, int flags, int64_t *duration)
{
    struct timeval tv_before;
    struct timeval tv_after;
    te_errno       te_rc;
    int            rc;

    *duration = -1;

    te_rc = te_gettimeofday(&tv_before, NULL);
    rc = func_zc_send(msgs, mlen, flags);
    if (te_rc == 0)
    {
        te_rc = te_gettimeofday(&tv_after, NULL);
        if (te_rc == 0)
            *duration = TIMEVAL_SUB(tv_after, tv_before);
    }

    return rc;
}

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE

TARPC_FUNC(onload_zc_register_buffers, {},
{
    uint8_t           *p = NULL;
    onload_zc_handle   handle = NULL;

    p = (uint8_t *)rcf_pch_mem_get(in->base_ptr);
    p = p + in->off;

    MAKE_CALL(out->retval =
                  func(in->fd, in->addr_space, (uint64_t)(uintptr_t)p,
                       in->len, in->flags, &handle));
    if (out->retval >= 0)
    {
        out->handle = rcf_pch_mem_alloc(handle);
    }
    else
    {
        out->common._errno = TE_OS_RC(TE_RPC, -out->retval);
        out->retval = -1;
    }
})

TARPC_FUNC(onload_zc_unregister_buffers, {},
{
    onload_zc_handle handle;

    handle = (onload_zc_handle)rcf_pch_mem_get(in->handle);

    MAKE_CALL(out->retval = func(in->fd, handle, in->flags));
    if (out->retval < 0)
    {
        out->common._errno = TE_OS_RC(TE_RPC, -out->retval);
        out->retval = -1;
    }
    rcf_pch_mem_free(in->handle);
})

/**
 * Allocate a head of the queue for keeping track of sent
 * ZC buffers which should be completed.
 *
 * @return Pointer to queue head on success, @c NULL on failure.
 */
static zc_compl_bufs *
sockts_alloc_zc_compl_queue(void)
{
    zc_compl_bufs *bufs;

    bufs = calloc(1, sizeof(*bufs));
    if (bufs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to allocate completion queue");
        return NULL;
    }

    TAILQ_INIT(bufs);

    return bufs;
}

TARPC_FUNC_STATIC(sockts_alloc_zc_compl_queue, {},
{
    zc_compl_bufs *bufs;

    MAKE_CALL(bufs = func());

    out->retval = rcf_pch_mem_alloc(bufs);
    if (out->retval == RPC_NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "Failed to get RPC pointer for allocated queue");
        free(bufs);
    }
})

/**
 * Release memory allocated for a queue used for keeping track of sent
 * ZC buffers.
 *
 * @param bufs      Pointer to the queue head.
 */
static void
sockts_free_zc_compl_queue(zc_compl_bufs *bufs)
{
    zc_compl_buf *p;
    zc_compl_buf *q;

    TAILQ_FOREACH_SAFE(p, bufs, links, q)
    {
        TAILQ_REMOVE(bufs, p, links);
        free(p);
    }

    free(bufs);
}

TARPC_FUNC_STATIC(sockts_free_zc_compl_queue, {},
{
    zc_compl_bufs *bufs;
    te_errno rc;

    bufs = rcf_pch_mem_get(in->qhead);
    if (bufs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve queue head pointer");
        out->retval = -1;
    }
    else
    {
        MAKE_CALL(func(bufs));

        rc = rcf_pch_mem_free(in->qhead);
        if (rc != 0)
        {
            te_rpc_error_set(rc, "rcf_pch_mem_free() failed");
            out->retval = -1;
        }
        else
        {
            out->retval = 0;
        }
    }
})

/**
 * Receive and process completion messages for sent ZC buffers tracked in
 * a queue. Remove from the queue buffers for which completion
 * messages arrived.
 *
 * @param bufs      Head of the queue.
 * @param timeout   Timeout when polling for completion messages,
 *                  in milliseconds (negative value means infinite
 *                  timeout).
 *
 * @return @c 1 if some buffers are not completed,
 *         @c 0 if all buffers were completed,
 *         @c -1 on failure.
 */
static int
sockts_proc_zc_compl_queue(zc_compl_bufs *bufs, int timeout)
{
    int rc;

    rc = wait_for_zc_completion(bufs, TRUE, TRUE, timeout);
    if (rc < 0)
        return -1;

    if (!TAILQ_EMPTY(bufs))
        return 1;

    return 0;
}

TARPC_FUNC_STATIC(sockts_proc_zc_compl_queue, {},
{
    zc_compl_bufs *bufs;

    bufs = rcf_pch_mem_get(in->qhead);
    if (bufs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve queue head pointer");
        out->retval = -1;
    }
    else
    {
        MAKE_CALL(out->retval = func(bufs, in->timeout));
    }
})

#endif /* ifdef ONLOAD_SO_ONLOADZC_COMPLETE */

/**
 * Structure storing auxiliary data used for
 * struct onload_zc_mmsg processing.
 */
typedef struct zc_mmsg_data {
    struct onload_zc_mmsg       *mmsg;  /**< Pointer to processed
                                             onload_zc_mmsg structure */

    unsigned int  iov_rlen;      /**< Real number of IOVs in the message */
    te_bool       use_reg_bufs;  /**< If @c TRUE and buf_specs is not
                                      specified, use
                                      @b onload_zc_register_buffers();
                                      otherwise -
                                      @b onload_zc_alloc_buffers() */
    int           alloc_fd;      /**< If not negative, use this FD for
                                      buffers allocation/registering
                                      instead of FD from mmsg */

    tarpc_onload_zc_buf_spec   *buf_specs;   /**< Array of ZC buffer
                                                  allocation
                                                  specifications */
#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    zc_compl_bufs                compl_bufs;   /**< Queue of zc_compl_buf
                                                    structures used when
                                                    waiting for completion
                                                    messages */
    void                        *mem;          /**< Address of memory chunk
                                                    allocated with mmap() */
    size_t                       mem_size;     /**< Number of bytes in the
                                                    mapped memory chunk */
    onload_zc_handle             mem_handle;   /**< Onload handle obtained
                                                    after registering the
                                                    mapped memory chunk */
#endif

    te_bool initialized;  /**< If @c TRUE, this structure was successfully
                               initialized with zc_mmsg_data_alloc_fill() */
} zc_mmsg_data;

/**
 * Allocate and fill Onload buffers for the single message to be sent
 * with @b onload_zc_send().
 *
 * @note Errors are reported with te_rpc_error_set().
 *
 * @param mmsg_data     Structure describing the message.
 *                      @b mmsg_data->buf_specs field tells how to allocate
 *                      buffers (or from where to take existing ones);
 *                      if it is @c NULL, @b mmsg_data->use_reg_bufs
 *                      determines how to allocate Onload iovecs.
 *                      @b mmsg_data->iov_rlen and
 *                      @b mmsg_data->mmsg->msg.msghdr contain information
 *                      how many iovecs should be allocated and what
 *                      data they should store.
 *                      @b mmsg_data->alloc_fd and @b mmsg_data->mmsg->fd
 *                      determine which FD to use for Onload buffers
 *                      allocation/registering.
 *                      This function allocates and fills
 *                      @b mmsg_data->mmsg->msg.iov, and also fills
 *                      auxiliary fields such as @b compl_bufs, @b mem,
 *                      @b mem_size, @b mem_handle, @b initialized.
 * @param no_compl      If @c TRUE, RPC call will not receive and process
 *                      completion messages for sent ZC user buffers
 *                      (so we should not allocate/release them
 *                      automatically).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
zc_mmsg_data_alloc_fill(zc_mmsg_data *mmsg_data,
                        te_bool no_compl)
{
    unsigned int  i = 0;
    unsigned int  j = 0;
    int           rc = 0;
    int           rc_aux;

    tarpc_onload_zc_buf_spec  *buf_specs;
    te_bool                    allocated_seq = FALSE;
    int                        buf_type;
    int                        buf_type_aux;

    int                     fd;
    struct msghdr          *msg = NULL;
    struct onload_zc_iovec *iovs = NULL;
    struct onload_zc_iovec *cur_iov = NULL;
    void                   *existing_buf = NULL;
    struct onload_zc_iovec *existing_iovs = NULL;

    api_func      func_alloc = NULL;
    api_func      func_release_bufs = NULL;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    api_func            func_unreg_bufs = NULL;
    size_t              reg_bufs_size = 0;
    zc_compl_buf       *compl_buf = NULL;
    zc_compl_buf       *compl_buf_aux = NULL;
    onload_zc_handle    buf_handle = NULL;
    onload_zc_handle    mem_handle = NULL;
    void               *mem = MAP_FAILED;
    size_t              mem_size = 0;
    uint8_t            *cur_reg_ptr = NULL;

    zc_reg_buf_type reg_buf_type = sockts_zc_reg_buf_type();

    TAILQ_INIT(&mmsg_data->compl_bufs);
#endif

    msg = &mmsg_data->mmsg->msg.msghdr;

    /*
     * If NULL iov is requested, no need to allocate
     * anything.
     */
    if (msg->msg_iov == NULL)
        goto cleanup;

    if (mmsg_data->use_reg_bufs)
        buf_type = TARPC_ONLOAD_ZC_BUF_NEW_REG;
    else
        buf_type = TARPC_ONLOAD_ZC_BUF_NEW_ALLOC;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_alloc_buffers",
                  &func_alloc);
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_release_buffers",
                  &func_release_bufs);
#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_unregister_buffers",
                  &func_unreg_bufs);
#endif

    buf_specs = mmsg_data->buf_specs;
    fd = mmsg_data->alloc_fd;
    if (fd < 0)
        fd = mmsg_data->mmsg->fd;

    iovs = calloc(mmsg_data->iov_rlen, sizeof(*iovs));
    if (iovs == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "calloc() failed to allocate array of "
                         "onload_zc_iovec structures");
        rc = -1;
        goto cleanup;
    }

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    if (buf_specs != NULL || mmsg_data->use_reg_bufs)
    {
        for (i = 0; i < mmsg_data->iov_rlen; i++)
        {
            if (buf_specs != NULL)
                buf_type = buf_specs[i].type;

            if (buf_type == TARPC_ONLOAD_ZC_BUF_NEW_REG)
                reg_bufs_size += msg->msg_iov[i].iov_len;
        }

        mem_size = reg_bufs_size;
        if (mem_size > 0)
        {
            if (no_compl)
            {
                te_rpc_error_set(
                      TE_RC(TE_TA_UNIX, TE_EINVAL),
                      "Cannot allocate/register/unregister/release ZC user "
                      "buffer automatically when processing of completion "
                      "messages by the RPC call is disabled");
                rc = -1;
                goto cleanup;
            }

            rc = alloc_register_zc_buf(fd, reg_buf_type, &mem_size, &mem,
                                       &mem_handle);
            if (rc < 0)
                goto cleanup;
        }

        cur_reg_ptr = (uint8_t *)mem;
    }
#endif

    for (i = 0; i < mmsg_data->iov_rlen; i++)
    {
        if (buf_specs != NULL)
            buf_type = buf_specs[i].type;

        if (buf_type != TARPC_ONLOAD_ZC_BUF_NEW_ALLOC)
        {
            /*
             * If there was a sequence of buffers allocated with
             * the single call of onload_zc_alloc_buffers(), now it
             * is finished
             */
            allocated_seq = FALSE;
        }

        if (buf_type == TARPC_ONLOAD_ZC_BUF_EXIST_ALLOC ||
            buf_type == TARPC_ONLOAD_ZC_BUF_EXIST_REG)
        {
            existing_buf = rcf_pch_mem_get(buf_specs[i].existing_buf);
            if (existing_buf == NULL)
            {
                te_rpc_error_set(
                         TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "failed to resolve buffer pointer");
                rc = -1;
                goto cleanup;
            }

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
            if (buf_type == TARPC_ONLOAD_ZC_BUF_EXIST_REG)
            {
                buf_handle = rcf_pch_mem_get(buf_specs[i].buf_handle);
                if (buf_handle == NULL)
                {
                    te_rpc_error_set(
                             TE_RC(TE_TA_UNIX, TE_ENOENT),
                             "failed to resolve buffer handle pointer");
                    rc = -1;
                    goto cleanup;
                }
            }
#endif
        }

        switch (buf_type)
        {
            case TARPC_ONLOAD_ZC_BUF_EXIST_ALLOC:
                existing_iovs = (struct onload_zc_iovec *)existing_buf;
                cur_iov = &existing_iovs[buf_specs[i].buf_index];
                memcpy(&iovs[i], cur_iov, sizeof(*cur_iov));
                break;

            case TARPC_ONLOAD_ZC_BUF_NEW_ALLOC:
                /*
                 * If we encounter a sequence of buffers to be
                 * allocated with onload_zc_alloc_buffers(),
                 * we allocate the whole sequence with the single
                 * call on encountering the first buffer and after
                 * that do nothing until the sequence is finished.
                 */
                if (allocated_seq)
                    break;

                buf_type_aux = buf_type;
                for (j = i + 1; j < mmsg_data->iov_rlen; j++)
                {
                    if (buf_specs != NULL)
                        buf_type_aux = buf_specs[j].type;
                    if (buf_type_aux != TARPC_ONLOAD_ZC_BUF_NEW_ALLOC)
                        break;
                }

                rc = func_alloc(fd, iovs + i, j - i,
                                ONLOAD_ZC_BUFFER_HDR_TCP);
                if (rc < 0)
                {
                    te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                                     "onload_zc_alloc_buffers() failed");
                    rc = -1;
                    goto cleanup;
                }
                allocated_seq = TRUE;
                break;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
            case TARPC_ONLOAD_ZC_BUF_EXIST_REG:
                iovs[i].iov_base = (uint8_t *)existing_buf +
                                              buf_specs[i].buf_offset;
                iovs[i].iov_len = msg->msg_iov[i].iov_len;
                iovs[i].buf = buf_handle;
                break;

            case TARPC_ONLOAD_ZC_BUF_NEW_REG:
                iovs[i].iov_base = cur_reg_ptr;
                iovs[i].iov_len = msg->msg_iov[i].iov_len;
                iovs[i].buf = mem_handle;
                cur_reg_ptr += iovs[i].iov_len;
                break;
#endif

            default:
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                                 "unsupported iovec allocation type %d",
                                 buf_type);
                rc = -1;
                goto cleanup;
        }

        if (iovs[i].iov_len < msg->msg_iov[i].iov_len)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                             "Onload iovec is too small");
            rc = -1;
            goto cleanup;
        }

        if (msg->msg_iov[i].iov_base == NULL)
        {
            iovs[i].iov_base = NULL;
        }
        else
        {
            memcpy(iovs[i].iov_base, msg->msg_iov[i].iov_base,
                   msg->msg_iov[i].iov_len);
        }
        iovs[i].iov_len = msg->msg_iov[i].iov_len;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
        if (buf_type == TARPC_ONLOAD_ZC_BUF_EXIST_REG ||
            buf_type == TARPC_ONLOAD_ZC_BUF_NEW_REG)
        {
            compl_buf = calloc(1, sizeof(*compl_buf));
            if (compl_buf == NULL)
            {
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                 "failed to allocate memory for "
                                 "zc_compl_buf structure");
                rc = -1;
                goto cleanup;
            }

            compl_buf->fd = mmsg_data->mmsg->fd;
            iovs[i].app_cookie = compl_buf;

            TAILQ_INSERT_TAIL(&mmsg_data->compl_bufs, compl_buf, links);
        }
#endif
    }

cleanup:

    if (rc < 0)
    {
#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
        unreg_unmap_zc_rbufs(func_unreg_bufs, fd, mem_handle,
                             mem, mem_size);
        TAILQ_FOREACH_SAFE(compl_buf, &mmsg_data->compl_bufs, links,
                           compl_buf_aux)
        {
            TAILQ_REMOVE(&mmsg_data->compl_bufs, compl_buf, links);
            free(compl_buf);
        }
#endif

        for (i = 0; i < mmsg_data->iov_rlen; i++)
        {
            if (buf_specs != NULL)
                buf_type = buf_specs[i].type;

            if (buf_type == TARPC_ONLOAD_ZC_BUF_NEW_ALLOC &&
                iovs[i].buf != NULL)
            {
                rc_aux = func_release_bufs(fd, &iovs[i].buf, 1);
                if (rc_aux < 0)
                {
                    te_rpc_error_set(TE_OS_RC(TE_RPC, -rc_aux),
                                     "onload_zc_release_buffers() failed");
                }
            }
        }

        free(iovs);
    }
    else
    {
        mmsg_data->mmsg->msg.iov = iovs;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
        mmsg_data->mem_handle = mem_handle;
        mmsg_data->mem = mem;
        mmsg_data->mem_size = mem_size;
#endif

        mmsg_data->initialized = TRUE;
    }

    return rc;
}

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE

/**
 * Add to a queue zc_compl_buf structures corresponding to
 * sent registered ZC buffers, for which completion messages
 * should arrive.
 *
 * @param mmsg_data       Pointer to a structure describing message
 *                        passed to @b onload_zc_send().
 * @param reg_bufs_queue  Queue to which to append zc_compl_buf
 *                        structures.
 * @param bufs_counter    If not @c NULL, will be incremented by
 *                        number of structures appended to the queue.
 */
static void
zc_mmsg_data_get_sent_rbufs(zc_mmsg_data *mmsg_data,
                            zc_compl_bufs *reg_bufs_queue,
                            unsigned int *bufs_counter)
{
    struct onload_zc_iovec *iovs;
    tarpc_onload_zc_buf_spec *buf_specs;
    unsigned int i;
    size_t iov_len_sum = 0;
    zc_compl_buf *compl_buf = NULL;

    if (mmsg_data->mmsg->rc <= 0)
        return;

    iovs = mmsg_data->mmsg->msg.iov;
    if (iovs == NULL)
        return;

    buf_specs = mmsg_data->buf_specs;

    if (buf_specs != NULL || mmsg_data->use_reg_bufs)
    {
        for (i = 0; i < mmsg_data->iov_rlen; i++)
        {
            if (iov_len_sum < (size_t)(mmsg_data->mmsg->rc))
            {
                if (buf_specs == NULL ||
                    buf_specs[i].type == TARPC_ONLOAD_ZC_BUF_NEW_REG ||
                    buf_specs[i].type == TARPC_ONLOAD_ZC_BUF_EXIST_REG)
                {
                    compl_buf = (zc_compl_buf *)(iovs[i].app_cookie);
                    TAILQ_REMOVE(&mmsg_data->compl_bufs, compl_buf, links);
                    TAILQ_INSERT_TAIL(reg_bufs_queue, compl_buf, links);
                    if (bufs_counter != NULL)
                        (*bufs_counter)++;
                }
            }
            else
            {
                break;
            }
            iov_len_sum += mmsg_data->mmsg->msg.iov[i].iov_len;
        }
    }
}

/**
 * Wait for completion messages for registered ZC buffers which were
 * successfully sent.
 *
 * @note Errors are reported with te_rpc_error_set().
 *
 * @param mmsgs         Array of structures describing sent messages.
 * @param mlen          Number of sent messages.
 * @param compl_queue   Queue to track not completed ZC buffers.
 *                      If @c NULL, this function will use its own
 *                      local queue and wait for all completions
 *                      before returning. If not @c NULL, this
 *                      function will only add all the sent buffers
 *                      to the specified queue and return immediately.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
zc_mmsg_data_proc_completions(zc_mmsg_data *mmsgs, unsigned int mlen,
                              zc_compl_bufs *compl_queue)
{
    unsigned int i;
    unsigned int sent_bufs_cnt = 0;
    zc_compl_bufs local_queue = TAILQ_HEAD_INITIALIZER(local_queue);
    zc_compl_bufs *queue_ptr = NULL;

    if (compl_queue != NULL)
        queue_ptr = compl_queue;
    else
        queue_ptr = &local_queue;

    for (i = 0; i < mlen; i++)
    {
        zc_mmsg_data_get_sent_rbufs(&mmsgs[i], queue_ptr,
                                    &sent_bufs_cnt);
    }

    if (sent_bufs_cnt > 0)
    {
        RING("%s(): %u buffers were sent, completion queue %p",
             __FUNCTION__, sent_bufs_cnt, queue_ptr);

        if (compl_queue == NULL)
            return wait_for_zc_completion(queue_ptr, TRUE, TRUE, -1);
    }

    return 0;
}

#endif /* ONLOAD_SO_ONLOADZC_COMPLETE */

/**
 * Release resources allocated for ZC message.
 *
 * @note Errors are reported with te_rpc_error_set().
 *
 * @param mmsg_data   Pointer to structure describing message and
 *                    allocated resources.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
zc_mmsg_data_free(zc_mmsg_data *mmsg_data)
{
    int res;
    int retval = 0;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    api_func func_unreg_bufs = NULL;
    zc_compl_buf *compl_buf = NULL;
    zc_compl_buf *compl_buf_aux = NULL;
#endif
    api_func func_release_bufs = NULL;
    int fd;

    struct onload_zc_iovec *iovs;
    tarpc_onload_zc_buf_spec *buf_specs;
    unsigned int i;
    size_t iov_len_sum = 0;

    if (!mmsg_data->initialized)
        return 0;

    fd = mmsg_data->alloc_fd;
    if (fd < 0)
        fd = mmsg_data->mmsg->fd;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_unregister_buffers",
                  &func_unreg_bufs);
#endif
    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_release_buffers",
                  &func_release_bufs);

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    if (mmsg_data->mem_size > 0)
    {
        res = unreg_unmap_zc_rbufs(func_unreg_bufs, fd,
                                   mmsg_data->mem_handle,
                                   mmsg_data->mem, mmsg_data->mem_size);
        if (res < 0)
            retval = -1;

        mmsg_data->mem_handle = NULL;
        mmsg_data->mem = MAP_FAILED;
        mmsg_data->mem_size = 0;
    }

    TAILQ_FOREACH_SAFE(compl_buf, &mmsg_data->compl_bufs, links,
                       compl_buf_aux)
    {
        TAILQ_REMOVE(&mmsg_data->compl_bufs, compl_buf, links);
        free(compl_buf);
    }
#endif

    iovs = mmsg_data->mmsg->msg.iov;
    buf_specs = mmsg_data->buf_specs;

    if (iovs != NULL && (buf_specs != NULL || !mmsg_data->use_reg_bufs))
    {
        /*
         * Release not sent buffers allocated with
         * onload_zc_alloc_buffers().
         */
        for (i = 0; i < mmsg_data->iov_rlen; i++)
        {
            if ((mmsg_data->mmsg->rc < 0 ||
                 iov_len_sum >= (size_t)(mmsg_data->mmsg->rc)) &&
                (buf_specs == NULL ||
                 buf_specs[i].type == TARPC_ONLOAD_ZC_BUF_NEW_ALLOC))

            {
                res = func_release_bufs(fd, &iovs[i].buf, 1);
                if (res < 0)
                {
                    if (mmsg_data->mmsg->rc < 0)
                    {
                        te_rpc_error_set(
                              TE_OS_RC(TE_RPC, -res),
                              "onload_zc_release_buffers() failed "
                              "(mmsg.rc = %s)",
                              te_rc_err2str(
                                te_rc_os2te(-mmsg_data->mmsg->rc)));
                    }
                    else
                    {
                        te_rpc_error_set(
                                    TE_OS_RC(TE_RPC, -res),
                                    "onload_zc_release_buffers() failed");
                    }
                    retval = -1;
                }
            }

            iov_len_sum += mmsg_data->mmsg->msg.iov[i].iov_len;
        }
    }

    free(mmsg_data->mmsg->msg.iov);
    mmsg_data->mmsg->msg.iov = NULL;
    return retval;
}

/**
 * Call @b onload_zc_send() using either @b onload_zc_alloc_buffers() or
 * @b onload_zc_register_buffers() for allocating or registering buffers
 * to be sent.
 *
 * @param msgs                Messages to send.
 * @param mlen                Number of messages.
 * @param flags               Flags for @b onload_zc_send().
 * @param iov_rlen            Array with real numbers of iovecs per
 *                            message.
 * @param add_sock            If not negative, this FD will be passed to
 *                            @b onload_zc_alloc_buffers() or
 *                            @b onload_zc_register_buffers().
 * @param use_reg_bufs        If @c TRUE, use
 *                            @b onload_zc_register_buffers(), otherwise
 *                            @b onload_zc_alloc_buffers().
 * @param send_duration       Where to save time taken by the send call
 *                            itself (in mircoseconds). Will be set to a
 *                            negative number if gettimeofday() fails.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
int
simple_zc_send(struct onload_zc_mmsg *msgs, int mlen, int flags,
               int64_t *send_duration)
{
    api_func_ptr func_zc_send = NULL;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_send", &func_zc_send);

    return call_zc_send(func_zc_send, msgs, mlen, flags, send_duration);
}

TARPC_FUNC(simple_zc_send,
{
    COPY_ARG(zc_rc);
},
{
    struct onload_zc_mmsg *msgs = NULL;
    rpcs_msghdr_helper *helpers = NULL;
    unsigned int j;
    zc_mmsg_data *mmsg_data = NULL;
    int res;

    if (in->msgs.msgs_val == NULL)
    {
        MAKE_CALL(out->retval = func_ptr(NULL, in->mlen,
                                         send_recv_flags_rpc2h(in->flags),
                                         &out->send_duration));
    }
    else
    {
        struct tarpc_msghdr    *rpc_msg;
        struct msghdr          *msg = NULL;
        te_errno                rc;
        te_bool                 no_completions = FALSE;

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
        struct zc_compl_bufs *compl_queue = NULL;

        if (in->compl_queue != RPC_NULL)
        {
            compl_queue = rcf_pch_mem_get(in->compl_queue);
            if (compl_queue == NULL)
            {
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                                 "Failed to resolve compl_queue pointer");
                out->retval = -1;
                goto finish;
            }
            no_completions = TRUE;
        }
#endif
        msgs = calloc(in->msgs.msgs_len, sizeof(*msgs));
        helpers = calloc(in->msgs.msgs_len, sizeof(*helpers));
        mmsg_data = calloc(in->msgs.msgs_len, sizeof(*mmsg_data));

        if (msgs == NULL || helpers == NULL || mmsg_data == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "calloc() failed to allocate arrays for "
                             "processing onload_zc_send() arguments");
            out->retval = -1;
            goto finish;
        }

        for (j = 0; j < in->msgs.msgs_len; j++)
        {
            msgs[j].rc = in->msgs.msgs_val[j].rc;
            msg = &msgs[j].msg.msghdr;
            msgs[j].fd = in->msgs.msgs_val[j].fd;
            rpc_msg = &(in->msgs.msgs_val[j].msg);

            rc = rpcs_msghdr_tarpc2h(RPCS_MSGHDR_CHECK_ARGS_SEND,
                                     rpc_msg, &helpers[j],
                                     msg, arglist,
                                     "msgs[%u].msg.msghdr", j);
            if (rc != 0)
            {
                out->common._errno = TE_RC(TE_TA_UNIX, rc);
                goto finish;
            }

            mmsg_data[j].mmsg = &msgs[j];
            mmsg_data[j].iov_rlen = rpc_msg->msg_iov.msg_iov_len;
            mmsg_data[j].use_reg_bufs = in->use_reg_bufs;
            mmsg_data[j].alloc_fd = in->add_sock;
            mmsg_data[j].buf_specs =
                  in->msgs.msgs_val[j].buf_specs.buf_specs_val;

            res = zc_mmsg_data_alloc_fill(&mmsg_data[j], no_completions);
            if (res < 0)
            {
                out->retval = -1;
                goto finish;
            }
        }

        VERB("simple_zc_send(): msg=%s, mlen=%d, flags=0x%x add_sock=%d",
             onload_zc_mmsg2str(msgs, in->mlen), in->mlen,
             send_recv_flags_rpc2h(in->flags), in->add_sock);
        MAKE_CALL(out->retval = func_ptr(msgs, in->mlen,
                                         send_recv_flags_rpc2h(in->flags),
                                         &out->send_duration));
        VERB("simple_zc_send(): msg=%s, mlen=%d, flags=0x%x add_sock=%d",
             onload_zc_mmsg2str(msgs, in->mlen), in->mlen,
             send_recv_flags_rpc2h(in->flags), in->add_sock);

        if (out->retval > 0)
        {
            for (j = 0; j < (unsigned)in->mlen; j++)
            {
                if (msgs[j].rc >= 0)
                    out->zc_rc.zc_rc_val[j] = msgs[j].rc;
                else
                    out->zc_rc.zc_rc_val[j] = -errno_h2rpc(-msgs[j].rc);
            }

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
            res = zc_mmsg_data_proc_completions(mmsg_data, out->retval,
                                                compl_queue);
            if (res < 0)
            {
                out->retval = -1;
                goto finish;
            }
#endif
        }
    }

finish:

    for (j = 0; j < in->msgs.msgs_len; j++)
    {
        res = zc_mmsg_data_free(&mmsg_data[j]);
        if (res < 0)
            out->retval = -1;

        rpcs_msghdr_helper_clean(&helpers[j], &msgs[j].msg.msghdr);
    }

    free(msgs);
    free(helpers);
    free(mmsg_data);
}
)

/*----------------- onload_msg_template_alloc() --------------------------*/

static int
te_onload_msg_template_flags_rpc2h(int rpc_flags)
{
    int flags = 0;

#define TEMPLATE_FLAGS_RPC2H(_flag) \
    if ((rpc_flags & TARPC_##_flag) == TARPC_##_flag)  \
        flags |= _flag;

    TEMPLATE_FLAGS_RPC2H(ONLOAD_TEMPLATE_FLAGS_SEND_NOW)
    TEMPLATE_FLAGS_RPC2H(ONLOAD_TEMPLATE_FLAGS_PIO_RETRY)
    TEMPLATE_FLAGS_RPC2H(ONLOAD_TEMPLATE_FLAGS_DONTWAIT)

#undef TEMPLATE_FLAGS_RPC2H

    return flags;
}

int
onload_msg_template_alloc(int fd, const struct iovec *iov, int iovcnt,
                          onload_template_handle *handle, unsigned flags)
{
    api_func func_alloc;

    RESOLVE_ACC_FUNC(func_alloc, onload_msg_template_alloc);
    if (func_alloc == NULL)
        return -1;

    return func_alloc(fd, iov, iovcnt, handle, flags);
}

#define IOVEC_RPC2H(_vector, _iov, _ptr) \
do {                                                                    \
    size_t i;                                                           \
    memset(_iov, 0, sizeof(_iov));                                      \
    for (i = 0; i < _vector.vector_len; i++)                            \
    {                                                                   \
        INIT_CHECKED_ARG(_vector.vector_val[i].iov_base.iov_base_val,   \
                         _vector.vector_val[i].iov_base.iov_base_len,   \
                         _vector.vector_val[i].iov_len);                \
        _iov[i].iov_base = _vector.vector_val[i].iov_base.iov_base_val; \
        _iov[i].iov_len = _vector.vector_val[i].iov_len;                \
    }                                                                   \
    _ptr = _vector.vector_len > 0 ? _iov : NULL;                        \
} while (0)

TARPC_FUNC(onload_msg_template_alloc, {},
{
    struct iovec            container[RCF_RPC_MAX_IOVEC];
    struct iovec           *iov;
    onload_template_handle *handle;
    onload_template_handle  handle_loc;

    if (in->handle == 0)
        handle = NULL;
    else
    {
        if (in->handle != (uint32_t)-1)
            handle_loc =
                (onload_template_handle)rcf_pch_mem_get(in->handle);
        handle = &handle_loc;
    }

    IOVEC_RPC2H(in->vector, container, iov);

    MAKE_CALL(out->retval =
        onload_msg_template_alloc(in->fd, iov, in->iovcnt, handle,
                            te_onload_msg_template_flags_rpc2h(in->flags)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    if (out->retval == 0 && handle != NULL)
        out->handle = rcf_pch_mem_alloc(*handle);
}
)

/*----------------- onload_msg_template_abort() --------------------------*/

int
onload_msg_template_abort(int fd, onload_template_handle handle)
{
    api_func        func_abort;

    RESOLVE_ACC_FUNC(func_abort, onload_msg_template_abort);
    if (func_abort == NULL)
        return -1;

    return func_abort(fd, handle);
}

TARPC_FUNC(onload_msg_template_abort, {},
{
    onload_template_handle handle =
        (onload_template_handle)rcf_pch_mem_get(in->handle);

    MAKE_CALL(out->retval = onload_msg_template_abort(in->fd, handle));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    rcf_pch_mem_free(in->handle);
}
)

/*------------------- onload_msg_template_update() -----------------------*/

int
onload_msg_template_update(int fd, onload_template_handle handle,
                    const struct onload_template_msg_update_iovec *updates,
                    int iovcnt, unsigned flags)
{
    api_func        func_update;
    int             rc;

    RESOLVE_ACC_FUNC(func_update, onload_msg_template_update);
    if (func_update == NULL)
        return -1;

    rc = func_update(fd, handle, updates, iovcnt, flags);

    return rc;
}

TARPC_FUNC(onload_msg_template_update, {},
{
    struct onload_template_msg_update_iovec updates[RCF_RPC_MAX_IOVEC];
    onload_template_handle handle =
        (onload_template_handle)rcf_pch_mem_get(in->handle);
    size_t  i;

    for (i = 0; i < in->updates.updates_len; i++)
    {
        INIT_CHECKED_ARG(in->updates.updates_val[i].otmu_base.otmu_base_val,
                         in->updates.updates_val[i].otmu_base.otmu_base_len,
                         in->updates.updates_val[i].otmu_len);

        updates[i].otmu_base =
            in->updates.updates_val[i].otmu_base.otmu_base_val;
        updates[i].otmu_len = in->updates.updates_val[i].otmu_len;
        updates[i].otmu_offset = in->updates.updates_val[i].otmu_offset;
        updates[i].otmu_flags = in->updates.updates_val[i].otmu_flags;
    }

    MAKE_CALL(out->retval =
        onload_msg_template_update(in->fd, handle,
                                   in->updates.updates_len > 0 ? updates :
                                                                 NULL,
                                   in->iovcnt,
                                   te_onload_msg_template_flags_rpc2h(in->flags)));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
}
)

/*--------------------------- template_send() ----------------------------*/
/**
 * Allocate and send onload templates
 */
int
template_send(int fd, struct iovec *iov, size_t iovcnt, int flags)
{
    onload_template_handle  handle;
    int rc;

    rc = onload_msg_template_alloc(fd, iov, iovcnt, &handle, flags);
    if (rc < 0)
    {
        ERROR("Unexpected return code from onload_msg_template_alloc %d",
              rc);
        errno = -rc;
        return -1;
    }

    rc = onload_msg_template_update(fd, handle, NULL, 0,
                                    ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
    if (rc < 0)
    {
        errno = -rc;
        return -1;
    }

    if (rc != 0)
    {
        ERROR("Unexpected return code from onload_msg_template_update %d",
              rc);
        return TE_EFAIL;
    }

    return rc;
}

TARPC_FUNC(template_send, {},
{
    struct iovec    container[RCF_RPC_MAX_IOVEC];
    struct iovec   *iov;

    IOVEC_RPC2H(in->vector, container, iov);

    MAKE_CALL(out->retval = func(in->fd, iov, in->iovcnt,
                            te_onload_msg_template_flags_rpc2h(in->flags)));

    if (out->retval == 0)
    {
        size_t i;

        for (i = 0; i < in->vector.vector_len; i++)
            out->retval += in->vector.vector_val[i].iov_len;
    }
}
)

/*------------ popen_flooder() -----------------------*/

/**
 * Flag to start popen flooders on all threads
 */
static te_bool popen_flooder_toggle_en = FALSE;

/**
 * Argument to be passed to a thread @b popen_flooder_thread() during
 * popen flooder work.
 */
typedef struct popen_flooder_thread_arg_t {
    int num;
    int enabled;
} popen_flooder_thread_arg_t;

/**
 * Function for a test thread which is used in popen flooder.
 * 
 * @param   Opaque argument should have type @b popen_flooder_thread_arg_t
 */
static void *
popen_flooder_thread(void *arg)
{
    int     i;
    char    buf[128];
    FILE   *f;

    for (i = 0; i < ((popen_flooder_thread_arg_t *)arg)->num; i++)
    {
        if ((f = popen("pwd", "r")) == NULL)
        {
            ERROR("iteration %d, popen() failed: %s", i, strerror(errno));
            return NULL;
        }

        if (fread(buf, 128, 1, f) == 0 && errno != ECHILD && errno != EINTR
            && errno != 0)
        {
            ERROR("iteration %d, fread() failed: %s", i, strerror(errno));
            pclose(f);
            return NULL;
        }

        if (pclose(f) != 0 && errno != ECHILD && errno != 0)
        {
            ERROR("iteration %d, pclose() failed: %s", i, strerror(errno));
            return NULL;
        }
    }

    ((popen_flooder_thread_arg_t *)arg)->enabled = 0;

    return NULL;
}

/**
 * Actually here is logic of a sapi-ts test @b basic/popen_multithread_flood
 * 
 * @param threads_num   Maximum number of parallel threads
 * @param iterations    Summary number of threads to be launced
 * @param popen_iter    Iterations number of internal loop of a thread
 * @param sync          @c TRUE to start flooder
 *                      when @b rpc_popen_flooder_toggle() enables it
 *
 * @par Scenario:
 * -# Start threads repeatedly in a genral loop.
 * -# Maximum number of parallel threads is @a threads.
 * -# Each thread make a sequence of calls popen()-fread()-pclose()
 *    in loop. The loop has random length from @c 0 to (@p popen_iter - 1)
 *    iterations.
 * -# When a thread is finished, it is restarted.
 * -# Test works until number @p iterations of threads is launched.
 * 
 * @return Number of started threads or @c -1 in case of failure
 */
int
popen_flooder(int threads_num, int iterations, int popen_iter,
              te_bool sync_popen)
{
    popen_flooder_thread_arg_t *thrd_arg;

    int         errno_b     = errno;
    int         rc          = 0;
    int         counter     = 0;
    pthread_t  *threads;
    int         thrd_iter;
    int         percent = 0;

    ta_log_lock_key key;

    srand(time(NULL));

    threads = calloc(threads_num, sizeof(*threads));
    thrd_arg = calloc(threads_num, sizeof(*thrd_arg));

    memset(threads, 0, threads_num * sizeof(*threads));
    memset(thrd_arg, 0, threads_num * sizeof(*thrd_arg));

    while (sync_popen && !popen_flooder_toggle_en)
        usleep(1000);

    if (ta_log_lock(&key) != 0)
        ERROR("Coouldn't lock logger");

    while(counter < iterations &&
          ((sync_popen && popen_flooder_toggle_en) || !sync_popen))
    {
        for (thrd_iter = 0; thrd_iter < threads_num; thrd_iter++)
        {
            if (thrd_arg[thrd_iter].enabled != 0)
                continue;

            if (threads[thrd_iter] != 0)
            {
                rc = pthread_join(threads[thrd_iter], NULL);
                if (rc != 0 && errno != 0)
                {
                    ERROR("Failed to join thread #%d: %s", thrd_iter,
                          strerror(errno));
                    rc = -1;
                    goto popen_flooder_cleanup;
                }
                threads[thrd_iter] = 0;
            }

            counter++;
            thrd_arg[thrd_iter].num = rand() % popen_iter;
            thrd_arg[thrd_iter].enabled = 1;
            rc = pthread_create(threads + thrd_iter, NULL,
                                popen_flooder_thread, thrd_arg + thrd_iter);
            if (rc != 0)
            {
                ERROR("Failed to create thread #%d: %s", thrd_iter,
                      strerror(errno));
                rc = -1;
                goto popen_flooder_cleanup;
            }
        }
        usleep(100);

        if (counter * 100 / iterations > percent)
        {
            percent = counter * 100 / iterations;
            if (percent % 10 == 0)
                RING("popen flooder is finished over %d%%", percent);
        }
    }

    rc = counter;
    errno = errno_b;

popen_flooder_cleanup:
    for (thrd_iter = 0; thrd_iter < threads_num; thrd_iter++)
    {
        rc = pthread_join(threads[thrd_iter], NULL);
        if (rc != 0 && errno != 0)
            ERROR("Failed to join thread #%d: %s", rc, strerror(errno));
    }

    free(threads);
    free(thrd_arg);

    ta_log_unlock(&key);

    return rc;
}

TARPC_FUNC(popen_flooder, {}, 
{
    MAKE_CALL(out->retval = func(in->threads, in->iterations,
                                 in->popen_iter, in->sync));
}
)

void
popen_flooder_toggle(te_bool enable)
{
    popen_flooder_toggle_en = enable;
}

TARPC_FUNC(popen_flooder_toggle, {},
{
    MAKE_CALL(func(in->enable));
}
)

/*-------------- onload_ordered_epoll_wait() --------------------------------*/

TARPC_FUNC(onload_ordered_epoll_wait,
{
    COPY_ARG(events);
    COPY_ARG(oo_events);
},
{
    struct epoll_event *events = NULL;
    struct onload_ordered_epoll_event *oo_events = NULL;
    int len = out->events.events_len;
    int oo_len = out->oo_events.oo_events_len;
    int i;

    if (len)
        events = calloc(len, sizeof(struct epoll_event));
    if (oo_len > 0)
        oo_events = calloc(oo_len,
                           sizeof(struct onload_ordered_epoll_event));

    MAKE_CALL(out->retval = func(in->epfd, events,
                                 oo_events, in->maxevents, in->timeout));
    if (out->retval < -1)
    {
        /*
         * This function may return -1 and set errno and also may return
         * -error. See ON-12826.
         */
        TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);
    }

    for (i = 0; i < (int)out->events.events_len && i < out->retval; i++)
    {
        out->oo_events.oo_events_val[i].bytes = oo_events[i].bytes;
        out->oo_events.oo_events_val[i].ts.tv_sec = oo_events[i].ts.tv_sec;
        out->oo_events.oo_events_val[i].ts.tv_nsec =
            oo_events[i].ts.tv_nsec;

        out->events.events_val[i].events =
            epoll_event_h2rpc(events[i].events);
        out->events.events_val[i].data.type = TARPC_ED_INT;
        out->events.events_val[i].data.tarpc_epoll_data_u.fd =
            events[i].data.fd;
    }
    free(events);
    free(oo_events);
}
)

/*------------------------- od_raw_send() --------------------------------*/

/**
 * Find index of interface by link local address.
 *
 * @param ll_addr  Link local address
 *
 * @return Index of interface or @c -1
 */
static int
find_ifindex_by_ll_addr(const unsigned char *ll_addr)
{
    struct ifaddrs        *ifaddr_list;
    struct ifaddrs        *ifa_cur;
    struct sockaddr_ll    *addr_cur;
    int                    ifindex = -1;

    if (getifaddrs(&ifaddr_list) == -1)
        return -1;

    for (ifa_cur = ifaddr_list; ifa_cur != NULL; ifa_cur = ifa_cur->ifa_next)
    {
        if (ifa_cur->ifa_addr == NULL)
            continue;

        if (ifa_cur->ifa_addr->sa_family != AF_PACKET)
            continue;

        addr_cur = (struct sockaddr_ll *)ifa_cur->ifa_addr;

        if (memcmp(addr_cur->sll_addr, ll_addr, ETH_ALEN) == 0)
        {
            ifindex = addr_cur->sll_ifindex;
            break;
        }
    }

    freeifaddrs(ifaddr_list);

    return ifindex;
}

/**
 * Send a raw TCPv4 packet with full ethernet header.
 *
 * @param raw_packet  Raw packet to send
 * @param packet_len  Size of packet
 * @param raw_socket  Raw socket for sending data
 * @param ifindex     Pointer to interface index
 *
 * @return @c 0 on success or @c -1 on failure.
 */
static int
od_raw_send(uint8_t *raw_packet, ssize_t packet_len, int raw_socket,
            int *ifindex)
{
    struct ethhdr          *ethh;
    struct sockaddr_ll      sadr_ll;
    ssize_t                 sent;
    int                     rc = 0;

    api_func                sendto_f;

    if ((rc = tarpc_find_func(TARPC_LIB_DEFAULT, "sendto", &sendto_f)) != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "failed to resolve \"sendto\" function");
        return -1;
    }

    rc = te_ipstack_prepare_raw_tcpv4_packet(raw_packet, &packet_len,
                                             TRUE, &sadr_ll);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                         "failed to prepare packet for raw sending");
        return -1;
    }

    /* Prepare destination address */
    ethh = (struct ethhdr *)raw_packet;
    if (*ifindex == -1)
        *ifindex = find_ifindex_by_ll_addr(ethh->h_source);

    sadr_ll.sll_ifindex = *ifindex;

    /* Send prepared raw packet */
    sent = sendto_f(raw_socket, raw_packet, packet_len, 0,
                    CONST_SA(&sadr_ll), sizeof(sadr_ll));
    if (sent < 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno), "sendto() failed");
        rc = -1;
    }
    else if (sent != packet_len)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),"sendto() returns %d,"
                         " but expected return value is %d", sent, packet_len);
        rc = -1;
    }

    return rc;
}

/*------------------- onload_delegated_send_prepare() --------------------*/

#define ASSIGN_VAL(_field) out->_field = in->_field;
/**
 * Copy struct onload_delegated_send internals to RPC container.
 * 
 * @param in    onload_delegated_send structure
 * @param out   Outgoing RPC contained
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
}

/**
 * Copy RPC container data to struct onload_delegated_send.
 * 
 * @param in    Incoming RPC contained
 * @param out   onload_delegated_send structure
 */
static void
onload_delegated_send_rpc2h(tarpc_onload_delegated_send *in,
                            struct onload_delegated_send *out)
{
    ASSIGN_VAL(headers_len);
    ASSIGN_VAL(mss);
    ASSIGN_VAL(send_wnd);
    ASSIGN_VAL(cong_wnd);
    ASSIGN_VAL(user_size);
    ASSIGN_VAL(tcp_seq_offset);
    ASSIGN_VAL(ip_len_offset);
    ASSIGN_VAL(ip_tcp_hdr_len);
}
#undef ASSIGN_VAL

enum onload_delegated_send_rc
onload_delegated_send_prepare(int fd, int size, unsigned flags,
                              struct onload_delegated_send* out)
{
    api_func func;

    RESOLVE_ACC_FUNC(func, onload_delegated_send_prepare);
    if (func == NULL)
        return -1;

    return func(fd, size, flags, out);
}

TARPC_FUNC(onload_delegated_send_prepare,
{
    out->ods.headers.headers_len = in->ods.headers.headers_len;
    out->ods.headers.headers_val = in->ods.headers.headers_val;
    in->ods.headers.headers_len = 0;
    in->ods.headers.headers_val = NULL;
},
{
    struct onload_delegated_send ods;

    onload_delegated_send_rpc2h(&in->ods, &ods);
    ods.headers = out->ods.headers.headers_val;

    MAKE_CALL(out->retval =
        onload_delegated_send_prepare(in->fd, in->size, in->flags, &ods));
    TE_RPC_CONVERT_NEGATIVE_ERR(out->retval);

    onload_delegated_send_h2rpc(&ods, &out->ods);
}
)


/*----------------- onload_delegated_send_tcp_update() -------------------*/

#ifndef HAVE_IMPL_ONLOAD_DELEGATED_SEND_TCP_UPDATE
static void
onload_delegated_send_tcp_update(struct onload_delegated_send *ds,
                                 int bytes, int push)
{
    typeof(onload_delegated_send_tcp_update) *func;

    RESOLVE_ACC_FUNC(func, onload_delegated_send_tcp_update);
    if (func == NULL)
        return;

    func(ds, bytes, push);
}
#endif

TARPC_FUNC_STATIC(onload_delegated_send_tcp_update, {},
{
    struct onload_delegated_send ods;

    out->ods.headers.headers_len = in->ods.headers.headers_len;
    out->ods.headers.headers_val = in->ods.headers.headers_val;
    in->ods.headers.headers_len = 0;
    in->ods.headers.headers_val = NULL;

    onload_delegated_send_rpc2h(&in->ods, &ods);
    ods.headers = out->ods.headers.headers_val;

    MAKE_CALL(func(&ods, in->bytes, in->push));

    onload_delegated_send_h2rpc(&ods, &out->ods);
})

/*----------------- onload_delegated_send_tcp_advance() -------------------*/

#ifndef HAVE_IMPL_ONLOAD_DELEGATED_SEND_TCP_ADVANCE
static void
onload_delegated_send_tcp_advance(struct onload_delegated_send *ds,
                                  int bytes)
{
    typeof(onload_delegated_send_tcp_advance) *func;

    RESOLVE_ACC_FUNC(func, onload_delegated_send_tcp_advance);
    if (func == NULL)
        return;

    func(ds, bytes);
}
#endif

TARPC_FUNC_STATIC(onload_delegated_send_tcp_advance, {},
{
    struct onload_delegated_send ods;

    out->ods.headers.headers_len = in->ods.headers.headers_len;
    out->ods.headers.headers_val = in->ods.headers.headers_val;
    in->ods.headers.headers_len = 0;
    in->ods.headers.headers_val = NULL;

    onload_delegated_send_rpc2h(&in->ods, &ods);
    ods.headers = out->ods.headers.headers_val;

    MAKE_CALL(func(&ods, in->bytes));

    onload_delegated_send_h2rpc(&ods, &out->ods);
})

/*------------------- onload_delegated_send_complete() -------------------*/

int
onload_delegated_send_complete(int fd, const struct iovec* iov, int iovlen,
                               int flags)
{
    api_func func;

    RESOLVE_ACC_FUNC(func, onload_delegated_send_complete);
    if (func == NULL)
        return -1;

    return func(fd, iov, iovlen, flags);
}

TARPC_FUNC(onload_delegated_send_complete, {},
{
    struct iovec container[RCF_RPC_MAX_IOVEC];
    struct iovec *iov;

    IOVEC_RPC2H(in->vector, container, iov);
    MAKE_CALL(out->retval =
        onload_delegated_send_complete(in->fd, iov, in->iovlen,
                                       send_recv_flags_rpc2h(in->flags)));
}
)

/*------------------- onload_delegated_send_cancel() ---------------------*/

int
onload_delegated_send_cancel(int fd)
{
    api_func func;

    RESOLVE_ACC_FUNC(func, onload_delegated_send_cancel);
    if (func == NULL)
        return -1;

    return func(fd);
}

TARPC_FUNC(onload_delegated_send_cancel, {},
{
    MAKE_CALL(out->retval = onload_delegated_send_cancel(in->fd));
}
)

/*------------------------------ od_send() -------------------------------*/

/**
 * Call sendmsg() function.
 *
 * @param fd          File descriptor
 * @param iov         Array of iovec structures
 * @param iov_len     Number of elements in the array
 * @param flags       Flags
 *
 * @return The sendmsg() call result.
 */
static int
od_fallback_sendmsg(int fd, struct iovec *iov, size_t iov_len, int flags)
{
    api_func sendmsg_f;
    te_errno rc;
    struct msghdr msg;

    rc = tarpc_find_func(TARPC_LIB_DEFAULT, "sendmsg",
                         (api_func *)&sendmsg_f);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "failed to find sendmsg()");
        return -1;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = iov_len;

    return sendmsg_f(fd, &msg, flags);
}

int
od_send(int fd, struct iovec *iov, size_t iov_len, int flags,
        te_bool raw_send)
{
    struct onload_delegated_send ods;
    uint8_t                      headers[OD_HEADERS_LEN];
    uint8_t                     *raw_packet = NULL;
    ssize_t                      raw_packet_len;
    api_func                     socket_f;
    size_t                       sent = 0;
    int                          raw_socket = -1;
    int                          ifindex = -1;
    int                          res;
    int                          rc;

    int len = 0;
    size_t sent_len;
    int i;

    memset(&ods, 0, sizeof(ods));
    ods.headers_len = sizeof(headers);
    ods.headers = headers;

    for (i = 0; i < iov_len; i++)
        len += iov[i].iov_len;

    rc = onload_delegated_send_prepare(fd, len, 0, &ods);
#ifdef HAVE_DECL_ONLOAD_DELEGATED_SEND_RC_NOCWIN
    /* Supported from the Onload branch eol6 */
    if (rc == ONLOAD_DELEGATED_SEND_RC_NOCWIN)
    {
        RING("onload_delegated_send_prepare() ONLOAD_DELEGATED_SEND_RC_NOCWIN, "
             "ignoring this error");
    }
    else
#endif
    if (rc != ONLOAD_DELEGATED_SEND_RC_OK)
    {
        WARN("onload_delegated_send_prepare() returned %d (%s) error, "
             "send_wnd=%d cong_wnd=%d, fall back to sendmsg()",
             rc, ods_prepare_err2string(rc), ods.send_wnd, ods.cong_wnd);

        return od_fallback_sendmsg(fd, iov, iov_len, flags);
    }
    else if ((ods.send_wnd < len || ods.cong_wnd < len) && raw_send)
    {
        WARN("onload_delegated_send_prepare() succeeded but returned "
             "send_wnd=%d cong_wnd=%d while requested length is %d, "
             "part of data will not be actually sent",
             ods.send_wnd, ods.cong_wnd, len);
    }

    if (raw_send)
    {
        if ((rc = tarpc_find_func(TARPC_LIB_DEFAULT, "socket", &socket_f))
            != 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "failed to resolve \"socket\" function");
            return -1;
        }

        raw_socket = socket_f(PF_PACKET, SOCK_RAW, IPPROTO_RAW);

        if (raw_socket < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "failed to create raw_socket");
            return -1;
        }
    }

    i = 0;
    sent = 0;
    sent_len = 0;
    while (raw_send && i < iov_len)
    {
        if (iov[i].iov_len <= sent || iov[i].iov_base == NULL)
        {
            i++;
            sent = 0;
            continue;
        }

        sent_len = MIN(od_get_min(&ods), iov[i].iov_len - sent);
        if (sent_len == 0)
            break;

        onload_delegated_send_tcp_update(&ods, sent_len, 1);

        raw_packet_len = ods.headers_len + sent_len;
        raw_packet = TE_ALLOC(raw_packet_len);
        if (raw_packet == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "not enough memory for packet buffer");
            return -1;
        }

        memcpy(raw_packet, ods.headers, ods.headers_len);
        memcpy(raw_packet + ods.headers_len,
               iov[i].iov_base + sent, sent_len);

        res = od_raw_send(raw_packet, raw_packet_len, raw_socket,
                          &ifindex);
        free(raw_packet);

        if (res != 0)
        {
            onload_delegated_send_cancel(fd);
            close(raw_socket);
            return -1;
        }

        onload_delegated_send_tcp_advance(&ods, sent_len);

        sent += sent_len;
    }

    if (raw_send)
        close(raw_socket);

    if ((res = onload_delegated_send_complete(fd, iov, iov_len,
                                              flags)) < 0)
    {
        te_rpc_error_set(RPC_ERRNO,
                         "onload_delegated_send_complete() failed");
        return -1;
    }
    if (res == 0)
    {
        /* See bug 75216 for details. */
        te_rpc_error_set(TE_RC(TE_RPC, TE_EAGAIN),
                         "onload_delegated_send_complete returned 0, "
                         "converting it to -1(EAGAIN)");
        return -1;
    }

    if (res < (int)len)
    {
        RING("Data was not sent completely with OD send API, "
             "onload_delegated_send_cancel() is called.");
        if ((rc = onload_delegated_send_cancel(fd)) != 0)
        {
            te_rpc_error_set(RPC_ERRNO,
                            "onload_delegated_send_cancel() failed ");
            return -1;
        }
    }

    return res;
}

TARPC_FUNC(od_send, {},
{
    struct iovec *iov;

    iov = TE_ALLOC(in->iov.iov_len * sizeof(*iov));
    if (iov == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "not enough memory for iovec array");
        out->retval = -1;
        return;
    }

    rpcs_iovec_tarpc2h(in->iov.iov_val, iov, in->iov.iov_len, FALSE,
                       arglist);
    MAKE_CALL(out->retval = od_send(in->fd, iov, in->iov_len,
                                    send_recv_flags_rpc2h(in->flags),
                                    in->raw_send));
    free(iov);
}
)

/*--------------nb_receiver() --------------------------*/

#define MAX_PKT (1024)

#define TA_NB_RECEIVER_START    TRUE
#define TA_NB_RECEIVER_STOP     FALSE

/**
 * Non-Block receiver start.
 *
 * @param in                input RPC argument
 *
 * @return number of received bytes or -1 in the case of failure
 */
int
nb_receiver_start(tarpc_nb_receiver_start_in *in)
{
    int             errno_save = errno;
#ifdef __unix__
    api_func        recv_func;
#endif
    char           *buf;
    int             rc;

    int            *running = (int *)rcf_pch_mem_get(in->handle);

#ifdef __unix__
    if (tarpc_find_func(in->common.lib_flags, "recv", &recv_func) != 0)
    {
        ERROR("Cannot find recv() routine handler");
        return -1;
    }
#endif    
    if ((buf = malloc(MAX_PKT)) == NULL)
    {
        ERROR("Out of memory");
        return -1;
    }

    if (running == NULL)
    {
        ERROR("Invalid pointer for receiver control field");
        errno = EINVAL;
        return -1;
    }

    *running = TA_NB_RECEIVER_START;

    RING("Start nonblocking receiveing");

    while (*running == TA_NB_RECEIVER_START)
    {
        rc = recv_func(in->s, buf, MAX_PKT, MSG_DONTWAIT);
        if (rc >= 0)
        {
            ERROR("recv() received some data (%d bytes) on empty socket",
                  rc);
            free(buf);
            return -1;
        } 
        if (errno != EAGAIN)
        {
            ERROR("recv() on empty socket did not returned EAGAIN, errno=%d",
                  errno);
            free(buf);
            return -1;
        }
    }

    RING("Stop nonblocking receiving");
    
    free(buf);

    errno = errno_save;
    return 0;
}


TARPC_FUNC(nb_receiver_start, {},
{
    MAKE_CALL(out->retval = func_ptr(in));
}
)

#undef MAX_PKT

/**
 * Non-Block receiver stop.
 *
 * @param in                input RPC argument
 *
 * @return number of received bytes or -1 in the case of failure
 */   
int
nb_receiver_stop(tarpc_nb_receiver_stop_in *in,
                 tarpc_nb_receiver_stop_out *out)
{
    int            *running = (int *)rcf_pch_mem_get(in->handle);

    UNUSED(out);

    *running = TA_NB_RECEIVER_STOP;

    return 0;
}


TARPC_FUNC(nb_receiver_stop, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
}
)

int
onload_hw_filters_limit(struct sockaddr *addr, socklen_t addr_len)
{
    struct onload_stat st;
    te_bool  fail = TRUE;
    int      rc;
    int     *s;
    int     *tmp;
    int      i;
    int      len = 5000;
    int      unacc = 0;
    int      num = 0;

    s = calloc(len, sizeof(*s));
    memset(s, -1, len * sizeof(*s));

    for (i = 0; TRUE; i++)
    {
        if (i == len)
        {
            tmp = realloc(s, len * sizeof(*s) * 2);
            if (tmp == NULL)
            {
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                 "out of memory");
                break;
            }
            s = tmp;
            memset(s + len, -1, len * sizeof(*s));
            len *= 2;
        }

        s[i] = socket(addr->sa_family, SOCK_DGRAM, 0);
        if (s[i] < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "failed to create a socket");
            ERROR("Failed to create socket %d: %s", i + 1, strerror(errno));
            break;
        }

        te_sockaddr_set_port(addr, 0);
        if ((rc = bind(s[i], addr, addr_len)) < 0)
        {
            /**
             * When a few HW filters are left, failures of allocatation HW
             * filters can be observed.
             * Matthew Slattery:
             * The filters are being placed in a hash table; the match
             * criteria hashes to two values, H1 and H2, and the probe
             * locations in the table are H1+k*H2 for
             * k=0,1,2,...,<max_hops-1>, where max_hops=200 in production
             * builds. If we don't find an empty space within max_hops
             * probes, the filter cannot be inserted, even if there are
             * some empty slots left in the table. 
             */
            if (RPC_ERRNO != RPC_EBUSY)
            {
                te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                                 "failed to bind a socket");
                ERROR("Failed to bind socket %d: %s", i + 1,
                      strerror(errno));
                break;
            }
        }
        else if ((rc = onload_fd_stat(s[i], &st)) < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -rc),
                             "onload_fd_stat() failed");
            break;
        }

        /* Socket is not accelerated or bind failed. */
        if (rc <= 0)
        {
            unacc++;
            if (unacc > 50)
            {
                fail = FALSE;
                break;
            }
        }
        else
        {
            num++;
            unacc = 0;
        }
    }

    for (; i >= 0; i--)
    {
        if (s[i] >= 0)
            close(s[i]);
    }

    free(s);

    return fail ? -1 : num;
}

TARPC_FUNC(onload_hw_filters_limit, {}, 
{
    struct sockaddr_storage  bind_addr_l;
    struct sockaddr         *addr;
    socklen_t                addrlen;

    sockaddr_rpc2h(&(in->addr),
                   SA(&bind_addr_l), sizeof(bind_addr_l),
                   &addr, &addrlen);

    MAKE_CALL(out->retval = func_ptr(addr, addrlen));
}
)

/** 
 * Create, bind and connect @p sock_num sockets.
 *
 * @param lib_flags             how to resolve function name
 * @param do_bind               bind socket before connect
 * @param bind_addr             address to bind
 * @param bind_addr_len         length of @p bind_addr
 * @param connect_addr          address to connect
 * @param connect_addr_len      length of @ connect_addr
 * @param sock_type             socket type
 * @param do_listen             call listen() instead of connect()
 * @param sock_num              number of sockets to create
 * @param acc_num               accelerated sockets number
 * @param err_num               fails number
 * @param sock1                 location for descriptor of the first
 *                              created socket
 * @param sock2                 location for the last created socket
 *
 * @return Opened connections number.
 *
 * @note It is assumed that RPC server is started so that it uses
 *       L5 functions by default.
 */
int
out_of_hw_filters_do(tarpc_lib_flags lib_flags, te_bool do_bind,
                     struct sockaddr *bind_addr, socklen_t bind_addr_len,
                     struct sockaddr *connect_addr,
                     socklen_t connect_addr_len, int sock_type, int action,
                     int sock_num, int *acc_num, int *err_num, int *sock1,
                     int *sock2)
{
#define SOCK_FORMAT   "#%d (fd=%d)"
#define SOCK_ARGS     i + 1, s

    struct onload_stat st;
    struct sockaddr    addr;
    socklen_t          len = sizeof(addr);

    api_func socket_f;
    api_func bind_f;
    api_func connect_f;
    api_func listen_f;
    api_func ioctl_f;
    api_func recvfrom_f;
    te_errno rc;

    int      i;
    int      num = 0;
    uint8_t  buf[1];
    int      val = 1;
    int      errno_b = errno;
    int      s;
    int      unacc = 0;
    int      fails = 0;
    int      finish = 0;
    int      res = 0;

    const char *func_name = NULL;

    if (tarpc_find_func(lib_flags, "socket", &socket_f) != 0 ||
        tarpc_find_func(lib_flags, "bind", &bind_f) != 0 ||
        tarpc_find_func(lib_flags, "listen", &listen_f) != 0 ||
        tarpc_find_func(lib_flags, "ioctl", &ioctl_f) != 0 ||
        tarpc_find_func(lib_flags, "recvfrom", &recvfrom_f) != 0 ||
        tarpc_find_func(lib_flags, "connect", &connect_f) != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve a function");
        return -1;
    }

    if (action == TARPC_OOR_LISTEN && sock_type == SOCK_DGRAM)
    {
        te_rpc_error_set(
              TE_RC(TE_TA_UNIX, TE_EINVAL),
              "Wrong parameters, listen() cannot be used with UDP");
        return -1;
    }

    for (i = 0; i - fails - unacc < sock_num && finish < 50; i++)
    {
        if ((s = socket_f(connect_addr->sa_family, sock_type, 0)) < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "Failed to create a socket");
            ERROR("Failed to create #%d socket", i + 1);
            return -1;
        }

        if (i % 256 == 0)
            INFO("Socket " SOCK_FORMAT " is created", SOCK_ARGS);

        if (do_bind)
        {
            te_sockaddr_set_port(bind_addr, 0);
            if ((rc = bind_f(s, bind_addr, bind_addr_len)) < 0)
            {
                if (RPC_ERRNO == RPC_EBUSY || RPC_ERRNO == RPC_ENOBUFS)
                {
                    fails++;
                    finish++;
                    RING("bind() failed on socket " SOCK_FORMAT " with EBUSY",
                         SOCK_ARGS);
                    continue;
                }

                te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                                 "Failed to bind a socket");
                ERROR("Failed to bind socket " SOCK_FORMAT ": %r",
                      SOCK_ARGS, RPC_ERRNO);
                return -1;
            }
        }

        rc = 0;
        func_name = NULL;
        switch (action)
        {
            case TARPC_OOR_LISTEN:
                rc = listen_f(s, 1);
                func_name = "listen";
                break;

            case TARPC_OOR_CONNECT:
                rc = connect_f(s, connect_addr, connect_addr_len);
                func_name = "connect";
                break;

            case TARPC_OOR_RECVFROM:
                if (ioctl_f(s, FIONBIO, &val) < 0)
                {
                    te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                                     "Failed to set socket to non-blocking "
                                     "mode");
                    ERROR("Failed to set socket " SOCK_FORMAT " to "
                          "non-blocking mode: %r",
                          SOCK_ARGS, RPC_ERRNO);
                    return -1;
                }

                if (recvfrom_f(s, buf, sizeof(buf), 0, &addr, &len) != -1)
                {
                    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                                     "recvfrom() unexpectedly succeeded");
                    ERROR("recvfrom() unexpectedly succeeded "
                          "for socket " SOCK_FORMAT, SOCK_ARGS);
                    return -1;
                }

                if (RPC_ERRNO != RPC_EAGAIN)
                {
                    te_rpc_error_set(
                             TE_OS_RC(TE_TA_UNIX, errno),
                             "recvfrom() failed with unexpected errno");
                    ERROR("recvfrom() failed with unexpected errno %r "
                          "for socket " SOCK_FORMAT, RPC_ERRNO, SOCK_ARGS);
                    return -1;
                }
                break;

            case TARPC_OOR_BIND:
                break;

            default:
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                                 "Unknown action %d was requested", action);
                return -1;
        }

        if (rc < 0 || (res = onload_fd_stat(s, &st)) <= 0)
        {
            finish++;

            if (rc < 0)
            {
                if (RPC_ERRNO == RPC_EBUSY)
                {
                    RING("Action failed on socket " SOCK_FORMAT
                         " with EBUSY", SOCK_ARGS);
                    fails++;
                    continue;
                }

                te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                                 "%s() failed on a socket", func_name);
                ERROR("%s() failed on the socket " SOCK_FORMAT ": %r",
                      func_name, SOCK_ARGS, RPC_ERRNO);
                return -1;
            }

            if (res < 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -res),
                                 "onload_fd_stat() failed");

                ERROR("Failed to check if the socket " SOCK_FORMAT
                      " is accelerated or not: %r", SOCK_ARGS, RPC_ERRNO);
                return -1;
            }

            unacc++;
            RING("Socket " SOCK_FORMAT " is NOT accelerated", SOCK_ARGS);
        }
        else
        {
            /* Count number of the accelerated sockets. */
            num++;
            finish = 0;
        }

        if (i == 0)
            *sock1 = s;
        *sock2 = s;
    }

    *acc_num = num;
    *err_num = fails;
    errno = errno_b;

    return i;

#undef SOCK_FORMAT
#undef SOCK_ARGS
}

TARPC_FUNC(out_of_hw_filters_do, {}, 
{
    struct sockaddr_storage  bind_addr_l;
    struct sockaddr_storage  connect_addr_l;
    struct sockaddr         *bind_addr;
    struct sockaddr         *connect_addr;
    socklen_t                bind_addrlen;
    socklen_t                connect_addrlen;

    sockaddr_rpc2h(&(in->bind_addr),
                   SA(&bind_addr_l), sizeof(bind_addr_l),
                   &bind_addr, &bind_addrlen); 
    sockaddr_rpc2h(&(in->connect_addr),
                   SA(&connect_addr_l), sizeof(connect_addr_l),
                   &connect_addr, &connect_addrlen); 

    MAKE_CALL(out->retval = func(in->common.lib_flags, in->do_bind,
        bind_addr, bind_addrlen, connect_addr, connect_addrlen,
        socktype_rpc2h(in->type), in->action, in->sock_num, &out->acc_num,
        &out->err_num, &out->sock1, &out->sock2));
}
)

te_errno out_of_netifs_result = 0;

#ifndef HAVE_ENVIRON_DECLARED
/*
 * Some systems provide 'environ' variable, but they
 * do not export it directly via unistd.h
 * (for example on Solaris we do not have it defined in unistd.h)
 */
extern char **environ;
#endif

#define OONETIF_NON_ACCELERATED 0
#define OONETIF_ERR -1
#define OONETIF_FINISH -2

/**
 * Read sockets opening statuses transmitted from the child
 * 
 * @param fd    Pipe file descriptor
 * @param pid   The child pid
 * @param num   Total opened sockets number (out)
 * @param acc   Accelerated sockets number (out)
 * 
 * @return @c -1 in case of error, @c 0 - success
 */
static int
read_child_status(int fd, int pid, int *num,  int *acc)
{
    int32_t res = 0;
    int nonacc = 0;
    int rc;

    *num = 0;
    *acc = 0;

    while ((rc = read(fd, &res, sizeof(res)) > 0))
    {
        switch(res)
        {
            case OONETIF_ERR:
                ERROR("Child finished with an error");
                return -1;

            case OONETIF_FINISH:
                return 0;

            case OONETIF_NON_ACCELERATED:
                nonacc++;

                /* It's enough to understand that no accelerated sockets
                 * will be opened, so stop execution. */
                if (nonacc >= 10)
                {
                    (*num)++;
                    kill(pid, SIGINT);
                    return 0;
                }
                break;

            default:
                (*acc)++;
                nonacc = 0;
        }
        (*num)++;
    }

    ERROR("read() failed with errno %s", strerror(errno));
    return -1;
}

/** 
 * Start a new iteration of out_of_netifs test sequence.
 *
 * @param lib_flags     how to resolve function name
 * @param iter_num      number of iterations
 * @param iter          iteration to be started
 * @param sock_type     socket type
 * @param ret           if TRUE, function should return (not exit)
 * @param num           Successfully performed iterations number (out)
 * @param acc           Accelerated sockets number (out)
 *
 * @return Status code.
 */
static int
start_iteration(tarpc_lib_flags lib_flags, int iter_num, int iter,
                int sock_type, int pipe_wr, int *num, int *acc)
{
    char       *argv[9];
    char        param1[16];
    char        param2[16];
    char        param3[16];
    char        param4[16];
    char        param5[16];
    te_errno    rc;

    if (pipe_wr < 0)
    {
        int pipefd[2];
        int pid;

        if (num == NULL || acc == NULL)
        {
            ERROR("Bad function %s arguments num and acc must not be NULL",
                  __FUNCTION__);
        }

        if ((rc = pipe(pipefd)) != 0)
        {
            ERROR("pipe() failed with error %r", TE_OS_RC(TE_TA_UNIX, errno));
            return -1;
        }
        pipe_wr = pipefd[1];
        pid = fork();
        
        if (pid < 0)
        { 
            ERROR("fork() failed with error %r", TE_OS_RC(TE_TA_UNIX, errno));
            return pid;
        }

        if (pid > 0)
        {
            /* We are the parent. So, we just wait for the child. */
            close(pipefd[1]);
            return read_child_status(pipefd[0], pid, num, acc);
        }
        else
        {
            close(pipefd[0]);
        }
    }

    sprintf(param1, "%d", iter_num);
    sprintf(param2, "%d", iter);
    sprintf(param3, "%d", sock_type);
    sprintf(param4, "%d", pipe_wr);
    sprintf(param5, "%d", lib_flags);

    memset(argv, 0, sizeof(argv));
    argv[0] = (char *)ta_execname;
    argv[1] = "exec";
    argv[2] = "out_of_netifs";
    argv[3] = param1;
    argv[4] = param2;
    argv[5] = param3;
    argv[6] = param4;
    argv[7] = param5;

    if ((rc = execve(ta_execname, argv, environ)) < 0)
    {
        ERROR("execve() failed with error %s", strerror(errno));
        return rc;
    }

    return 0;
}

/** 
 * Entry point for the process used in out_of_netif test. 
 * Arguments are: <number of iterations> <iteration>
 *
 * When the test is finished or failure observed the new RPC server
 * is created which allows to get value of out_of_netifs_result.
 */
int
out_of_netifs(int argc, char *argv[])
{
    struct onload_stat st;
    int  iter;
    int  iter_num;
    int  s;
    int  sock_type;
    int  pipe_wr = -1;
    int  res = 0;
    int32_t write_rc;

    api_func socket_f;
    tarpc_lib_flags lib_flags;

#define FINISH(rc, msg...) \
    do {                                                     \
        write_rc = rc;                                       \
        if (rc == OONETIF_ERR)                               \
            ERROR(msg);                                      \
        if (write(pipe_wr, &write_rc, sizeof(write_rc)) < 0) \
            ERROR("Failed to write 'write_rc'");             \
        exit(EXIT_FAILURE);                                  \
    } while (0)

    if (argc != 5)
        FINISH(OONETIF_ERR, "Incorrect number of arguments are passed "
               "to out_of_netifs()");

    iter_num = atoi(argv[0]);
    iter = atoi(argv[1]);
    sock_type = atoi(argv[2]);
    pipe_wr = atoi(argv[3]);
    lib_flags = atoi(argv[4]);

    if (tarpc_find_func(lib_flags, "socket", &socket_f) != 0)
        FINISH(OONETIF_ERR, "Failed to resolve socket() function");

    if ((s = socket_f(AF_INET, sock_type, 0)) < 0)
    {
        if (RPC_ERRNO == RPC_EBUSY || RPC_ERRNO == RPC_ENOMEM)
            FINISH(OONETIF_FINISH, "");
        FINISH(OONETIF_ERR, "Failed to create socket: %r", RPC_ERRNO);
    }

    if ((res = onload_fd_stat(s, &st)) < 0)
        FINISH(OONETIF_ERR, "Failed to check if the socket is "
               "accelerated or not: %s", strerror(-res));

    write_rc = res;
    if (write(pipe_wr, &write_rc, sizeof(write_rc)) < 0)
        ERROR("Failed to write 'write_rc'");

    if (++iter == iter_num)
        FINISH(OONETIF_FINISH, "");

    start_iteration(lib_flags, iter_num, iter, sock_type, pipe_wr, NULL, NULL);

    return 0;
}

#undef OONETIF_NON_ACCELERATED
#undef OONETIF_ERR
#undef OONETIF_FINISH

TARPC_FUNC(out_of_netifs, {}, 
{
    MAKE_CALL(out->rc = start_iteration(in->common.lib_flags, in->sock_num, 0,
                                        socktype_rpc2h(in->sock_type),
                                        -1, &out->num, &out->acc));
}
)

/**
 * WARNING: function is blocking.
 * Function sets SO_RCVTIMEO option value to 1 second and then
 * restores it to default.
 */
static int
many_socket_send_and_recv(tarpc_lib_flags lib_flags, int s, int sock_num,
                          char* buf, int data_len, int send_count,
                          api_func recv_f, api_func send_f)
{
    int             i;
    int             err = errno;
    int             rc;
    int             retval = 0;
    api_func        setsockopt_f;
    api_func        getsockopt_f;
    struct timeval  tv = {.tv_sec = 1, .tv_usec = 0};
    struct timeval  tv_def = {0,0};
    socklen_t       tv_def_len = sizeof(tv_def);

    assert(send_count);

    if (tarpc_find_func(lib_flags, "setsockopt", &setsockopt_f) != 0)
    {
        ERROR("failed to resolve setsockopt() function");
        return -1;
    }
    if (tarpc_find_func(lib_flags, "getsockopt", &getsockopt_f) != 0)
    {
        ERROR("failed to resolve getsockopt() function");
        return -1;
    }

    /* Since @p s can be an accepted socket (and inherits SO_RCVTIMEO value
     * from a listening socket) lets get the default value of the option. */
    if (getsockopt_f(s, SOL_SOCKET, SO_RCVTIMEO, &tv_def, &tv_def_len) != 0)
        WARN("getsockopt() failed");

    for (i = 0; i < send_count; i++) {
        if (send_f(s, buf, data_len, 0) != data_len)
        {
            WARN("Failed to send %dth data packet on socket #%d",
                  i, sock_num);
            return -1;
        }
    }

    if (setsockopt_f(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
        WARN("setsockopt() failed");

    for (i = 0; i < send_count; ++i)
    {
        rc = recv_f(s, buf, data_len, 0);
        if (rc < 0 && RPC_ERRNO != RPC_EAGAIN)
        {
            WARN("Socket number %d recv() returned errno %r",
                 sock_num, RPC_ERRNO);
            retval = -1;
            break;
        }
        else if (rc == -1 && RPC_ERRNO == RPC_EAGAIN)
        {
            WARN("Socket number %d did not receive the "
                 "data packet", sock_num);
            retval = -1;
            break;
        }
        else if (rc != data_len)
        {
            WARN("Socket number %d: unexpected recv() length: "
                 "expected %d, got %d", sock_num, data_len, rc);
            retval = -1;
            break;
        }
        else
        {
            errno = err;
            retval = 0;
        }
    }

    if (setsockopt_f(s, SOL_SOCKET, SO_RCVTIMEO, &tv_def, tv_def_len) != 0)
        WARN("Restoring SO_RCVTIMEO to default failed");

    return retval;
}

/** 
 * Accept huge number of connections.
 *
 * @param lib_flags  How to resolve function name
 * @param l_s        Listening socket
 * @param sock_num   Number of connections to accept
 * @param data_len   Bytes to send
 * @param send_count Number of times to call send
 * @param sock1      Location for descriptor of the first accepted socket
 * @param sock2      Location for the last accepted socket
 * @param iteration  Last iteration number
 * @param handle     Location for pointer to array of accepted sockets.
 *
 * @return Status code.
 */
int
many_accept(tarpc_lib_flags lib_flags, int l_s, int sock_num,
            int data_len, int send_count, int *sock1, int *sock2,
            int *iteration, int **handle)
{
    api_func accept_f;
    api_func recv_f;
    api_func send_f;

    int i;
    int err = errno;
    int s;
    int eagain = 0;

    int *sockets = NULL;

    sockets = calloc(sock_num, sizeof(*sockets));
    memset(sockets, -1, sock_num * sizeof(*sockets));
    *handle = sockets;

    if (tarpc_find_func(lib_flags, "accept", &accept_f) != 0 ||
        tarpc_find_func(lib_flags, "recv", &recv_f) != 0 ||
        tarpc_find_func(lib_flags, "send", &send_f) != 0)
    {
        ERROR("Failed to resolve function");
        return -1;
    }

    for (i = 0; i < sock_num; i++)
    {
        *iteration = i;
        if ((s = accept_f(l_s, NULL, NULL)) < 0)
        {
            if (RPC_ERRNO == RPC_EAGAIN)
            {
                eagain++;
                if (eagain > 200)
                {
                    errno = err;
                    break;
                }

                usleep(10000);
                i--;
                continue;
            }

            /* accept() can fail if fd table is full. */
            if (RPC_ERRNO == RPC_EMFILE || RPC_ERRNO == RPC_ENOMEM)
            {
                RING("accept() failed with errno %r", RPC_ERRNO);
                errno = err;
                break;
            }

            WARN("accept() failed for socket #%d: %r", i + 1, s);
            return -1;
        }
        else
            eagain = 0;

        sockets[i] = s;

        *sock2 = s;
        if (i == 0)
            *sock1 = s;

        if (send_count != 0 )
        {
            char *buf;
            int rc;

            buf = calloc(1, data_len);
            rc = many_socket_send_and_recv(lib_flags, s, i + 1, buf, data_len,
                                           send_count, recv_f, send_f);
            free(buf);
            if (rc < 0)
              return rc;
        }
    }

    return i;
}

TARPC_FUNC(many_accept, {}, 
{
    int *handle = NULL;
    MAKE_CALL(out->retval = many_accept(in->common.lib_flags, in->s,
                                        in->sock_num, in->data_len,
                                        in->send_count,
                                        (int *)&out->sock1,
                                        (int *)&out->sock2,
                                        (int *)&out->iteration,
                                        &handle));
    out->handle = rcf_pch_mem_alloc(handle);
}
)

/** 
 * Create a lot of sockets and connect them
 *
 * @param lib_flags  How to resolve function name
 * @param addr       Address to connect
 * @param addr_lem   The address length
 * @param sock_num   Number of connections
 * @param data_len   Bytes to send
 * @param send_count Number of times to call send
 * @param sock1      Location for descriptor of the first socket
 * @param sock2      Location for the last socket
 * @param handle     Location for pointer to array of accepted sockets
 */
int
many_connect(tarpc_lib_flags lib_flags, struct sockaddr *addr,
             socklen_t addr_len, int sock_num, int data_len, int send_count,
             int *sock1, int *sock2, int **handle)
{
    api_func socket_f;
    api_func connect_f;
    api_func setsockopt_f;
    api_func recv_f;
    api_func send_f;

    int err = errno;
    int i;
    int s;

    int *sockets = NULL;

    if (tarpc_find_func(lib_flags, "socket", &socket_f) != 0 ||
        tarpc_find_func(lib_flags, "connect", &connect_f) != 0 ||
        tarpc_find_func(lib_flags, "setsockopt", &setsockopt_f) != 0 ||
        tarpc_find_func(lib_flags, "recv", &recv_f) != 0 ||
        tarpc_find_func(lib_flags, "send", &send_f) != 0)
    {
        ERROR("failed to resolve function");
        return -1;
    }

    sockets = calloc(sock_num, sizeof(*sockets));
    memset(sockets, -1, sock_num * sizeof(*sockets));
    *handle = sockets;

    for (i = 0; i < sock_num; i++)
    {
        if ((s = socket_f(addr->sa_family, SOCK_STREAM, 0)) < 0)
        {
            ERROR("socket() failed for socket #%d: %r", i + 1, RPC_ERRNO);
            return -1;
        }
        sockets[i] = s;
        if (i % 1024 == 0)
            RING("%s: socket[%d]=%d", __func__, i, s);

        if (send_count > 1)
        {
            int val = 1;
            /* Do not check the result - we do not really care */
            setsockopt(s, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        }

        if (connect_f(s, addr, addr_len) < 0)
        {
            /* connect() can fail if the peer fd table is full. */
            if (RPC_ERRNO == RPC_EAGAIN)
            {
                RING("connect() failed with errno EAGAIN");
                errno = err;
                break;
            }

            ERROR("Failed to connect socket #%d: %r", i + 1, RPC_ERRNO);
            return -1;
        }

        *sock2 = s;
        if (i == 0)
            *sock1 = s;

        if (send_count != 0)
        {
            char *buf;
            int rc;

            buf = calloc(1, data_len);
            rc = many_socket_send_and_recv(lib_flags, s, i + 1, buf, data_len,
                                           send_count, recv_f, send_f);
            free(buf);
            if (rc < 0)
              return rc;
        }
    }

    errno = err;
    return i;
}

TARPC_FUNC(many_connect, {}, 
{
    struct sockaddr_storage  addr_l;
    socklen_t                addrlen;
    struct sockaddr         *addr;
    int                     *handle = NULL;

    sockaddr_rpc2h(&(in->addr),
                   SA(&addr_l), sizeof(addr_l),
                   &addr, &addrlen);

    MAKE_CALL(out->retval = many_connect(in->common.lib_flags, addr,
                                         addrlen, in->sock_num,
                                         in->data_len, in->send_count,
                                         (int *)&out->sock1, 
                                         (int *)&out->sock2,
                                         &handle));
    out->handle = rcf_pch_mem_alloc(handle);
}
)

/** 
 * Created @p num sockets.
 *
 * @param lib_flags How to resolve function name
 * @param domain    Communication domain
 * @param sock_num  Sockets number
 * @param handle    Location for pointer to array of accepted sockets
 * 
 * @return Status code
 */
int
many_socket(tarpc_lib_flags lib_flags, int domain, int sock_num, int **handle)
{
    api_func socket_f;
    int i;
    int err = errno;

    int *sockets = NULL;

    if (tarpc_find_func(lib_flags, "socket", &socket_f) != 0)
    {
        ERROR("failed to resolve function");
        return -1;
    }

    sockets = calloc(sock_num, sizeof(*sockets));
    memset(sockets, -1, sock_num * sizeof(*sockets));
    *handle = sockets;

    for (i = 0; i < sock_num; i++)
    {
        if ((sockets[i] = socket_f(domain, SOCK_STREAM, 0)) < 0)
        {
            /* accept() can fail if fd table is full. */
            if (RPC_ERRNO == RPC_EMFILE)
            {
                errno = err;
                break;
            }

            ERROR("accept() failed for socket #%d: %r", i + 1, RPC_ERRNO);
            return -1;
        }
    }

    return i;
}

TARPC_FUNC(many_socket, {}, 
{
    int *handle = NULL;
    MAKE_CALL(out->retval = many_socket(in->common.lib_flags,
                                        domain_rpc2h(in->domain),
                                        in->num, &handle));
    out->handle = rcf_pch_mem_alloc(handle);
}
)

/**
 * Determine if the socket is cached or not.
 * 
 * @param sock  Socket descriptor
 * @param func  onload_fd_stat() function pointer or @c NULL
 * 
 * @return @c TRUE if the socket is cached.
 */
static te_bool
socket_is_cached(int sock, api_func func)
{
    struct stat st;
    struct onload_stat ostat;
    int rc_sys;
    int rc_ol;

    memset(&st, 0, sizeof(st));
    memset(&ostat, 0, sizeof(ostat));

    if (func == NULL)
        return FALSE;

    rc_ol = func(sock, &ostat);

    if ((rc_sys = fstat(sock, &st)) != 0 && RPC_ERRNO != RPC_EBADF)
        ERROR("fstat() failed with unexpected errno: %r", RPC_ERRNO);

    if (rc_ol == 0 && rc_sys == 0)
        return TRUE;

    return FALSE;
}

/** 
 * Close created sockets and free memory, calculate cached sockets number
 * if @p cached is not @c NULL.
 *
 * @param lib_flags     How to resolve function name
 * @param sockets_in    Pointer to sockets arrya to be closed
 * @param num           Sockets number
 * @param cached        Location for cached sockets number or @c NULL
 * 
 * @return Status code
 */
int
many_close(tarpc_lib_flags lib_flags, int *sockets_in, int num, int *cached)
{
    api_func close_f;
    api_func func = NULL;
    int *sock;
    int i;

    if (tarpc_find_func(lib_flags, "close", &close_f) != 0)
    {
        ERROR("failed to resolve function");
        return -1;
    }

    if (cached != NULL)
    {
        func = get_onload_fd_stat_func();
        *cached = 0;
    }

    sock = sockets_in;

    for (i = 0; i < num; i++)
    {
        if (sock[i] == -1)
            break;

        close_f(sock[i]);

        if (cached != NULL && socket_is_cached(sock[i], func))
            (*cached)++;
    }

    free(sock);

    return 0;
}

TARPC_FUNC(many_close, {}, 
{
     MAKE_CALL(out->retval = many_close(in->common.lib_flags,
                                      (int *)rcf_pch_mem_get(in->handle),
                                      in->num, NULL));
}
)

/**
 * Call epoll_wait() in a loop with increasing @p maxevents argument
 * until it returns less than @p maxevents.
 *
 * @param epoll_wait_f          Pointer to epoll_wait() function.
 * @param epfd                  Epoll FD.
 * @param evts                  Pointer to array of epoll events
 *                              (can be reallocated by this function).
 * @param evts_num              Number of elements in the array
 *                              (can be increased by this function).
 *
 * @return @c 0 on success, @c -1 on failure (RPC error is set in
 *         case of failure).
 */
static int
get_all_epoll_evts(api_func epoll_wait_f, int epfd,
                   struct epoll_event **evts, int *evts_num)
{
    int maxevents = 1;
    int new_num;
    int rc;
    void *p;

    if (maxevents < *evts_num)
        maxevents = *evts_num;

    while (TRUE)
    {
        if (*evts_num < maxevents)
        {
            new_num = maxevents * 2;
            p = realloc(*evts, new_num * sizeof(struct epoll_event));
            if (p == NULL)
            {
                te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                                 "Not enough memory for array of epoll "
                                 "events");
                return -1;
            }

            *evts = (struct epoll_event *)p;
            *evts_num = new_num;
        }

        rc = epoll_wait_f(epfd, *evts, maxevents, 0);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_RPC, errno),
                             "epoll_wait() failed");
            return -1;
        }

        if (rc < maxevents)
            return rc;

        maxevents *= 2;
    }
}

/**
 * Check whether expected events are reported for a given FD
 * by epoll_wait().
 *
 * @param evts        Array of epoll_event structures passed to
 *                    epoll_wait().
 * @param num         Number of events returned by epoll_wait().
 * @param fd          FD to look for.
 * @param events      Expected events.
 * @param expect_evt  Whether any events should be reported for
 *                    the given FD.
 *
 * @return @c 0 on success, @c -1 on failure (RPC error is set in
 *         case of failure).
 */
static int
check_evts_for_fd(struct epoll_event *evts, int num, int fd,
                  uint32_t events, te_bool expect_evt)
{
    int i;
    int found_idx = -1;
    int found_cnt = 0;

    for (i = 0; i < num; i++)
    {
        if (evts[i].data.fd == fd)
        {
            if (found_idx < 0)
                found_idx = i;

            found_cnt++;
        }
    }

    if (found_cnt > 1)
    {
        ERROR("epoll_wait() reported events multiple times for "
              "FD %d", fd);

        te_rpc_error_set(TE_RC(TE_RPC, TE_EFAIL),
                         "epoll_wait() returned events multiple times "
                         "for %s socket",
                         (expect_evt ? "added" : "removed"));
        return -1;
    }

    if (found_cnt > 0 && !expect_evt)
    {
        ERROR("epoll_wait() unexpectedly returned events 0x%x for FD %d",
              evts[found_idx].events, fd);

        te_rpc_error_set(TE_RC(TE_RPC, TE_EFAIL),
                         "epoll_wait() unexpectedly returned events"
                         "for removed socket");
        return -1;
    }
    else if (found_cnt == 0 && expect_evt)
    {
        ERROR("epoll_wait() did not report events for FD %d", fd);

        te_rpc_error_set(TE_RC(TE_RPC, TE_EFAIL),
                         "epoll_wait() did not report events for added "
                         "socket");
        return -1;
    }
    else if (found_cnt > 0 && evts[found_idx].events != events)
    {
        ERROR("epoll_wait() reported unexpected events 0x%x for FD %d",
              evts[found_idx].events, fd);

        te_rpc_error_set(TE_RC(TE_RPC, TE_EFAIL),
                         "epoll_wait() reported unexpected events for "
                         "added socket");
        return -1;
    }

    return 0;
}

/**
 * In a loop add socket FDs to epoll set, remove them from it,
 * and check what epoll_wait() returns after these operations if
 * requested.
 *
 * @param lib_flags         Flags for tarpc_find_func().
 * @param sockets           Socket FDS to add/remove.
 * @param socks_num         Number of socket FDs.
 * @param epfd              Epoll FD.
 * @param events            Epoll events to expect.
 * @param check_epoll_wait  If @c TRUE, check what epoll_wait() returns.
 * @param time2run          How long to run the loop, in ms.
 *
 * @return @c 0 on success, @c -1 on failure (RPC error is set in
 *         case of failure).
 */
static int
many_epoll_ctl_add_del(tarpc_lib_flags lib_flags, int *sockets, int socks_num,
                       int epfd, uint32_t events, te_bool check_epoll_wait,
                       int time2run)
{
    int i = 0;
    int rc = 0;
    te_errno te_rc;
    struct epoll_event ev;
    struct epoll_event *evts = NULL;
    int evts_num = 0;
    api_func epoll_ctl_f;
    api_func epoll_wait_f;

    struct timeval tv_start;
    struct timeval tv_current;

    if (tarpc_find_func(lib_flags, "epoll_ctl", &epoll_ctl_f) != 0 ||
        tarpc_find_func(lib_flags, "epoll_wait", &epoll_wait_f) != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "fail to resolve functions");
        return -1;
    }

    ev.events = events;

    te_rc = te_gettimeofday(&tv_start, NULL);
    if (te_rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, te_rc),
                         "gettimeofday() failed");
        return -1;
    }

    while (TRUE)
    {
        for (i = 0; i < socks_num; i++)
        {
            ev.data.fd = sockets[i];

            if (epoll_ctl_f(epfd, EPOLL_CTL_ADD, sockets[i], &ev) != 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_RPC, errno),
                                 "failed to add a socket to epoll set");
                rc = -1;
                goto cleanup;
            }

            if (check_epoll_wait)
            {
                rc = get_all_epoll_evts(epoll_wait_f, epfd, &evts,
                                        &evts_num);
                if (rc < 0)
                    goto cleanup;

                rc = check_evts_for_fd(evts, rc, sockets[i], events, TRUE);
                if (rc < 0)
                    goto cleanup;
            }

            if (epoll_ctl_f(epfd, EPOLL_CTL_DEL, sockets[i], &ev) != 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_RPC, errno),
                                 "failed to delete a socket from "
                                 "epoll set");
                rc = -1;
                goto cleanup;
            }

            if (check_epoll_wait)
            {
                rc = get_all_epoll_evts(epoll_wait_f, epfd, &evts,
                                        &evts_num);
                if (rc < 0)
                    goto cleanup;

                rc = check_evts_for_fd(evts, rc, sockets[i], events, FALSE);
                if (rc < 0)
                    goto cleanup;
            }
        }

        te_rc = te_gettimeofday(&tv_current, NULL);
        if (te_rc != 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, te_rc),
                             "gettimeofday() failed");
            rc = -1;
            goto cleanup;
        }

        if (TIMEVAL_SUB(tv_current, tv_start) >= TE_MS2US(time2run))
            break;
    }

cleanup:

    free(evts);
    return rc;
}

TARPC_FUNC_STATIC(many_epoll_ctl_add_del, {},
{
    MAKE_CALL(
        out->retval = func(in->common.lib_flags,
                           rcf_pch_mem_get(in->socks_arr),
                           in->socks_num, in->epfd,
                           epoll_event_rpc2h(in->events),
                           in->check_epoll_wait, in->time2run);
    );
}
)

/**
 * Wrapper function which calls many_close(), see its description for
 * details.
 */
int
many_close_cache(tarpc_lib_flags lib_flags, int *sockets_in,
                 int num, int *cached)
{
    return many_close(lib_flags, sockets_in, num, cached);
}

TARPC_FUNC(many_close_cache, {}, 
{
    int cached;

     MAKE_CALL(out->retval = many_close_cache(in->common.lib_flags,
                                         (int *)rcf_pch_mem_get(in->handle),
                                         in->num, &cached));
    out->cached = cached;
}
)

/**
 * Get a socket from a sockets array.
 *
 * @param array_handle      Handle of a memory chunk allocated for
 *                          the array.
 * @param idx               Index in the array.
 * @param s                 Where to save socket fd.
 *
 * @return Status code.
 */
static te_errno
get_socket_from_array(tarpc_ptr array_handle, unsigned int idx, tarpc_int *s)
{
    int *array;

    array = (int *)rcf_pch_mem_get(array_handle);
    if (array == NULL)
        return TE_EINVAL;

    *s = array[idx];

    return 0;
}

TARPC_FUNC_STATIC(get_socket_from_array, {},
{
    te_errno rc;

    MAKE_CALL(rc = func(in->handle, in->idx, &out->s));
    if (rc != 0)
    {
        out->retval = -1;
        out->common._errno = TE_RC(TE_TA_UNIX, rc);
    }
    else
    {
        out->retval = 0;
    }
}
)

/**
 * Check if provided time interval is expired.
 * 
 * @param duration  The interval duration
 * @param tv_start  Timestamp of the beginning
 * 
 * @return @c TRUE if durtaion is expired.
 */
static inline te_bool
duration_is_expired(int duration, struct timeval *tv_start)
{
    struct timeval tv_finish;

    if (duration == -1)
        return FALSE;

    gettimeofday(&tv_finish, NULL);
    if (duration < (tv_finish.tv_sec - tv_start->tv_sec) * 1000 +
                   (tv_finish.tv_usec - tv_start->tv_usec) / 1000)
        return TRUE;

    return FALSE;
}

/**
 * Receive packets with function @b recv() until @p num packets are received
 * or packet, which is equal to @p last_packet, is received.
 * 
 * @param lib_flags       How to resolve function name
 * @param sock            Socket
 * @param num             Packets number or @c -1 for unlimited number
 * @param duration        How long receive packets or @c NULL
 * @param length          Packets length
 * @param last_packet     Last packet or @c NULL
 * @param last_packet_len Last packet length
 * @param count_fails     Don't stop on fail
 * @param fails           Fails number (OUT)
 * 
 * @return Received packets number or @c -1 in case of failure
 */
int
many_recv(tarpc_lib_flags lib_flags, int sock, int num, int duration,
          size_t length, uint8_t *last_packet, size_t last_packet_len,
          te_bool count_fails, int *fails)
{
    struct timeval tv_start;
    api_func func = NULL;
    uint8_t *buf;
    int res;
    int i;
    int err = errno;
    int fails_counter = 0;

    if (tarpc_find_func(lib_flags, "recv", &func) != 0)
    {
        ERROR("failed to resolve recv() function");
        return -1;
    }

    buf = malloc(length);

    if (duration != -1)
        gettimeofday(&tv_start, NULL);

    for (i = 0; i < num || num == -1; i++)
    {
        if (duration_is_expired(duration, &tv_start))
            break;

        res = func(sock, buf, length, 0);
        if (last_packet != NULL && res == (int)last_packet_len &&
            memcmp(last_packet, buf, last_packet_len) == 0)
        {
            i++;
            break;
        }

        if (res < 0)
        {
            fails_counter++;

            if (errno == EAGAIN)
                i--;
            else if (!count_fails)
            {
                ERROR("recv function unexpectedly failed with %r", RPC_ERRNO);
                free(buf);
                return -1;
            }
        }
    }

    free(buf);
    if (errno == EAGAIN)
        errno = err;

    if (fails != NULL)
        *fails = fails_counter;

    return i;
}

TARPC_FUNC(many_recv, {}, 
{
     MAKE_CALL(out->retval = many_recv(in->common.lib_flags, in->sock,
                                       in->num, in->duration, in->length,
                                       in->last_packet.last_packet_val,
                                       in->last_packet.last_packet_len,
                                       in->count_fails, &out->fails_num));
}
)

/**
 * Receive data from a socket, measuring how much time it took.
 *
 * @param lib_flags   How to resolve function name recv().
 * @param fd          Socket descriptor.
 * @param fd_aux      Auxiliary socket descriptor. If non-negative,
 *                    the function will first wait until some data
 *                    arrives on it, and after that will start to
 *                    receive data from @p fd and measure duration.
 * @param length      How many bytes should be received.
 * @param duration    Where to save measured duration, in microseconds.
 * @param te_err      Where to save TE error (not related to checked
 *                    recv() call).
 *
 * @param Number of bytes actually received on success,
 *        or @c -1 on failure.
 */
ssize_t
recv_timing(tarpc_lib_flags lib_flags, int fd, int fd_aux, size_t length,
            uint64_t *duration, te_errno *te_err)
{
    struct timeval tv_start;
    struct timeval tv_end;
    te_errno       rc;
    api_func       recv_func = NULL;
    char          *buf = NULL;
    ssize_t        received = 0;
    size_t         total_read = 0;

    rc = tarpc_find_func(lib_flags, "recv", &recv_func);
    if (rc != 0)
    {
        ERROR("%s(): failed to resolve recv() function",
              __FUNCTION__);
        *te_err = rc;
        return -1;
    }

    buf = calloc(length, 1);
    if (buf == NULL)
    {
        ERROR("%s(): out of memory", __FUNCTION__);
        *te_err = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        return -1;
    }

    if (fd_aux >= 0)
    {
        received = recv_func(fd_aux, buf, length, 0);
        if (received < 0)
        {
            ERROR("%s(): failed to receive a packet from "
                  "auxiliary socket", __FUNCTION__);
            *te_err = TE_RC(TE_TA_UNIX, errno_h2rpc(errno));
            free(buf);
            return -1;
        }
    }

    if (gettimeofday(&tv_start, NULL) < 0)
    {
        ERROR("%s(): gettimeofday() failed to get start time",
              __FUNCTION__);
        *te_err = TE_RC(TE_TA_UNIX, errno_h2rpc(errno));
        free(buf);
        return -1;
    }

    while (TRUE)
    {
        received = recv_func(fd, buf, length, 0);
        if (received < 0)
        {
            ERROR("%s(): failed to receive data from "
                  "main socket", __FUNCTION__);
            free(buf);
            return -1;
        }

        total_read += received;
        if (total_read >= length)
            break;
    }

    free(buf);

    if (gettimeofday(&tv_end, NULL) < 0)
    {
        ERROR("%s(): gettimeofday() failed to get end time",
              __FUNCTION__);
        *te_err = TE_RC(TE_TA_UNIX, errno_h2rpc(errno));
        return -1;
    }

    *duration = TIMEVAL_SUB(tv_end, tv_start);

    return total_read;
}

TARPC_FUNC(recv_timing, {},
{
    te_errno te_err = 0;

    MAKE_CALL(out->retval = recv_timing(in->common.lib_flags, in->fd,
                                        in->fd_aux, in->length,
                                        &out->duration, &te_err));

    if (te_err != 0)
        out->common._errno = te_err;
}
)

/**
 * Send @p num packets with function @b send().
 * 
 * @param lib_flags     How to resolve function name
 * @param sock          Socket
 * @param length_min    Minimum packets length
 * @param length_max    Maximum packets length
 * @param num           Packets number or @c -1 for unlimited number
 * @param duration      How long receive packets or @c NULL
 * @param func_name     Function name to send data
 * @param check_len     Check that a send call sends all the data, this
 *                      check is not correct for TCP
 * @param count_fails   Don't stop on fail
 * @param fails         Fails number (OUT)
 * 
 * @return Sent packets number or @c -1 in case of failure
 */
int
many_send_num(tarpc_lib_flags lib_flags, int sock, size_t length_min,
              size_t length_max, int num, int duration,
              const char *func_name, te_bool check_len, te_bool count_fails,
              int *fails)
{
    struct timeval tv_start;
    struct iovec iov;
    struct msghdr *msg;
#ifndef HAVE_STRUCT_MMSGHDR
    struct msghdr msg_hdr;
#else
    struct mmsghdr mmsg;
#endif
    api_func func = NULL;
    uint8_t *buf;
    int fails_num = 0;
    int i;
    int err = errno;
    int length;
    int rc;

    if (tarpc_find_func(lib_flags, func_name, &func) != 0)
    {
        ERROR("Failed to resolve %s() function", func_name);
        return -1;
    }

    buf = malloc(length_max);
    iov.iov_base = buf;
#ifndef HAVE_STRUCT_MMSGHDR
    memset(&msg_hdr, 0, sizeof(msg_hdr));
    msg = &msg_hdr;
#else
    memset(&mmsg, 0, sizeof(mmsg));
    msg = &mmsg.msg_hdr;
#endif
    msg->msg_iov = &iov;
    msg->msg_iovlen = 1;

    if (duration != -1)
        gettimeofday(&tv_start, NULL);

#define SEND_LOOP(_send_call, _check_len_exp) \
do {                                                                \
    for (i = 0; i < num || num == -1; i++)                          \
    {                                                               \
        length = rand_range(length_min, length_max);                \
        iov.iov_len = length;                                       \
        if ((rc = _send_call) < 0)                                  \
        {                                                           \
            fails_num++;                                            \
            if (!count_fails)                                       \
            {                                                       \
                ERROR("send function unexpectedly failed with %r",  \
                      RPC_ERRNO);                                   \
                free(buf);                                          \
                return -1;                                          \
            }                                                       \
        }                                                           \
        else if (check_len && _check_len_exp)                       \
        {                                                           \
            ERROR("Datagram was not sent completely: rc %d, "       \
                  "length %d, errno %r", rc, length, RPC_ERRNO);    \
            i = -1;                                                 \
            break;                                                  \
        }                                                           \
        if (duration_is_expired(duration, &tv_start))               \
            break;                                                  \
    }                                                               \
} while (0)

    if (strcmp(func_name, "send") == 0)
        SEND_LOOP(func(sock, buf, length, 0), (rc != length));
    else if (strcmp(func_name, "write") == 0)
        SEND_LOOP(func(sock, buf, length), (rc != length));
    else if (strcmp(func_name, "writev") == 0)
        SEND_LOOP(func(sock, &iov, 1), (rc != length));
    else if (strcmp(func_name, "sendto") == 0)
        SEND_LOOP(func(sock, buf, length, 0, NULL, 0), (rc != length));
    else if (strcmp(func_name, "sendmsg") == 0)
        SEND_LOOP(func(sock, msg, 0), (rc != length));
#ifdef HAVE_STRUCT_MMSGHDR
    else if (strcmp(func_name, "sendmmsg") == 0)
        SEND_LOOP(func(sock, &mmsg, 1, 0), ((int)mmsg.msg_len != length));
#endif
    else
    {
        ERROR("Function %s is not supported by this RPC", func_name);
        i = -1;
    }

#undef SEND_LOOP

    free(buf);

    if (fails != NULL)
        *fails = fails_num;

    if (count_fails)
        errno = err;

    return i;
}

TARPC_FUNC(many_send_num, {},
{
     MAKE_CALL(out->retval = many_send_num(in->common.lib_flags, in->sock,
                                           in->length_min, in->length_max,
                                           in->num, in->duration,
                                           in->func_name, in->check_len,
                                           in->count_fails,
                                           &out->fails_num));
}
)

/** 
 * Start traffic processor (sender/receiver).
 *
 * @param lib        library name for function resolving
 * @param s          socket for sending/receiving
 * @param snd        if TRUE, send traffic
 * @param bytes_p    location for number of sent bytes in network order
 * @param stop       stop flag location
 *
 * @return Status code.
 */
te_errno
traffic_processor(tarpc_lib_flags lib_flags, int s, te_bool snd,
                  uint8_t *bytes_p, uint8_t *stop)
{
    te_errno rc;
    uint64_t bytes = 0;
    uint8_t *buf;
    int      err;
    int      val = 1;

#define TP_SIZE         (1024 * 4)
    api_func func;

    if ((rc = tarpc_find_func(lib_flags, snd ? "send" : "recv", &func)) != 0)
        return rc;

    err = ioctl(s, FIONBIO, &val);
    if (err < 0)
    {
        rc = RPC_ERRNO;
        
        ERROR("Failed to set socket to non-blocking mode: %r", rc);
        return rc;
    }

    if ((buf = malloc(TP_SIZE)) == NULL)
        return TE_RC(TE_TA, TE_ENOMEM);
        
    while (!*stop)
    {
        int len = 0;
        
        len = func(s, buf, TP_SIZE, 0);
        if (len <= 0)
        {
            rc = RPC_ERRNO;
            if (rc == RPC_EAGAIN)
            {
                rc = 0;
                continue;
            }
                
            if (bytes == 0)
            {
                ERROR("Failed to %s data: %r", snd ? "send" : "recv", rc);
                goto cleanup;
            }
            RING("Exit from traffic_processor: %llu %r", bytes, rc);
            break;
        }
        bytes += len;
        *(uint32_t *)bytes_p = htonl(bytes >> 32);
        *((uint32_t *)bytes_p + 1) = htonl(bytes & 0xFFFFFFFF);
    }
    
cleanup:    
    free(buf);
    val = 0;
    ioctl(s, FIONBIO, &val);

    return 0;

#undef TP_SIZE    
}

TARPC_FUNC(traffic_processor, {}, 
{
     uint8_t *stop;
     uint8_t *bytes;
     
     if ((bytes = (uint8_t *)rcf_pch_mem_get(in->bytes)) == NULL ||
         (stop = (uint8_t *)rcf_pch_mem_get(in->stop)) == NULL)
     {
         out->common._errno = TE_RC(TE_TA, TE_EINVAL);
         goto finish;
     }
     *stop = FALSE;
     memset(bytes, 0, 8);
     
     MAKE_CALL(out->common._errno = traffic_processor(in->common.lib_flags,
                                                      in->sock, in->snd,
                                                      bytes, stop)); 
     finish:         
     ;                                             
}
)

#if defined(__x86_64__) || defined(__i386__)
/* ------------ close() system call ------------- */
#ifdef __unix__
#if (SIZEOF_VOID_P == 4)
/* close() via interrupt is implemented both for Linux and SunOS */
TARPC_FUNC(close_interrupt, {},
{
    te_errno rc;
    
    MAKE_CALL({
        rc = func(in->fd);
        if (rc != 0)
            errno = rc;
        out->retval = (rc == 0)? 0 : -1;
    }
    );
}
)
#else
TARPC_FUNC(close_syscall, {},
{
    te_errno rc;
    
    MAKE_CALL(
    {
        rc = func(in->fd);
        if (rc != 0)
            errno = rc;
        out->retval = (rc == 0)? 0 : -1;
    }
    );
}
)
#endif /* 32-bit platform */
#endif /* Unix */

#if (defined(__linux__) && (SIZEOF_VOID_P == 4))
TARPC_FUNC(close_sysenter, {},
{
    te_errno rc;
    
    if (vsyscall_enter == NULL)
    {
        ERROR("Cannot find vsyscall page entrance");
        out->retval = -1;
        out->common._errno = TE_RC(TE_TA_UNIX, TE_EOPNOTSUPP);
        return;
    }
 
    MAKE_CALL(
    {
        rc = func(in->fd, vsyscall_enter);
        if (rc != 0)
            errno = rc;
        out->retval = (rc == 0)? 0 : -1;
    }
    );
}
)
#endif
#endif

#if defined(HAVE_NETPACKET_PACKET_H) && defined (HAVE_NET_ETHERNET_H)
/*-------------- incorrect CRC sending test staff -----------------*/

/**
 * Checksum routine for Internet Protocol family headers.
 *
 * @param addr Pointer into header
 * @param len  Length of header
 *
 * @return Checksum for target header.
 */

static inline unsigned int
in_cksum(unsigned short int *addr, int len)
{
    register int nleft = len;
    unsigned int answer = 0;
    
    register unsigned int        sum = 0;
    register unsigned short int *w = addr;

     /* Our algorithm is simple, using a 32 bit accumulator (sum), we add
      * sequential 16 bit words to it, and at the end, fold back all the
      * carry bits from the top 16 bits into the lower 16 bits. */

     while (nleft > 1)  {
         sum += *w++;
         nleft -= 2;
     }

     /* mop up an odd byte, if necessary */
     if (nleft == 1) {
         *(u_char *)(&answer) = *(u_char *) w;
         sum += answer;
     }

     /* add back carry outs from top 16 bits to low 16 bits */
     sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
     sum += (sum >> 16);                 /* add carry */
     answer = ~sum;                      /* truncate to 16 bits */
     return(answer);
}

#define SIOCRCIGNOREON  SIOCDEVPRIVATE + 10
#define SIOCRCIGNOREOFF SIOCDEVPRIVATE + 9

/**
 * Incorrect CRC sendig test.
 *
 * @param ifname    ethernet interface symbolic name
 * @param dest_addr destination host hadware address
 *
 * @return TE error code.
 *
 * @note Send ethernet frames with incorrect CRC from 
 * tst host to iut host, and check for reception.
 */
int
incorrect_crc_send_test(tarpc_incorrect_crc_send_test_in *in, 
                        tarpc_incorrect_crc_send_test_out *out)
{
    int   sd;
    int   ifindex;
    char *frame;
    char *hdr_ptr;

    struct ifreq  ifr;
    struct ethhdr ethh;
    struct sockaddr_ll sa;    

    /* Pseudo header */    
    struct psdhdr {
        struct iphdr  iph;
        struct udphdr udph;
    } psdh;

    out->retval = 0;

    if (in->ifname == NULL)
    {
        ERROR("Can't get ethernet interface name.");
        out->common._errno = EINVAL;
        return errno;
    }

    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sd < 0)
    {
        ERROR("socket(): can't create socket");
        out->common._errno = errno;
        return errno;
    }


    ifindex = if_nametoindex(in->ifname);
    if (ifindex < 0)
    {
        ERROR("if_nametoindex(): can't get interface index");
        close(sd);
        out->common._errno = errno;
        return errno;
    }
    
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_IP);
    sa.sll_ifindex = ifindex;
    sa.sll_pkttype = PACKET_HOST;
    sa.sll_hatype = ARPHRD_ETHER;
    sa.sll_halen = ETHER_ADDR_LEN;

    if (bind(sd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
    {
        ERROR("bind(): can't bind socket");
        close(sd);
        out->common._errno = errno;
        return errno;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, in->ifname);    
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {        
        ERROR("ioctl(): can't get source socket address");
        close(sd);
        out->common._errno = errno;
        return errno;
    }
            
    /* Fill ip header */
    memset(&psdh, 0, sizeof(struct psdhdr));
    psdh.iph.version = IPVERSION;
    psdh.iph.ihl     = sizeof(struct iphdr) / sizeof(uint32_t);
    psdh.iph.tos     = IPTOS_PREC_ROUTINE;
    psdh.iph.tot_len = htons(ETH_ZLEN - sizeof(struct ethhdr));
    psdh.iph.id      = getpid();
    psdh.iph.frag_off = 0;
    psdh.iph.ttl      = IPDEFTTL;
    psdh.iph.protocol = IPPROTO_UDP;
    psdh.iph.saddr = ((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr.s_addr;
    psdh.iph.daddr = 
        *((uint32_t *)&in->dest_sa.dest_sa_val->data.tarpc_sa_data_u.in.addr);
    psdh.iph.check = in_cksum((uint16_t *)&psdh.iph, sizeof(struct iphdr));

    /* Fill udp header */
    psdh.udph.source = htons(in->dest_sa.dest_sa_val->
                                 data.tarpc_sa_data_u.in.port);
    psdh.udph.dest = htons(in->dest_sa.dest_sa_val->
                                 data.tarpc_sa_data_u.in.port);
    psdh.udph.len = htons(ETH_ZLEN - sizeof(struct ethhdr) - 
                          sizeof(struct iphdr));
    /* Without UDP checksum */
    psdh.udph.check = 0; 
    
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0)
    {        
        ERROR("ioctl(): can't get interface hardware address");
        close(sd);
        out->common._errno = errno;
        return errno;
    }
    
    /* Fill ethernet header */
    memset(&ethh, 0, sizeof(struct ethhdr));
    memcpy(&ethh.h_dest, in->dest_addr.dest_addr_val, ETH_ALEN);
    memcpy(&ethh.h_source, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    ethh.h_proto = htons(ETH_P_IP);
     
    frame = malloc(ETHER_MIN_LEN);
    if (frame == NULL)
    {
        ERROR("%s(): Memory allocation failure.", __FUNCTION__);
        out->common._errno = errno;
        return errno;
    }
    
    memset(frame, 1, ETHER_MIN_LEN);
    hdr_ptr = frame;
    memcpy(hdr_ptr, &ethh, sizeof(struct ethhdr));
    memcpy(hdr_ptr += sizeof(struct ethhdr), &psdh, sizeof(struct psdhdr));

    /* Send frame wiht correct CRC */
    if (write(sd, frame, ETH_ZLEN) <= 0)
    {
        ERROR("write(): can't write to socket");
        free(frame);
        close(sd);
        out->common._errno = errno;
        return errno;
    }
    
    if (ioctl(sd, SIOCRCIGNOREON, &ifr) < 0)
    {
        ERROR("ioctl(): can't set ignore crc mode");
        close(sd);
        out->common._errno = errno;
        return errno;
    }

    /* Send frame with bad CRC */
    if (write(sd, frame, ETHER_MIN_LEN) <= 0)
    {
        ERROR("write(): can't write to socket");
        free(frame);
        close(sd);
        out->common._errno = errno;
        return errno;
    }

    /* Cancel CRC appending disable */
    strcpy(ifr.ifr_name, in->ifname);
    if (ioctl(sd, SIOCRCIGNOREOFF, &ifr) < 0)
    {
        ERROR("ioctl(): can't cancel ignore crc mode");
        free(frame);
        close(sd);
        out->common._errno = errno;
        return errno;
    }
    free(frame);
    close(sd);
    out->common._errno = errno;
    
    return 0;
}

TARPC_FUNC(incorrect_crc_send_test, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
}
)
#endif /* Incorrect CRC test */

/*-------------- many_send() -----------------------------*/
int
many_send(tarpc_many_send_in *in, tarpc_many_send_out *out)
{
    ssize_t        rc = 0;
    unsigned int   i;
    api_func  send_func;
    size_t         max_len = 0;
    uint8_t       *buf = NULL;
    int            flags;

    out->bytes = 0;

    if (in->vector.vector_len == 0)
    {
        ERROR("%s(): Invalid number of send() operations to be executed",
              __FUNCTION__);
        out->common._errno = TE_RC(TE_TA_UNIX, TE_EINVAL);
        rc = -1;
        goto many_send_exit;
    }

    for (i = 0; i < in->vector.vector_len; i++)
    {
        if (in->vector.vector_val[i] == 0)
        {
            ERROR("%s(): Invalid data length %u to be sent "
                  "by %d send() call", __FUNCTION__,
                  in->vector.vector_val[i], i);
            out->common._errno = TE_RC(TE_TA_UNIX, TE_EINVAL);
            rc = -1;
            goto many_send_exit;
        }
        max_len = MAX(max_len, in->vector.vector_val[i]);
    }

    buf = calloc(1, max_len);
    if (buf == NULL)
    {
        ERROR("%s(): Out of memory", __FUNCTION__);
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        rc = -1;
        goto many_send_exit;
    }

    memset(buf, 0xDEADBEEF, sizeof(max_len));

    if (tarpc_find_func(in->common.lib_flags, "send", &send_func) != 0)
    {
        ERROR("Failed to resolve send() function");
        rc = -1;
        goto many_send_exit;
    }

    flags = send_recv_flags_rpc2h(in->flags);
    for (i = 0; i < in->vector.vector_len; i++)
    {
        if (i % 1024 == 0)
            RING("%s(): [%d] send(%d, buf, %u, 0x%x)", __FUNCTION__, i,
                 in->sock, in->vector.vector_val[i], flags);
        rc = send_func(in->sock, buf, in->vector.vector_val[i], flags);
        if (rc != (ssize_t)in->vector.vector_val[i])
        {
           ERROR("%s(): %dth send(%d, buf, %u, 0x%x) failed: %d",
                 __FUNCTION__,
                 i, in->sock, in->vector.vector_val[i], flags, errno);
            rc = -1;
            goto many_send_exit;
        }
        out->bytes += rc;
        rc = 0;
    }

many_send_exit:

    free(buf);
    return rc;
}

TARPC_FUNC(many_send, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
}
)

/*-------------- send_traffic() --------------------------*/
/**
 * Repeatedly send traffic to various addresses.
 *
 * @param lib_flags Using lib_flags.
 * @param fd        File descriptors array.
 * @param buf       Buffer to send.
 * @param len       The buffer length.
 * @param flags     Send flags.
 * @param to        Destination addresses array.
 * @param addr_len  Addresslength array.
 * @param num       Send calls number, equal to arrays length.
 *
 * @return Zero on success or a negative value in case of fail.
 */
int
send_traffic(tarpc_lib_flags lib_flags, int *fd, uint8_t *buf, size_t len,
             int flags, struct sockaddr **to, socklen_t *addr_len, int num)
{
    api_func sendto_func;
    int      rc;
    int      i;

    if (tarpc_find_func(lib_flags, "sendto", &sendto_func) != 0)
        return -1;

    for (i = 0; i < num; i++)
    {
        rc = sendto_func(fd[i], buf, len, flags, to[i], addr_len[i]);
        if (rc < 0)
            return rc;
    }

    return 0;
}

TARPC_FUNC(send_traffic, {},
{
    struct sockaddr **addr_arr = NULL;
    socklen_t        *addr_len;
    int i;

    addr_arr = TE_ALLOC(in->num * sizeof(*addr_arr));
    addr_len = TE_ALLOC(in->num * sizeof(*addr_len));
    if (addr_arr == NULL || addr_len == NULL)
    {
        free(addr_arr);
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        return;
    }

    out->common._errno = 0;
    for (i = 0; i < in->num; i++)
    {
        PREPARE_ADDR_GEN(to, in->to.to_val[i], 0, FALSE, TRUE);
        addr_arr[i] = to_dup;
        addr_len[i] = tolen;
    }

    if (out->common._errno == 0)
    {
        INIT_CHECKED_ARG(in->buf.buf_val, in->buf.buf_len, 0);
        MAKE_CALL(out->retval = func_ptr(in->common.lib_flags, in->fd.fd_val,
                                        in->buf.buf_val, in->len,
                                        send_recv_flags_rpc2h(in->flags),
                                        addr_arr, addr_len, in->num));
    }

    for (i = 0; i < in->num; i++)
        free(addr_arr[i]);
    free(addr_arr);
    free(addr_len);
}
)

/*-------------- many_sendto() --------------------------*/
int
many_sendto(checked_arg_list *arglist,
            tarpc_many_sendto_in *in,
            tarpc_many_sendto_out *out)
{
    ssize_t       rc = 0;
    api_func      sendto_func;
    int           num = in->num;
    int           i;
    uint8_t       *buf = NULL;

    out->retval= 0;
    out->sent = 0;

    buf = calloc(1, in->len);
    if (buf == NULL)
    {
        ERROR("%s(): Out of memory", __FUNCTION__);
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        rc = -1;
        goto many_sendto_exit;
    }

    memset(buf, 0xDEADBEEF, sizeof(in->len));

    if (tarpc_find_func(in->common.lib_flags, "sendto", &sendto_func) != 0)
    {
        rc = -1;
        goto many_sendto_exit;
    }

    PREPARE_ADDR(to, in->to, 0);
    for (i = 0; i < num; i++)
    {
        if ((rc = sendto_func(in->sock, buf, in->len,
                              send_recv_flags_rpc2h(in->flags),
                              to, tolen)) == -1)
        {
            rc = -1;
            goto many_sendto_exit;
        }
        out->sent += rc;
        rc = 0;
    }

many_sendto_exit:
    free(buf);
    return rc;
}

TARPC_FUNC(many_sendto, {},
{
    MAKE_CALL(out->retval = func_ptr(arglist, in, out));
}
)

struct msghdr *
make_msghdr(size_t namelen, size_t iovlen, 
            size_t buflen, size_t controllen)
{
    struct msghdr *hdr;
    int i;
    int j;
    int k;
    struct iovec *res;

    hdr = calloc(1, sizeof(struct msghdr));
    if (hdr == NULL)
    {
        printf("No resources for make_msghdr\n");
        return NULL;
    }
    hdr->msg_namelen = (namelen > 0) ? namelen : 
                                       sizeof(struct sockaddr_storage);
    if (hdr->msg_namelen != 0)
    {
        hdr->msg_name = calloc(1, hdr->msg_namelen);
        if (hdr->msg_name == NULL)
        {
            printf("No resources for make_msghdr\n");
            free(hdr);
            return NULL;
        }
    }
    hdr->msg_iovlen = iovlen;
    res = (struct iovec *)calloc(iovlen, sizeof(struct iovec));
    if (res == NULL)
    {
        printf("No resources for make_msghdr\n");
        free(hdr->msg_name);
        free(hdr);
        return NULL;
    }
    
    for (i = 0; i < (int)iovlen - 1; i++)
    {
        res[i].iov_len = rand_range(0, buflen);
        for (j = i - 1, k = i; j >= 0; --j)
        {
            if (res[k].iov_len < res[j].iov_len)
            {
                size_t tmp = res[k].iov_len;
                
                res[k].iov_len = res[j].iov_len;
                res[j].iov_len = tmp;
                k = j;
            }
        }
    }
    
    res[iovlen - 1].iov_len = buflen;
    for (i = iovlen - 1; i > 0; --i)
    {
        res[i].iov_len -= res[i - 1].iov_len;
    }
    for (i = 0; i < (int)iovlen; ++i)
    {
        res[i].iov_base = calloc(1, res[i].iov_len);
        if (res[i].iov_base == NULL)
        {
            for (j = 0; j < i; j++)
                free(res[j].iov_base);
            free(res);
            free(hdr->msg_name);
            free(hdr);
            printf("No resources for make_msghdr\n");
            return NULL;
        }
    }
    hdr->msg_iov = res;
    hdr->msg_controllen = controllen;
    if (controllen != 0)
    {
        hdr->msg_control = calloc(1, controllen);
        if (hdr->msg_control == NULL)
        {
            for (i = 0; i < (int)iovlen; i++)
                free(res[i].iov_base);
            free(res);
            free(hdr->msg_name);
            free(hdr);
            printf("No resources for make msghdr\n");
            return NULL;
        }
    }
    return hdr;
}

int
free_msghdr(struct msghdr *hdr)
{
    int i;

    if (hdr != NULL)
    {
        free(hdr->msg_name);
        free(hdr->msg_control);
        if (hdr->msg_iov != NULL)
            for (i = 0; i < (int)(hdr->msg_iovlen); i++)
                free((hdr->msg_iov)[i].iov_base);
        free(hdr->msg_iov);
    }
    free(hdr);
    return 0;
}


/*-------------- timely_round_trip() --------------------------*/
int
timely_round_trip(checked_arg_list *arglist,
                  tarpc_timely_round_trip_in *in,
                  tarpc_timely_round_trip_out *out)
{
    api_func_ret_ptr make_msghdr_func;
    api_func_ptr     free_msghdr_func;
    api_func         sendmsg_func;
    api_func         recvmsg_func;
    api_func         select_func;

    struct timeval        timeout; 
    struct timeval        time2wait;
    struct timeval        temp;
        
    struct msghdr *tx_hdr = NULL;
    struct msghdr *rx_hdr = NULL;
    int i;

    fd_set          rfds;
    int             fd;
    struct tarpc_sa to;
    int             max;
    int             res = 0;

    out->index = 0;

    if ((tarpc_find_func(in->common.lib_flags, "select",
                         &select_func) != 0)                  ||
        (tarpc_find_func(in->common.lib_flags, "sendmsg",
                         &sendmsg_func) != 0)                 ||
        (tarpc_find_func(in->common.lib_flags, "recvmsg",
                         &recvmsg_func) != 0)                 ||
        (tarpc_find_func(in->common.lib_flags, "make_msghdr",
                         (api_func *)&make_msghdr_func) != 0) ||
        (tarpc_find_func(in->common.lib_flags, "free_msghdr",
                         (api_func *)&free_msghdr_func) != 0)
       )
    {
        ERROR("Failed to resolve functions");
        res = ROUND_TRIP_ERROR_OTHER;
        goto cleanup;
    }

#if 0
    if ((tx_hdr = (struct msghdr *)
                       make_msghdr_func(in->tolen,
                                        in->vector_len,
                                        in->size,
                                        0)) == NULL)
    {
        ERROR("Failed to prepare msghdr");
        res = ROUND_TRIP_ERROR_OTHER;
        goto cleanup;
    }
    
    if ((rx_hdr = (struct msghdr *)
                       make_msghdr_func(in->tolen,
                                        in->vector_len,
                                        in->size,
                                        0)) == NULL)
    {
        ERROR("Failed to prepare msghdr");
        res = ROUND_TRIP_ERROR_OTHER;
        goto cleanup;
    }
#endif
    max = (in->sock_num != 1) ? in->sock_num : in->addr_num;
    
    for (i = 0; i < max; i++, out->index++)
    {
        to = (in->addr_num != 1) ? in->to.to_val[i] : in->to.to_val[0];
        fd = (in->sock_num == 1) ? in->fd.fd_val[0] : in->fd.fd_val[i];

        PREPARE_ADDR(a, to, 0);
        memcpy(tx_hdr->msg_name, a, alen);

        time2wait.tv_sec = 0;
        time2wait.tv_usec = in->time2wait * 1000;
        
        if (gettimeofday(&temp, NULL))
        {
            ERROR("%s(): gettimeofday(timeout) failed: %d",
                  __FUNCTION__, errno);
            return ROUND_TRIP_ERROR_OTHER;
        }
#ifdef timeradd
        timeradd(&time2wait, &temp, &time2wait); 
#else
        time2wait.tv_sec += temp.tv_sec;
        time2wait.tv_usec += temp.tv_usec;
        if (time2wait.tv_usec >= 1000000)
        {
            time2wait.tv_sec++;
            time2wait.tv_usec -= 1000000;
        }
#endif

        if (sendmsg_func(fd, tx_hdr, 
                         send_recv_flags_rpc2h(in->flags)) == -1)
        {
            ERROR("sendmsg failed");
            res = ROUND_TRIP_ERROR_SEND;
            goto cleanup;
        }
       
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        
        timeout.tv_sec = 0;
        /* Timeout passed in milliseconds */
        timeout.tv_usec = in->timeout * 1000;
       
        if (select_func(fd + 1, &rfds, NULL, NULL, &timeout) == -1)
        {
            ERROR("Timeout occuring while calling select()");
            res = ROUND_TRIP_ERROR_TIMEOUT;
            goto cleanup;
        }
        
        if (gettimeofday(&temp, NULL))
        {
            ERROR("%s(): gettimeofday(timeout) failed: %d",
                  __FUNCTION__, errno);
            return ROUND_TRIP_ERROR_OTHER;
        }

        if (timercmp(&time2wait, &temp, <))
        {
            ERROR("time2wait expired");
            res = ROUND_TRIP_ERROR_TIME_EXPIRED;
            goto cleanup;
        }
 
        if (FD_ISSET(fd, &rfds))
        {
            if (recvmsg_func(fd, rx_hdr, 
                             send_recv_flags_rpc2h(in->flags)) == -1)
            {
                ERROR("recvmsg failed");
                res = ROUND_TRIP_ERROR_RECV;
                goto cleanup;
            }
        }
    }
cleanup:
    free_msghdr_func(tx_hdr);
    free_msghdr_func(rx_hdr);

    return res;
}

TARPC_FUNC(timely_round_trip, {},
{
    MAKE_CALL(out->retval = func_ptr(arglist, in, out));
}
)

/*-------------- round_trip_echoer() --------------------------*/
int
round_trip_echoer(tarpc_round_trip_echoer_in *in,
                  tarpc_round_trip_echoer_out *out)
{
    api_func_ret_ptr make_msghdr_func;
    api_func_ptr     free_msghdr_func;
    api_func         sendmsg_func;
    api_func         recvmsg_func;
    api_func         select_func;

    struct timeval        timeout; 

    struct msghdr *hdr = NULL;

    fd_set         rfds;
    int            res = 0;
    int            max;
    int            fd;
    int            i = 0;

    out->index = 0;

    if ((tarpc_find_func(in->common.lib_flags, "select",
                         &select_func) != 0)                  ||
        (tarpc_find_func(in->common.lib_flags, "sendmsg",
                         &sendmsg_func) != 0)                 ||
        (tarpc_find_func(in->common.lib_flags, "recvmsg",
                         &recvmsg_func) != 0)                 ||
        (tarpc_find_func(in->common.lib_flags, "make_msghdr",
                         (api_func *)&make_msghdr_func) != 0) ||
        (tarpc_find_func(in->common.lib_flags, "free_msghdr",
                         (api_func *)&free_msghdr_func) != 0)
       )
    {
        ERROR("Failed to resolve functions");
        res = ROUND_TRIP_ERROR_OTHER;
        goto cleanup;
    }

    if ((hdr = (struct msghdr *)
                    make_msghdr_func(sizeof(struct sockaddr_in),
                                     in->vector_len,
                                     in->size,
                                     0)) == NULL)
    {
        ERROR("Failed to prepare msghdr");
        res = ROUND_TRIP_ERROR_OTHER;
        goto cleanup;
    }
    
    max = (in->sock_num != 1) ? in->sock_num : in->addr_num;

    for (i = 0; i < max; i++)
    {   
        fd = (in->sock_num != 1) ? in->fd.fd_val[i] : in->fd.fd_val[0];
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        
        timeout.tv_sec = 0;
        /* Timeout passed in milliseconds */
        timeout.tv_usec = in->timeout * 1000;

       if (select_func(fd + 1, &rfds, NULL, NULL, &timeout) == -1)
        {
            ERROR("Timeout ocuured while calling select()");
            res = ROUND_TRIP_ERROR_TIMEOUT;
            goto cleanup;
        }

        if (FD_ISSET(fd, &rfds))
        {
            if (recvmsg_func(fd, hdr, 
                             send_recv_flags_rpc2h(in->flags)) == -1)
            {
                ERROR("recvmsg failed");
                res = ROUND_TRIP_ERROR_RECV;
                goto cleanup;
            }

            /* Send message back */
            if (sendmsg_func(fd, hdr, 
                             send_recv_flags_rpc2h(in->flags)) == -1)
            {
                ERROR("sendmsg failed");
                res = ROUND_TRIP_ERROR_SEND;
                goto cleanup;
            }
        }  
    }
    
cleanup:
    free_msghdr_func(hdr);
    return res;
}

TARPC_FUNC(round_trip_echoer, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
}
)

/*-------------- close_and_accept() --------------------------*/
/**
 * For given list of accepted sockets close some of them
 * and accept again pending connections.
 *
 * @param listening    listening socket
 * @param conns        number of connections
 * @param fd           list of accepted sockets
 * @param state        mask to close/open connections
 * 
 * @return 0 on success or -1 in the case of failure
 */ 
int
close_and_accept(tarpc_close_and_accept_in *in,
                 tarpc_close_and_accept_out *out)
{
    api_func         accept_func;
    api_func         close_func;
    api_func         select_func;

    tarpc_int            *fd_array = NULL; 

    int i;

    struct timeval  timeout;

    fd_set          rfds;
    int             res = 0;

    if ((tarpc_find_func(in->common.lib_flags, "select",
                         &select_func) != 0)    ||
        (tarpc_find_func(in->common.lib_flags, "accept",
                         &accept_func) != 0)    ||
        (tarpc_find_func(in->common.lib_flags, "close",
                         &close_func) != 0)
       )
    {
        ERROR("Failed to resolve functions, %s", __FUNCTION__);
        res = -1;
        goto cleanup;
    }

    fd_array = (tarpc_int *)calloc(in->conns, sizeof(tarpc_int));
    if (fd_array == NULL)
    {
        ERROR("No resources in %s", __FUNCTION__);
        res = -1;
        goto cleanup;
    }
    FD_ZERO(&rfds);
    FD_SET(in->listening, &rfds);
    
    for (i = 0; i < in->conns; i++)
    {
        if (!((1 << i) & in->state))
        {
            fd_array[i] = in->fd.fd_val[i];  
            continue;
        }
        res = close_func(in->fd.fd_val[i]);
        if (res != 0)
        {
            ERROR("%s: close on socket %d failed, %s", 
                  __FUNCTION__, in->fd.fd_val[i], strerror(errno));
            goto cleanup;
        }
        
        timeout.tv_sec = 50;
        timeout.tv_usec = 0;
       
        if ((res = select_func(in->listening + 1, &rfds, 
                        NULL, NULL, &timeout)) <= 0)
        {
            ERROR("Timeout occuring while calling select "
                  "or any other error(), %s, res %d, %s", 
                  __FUNCTION__, res, strerror(errno));
            res = -1;
            goto cleanup;
        }
        res = 0;

        fd_array[i] = accept_func(in->listening, NULL, NULL);
        if (fd_array[i] == -1)
        {
            ERROR("accept failed, %s", __FUNCTION__);
            goto cleanup;
        }
    }

    out->fd.fd_val = (tarpc_int *)fd_array;
    out->fd.fd_len = in->conns;
    
cleanup:
    if (res != 0 && fd_array != NULL)
    {
        free(fd_array);
        out->fd.fd_val = NULL;
        out->fd.fd_len = 0;
    }

    return res;
}

TARPC_FUNC(close_and_accept, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
    if ((out->retval != 0) && (out->fd.fd_val != NULL))
    {
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ECORRUPTED);
        out->fd.fd_val = NULL;
    }
    if (out->fd.fd_val != NULL)
    {
        out->mem_ptr = rcf_pch_mem_alloc(out->fd.fd_val);
    }
}
)

/*-------------- close_and_socket() --------------------------*/
/**
 * For given socket close it and reopen immediately
 * with the same fd.
 * 
 * @param fd        socket fd
 * @param domain    communication domain.
 *                  Select the protocol family used for communication
 *                  supported protocol families are difined in 
 *                  te_rpc_sys_socket.h
 * @param type      defines the semantic of communication. Current defined 
 *                  types can be found in te_rpc_sys_socket.h
 * @param protocol  specifies the protocol to be used. If @b protocol is 
 *                  set to RPC_PROTO_DEF, the system selects the default 
 *                  protocol number for the socket domain and type 
 *                  specified.
 *
 * @return 0 on success or -1 in the case of failure
 */ 
int
close_and_socket(tarpc_close_and_socket_in *in)
{
    api_func    close_func;
    api_func    socket_func;
    int         res;

    TRY_FIND_FUNC(in->common.lib_flags, "socket", &socket_func);
    TRY_FIND_FUNC(in->common.lib_flags, "close", &close_func);

    res = close_func(in->fd);
    if (res != 0)
    {
        ERROR("%s: close on socket %d failed, %s", 
              __FUNCTION__, in->fd, strerror(errno));
        return res;
    }

    res = socket_func(domain_rpc2h(in->domain), socktype_rpc2h(in->type),
                      proto_rpc2h(in->protocol));

    if (res < 0)
    {
        ERROR("%s: socket() failed, %s", __FUNCTION__, strerror(errno));
        return res;
    }
    else if (res != in->fd)
    {
        ERROR("%s: closed fd=%d, but socket returns %d", __FUNCTION__,
              in->fd, res);
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                         "socket() returns different FD than that which "
                         "was just closed");
        close_func(res);
        return -1;
    }

    return 0;
}

TARPC_FUNC(close_and_socket, {},
{
    MAKE_CALL(out->retval = func_ptr(in));
}
)


#if HAVE_AIO_H

#if HAVE_SIGINFO_T_SI_VALUE
#define SI_VALUE    si_value
#elif HAVE_SIGINFO_T_SI_SIGVAL
#define SI_VALUE    si_sigval
#else
#error No signal value field in siginfo_t!
#endif

/** Get value from siginfo */
#if HAVE_UNION_SIGVAL_SIVAL_INT
#define SIVAL_INT   sival_int
#define SIVAL_PTR   sival_ptr
#elif HAVE_UNION_SIGVAL_SIGVAL_INT
#define SIVAL_INT   sigval_int
#define SIVAL_PTR   sigval_ptr
#else        
#error "Failed to discover memeber names of the union sigval."
#endif

/** Functions and definitions for operating with callback list. */

#define AIO_MAX_CALLBACKS       1024

/** Node of callback list. */
typedef struct aio_callback_node {
    int                       num;
    int                       signo;
    union sigval              val;
} aio_callback_node;

/** Callback list */
static aio_callback_node aio_cb_list[AIO_MAX_CALLBACKS];

/** Current callback list length */
static int aio_cb_list_len = 0;

/** Signal handler call list */
static aio_callback_node aio_sh_list[AIO_MAX_CALLBACKS];

/** Current signal handler list length */
static int aio_sh_list_len = 0;

/**
 * Add callback to the callback list.
 *
 * @param n     callback number
 * @param signo signal (for signal handlers only)
 * @param val   value for the callback
 *
 * @note This function may be called from signal handler or
 *       aio callback. Data protection should be performed there.
 */
static void
aio_callback_add(int n, int signo, int val, 
                 int *len, aio_callback_node *list)
{
    int i = *len % AIO_MAX_CALLBACKS;

    if (*len < AIO_MAX_CALLBACKS)
        (*len)++;
    else
        ERROR("Callback list overflow"); 
    
    list[i].num = n;
    list[i].val.SIVAL_INT = val;
    list[i].signo = signo;
}

static pthread_mutex_t aio_callback_lock = PTHREAD_MUTEX_INITIALIZER;

/** Declaration of the callback. */
#define AIO_CALLBACK_DECLARE(_i) \
void                                                            \
aio_callback_##_i(int x)                                        \
{                                                               \
    pthread_mutex_lock(&aio_callback_lock);                     \
    aio_callback_add(_i, 0, x, &aio_cb_list_len, aio_cb_list);  \
    pthread_mutex_unlock(&aio_callback_lock);                   \
}

AIO_CALLBACK_DECLARE(1);
AIO_CALLBACK_DECLARE(2);
AIO_CALLBACK_DECLARE(3);
AIO_CALLBACK_DECLARE(4);
AIO_CALLBACK_DECLARE(5);
AIO_CALLBACK_DECLARE(6);
AIO_CALLBACK_DECLARE(7);
AIO_CALLBACK_DECLARE(8);
AIO_CALLBACK_DECLARE(9);
        
        
/** Declaration of signal handler */
#define AIO_SIGHANDLER_DECLARE(_i) \
void                                                            \
aio_sighandler_##_i(int signo, siginfo_t *info, void *context)  \
{                                                               \
    UNUSED(context);                                            \
    aio_callback_add(_i, signum_h2rpc(signo),                   \
                     info->SI_VALUE.SIVAL_INT,                  \
                     &aio_sh_list_len, aio_sh_list);            \
}

AIO_SIGHANDLER_DECLARE(1);
AIO_SIGHANDLER_DECLARE(2);

/** 
 * Produce the array of callbacks from callback list. 
 *
 * @note It is assumed that all callbacks/signal handlers are called -
 *       there is no data protection.
 */
void
get_callback_list(tarpc_get_callback_list_in *in,
                  tarpc_get_callback_list_out *out)
{
    int i, k;
    
    UNUSED(in);
        
    out->list.list_val = calloc(aio_cb_list_len + aio_sh_list_len,
                                sizeof(tarpc_callback_item));
    if (out->list.list_val == NULL)
    {
        ERROR("calloc has returned NULL");
        return;
    }
    out->list.list_len = aio_cb_list_len + aio_sh_list_len;
    for (i = 0, k = 0; i < aio_cb_list_len; i++, k++)
    {
        out->list.list_val[i].callback_num = aio_cb_list[i].num;
        out->list.list_val[i].val = aio_cb_list[i].val.SIVAL_INT;
        out->list.list_val[i].signo = aio_cb_list[i].signo;
    }
    for (i = 0; i < aio_sh_list_len; i++, k++)
    {
        out->list.list_val[k].callback_num = aio_sh_list[i].num;
        out->list.list_val[k].val = aio_sh_list[i].val.SIVAL_INT;
        out->list.list_val[k].signo = aio_sh_list[i].signo;
    }
    
    aio_cb_list_len = aio_sh_list_len = 0; 
}
    
TARPC_FUNC(get_callback_list, {},
{
    UNUSED(func);
    MAKE_CALL(get_callback_list(in, out));
}
)

#ifdef SIGEV_THREAD
/** Callback called for AIO request completion notification */
static void
blk_aio_callback(union sigval val)
{
    *(te_bool *)(val.SIVAL_PTR) = TRUE;
}
#endif

/** Handler for signal sent for AIO request completion notification */
static void
blk_aio_sighandler(int signo)
{
    UNUSED(signo);
}

/**
 * Emulate blocking read using AIO calls.
 *
 * @param s     socket handle
 * @param buf   buffer for read data
 * @param len   buffer length
 * @param op    RPC_LIO_WRITE or RPC_LIO_READ
 * @param mode  blocking mode: aio_suspend(), polling, 
 *              signal, callback
 * @param lib   library for aio functions resolution
 *
 * @return Result of read operation
 */
static ssize_t
blk_aio(int s, void *buf, size_t len, rpc_lio_opcode op, int mode, 
        tarpc_lib_flags lib_flags)
{
    struct aiocb  cb;

    struct aiocb const * cblist[1] = { &cb };
    
    int rc;
    
    int _err = errno;

    te_bool called = FALSE;
    
    sighandler_t old = NULL;

    api_func_ptr aio_read_func;
    api_func_ptr aio_write_func;
    api_func_ptr aio_return_func;
    api_func_ptr aio_suspend_func;
    api_func_ptr aio_error_func;
    
    if (tarpc_find_func(lib_flags, "aio_read",
                        (api_func *)&aio_read_func) != 0 ||
        tarpc_find_func(lib_flags, "aio_write",
                        (api_func *)&aio_write_func) != 0 ||
        tarpc_find_func(lib_flags, "aio_suspend",
                        (api_func *)&aio_suspend_func) != 0 ||
        tarpc_find_func(lib_flags, "aio_error",
                        (api_func *)&aio_error_func) != 0 ||
        tarpc_find_func(lib_flags, "aio_return",
                        (api_func *)&aio_return_func) != 0)
    {
        ERROR("Failed to resolve asynchronous AIO functions");
        errno = EFAULT;
        return -1;
    }
    
    memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = s;
    cb.aio_buf = buf;
    cb.aio_nbytes = len;
    if (mode == TARPC_AIO_BLK_SIGNAL)
    {
        cb.aio_sigevent.sigev_signo = SIGUSR1;
        old = signal(SIGUSR1, blk_aio_sighandler);
    }    
    else if (mode == TARPC_AIO_BLK_CALLBACK)
    {
#ifdef SIGEV_THREAD
        cb.aio_sigevent.sigev_notify_function = blk_aio_callback;
        cb.aio_sigevent.sigev_value.SIVAL_PTR = &called;
        cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
#else
        ERROR("SIGEV_THREAD notification is not supported");
        errno = ENOSYS;
        return -1;
#endif
    }
    else
        cb.aio_sigevent.sigev_notify = SIGEV_NONE;
    
    if (op == RPC_LIO_READ && aio_read_func(&cb) < 0)
    {
        ERROR("aio_read() failed");
        errno = EFAULT;
        return -1;
    }
    else if (op == RPC_LIO_WRITE && aio_write_func(&cb) < 0)
    {
        ERROR("aio_write() failed");
        errno = EFAULT;
        return -1;
    }
    else if (op != RPC_LIO_READ && op != RPC_LIO_WRITE)
    {
        ERROR("incorrect operation is passed to blk_aio()");
        errno = EFAULT;
        return -1;
    }
    
    switch (mode)
    {
        case TARPC_AIO_BLK_SUSPEND:
            if (aio_suspend_func(cblist, 1, NULL) < 0)
            {
                ERROR("aio_suspend() failed");
                errno = EFAULT;
                return -1;
            }
            break;
            
        case TARPC_AIO_BLK_SIGNAL:
        {
            sigset_t set;
            
            sigemptyset(&set);
            sigsuspend(&set);
            signal(SIGUSR1, old);
            break;
        }
            
        default:
            while (!called && !(mode == TARPC_AIO_BLK_POLL && 
                                aio_error_func(&cb) != EINPROGRESS))
            {
                usleep(500);
            }
            break;
    }
    
    if ((rc = aio_return_func(&cb)) < 0)
        errno = aio_error_func(&cb);
    else
        errno = _err;
    
    return rc;
}

/** Global wrapper for blk_aio() with read operation */
ssize_t
aio_read_blk(int s, void *buf, size_t len, int mode, tarpc_lib_flags lib_flags)
{
    return blk_aio(s, buf, len, RPC_LIO_READ, mode, lib_flags);
}

/** Global wrapper for blk_aio() with write operation */
ssize_t
aio_write_blk(int s, void *buf, size_t len, int mode, tarpc_lib_flags lib_flags)
{
    return blk_aio(s, buf, len, RPC_LIO_WRITE, mode, lib_flags);
}


/*-------------- aio_read_blk() --------------------------*/
TARPC_FUNC(aio_read_blk, 
{
    COPY_ARG(buf);
},
{
    INIT_CHECKED_ARG(out->buf.buf_val, out->buf.buf_len, in->len);
    MAKE_CALL(out->retval = func(in->fd, out->buf.buf_val, in->len,
                                 in->mode, in->common.lib_flags));
}
)

/*-------------- aio_write_blk() --------------------------*/
TARPC_FUNC(aio_write_blk, {}, 
{
    INIT_CHECKED_ARG(in->buf.buf_val, in->buf.buf_len, 0);
    MAKE_CALL(out->retval = func(in->fd, in->buf.buf_val, in->len,
                                 in->mode, in->common.lib_flags));
}
)

/*-------- Variable and handler for signal_handler_close test --------*/

/** Socket for closing by sighandler_close() */
int     sock4cl = -1;
/** Whether to use dup2() in sighandler_close() or not */
int     close_func = 0;
/** File descriptor to be duplicated by dup2() in sighandler_close() */
int     fd2dup = -1;

/**
 * Will be set to non-zero if closing function inside sighandler_close()
 * failed.
 */
int     sighandler_close_failed = 0;

/**
 * Will be set to errno after calling closing function inside
 * sighandler_close() if it failed.
 */
int     sighandler_close_errno = 0;

void
sighandler_close(int signo, siginfo_t *info, void *context)
{
    char    *func_name = NULL;
    int      rc = 0;
    int      saved_errno = errno;

    UNUSED(context);
    UNUSED(signo);
    UNUSED(info);

    api_func func;

    sighandler_close_failed = 0;

    switch (close_func)
    {
        case 0: func_name = "close"; break;
        case 1: func_name = "dup2"; break;
        case 2: func_name = "shutdown"; break;
        default: ERROR("Bad value for close_func: %d", close_func); return;
    }

    if (tarpc_find_func(TARPC_LIB_DEFAULT, func_name, &func) == 0)
    {
        switch (close_func)
        {
            case 0: rc = func(sock4cl); break;
            case 1: rc = func(fd2dup, sock4cl); break;
            case 2: rc = func(sock4cl, SHUT_RDWR); break;
        }

        if (rc < 0)
        {
            ERROR("%s() failed", func_name);
            sighandler_close_failed = 1;
            sighandler_close_errno = te_rc_os2te(errno);

            /*
             * Restore original errno - otherwise RPC call interrupted
             * by this signal handler can fail due to unexpected errno
             * change.
             */
            errno = saved_errno;
        }
    }
    else
        ERROR("Failed to find function %s", func_name);

    return;
}

/*-------- Handler for two_signals_hndlr_run test --------*/
void
sighandler_sigusr(int signo, siginfo_t *info, void *context)
{
    UNUSED(context);
    UNUSED(signo);
    UNUSED(info);

    api_func func_us;
    api_func func_kl;

    tarpc_find_func(TARPC_LIB_DEFAULT, "usleep", &func_us);
    tarpc_find_func(TARPC_LIB_DEFAULT, "kill", &func_kl);
    func_kl(getpid(), SIGUSR1);
    func_us(100000);

    return;
}

/*------------------ sighandler which creates file ----------------*/
/* from unix_internal.h */
extern char ta_dir[RCF_MAX_PATH];

static char *
sighandler_get_filename(int signo)
{
    char filename[RCF_MAX_PATH];

    snprintf(filename, RCF_MAX_PATH - 1,
             "%s/%s.%u.%llu.%d.%s", ta_dir, "sighandler_createfile",
             getpid(), (unsigned long long int)pthread_self(),
             signo, strsignal(signo));
    return strndup(filename, RCF_MAX_PATH);
}

static char *
thrd_sighandler_get_filename(int signo, tarpc_pid_t pid,
                             tarpc_pthread_t tid)
{
    char filename[RCF_MAX_PATH];

    snprintf(filename, RCF_MAX_PATH - 1,
             "%s/%s.%u.%llu.%d.%s", ta_dir, "sighandler_createfile",
             pid, (unsigned long long int)tid,
             signo, strsignal(signo));
    return strndup(filename, RCF_MAX_PATH);
}

/* The signal handler itself */
void
sighandler_createfile(int signo)
{
    char *filename = sighandler_get_filename(signo);
    int   fd;

    fd = open(filename, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    free(filename);
    if (fd < 0)
    {
        ERROR("Signal handler failed to create file %s", filename);
        return;
    }
    close(fd);
}

void
sighandler_createfile_siginfo(int signo, siginfo_t *info, void *context)
{
    char *filename = sighandler_get_filename(signo);
    int fd;

    signal_registrar_siginfo(signo, info, context);

    fd = open(filename, O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    free(filename);
    if (fd < 0)
    {
        ERROR("Signal handler failed to create file %s", filename);
        return;
    }
    close(fd);
}

/*---------- sighandlers for sigaction flags testing -----------*/
#ifdef SS_ONSTACK
/** 
 * Address of the first variable of
 * the signal handler (used to check whether
 * is is really executed on alternate signal
 * stack)
 */
long long unsigned int    onstack_addr = 0;
/**
 * Whether SS_ONSTACK flag was returned
 * by sigaltstack() or not
 */
te_bool                   was_onstack = FALSE;

/**
 * Special signal handler which registers signals
 * and checks sigaltstack() return value.
 * 
 * @param signum    received signal
 */
void
signal_registrar_onstack(int signum)
{
    stack_t      oss;
    api_func_ptr func_sigaltstack;

    signal_registrar(signum);

    onstack_addr = (long long unsigned int)
                    ((uint8_t *)&oss - (uint8_t *)NULL);
    was_onstack = FALSE;

    tarpc_find_func(TARPC_LIB_DEFAULT, "sigaltstack",
                    (api_func *)&func_sigaltstack);

    memset(&oss, 0, sizeof(oss));
    func_sigaltstack(NULL, &oss);
    if (oss.ss_flags == SS_ONSTACK)
        was_onstack = TRUE;
}
#endif

/**
 * Whether signal_registrar_nodefer() was called
 * twice when it was executing already or not.
 */
te_bool nodefer_called_twice = FALSE;

/**
 * How many times signal_registrar_nodefer() was called.
 */
int nodefer_calls_count = 0;

/**
 * Whether from the signal handler the signal action seems to be reset
 * to default.
 */
te_bool nodefer_reset = FALSE;

/**
 * Signal handler for @c SA_NODEFER testing.
 *
 * @param signum Signal number
 */
void
signal_registrar_nodefer(int signum)
{
    pthread_t       (*func_pthread_self)();
    int             (*func_pthread_kill)(pthread_t, int);

    api_func            func_sigaction;
    struct sigaction    old_act;
    pthread_t           tid;

    static te_bool      nodefer_called_already = FALSE;

    if (!nodefer_called_already)
        nodefer_called_already = TRUE;
    else
        nodefer_called_twice = TRUE;

    signal_registrar(signum);

    nodefer_calls_count++;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "sigaction",
                        (api_func *)&func_sigaction))
        ERROR("Failed to find sigaction()");
    else
    {
        memset(&old_act, 0, sizeof(old_act));
        func_sigaction(signum, NULL, &old_act);
        if (old_act.sa_handler == SIG_DFL)
            nodefer_reset = TRUE;
    }

    if (nodefer_calls_count < 2 && !nodefer_reset)
    {
        if (tarpc_find_func(TARPC_LIB_DEFAULT, "pthread_kill",
                            (api_func *)&func_pthread_kill) ||
            tarpc_find_func(TARPC_LIB_DEFAULT, "pthread_self",
                            (api_func *)&func_pthread_self))
            ERROR("%s(): failed to find required functions", __FUNCTION__);
        else
        {
            tid = func_pthread_self();
            func_pthread_kill(tid, signum);
        }
        /*
         * Let signal be processed second time it it is not
         * blocked.
         */
        te_msleep(100);
    }

    nodefer_called_already = FALSE;
}

/**
 * Signal handler for @c SA_RESETHAND testing that
 * reinstalls sighandler_createfile() signal handler for
 * the same signal.
 *
 * @param signum Signal number
 */
void
sighandler_resethand_reinstall(int signum)
{
    api_func            func_sigaction;
    struct sigaction    act;

    signal_registrar(signum);

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "sigaction",
                        (api_func *)&func_sigaction))
        ERROR("Failed to find sigaction()");
    else
    {
        memset(&act, 0, sizeof(act));
        act.sa_handler = (void (*)(int))sighandler_createfile;
        if (func_sigaction(signum, &act, NULL) < 0)
            ERROR("%s(): failed to install signal handler",
                  __FUNCTION__);
    }
}

/*---------- sighandlers creating files identifying receiver------*/
/* Remove the file before the signal handler */
void
sighandler_createfile_cleanup(int signo)
{
    int  saved_errno;
    char *filename = sighandler_get_filename(signo);
    saved_errno = errno;
    unlink(filename);
    if (errno == ENOENT)
        errno = saved_errno;
    free(filename);
}
TARPC_FUNC(sighandler_createfile_cleanup, {},
{
    MAKE_CALL(sighandler_createfile_cleanup(signum_rpc2h(in->sig)));
}
)

/* Check the presence of the file */
te_bool
sighandler_createfile_exists_unlink(int signo)
{
    char *filename = sighandler_get_filename(signo);
    int rc = unlink(filename);
    free(filename);
    if (rc == 0)
        return TRUE;
    else
        return FALSE;
}
TARPC_FUNC(sighandler_createfile_exists_unlink, {},
{
    MAKE_CALL(out->retval =
              sighandler_createfile_exists_unlink(signum_rpc2h(in->sig)));
}
)

/* Check the presence of the file from another RPC server*/
te_bool
thrd_sighnd_crtfile_exists_unlink(int signo, tarpc_pid_t pid,
                                  tarpc_pthread_t tid)
{
    char *filename = thrd_sighandler_get_filename(signo, pid, tid);
    int rc = unlink(filename);
    free(filename);
    if (rc == 0)
        return TRUE;
    else
        return FALSE;
}

TARPC_FUNC(thrd_sighnd_crtfile_exists_unlink, {},
{
    MAKE_CALL(out->retval =
              thrd_sighnd_crtfile_exists_unlink(signum_rpc2h(in->sig),
                                                in->pid, in->tid));
}
)

/*-------- Handler for template_signal test --------*/

/** Socket to pass Onload template. */
int template_signal_socket = -1;

/** Total template length. */
int template_signal_total = 1024;

/** IOVs array length. */
int template_signal_iovcnt = 5;

void
sighandler_template_send(int signo, siginfo_t *info, void *context)
{
    onload_template_handle handle;
    char *buf;
    struct iovec *iov;
    int i;

    UNUSED(context);
    UNUSED(signo);
    UNUSED(info);

    iov = calloc(template_signal_iovcnt, sizeof(*iov));
    buf = malloc(template_signal_total / template_signal_iovcnt);
    for (i = 0; i < template_signal_iovcnt; i++)
    {
        iov[i].iov_base = buf;
        iov[i].iov_len = template_signal_total / template_signal_iovcnt;
    }

    onload_msg_template_alloc(template_signal_socket, iov,
                              template_signal_iovcnt, &handle, 0);
    free(buf);
    free(iov);

    onload_msg_template_update(template_signal_socket, handle, NULL, 0,
                               ONLOAD_TEMPLATE_FLAGS_SEND_NOW);

    return;
}


/*------------------- nested_requests test staff -------------------*/

/** Functions to be used for AIO operations */
static api_func_ptr nr_aio_read_func;
static api_func_ptr nr_aio_write_func;
static api_func_ptr nr_aio_return_func;
static api_func_ptr nr_aio_error_func;
static api_func     nr_aio_cancel_func;

#ifdef SIGEV_THREAD

/** Lock to be used from the callback to protect counters */
static pthread_mutex_t nr_lock = PTHREAD_MUTEX_INITIALIZER;

/** AIO control blocks for read requests */
static struct aiocb *nr_rx_cbs;

/** AIO control blocks for write requests */
static struct aiocb *nr_tx_cbs;

/** Number of write requests */
static int nr_req_num;

/** First unposted read request index */
static int nr_next_rx;

/** First unposted write request index */
static int nr_next_tx;

/** Number of completed write requests */
static int nr_completed_tx;

/** Number of completed read requests */
static int nr_completed_rx;

/** Current error status */
static int nr_error;

/* Post read request */
#define NR_POST_READ \
    do {                                                        \
        if (nr_aio_read_func(nr_rx_cbs + nr_next_rx++) != 0)    \
        {                                                       \
            nr_error = TE_OS_RC(TE_TA_UNIX, errno);             \
            ERROR("aio_read() failed with errno %r", nr_error); \
        }                                                       \
    } while (0)

/* Post write request */
#define NR_POST_WRITE \
    do {                                                        \
        if (nr_aio_write_func(nr_tx_cbs + nr_next_tx++) != 0)   \
        {                                                       \
            nr_error = TE_OS_RC(TE_TA_UNIX, errno);             \
            ERROR("aio_read() failed with errno %r", nr_error); \
        }                                                       \
    } while (0)

/** 
 * AIO callback for nested_requests test.
 *
 * @param val     pointer of the control block corresponding to finished
 *                request
 */
static void
nr_callback(union sigval val)
{
    struct aiocb *cb = (struct aiocb *)(val.SIVAL_PTR);
    
    te_bool rd;
    int     i;
    int     rc;
    
    pthread_mutex_lock(&nr_lock);

    if (cb >= nr_rx_cbs && cb < nr_rx_cbs + nr_req_num) 
    {
        nr_completed_rx++;
        rd = TRUE;
        i = (cb - nr_rx_cbs) + 1;
    }
    else if (cb >= nr_tx_cbs && cb < nr_tx_cbs + nr_req_num) 
    {
        nr_completed_tx++;
        rd = FALSE;
        i = (cb - nr_tx_cbs) + 1;
    }
    else
    {
        ERROR("Incorrect pointer is passed to completion callback");
        nr_error = TE_RC(TE_TA_UNIX, TE_EINVAL);
        pthread_mutex_unlock(&nr_lock);
        return;
    }
    
    if ((rc = nr_aio_error_func(cb)) != 0)
    {
        nr_error = TE_OS_RC(TE_TA_UNIX, rc);
        ERROR("%s request %d failed with error %r", 
              rd ? "read" : "write", i, nr_error);
        pthread_mutex_unlock(&nr_lock);
        return;
    }
    
    if ((rc = nr_aio_return_func(cb)) != 1)
    {
        nr_error = TE_RC(TE_TA_UNIX, EINVAL);
        ERROR("%s request %d returned %d instead 1", 
              rd ? "read" : "write", i, rc);
        pthread_mutex_unlock(&nr_lock);
        return;
    }
    
    if (nr_next_rx < nr_req_num  && nr_next_tx < nr_req_num)
    {
        NR_POST_WRITE;
        NR_POST_READ;
    }
    
    pthread_mutex_unlock(&nr_lock);
}
#endif /* SIGEV_THREAD */

/**
 * Nested AIO requests test.
 *
 * @param s             connected socket
 * @param req_num       number of write requests < 256
 *
 * @note One write operation transmit one exactly byte to avoid mixing of 
 *       data from different write request in the one read request for
 *       the case of TCP socket.
 */
int
nested_requests_test(int s, int req_num)
{
#ifdef SIGEV_THREAD
    uint8_t *rx_buf = NULL;
    uint8_t *tx_buf = NULL;
    
    int i;
    
    nr_error = 0;
    
    if (req_num > 256 || req_num < 2)
    {
        ERROR("Incorrect number of requests is passed to nr_test");
        return TE_RC(TE_TA_UNIX, TE_EINVAL);
    }
    
    nr_req_num = req_num;
    
    /* Allocate memory for control blocks and TX/RX buffers */
    if ((nr_rx_cbs = calloc(req_num, sizeof(*nr_rx_cbs))) == NULL ||
        (nr_tx_cbs = calloc(req_num, sizeof(*nr_tx_cbs))) == NULL ||
        (rx_buf = calloc(req_num, 1)) == NULL ||
        (tx_buf = malloc(req_num)) == NULL)
    {
        nr_error = TE_RC(TE_TA_UNIX, TE_ENOMEM); 
        goto cleanup;
    }

    /* Fill control blocks */
    for (i = 0; i < req_num; i++)
    {
        tx_buf[i] = i;
        
        nr_rx_cbs[i].aio_fildes = nr_tx_cbs[i].aio_fildes = s;
        nr_rx_cbs[i].aio_buf = rx_buf + i;
        nr_tx_cbs[i].aio_buf = tx_buf + i;
        nr_rx_cbs[i].aio_nbytes = nr_tx_cbs[i].aio_nbytes = 1;
        nr_rx_cbs[i].aio_lio_opcode = LIO_READ;
        nr_tx_cbs[i].aio_lio_opcode = LIO_WRITE;
        
        nr_rx_cbs[i].aio_sigevent.sigev_notify = 
            nr_tx_cbs[i].aio_sigevent.sigev_notify = SIGEV_THREAD;
        
        nr_rx_cbs[i].aio_sigevent.sigev_notify_function =
            nr_tx_cbs[i].aio_sigevent.sigev_notify_function = nr_callback;
            
        nr_rx_cbs[i].aio_sigevent.sigev_value.SIVAL_PTR = nr_rx_cbs + i;
        nr_tx_cbs[i].aio_sigevent.sigev_value.SIVAL_PTR = nr_tx_cbs + i;
    }
    
    /* Post first requests */
    /* Attention! If read request is posted first, nothing works */
    NR_POST_WRITE;
    NR_POST_READ;
    
    
    /* Wait until all requests are processed */
    while (nr_completed_rx < req_num && nr_completed_tx < req_num &&
           nr_error == 0)
    {
        for (i = 0; i < nr_next_rx; i++)
        {
            int rc = nr_aio_error_func(nr_rx_cbs + i);
            
            if (rc != 0 && rc != EINPROGRESS)
            {
                nr_error = TE_OS_RC(TE_TA_UNIX, errno); 
                ERROR("Read request %d failed with errno %r", i, nr_error);
                goto cleanup;
            }
        }

        for (i = 0; i < nr_next_tx; i++)
        {
            int rc = nr_aio_error_func(nr_tx_cbs + i);
            
            if (rc != 0 && rc != EINPROGRESS)
            {
                nr_error = TE_OS_RC(TE_TA_UNIX, errno); 
                ERROR("Write request %d failed with errno %r", i, nr_error);
                goto cleanup;
            }
        }
        sleep(1);
    }
    
    if (nr_error != 0)
        goto cleanup;
        
    /* Check that data are not corrupted */
    memset(tx_buf, 0, req_num);
    for (i = 0; i < req_num; i++)
    {
        if (tx_buf[rx_buf[i]] > 0)
        {
            ERROR("Byte %d is received twice", rx_buf[i]);
            nr_error = TE_RC(TE_TA_UNIX, TE_EFAIL); 
            goto cleanup;
        }
        
        tx_buf[rx_buf[i]] = 1;
    }
    
    /* It's bit excessive, but... */
    for (i = 0; i < req_num; i++)
    {
        if (tx_buf[i] == 0)
        {
            ERROR("Byte %d is not received", i);
            nr_error = TE_RC(TE_TA_UNIX, TE_EFAIL); 
            goto cleanup;
        }
    }

cleanup:
    nr_req_num = nr_next_rx = nr_next_tx = 
    nr_completed_rx = nr_completed_tx = 0;
    nr_aio_cancel_func(s, NULL);
    free(nr_rx_cbs); nr_rx_cbs = NULL;
    free(nr_tx_cbs); nr_tx_cbs = NULL;
    
    free(rx_buf); free(tx_buf);
    
    return nr_error;
#else /* !SIGEV_THREAD */
    UNUSED(s);
    UNUSED(req_num);
    ERROR("SIGEV_THREAD notification is not supported");
    return TE_RC(TE_TA, TE_ENOSYS);
#endif /* !SIGEV_THREAD */
}

TARPC_FUNC(nested_requests_test, {}, 
{
    if (tarpc_find_func(in->common.lib_flags, "aio_read",
                        (api_func *)&nr_aio_read_func) != 0 ||
        tarpc_find_func(in->common.lib_flags, "aio_write",
                        (api_func *)&nr_aio_write_func) != 0 ||
        tarpc_find_func(in->common.lib_flags, "aio_error",
                        (api_func *)&nr_aio_error_func) != 0 ||
        tarpc_find_func(in->common.lib_flags, "aio_cancel",
                        (api_func *)&nr_aio_cancel_func) != 0 ||
        tarpc_find_func(in->common.lib_flags, "aio_return",
                        (api_func *)&nr_aio_return_func) != 0)
    {
        ERROR("Failed to resolve asynchronous AIO functions");
        out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOENT); 
        out->retval = -1;
    }
    else
    {
        int rc;
        
        MAKE_CALL(rc = func(in->s, in->req_num));
        
        out->common._errno = rc;
        out->retval = rc == 0 ? 0 : -1;
    }
}
)

#endif /* HAVE_AIO_H */

/**
 * Epoll timeout, ZF reactor is called during that time, milliseconds.
 * The plugin blocks RPC server for this time.
 */
#define ZF_SHIM_RPCS_PLUGIN_DELAY 0

/** How long wait for a library loading, milliseconds. */
#define ZF_SHIM_PLUGIN_AWAIT_LIB_DELAY 50

/**
 * The context of RPC plugin which interacts with ZF shim.
 */
struct zf_reactor_context {
  int       fd;         /**< epoll file descriptior */
  api_func  epoll_wait; /**< function @b epoll_wait inside ZF shim */
  api_func  close;      /**< function @b close inside ZF shim */
};

/**
 * Create the plugin @p context and initializing a RPC server plugin
 *
 * @param context   Context of RPC server plugin
 *
 * @return Status code
 */
te_errno
zf_shim_rpcs_plugin_install(void **context)
{
    RPCSERVER_PLUGIN_AWAIT_DYNAMIC_LIBRARY(ZF_SHIM_PLUGIN_AWAIT_LIB_DELAY);

    api_func func_epoll_create;
    api_func func_epoll_wait;
    api_func func_close;
    struct zf_reactor_context *zcont;

/**
 * Find a function or fail with error if it is impossible
 *
 * @param _func     function pointer
 * @param _name     function name
 */
#define FIND_FUNC(_func, _name)                                             \
    do {                                                                    \
        if (tarpc_find_func(TARPC_LIB_DEFAULT, #_name, &_func) != 0)        \
        {                                                                   \
            ERROR("%s(): Failed to find \"" #_name "\" function "           \
                  "in the library under test",                              \
                  __FUNCTION__);                                            \
            return TE_RC(TE_TA_UNIX, TE_EFAIL);                             \
        }                                                                   \
    } while (0)

    FIND_FUNC(func_epoll_create, epoll_create);
    FIND_FUNC(func_epoll_wait, epoll_wait);
    FIND_FUNC(func_close, close);

#undef FIND_FUNC

    zcont = calloc(sizeof(zcont), 1);
    if (zcont == NULL)
    {
        ERROR("%s(): Memory allocation failure", __FUNCTION__);
        return TE_RC(TE_TA_UNIX, TE_ENOMEM);
    }
    zcont->fd = func_epoll_create(0);
    if (zcont->fd == -1)
    {
        ERROR("%s(): Failed to open an epoll file descriptor",
              __FUNCTION__);
        free(zcont);
        return TE_OS_RC(TE_TA_UNIX, errno);
    }
    zcont->epoll_wait = func_epoll_wait;
    zcont->close = func_close;

    *context = zcont;
    RING("Installation of plugin is complete (fd=%d)", zcont->fd);
    return 0;
}

/**
 * Execute a RPC server plugin action
 *
 * @param call_list List of pending asynchronous RPC calls
 * @param context   Context of RPC server plugin
 *
 * @return Status code
 */
te_errno
zf_shim_rpcs_plugin_action(deferred_call_list *call_list, void *context)
{
    RPCSERVER_PLUGIN_AWAIT_RPC_CALL(call_list,
                                    ZF_SHIM_PLUGIN_AWAIT_LIB_DELAY);

    int retval;
    struct zf_reactor_context *zcont = context;
    struct epoll_event ev;

    retval = zcont->epoll_wait(
                zcont->fd, &ev, 1, ZF_SHIM_RPCS_PLUGIN_DELAY);
    if (retval != 0)
    {
        ERROR("%s(): Failed to wait an I/O event on the epoll "
              "file descriptor",
              __FUNCTION__);
        return TE_OS_RC(TE_TA_UNIX, errno);
    }

    return 0;
}

/**
 * Deinitialize a RPC server plugin and remove the plugin @p context
 *
 * @param context   Context of RPC server plugin
 *
 * @return Status code
 */
te_errno
zf_shim_rpcs_plugin_uninstall(void **context)
{
    struct zf_reactor_context *zcont = *context;
    RING("Uninstallation of plugin is complete (fd=%d)", zcont->fd);
    zcont->close(zcont->fd);
    free(zcont);
    return 0;
}

/*-------------- send_msg_warm_flow() --------------------------*/

/** Send function context. */
typedef struct send_func_ctx {
    te_void_func    func;           /**< Send function pointer. */
    api_func        func_alloc;     /**< Pointer to function for
                                       buffer allocation. */
    api_func        func_free;      /**< Pointer to function for
                                       buffer releasing. */
    tarpc_lib_flags lib_flags;      /**< How to resolve functions name. */

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    /*
     * These fields are used only for
     * tarpc_send_func_onload_zc_send_user_buf().
     */
    uint8_t *user_buf;            /**< Registered ZC buffer for
                                       onload_zc_send() */
    size_t user_buf_len;          /**< Length of the registered
                                       buffer */
    onload_zc_handle buf_handle;  /**< Handle returned for the buffer
                                       by onload_zc_register_buffers() */
    zc_compl_bufs compl_bufs;     /**< Queue of sent data chunks waiting for
                                       completion */
#endif
} send_func_ctx;

/**
 * Resolve function, save pointer in send_func_ctx member.
 *
 * @param m_      Structure member where to save pointer.
 * @param func_   Function name.
 */
#define TARPC_SEND_FUNC_FIND(m_, func_) \
    do {                                                              \
        if (ctx->m_ == NULL)                                          \
        {                                                             \
            te_errno _rc;                                             \
            _rc = tarpc_find_func(ctx->lib_flags, func_,              \
                                  (api_func *)&ctx->m_);              \
            if (_rc != 0)                                             \
            {                                                         \
                te_rpc_error_set(_rc, "failed to find %s", func_);    \
                return -1;                                            \
            }                                                         \
        }                                                             \
    } while (0)

/**
 * Call send function with specified parameters.
 *
 * @param func_     Function pointer.
 * @param fd_       File descriptor.
 * @param ...       Remaining send function parameters.
 */
#define CALL_SEND_FUNC(func_, fd_...) \
    ((ssize_t (*)(int, ...))(func_))(fd_)

/**
 * Wrapper for send().
 *
 * @param ctx     Send function context.
 * @param fd      File descriptor.
 * @param buf     Buffer.
 * @param len     Number of bytes to send.
 * @param flags   Flags to pass to send function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_send(send_func_ctx *ctx,
                     int fd, const void *buf, size_t len, int flags)
{
    TARPC_SEND_FUNC_FIND(func, "send");

    return CALL_SEND_FUNC(ctx->func, fd, buf, len, flags);
}

/**
 * Wrapper for sendto().
 *
 * @param ctx     Send function context.
 * @param fd      File descriptor.
 * @param buf     Buffer.
 * @param len     Number of bytes to send.
 * @param flags   Flags to pass to send function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_sendto(send_func_ctx *ctx,
                       int fd, const void *buf, size_t len, int flags)
{
    TARPC_SEND_FUNC_FIND(func, "sendto");

    return CALL_SEND_FUNC(ctx->func, fd, buf, len, flags, NULL, 0);
}

/**
 * Wrapper for sendto() allowing to pass all parameters.
 *
 * @param ctx       Send function context.
 * @param fd        File descriptor.
 * @param buf       Buffer.
 * @param len       Number of bytes to send.
 * @param flags     Flags to pass to send function.
 * @param dest_addr Destination address
 * @param addrlen   Size of @p dest_addr
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_sendto_ext(send_func_ctx *ctx,
                           int fd, const void *buf, size_t len, int flags,
                           const struct sockaddr *dest_addr, socklen_t addrlen)
{
    TARPC_SEND_FUNC_FIND(func, "sendto");

    return CALL_SEND_FUNC(ctx->func, fd, buf, len, flags, dest_addr, addrlen);
}

/**
 * Wrapper for sendmsg().
 *
 * @param ctx     Send function context.
 * @param fd      File descriptor.
 * @param buf     Buffer.
 * @param len     Number of bytes to send.
 * @param flags   Flags to pass to send function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_sendmsg(send_func_ctx *ctx,
                        int fd, const void *buf, size_t len, int flags)
{
    struct msghdr   msg;
    struct iovec    iov;

    TARPC_SEND_FUNC_FIND(func, "sendmsg");

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return CALL_SEND_FUNC(ctx->func, fd, &msg, flags);
}

/**
 * Send data with the help of onload_zc_send(). This function will use the
 * single onload_zc_mmsg structure, and will allocate as many Onload
 * buffers as necessary to contain all the data.
 *
 * @param func_zc_send      Pointer to onload_zc_send().
 * @param func_alloc        Pointer to onload_zc_alloc_buffers().
 * @param func_release      Pointer to onload_zc_release_buffers().
 * @param fd                File descriptor.
 * @param buf               Buffer with data.
 * @param len               Number of bytes to send.
 * @param flags             Flags to pass to onload_zc_send().
 *
 * @return @c -1 on failure, number of bytes sent on success.
 */
static ssize_t
onload_zc_send_data(api_func_ptr func_zc_send, api_func func_alloc,
                    api_func func_release,
                    int fd, const char *buf, size_t len, int flags)
{
    struct onload_zc_mmsg   msg;
    struct onload_zc_iovec *onload_iov = NULL;
    size_t                  iov_len;
    size_t                  data_sent = 0;
    size_t                  sent_bufs = 0;
    size_t                  i;
    int                     rc;
    ssize_t                 result = 0;

    rc = alloc_fill_zc_bufs(func_alloc, func_release,
                            fd, &onload_iov,
                            &iov_len, buf, len);
    if (rc != 0)
        return -1;

    memset(&msg, 0, sizeof(msg));
    msg.fd = fd;
    msg.msg.iov = onload_iov;
    msg.msg.msghdr.msg_iovlen = iov_len;

    rc = func_zc_send(&msg, 1, flags);
    if (rc < 0)
    {
        ERROR("onload_zc_send() failed with errno %r",
              te_rc_os2te(-rc));
        errno = -rc;
        result = -1;
    }
    else
    {
        if (rc > 1)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                             "onload_zc_send() returned too big value %d",
                             rc);
            result = -1;
        }
        else
        {
            result = msg.rc;
            if (result < 0)
            {
                ERROR("onload_zc_send() returned error %r in msg.rc",
                      te_rc_os2te(-msg.rc));
                errno = -msg.rc;
                result = -1;
            }
            else
            {
                /* In case of ONLOAD_MSG_WARM nothing is sent
                 * actually and we have to release all the buffers.
                 */
                if (!(flags & ONLOAD_MSG_WARM))
                {
                    for (i = 0; i < iov_len; i++)
                    {
                        data_sent += onload_iov[i].iov_len;
                        if (data_sent <= (size_t)msg.rc)
                            sent_bufs = i + 1;
                        else
                            break;
                    }
                }
            }
        }
    }

    if (sent_bufs < iov_len)
    {
        rc = free_onload_zc_buffers(func_release, fd,
                                    onload_iov + sent_bufs,
                                    iov_len - sent_bufs);
        if (rc < 0)
            result = -1;
    }

    free(onload_iov);

    return result;
}

#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
/**
 * Wrapper for onload_zc_send() used with registered ZC buffer.
 * Can be passed to rpc_pattern_sender().
 *
 * @param ctx     Send function context.
 * @param fd      File descriptor.
 * @param buf     Buffer with data.
 * @param len     Number of bytes to send.
 * @param flags   Flags to pass to send function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_onload_zc_send_user_buf(send_func_ctx *ctx,
                                        int fd, const void *buf,
                                        size_t len, int flags)
{
    uint8_t *p_start;
    size_t len_avail;
    zc_compl_buf *first_buf;
    zc_compl_buf *last_buf;
    zc_compl_buf *new_buf;

    struct onload_zc_mmsg mmsg;
    struct onload_zc_iovec iov;
    int rc;

    TARPC_SEND_FUNC_FIND(func, "onload_zc_send");

    /*
     * We have a big registered buffer. We keep a queue of its chunks
     * which are sent but not yet completed, stored in the order of their
     * sending.
     *
     * Each time we need a new chunk, we try to find a place in the big
     * buffer not assigned to some other chunk. If the queue is empty, new
     * chunk is allocated at the beginning of the big buffer. If some chunks
     * are already in the queue, we look either (1) at the space between the
     * last chunk in the queue and the end of big buffer (if the last chunk
     * in the queue has greater address than the first chunk) or (2) at the
     * space between the end of the last chunk and the beginning of the
     * first chunk otherwise. In (1), if there is not enough space at the
     * end of the big buffer, we try to allocate a new chunk at the
     * beginning of the big buffer (this way the last chunk may get smaller
     * address than the first one in the queue).
     *
     * After sending a new data chunk it is added to the end of the queue
     * and stays in the queue until completion message is received for it.
     */

    if (!TAILQ_EMPTY(&ctx->compl_bufs))
    {
        /*
         * Try to wait for completions of buffers sent previously;
         * do it before sending new data so that if there is some
         * problem here, returned error will not mask successful
         * queueing of new data.
         *
         * Completion event for the last buffer sent with this
         * function is checked in sockts_send_func_ctx_clean_zc_buf().
         */
        rc = wait_for_zc_completion(&ctx->compl_bufs, TRUE, FALSE, 0);
        if (rc < 0)
            return -1;
    }

    if (TAILQ_EMPTY(&ctx->compl_bufs))
    {
        p_start = ctx->user_buf;
        len_avail = ctx->user_buf_len;
    }
    else
    {
        first_buf = TAILQ_FIRST(&ctx->compl_bufs);
        last_buf = TAILQ_LAST(&ctx->compl_bufs, zc_compl_bufs);
        len_avail = 0;

        /*
         * Pointers may be equal if only the single buffer is in the queue.
         */
        if (last_buf->ptr >= first_buf->ptr)
        {
            p_start = last_buf->ptr + last_buf->len;
            len_avail = ctx->user_buf_len - last_buf->len -
                        (last_buf->ptr - ctx->user_buf);

            if (len_avail < len)
            {
                p_start = ctx->user_buf;
                len_avail = first_buf->ptr - ctx->user_buf;
            }
        }
        else
        {
            p_start = last_buf->ptr + last_buf->len;
            len_avail = first_buf->ptr - p_start;
        }
    }

    if (len_avail < len)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                         "%s(): not enough space for requested "
                         "data length", __FUNCTION__);
        return -1;
    }

    new_buf = calloc(1, sizeof(*new_buf));
    if (new_buf == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "%s(): failed to allocate memory for zc_compl_buf "
                         "structure", __FUNCTION__);
        return -1;
    }
    new_buf->fd = fd;
    new_buf->ptr = p_start;
    new_buf->len = len;

    memset(&mmsg, 0, sizeof(mmsg));
    mmsg.fd = fd;
    mmsg.msg.iov = &iov;
    mmsg.msg.msghdr.msg_iovlen = 1;

    memset(&iov, 0, sizeof(iov));
    iov.app_cookie = new_buf;
    iov.iov_base = p_start;
    iov.iov_len = len;
    iov.buf = ctx->buf_handle;

    memcpy(iov.iov_base, buf, len);

    rc = ((api_func_ptr)(ctx->func))(&mmsg, 1, flags);
    if (rc < 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -rc),
                         "onload_zc_send() returned negative number");
        rc = -1;
    }
    else if (rc == 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                         "onload_zc_send() returned zero");
        rc = -1;
    }
    else if (rc > 1)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                         "onload_zc_send() returned too big number");
        rc = -1;
    }
    else
    {
        if (mmsg.rc < 0)
        {
            ERROR("%s(): onload_zc_send() returned mmsg.rc=%d ('%s')",
                  __FUNCTION__, mmsg.rc, strerror(-mmsg.rc));
            errno = -mmsg.rc;
            rc = -1;
        }
        else
        {
            rc = mmsg.rc;
        }
    }

    if (rc < 0)
        free(new_buf);
    else
        TAILQ_INSERT_TAIL(&ctx->compl_bufs, new_buf, links);

     return rc;
}

/**
 * This handler is called from pattern_sender() when it encounters
 * @c POLLERR event. Completion events should be processed to
 * finalize sending and free space for new data.
 *
 * @param data          Pointer to send_func_ctx structure.
 * @param s             Socket on which poll() was called (not used).
 *
 * @return @c 0 on success, @c -1 on failure.
 */
int
tarpc_zc_send_pollerr_handler(void *data, int s)
{
    send_func_ctx *ctx = (send_func_ctx *)data;

    UNUSED(s);

    return wait_for_zc_completion(&ctx->compl_bufs, TRUE, FALSE, 0);
}
#endif

/**
 * Wrapper for onload_zc_send().
 *
 * @param ctx     Send function context.
 * @param fd      File descriptor.
 * @param buf     Buffer.
 * @param len     Number of bytes to send.
 * @param flags   Flags to pass to send function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
tarpc_send_func_onload_zc_send(send_func_ctx *ctx,
                               int fd, const void *buf,
                               size_t len, int flags)
{
    TARPC_SEND_FUNC_FIND(func, "onload_zc_send");
    TARPC_SEND_FUNC_FIND(func_alloc, "onload_zc_alloc_buffers");
    TARPC_SEND_FUNC_FIND(func_free, "onload_zc_release_buffers");

    return onload_zc_send_data((api_func_ptr)ctx->func, ctx->func_alloc,
                               ctx->func_free, fd, buf, len,
                               flags);
}

/**
 * TARPC send function pointer type.
 */
typedef ssize_t (*tarpc_send_func_ptr)(void *, ...);

/**
 * Get pointer to send function wrapper.
 *
 * @param func_name       Function name.
 *
 * @return Pointer to wrapper on success, @c NULL on failure.
 */
static tarpc_send_func_ptr
tarpc_send_func_find(const char *func_name)
{
    if (strcmp(func_name, "send") == 0)
        return (tarpc_send_func_ptr)&tarpc_send_func_send;
    else if (strcmp(func_name, "sendto") == 0)
        return (tarpc_send_func_ptr)&tarpc_send_func_sendto;
    else if (strcmp(func_name, "sendmsg") == 0)
        return (tarpc_send_func_ptr)&tarpc_send_func_sendmsg;
    else if (strcmp(func_name, "onload_zc_send") == 0)
        return (tarpc_send_func_ptr)&tarpc_send_func_onload_zc_send;
#ifdef ONLOAD_SO_ONLOADZC_COMPLETE
    else if (strcmp(func_name, "onload_zc_send_user_buf") == 0)
        return (tarpc_send_func_ptr)&tarpc_send_func_onload_zc_send_user_buf;
#endif

    ERROR("%s: unknown function '%s'", __FUNCTION__, func_name);
    return NULL;
}

/**
 * Send data from one or two sockets for a while, sometimes passing
 * @c ONLOAD_MSG_WARM flag to send function.
 *
 * @note If both sockets are specified, this function will
 *       use nonblocking send.
 *
 * @param func_name     Name of send function to use.
 * @param fd1           First socket (not used if negative).
 * @param fd2           Second socket (not used if negative).
 * @param buf_size_min  Minimum number of bytes to pass to
 *                      send function at once.
 * @param buf_size_max  Maximum number of bytes to pass to
 *                      send function at once.
 * @param time2run      How long to send data, in seconds.
 * @param sent1         Where to save number of bytes sent
 *                      from the first socket.
 * @param sent2         Where to save number of bytes sent
 *                      from the second socket.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
int
send_msg_warm_flow(const char *func_name,
                   int fd1, int fd2,
                   size_t buf_size_min, size_t buf_size_max,
                   unsigned int time2run,
                   uint64_t *sent1, uint64_t *sent2)
{
    api_func_ptr        fill_buf;
    tarpc_send_func_ptr send_func;
    te_errno            rc = 0;

    send_func_ctx ctx;

    struct timeval tv_start;
    struct timeval tv_cur;

    uint64_t normal_sent1 = 0;
    uint64_t warm_sent1 = 0;

    uint64_t normal_sent2 = 0;
    uint64_t warm_sent2 = 0;

    te_bool    first_fd = FALSE;
    int        fd;
    uint64_t  *normal_sent_p = NULL;
    uint64_t  *warm_sent_p = NULL;
    uint64_t  *sent_p = NULL;

    char    *buf = NULL;
    int      flags = 0;
    int      add_flags = 0;
    size_t   send_len = 0;

    int      saved_errno = errno;

    tarpc_pat_gen_arg gen_arg = {0};

    if (fd1 >= 0 && fd2 >= 0)
    {
        add_flags = MSG_DONTWAIT;
    }
    else if (fd1 < 0 && fd2 < 0)
    {
        *sent1 = 0;
        *sent2 = 0;
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));

    send_func = tarpc_send_func_find(func_name);
    if (send_func == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "failed to resolve send function");
        return -1;
    }

    rc = tarpc_find_func(TARPC_LIB_DEFAULT,
                         "tarpc_fill_buff_with_sequence",
                         (api_func *)&fill_buf);
    if (rc != 0)
    {
        te_rpc_error_set(
                rc, "failed to resolve tarpc_fill_buff_with_sequence");
        return -1;
    }

    buf = calloc(buf_size_max, 1);
    if (buf == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                         "failed to allocate memory");
        return -1;
    }

    rc = gettimeofday(&tv_start, NULL);
    if (rc < 0)
    {
        te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                         "gettimeofday() failed");
        rc = -1;
        goto cleanup;
    }

    while (TRUE)
    {
        rc = gettimeofday(&tv_cur, NULL);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "gettimeofday() failed");
            rc = -1;
            goto cleanup;
        }

        if (TE_US2SEC(TIMEVAL_SUB(tv_cur, tv_start)) > (int)time2run)
            break;

        first_fd = !first_fd;
        if ((first_fd && fd1 < 0) ||
            (!first_fd && fd2 < 0))
            first_fd = !first_fd;

        if (first_fd)
        {
            fd = fd1;
            normal_sent_p = &normal_sent1;
            warm_sent_p = &warm_sent1;
            sent_p = sent1;
        }
        else
        {
            fd = fd2;
            normal_sent_p = &normal_sent2;
            warm_sent_p = &warm_sent2;
            sent_p = sent2;
        }

        if (rand_range(0, 1) == 1)
            flags = ONLOAD_MSG_WARM;
        else
            flags = 0;

        send_len = rand_range(buf_size_min, buf_size_max);
        gen_arg.coef1 = flags == 0 ? *normal_sent_p : *warm_sent_p;
        rc = fill_buf(buf, send_len, &gen_arg);
        if (rc != 0)
        {
            te_rpc_error_set(rc, "filling buffer with sequence failed");
            rc = -1;
            goto cleanup;
        }

        rc = send_func(&ctx, fd, buf, send_len, flags | add_flags);
        if (rc < 0)
        {
            if (!((add_flags & MSG_DONTWAIT) && te_rpc_error_get_num() == 0
                  && errno == EAGAIN))
            {
                goto cleanup;
            }
            else
            {
                errno = saved_errno;
                rc = 0;
            }
        }

        if (flags == 0)
            *normal_sent_p += rc;
        else
            *warm_sent_p += rc;

        if (sent_p != NULL)
            *sent_p = *normal_sent_p;
    }
    rc = 0;

cleanup:

    free(buf);
    return rc;
}

TARPC_FUNC_STATIC(send_msg_warm_flow, {},
{
    MAKE_CALL(out->retval = func(in->func_name.func_name_val,
                                 in->fd1, in->fd2, in->buf_size_min,
                                 in->buf_size_max, in->time2run,
                                 &out->sent1, &out->sent2));
})

/**
 * Send data @p send_num number times use delays between calls if required.
 * In the final data transmission is triggered using socket options
 * TCP_CORK or TCP_NODELAY.
 *
 * @param lib_flags     How to resolve function name
 * @param fd            Socket descriptor.
 * @param fd_aux        Auxiliary socket descriptor used (if not negative)
 *                      to notify receiver that sending will soon begin.
 * @param size_min      Minimum data amount to send by one call.
 * @param size_max      Maximum data amount to send by one call.
 * @param send_num      Send calls number.
 * @param length        How much data to send (in all send calls combined).
 * @param send_usleep   Sleep between @c send() calls if non-negative,
 *                      microseconds.
 * @param tcp_nodelay   Use option TCP_NODELAY to force data transmission
 *                      if @c TRUE, otherwise - TCP_CORK.
 * @param no_trigger    If @c TRUE, do not trigger final transmission
 *                      with TCP_CORK or TCP_NODELAY.
 * @param te_err        Test environment error.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
many_send_cork(tarpc_lib_flags lib_flags, int fd, int fd_aux,
               size_t size_min, size_t size_max,
               size_t send_num, size_t length,
               int send_usleep, te_bool tcp_nodelay,
               te_bool no_trigger,
               te_errno *te_err)
{
    api_func setsockopt_f;
    api_func send_f;
    char *buf = NULL;
    size_t i;
    int val = tcp_nodelay ? 1 : 0;
    int len;
    int rc;

    ssize_t cur_min;
    ssize_t cur_max;
    ssize_t cur_length;

    if ((rc = tarpc_find_func(lib_flags, "send", &send_f)) != 0 ||
        (rc = tarpc_find_func(lib_flags, "setsockopt", &setsockopt_f)) != 0)
    {
        *te_err = rc;
        return -1;
    }

    buf = TE_ALLOC(size_max);
    if (buf == NULL)
    {
        *te_err = TE_RC(TE_TA_UNIX, TE_ENOMEM);
        return -1;
    }

    if (fd_aux >= 0)
    {
        rc = send_f(fd_aux, buf, 1, 0);
        if (rc < 0)
        {
            ERROR("%s(): failed to send data via auxiliary socket",
                  __FUNCTION__);
            *te_err = TE_RC(TE_TA_UNIX, errno_h2rpc(errno));
            free(buf);
            return -1;
        }
    }

    cur_length = length;

    for (i = 0; i < send_num; i++)
    {
        cur_min = cur_length - size_max * (send_num - i - 1);
        cur_min = MAX(cur_min, (ssize_t)size_min);
        cur_max = cur_length - size_min * (send_num - i - 1);
        cur_max = MIN(cur_max, (ssize_t)size_max);
        if (cur_max < cur_min)
        {
            ERROR("%s(): incorrect packet length boundaries, "
                  "perhaps provided arguments are inconsistent",
                  __FUNCTION__);
            *te_err = TE_RC(TE_TA_UNIX, TE_EFAIL);
            rc = -1;
            break;
        }

        len = rand_range(cur_min, cur_max);
        te_fill_buf(buf, len);
        rc = send_f(fd, buf, len, 0);
        if (rc != len)
        {
            ERROR("Send call returned unexpected value %d instead of %d",
                  rc, len);
            if (rc >= 0)
                *te_err = TE_RC(TE_TA_UNIX, TE_EFAIL);
            rc = -1;
            break;
        }

        cur_length -= len;

        if (send_usleep >= 0)
            usleep(send_usleep);
    }

    if (cur_length > 0)
    {
        ERROR("%s(): not all requested data was sent", __FUNCTION__);
        *te_err = TE_RC(TE_TA_UNIX, TE_EFAIL);
        rc = -1;
    }

    if (rc >= 0 && !no_trigger)
    {
        if (tcp_nodelay)
            rc = setsockopt_f(fd, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
        else
            rc = setsockopt_f(fd, SOL_TCP, TCP_CORK, &val, sizeof(val));
    }

    free(buf);
    return rc;
}

TARPC_FUNC_STATIC(many_send_cork, {},
{
    te_errno te_err = 0;

    MAKE_CALL(out->retval = func(in->common.lib_flags, in->fd, in->fd_aux,
                                 in->size_min, in->size_max, in->send_num,
                                 in->length, in->send_usleep,
                                 in->tcp_nodelay, in->no_trigger, &te_err));
    if (te_err != 0)
        out->common._errno = te_err;
})

#ifdef HAVE_DECL_ONLOAD_SOCKET_UNICAST_NONACCEL
/* Supported from the Onload branch eol6 */
TARPC_FUNC(onload_socket_unicast_nonaccel, {},
{
    MAKE_CALL(out->fd = func(domain_rpc2h(in->domain),
                             socktype_rpc2h(in->type),
                             proto_rpc2h(in->proto)));
})
#endif

/**
 * Call epoll_wait() in a loop until it returns non-zero (expect
 * at most one event).
 *
 * @param lib_flags     How to resolve function epoll_wait().
 * @param epfd          Epoll file descriptor.
 * @param event         Where to save event reported by epoll_wait().
 * @param timeout       Timeout in milliseconds.
 * @param te_err        If some error not related to epoll_wait()
 *                      was encountered, it will be saved here.
 *
 * @return epoll_wait() result on success, @c -1 in case of failure.
 */
static int
epoll_wait_loop(tarpc_lib_flags lib_flags, int epfd, struct epoll_event *event,
                int timeout, te_errno *te_err)
{
    int          rc = 0;
    api_func     func_epoll_wait;

    rc = tarpc_find_func(lib_flags, "epoll_wait", &func_epoll_wait);
    if (rc != 0)
    {
        ERROR("%s(): failed to resolve epoll_wait() function",
              __FUNCTION__);
        *te_err = rc;
        return -1;
    }

    while (TRUE)
    {
        rc = func_epoll_wait(epfd, event, 1, timeout);
        if (rc != 0)
            break;
    }

    return rc;
}

TARPC_FUNC_STATIC(epoll_wait_loop, {},
{
    struct epoll_event  event;
    tarpc_epoll_event  *tarpc_evt = NULL;
    te_errno            te_err = 0;

    MAKE_CALL(out->retval = func(in->common.lib_flags, in->epfd,
                                 &event, in->timeout, &te_err));
    if (te_err != 0)
        out->common._errno = te_err;

    if (out->retval > 0)
    {
        tarpc_evt = calloc(1, sizeof(*tarpc_evt));
        if (tarpc_evt == NULL)
        {
            ERROR("%s(): out of memory", __FUNCTION__);
            out->common._errno = TE_RC(TE_TA_UNIX, TE_ENOMEM);
            out->retval = -1;
            return;
        }

        tarpc_evt->events =
            epoll_event_h2rpc(event.events);
        /* TODO: should be substituted by correct handling of union */
        tarpc_evt->data.type = TARPC_ED_INT;
        tarpc_evt->data.tarpc_epoll_data_u.fd = event.data.fd;

        out->events.events_len = 1;
        out->events.events_val = tarpc_evt;
    }
})

/**
 * Get TCP state from a tool's output (netstat, onload_stackdump,
 * zf_stackdump).
 *
 * @param tool        Command line of the tool.
 * @param loc_addr    Local address.
 * @param rem_addr    Remote address.
 * @param state       Where to save obtained TCP state.
 * @param found       Will be set to @c TRUE if a socket was found.
 *
 * @return Status code.
 */
static te_errno
tcp_get_state_from_tool(const char *tool,
                        struct sockaddr *loc_addr,
                        struct sockaddr *rem_addr,
                        rpc_tcp_state *state, te_bool *found)
{
#define STATE_LEN 256
    te_string  cmd = TE_STRING_INIT;
    FILE      *f = NULL;
    char       buf[STATE_LEN];
    ssize_t    rc;
    te_errno   res = 0;
    pid_t      cmd_pid;

    char       loc_addr_str[INET6_ADDRSTRLEN] = "";
    char       rem_addr_str[INET6_ADDRSTRLEN] = "";

    *found = FALSE;
    *state = RPC_TCP_UNKNOWN;

    if (inet_ntop(loc_addr->sa_family,
                  te_sockaddr_get_netaddr(loc_addr),
                  loc_addr_str, sizeof(loc_addr_str)) == NULL)
    {
        ERROR("%s(): failed to convert local address to string",
              __FUNCTION__);
        res = TE_RC(TE_TA_UNIX, te_rc_os2te(errno));
        goto cleanup;
    }

    if (inet_ntop(rem_addr->sa_family,
                  te_sockaddr_get_netaddr(rem_addr),
                  rem_addr_str, sizeof(rem_addr_str)) == NULL)
    {
        ERROR("%s(): failed to convert remote address to string",
              __FUNCTION__);
        res = TE_RC(TE_TA_UNIX, te_rc_os2te(errno));
        goto cleanup;
    }

    /*
     * grep "[^0-9]\[\?%s\]\?:%hu\(\s.*[^0-9]\|\s\+\)\[\?%s\]\?:%hu\s\+"
     *
     * searches for two addresses in netstat/onload_stackdump output,
     * each of them can look like [addr]:port. Here square brackets are
     * optional because in older versions of onload_stackdump they are
     * not printed, but it is planned to use them for IPv6 addresses
     * in newer version (see SF bug 85164). In "netstat -atn" used for
     * system (non-accelerated) sockets square brackets are not printed.
     *
     * sed "s/^.*\s\([^[:space:]]\+\)\s*$/\1/"
     *
     * removes from string everything except the last word which
     * is assumed to be TCP state name.
     */
    res = te_string_append(
              &cmd,
              "%s | grep \"[^0-9]\\[\\?%s\\]\\?:%hu"
              "\\(\\s.*[^0-9]\\|\\s\\+\\)\\[\\?%s\\]\\?:%hu\\s\\+\" | "
              "sed \"s/^.*\\s\\([^[:space:]]\\+\\)\\s*\\$/\\1/\"",
              tool, loc_addr_str, ntohs(te_sockaddr_get_port(loc_addr)),
              rem_addr_str, ntohs(te_sockaddr_get_port(rem_addr)));
    if (res != 0)
        goto cleanup;

    res = ta_popen_r(cmd.ptr, &cmd_pid, &f);
    if (res != 0)
    {
        ERROR("%s(): ta_popen_r() failed, %r", __FUNCTION__, res);
        goto cleanup;
    }

    rc = fread(buf, 1, STATE_LEN, f);
    if (rc > 0)
    {
        *found = TRUE;

        if (rc >= STATE_LEN)
        {
            res = TE_RC(TE_TA_UNIX, TE_EINVAL);
            buf[STATE_LEN - 1] = '\0';
            ERROR("%s(): too long string for TCP state, '%s'",
                  __FUNCTION__, buf);
            goto cleanup;
        }

        buf[rc] = '\0';
        for (rc = rc - 1; rc >= 0; rc--)
        {
            if (isspace(buf[rc]))
                buf[rc] = '\0';
            else
                break;
        }

        for ( ; rc >= 0; rc--)
        {
            if (buf[rc] == '-')
                buf[rc] = '_';
        }

        if (strcmp(buf, "ESTABLISHED") == 0)
            *state = RPC_TCP_ESTABLISHED;
        else if (strcmp(buf, "SYN_SENT") == 0)
            *state = RPC_TCP_SYN_SENT;
        else if (strcmp(buf, "SYN_RECV") == 0)
            *state = RPC_TCP_SYN_RECV;
        else if (strcmp(buf, "FIN_WAIT1") == 0)
            *state = RPC_TCP_FIN_WAIT1;
        else if (strcmp(buf, "FIN_WAIT2") == 0)
            *state = RPC_TCP_FIN_WAIT2;
        else if (strcmp(buf, "TIME_WAIT") == 0)
            *state = RPC_TCP_TIME_WAIT;
        else if (strcmp(buf, "CLOSED") == 0)
            *state = RPC_TCP_CLOSE;
        else if (strcmp(buf, "CLOSE_WAIT") == 0)
            *state = RPC_TCP_CLOSE_WAIT;
        else if (strcmp(buf, "LAST_ACK") == 0)
            *state = RPC_TCP_LAST_ACK;
        else if (strcmp(buf, "LISTEN") == 0)
            *state = RPC_TCP_LISTEN;
        else if (strcmp(buf, "CLOSING") == 0)
            *state = RPC_TCP_CLOSING;

        if (*state == RPC_TCP_UNKNOWN)
        {
            ERROR("%s(): unknown TCP state '%s'", __FUNCTION__, buf);
            res = TE_RC(TE_TA_UNIX, TE_EINVAL);
        }
    }

cleanup:

    te_string_free(&cmd);

    if (f != NULL)
    {
        te_errno res2;

        res2 = ta_pclose_r(cmd_pid, f);
        if (res2 != 0)
        {
            ERROR("ta_pclose_r() failed, %r", res);
            if (res == 0)
                res = res2;
        }
    }

    return res;
}

/**
 * Get state of a TCP socket from output of one of the tools (netstat,
 * onload_stackdump, zf_stackdump). All the available tools will be
 * tried in search of the socket.
 *
 * @param loc_addr              Local address.
 * @param rem_addr              Remote address.
 * @param onload_stdump         Whether te_onload_stdump should be tried.
 * @param onload_stdump_netstat Whether "te_onload_stdump -z netstat" is
 *                              available.
 * @param zf_stdump             Whether zf_stackdump should be tried.
 * @param state                 Where to save obtained TCP state.
 * @param found                 Will be set to @c TRUE if TCP socket was
 *                              found.
 *
 * @return Status code.
 */
static te_errno
tcp_get_state(struct sockaddr *loc_addr, struct sockaddr *rem_addr,
              te_bool onload_stdump, te_bool onload_stdump_netstat,
              te_bool zf_stdump,
              rpc_tcp_state *state, te_bool *found)
{
    te_errno rc = 0;

    *found = FALSE;

    rc = tcp_get_state_from_tool("netstat -atn",
                                 loc_addr, rem_addr, state, found);

    if (rc == 0 && onload_stdump && !*found)
        rc = tcp_get_state_from_tool("te_onload_stdump netstat",
                                     loc_addr, rem_addr, state, found);

    if (rc == 0 && onload_stdump && !*found)
    {
        rc = tcp_get_state_from_tool((onload_stdump_netstat ?
                                      "te_onload_stdump -z netstat" :
                                      "te_onload_stdump -z dump"),
                                     loc_addr, rem_addr, state, found);
    }

    if (rc == 0 && zf_stdump && !*found)
        rc = tcp_get_state_from_tool("zf_stackdump dump",
                                     loc_addr, rem_addr, state, found);

    return rc;
}

/**
 * Maximum length of bash command.
 */
#define MAX_CMD_LEN (PATH_MAX + 1024)

/**
 * Check whether file in a given location can be executed.
 *
 * @param exists      Will be set to @c TRUE if file exists and
 *                    can be executed.
 * @param path        Format string for path.
 * @param ...         Parameters for format string.
 *
 * @return Status code.
 */
static te_errno
check_program_exists(te_bool *exists, const char *path, ...)
{
    va_list     ap;
    te_errno    rc;
    char        buf[MAX_CMD_LEN];
    te_string   str = TE_STRING_BUF_INIT(buf);

    *exists = FALSE;

    va_start(ap, path);
    rc = te_string_append_va(&str, path, ap);
    va_end(ap);

    if (rc != 0)
    {
        ERROR("%s(): te_string_append_va() failed, %r",
              __FUNCTION__, rc);
        return rc;
    }

    if (access(str.ptr, X_OK) == 0)
        *exists = TRUE;

    return 0;
}

/**
 * Find tools which can be used to obtain information about existing
 * sockets and their states.
 *
 * @param onload_stdump           Will be set to @c TRUE if te_onload_stdump
 *                                is present.
 * @param onload_stdump_netstat   Will be set to @c TRUE if te_onload_stdump
 *                                understands "-z netstat".
 * @param zf_stdump               Will be set to @c TRUE if zf_stackdump
 *                                is present.
 * @return Status code.
 */
static te_errno
find_netstat_tools(te_bool *onload_stdump, te_bool *onload_stdump_netstat,
                   te_bool *zf_stdump)
{
    te_errno rc;

    *onload_stdump = FALSE;
    *onload_stdump_netstat = FALSE;
    *zf_stdump = FALSE;

    char        buf[MAX_CMD_LEN];
    te_string   str = TE_STRING_BUF_INIT(buf);

    rc = check_program_exists(onload_stdump, "%s/te_onload_stdump",
                              ta_dir);
    if (rc != 0)
        return rc;

    if (*onload_stdump)
    {
        int retval;

        rc = te_string_append(&str,
                              "%s/te_onload_stdump -z netstat "
                              "| grep \"unknown command\"", ta_dir);
        if (rc != 0)
            return rc;

        retval = ta_system(str.ptr);

        /*
         * grep's exit status is 1 if no lines were selected, i.e.
         * -z netstat is a known command.
         */

        if (WEXITSTATUS(retval) == 1)
            *onload_stdump_netstat = TRUE;
    }

    return check_program_exists(zf_stdump, "%s/zf_stackdump",
                                ta_dir);
}

/**
 * Wait until TCP socket disappears, measure time it took.
 *
 * @param loc_addr          Local address.
 * @param rem_addr          Remote address.
 * @param last_state_time   Where to save time during which the last
 *                          TCP state was observed (in milliseconds).
 * @param close_time        Where to save time elapsed since socket
 *                          entered one of the closing states (i.e.
 *                          states after TCP_ESTABLISHED) until the
 *                          socket disappeared.
 */
static te_errno
wait_tcp_socket_termination(struct sockaddr *loc_addr,
                            struct sockaddr *rem_addr,
                            int *last_state,
                            int *last_state_time,
                            int *close_time)
{
#define GET_TIME(tv_) \
    do {                                                          \
        retval = gettimeofday(&tv_, NULL);                        \
        if (retval < 0)                                           \
        {                                                         \
            rc = te_rc_os2te(errno);                              \
            ERROR("%s(): gettimeofday() failed with errno %r",    \
                  __FUNCTION__, rc);                              \
            return TE_RC(TE_TA_UNIX, rc);                         \
        }                                                         \
    } while (0)

    int saved_errno = errno;

    rpc_tcp_state   prev_state = RPC_TCP_UNKNOWN;
    rpc_tcp_state   cur_state = RPC_TCP_UNKNOWN;
    te_errno        rc;
    int             retval;
    te_bool         found = FALSE;

    struct timeval  tv_start_close;
    struct timeval  tv_start;
    struct timeval  tv_end;

    te_bool onload_stdump = FALSE;
    te_bool onload_stdump_netstat = FALSE;
    te_bool zf_stdump = FALSE;

    rc = find_netstat_tools(&onload_stdump, &onload_stdump_netstat,
                            &zf_stdump);
    if (rc != 0)
        return rc;

    *last_state = RPC_TCP_UNKNOWN;
    GET_TIME(tv_start);
    memcpy(&tv_start_close, &tv_start, sizeof(tv_start));

    while (TRUE)
    {
        rc = tcp_get_state(loc_addr, rem_addr,
                           onload_stdump, onload_stdump_netstat, zf_stdump,
                           &cur_state, &found);
        if (rc != 0)
            return rc;

        if (!found)
            break;

        if (prev_state != cur_state && prev_state != RPC_TCP_UNKNOWN)
        {
            GET_TIME(tv_start);
            if (prev_state == RPC_TCP_ESTABLISHED ||
                (prev_state == RPC_TCP_SYN_RECV &&
                 cur_state != RPC_TCP_ESTABLISHED))
                memcpy(&tv_start_close, &tv_start, sizeof(tv_start));
        }

        *last_state = cur_state;
        prev_state = cur_state;
        usleep(100000);
    }

    GET_TIME(tv_end);

    *last_state_time = TE_US2MS(TIMEVAL_SUB(tv_end, tv_start));
    *close_time = TE_US2MS(TIMEVAL_SUB(tv_end, tv_start_close));
    errno = saved_errno;

    return 0;
}

TARPC_FUNC_STATIC(wait_tcp_socket_termination, {},
{
    te_errno rc = 0;

    PREPARE_ADDR(loc_addr, in->loc_addr, 0);
    PREPARE_ADDR(rem_addr, in->rem_addr, 0);
    MAKE_CALL(rc = func(loc_addr, rem_addr,
                        &out->last_state, &out->last_state_time,
                        &out->close_time));

    if (rc != 0)
    {
        out->retval = -1;
        out->common._errno = rc;
    }
    else
    {
        out->retval = 0;
    }
})

/**
 * Send @p msg_len packets @p msg_size bytes each with dummy data
 * from connected or non-connected socket with help of
 * @b sendmmsg() function in non-blocking mode.
 *
 * @param lib_flags     How to resolve function name.
 * @param fd            Socket descriptor.
 * @param msg_size      Size of packet.
 * @param msg_len       Number of packets.
 *
 * @return Number of sent packets, or -1 when an error occured.
 */
static int
sendmmsg_nobuf(tarpc_lib_flags lib_flags, int fd, unsigned int msg_size,
               unsigned int msg_len)
{
    api_func                sendmmsg_func;
    struct mmsghdr         *mmsg = NULL;
    char                   *buf = NULL;
    unsigned int            vlen = msg_len;
    size_t                  buf_len = msg_size;
    struct iovec            iov = {NULL, buf_len};
    int                     rc = 0;
    unsigned int            i = 0;

    if ((rc = tarpc_find_func(lib_flags, "sendmmsg", &sendmmsg_func)) != 0)
    {
        ERROR("Failed to find \"sendmmsg\" function.");
        return rc;
    }

    buf = malloc(buf_len);
    if (buf == NULL)
        return TE_RC(TE_TA, TE_ENOMEM);
    iov.iov_base = buf;

    mmsg = calloc(vlen, sizeof(struct mmsghdr));
    if (mmsg == NULL)
    {
        free(buf);
        return TE_RC(TE_TA, TE_ENOMEM);
    }

    for (i = 0; i < vlen; ++i)
    {
        mmsg[i].msg_hdr.msg_iov = &iov;
        mmsg[i].msg_hdr.msg_iovlen = 1;
    }

    rc = sendmmsg_func(fd, mmsg, vlen, MSG_DONTWAIT);

    free(buf);
    free(mmsg);

    return rc;
}

/**
 * Send @p msg_len packets @p msg_size bytes each with dummy data
 * from connected or non-connected socket with help of @b sendmmsg()
 * function in non-blocking mode. Socket will be closed according to
 * @p disconn_way right after @b sendmmsg() call.
 *
 * @note If socket is successfully closed, -1 is assigned to socket
 *       descriptor.
 *
 * @param in        In parameters structure
 * @param out       Out parameters structure
 *
 * @return Number of sent packets (zero in case @p disconn_way == @c EXIT,
 * just to show the function call was succesfull), or -1 when an error occured.
 */
int
sendmmsg_disconnect(tarpc_sendmmsg_disconnect_in *in,
                    tarpc_sendmmsg_disconnect_out *out)
{
    api_func                close_func;
    api_func                connect_func;
    int                     rc = 0;
    int                     fd = in->fd;
    tarpc_disconn_way       way = in->disconn_way;
    struct sockaddr         unspec_addr = {.sa_family = AF_UNSPEC};
    struct sockaddr_storage conn_to_addr_st;
    struct sockaddr        *conn_to_addr;
    socklen_t               conn_to_addr_len;
    pid_t                   pid;

    if (in->connect_to_addr.flags & TARPC_SA_NOT_NULL)
    {
        if (sockaddr_rpc2h(&in->connect_to_addr, SA(&conn_to_addr_st),
                           sizeof(conn_to_addr_st), &conn_to_addr,
                           &conn_to_addr_len) != 0)
        {
            ERROR("Failed to convert sockaddr structure from RPC"
                  "to host representation.");
            return -1;
        }
    }

    if (tarpc_find_func(in->common.lib_flags, "close", &close_func) != 0)
    {
        ERROR("Failed to find \"close\" function.");
        return -1;
    }
    if (tarpc_find_func(in->common.lib_flags, "connect", &connect_func) != 0)
    {
        ERROR("Failed to find \"connect\" function.");
        return -1;
    }

    if (way == EXIT)
    {
        pid = fork();
        if (pid == 0)
        {
            rc = sendmmsg_nobuf(in->common.lib_flags, fd, in->msg_size,
                                in->msg_len);
            RING("%s(): child: sendmmsg_nobuf returned %d",
                 __FUNCTION__, rc);
            if (rc < 0)
                exit(EXIT_FAILURE);
            else
                exit(EXIT_SUCCESS);
        }
        else if (pid > 0)
        {
            int   status = 0;
            pid_t ret_pid = ta_waitpid(pid, &status, 0);
            if (ret_pid < 0 || !WIFEXITED(status) ||
                WEXITSTATUS(status) != EXIT_SUCCESS)
                rc = -1;
            else
                rc = 0;
        }
        else
        {
            ERROR("fork() failed.");
            rc = -1;
        }
    }
    else
    {
        rc = sendmmsg_nobuf(in->common.lib_flags, fd, in->msg_size,
                            in->msg_len);
    }

    switch (way)
    {
        case CLOSE:
            if (close_func(fd) < 0)
                WARN("close() failed");
            else
                fd = -1;
            break;
        case EXIT:
            break;
        case DISCONNECT:
            if (connect_func(fd, &unspec_addr, sizeof(unspec_addr)) < 0)
                ERROR("Connect to AF_UNSPEC failed.");
            if (connect_func(fd, conn_to_addr, conn_to_addr_len) < 0)
                ERROR("Connect to %s failed.", sockaddr_h2str(conn_to_addr));
            break;
    }

    out->fd = fd;

    return rc;
}

TARPC_FUNC(sendmmsg_disconnect, {},
{
    MAKE_CALL(out->retval = func_ptr(in, out));
}
)

/**
 * Get TCP socket state from netstat-like tools.
 *
 * @param loc_addr      Local address/port.
 * @param rem_addr      Remote address/port.
 * @param state         Where to save TCP state.
 * @param found         Will be set to @c TRUE if socket was found.
 *
 * @return Status code.
 */
static te_errno
get_tcp_socket_state(struct sockaddr *loc_addr,
                     struct sockaddr *rem_addr,
                     tarpc_int *state,
                     tarpc_bool *found)
{
    te_errno        rc;
    rpc_tcp_state   sock_state;
    te_bool         sock_found;

    te_bool onload_stdump = FALSE;
    te_bool onload_stdump_netstat = FALSE;
    te_bool zf_stdump = FALSE;

    int saved_errno = errno;

    rc = find_netstat_tools(&onload_stdump, &onload_stdump_netstat,
                            &zf_stdump);
    if (rc != 0)
        return rc;

    rc = tcp_get_state(loc_addr, rem_addr,
                       onload_stdump, onload_stdump_netstat, zf_stdump,
                       &sock_state, &sock_found);
    if (rc != 0)
        return rc;

    if (state != NULL)
        *state = sock_state;
    if (found != NULL)
        *found = sock_found;

    errno = saved_errno;
    return 0;
}

TARPC_FUNC_STATIC(get_tcp_socket_state, {},
{
    te_errno rc = 0;

    PREPARE_ADDR(loc_addr, in->loc_addr, 0);
    PREPARE_ADDR(rem_addr, in->rem_addr, 0);
    MAKE_CALL(rc = func(loc_addr, rem_addr,
                        &out->state, &out->found));

    if (rc != 0)
    {
        out->retval = -1;
        out->common._errno = rc;
    }
    else
    {
        out->retval = 0;
    }
})

/**
 * Try to send packet with size @p len from socket @p s via the function
 * determined by @p send_func.
 *
 * This function is to check behavior of transmitting function
 * with various buffer size passed, e.g. extra large (over 2^31).
 *
 * @note Only TARPC_SEND_FUNC_SEND and TARPC_SEND_FUNC_SENDTO are supported.
 *
 * @param s             Socket descriptor.
 * @param ctx           Send function context.
 * @param len           Size of datagram (can be any within size_t type).
 * @param flags         Send flags.
 * @param dest_addr     Destination address.
 * @param addrlen       Size of @p dest_addr.
 * @param send_func     Transmitting function.
 *
 * @return Number of bytes sent on success, @c -1 on failure.
 */
ssize_t
send_var_size(int s, send_func_ctx *ctx, size_t len, int flags,
              const struct sockaddr *dest_addr, socklen_t addrlen,
              tarpc_send_function send_func)
{
    char   *buf = NULL;
    ssize_t rc;

    buf = malloc(len);
    if (buf == NULL)
        return -1;

    switch (send_func) {
        case TARPC_SEND_FUNC_SEND:
            rc = tarpc_send_func_send(ctx, s, buf, len, flags);
            break;
        case TARPC_SEND_FUNC_SENDTO:
            rc = tarpc_send_func_sendto_ext(ctx, s, buf, len, flags, dest_addr,
                                            addrlen);
            break;
        default:
            ERROR("Unsupported transmitting function");
            rc = -1;
    }

    free(buf);
    return rc;
}

TARPC_FUNC(send_var_size, {},
{
    PREPARE_ADDR(addr, in->addr, 0);
    send_func_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.lib_flags = in->common.lib_flags;
    MAKE_CALL(out->retval = func(in->fd, &ctx, in->len,
                                 send_recv_flags_rpc2h(in->flags),
                                 addr, addrlen, in->send_func));
})

/**
 * Try to receive packet with size @p len from socket @p s via the function
 * determined by @p recv_func.
 *
 * This function is to check behavior of receiving function
 * with various buffer size passed, e.g. extra large (over 2^31).
 *
 * @param lib_flags     How to resolve function name.
 * @param s             Socket descriptor.
 * @param len           Size of packet (can be any within size_t type).
 * @param flags         Receive flags.
 * @param recv_func     Receiving function.
 *
 * @return Number of bytes received on success, @c -1 on failure.
 */
ssize_t
recv_var_size(tarpc_lib_flags lib_flags, int s, size_t len, int flags,
              tarpc_recv_function recv_func)
{
    char    *buf = NULL;
    ssize_t  rc = -1;
    api_func recv_f = NULL;

    buf = malloc(len);
    if (buf == NULL)
        return -1;

    switch (recv_func)
    {
        case TARPC_RECV_FUNC_RECV:
            if (tarpc_find_func(lib_flags, "recv", &recv_f) == 0)
                rc = recv_f(s, buf, len, flags);
            else
                rc = -1;
            break;

        case TARPC_RECV_FUNC_RECVFROM:
            if (tarpc_find_func(lib_flags, "recvfrom", &recv_f) == 0)
                rc = recv_f(s, buf, len, flags, NULL, NULL);
            else
                rc = -1;
            break;

        default:
            ERROR("Unsupported receiving function");
            rc = -1;
    }

    free(buf);
    return rc;
}

TARPC_FUNC(recv_var_size, {},
{
    MAKE_CALL(out->retval = func(in->common.lib_flags, in->fd, in->len,
                                 send_recv_flags_rpc2h(in->flags),
                                 in->recv_func));
})

/**
 * Allocate send_func_ctx structure, return RPC pointer to it.
 *
 * @param lib_flags    Value of lib_flags field of send_func_ctx
 *                     structure.
 *
 * @return RPC pointer on success, @c RPC_NULL on failure.
 */
static tarpc_ptr
sockts_alloc_send_func_ctx(tarpc_lib_flags lib_flags)
{
    send_func_ctx *ctx;
    tarpc_ptr      result;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return RPC_NULL;

    ctx->lib_flags = lib_flags;
    result = rcf_pch_mem_alloc(ctx);
    if (result == RPC_NULL)
        free(ctx);

    return result;
}

TARPC_FUNC_STATIC(sockts_alloc_send_func_ctx, {},
{
    MAKE_CALL(out->ctx_ptr = func(in->common.lib_flags));
})

/**
 * Initialize fields of sending function context related to
 * registered ZC buffer and onload_zc_send().
 *
 * @param ctx_ptr       RPC pointer to the context.
 * @param fd            Socket FD.
 * @param buf_size      Minumum size of the ZC buffer to allocate.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
sockts_send_func_ctx_init_zc_buf(tarpc_ptr ctx_ptr, int fd,
                                 size_t buf_size)
{
#ifndef ONLOAD_SO_ONLOADZC_COMPLETE
    UNUSED(ctx_ptr);
    UNUSED(fd);
    UNUSED(buf_size);

    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EOPNOTSUPP),
                     "onload_zc_send() with registered buffers is "
                     "not supported");
    return -1;
#else
    send_func_ctx *ctx;

    ctx = (send_func_ctx *)rcf_pch_mem_get(ctx_ptr);
    if (ctx == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve sending context pointer");
        return -1;
    }

    TAILQ_INIT(&ctx->compl_bufs);

    ctx->user_buf_len = buf_size;
    return alloc_register_zc_buf(fd, sockts_zc_reg_buf_type(),
                                 &ctx->user_buf_len,
                                 (void **)&ctx->user_buf,
                                 &ctx->buf_handle);
#endif
}

TARPC_FUNC_STATIC(sockts_send_func_ctx_init_zc_buf, {},
{
    MAKE_CALL(out->retval = func(in->ctx, in->fd, in->buf_size));
})

/**
 * Clean fields of sending function context related to registered ZC buffer
 * and onload_zc_send(). Try to wait for remaining completion messages
 * before unregistering and releasing the buffer.
 *
 * @param ctx_ptr       RPC pointer to the context.
 * @param fd            Socket FD.
 * @param timeout       Timeout in milliseconds when polling for completion
 *                      messages.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
sockts_send_func_ctx_clean_zc_buf(tarpc_ptr ctx_ptr, int fd, int timeout)
{
#ifndef ONLOAD_SO_ONLOADZC_COMPLETE
    UNUSED(ctx_ptr);
    UNUSED(fd);
    UNUSED(timeout);

    te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EOPNOTSUPP),
                     "onload_zc_send() with registered buffers is "
                     "not supported");
    return -1;
#else

    send_func_ctx *ctx;
    int rc_wait;
    int rc_unreg;
    zc_compl_buf *buf;
    zc_compl_buf *buf_aux;

    api_func func_unreg_bufs = NULL;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_unregister_buffers",
                  &func_unreg_bufs);

    ctx = (send_func_ctx *)rcf_pch_mem_get(ctx_ptr);
    if (ctx == NULL)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve sending context pointer");
        return -1;
    }

    rc_wait = wait_for_zc_completion(&ctx->compl_bufs, TRUE, TRUE, timeout);
    if (rc_wait >= 0 && !TAILQ_EMPTY(&ctx->compl_bufs))
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                         "Not all the buffers were completed");
        rc_wait = -1;
    }

    TAILQ_FOREACH_SAFE(buf, &ctx->compl_bufs, links, buf_aux)
    {
        TAILQ_REMOVE(&ctx->compl_bufs, buf, links);
        free(buf);
    }

    rc_unreg = unreg_unmap_zc_rbufs(func_unreg_bufs, fd,
                                    ctx->buf_handle, ctx->user_buf,
                                    ctx->user_buf_len);

    if (rc_wait < 0 || rc_unreg < 0)
        return -1;

    return 0;
#endif
}

TARPC_FUNC_STATIC(sockts_send_func_ctx_clean_zc_buf, {},
{
    MAKE_CALL(out->retval = func(in->ctx, in->fd, in->timeout));
})

#ifdef HAVE_DECL_ONLOAD_ZC_HLRX_RECV_ZC
/* Supported after the Onload branch onload-7.1 */

/**
 * Structure storing pointer to onload_zc_hlrx structure
 * associated with a given socket FD.
 */
typedef struct zc_hlrx_ctxt {
    TAILQ_ENTRY(zc_hlrx_ctxt)     links;    /**< Queue links */
    int                           fd;       /**< Socket FD */
    struct onload_zc_hlrx        *hlrx;     /**< Pointer to onload_zc_hlrx
                                                 structure */
} zc_hlrx_ctxt;

/** Type of the head of the queue of zc_hlrx_ctxt structures */
typedef TAILQ_HEAD(zc_hlrx_ctxts, zc_hlrx_ctxt) zc_hlrx_ctxts;

/** Queue of zc_hlrx_ctxt structures */
static zc_hlrx_ctxts saved_hlrx_ctxts =
                    TAILQ_HEAD_INITIALIZER(saved_hlrx_ctxts);
/** Lock protecting queue of zc_hlrx_ctxt structures */
static pthread_mutex_t hlrx_ctxts_lock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Should be set to @c TRUE after hlrx_close_fd_hook() is registered
 * to prevent multiple registations.
 */
static te_bool hlrx_hook_set = FALSE;

/**
 * Hook called just before closing FD; used to release onload_zc_hlrx
 * structure associated with closed socket FD.
 *
 * @param fd          Closed FD.
 * @param cookie      Not used.
 */
static void
hlrx_close_fd_hook(int fd, void *cookie)
{
    te_errno         rc;
    int              res;
    zc_hlrx_ctxt    *ctxt;
    api_func_ptr     func_free = NULL;

    UNUSED(cookie);

    rc = tarpc_find_func(TARPC_LIB_DEFAULT, "onload_zc_hlrx_free",
                         (api_func *)&func_free);
    if (rc != 0)
    {
        te_rpc_error_set(rc, "Failed to resolve onload_zc_hlrx_free");
        return;
    }

    res = tarpc_mutex_lock(&hlrx_ctxts_lock);
    if (res != 0)
        return;

    TAILQ_FOREACH(ctxt, &saved_hlrx_ctxts, links)
    {
        if (ctxt->fd == fd)
        {
            TAILQ_REMOVE(&saved_hlrx_ctxts, ctxt, links);

            rc = func_free(ctxt->hlrx);
            if (rc != 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -rc),
                                 "onload_zc_hlrx_free() failed");
            }

            free(ctxt);
            break;
        }
    }

    tarpc_mutex_unlock(&hlrx_ctxts_lock);
}

/**
 * Obtain a pointer to onload_zc_hlrx structure allocated for a
 * given socket FD (if it is not yet allocated, allocate it now).
 *
 * @param fd                Socket FD.
 * @param hlrx              Where to save pointer to onload_zc_hlrx
 *                          structure.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
obtain_hlrx_struct(int fd, struct onload_zc_hlrx **hlrx)
{
    zc_hlrx_ctxt   *ctxt;
    te_bool         found = FALSE;
    int             rc = 0;
    int             res;
    api_func        func_alloc = NULL;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_hlrx_alloc",
                  &func_alloc);

    res = tarpc_mutex_lock(&hlrx_ctxts_lock);
    if (res != 0)
        return -1;

    if (!hlrx_hook_set)
    {
        rc = tarpc_close_fd_hook_register(&hlrx_close_fd_hook, NULL);
        if (rc != 0)
            goto finish;
        hlrx_hook_set = TRUE;
    }

    TAILQ_FOREACH(ctxt, &saved_hlrx_ctxts, links)
    {
        if (ctxt->fd == fd)
        {
            found = TRUE;
            break;
        }
    }

    if (!found)
    {
        ctxt = calloc(1, sizeof(*ctxt));
        if (ctxt == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "%s(): failed to allocate memory",
                             __FUNCTION__);
            rc = -1;
            goto finish;
        }

        ctxt->fd = fd;

        rc = func_alloc(fd, 0, &ctxt->hlrx);
        if (rc != 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -rc),
                             "onload_zc_hlrx_alloc() failed");
            rc = -1;
            free(ctxt);
            goto finish;
        }

        TAILQ_INSERT_TAIL(&saved_hlrx_ctxts, ctxt, links);
    }

finish:
    res = tarpc_mutex_unlock(&hlrx_ctxts_lock);
    if (res != 0)
        return -1;

    if (rc == 0)
        *hlrx = ctxt->hlrx;
    return rc;
}

/**
 * Call onload_zc_hlrx_recv_zc().
 *
 * @param fd          Socket FD.
 * @param msg         Pointer to filled Onload message structure.
 * @param max_bytes   Maximum number of bytes to receive.
 * @param flags       Flags to pass to onload_zc_hlrx_recv_zc().
 *
 * @return Number of received bytes on success, negative value on failure.
 */
ssize_t
simple_hlrx_recv_zc(int fd, struct onload_zc_msg *msg, size_t max_bytes,
                    int flags)
{
    int                      rc;
    struct onload_zc_hlrx   *hlrx = NULL;
    api_func_ptr             func_recv = NULL;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_hlrx_recv_zc", &func_recv);

    rc = obtain_hlrx_struct(fd, &hlrx);
    if (rc != 0)
        return rc;

    rc = func_recv(hlrx, msg, max_bytes, flags);
    if (rc < 0)
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

TARPC_FUNC(simple_hlrx_recv_zc,
{
    COPY_ARG(msg);
},
{
    /*
     * It is assumed that Onload will retrieve buffers of
     * at least this size (except for the last one).
     */
    const unsigned int   onload_buffer_size = 1000;
    /*
     * Minumum number of Onload IOVs - it will ensure
     * this works fine in tests with a few small packets.
     */
    const unsigned int   min_oiovs_num = 1000;

    rpcs_msghdr_helper   msg_helper;
    struct msghdr        msg;
    size_t               max_bytes = 0;
    size_t               i;
    size_t               j;
    int                  flags;
    te_errno             rc;
    int                  res;

    struct onload_zc_msg    omsg;
    struct onload_zc_iovec *oiovs = NULL;
    int                     oiovs_num = 0;
    struct iovec           *cur_iov = NULL;
    uint8_t                *cur_pos = NULL;
    uint8_t                *oiov_cur_pos = NULL;
    size_t                  cur_size;
    size_t                  copy_size;
    size_t                  oiov_left_bytes;
    size_t                  total_left_bytes;
    api_func                func_decref;

    rc = tarpc_find_func(TARPC_LIB_DEFAULT, "onload_zc_buffer_decref",
                         &func_decref);
    if (rc != 0)
    {
        te_rpc_error_set(rc, "Failed to find onload_zc_buffer_decref()");
        out->retval = -1;
        return;
    }

    flags = send_recv_flags_rpc2h(in->flags);
    if (in->os_inline)
        flags = flags | ONLOAD_MSG_RECV_OS_INLINE;

    if (out->msg.msg_val == NULL)
    {
        MAKE_CALL(out->retval = func(in->s, NULL, 0, flags));
        return;
    }

    memset(&msg_helper, 0, sizeof(msg_helper));
    memset(&msg, 0, sizeof(msg));

    rc = rpcs_msghdr_tarpc2h(RPCS_MSGHDR_CHECK_ARGS_RECV, out->msg.msg_val,
                             &msg_helper, &msg, arglist, "msg");
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "rpcs_msghdr_tarpc2h() failed");
        out->retval = -1;
        goto finish;
    }

    if (msg.msg_iov == NULL)
    {
        oiovs = NULL;
        oiovs_num = msg.msg_iovlen;
    }
    else
    {
        for (i = 0; i < msg.msg_iovlen; i++)
        {
            max_bytes += msg.msg_iov[i].iov_len;
        }

        /*
         * Try to compute number of Onload buffers which will
         * be enough for requested number of bytes.
         */
        oiovs_num = MAX(max_bytes / onload_buffer_size + 1, msg.msg_iovlen);
        oiovs_num = MAX(oiovs_num, min_oiovs_num);
        oiovs = calloc(oiovs_num, sizeof(*oiovs));
        if (oiovs == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "Failed to allocate array of onload_zc_iovec "
                             "structures");
            out->retval = -1;
            goto finish;
        }
    }

    omsg.iov = oiovs;
    memcpy(&omsg.msghdr, &msg, sizeof(msg));
    omsg.msghdr.msg_iovlen = oiovs_num;

    MAKE_CALL(out->retval = func(in->s, &omsg, max_bytes, flags));

    if (out->retval >= 0)
    {
        /*
         * Here we copy data from Onload IOVs to IOVs supplied
         * by caller, hiding the fact that Onload IOVs can have
         * different number and sizes.
         */
        cur_iov = msg.msg_iov;
        cur_pos = (uint8_t *)(cur_iov->iov_base);
        cur_size = cur_iov->iov_len;
        total_left_bytes = out->retval;
        j = 0;
        for (i = 0; i < omsg.msghdr.msg_iovlen; i++)
        {
            oiov_left_bytes = omsg.iov[i].iov_len;
            if (oiov_left_bytes > total_left_bytes)
            {
                te_rpc_error_set(
                        TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                        "IOVs returned by onload_zc_hlrx_recv_zc() "
                        "contain more data than its return value "
                        "suggests");
                out->retval = -1;
                break;
            }

            oiov_cur_pos = omsg.iov[i].iov_base;
            while (oiov_left_bytes > 0 && j < msg.msg_iovlen)
            {
                copy_size = MIN(oiov_left_bytes, cur_size);
                memcpy(cur_pos, oiov_cur_pos, copy_size);
                oiov_cur_pos += copy_size;
                oiov_left_bytes -= copy_size;
                total_left_bytes -= copy_size;
                if (copy_size < cur_size)
                {
                    cur_pos += copy_size;
                    cur_size -= copy_size;
                }
                else
                {
                    j++;
                    if (j >= msg.msg_iovlen)
                        break;
                    cur_iov++;
                    cur_pos = (uint8_t *)(cur_iov->iov_base);
                    cur_size = cur_iov->iov_len;
                }
            }

            if (oiov_left_bytes > 0)
            {
                te_rpc_error_set(
                        TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                        "Data returned by onload_zc_hlrx_recv_zc() "
                        "did not fit into provided msghdr");
                out->retval = -1;
                break;
            }
        }

        if (omsg.msghdr.msg_iovlen > 0)
        {
            for (i = 0; i < omsg.msghdr.msg_iovlen; i++)
            {
                res = func_decref(in->s, omsg.iov[i].buf);
                if (res < 0)
                {
                    te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, -res),
                                     "onload_zc_buffer_decref() failed");
                    out->retval = -1;
                    goto finish;
                }
            }
        }

        if (total_left_bytes > 0 && out->retval >= 0)
        {
            te_rpc_error_set(
                    TE_RC(TE_TA_UNIX, TE_ESMALLBUF),
                    "IOVs returned by onload_zc_hlrx_recv_zc() "
                    "contain less data than its return value "
                    "suggests");
            out->retval = -1;
            goto finish;
        }
    }

    msg.msg_namelen = omsg.msghdr.msg_namelen;
    msg.msg_controllen = omsg.msghdr.msg_controllen;
    msg.msg_flags = omsg.msghdr.msg_flags;
    rc = rpcs_msghdr_h2tarpc(&msg, &msg_helper, out->msg.msg_val);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "rpcs_msghdr_h2tarpc() failed");
        out->retval = -1;
        goto finish;
    }

finish:

    free(oiovs);
    rpcs_msghdr_helper_clean(&msg_helper, &msg);
})

/**
 * Call onload_zc_hlrx_recv_copy().
 *
 * @param fd          Socket FD.
 * @param msg         Pointer to struct msghdr.
 * @param flags       Flags to pass to onload_zc_hlrx_recv_copy().
 *
 * @return Number of received bytes on success, negative value on failure.
 */
ssize_t
simple_hlrx_recv_copy(int fd, struct msghdr *msg, int flags)
{
    int                      rc;
    struct onload_zc_hlrx   *hlrx = NULL;
    api_func_ptr             func_recv = NULL;

    TRY_FIND_FUNC(TARPC_LIB_DEFAULT, "onload_zc_hlrx_recv_copy",
                  &func_recv);

    rc = obtain_hlrx_struct(fd, &hlrx);
    if (rc != 0)
        return rc;

    rc = func_recv(hlrx, msg, flags);
    if (rc < 0)
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

TARPC_FUNC(simple_hlrx_recv_copy,
{
    COPY_ARG(msg);
},
{
    rpcs_msghdr_helper   msg_helper;
    struct msghdr        msg;
    int                  flags;
    te_errno             rc;

    memset(&msg_helper, 0, sizeof(msg_helper));
    memset(&msg, 0, sizeof(msg));

    flags = send_recv_flags_rpc2h(in->flags);
    if (in->os_inline)
        flags = flags | ONLOAD_MSG_RECV_OS_INLINE;

    rc = rpcs_msghdr_tarpc2h(RPCS_MSGHDR_CHECK_ARGS_RECV, out->msg.msg_val,
                             &msg_helper, &msg, arglist, "msg");
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "rpcs_msghdr_tarpc2h() failed");
        out->retval = -1;
        goto finish;
    }

    MAKE_CALL(out->retval = func(in->s, &msg, flags));

    rc = rpcs_msghdr_h2tarpc(&msg, &msg_helper, out->msg.msg_val);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, rc),
                         "rpcs_msghdr_h2tarpc() failed");
        out->retval = -1;
        goto finish;
    }

finish:

    rpcs_msghdr_helper_clean(&msg_helper, &msg);
})

#endif /* HAVE_DECL_ONLOAD_ZC_HLRX_RECV_ZC */


/*------------ connect_send_dur_time() -----------------------*/

/**
 * Argument to be passed to a thread @b connect_send_dur_time_thread() during
 * connect_send_dur_time work.
 */
typedef struct connect_send_dur_time_arg_t {
    tarpc_lib_flags         lib_flags;
    uint64_t                duration; /* In seconds */

    struct sockaddr_storage src_addr_st;
    struct sockaddr        *src_addr;
    socklen_t               src_addrlen;

    struct sockaddr_storage dst_addr_st;
    struct sockaddr        *dst_addr;
    socklen_t               dst_addrlen;

    int                     thrd_rc; /* Thread's return code */
    uint64_t                sent;
} connect_send_dur_time_arg_t;

/**
 * Function for a test thread which is used in connect_send_dur_time.
 *
 * @param thrd_arg  Argument should have type @b connect_send_dur_time_arg_t
 */
static void *
connect_send_dur_time_thread(void *thrd_arg)
{
    connect_send_dur_time_arg_t *arg = (connect_send_dur_time_arg_t *)thrd_arg;
    int *rc = &arg->thrd_rc;
    *rc = -1;

    struct tarpc_simple_sender_in ss_in;
    struct tarpc_simple_sender_out ss_out;

    api_func func_socket;
    api_func func_bind;
    api_func func_connect;
    api_func_ptr func_ss;
    api_func func_getsockname;
    api_func func_close;

    arg->sent = 0;

    if (tarpc_find_func(TARPC_LIB_DEFAULT, "socket", &func_socket) != 0)
        pthread_exit((void *) rc);
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "bind", &func_bind) != 0)
        pthread_exit((void *) rc);
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "connect", &func_connect) != 0)
        pthread_exit((void *) rc);
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "simple_sender", (api_func *)&func_ss) != 0)
        pthread_exit((void *) rc);
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "getsockname", &func_getsockname) != 0)
        pthread_exit((void *) rc);
    if (tarpc_find_func(TARPC_LIB_DEFAULT, "close", &func_close) != 0)
        pthread_exit((void *) rc);

    /* Prepare args to simple sender call */
    memset(&ss_in, 0, sizeof(ss_in));
    memset(&ss_out, 0, sizeof(ss_out));

    ss_in.common.lib_flags = arg->lib_flags;
    ss_in.size_min = 500;
    ss_in.size_max = 1500;
    ss_in.size_rnd_once = FALSE;
    ss_in.delay_min = 0;
    ss_in.delay_max = 10000; /* microseconds */
    ss_in.delay_rnd_once = FALSE;
    ss_in.time2run = arg->duration; /* seconds */
    ss_in.ignore_err = TRUE;

    if ((ss_in.s = func_socket(arg->src_addr->sa_family, SOCK_STREAM, 0)) < 0)
    {
        ERROR("%s() socket() failed with errno %d(%s)", __func__, errno,
              strerror(errno));
        pthread_exit((void *) rc);
    }

    if ((*rc = func_bind(ss_in.s, arg->src_addr, arg->src_addrlen)) < 0)
    {
        ERROR("%s() bind() failed with errno %d(%s)", __func__, errno,
              strerror(errno));
        func_close(ss_in.s);
        pthread_exit((void *) rc);
    }

    if ((*rc = func_connect(ss_in.s, arg->dst_addr, arg->dst_addrlen)) < 0)
    {
        ERROR("%s() connect() failed with errno %d(%s)", __func__, errno,
              strerror(errno));
        goto connect_send_dur_time_thread_cleanup;
    }

    if ((*rc = func_ss(&ss_in, &ss_out)) < 0)
    {
        ERROR("%s() simple_sender() failed unexpectedly", __func__);
        goto connect_send_dur_time_thread_cleanup;
    }

    *rc = ss_out.retval;
    arg->sent = ss_out.bytes;

connect_send_dur_time_thread_cleanup:
    if (func_close(ss_in.s) < 0)
    {
        ERROR("%s() close() failed with errno %d(%s)", __func__, errno,
              strerror(errno));
        *rc = -1;
    }

    pthread_exit((void *) rc);
}

/**
 * The function implements logic of a sapi-ts test:
 * @b level5/ext_stackname/tcp_conn_move_fd_in_pkt_flow, and
 * call connect-send-close functions in multiple threads for @c SOCK_STREAM
 * socket type.
 *
 * @param in            Input arguments.
 * @param sent (out)    Array of sent bytes by each thread.
 *
 * @return              @c 0 on success, @c -1 on failure.
 */
int
connect_send_dur_time(struct tarpc_connect_send_dur_time_in *in, uint64_t *sent)
{
    pthread_t *thrd_list = NULL;
    connect_send_dur_time_arg_t *arg_list = NULL;
    int i;
    int count = 0; /* number of actually started threads */
    int rc = 0;
    int rc2 = 0;
    int *thrd_rc = NULL;
    ta_log_lock_key key;

    if (ta_log_lock(&key) != 0)
    {
        ERROR("Coouldn't lock logger");
        return -1;
    }

    thrd_list = TE_ALLOC(in->threads_num * sizeof(*thrd_list));
    arg_list = TE_ALLOC(in->threads_num * sizeof(*arg_list));

    if (thrd_list == NULL || arg_list == NULL)
        return -1;

    for (i = 0; i < in->threads_num; i++)
    {
        connect_send_dur_time_arg_t *a = arg_list + i;

        a->lib_flags = in->common.lib_flags;
        a->duration = in->duration;

        if (sockaddr_rpc2h(&in->dst_addr, SA(&a->dst_addr_st),
                    sizeof(a->dst_addr_st), &a->dst_addr, &a->dst_addrlen) != 0)
        {
            ERROR("Failed to convert sockaddr structure from RPC"
                  "to host representation.");
            rc2 = -1;
            goto connect_send_dur_time_cleanup;
        }

        if (sockaddr_rpc2h(&in->src_addr.src_addr_val[i], SA(&a->src_addr_st),
                    sizeof(a->src_addr_st), &a->src_addr, &a->src_addrlen) != 0)
        {
            ERROR("Failed to convert sockaddr structure from RPC"
                  "to host representation.");
            rc2 = -1;
            goto connect_send_dur_time_cleanup;
        }

        if ((rc = pthread_create(thrd_list + i, NULL,
                                 connect_send_dur_time_thread, arg_list + i)) != 0)
        {
            ERROR("Failed to create thread #%d: %s", i, strerror(errno));
            rc2 = rc;
            goto connect_send_dur_time_cleanup;
        }
        count++;
    }

connect_send_dur_time_cleanup:
    for (i = 0; i < count; i++)
    {
        rc = pthread_join(thrd_list[i], (void *)&thrd_rc);
        if (rc != 0 && errno != 0)
        {
            ERROR("Failed to join thread #%d: %s", rc, strerror(errno));
            if (rc2 == 0)
                rc2 = rc;
        }
        if (*thrd_rc != 0)
            ERROR("Thread #%d returned unexpected result: %d", i, *thrd_rc);

        sent[i] = arg_list[i].sent;
        if (rc2 == 0 && *thrd_rc != 0)
            rc2 = *thrd_rc;
    }

    free(thrd_list);
    free(arg_list);

    rc = ta_log_unlock(&key);
    if (rc2 == 0)
        rc2 = rc;
    return rc2;
}

TARPC_FUNC(connect_send_dur_time, {},
{
    out->sent.sent_val = TE_ALLOC(sizeof(uint64_t) * in->threads_num);
    out->sent.sent_len = in->threads_num;

    MAKE_CALL(out->retval = func(in, out->sent.sent_val));
}
)

/**
 * Call specified iomux function requested number of times (expecting
 * that it times out every time).
 *
 * @param in          Parameters of rpc_sockts_iomux_timeout_loop().
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
sockts_iomux_timeout_loop(tarpc_sockts_iomux_timeout_loop_in *in)
{
    iomux_funcs iomux_f;
    iomux_func iomux = in->iomux;
    iomux_state iomux_st;
    iomux_return iomux_ret;
    iomux_return_iterator it;
    int rc = 0;
    int rc_aux = 0;

    struct tarpc_pollfd *fds = in->fds.fds_val;
    int nfds = in->fds.fds_len;
    int n_calls = in->n_calls;
    int timeout = in->timeout;

    int fd;
    int events;
    int i;
    int j;

    api_func oo_epoll;
    struct onload_ordered_epoll_event *oo_events = NULL;

    if (iomux_find_func(in->common.lib_flags, &iomux, &iomux_f) != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOENT),
                         "Failed to resolve iomux function");
        return -1;
    }

    rc = iomux_create_state(iomux, &iomux_f, &iomux_st);
    if (rc != 0)
    {
        te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                         "iomux_create_state() failed");
        return -1;
    }

    if (in->oo_epoll)
    {
        rc = tarpc_find_func(in->common.lib_flags,
                             "onload_ordered_epoll_wait",
                             &oo_epoll);
        if (rc != 0)
        {
            te_rpc_error_set(
                       TE_RC(TE_TA_UNIX, TE_ENOENT),
                       "Failed to resolve onload_ordered_epoll_wait()");
            return -1;
        }

        oo_events = TE_ALLOC(nfds * sizeof(*oo_events));
        if (oo_events == NULL)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ENOMEM),
                             "Failed to allocate memory for array of "
                             "onload_ordered_epoll_event");
            return -1;
        }
    }

    for (i = 0; i < nfds; i++)
    {
        rc = iomux_add_fd(iomux, &iomux_f, &iomux_st,
                          fds[i].fd, poll_event_rpc2h(fds[i].events));
        if (rc < 0)
        {
            ERROR("iomux_add_fd() failed for fd %d, errno=%r",
                  fds[i].fd, te_rc_os2te(errno));

            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                             "iomux_add_fd() failed");
            rc = -1;
            goto finish;
        }
    }

    for (i = 0; i < n_calls; i++)
    {
        if (iomux == FUNC_POLL || iomux == FUNC_PPOLL)
        {
            /*
             * This is done to check that revents are
             * reset to 0 in case of timeout.
             */

            for (j = 0; j < nfds; j++)
            {
                iomux_st.poll.fds[j].revents = 0xffff;
            }
        }

        if (in->oo_epoll)
        {
            rc = oo_epoll(iomux_st.epoll, iomux_ret.epoll.events,
                          oo_events, nfds, timeout);
            if (rc < 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_RPC, -rc),
                                 "iomux function failed");
                rc = -1;
                goto finish;
            }
        }
        else
        {
            rc = iomux_wait(iomux, &iomux_f, &iomux_st, &iomux_ret, timeout);
            if (rc < 0)
            {
                te_rpc_error_set(TE_OS_RC(TE_RPC, errno),
                                 "iomux function failed");
                rc = -1;
                goto finish;
            }
        }

        if (rc > 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                             "iomux function returned positive value");
            rc = -1;
            goto finish;
        }

        if (in->oo_epoll)
            continue;

        it = iomux_return_iterate(iomux, &iomux_st, &iomux_ret,
                                  IOMUX_RETURN_ITERATOR_START,
                                  &fd, &events);
        if (it != IOMUX_RETURN_ITERATOR_END)
        {
            ERROR("iomux returned zero, but events 0x%x are reported for "
                  "FD %d", events, fd);

            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EFAIL),
                             "iomux function returned zero, but some "
                             "events are reported");
            rc = -1;
            goto finish;
        }
    }

finish:

    rc_aux = iomux_close(iomux, &iomux_f, &iomux_st);
    if (rc_aux < 0)
    {
        if (rc >= 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "iomux_close() failed");
            rc = -1;
        }
        else
        {
            ERROR("iomux_close() failed");
        }
    }

    free(oo_events);
    return rc;
}

TARPC_FUNC_STATIC(sockts_iomux_timeout_loop, {},
{
    MAKE_CALL(out->retval = func(in));
})

/**
 * Receive data sent from TCP peer, often using recv() with
 * @c MSG_PEEK flag. It is supposed that data is generated by
 * tarpc_fill_buff_with_sequence_lcg(); this function checks
 * whether received data matches the expected pattern.
 *
 * @param in      Input arguments of RPC call.
 * @param out     Output arguments of RPC call.
 *
 * @return @c 0 on success, @c -1 on failure.
 */
static int
sockts_peek_stream_receiver(tarpc_sockts_peek_stream_receiver_in *in,
                            tarpc_sockts_peek_stream_receiver_out *out)
{
    api_func_ptr func_poll = NULL;
    api_func func_recv = NULL;

    struct pollfd pfd;
    struct timeval tv_start = {0, 0};
    struct timeval tv_cur = {0, 0};
    te_bool time_got = FALSE;
    int timeout;

    te_errno te_rc;
    int rc;
    int res = -1;

    char buf[1024];
    char check_buf[TARPC_LCG_LEN(sizeof(buf))];
    uint32_t offset;
    int data_len;
    int flags;

    tarpc_pat_gen_arg cur_arg;
    tarpc_pat_gen_arg saved_arg;
    uint64_t received;

    /*
     * Average number of recv() calls with MSG_PEEK per every
     * call without this flag.
     */
    const int peek_count = 2;

    TRY_FIND_FUNC(in->common.lib_flags, "poll", &func_poll);
    TRY_FIND_FUNC(in->common.lib_flags, "recv", &func_recv);

    memcpy(&cur_arg, &in->gen_arg, sizeof(cur_arg));
    received = 0;

    while (TRUE)
    {
        te_rc = te_gettimeofday(&tv_cur, NULL);
        if (te_rc != 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, te_rc),
                             "gettimeofday() failed");
            goto cleanup;
        }
        if (!time_got)
        {
            memcpy(&tv_start, &tv_cur, sizeof(tv_cur));
            time_got = TRUE;
            timeout = MIN(in->time2run, in->time2wait);
        }
        else
        {
            timeout = in->time2run - TE_US2MS(TIMEVAL_SUB(tv_cur, tv_start));
            timeout = MIN(timeout, in->time2wait);
        }
        if (timeout < 0)
            break;

        pfd.fd = in->fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        rc = func_poll(&pfd, 1, timeout);

        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "poll() failed");
            goto cleanup;
        }
        else if (rc == 0)
        {
            break;
        }
        else if (rc > 1)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                             "poll() returned too big value");
            goto cleanup;
        }
        else if (pfd.revents != POLLIN)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_EINVAL),
                             "poll() returned unexpected events %s",
                             poll_event_rpc2str(
                                    poll_event_h2rpc(pfd.revents)));
            goto cleanup;
        }

        if (rand_range(0, peek_count) < peek_count)
            flags = MSG_PEEK;
        else
            flags = 0;

        data_len = rand_range(1, sizeof(buf));
        rc = func_recv(in->fd, buf, data_len, flags);
        if (rc < 0)
        {
            te_rpc_error_set(TE_OS_RC(TE_TA_UNIX, errno),
                             "recv() failed");
            goto cleanup;
        }
        else if (rc == 0)
        {
            WARN("%s(): recv() returned zero", __FUNCTION__);
            break;
        }

        data_len = rc;

        if (flags & MSG_PEEK)
            memcpy(&saved_arg, &cur_arg, sizeof(saved_arg));

        offset = cur_arg.offset;
        te_rc = tarpc_fill_buff_with_sequence_lcg(check_buf, data_len,
                                                  &cur_arg);
        if (te_rc != 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, te_rc),
                             "tarpc_fill_buff_with_sequence_lcg() failed");
            goto cleanup;
        }

        if (flags & MSG_PEEK)
            memcpy(&cur_arg, &saved_arg, sizeof(saved_arg));
        else
            received += data_len;

        if (memcmp(buf, check_buf + offset, data_len) != 0)
        {
            te_rpc_error_set(TE_RC(TE_TA_UNIX, TE_ECORRUPTED),
                             "Received data does not match the pattern");
            goto cleanup;
        }
    }

    res = 0;
cleanup:

    memcpy(&out->gen_arg, &cur_arg, sizeof(cur_arg));
    out->received = received;
    return res;
}

TARPC_FUNC_STATIC(sockts_peek_stream_receiver, {},
{
    MAKE_CALL(out->retval = func(in, out));
})
