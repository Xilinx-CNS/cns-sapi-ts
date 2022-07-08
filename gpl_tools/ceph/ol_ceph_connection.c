/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#if USE_DLSYM
#define _GNU_SOURCE /* For RTLD_DEFAULT */
#include <dlfcn.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <netinet/in.h>

#include "ol_ceph_connection.h"
#include "ol_ceph_offload.h"

#if USE_DLSYM
/** Helper macros to call Onload functions which are resolved with dlsym. */
#define ef_driver_open(...) \
    ef_vi->ops.ef_driver_open_f(__VA_ARGS__)
#define ef_pd_alloc_by_name(...) \
    ef_vi->ops.ef_pd_alloc_by_name_f(__VA_ARGS__)
#define ef_vi_alloc_from_pd(...) \
    ef_vi->ops.ef_vi_alloc_from_pd_f(__VA_ARGS__)
#define ef_vi_free(...) \
    ef_vi->ops.ef_vi_free_f(__VA_ARGS__)
#define ef_pd_free(...) \
    ef_vi->ops.ef_pd_free_f(__VA_ARGS__)
#define ef_driver_close(...) \
    ef_vi->ops.ef_driver_close_f(__VA_ARGS__)
#define ef_memreg_alloc(...) \
    ef_vi->ops.ef_memreg_alloc_f(__VA_ARGS__)
#define ef_memreg_free(...) \
    ef_vi->ops.ef_memreg_free_f(__VA_ARGS__)
#define ef_vi_transmit_unbundle(...) \
    ef_vi->ops.ef_vi_transmit_unbundle_f(__VA_ARGS__)
#define onload_zc_hlrx_alloc(...) \
    conn->ops.onload_zc_hlrx_alloc_f(__VA_ARGS__)
#define onload_zc_hlrx_free(...) \
    conn->ops.onload_zc_hlrx_free_f(__VA_ARGS__)
#define onload_zc_hlrx_recv_zc(...) \
    conn->ops.onload_zc_hlrx_recv_zc_f(__VA_ARGS__)
#define onload_zc_hlrx_buffer_release(...) \
    conn->ops.onload_zc_hlrx_buffer_release_f(__VA_ARGS__)
#define onload_zc_hlrx_recv_copy(...) \
    conn->ops.onload_zc_hlrx_recv_copy_f(__VA_ARGS__)

/**
 * Macro to find functions from Onload libraries.
 *
 * @param struct_name   Name of a structure that holds a pointer for the needed
 *                      function (maybe ef_vi or conn). See macros below.
 * @param func_name     The function name.
 */
#define _FIND_FUNC(struct_name, func_name) \
    do {                                                                    \
        struct_name->ops.func_name ## _f = dlsym(RTLD_DEFAULT, #func_name); \
        if (struct_name->ops.func_name ## _f == NULL)                       \
        {                                                                   \
            fprintf(stderr, "Failed to resolve %s (%s)\n", #func_name,      \
                    dlerror());                                             \
            return -ENOSYS;                                                 \
        }                                                                   \
    } while (0)

#define EF_VI_FIND_FUNC(name) _FIND_FUNC(ef_vi, name)
#define ZC_FIND_FUNC(name)_FIND_FUNC(conn, name)
#else
#define EF_VI_FIND_FUNC(name) do{} while(0)
#define ZC_FIND_FUNC(name) do{} while(0)
#endif /* USE_DLSYM */

#define EV_POLL_BATCH_SIZE 16

#define EF_REMOTE_IOVEC_FMT "[base=%lx,len=%u,flags=%x,addrspace=%lx]"
#define EF_REMOTE_IOVEC_ARG(x) (x).iov_base,(x).iov_len,(x).flags,(x).addrspace

/**
 * Check @p _expr against return value. If it is negative, log error and exit.
 */
#define EXP_NON_NEG(_expr) \
    do {                                                                \
        ssize_t _rc = (_expr);                                          \
        if (_rc < 0)                                                    \
        {                                                               \
            fprintf(stderr, "%s:%d: %s failed with rc=%ld (%s)\n",      \
                    __FILE__, __LINE__, #_expr, _rc, strerror(-_rc));   \
            return _rc;                                                 \
        }                                                               \
    } while (0)

/**
 * Check system call @p _call against return value. If it is negative, log
 * error and exit with @c -errno value.
 */
#define CHECK_SYSCALL(_call) \
    do {                                                                    \
        long _rc = (_call);                                                 \
        if (_rc < 0)                                                        \
        {                                                                   \
            _rc = -errno;                                                   \
            fprintf(stderr, "%s:%d: %s failed (%s)\n", __FILE__, __LINE__,  \
                    #_call, strerror(errno));                               \
            return _rc;                                                     \
        }                                                                   \
    } while (0)

#if HAVE_ZC
/**
 * Initialize ev_fi instance.
 *
 * @param ef_vi     The instance
 * @param iface     Interface name
 *
 * @return zero, or a negative error code in case of failure.
 */
static int
ol_efvi_init(ol_ef_vi_t *ef_vi, const char *iface)
{
    unsigned vi_flags = EF_VI_ALLOW_MEMCPY | EF_VI_TX_PHYS_ADDR;
    unsigned pd_flags = EF_PD_PHYS_MODE;
    int mmap_flags = MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS | MAP_HUGETLB;

    memset(ef_vi, 0, sizeof(*ef_vi));

    if (iface == NULL)
    {
        fprintf(stderr, "SFC interface needed for ef_vi API is not "
                        "specified.\n");
        return -EINVAL;
    }
    ef_vi->iface = iface;
    ef_vi->dma_mem_size = 1048576;
    ef_vi->dma_mem = mmap(NULL, ef_vi->dma_mem_size, PROT_READ | PROT_WRITE,
                          mmap_flags, -1, 0);

    if (ef_vi->dma_mem == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return -errno;
    }

    EF_VI_FIND_FUNC(ef_driver_open);
    EF_VI_FIND_FUNC(ef_pd_alloc_by_name);
    EF_VI_FIND_FUNC(ef_vi_alloc_from_pd);
    EF_VI_FIND_FUNC(ef_vi_free);
    EF_VI_FIND_FUNC(ef_pd_free);
    EF_VI_FIND_FUNC(ef_driver_close);
    EF_VI_FIND_FUNC(ef_memreg_alloc);
    EF_VI_FIND_FUNC(ef_memreg_free);
    EF_VI_FIND_FUNC(ef_vi_transmit_unbundle);

    EXP_NON_NEG(ef_driver_open(&ef_vi->dh));
    EXP_NON_NEG(ef_pd_alloc_by_name(&ef_vi->pd, ef_vi->dh, ef_vi->iface,
                                    pd_flags));
    EXP_NON_NEG(ef_vi_alloc_from_pd(&ef_vi->vi, ef_vi->dh, &ef_vi->pd,
                                    ef_vi->dh, -1, 0, -1, NULL, -1,
                                    vi_flags));
    EXP_NON_NEG(ef_memreg_alloc(&ef_vi->memreg, ef_vi->dh, &ef_vi->pd,
                                ef_vi->dh, ef_vi->dma_mem,
                                ef_vi->dma_mem_size));

    return 0;
}

/**
 * De-initialize ev_fi instance.
 *
 * @param ef_vi     The instance
 * @param iface     Interface name
 *
 * @return zero, or a negative error code in case of failure.
 */
static int
ol_efvi_deinit(ol_ef_vi_t *ef_vi)
{
    if (ef_vi->dma_mem != MAP_FAILED)
        munmap(ef_vi->dma_mem, ef_vi->dma_mem_size);
    EXP_NON_NEG(ef_memreg_free(&ef_vi->memreg, ef_vi->dh));
    EXP_NON_NEG(ef_vi_free(&ef_vi->vi, ef_vi->dh));
    EXP_NON_NEG(ef_pd_free(&ef_vi->pd, ef_vi->dh));
    EXP_NON_NEG(ef_driver_close(ef_vi->dh));
    return 0;
}

/**
 * Process event queue and check that memcpy event has occured.
 *
 * @param ef_vi     ev_vi handle.
 *
 * @return @c true if event has occured, @c false otherwise.
 */
static bool
poll_evq(ol_ef_vi_t *ef_vi)
{
    ef_event evs[EV_POLL_BATCH_SIZE];
    ef_request_id ids[EF_VI_TRANSMIT_BATCH];
    int i;
    int n_ev = ef_eventq_poll(&ef_vi->vi, evs, EV_POLL_BATCH_SIZE);

    for (i = 0; i < n_ev; ++i)
    {
        switch (EF_EVENT_TYPE(evs[i]))
        {
            case EF_EVENT_TYPE_TX:
                ef_vi_transmit_unbundle(&ef_vi->vi, &evs[i], ids);
                break;

            case EF_EVENT_TYPE_MEMCPY:
                if (evs[i].memcpy.dma_id != ef_vi->dma_id)
                {
                    fprintf(stderr, "dma_id is invalid (0x%x, exp: 0x%x)\n",
                            evs[i].memcpy.dma_id, ef_vi->dma_id);
                }
                ++ef_vi->dma_id;
                return true;

            default:
                fprintf(stderr, "ERROR: unexpected event type=%d\n",
                        (int)EF_EVENT_TYPE(evs[i]));
                break;
        }
    }

    return false;
}

/**
 * Copy data stored in FPGA DDR pointed by @p src_zc_iov into host memory.
 *
 * @param conn          Connection handle.
 * @param src_zc_iov    Source zc buffer.
 *
 * @return number of bytes transferred or a negative error value if an error
 *         occured. List of returned errors corresponds to
 *         @ref ef_vi_transmit_memcpy.
 */
static ssize_t
ol_efvi_fetch_fpga_data(ol_ceph_connection *conn,
                        struct onload_zc_iovec *src_zc_iov)
{
    ef_remote_iovec src, dst;
    ssize_t transferred = 0;

    /* FPGA buffer */
    src.iov_base = (ef_addr)src_zc_iov->iov_base;
    src.iov_len = src_zc_iov->iov_len;
    src.addrspace = src_zc_iov->addr_space;
    src.flags = 0;

    /* Host buffer */
    dst.iov_base = ef_memreg_dma_addr(&conn->ef_vi.memreg, 0);
    dst.iov_len = src.iov_len;
    dst.addrspace = EF_ADDRSPACE_LOCAL;
    dst.flags = 0;

    transferred = ef_vi_transmit_memcpy(&conn->ef_vi.vi, &dst, 1, &src, 1);
    if (transferred < 0)
    {
        fprintf(stderr, "FPGA data transmit error:\n");
        fprintf(stderr, "dma id = %u\n", conn->ef_vi.dma_id);
        fprintf(stderr, "ef_vi_transmit_memcpy("
                "dst:" EF_REMOTE_IOVEC_FMT "x1; "
                "src:" EF_REMOTE_IOVEC_FMT "x1) "
                "failed rc=%ld (%s)\n",
                EF_REMOTE_IOVEC_ARG(dst), EF_REMOTE_IOVEC_ARG(src),
                transferred, strerror(-transferred));
        return transferred;
    }
    else
    {
        ssize_t rc = 0;

        if (transferred != dst.iov_len)
        {
            fprintf(stderr, "ef_vi_transmit_memcpy failed to copy full data, "
                    "rc=%ld, iov_len=%u\n", transferred, dst.iov_len);
        }

        rc = ef_vi_transmit_memcpy_sync(&conn->ef_vi.vi, conn->ef_vi.dma_id);
        if (rc < 0)
        {
            fprintf(stderr, "ef_vi_transmit_memcpy_sync(dma_id=%u) failed "
                    "rc=%ld (%s)\n", conn->ef_vi.dma_id, rc, strerror(-rc));
            return rc;
        }
        ef_vi_transmit_push(&conn->ef_vi.vi);
    }

    while (true)
    {
        if (poll_evq(&conn->ef_vi))
            break;
    }

    return transferred;
}
#endif /* HAVE_ZC */

/**
 * Read @p len bytes via @p conn and write it to @p ptr. If @p use_zc
 * is @c true, and Onload libraries are available and initialized, then
 * zero-zopy API is used, otherwise @b read() syscall is used. If offloading
 * is used, data is transmitted from remote buffer to the host memory.
 *
 * @param conn      Connection handle.
 * @param ptr       Pointer to write received data to.
 * @param len       Length of data to receive.
 * @param use_zc    If @c true, use zero-copy.
 *
 * @return number of read bytes, or zero if a peer closes connection,
 *         or a negative error value in case of failure.
 */
static ssize_t
ol_ceph_recv_chunk(ol_ceph_connection *conn, void *ptr, size_t len, bool use_zc)
{
    ssize_t rc;

#if HAVE_ZC
    if (conn->hlrx != NULL)
    {
        if (use_zc)
        {
            struct onload_zc_iovec iov = {{0}};
            struct onload_zc_msg zc_msg = {
                .iov = &iov,
                .msghdr.msg_iovlen = 1,
            };

            EXP_NON_NEG(rc = onload_zc_hlrx_recv_zc(conn->hlrx, &zc_msg, len,
                                                    0));
            if (rc == 0)
                return rc;

            /*
             * If TCP/Ceph offloading is used, we get a remote buffer, which is
             * located in NIC internal memory. To read it we have to transfer
             * its contents into the host memory with ef_vi special API.
             */
            if (conn->ceph_offload_support)
            {
                rc = ol_efvi_fetch_fpga_data(conn, &iov);

                if (rc < 0)
                {
                    /*
                    * In case of error do not exit right now because we need to
                    * release the buffer first.
                    */
                    fprintf(stderr, "Fetching data from FPGA failed\n");
                }

                memcpy(ptr, conn->ef_vi.dma_mem, iov.iov_len);
            }
            else
            {
                memcpy(ptr, iov.iov_base, iov.iov_len);
            }

            EXP_NON_NEG(onload_zc_hlrx_buffer_release(conn->socket, iov.buf));
            return rc;
        }
        else
        {
            EXP_NON_NEG(rc = onload_zc_hlrx_recv_copy(
                                conn->hlrx,
                                &(struct msghdr) {
                                    .msg_iov = &(struct iovec){.iov_base = ptr,
                                                               .iov_len = len},
                                    .msg_iovlen = 1
                                },
                                0));
            return rc;
        }
    }
#endif /* HAVE_ZC */
    CHECK_SYSCALL(rc = recv(conn->socket, ptr, len, 0));
    return rc;
}

static ssize_t
ol_ceph_recv_gen(ol_ceph_connection *conn, size_t len_to_read, bool append,
                 bool use_zc)
{
    size_t data_left = len_to_read;

    if (!append)
        conn->offs = 0;

    if (len_to_read + conn->offs > conn->buflen)
    {
        fprintf(stderr, "receiver: buffer length is too small (len_to_read=%lu,"
                "offs=%lu,buflen=%lu)\n",
                len_to_read, conn->offs, conn->buflen);
        return -ENOBUFS;
    }

    while (data_left > 0)
    {
        void *buf_ptr = (void *)((uintptr_t)conn->buf + conn->offs);
        ssize_t rc = 0;

        rc = ol_ceph_recv_chunk(conn, buf_ptr, data_left, use_zc);

        if (rc > 0)
        {
            conn->offs += rc;
            data_left -= rc;
        }
        else if (rc == 0)
        {
            printf("receiver: peer closed the connection\n");
            return rc;
        }
        else
        {
            fprintf(stderr, "receiver: receive error - %s\n", strerror(-rc));
            return rc;
        }
    }

    return len_to_read;
}

static void
ol_ceph_fill_rand(void *buf, size_t len)
{
    size_t i;
    uint8_t *ptr = buf;

    for (i = 0; i < len; i++)
        *ptr++ = rand();
}

int
ol_ceph_conn_init(ol_ceph_connection *conn, int s, const char *iface, void *buf,
                  size_t buflen, bool use_zc)
{
    assert(conn != NULL);

    srand((unsigned)time(NULL));

    conn->buf = buf;
    conn->buflen = buflen;
    conn->socket = s;
    conn->offs = 0;

    if (use_zc)
    {
#if HAVE_ZC
        int rc = 0;

        conn->hlrx = NULL;
        conn->ceph_offload_support = false;

        ZC_FIND_FUNC(onload_zc_hlrx_alloc);
        ZC_FIND_FUNC(onload_zc_hlrx_free);
        ZC_FIND_FUNC(onload_zc_hlrx_recv_zc);
        ZC_FIND_FUNC(onload_zc_hlrx_buffer_release);
        ZC_FIND_FUNC(onload_zc_hlrx_recv_copy);

        EXP_NON_NEG(onload_zc_hlrx_alloc(s, 0, &conn->hlrx));

        /* Check whether TCP/Ceph offloading is supported and enabled. */
        conn->ceph_offload_support = ol_ceph_offload_check(conn->socket);
        if (conn->ceph_offload_support)
        {
            rc = ol_efvi_init(&conn->ef_vi, iface);
            if (rc < 0)
            {
                conn->ceph_offload_support = false;
                fprintf(stderr, "Failed to init ef_vi instance. Offloading is "
                        "not supported\n");
                ol_ceph_offload_disable(conn->socket);
                return rc;
            }
        }
#else
        printf("Onload headers are not found. Zero-copy is not supported.\n");
#endif /* HAVE_ZC */
    }
    return 0;
}

int
ol_ceph_conn_close(ol_ceph_connection *conn)
{
#if HAVE_ZC
    if (conn->ceph_offload_support)
        EXP_NON_NEG(ol_efvi_deinit(&conn->ef_vi));

    if (conn->hlrx != NULL)
    {
        EXP_NON_NEG(onload_zc_hlrx_free(conn->hlrx));
        return 0;
    }
#endif /* HAVE_ZC */
    CHECK_SYSCALL(close(conn->socket));
    return 0;
}

ssize_t
ol_ceph_recv(ol_ceph_connection *conn, size_t len_to_read, bool append)
{
    return ol_ceph_recv_gen(conn, len_to_read, append, false);
}

ssize_t
ol_ceph_recv_zc(ol_ceph_connection *conn, size_t len_to_read, bool append)
{
    return ol_ceph_recv_gen(conn, len_to_read, append, true);
}

ssize_t
ol_ceph_send(ol_ceph_connection *conn)
{
    size_t len = conn->offs;
    ssize_t sent;

    CHECK_SYSCALL(sent = send(conn->socket, conn->buf, len, 0));

    if (sent != len)
    {
        fprintf(stderr, "Failed to send full data - %ld instead of %lu\n",
                sent, len);
    }

    conn->offs = 0;
    return sent;
}

int
ol_ceph_append(ol_ceph_connection *conn, const void *data, size_t len)
{
    void *buf_ptr = (void *)((uintptr_t)conn->buf + conn->offs);

    if (conn->offs + len > conn->buflen)
        return -ENOBUFS;

    if (data == NULL)
        ol_ceph_fill_rand(buf_ptr, len);
    else
        memcpy(buf_ptr, data, len);

    conn->offs += len;
    return 0;
}
