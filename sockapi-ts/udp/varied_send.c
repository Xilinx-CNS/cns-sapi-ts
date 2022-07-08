/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Tests
 *
 *
 * $Id:$
 */

/**
 * @page udp-varied_send Send datagrams of various size in varied ways.
 *
 * @objective Transmit datagrams during a time, sent datagrams have differnt
 *            size and iovcnt on each iteration.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME "udp/varied_send"

#include "sockapi-test.h"
#include "te_sleep.h"

/* Disable/enable RPC logging. */
#define VERBOSE_LOGGING TRUE

/* How often dump the loop execution rpogress. */
#define LOGGING_STEP 10

/* The main loop execution time, milliseconds. */
#define TEST_LOOP_TIME 3000

/* Datagrams number to be sent in a bunch. */
#define TEST_BUNCH 10

/* Minimum buffer size to use in a iov. */
#define BUF_SIZE_MIN 1

/* Middle buffer size to use in a iov. */
#define BUF_SIZE_MID 1400

/* Maximum buffer size to use in a iov. */
#define BUF_SIZE_MAX 4000

/* Maximum datagram size. */
#define DGRAM_MAX (BUF_SIZE_MAX * 2)

/* Random iovcnt vectros number > @c 2. */
#define IOVCNT_MANY rand_range(2, 10)

/* Iov vectors types. */
enum {
    IOV_KIND_MIN = 0,
    IOV_SMALL_ONE = IOV_KIND_MIN,
    IOV_SMALL_MANY,
    IOV_BIG_ONE,
    IOV_BIG_MANY,
    IOV_BIG_MANY_FSMALL,
    IOV_BIG_MANY_FLARGE,
    IOV_BIG_MANY_LSMALL,
    IOV_BIG_MANY_LLARGE,
    IOV_KIND_MAX = IOV_BIG_MANY_LLARGE
};

/* Iov vectors with length. */
typedef struct iovec_cnt {
    rpc_iovec  *iov;
    size_t      iovcnt;
} iovec_cnt;

/**
 * Allocate and fill iov vectors to send as a datagram, copy the data to the
 * single buffer @p dbuf.
 *
 * @param mtu   MTU size.
 * @param iov   Pointer to the iov vectors location.
 * @param dbuf  Data buffer.
 */
static void
make_iov_dbuf(int mtu, iovec_cnt *iov, te_dbuf *dbuf)
{
    int iov_type = rand_range(IOV_KIND_MIN, IOV_KIND_MAX);
    int min;
    int max;

    rpc_release_iov(iov->iov, iov->iovcnt);
    free(iov->iov);

    switch (iov_type)
    {
        case IOV_SMALL_ONE:
            iov->iovcnt = 1;
            min = BUF_SIZE_MIN;
            max = BUF_SIZE_MID;
            break;

        case IOV_SMALL_MANY:
            iov->iovcnt = IOVCNT_MANY;
            min = BUF_SIZE_MIN;
            max = BUF_SIZE_MID / iov->iovcnt;
            break;

        case IOV_BIG_ONE:
            iov->iovcnt = 1;
            min = BUF_SIZE_MID;
            max = BUF_SIZE_MAX;
            break;

        case IOV_BIG_MANY:
        case IOV_BIG_MANY_FSMALL:
        case IOV_BIG_MANY_FLARGE:
        case IOV_BIG_MANY_LSMALL:
        case IOV_BIG_MANY_LLARGE:
            iov->iovcnt = IOVCNT_MANY;
            min = BUF_SIZE_MID / iov->iovcnt;
            max = BUF_SIZE_MAX / iov->iovcnt;
            break;

        default:
            TEST_FAIL("Invalid iov type value");
    }

    rpc_alloc_iov(&iov->iov, iov->iovcnt, min, max);

    switch (iov_type)
    {
        case IOV_BIG_MANY_FSMALL:
            free(iov->iov[0].iov_base);
            rpc_make_iov(iov->iov, 1, BUF_SIZE_MIN, mtu);
            break;

        case IOV_BIG_MANY_FLARGE:
            free(iov->iov[0].iov_base);
            rpc_make_iov(iov->iov, 1, mtu, BUF_SIZE_MAX);
            break;

        case IOV_BIG_MANY_LSMALL:
            free(iov->iov[iov->iovcnt - 1].iov_base);
            rpc_make_iov(iov->iov + iov->iovcnt - 1, 1, BUF_SIZE_MIN, mtu);
            break;

        case IOV_BIG_MANY_LLARGE:
            free(iov->iov[iov->iovcnt - 1].iov_base);
            rpc_make_iov(iov->iov + iov->iovcnt - 1, 1, mtu, BUF_SIZE_MAX);
            break;

        default:
            ; /* Do nothing. */
    }

    rpc_iov_append2dbuf(iov->iov, iov->iovcnt, dbuf);
}

/**
 * Allocate and fill datagrams bunch in iov vectors, copy the data to the
 * single buffer @p dbuf.
 *
 * @param mtu   MTU size.
 * @param iov   Iov vectors array.
 * @param num   Datagrams number.
 * @param dbuf  Data buffer.
 */
static void
init_send_bufs(int mtu, iovec_cnt *iovs, int num, te_dbuf *dbuf)
{
    int i;

    for (i = 0; i < num; i++)
    {
        make_iov_dbuf(mtu, iovs + i, dbuf);
    }
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server         *pco_iut = NULL;
    rcf_rpc_server         *pco_tst = NULL;
    const struct sockaddr  *iut_addr = NULL;
    const struct sockaddr  *tst_addr = NULL;
    const struct if_nameindex *iut_if = NULL;

    te_dbuf snd_buf = TE_DBUF_INIT(0);
    te_dbuf rcv_buf = TE_DBUF_INIT(0);
    char    buf[DGRAM_MAX];
    iovec_cnt iovs[TEST_BUNCH];
    struct timeval tv1;
    struct timeval tv2;
    int iut_s = -1;
    int tst_s = -1;
    int mtu;
    int len;
    int iter = 0;
    int i;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_IF(iut_if);

    memset(iovs, 0, sizeof(iovs));

    CHECK_RC(tapi_cfg_base_if_get_mtu_u(pco_iut->ta, iut_if->if_name, &mtu));

    /*- Create and bind UDP sockets on IUT and tester. */
    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    gettimeofday(&tv1, NULL);

    if (!VERBOSE_LOGGING)
    {
        pco_iut->silent_default = TRUE;
        pco_tst->silent_default = TRUE;
    }

    RING("In the loop, send %d datagrams from IUT, receive them on "
         "tester and check the data", TEST_BUNCH);
    /*- In the loop during @c 3 seconds: */
    do {
        /*-- Send a bunch of datagrams
         *      -# bunch size is @c 10;
         *      -# a datagram have the following parameters
         *        -# size
         *          -# small [1;1400]
         *          -# big [1400;4000]
         *        -# iovcnt
         *          -# one;
         *          -# many [2;10]
         *      -# each datagram has one of the following parameters set
         *         (size-iovcnt) chosen randomly
         *        -# small-one
         *        -# small-many
         *        -# big-one
         *        -# big-many
         *        -# big-many, first iov is smaller than MTU
         *        -# big-many, first iov is larger than MTU
         *        -# big-many, last iov is smaller than MTU
         *        -# big-many, last iov is larger than MTU */
        init_send_bufs(mtu, iovs, TEST_BUNCH, &snd_buf);
        for (i = 0; i < TEST_BUNCH; i++)
        {
            rc = rpc_writev(pco_iut, iut_s, iovs[i].iov, iovs[i].iovcnt);
            len = rpc_iov_data_len(iovs[i].iov, iovs[i].iovcnt);
            if (rc != len)
            {
                ERROR("Sent data amount is %d instead of %d", rc, len);
                TEST_VERDICT("Incorrect data amount was returned from the "
                             "writev() call");
            }
        }

        /*-- Read and check datagrams on tester. */
        for (i = 0; i < TEST_BUNCH; i++)
        {
            rc = rpc_recv(pco_tst, tst_s, buf, DGRAM_MAX, 0);
            te_dbuf_append(&rcv_buf, buf, rc);
        }
        SOCKTS_CHECK_RECV(pco_tst, snd_buf.ptr, rcv_buf.ptr,
                          snd_buf.len, rcv_buf.len);
        te_dbuf_reset(&snd_buf);
        te_dbuf_reset(&rcv_buf);

        gettimeofday(&tv2, NULL);
        if (iter % LOGGING_STEP == 0)
            RING("Iteration number %d, remaining execution time %dms", iter,
                 TEST_LOOP_TIME - TE_US2MS(TIMEVAL_SUB(tv2, tv1)));
        iter++;
    } while(TE_US2MS(TIMEVAL_SUB(tv2, tv1)) < TEST_LOOP_TIME);

    TEST_SUCCESS;

cleanup:
    pco_iut->silent_default = FALSE;
    pco_tst->silent_default = FALSE;

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    TEST_END;
}
