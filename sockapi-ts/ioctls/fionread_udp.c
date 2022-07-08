/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * IOCTL Requests
 * 
 * $Id$
 */

/** @page ioctls-fionread_udp Usage of FIONREAD and SIOCINQ requests with connectionless sockets
 *
 * @objective Check that @c FIONREAD and @c SIOCINQ requests return
 *            the current number of bytes on the socket's receive queue.
 *            For UDP sockets this includes all queued datagrams.
 * 
 * @note Be aware that the count returned for a UDP socket by
 *       Berkeley-derived implementations includes the space required for
 *       the socket address structure containing the sender's IP address and
 *       port for each datagram (16 bytes for IPv4; 24 bytes for IPv6)
 *       @ref STEVENS, page 366.
 *
 * @type conformance
 *
 * @reference @ref XNS5 section 8.1
 *
 * @param req           IOCTL request used in the test
 *                      (@c FIONBIO or @c SIOCINQ)
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param n_bufs        Number of buffers used in the test
 * 
 * @note @c SIOCINQ request is an alias for @c FIONBIO, so that this test
 *       can be run with @c SIOCINQ request as well.
 * 
 * @par Test sequence:
 * -# Create @p iut_s socket of type @c SOCK_DGRAM on @p pco_iut.
 * -# Create @p tst_s socket of type @c SOCK_DGRAM on @p pco_tst.
 * -# @b bind() @p iut_s socket to a local address.
 * -# Create a set of transmit buffers: @p tx_buf{i} of size @p
 *    tx_buf_len{i}, (@p i = @c 0, ... @p n_bufs @c - @c 1).
 * -# Create @p rx_buf buffer of size 1 byte.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Call @b ioctl() on @p iut_s socket with @p req request 
 *    (there is no data on the socket).
 * -# Check that the function returns @c 0 and and updates @a value
 *    parameter with @c 0.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# Set @p total to zero.
 * -# Perform the following steps for each transmit buffer:
 *        - @b send() @p tx_buf{i} from @p tst_s socket to @p iut_s socket;
 *        - Call @b ioctl() on @p iut_s socket with @p req request;
 *        - Check that @p ioctl() returns @c 0;
 *        - Check @a value parameter returned by @b ioctl().
 *          There might be three possible behaviour of @p req request:
 *              -# It always returns @p tx_buf_len{0} - size of the first
 *                 datagram in socket's receive buffer. \n
 *                 @p total = @p tx_buf_len{0}.
 *                 See @ref ioctls_fionread_1 "note 1";
 *              -# Total size of all datagrams in socket's receive queue not
 *                 including socket address structure. \n
 *                 @p total += @p tx_buf_len{i}. See @ref
 *                 ioctls_fionread_2 "note 2" ;
 *              -# Total size of all datagrams in socket's receive queue
 *                 plus the space required for the socket address structure
 *                 for all datagram. \n
 *                 @p total += (@p tx_buf_len{i} + size of an
 *                 appropriate sockaddr structure). See @ref
 *                 ioctls_fionread_3 "note 3".
 *              .
 *          Check @p total against the value returned.
 *          \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Perform the following steps for each transmit buffer:
 *        - Call @b recv(@p iut_s, @p rx_buf, @c 1, @c 0); 
 *        - Call @b ioctl() on @p iut_s socket with @p req request;
 *        - Check that @p ioctl() returns @c 0;
 *        - Check @a value parameter returned by @b ioctl().
 *          There might be three possible behaviour of @p req request,
 *          that correspond to the previous list:
 *              -# It always returns @p tx_buf_len{i} - size of the first
 *                 datagram in socket's receive buffer. \n
 *                 @p total = @p tx_buf_len{i + 1}, where a buffer with non
 *                 existing index has zero length;
 *              -# Total size of all datagrams in socket's receive queue not
 *                 including socket address structure.  \n
 *                 @p total -= @p tx_buf_len{i};
 *              -# Total size of all datagrams in socket's receive queue
 *                 plus the space required for the socket address structure
 *                 for all datagram. \n
 *                 @p total -= (@p tx_buf_len{i} + size of an
 *                 appropriate sockaddr structure);
 *              .
 *          Check @p total against the value returned.
 *          \n @htmlonly &nbsp; @endhtmlonly
 *        .
 * -# Delete all @p tx_buf and @p rx_buf buffers.
 * -# Close @p iut_s and @p tst_s sockets.
 * 
 * @note
 * -# @anchor ioctls_fionread_1
 *    This is Linux behaviour;
 * -# @anchor ioctls_fionread_2
 *    This might be on non Berkeley-derived implementations, @ref STEVENS,
 *    section 13.7.
 * -# @anchor ioctls_fionread_3
 *    This is FreeBSD behaviour.
 * 
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ioctls/fionread_udp"

#include "sockapi-test.h"

 
/** Type of processing FIONREAD ioct request */
enum fionread_behav {
    LINUX_LIKE, /**< See @ref ioctls_fionread_1 */
    BERKELEY_LIKE, /**< See @ref ioctls_fionread_3 */
    OTHER_LIKE, /**< See @ref ioctls_fionread_2 */
    UNKNOWN, /**< Undefined behaviour */
};

#define RING_FIONREAD_BEHAV(behav_) \
    RING("ioctl(%s) behaviour is based on %s", ioctl_rpc2str(req),         \
         (behav_ == LINUX_LIKE) ? "Linux implementation" :                 \
         (behav_ == BERKELEY_LIKE) ? "Berkeley derived implementations" :  \
         (behav_ == OTHER_LIKE) ? "non Berkeley derived implementations" : \
         "Unknown implementation");

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    rcf_rpc_server *pco_tst = NULL;
    int             iut_s = -1;
    int             tst_s = -1;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;
    rpc_ioctl_code         req;
    int                    n_bufs = 0;
    int                    req_val;
    int                    i;
    int                    total;
    int                    ret;

    void          **tx_buf = NULL;
    size_t         *tx_buf_len = NULL;
    unsigned char   rx_buf[1]; /* Buffer of size one byte */
    
    rpc_socket_domain domain;

    
    enum fionread_behav behav;
    int                 opt_val;

    TEST_START;
    TEST_GET_IOCTL_REQ(req);
    TEST_GET_INT_PARAM(n_bufs);
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
   
    domain = rpc_socket_domain_by_addr(iut_addr);

    if (req != RPC_FIONREAD && req != RPC_SIOCINQ)
    {
        TEST_FAIL("The test does not support requests other than "
                  "FIONREAD and SIOCINQ");
    }
    if (n_bufs < 2)
    {
        TEST_FAIL("Number of buffers should be at least two");
    }

    CHECK_NOT_NULL(tx_buf = malloc(sizeof(*tx_buf) * n_bufs));
    CHECK_NOT_NULL(tx_buf_len = malloc(sizeof(*tx_buf_len) *  (n_bufs + 1)));
    memset(tx_buf, 0, sizeof(*tx_buf) * n_bufs);
    tx_buf_len[n_bufs] = 0;
    /* 
     * The last entry of tx_buf_len array does not correspond to any TX
     * buffer but it is used in validation of the request value in case
     * of Linux behaviour (see test description) 
     */

    total = 0;
    for (i = 0; i < n_bufs; i++)
    {
        CHECK_NOT_NULL(tx_buf[i] = sockts_make_buf_dgram(&(tx_buf_len[i])));
    }

    GEN_CONNECTION_WILD(pco_iut, pco_tst, RPC_SOCK_DGRAM, RPC_PROTO_DEF,
                        iut_addr, tst_addr, &iut_s, &tst_s, TRUE);

    /* Increase RCVBUF to overcome bad drivers problem */
    rpc_getsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);
    opt_val *= 2;
    rpc_setsockopt(pco_iut, iut_s, RPC_SO_RCVBUF, &opt_val);

#define CALL_IOCTL \
do {                                                        \
    RPC_AWAIT_IUT_ERROR(pco_iut);                           \
    ret = rpc_ioctl(pco_iut, iut_s, req, &req_val);         \
    if (ret != 0)                                           \
    {                                                       \
        TEST_VERDICT("ioctl(%s) unexpectedly failed with "  \
                     "errno %s", ioctl_rpc2str(req),        \
                     errno_rpc2str(RPC_ERRNO(pco_iut)));    \
    }                                                       \
} while (0)

    /* There is no data in receive buffer */
    CALL_IOCTL;
    
    if (req_val != 0)
    {
        TEST_FAIL("There is not data in receive buffer of 'iut_s' socket: "
                  "ioctl(%s) returns %d, but expected 0",
                  ioctl_rpc2str(req), req_val);
    }

    total = 0;

    /* On first */
    RPC_SEND(rc, pco_tst, tst_s, tx_buf[0], tx_buf_len[0], 0);
    MSLEEP(100);

    CALL_IOCTL;

    if (req_val == (int)tx_buf_len[0])
    {
        /*
         * It can be LINUX_LIKE or OTHER_LIKE behaviour, so that set 
         * 'behav' variable to UNKNOWN;
         */
        behav = UNKNOWN;
    }
    else if (req_val ==
             (int)(tx_buf_len[i] + sockaddr_get_size_by_domain(domain)))
    {
        behav = BERKELEY_LIKE;
    }
    else
    {
        TEST_FAIL("ioctl(%s) returns unexpected value %d: "
                  "Neither %u (as on Linux) nor %u (as on Berkeley-derived "
                  "implementations)", ioctl_rpc2str(req), req_val,
                  (unsigned)(tx_buf_len[0]),
                  (unsigned)(tx_buf_len[0] +
                             sockaddr_get_size_by_domain(domain)));
    }
    
    total = req_val;
    
    for (i = 1; i < n_bufs; i++)
    {
        RPC_SEND(rc, pco_tst, tst_s, tx_buf[i], tx_buf_len[i], 0);
        MSLEEP(100);
       
        CALL_IOCTL;
        
#define REQ_VALUE_FAIL \
        do {                                                        \
            RING_FIONREAD_BEHAV(behav);                             \
            TEST_FAIL("Unexpected value '%d' of ioctl(%s) request " \
                      "obtained after receiving %d datagram",       \
                      req_val, ioctl_rpc2str(req), i + 1);          \
        } while (0)

        if (req_val == (int)tx_buf_len[0])
        {
            if (behav != UNKNOWN && behav != LINUX_LIKE)
            {
                REQ_VALUE_FAIL;
            }
            behav = LINUX_LIKE;
            total = tx_buf_len[0];
        }
        else if (req_val == (int)(total + tx_buf_len[i]))
        {
            if (behav != UNKNOWN && behav != OTHER_LIKE)
            {
                REQ_VALUE_FAIL;
            }
            behav = OTHER_LIKE;
            total += tx_buf_len[i];
        }
        else if (req_val == (int)(total + tx_buf_len[i] + 
                                  sockaddr_get_size_by_domain(domain)))
        {
            if (behav != BERKELEY_LIKE)
            {
                REQ_VALUE_FAIL;
            }
            total += tx_buf_len[i] + sockaddr_get_size_by_domain(domain);
        }
        else
        {
            REQ_VALUE_FAIL;
        }

#undef REQ_VALUE_FAIL

    }
    RING_FIONREAD_BEHAV(behav);

    for (i = 0; i < n_bufs; i++)
    {
        rc = rpc_recv(pco_iut, iut_s, rx_buf, sizeof(rx_buf), 0);
        if (rc != sizeof(rx_buf))
        {
            TEST_FAIL("Cannot read %d bytes of %d datagram",
                      sizeof(rx_buf), i + 1);
        }

        CALL_IOCTL;
#undef CALL_IOCTL 

        switch (behav)
        {

#define CHECK_REQ_VALUE(exp_val_) \
            do {                                                            \
                if (req_val != (int)exp_val_)                               \
                {                                                           \
                    WARN("Unexpected value '%d' of ioctl(%s) request "      \
                         "obtained after reading %d datagram. "             \
                         "Expected value is '%d'",                          \
                         req_val, ioctl_rpc2str(req), i + 1, exp_val_);     \
                                                                            \
                    TEST_VERDICT("Not all datagrams successfully received"); \
                }                                                           \
            } while (0)

            case LINUX_LIKE:
                CHECK_REQ_VALUE(tx_buf_len[i + 1]);
                break;

            case OTHER_LIKE:
                total -= tx_buf_len[i];
                CHECK_REQ_VALUE(total);
                break;

            case BERKELEY_LIKE:
                total -= (tx_buf_len[i] +
                         sockaddr_get_size_by_domain(domain));
                CHECK_REQ_VALUE(total);
                break;

#undef CHECK_REQ_VALUE

            default:
                TEST_FAIL("Unknown behaviour of ioctl(%s) request",
                          ioctl_rpc2str(req));
        }
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    for (i = 0; (tx_buf != NULL) && (i < n_bufs); i++)
        free(tx_buf[i]);

    free(tx_buf);
    free(tx_buf_len);

    TEST_END;
}

