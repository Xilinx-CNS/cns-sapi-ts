/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Socket options
 *
 * $Id$
 */

/** @page sockopts-tcpinfo_optlen Checking receipt of the partial @b tcp_info
 *        from the @b getsockopt
 *
 * @objective Checking the result of the work @b getsockopt with argument
 *            @b TCP_INFO in a variety of value @b opt_len.
 *
 * @type conformance
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TESTER
 * @param iut_s         TCP socket on @p pco_iut
 * @param tst_s         TCP socket on @p pco_tst
 * @param overflow      Size of overflow @b opt_val
 *
 * @par Test sequence:
 * -# Specifies and check the actual size of the structure @b tcp_info.
 * -# Validates receiving partial when @b opt_val is less then size of tcp_info
 * -# Checks limiting when @b opt_len is greater than size of tcp_info
 *
 * @author Oleg Sadakov <osadakov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "sockopts/tcpinfo_optlen"

#include "sockapi-test.h"

/*
 * If we assume that the userland structure size tcp_info is different from
 * the size in the kernel space then:
 */

/** Sufficient size for buffer @b opt_val */
#define SUFFICIENT_SIZE(userland_sizeof_tcpinfo) \
    ((userland_sizeof_tcpinfo) * 4)

/**
 * The maximum allowable size of the structure @b tcp_info kernel space at the
 * specified size in the userland
 */
#define LIMIT_SIZE(userland_sizeof_tcpinfo) \
    ((userland_sizeof_tcpinfo) * 2)

/** The uninteresting arguments of the function @b real_size */
typedef struct real_size_ua {
    rcf_rpc_server* pco; /**< RPC server */
    int s;               /**< Socket */
    uint8_t* opt_val_00; /**< @b opt_val filled 0x00 */
    uint8_t* opt_val_ff; /**< @b opt_val filled 0xff */
    socklen_t buf_rlen;  /**< Maximum size of @b opt_val */
} real_size_ua;

/** The result of the function @b real_size */
typedef struct real_size_res {
    socklen_t real_size; /**< Actual length of the @b opt_val */
    socklen_t opt_len;   /**< Updated value of the @b opt_len */
} real_size_res;

/**
 * Calculates the actual length of the @b opt_val
 *
 * @param rs_ia    Uninteresting arguments
 * @param opt_len  Specified size of @b opt_val
 *
 * @return actual length of the @b opt_val and @b opt_len
 */
static inline real_size_res
real_size(real_size_ua rs_ua, socklen_t opt_len)
{
    real_size_res r;
    socklen_t opt_len_ff = opt_len;

    memset(rs_ua.opt_val_00, 0x00, rs_ua.buf_rlen);
    CHECK_RC(rpc_getsockopt_gen(rs_ua.pco, rs_ua.s,
                                RPC_SOL_TCP, RPC_TCP_INFO, NULL,
                                rs_ua.opt_val_00, &opt_len, rs_ua.buf_rlen));

    memset(rs_ua.opt_val_ff, 0xff, rs_ua.buf_rlen);
    CHECK_RC(rpc_getsockopt_gen(rs_ua.pco, rs_ua.s,
                                RPC_SOL_TCP, RPC_TCP_INFO, NULL,
                                rs_ua.opt_val_ff, &opt_len_ff, rs_ua.buf_rlen));

    if (opt_len != opt_len_ff)
    {
        TEST_VERDICT("Different results in the sequence of calls "
                     "getsockopt (%d != %d)",
                     opt_len, opt_len_ff);
    }

    r.opt_len = opt_len;
    for (r.real_size = 0; r.real_size < rs_ua.buf_rlen; r.real_size++)
        if(rs_ua.opt_val_00[r.real_size] == 0x00 &&
           rs_ua.opt_val_ff[r.real_size] == 0xff)
            break;

    return r;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst = NULL;
    int                    iut_s = -1;
    int                    tst_s = -1;
    int                    overflow = 0;

    int                    overflow_i = 0;
    socklen_t              opt_len = 0;
    socklen_t              opt_len_userland = 0;
    real_size_res          rs_actual;
    real_size_res          rs_current;
    real_size_ua           rs_ua;

    const struct sockaddr *iut_addr;
    const struct sockaddr *tst_addr;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);

    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);

    TEST_GET_INT_PARAM(overflow);

    GEN_CONNECTION(pco_iut, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                   iut_addr, tst_addr, &iut_s, &tst_s);

    opt_len_userland = rpc_get_sizeof(pco_iut, "struct tcp_info");

    rs_ua.pco        = pco_iut;
    rs_ua.s          = iut_s;
    rs_ua.buf_rlen   = SUFFICIENT_SIZE(opt_len_userland);
    rs_ua.opt_val_00 = te_make_buf_by_len(rs_ua.buf_rlen);
    rs_ua.opt_val_ff = te_make_buf_by_len(rs_ua.buf_rlen);

    /* Specifies and check the actual size of tcp_info */
    rs_actual = real_size(rs_ua, rs_ua.buf_rlen);
    if (rs_actual.real_size != opt_len_userland)
    {
        if (rs_actual.real_size > LIMIT_SIZE(opt_len_userland))
        {
            TEST_VERDICT("The actual length of tcp_info (%d) is "
                         "much more than obtained from "
                         "sizeof(struct tcp_info) = %d.",
                         rs_actual.real_size, opt_len_userland);
        }
        if (rs_actual.real_size < opt_len_userland)
        {
            TEST_VERDICT("The actual length of tcp_info (%d) is "
                         "less than obtained from "
                         "sizeof(struct tcp_info) = %d.",
                         rs_actual.real_size, opt_len_userland);
        }
    }
    if (rs_actual.opt_len != rs_actual.real_size)
    {
        TEST_VERDICT("Invalid function result: opt_len (%d) != %d",
                     rs_actual.opt_len, rs_actual.real_size);
    }
    INFO("The actual length of tcp_info is %d", rs_actual.real_size);

    /* Check receiving partial opt_val */
    for (opt_len = 0; opt_len < rs_actual.real_size; opt_len++)
    {
        rs_current = real_size(rs_ua, opt_len);

        if (opt_len != rs_current.opt_len)
            TEST_VERDICT("getsockopt(%d, %d) has changed opt_len",
                         opt_len, rs_current.opt_len);

        if (opt_len != rs_current.real_size)
            TEST_VERDICT("getsockopt(%d, %d) returned the wrong data",
                         opt_len, rs_current.real_size);
    }

    /* Check limitation opt_len when it is more than actual opt_len */
    for (overflow_i = 0; overflow_i < overflow; overflow_i++, opt_len++)
    {
        rs_current = real_size(rs_ua, opt_len);

        if (rs_actual.real_size != rs_current.opt_len)
            TEST_VERDICT("getsockopt(%d, %d, %d) has changed opt_len",
                         opt_len, rs_actual.real_size, rs_current.opt_len);

        if (rs_actual.real_size != rs_current.real_size)
            TEST_VERDICT("getsockopt(%d, %d, %d) returned the wrong data",
                         opt_len, rs_actual.real_size, rs_current.real_size);
    }

    TEST_SUCCESS;

cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, iut_s);
    CLEANUP_RPC_CLOSE(pco_tst, tst_s);

    free(rs_ua.opt_val_00);
    free(rs_ua.opt_val_ff);

    TEST_END;
}
