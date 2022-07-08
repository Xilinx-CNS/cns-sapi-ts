/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros for SO_LINGER socket option tests 
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __SOCKOPTS_LINGER_H__
#define __SOCKOPTS_LINGER_H__

/* Create aux process if the socket closing is done by process stopping. */
#define ST_LINGER_CREATE_PROCESS \
do {                                                \
    if (way == CL_EXIT || way == CL_KILL)           \
    {                                               \
        rcf_rpc_server *pco_tmp = NULL;             \
                                                    \
        CHECK_RC(rcf_rpc_server_create_process(pco_iut, \
            "pco_iut_child", 0, &pco_iut_par));         \
        pco_tmp = pco_iut_par;                      \
        pco_iut_par = pco_iut;                      \
        pco_iut = pco_tmp;                          \
    }                                               \
} while(0)

/**
 * Check if current iteration tests loopback.
 * 
 * @param pco_iut   IUT RPC handler
 * @param pco_tst   Tetster RPC handler
 * 
 * @return @c TRUE if both RPC handlers belongs to a one host.
 */
static inline te_bool
linger_lo_iter(rcf_rpc_server *pco_iut, rcf_rpc_server *pco_tst)
{
    if (strcmp(pco_iut->ta, pco_tst->ta) == 0)
        return TRUE;

    return FALSE;
}

/* Put tester or loopback interface name in dependence on environments. */
#define SOCKOPTS_LINGER_GET_IF \
    linger_lo_iter(pco_iut, pco_tst) ? "lo" : tst_if->if_name

/* Establish TCP connection. */
#define ST_LINGER_GEN_CONNECTION(_pco_iut, _pco_tst, _iut_addr, _tst_addr) \
do {                                                                    \
    iut_l = rpc_socket(_pco_iut, rpc_socket_domain_by_addr(_iut_addr),  \
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);                 \
    rpc_bind(_pco_iut, iut_l, _iut_addr);                               \
    rpc_listen(_pco_iut, iut_l, -1);                                    \
    tst_s = rpc_socket(_pco_tst, rpc_socket_domain_by_addr(_tst_addr),  \
                       RPC_SOCK_STREAM, RPC_PROTO_DEF);                 \
    rpc_bind(_pco_tst, tst_s, _tst_addr);                               \
    rpc_connect(_pco_tst, tst_s, _iut_addr);                            \
    iut_s = rpc_accept(_pco_iut, iut_l, NULL, NULL);                    \
} while (0)

/* Close listener sockte if it is necessary. */
#define ST_LINGER_CLOSE_LISTENER \
do {                                        \
    if (way != CL_EXIT && way != CL_KILL && \
        iut_l >= 0)                         \
        rpc_close(pco_iut, iut_l);          \
    iut_l = -1;                             \
} while (0)

/* Check that no finalizing packets was sent. */
#define ST_LINGER_NO_FIN_PACKETS \
do {                                                                    \
    if (ctx.rst_ack != 0 || ctx.rst != 0 || ctx.fin_ack != 0 ||         \
        ctx.push_fin_ack != 0)                                          \
        RING_VERDICT("Unexpected finalizing packet was caught");        \
} while (0)

#endif  /* !__SOCKOPTS_LINGER_H__ */
