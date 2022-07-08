/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Asynchronous input/output internal definitions
 * 
 * $Id$
 */
 
#ifndef __AIO_INTERNAL_H__
#define __AIO_INTERNAL_H__

/**
 * Initialize sigevent structure.
 */
#define INIT_EV(_ev) \
    do {                                \
        memset(_ev, 0, sizeof(*(_ev))); \
        (_ev)->notify = RPC_SIGEV_NONE; \
    } while (0)

/**
 * Create and fill AIO control block.
 *
 * @param rpcs          RPC server handle
 * @param s             socket
 * @param opcode        LIO opcode
 * @param buf           location for the buffer
 * @param buflen        buffer length
 * @param len           length of data to be transmitted
 * @param ev            sigevent pointer or NULL (for SIGEV_NONE)
 * @param cb            location for control block 
 */
static inline void
create_aiocb(rcf_rpc_server *rpcs, int s, rpc_lio_opcode opcode, rpc_ptr *buf, 
             int buflen, int len, tarpc_sigevent *ev, rpc_aiocb_p *cb)
{
    tarpc_sigevent ev0;

    if (ev == NULL)
    {
        ev = &ev0;
        INIT_EV(ev);
    }
        
    *buf = rpc_malloc(rpcs, buflen);
    *cb = rpc_create_aiocb(rpcs);
    rpc_fill_aiocb(rpcs, *cb, s, opcode, 0, *buf, len, ev);
}             

/** 
 * Cancel the AIO request on the PCO or restart PCO.
 *
 * @param _rpcs         PCO
 * @param _fd           file descriptor
 * @param _cb           AIO control block
 */
#define CLEANUP_AIO_CANCEL(_rpcs, _fd, _cb) \
    do {                                                                \
        if ((_rpcs != NULL) && (_cb != RPC_NULL) && (_fd != -1))        \
        {                                                               \
            if (rpc_aio_cancel(_rpcs, _fd, _cb) == RPC_AIO_NOTCANCELED) \
            {                                                           \
                WARN("PCO %s is restarted because aio_cancel() "        \
                     "returned  AIO_NOTCANCELLED", _rpcs->name);        \
                rcf_rpc_server_restart(_rpcs);                          \
                _rpcs = NULL;                                           \
            }                                                           \
        }                                                               \
    } while (0)

#define AIO_CALLBACK_NAME       "aio_callback_"
#define AIO_SIGHANDLER_NAME     "aio_sighandler_"

#endif /* __AIO_INTERNAL_H__ */
