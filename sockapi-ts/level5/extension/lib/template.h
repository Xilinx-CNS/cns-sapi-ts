/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common macros and functions for Onload templates transmission API.
 *
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __ONLOAD_TEMPLATE_H__
#define __ONLOAD_TEMPLATE_H__

/**
 * Initialize vectors array
 * 
 * @param iovcnt    Vectors array length
 * @param total     Total payload length of all vectors
 * @param sndbuf    Buffer with payload or @c NULL
 * 
 * @return Pointer to iov array
 */
extern rpc_iovec *init_iovec(int iovcnt, int total, char **sndbuf);

/**
 * Clean iovec array and free memory
 * 
 * @param iov       Vector location
 * @param iovcnt    Length of the array
 */
extern void release_iovec(rpc_iovec *iov, int iovcnt);

#endif /* __ONLOAD_TEMPLATE_H__ */
