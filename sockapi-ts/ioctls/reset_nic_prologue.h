/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Definitions for removing/restoring serial parser pattern, used
 * in reset NIC prologue.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __IOCTLS_RESET_NIC_PROLOGUE_H__
#define __IOCTLS_RESET_NIC_PROLOGUE_H__

#define PARSER_PATTERN  "x flush outstanding after"
#define PARSER_EVENT    "x_flush_outstanding_after"
#define PARSER_OID_FMT  "/agent:LogListener/parser:%s/event:%s"
#define PARSER_OID_ARGS SERIAL_LOG_PARSER_NAME, PARSER_EVENT

#define CFG_LOCAL_PATTERN_OID "/local:/serial_pattern_name:"

#endif /* __IOCTLS_RESET_NIC_PROLOGUE_H__ */
