/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CEPH_PROTOCOL_TYPES_H__
#define __OL_CEPH_PROTOCOL_TYPES_H__

#include "include/msgr.h"
#include "include/ceph_fs.h"
#include "include/rados.h"

typedef struct ceph_entity_addr         ol_ceph_entityaddr;
typedef struct ceph_msg_connect_reply   ol_ceph_msg_connect_reply;
typedef struct ceph_timespec            ol_ceph_timespec;
typedef struct ceph_osd_op              ol_ceph_osd_op;
typedef struct ceph_msg_header          ol_ceph_msg_header;
typedef struct ceph_msg_footer          ol_ceph_msg_footer;

/* The type is inferred from struct object_t. See ceph/src/include/object.h. */
typedef struct __attribute__((__packed__)) ol_ceph_string
{
    uint32_t len;
    uint8_t str[64];
} ol_ceph_string;

/* The type is inferred from struct pg_t. See ceph/src/osd/osd_types.h. */
typedef struct __attribute__((__packed__)) ol_ceph_pg_t
{
    uint8_t v;
    uint64_t pool;
    uint32_t seed;
    uint32_t preferred;
} ol_ceph_pg_t;

/* The type is inferred from class eversion_t. See ceph/src/osd/osd_types.h. */
typedef struct __attribute__((__packed__)) ol_ceph_eversion_t
{
    uint64_t version;
    uint32_t epoch;
} ol_ceph_eversion_t;

/*
 * The type is inferred from struct request_redirect_t.
 * See ceph/src/osd/osd_types.h.
 */
typedef struct __attribute__((__packed__)) ol_ceph_request_redirect_t {
    uint8_t v;
    uint8_t compat;
    uint32_t struct_len;
    struct __attribute__((__packed__)) object_locator_t {
        uint8_t v;
        uint8_t compat;
        uint32_t struct_len;
        uint64_t pool;
        uint32_t preferred;
        ol_ceph_string key;
        ol_ceph_string nspace;
        uint64_t hash;
    } redirect_locator;
    ol_ceph_string redirect_object;
    uint32_t pad;
} ol_ceph_request_redirect_t;

#endif /* __OL_CEPH_PROTOCOL_TYPES_H__ */
