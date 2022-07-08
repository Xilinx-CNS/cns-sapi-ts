/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "ol_ceph_protocol_types.h"
#include "ol_ceph_protocol.h"
#include "ol_ceph_connection.h"
#include "ol_poll.h"
#include "ol_helpers.h"

/* Length of the banner excluding terminating null */
#define OL_CEPH_BANNER_LEN (sizeof(CEPH_BANNER) - 1)

/**
 * Call @ref ol_ceph_recv with the corresponding parameters and exit if
 * an error occurs.
 */
#define OL_CEPH_RECV(_conn, _len2read, _append) \
    do {                                                    \
        int _rc = ol_ceph_recv(_conn, _len2read, _append);  \
        if (_rc < 0)                                        \
            return OL_CEPH_RECV_ERROR;                      \
        else if (_rc == 0)                                  \
            return OL_CEPH_RECV_ZERO;                       \
    } while(0)

#define OL_CEPH_CONN_CHECK_RC(_call)    \
    do {                                \
        if ((_call) < 0)                \
            return OL_CEPH_SEND_ERROR;  \
    } while (0)

/**
 * Exit from the function if @p _expr returns non-success code and log if it
 * is an error.
 *
 * @param _expr Expression with @ref ol_ceph_proto_rc return value.
 */
#define OL_CEPH_CHECK_RC(_expr) \
    do {                                                                \
        ol_ceph_proto_rc _rc = (_expr);                                 \
        if (_rc != OL_CEPH_OK)                                          \
        {                                                               \
            if (_rc != OL_CEPH_RECV_ZERO)                               \
            {                                                           \
                fprintf(stderr, "%s:%d: %s failed, ceph_rc=%s\n",       \
                        __FILE__, __LINE__, #_expr, cephrc2str(_rc));   \
            }                                                           \
            return _rc;                                                 \
        }                                                               \
    } while (0)

static const char *
cephrc2str(ol_ceph_proto_rc rc)
{
#define CASE_RC2STR(_rc) case _rc: return #_rc

    switch (rc)
    {
        CASE_RC2STR(OL_CEPH_OK);
        CASE_RC2STR(OL_CEPH_RECV_ERROR);
        CASE_RC2STR(OL_CEPH_SEND_ERROR);
        CASE_RC2STR(OL_CEPH_RECV_ZERO);
        CASE_RC2STR(OL_CEPH_HANDLE_ERROR);
        default: return "<unknown>";
    }

#undef CASE_RC2STR
}

static bool
is_connect_reply_tag(uint8_t tag)
{
    switch (tag)
    {
        case CEPH_MSGR_TAG_READY:
        case CEPH_MSGR_TAG_RESETSESSION:
        case CEPH_MSGR_TAG_WAIT:
        case CEPH_MSGR_TAG_RETRY_SESSION:
        case CEPH_MSGR_TAG_RETRY_GLOBAL:
        case CEPH_MSGR_TAG_BADPROTOVER:
        case CEPH_MSGR_TAG_BADAUTHORIZER:
        case CEPH_MSGR_TAG_FEATURES:
        case CEPH_MSGR_TAG_SEQ:
            return true;

        default:
            return false;
    }
}

static ol_ceph_proto_rc
ol_ceph_send_banner(ol_ceph_proto_handle *h)
{
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, CEPH_BANNER,
                                         OL_CEPH_BANNER_LEN));
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                         2 * sizeof(ol_ceph_entityaddr)));
    OL_CEPH_CONN_CHECK_RC(ol_ceph_send(&h->conn));
    h->state = OL_CEPH_STATE_OPENED;
    printf("Sent banner\n");

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_send_conn_reply(ol_ceph_proto_handle *h, uint8_t tag)
{
    ol_ceph_msg_connect_reply *msg = (ol_ceph_msg_connect_reply *)h->conn.buf;

    if (!is_connect_reply_tag(tag))
    {
        fprintf(stderr, "Invalid tag specified - %d\n", tag);
        return OL_CEPH_SEND_ERROR;
    }

    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(*msg)));
    if (tag == CEPH_MSGR_TAG_SEQ)
        OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint64_t)));

    msg->tag = tag;
    msg->authorizer_len = 0;

    OL_CEPH_CONN_CHECK_RC(ol_ceph_send(&h->conn));
    h->state = OL_CEPH_STATE_SEND_MSG;
    printf("Sent connect-reply\n");

    return OL_CEPH_OK;
}

/**
 * Compute length of front field of @c OSD_OPREPLY message.
 *
 * @return length in bytes.
 */
static size_t
ol_ceph_front_len(int n_ops)
{
    return sizeof(ol_ceph_string) +             /* oid */
           sizeof(ol_ceph_pg_t) +               /* pgid */
           sizeof(uint64_t) +                   /* flags */
           sizeof(uint32_t) +                   /* result */
           sizeof(ol_ceph_eversion_t) +         /* bad_replay_version */
           sizeof(uint32_t) +                   /* osdmap_epoch */
           sizeof(uint32_t) +                   /* num_ops */
           sizeof(ol_ceph_osd_op) * n_ops +     /* ops[num_ops] */
           sizeof(uint32_t) +                   /* retry_attempt */
           sizeof(uint32_t) * n_ops +           /* rval[num_ops] */
           sizeof(ol_ceph_eversion_t) +         /* replay_version */
           sizeof(uint64_t) +                   /* user_version */
           sizeof(ol_ceph_request_redirect_t);  /* request_redirect */
}

/**
 * Generate @c OSD_OPREPLY message with @p n_ops data messages of @c OSD_OP_READ
 * type, and write it to connection buffer. A user callback passed to
 * @ref ol_ceph_proto_generator_init is called on every data message generating.
 *
 * @param h         Protocol handle.
 * @param n_ops     Number of operations to encode.
 *
 * @return ceph protocol status code.
 */
static ol_ceph_proto_rc
ol_ceph_generate_msg(ol_ceph_proto_handle *h, int n_ops)
{
    ol_ceph_msg_header msg_hdr;
    ol_ceph_msg_footer footer = {0};
    int i;
    ol_ceph_string oid;
    ol_ceph_request_redirect_t req_redirect = {0};

    msg_hdr.src.type = CEPH_ENTITY_TYPE_OSD;
    msg_hdr.src.num = 0;
    msg_hdr.version = 8;
    msg_hdr.crc = 0;
    msg_hdr.type = CEPH_MSG_OSD_OPREPLY;
    msg_hdr.front_len = ol_ceph_front_len(n_ops);
    msg_hdr.middle_len = 0;
    msg_hdr.data_len = OL_CEPH_MAX_DATA_LEN;
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &msg_hdr, sizeof(msg_hdr)));

    /* FRONT */
    /* oid */
    oid.len = sizeof(oid.str);
    memset(oid.str, 'a', oid.len);
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &oid, sizeof(oid)));
    /* pgid */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(ol_ceph_pg_t)));
    /* flags */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint64_t)));
    /* result */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint32_t)));
    /* bad_replay_version */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                         sizeof(ol_ceph_eversion_t)));
    /* osdmap_epoch */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint32_t)));
    /* num_ops */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &n_ops, sizeof(n_ops)));
    /* ops[num_ops] */
    for (i = 0; i < n_ops; i++)
    {
        ol_ceph_osd_op op_hdr;

        op_hdr.op = CEPH_OSD_OP_READ;
        op_hdr.flags = 0;
        op_hdr.extent.offset = 0;
        op_hdr.extent.length = msg_hdr.data_len;
        op_hdr.extent.truncate_seq = 0;
        op_hdr.extent.truncate_size = 0;
        op_hdr.payload_len = msg_hdr.data_len;
        OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &op_hdr,
                                             sizeof(op_hdr)));
    }
    /* retry_attempt */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint32_t)));
    /* rval[num_ops] */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                         sizeof(uint32_t) * n_ops));
    /* replay_version */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                         sizeof(ol_ceph_eversion_t)));
    /* user_version */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL, sizeof(uint64_t)));
    /* request_redirect */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &req_redirect,
                                         sizeof(req_redirect)));

    /* DATA */
    for (i = 0; i < n_ops; i++)
    {
        if (h->user_data_cb.callback != NULL)
        {
            char user_data[OL_CEPH_MAX_DATA_LEN];
            ol_ceph_opread_wr_callback callback = h->user_data_cb.callback;

            callback(user_data, sizeof(user_data), h->user_data_cb.user_data);
            OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, user_data,
                                                 sizeof(user_data)));
        }
        else
        {
            OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                                 OL_CEPH_MAX_DATA_LEN));
        }
    }

    /* FOOTER */
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &footer, sizeof(footer)));

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_send_msg(ol_ceph_proto_handle *h, uint8_t tag)
{
    OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, &tag, sizeof(tag)));

    switch (tag)
    {
        case CEPH_MSGR_TAG_ACK:
            OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                                 sizeof(uint64_t)));
            break;

        case CEPH_MSGR_TAG_KEEPALIVE2:
        case CEPH_MSGR_TAG_KEEPALIVE2_ACK:
            OL_CEPH_CONN_CHECK_RC(ol_ceph_append(&h->conn, NULL,
                                                 sizeof(ol_ceph_timespec)));
            break;

        case CEPH_MSGR_TAG_MSG:
            OL_CEPH_CHECK_RC(ol_ceph_generate_msg(h, 1));
            break;

        default:
            break;
    }

    OL_CEPH_CONN_CHECK_RC(ol_ceph_send(&h->conn));

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_handle_banner(ol_ceph_proto_handle *h)
{
    if (h->state != OL_CEPH_STATE_CLOSED)
    {
        fprintf(stderr, "Got banner within invalid state\n");
        return OL_CEPH_HANDLE_ERROR;
    }

    if (memcmp(h->conn.buf, CEPH_BANNER, OL_CEPH_BANNER_LEN) != 0)
    {
        fprintf(stderr, "Wrong banner\n");
        ol_hex_diff_dump((uint8_t *)CEPH_BANNER, h->conn.buf,
                         OL_CEPH_BANNER_LEN);
        return OL_CEPH_HANDLE_ERROR;
    }

    printf("Got banner\n");
    h->state = OL_CEPH_STATE_OPENED;

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_read_banner(ol_ceph_proto_handle *h)
{
    size_t msg_size = OL_CEPH_BANNER_LEN + 2 * sizeof(ol_ceph_entityaddr);
    OL_CEPH_RECV(&h->conn, msg_size, false);
    return ol_ceph_handle_banner(h);
}

static ol_ceph_proto_rc
ol_ceph_handle_connect_reply(ol_ceph_proto_handle *h)
{
    ol_ceph_msg_connect_reply *msg = h->conn.buf;

    if (h->state != OL_CEPH_STATE_OPENED)
    {
        fprintf(stderr, "Got connect-reply within invalid state\n");
        return OL_CEPH_HANDLE_ERROR;
    }

    if (!is_connect_reply_tag(msg->tag))
    {
        fprintf(stderr, "Got invalid tag %d\n", msg->tag);
        return OL_CEPH_HANDLE_ERROR;
    }

    printf("Got connect-reply\n");
    h->state = OL_CEPH_STATE_WAIT_MSG;

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_read_connect_reply(ol_ceph_proto_handle *h)
{
    ol_ceph_msg_connect_reply *msg;

    printf("Reading connect-reply\n");
    OL_CEPH_RECV(&h->conn, sizeof(ol_ceph_msg_connect_reply), false);

    msg = (ol_ceph_msg_connect_reply *)h->conn.buf;
    printf("Reading auth %d bytes\n", msg->authorizer_len);
    if (msg->authorizer_len > 0)
        OL_CEPH_RECV(&h->conn, msg->authorizer_len, true);

    if (msg->tag == CEPH_MSGR_TAG_SEQ)
    {
        printf("Reading tag seq\n");
        OL_CEPH_RECV(&h->conn, sizeof(uint64_t), true);
    }

    return ol_ceph_handle_connect_reply(h);
}

static ol_ceph_proto_rc
ol_ceph_handle_msg(ol_ceph_proto_handle *h)
{
    if (h->user_data_cb.callback != NULL)
    {
        ol_ceph_opread_rd_callback callback = h->user_data_cb.callback;
        callback(h->conn.buf, h->conn.offs, h->user_data_cb.user_data);
    }

    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_read_footer(ol_ceph_proto_handle *h)
{
    OL_CEPH_RECV(&h->conn, sizeof(ol_ceph_msg_footer), false);
    return OL_CEPH_OK;
}

static ol_ceph_proto_rc
ol_ceph_read_msg(ol_ceph_proto_handle *h)
{
    uint8_t tag;

    OL_CEPH_RECV(&h->conn, sizeof(tag), false);

    tag = *((uint8_t *)h->conn.buf);

    if (tag == CEPH_MSGR_TAG_MSG)
    {
        ol_ceph_msg_header *hdr;
        uint32_t front_len;
        uint32_t middle_len;
        uint32_t data_len;

        OL_CEPH_RECV(&h->conn, sizeof(ol_ceph_msg_header), false);

        hdr = h->conn.buf;
        front_len = hdr->front_len;
        middle_len = hdr->middle_len;
        data_len = hdr->data_len;

        if (front_len > 0)
            OL_CEPH_RECV(&h->conn, front_len, false);

        if (middle_len > 0)
            OL_CEPH_RECV(&h->conn, middle_len, false);

        if (data_len > 0)
        {
            int rc = ol_ceph_recv_zc(&h->conn, data_len, false);

            if (rc < 0)
                return OL_CEPH_RECV_ERROR;
            else if (rc == 0)
                return OL_CEPH_RECV_ZERO;

            OL_CEPH_CHECK_RC(ol_ceph_handle_msg(h));
        }

        return ol_ceph_read_footer(h);
    }

    fprintf(stderr, "%s(): cannot handle the tag %d\n", __FUNCTION__, tag);
    return OL_CEPH_HANDLE_ERROR;
}

int
proto_rc2poll_rc(ol_ceph_proto_rc ceph_proto_rc)
{
    switch (ceph_proto_rc)
    {
        case OL_CEPH_OK:
            return OL_POLL_RC_OK;

        case OL_CEPH_RECV_ERROR:
        case OL_CEPH_HANDLE_ERROR:
        case OL_CEPH_SEND_ERROR:
            return OL_POLL_RC_FAIL;

        case OL_CEPH_RECV_ZERO:
            return OL_POLL_RC_STOP;

        default:
            fprintf(stderr, "Fail to handle ceph protocol return code\n");
            return OL_POLL_RC_FAIL;
    }
}

int
ol_ceph_proto_client_init(ol_ceph_proto_handle *h, int s, const char *iface,
                          void *buf, size_t len,
                          ol_ceph_opread_rd_callback callback, void *user_data)
{
    if (h == NULL)
        return -1;

    h->state = OL_CEPH_STATE_CLOSED;
    h->user_data_cb.callback = callback;
    h->user_data_cb.user_data = user_data;
    return ol_ceph_conn_init(&h->conn, s, iface, buf, len, true);
}

int
ol_ceph_proto_generator_init(ol_ceph_proto_handle *h, int s, void *buf,
                             size_t len, ol_ceph_opread_wr_callback callback,
                             void *user_data)
{
    h->state = OL_CEPH_STATE_CLOSED;
    h->user_data_cb.callback = callback;
    h->user_data_cb.user_data = user_data;
    return ol_ceph_conn_init(&h->conn, s, NULL, buf, len, false);
}

ol_ceph_proto_rc
ol_ceph_recv_state_proc(ol_ceph_proto_handle *h)
{
    ol_ceph_proto_rc rc = OL_CEPH_OK;

    switch (h->state)
    {
        case OL_CEPH_STATE_CLOSED:
            rc = ol_ceph_read_banner(h);
            break;

        case OL_CEPH_STATE_OPENED:
            rc = ol_ceph_read_connect_reply(h);
            break;

        case OL_CEPH_STATE_WAIT_MSG:
            rc = ol_ceph_read_msg(h);
            break;

        default:
            break;
    }

    OL_CEPH_CHECK_RC(rc);
    return OL_CEPH_OK;
}

ol_ceph_proto_rc
ol_ceph_generator_state_proc(ol_ceph_proto_handle *h)
{
    ol_ceph_proto_rc rc = OL_CEPH_OK;

    switch (h->state)
    {
        case OL_CEPH_STATE_CLOSED:
            rc = ol_ceph_send_banner(h);
            break;

        case OL_CEPH_STATE_OPENED:
            rc = ol_ceph_send_conn_reply(h, CEPH_MSGR_TAG_SEQ);
            break;

        case OL_CEPH_STATE_SEND_MSG:
            rc = ol_ceph_send_msg(h, CEPH_MSGR_TAG_MSG);
            break;

        default:
            break;
    }

    OL_CEPH_CHECK_RC(rc);
    return OL_CEPH_OK;
}
