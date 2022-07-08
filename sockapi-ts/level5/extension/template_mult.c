/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Onload extensions
 *
 * $Id$
 */

/** @page extension-template_mult Allocate and pass a few templates
 *
 * @objective  Allocate and pass a few templates via a few sockets
 *
 * @param pco_iut       PCO on IUT
 * @param pco_tst       PCO on TST
 * @param iovcnt        IOVs array length
 * @param total         Total amount of data to be passed by template
 * @param sockets_num   Sockets number
 * @param updates_num   Updates number
 * @param templates_num Templates number to be allocated
 * @param send_num      Number templates which should be sent
 * @param order         If @c TRUE send templates in the same order as they
 *                      were allocated, if @c FALSE send in reverse order
 * @param thread_prcess Create new process or thread for each IUT socket
 * @param flags_pio_retry Use PIO_RETRY flag with allocation
 * 
 * @type Conformance.
 *
 * @par Scenario:
 *
 * @author Andrey Dmitrov <Andrey.Dmitrov@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/extension/template_mult"

#include "sockapi-test.h"
#include "template.h"

/**
 * Use different process or thread for the socket
 */
typedef enum {
    TP_NONE = 0,        /**< Sockets in single thread */
    TP_THREAD,          /**< Sockets in different threads */
    TP_PROCESS,         /**< Sockets in different processes */
} thread_process_type;

#define THREAD_PROCESS  \
    { "none", TP_NONE },       \
    { "thread", TP_THREAD },   \
    { "process", TP_PROCESS }

/**
 * Streams context
 */
typedef struct stream_ctx_type {
    rcf_rpc_server *rpcs;  /**< IUT RPC server */
    int iut_s;             /**< IUT socket */
    int tst_s;             /**< Tester socket */
} stream_ctx_type;

/**
 * Template context
 */
typedef struct template_ctx_type {
    stream_ctx_type *st;                /**< Stream context */
    rpc_onload_template_handle handle;  /**< Template handler */
    rpc_iovec *iov;                     /**< Pointer to iovector */
    int iovcnt;                         /**< iov array length */
    char *iovbuf;                       /**< Buffer with iov payload */
    int buflen;                         /**< Length of the iovbuf */
} template_ctx_type;

/** IUT RPC server */
static rcf_rpc_server *pco_iut = NULL;

/** Tester RPC server */
static rcf_rpc_server *pco_tst = NULL;

/**
 * Close connection and free memory
 * 
 * @param streams        Array with streams
 * @param sockets_num    Streams number
 * @param thread_process Destroy IUT RPC server if it is not @c TP_NONE
 */
static void
clean_connections(stream_ctx_type *streams, int sockets_num,
                  thread_process_type thread_process)
{
    int i;

    if (streams == NULL)
        return;

    for (i = 0; i < sockets_num; i++)
    {
        if (streams[i].iut_s > 0)
            RPC_CLOSE(streams[i].rpcs, streams[i].iut_s);
        if (streams[i].tst_s > 0)
            RPC_CLOSE(pco_tst, streams[i].tst_s);
        if (thread_process != TP_NONE)
            rcf_rpc_server_destroy(streams[i].rpcs);
    }

    free(streams);
}

/**
 * Clean array of templates
 * 
 * @param templates     Templates array
 * @param templates_num Length of the array
 */
static void
clean_templates(template_ctx_type *templates, int templates_num)
{
    int i;

    if (templates == NULL)
        return;

    for (i = 0; i < templates_num; i++)
    {
        release_iovec(templates[i].iov, templates[i].iovcnt);
        free(templates[i].iovbuf);
    }

    free(templates);
}

/**
 * Establish number @p sockets_num connections
 * 
 * @param iut_addr       IUT address
 * @param tst_addr       Tester address
 * @param sockets_num    Streams number
 * @param thread_process Create new process or thread for each IUT socket
 * 
 * @return Streams array
 */
static stream_ctx_type *
create_connections(struct sockaddr *iut_addr,
                   struct sockaddr *tst_addr, int sockets_num,
                   thread_process_type thread_process)
{
    stream_ctx_type *st = te_calloc_fill(sockets_num, sizeof(*st), 0xff);
    int i;
    char name[32] = {0,};

    for (i = 0; i < sockets_num; i++)
    {
        TAPI_SET_NEW_PORT(pco_iut, iut_addr);
        TAPI_SET_NEW_PORT(pco_tst, tst_addr);

        if (thread_process == TP_NONE)
            st[i].rpcs = pco_iut;
        else
        {
            snprintf(name, sizeof(name), "pco_iut_child%d", i);

            if (thread_process == TP_THREAD)
                CHECK_RC(rcf_rpc_server_thread_create(pco_iut, name,
                                                      &st[i].rpcs));
            else
                CHECK_RC(rcf_rpc_server_fork(pco_iut, name, &st[i].rpcs));
        }

        GEN_CONNECTION(st[i].rpcs, pco_tst, RPC_SOCK_STREAM, RPC_PROTO_DEF,
                       iut_addr, tst_addr, &st[i].iut_s, &st[i].tst_s);
    }

    return st;
}

/**
 * Create and allocate a few templates
 * 
 * @param streams         Streams array
 * @param sockets_num     Streams array length
 * @param iovcnt          Items number in each template
 * @param total           Payload length in each template
 * @param templates_num   Templates number
 * @param flags_pio_retry Use PIO_RETRY flag
 * 
 * @param Templates array
 */
static template_ctx_type *
create_templates(stream_ctx_type *streams, int sockets_num, int iovcnt,
                 int total, int templates_num, te_bool flags_pio_retry)
{
    template_ctx_type *tmpl;
    int i;
    int rc;

    tmpl = te_calloc_fill(templates_num, sizeof(*tmpl), 0);

    for (i = 0; i < templates_num; i++)
    {
        tmpl[i].st = streams + (i % sockets_num);
        tmpl[i].iov = init_iovec(iovcnt, total, &tmpl[i].iovbuf);
        tmpl[i].buflen = total;
        tmpl[i].iovcnt = iovcnt;

        RPC_AWAIT_IUT_ERROR(tmpl[i].st->rpcs);
        rc = rpc_onload_msg_template_alloc(tmpl[i].st->rpcs, tmpl[i].st->iut_s,
                                           tmpl[i].iov, iovcnt,
                                           &tmpl[i].handle,
                                           flags_pio_retry ?
                                   RPC_ONLOAD_TEMPLATE_FLAGS_PIO_RETRY : 0);

        if (rc != 0)
        {
            TEST_STEP("Allocation fails with E2BIG if try to allocate too big "
                      "vector or with ENOMEM if it is not enough PIO buffers.");
            if (RPC_ERRNO(tmpl[i].st->rpcs) == RPC_E2BIG || 
                RPC_ERRNO(tmpl[i].st->rpcs) == RPC_ENOMEM)
                TEST_VERDICT("Template allocation failed with errno %s",
                             errno_rpc2str(RPC_ERRNO(tmpl[i].st->rpcs)));
            TEST_VERDICT("Template allocation failed with unexpected errno %s",
                         errno_rpc2str(RPC_ERRNO(tmpl[i].st->rpcs)));
        }
    }

    return tmpl;
}

/**
 * Perform updates for some templates
 * 
 * @param templates     Templates array
 * @param templates_num Templates number
 * @param updates_num   Updates number
 */
static void
perform_updates(template_ctx_type *templates, int templates_num,  
                int updates_num)
{
    int i;
    rpc_onload_template_msg_update_iovec update;
    template_ctx_type *tmpl;

    for (i = 0; i < updates_num; i++)
    {
        tmpl = templates + rand_range(0, templates_num - 1);

        memset(&update, 0, sizeof(update));
        update.otmu_offset = rand_range(0, tmpl->buflen - 1);
        update.otmu_len = rand_range(1, tmpl->buflen - update.otmu_offset);
        update.otmu_base = te_make_buf_by_len(update.otmu_len);
        memcpy(tmpl->iovbuf + update.otmu_offset, update.otmu_base,
               update.otmu_len);

        rpc_onload_msg_template_update(tmpl->st->rpcs, tmpl->st->iut_s,
                                       tmpl->handle, &update, 1, 0);
        free(update.otmu_base);
    }
}

/**
 * Determine if finish condition is achived to leave transmission loop
 * 
 * @param send_num   Number templates which should be sent
 * @param order      Determines templates order
 * @param i          Iterator
 * @param first_iter @c TRUE if it is the first iteration in the loop
 */
static te_bool
send_condition(int send_num, te_bool order, int *i, te_bool *first_iter)
{
    if (*first_iter)
    {
        *i = order ? 0 : send_num - 1;
        *first_iter = FALSE;

        if (send_num == 0)
            return FALSE;
        return TRUE;
    }

    if (order)
    {
        (*i)++;
        if (*i == send_num)
            return FALSE;
    }
    else
    {
        (*i)--;
        if (*i < 0)
            return FALSE;
    }

    return TRUE;
}

/**
 * Send, receive and verify number @p send_num allocated templates.
 * 
 * @param templates     Templates array
 * @param templates_num Templates number
 * @param send_num      Number templates which should be sent
 * @param order         Determines templates transmission order
 */
static void
send_recv_templates(template_ctx_type *templates, int templates_num,
                    int send_num, te_bool order)
{
    int i;
    char *buf = NULL;
    te_bool first_iter = TRUE;

    if (send_num > templates_num || send_num < 0)
        TEST_FAIL("Argumen send_num must not be more than templates_num "
                  "or less 0");

    while (send_condition(send_num, order, &i, &first_iter))
    {
        rpc_onload_msg_template_update(templates[i].st->rpcs,
                                       templates[i].st->iut_s,
                                       templates[i].handle, NULL, 0,
                                       RPC_ONLOAD_TEMPLATE_FLAGS_SEND_NOW);
    }

    buf = te_calloc_fill(1, templates->buflen, 0);

    first_iter = TRUE;
    while (send_condition(send_num, order, &i, &first_iter))
    {
        if (rpc_recv(pco_tst, templates[i].st->tst_s, buf,
                     templates[i].buflen, 0) != templates[i].buflen)
            TEST_VERDICT("Amount of received data is not equal to sent "
                         "data");

        if (memcmp(buf, templates[i].iovbuf, templates[i].buflen) != 0)
            TEST_VERDICT("Send and received data are not equal");
    }

    free(buf);
}

int
main(int argc, char *argv[])
{
    const struct sockaddr *iut_addr = NULL;
    const struct sockaddr *tst_addr = NULL;
    thread_process_type    thread_process = TP_NONE;

    int iovcnt;
    int total;
    int sockets_num;
    int templates_num;
    int updates_num;
    int send_num;
    te_bool order;
    te_bool flags_pio_retry;

    stream_ctx_type *streams     = NULL;
    template_ctx_type *templates = NULL;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_ADDR(pco_tst, tst_addr);
    TEST_GET_INT_PARAM(iovcnt);
    TEST_GET_INT_PARAM(total);
    TEST_GET_INT_PARAM(sockets_num);
    TEST_GET_INT_PARAM(templates_num);
    TEST_GET_INT_PARAM(updates_num);
    TEST_GET_INT_PARAM(send_num);
    TEST_GET_BOOL_PARAM(order);
    TEST_GET_BOOL_PARAM(flags_pio_retry);
    TEST_GET_ENUM_PARAM(thread_process, THREAD_PROCESS);

    sockts_kill_zombie_stacks(pco_iut);

    TEST_STEP("Create @p sockets_num TCP connections between IUT and tester.");
    streams = create_connections((struct sockaddr *)iut_addr,
                                 (struct sockaddr *)tst_addr, sockets_num,
                                 thread_process);

    TEST_STEP("Allocate @p templates_num templates on different sockets.");
    templates = create_templates(streams, sockets_num, iovcnt, total,
                                 templates_num, flags_pio_retry);

    TEST_STEP("Perform @p updates_num updates on the templates.");
    perform_updates(templates, templates_num, updates_num);

    TEST_STEP("Send receive and verify @p send_num templates.");
    send_recv_templates(templates, templates_num, send_num, order);

    TEST_SUCCESS;

cleanup:
    clean_templates(templates, templates_num);
    clean_connections(streams, sockets_num, thread_process);

    TEST_END;
}
