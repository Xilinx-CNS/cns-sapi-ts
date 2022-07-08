/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * I/O Multiplexing
 * 
 * $Id$
 */

/** @page iomux-iomux_one_pipe Check iomux function with one pipe
 *
 * @objective Check that iomux function correctly report events for one
 *            pipe.
 *
 * @type conformance, compatibility
 *
 * @param pco_iut   PCO with IUT
 * @param iomux     Type of I/O Multiplexing function
 *                  (@b select(), @b pselect(), @b poll(), @b epoll_wait())
 * @param timeout   Timeout for @p iomux function
 * @param pipe_end  The end of pipe to use in the test
 * @param evts      Events for @b iomux function
 * @param ev_pr     Prepare or don't prepare event before @p iomux call
 * @param action    Action to be performed after iomux function hanging
 *
 * @par Scenario:
 * -# Create pipe on @p pco_iut.
 * -# According to @p ev_pr and @p evts parameters prepare read or write
 *    events on the pipe.
 * -# Call @p iomux function with @p pipe_end, @p evts and @p timeout.
 * -# If @p action is @c read recieve all data from the pipe.
 * -# If @p action is @c write send some data to the pipe.
 * -# Check that @p iomux function returns appropriate events or @c 0 in
 *    case @p ev_pr is @c FALSE.
 *
 * @author Yurij Plotnikov <Yurij.Plotnikov@oktetlabs.ru>
 */

#define TE_TEST_NAME "iomux/iomux_one_pipe"
#include "sockapi-test.h"
#include "iomux.h"

#define BUF_SIZE 1024

int
main(int argc, char *argv[])
{
    iomux_call_type     iomux;

    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_aux = NULL;

    int                 pipefds[2];

    int                 data_size;
    int                 buf[BUF_SIZE];
    uint64_t            total_bytes = 0;

    int                 timeout;
    te_bool             pr_ev;
    const char         *evts;
    const char         *pipe_end;
    const char         *action;

    te_bool             read_ev = FALSE;
    te_bool             write_ev = FALSE;
    te_bool             both_ends;
    te_bool             read_end = TRUE;
    te_bool             write_end = TRUE;

    int                 ret_val = 0;

    iomux_evt_fd        events[2];
    tarpc_timeval       to;

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_INT_PARAM(data_size);
    TEST_GET_INT_PARAM(timeout);
    TEST_GET_BOOL_PARAM(pr_ev);
    TEST_GET_STRING_PARAM(evts);
    TEST_GET_STRING_PARAM(pipe_end);
    TEST_GET_STRING_PARAM(action);
    TEST_GET_IOMUX_FUNC(iomux);

    both_ends = (strcmp(pipe_end, "both") == 0);

    pipefds[0] = -1;
    pipefds[1] = -1;
    rpc_pipe(pco_iut, pipefds);

    if (strcmp(evts, "rd") == 0)
        read_ev = TRUE;
    else if (strcmp(evts, "wr") == 0)
        write_ev = TRUE;
    else if (strcmp(evts, "rdwr") == 0)
    {
        write_ev = TRUE;
        read_ev = TRUE;
    }
    else
        TEST_FAIL("Incorrect value of 'evts' parameter.");

    if (write_ev && !pr_ev)
    {
        rpc_overfill_fd(pco_iut, pipefds[1], &total_bytes);
        write_end = FALSE;
    }
    else if (read_ev && pr_ev)
        RPC_WRITE(rc, pco_iut, pipefds[1], buf, data_size);
    else
        read_end = FALSE;

    to.tv_sec = timeout / 1000;
    to.tv_usec = (timeout % 1000) * 1000;
    if (strcmp(pipe_end, "read") == 0)
        events[0].fd = pipefds[0];
    else if (strcmp(pipe_end, "write") == 0)
        events[0].fd = pipefds[1];
    else if (both_ends)
    {
        events[0].fd = pipefds[0];
        events[1].fd = pipefds[1];
    }
    else
        TEST_FAIL("Incorrect value of 'pipe_end' parameter.");

    events[0].events = 0;
    events[0].events = read_ev ? events[0].events | EVT_RD:
                                 events[0].events;
    events[0].events = write_ev ? events[0].events |EVT_WR :
                                  events[0].events;
    if (both_ends)
        events[1].events = events[0].events;

    if (strcmp(action, "none") != 0)
    {
        CHECK_RC(rcf_rpc_server_thread_create(pco_iut, "child_thread",
                                              &pco_aux));
        pco_iut->op = RCF_RPC_CALL;
    }
    rc = iomux_call(iomux, pco_iut, events, both_ends ? 2 : 1, &to);

    if (strcmp(action, "none") != 0)
    {
        TAPI_WAIT_NETWORK;
        if (strcmp(action, "read") == 0)
        {
            do {
                rc = rpc_read(pco_aux, pipefds[0], buf, data_size);
                if (rc > 0)
                    total_bytes -= rc;
            } while (total_bytes > 0);
            write_end = TRUE;
        }
        else if (strcmp(action, "write") == 0)
        {
            RPC_WRITE(rc, pco_aux, pipefds[1], buf, data_size);
            read_end = TRUE;
        }
        else
            TEST_FAIL("Incorrect value of 'action' parameter");

        pco_iut->op = RCF_RPC_WAIT;
        rc = iomux_call(iomux, pco_iut, events, both_ends ? 2 : 1, &to);
    }

    if (!both_ends)
    {
        if (strcmp(pipe_end, "read") == 0 && read_end && read_ev &&
            (rc != 1 || events[0].revents != EVT_RD))
            TEST_VERDICT("%s() called with %s events on read end "
                         "returns %d with %s events",
                         iomux_call_en2str(iomux), evts,
                         rc, iomux_event_rpc2str(events[0].revents));
        else if (strcmp(pipe_end, "write") == 0 && write_end && write_ev &&
                 (rc != 1 || events[0].revents != EVT_WR))
            TEST_VERDICT("%s() called with %s events on write end "
                         "returns %d with %s events",
                         iomux_call_en2str(iomux), evts,
                         rc, iomux_event_rpc2str(events[0].revents));
        else if (((strcmp(pipe_end, "write") == 0 && (!write_end ||
                                                      !write_ev)) ||
                  (strcmp(pipe_end, "read") == 0 && (!read_end ||
                                                     !read_ev))) &&
                 (rc != 0))
            TEST_VERDICT("%s() called with %s events on %s end returns %d "
                         "with %s events", iomux_call_en2str(iomux), evts,
                         pipe_end, rc,
                         iomux_event_rpc2str(events[0].revents));
    }
    else
    {
        if (read_end && (events[0].revents == EVT_RD))
            ret_val++;
        else if (events[0].revents != 0)
            TEST_VERDICT("%s() called with %s events returns %d "
                         "with %s events for read end",
                         iomux_call_en2str(iomux), evts, rc,
                         iomux_event_rpc2str(events[0].revents));

        if (write_end && (events[1].revents == EVT_WR))
            ret_val++;
        else if (events[1].revents != 0)
            TEST_VERDICT("%s() called with %s events returns %d "
                         "with %s events for write end",
                         iomux_call_en2str(iomux), evts, rc,
                         iomux_event_rpc2str(events[1].revents));

        if (rc != ret_val)
            TEST_VERDICT("%s() called with %s events for both ends "
                         "returns %d instead of %d",
                         iomux_call_en2str(iomux), evts, rc, ret_val);
    }

    TEST_SUCCESS;
cleanup:
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[0]);
    CLEANUP_RPC_CLOSE(pco_iut, pipefds[1]);

    if (pco_aux != NULL)
        CLEANUP_CHECK_RC(rcf_rpc_server_destroy(pco_aux));

    TEST_END;
}
