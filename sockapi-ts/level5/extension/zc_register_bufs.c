/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Onload extensions
 */

/**
 * @page extension-zc_register_bufs Test onload_zc_[un]register_buffers()
 *
 * @objective Check that a buffer can be registered with
 *            @b onload_zc_register_buffers() and unregistered with
 *            @b onload_zc_unregister_buffers() if its address is
 *            page-aligned and its length is a multiple of memory page
 *            size.
 *
 * @param env               Network environment configuration:
 *                          - @ref arg_types_env_peer2peer_lo
 *                          - @ref arg_types_env_peer2peer_lo_ipv6
 * @param sock_type         Socket type:
 *                          - @c SOCK_DGRAM
 *                          - @c SOCK_STREAM
 * @param buf_len           Buffer length (in memory page units):
 *                          - @c 1
 *                          - @c 1000
 *                          - @c 2.5
 * @param buf_aligned       If @c TRUE, buffer address is page-aligned,
 *                          otherwise it is not.
 * @param huge_pages        Whether to use huge pages:
 *                          - @c no: do not use
 *                          - @c explicit: use huge pages explicitly
 *                            allocated with @c MAP_HUGETLB
 *                          - @c transparent: use transparent huge
 *                            page allocation
 *
 * @note
 * This test does not really need the loopback interface, but it needs
 * @p pco_tst on IUT which runs independently from pco_iut (i.e. no forks).
 * And it also needs socket domain, which is derived from the @p iut_addr.
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME "level5/extension/zc_register_bufs"

#include "sockapi-test.h"
#include "onload.h"

/** Variants of huge pages testing */
enum {
    HUGE_PAGES_NO,            /**< No huge pages */
    HUGE_PAGES_EXPLICIT,      /**< Use MAP_HUGETLB flag of mmap() */
    HUGE_PAGES_TRANSPARENT,   /**< Check transparent huge pages with
                                   memalign() + madvise() */
};

/** List of "huge_pages" parameter values for TEST_GET_ENUM_PARAM() */
#define HUGE_PAGES_MAPPING_LIST \
    { "no", HUGE_PAGES_NO },                      \
    { "explicit", HUGE_PAGES_EXPLICIT },          \
    { "transparent", HUGE_PAGES_TRANSPARENT }

/**
 * Maximum number of transparent huge pages to allocate
 * when trying to consume already mapped ones.
 */
#define MAX_THPAGES 200

/** Huge page size (usually 2 MB on Linux) */
#define HUGE_PAGE_SIZE (1 << 21)

/**
 * Array of buffer pointers used to store consumed
 * transparent huge pages.
 */
static rpc_ptr thp_bufs[MAX_THPAGES];

/** Set to TRUE after thp_bufs is initialized */
static te_bool thp_bufs_init = FALSE;

/**
 * Get sum of values of AnonHugePages fields from proc/[PID]/smaps.
 *
 * @param rpcs        RPC server handle.
 * @param pid         PID to check.
 *
 * @return Sum of fields values.
 */
static unsigned int
get_thp_total_size(rcf_rpc_server *rpcs, pid_t pid)
{
    char *cmd_out = NULL;
    unsigned int sum = 0;
    unsigned int cur_number = 0;
    unsigned int i;

    rpc_wait_status status;
    te_bool old_silent_def;

    old_silent_def = rpcs->silent_pass_default;
    rpcs->silent_pass = rpcs->silent_pass_default = TRUE;

    RPC_AWAIT_ERROR(rpcs);
    status = rpc_shell_get_all2(
                       rpcs, &cmd_out,
                       "cat /proc/%d/smaps | grep AnonHugePages "
                       "| sed \"s/^.*\\s\\+\\([0-9]\\+\\)\\s\\+.*$/\\1/\"",
                       pid);
    rpcs->silent_pass = rpcs->silent_pass_default = old_silent_def;

    if (status.flag != RPC_WAIT_STATUS_EXITED || status.value != 0)
    {
        TEST_VERDICT("Failed to obtain transparent huge pages usage");
    }

    for (i = 0; cmd_out != NULL && cmd_out[i] != '\0'; i++)
    {
        if (cmd_out[i] >= '0' && cmd_out[i] <= '9')
        {
            cur_number = cur_number * 10 + (cmd_out[i] - '0');
        }
        else
        {
            sum += cur_number;
            cur_number = 0;
        }
    }
    sum += cur_number;

    free(cmd_out);

    RING("Current sum of AnonHugePages fields: %u", sum);

    /*
     * /proc/vmstat contains useful info which is neede when something
     * goes awry.  Let's log it.
     */
    rpc_system(rpcs, "grep thp /proc/vmstat");

    return sum;
}

/**
 * Allocate new transparent huge pages until sum of
 * AnonHugePages fields begins to increase.
 *
 * @param pco_iut       IUT RPC server handle.
 * @param pco_tst       TST RPC server handle (on the same host).
 * @param pid           PID of the IUT RPC server.
 * @param cur_thp_size  Current sum of AnonHugePages fields.
 *
 * @return Sum of AnonHugePages fields after the last allocation.
 */
static unsigned int
consume_existing_thpages(rcf_rpc_server *pco_iut,
                         rcf_rpc_server *pco_tst, pid_t pid,
                         unsigned int cur_thp_size)
{
    unsigned int i;
    int size = HUGE_PAGE_SIZE;
    uint8_t test_byte = 0xff;
    unsigned int new_thp_size = cur_thp_size;

    for (i = 0; i < MAX_THPAGES; i++)
    {
        thp_bufs[i] = RPC_NULL;
    }
    thp_bufs_init = TRUE;

    for (i = 0; i < MAX_THPAGES; i++)
    {
        pco_iut->silent_pass = TRUE;
        rpc_posix_memalign(pco_iut, &thp_bufs[i], size, size);

        pco_iut->silent_pass = TRUE;
        rpc_madvise(pco_iut, thp_bufs[i], size, RPC_MADV_HUGEPAGE);

        /*
         * Set a single byte of the allocated buffer so that
         * memory is actually allocated.
         */
        pco_iut->silent_pass = TRUE;
        rpc_set_buf(pco_iut, &test_byte, 1, thp_bufs[i]);

        new_thp_size = get_thp_total_size(pco_tst, pid);
        if (new_thp_size > cur_thp_size)
            break;
    }

    if (new_thp_size <= cur_thp_size)
    {
        TEST_VERDICT("Failed to ensure that already mapped transparent "
                     "huge pages are consumed");
    }
    return new_thp_size;
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server     *pco_iut = NULL;
    rcf_rpc_server     *pco_tst = NULL;
    int                 iut_s = -1;
    int64_t             page_size = 0;
    int64_t             sys_page_size = 0;

    uint64_t            passed_len;
    uint64_t            real_len;
    rpc_ptr             buf_ptr = RPC_NULL;
    rpc_ptr             buf_ptr_aux = RPC_NULL;
    uint64_t            off = 0;
    te_bool             test_failed = FALSE;
    te_bool             reg_success = FALSE;

    const struct sockaddr  *iut_addr;
    rpc_onload_zc_handle    handle = RPC_NULL;

    rpc_socket_type     sock_type;
    double              buf_len;
    te_bool             buf_aligned;
    int                 huge_pages;

    int i;
    pid_t iut_pid;
    unsigned int thp_size_aux;
    unsigned int thp_size1;
    unsigned int thp_size2;
    unsigned int thp_size3;
    unsigned int thp_size4;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst);
    TEST_GET_ADDR(pco_iut, iut_addr);
    TEST_GET_SOCK_TYPE(sock_type);
    TEST_GET_DOUBLE_PARAM(buf_len);
    TEST_GET_BOOL_PARAM(buf_aligned);
    TEST_GET_ENUM_PARAM(huge_pages, HUGE_PAGES_MAPPING_LIST);

    iut_pid = rpc_getpid(pco_iut);

    sys_page_size = rpc_sysconf(pco_iut, RPC_SC_PAGESIZE);
    if (huge_pages != HUGE_PAGES_NO)
    {
        page_size = HUGE_PAGE_SIZE;
    }
    else
    {
        page_size = sys_page_size;
    }

    if (huge_pages == HUGE_PAGES_TRANSPARENT)
    {
        TEST_STEP("If @p huge_pages is @c transparent, memorize the "
                  "current sum of AnonHugePages fields for IUT "
                  "process.");
        thp_size1 = get_thp_total_size(pco_tst, iut_pid);
        if (thp_size1 > 0)
        {
            TEST_SUBSTEP("If the current sum is nonzero, allocate a few "
                         "buffers until the sum increases to ensure "
                         "that no already allocated transparent huge "
                         "pages will be reused.");
            thp_size1 = consume_existing_thpages(pco_iut, pco_tst,
                                                 iut_pid, thp_size1);
        }
    }

    TEST_STEP("Create a socket according to the domain of @p iut_addr "
              "and @p sock_type.");
    iut_s = rpc_socket(pco_iut, rpc_socket_domain_by_addr(iut_addr),
                       sock_type, RPC_PROTO_DEF);

    if (huge_pages == HUGE_PAGES_TRANSPARENT)
    {
        TEST_STEP("If @p huge_pages is @c transparent, check that the "
                  "sum of AnonHugePages fields for IUT process "
                  "did not change after creating a socket.");
        thp_size_aux= get_thp_total_size(pco_tst, iut_pid);
        if (thp_size_aux != thp_size1)
        {
            ERROR_VERDICT("Sum of AnonHugePages fields changed after "
                          "creating a socket");
            thp_size1 = thp_size_aux;
        }
    }

    TEST_STEP("Allocate a memory chunk according to @p buf_aligned, "
              "@p buf_len and @p huge_pages.");

    passed_len = buf_len * page_size;
    real_len = passed_len;
    if (!buf_aligned)
        real_len += page_size;

    RPC_AWAIT_ERROR(pco_iut);
    if (huge_pages == HUGE_PAGES_EXPLICIT)
    {
        /*
         * Huge pages can be explicitly allocated only with
         * mmap().
         */
        buf_ptr = rpc_mmap(
                     pco_iut, 0, real_len,
                     RPC_PROT_READ | RPC_PROT_WRITE,
                     RPC_MAP_PRIVATE | RPC_MAP_ANONYMOUS |
                     RPC_MAP_POPULATE | RPC_MAP_HUGETLB,
                     -1, 0);
    }
    else
    {
        rpc_posix_memalign(pco_iut, &buf_ptr, page_size, real_len);
        if (huge_pages == HUGE_PAGES_TRANSPARENT)
            rpc_madvise(pco_iut, buf_ptr, real_len, RPC_MADV_HUGEPAGE);
    }
    if (buf_ptr == RPC_NULL)
    {
        TEST_VERDICT("Failed to allocate buffer for registering, errno=%r",
                     RPC_ERRNO(pco_iut));
    }

    if (buf_aligned)
        off = 0;
    else
        off = sys_page_size / 2;

    TEST_STEP("Pass address and length of allocated memory chunk to "
              "@b onload_zc_register_buffers() called on the previously "
              "created socket. Check that it succeeds only if the address "
              "is page-aligned and the length is a multiple of memory page "
              "size.");

    RPC_AWAIT_ERROR(pco_iut);
    rc = rpc_onload_zc_register_buffers(pco_iut, iut_s,
                                        SOCKTS_EF_ADDRSPACE_LOCAL,
                                        buf_ptr, off,
                                        passed_len, 0, &handle);

    if (buf_aligned && passed_len % page_size == 0)
    {
        if (rc < 0)
        {
            ERROR_VERDICT("onload_zc_register_buffers() unexpectedly "
                          "failed with errno %r", RPC_ERRNO(pco_iut));
            test_failed = TRUE;
        }
    }
    else if (rc >= 0)
    {
        ERROR_VERDICT("onload_zc_register_buffers() unexpectedly "
                      "succeeded");
        test_failed = TRUE;
    }
    else if (RPC_ERRNO(pco_iut) != RPC_EINVAL)
    {
        ERROR_VERDICT("onload_zc_register_buffers() failed with "
                      "unexpected errno %r", RPC_ERRNO(pco_iut));
        test_failed = TRUE;
    }

    TEST_STEP("If @b onload_zc_register_buffers() succeeded, call "
              "@b onload_zc_unregister_buffers() and check that it "
              "succeeds too.");
    if (rc >= 0)
    {
        reg_success = TRUE;

        if (huge_pages == HUGE_PAGES_TRANSPARENT)
            thp_size2 = get_thp_total_size(pco_tst, iut_pid);

        RPC_AWAIT_ERROR(pco_iut);
        rc = rpc_onload_zc_unregister_buffers(pco_iut, iut_s, handle, 0);
        if (rc < 0)
        {
            TEST_VERDICT("onload_zc_unregister_buffers() failed with errno "
                         "%r", RPC_ERRNO(pco_iut));
        }
    }

    TEST_STEP("If @p huge_pages is @c transparent and "
              "@b onload_zc_register_buffers() was successful, check "
              "that sum of AnonHugePages counters in /proc/[PID]/smaps has "
              "increased for @p pco_iut.");
    if (huge_pages == HUGE_PAGES_TRANSPARENT && reg_success)
    {
        if (thp_size2 <= thp_size1)
        {
            uint8_t test_byte = 0xff;

            TEST_SUBSTEP("If the sum did not increase, try to change "
                         "contents of the allocated buffer and recheck.");
            rpc_set_buf(pco_iut, &test_byte, 1, buf_ptr);
            thp_size3 = get_thp_total_size(pco_tst, iut_pid);

            if (thp_size3 > thp_size2)
            {
                TEST_VERDICT("Transparent huge pages were not allocated "
                             "after onload_zc_register_bufs() but after "
                             "changing the buffer contents they are "
                             "allocated");
            }
            else
            {
                TEST_SUBSTEP("If the sum did not increase, try to allocate "
                             "a new buffer, change its contents and "
                             "recheck.");
                rpc_posix_memalign(pco_iut, &buf_ptr_aux, page_size, real_len);
                rpc_madvise(pco_iut, buf_ptr_aux, real_len,
                            RPC_MADV_HUGEPAGE);
                rpc_set_buf(pco_iut, &test_byte, 1, buf_ptr_aux);
                thp_size4 = get_thp_total_size(pco_tst, iut_pid);

                if (thp_size4 > thp_size3)
                {
                    TEST_VERDICT("Transparent huge pages were not allocated "
                                 "after onload_zc_register_bufs() but after "
                                 "allocating a new buffer they are "
                                 "allocated");
                }
                else
                {
                    TEST_VERDICT("Transparent huge pages were not allocated");
                }
            }
        }
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    CLEANUP_RPC_CLOSE(pco_iut, iut_s);

    if (buf_ptr != RPC_NULL)
    {
        if (huge_pages == HUGE_PAGES_EXPLICIT)
            rpc_munmap(pco_iut, buf_ptr, real_len);
        else
            rpc_free(pco_iut, buf_ptr);
    }

    if (buf_ptr_aux != RPC_NULL)
        rpc_free(pco_iut, buf_ptr_aux);

    if (thp_bufs_init)
    {
        for (i = 0; i < MAX_THPAGES; i++)
        {
            if (thp_bufs[i] != RPC_NULL)
                rpc_free(pco_iut, thp_bufs[i]);
        }
    }

    TEST_END;
}
