/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Reliability Socket API in Normal Use
 * 
 * $Id$
 */

/** @page ext_stackname-set_stackname_save_restore Testing of @b onload_stackname_save()/@b onload_stackname_restore()
 *
 * @objective Check that if @b onload_stackname_save() was calles after
 *            @b onload_set_stackname(), then calling @b
 *            onload_stackname_restore() after that is equivalent to
 *            calling @b onload_set_stackname() with the same parameters
 *            as it was done before the @b onload_stackname_save() call.
 *
 * @type use case
 *
 * @param pco_iut       PCO on IUT
 * @param all_threads1  Whether to call @b onload_set_stackname() with
 *                      @c ONLOAD_ALL_THREADS the first time
 * @param all_threads2  Whether to call @b onload_set_stackname() with
 *                      @c ONLOAD_ALL_THREADS the second time
 * @param scope1        Value of the scope parameter for the first call
 *                      of @b onload_set_staclname()
 * @param scope2        Value of the scope parameter for the second call
 *                      of @b onload_set_staclname()
 *
 * @par Scenario:
 *
 * @author Dmitry Izbitsky <Dmitry.Izbitsky@oktetlabs.ru>
 */

#define TE_TEST_NAME  "level5/ext_stackname/set_stackname_save_restore"

#include "sockapi-test.h"

#if HAVE_PWD_H
#include <pwd.h>
#endif

#include "onload.h"

#include "extensions.h"

#define CI_CFG_STACK_NAME_LEN 16

static inline int
rpc_server_change_uid(rcf_rpc_server *rpcs,
                      struct passwd *passwd)
{
    tarpc_uid_t     uid = 0;

    passwd = rpc_getpwnam(rpcs, passwd->pw_name);
    rpc_setuid(rpcs, passwd->pw_uid);
    uid = rpc_getuid(rpcs);
    if (uid != passwd->pw_uid)
    {
        ERROR("User ID change failed");
        return -1;
    }
    return 0;
}

#define RPC_SRV_CNT 5
#define RPC_SRV_PROCESS 0
#define RPC_SRV_OTH_THREAD1 1
#define RPC_SRV_OTH_THREAD2 2
#define RPC_SRV_OTH_PROCESS 3
#define RPC_SRV_OTH_UID 4

static inline te_errno
prepare_rpcs(rcf_rpc_server *rpcs,
             rcf_rpc_server **servers)
{
    static unsigned int set_id = 0;

    char name[RCF_MAX_NAME];

    struct passwd  *passwd = getpwuid(getuid());

    set_id++;

    snprintf(name, RCF_MAX_NAME, "set_%d_proc", set_id);
    rcf_rpc_server_fork(rpcs, name, &servers[RPC_SRV_PROCESS]);
    snprintf(name, RCF_MAX_NAME, "set_%d_proc_thread1", set_id);
    rcf_rpc_server_thread_create(servers[RPC_SRV_PROCESS],
                                 name, &servers[RPC_SRV_OTH_THREAD1]);
    snprintf(name, RCF_MAX_NAME, "set_%d_proc_thread2", set_id);
    rcf_rpc_server_thread_create(servers[RPC_SRV_PROCESS],
                                 name, &servers[RPC_SRV_OTH_THREAD2]);
    snprintf(name, RCF_MAX_NAME, "set_%d_oth_proc", set_id);
    rcf_rpc_server_fork(rpcs, name, &servers[RPC_SRV_OTH_PROCESS]);
    snprintf(name, RCF_MAX_NAME, "set_%d_oth_uid", set_id);
    rcf_rpc_server_fork(rpcs, name, &servers[RPC_SRV_OTH_UID]);

    rpc_server_change_uid(servers[RPC_SRV_PROCESS], passwd);
    rpc_server_change_uid(servers[RPC_SRV_OTH_PROCESS], passwd);

    return 0;
}

static inline te_errno
destroy_rpcs(rcf_rpc_server **servers)
{
    /* We should delete threads firstly */
    rcf_rpc_server_destroy(servers[RPC_SRV_OTH_THREAD1]);
    rcf_rpc_server_destroy(servers[RPC_SRV_OTH_THREAD2]);
    rcf_rpc_server_destroy(servers[RPC_SRV_PROCESS]);
    rcf_rpc_server_destroy(servers[RPC_SRV_OTH_PROCESS]);
    rcf_rpc_server_destroy(servers[RPC_SRV_OTH_UID]);

    return 0;
}

static inline te_errno
set_stackname(rcf_rpc_server **servers,
              int who,
              int scope,
              const char *name)
{
    unsigned int i;

    for (i = 0; i < RPC_SRV_CNT; i++)
        if (i != RPC_SRV_OTH_THREAD1)
            rpc_onload_set_stackname(servers[i], who, scope, name);

    return 0;
}

static inline te_errno
save_stackname(rcf_rpc_server **servers)
{
    unsigned int i;

    for (i = 0; i < RPC_SRV_CNT; i++)
        if (i != RPC_SRV_OTH_THREAD1)
            rpc_onload_stackname_save(servers[i]);

    return 0;
}

static inline te_errno
restore_stackname(rcf_rpc_server **servers)
{
    unsigned int i;

    for (i = 0; i < RPC_SRV_CNT; i++)
        if (i != RPC_SRV_OTH_THREAD1)
            rpc_onload_stackname_restore(servers[i]);

    return 0;
}

typedef struct onload_fd_info {
    int                 fd;
    tarpc_onload_stat   ostat;
} onload_fd_info;

static inline te_bool
compare_servers_sets(const char *msg,
                     rcf_rpc_server **set1, rcf_rpc_server **set2,
                     const char *object, const char *exp_stack_name)
{
    unsigned int i;
    unsigned int j;

    te_bool failed = FALSE;

    onload_fd_info set1_fds[RPC_SRV_CNT];
    onload_fd_info set2_fds[RPC_SRV_CNT];

    for (i = 0; i < RPC_SRV_CNT; i++)
    {
        set1_fds[i].fd = tapi_onload_object_create(set1[i], object);
        rpc_onload_fd_stat(set1[i], set1_fds[i].fd,
                           &set1_fds[i].ostat);
        set2_fds[i].fd = tapi_onload_object_create(set2[i], object);
        rpc_onload_fd_stat(set2[i], set2_fds[i].fd,
                           &set2_fds[i].ostat);

        if (set1_fds[i].ostat.stack_name_null !=
                                      set2_fds[i].ostat.stack_name_null)
        {
            ERROR("%s: fd from the RPC server %d from "
                  "the first set is %sOnload, whereas fd "
                  "from the RPC server %d from the second "
                  "set is %sOnload",
                  msg, i,
                  set1_fds[i].ostat.stack_name_null ? "not " : "",
                  i,
                  set2_fds[i].ostat.stack_name_null ? "not " : "");
            failed = TRUE;
        }

        if (!set1_fds[i].ostat.stack_name_null &&
            !set2_fds[i].ostat.stack_name_null &&
            strncmp(set1_fds[i].ostat.stack_name,
                    set2_fds[i].ostat.stack_name,
                    strlen(exp_stack_name)) != 0)
        {
            ERROR("%s: fd from the RPC server %d from "
                  "the first set is from '%s' stack, fd "
                  "from the RPC server %d from the second "
                  "set is from '%s' stack, but stack name prefix "
                  "should be '%s' for both",
                  msg, i,
                  set1_fds[i].ostat.stack_name,
                  i,
                  set2_fds[i].ostat.stack_name,
                  exp_stack_name);
            failed = TRUE;
        }
    }

    for (i = 0; i < RPC_SRV_CNT; i++)
    {
        for (j = i + 1; j < RPC_SRV_CNT; j++)
        {
            te_bool shared1;
            te_bool shared2;

            shared1 = (set1_fds[i].ostat.stack_id ==
                                  set1_fds[j].ostat.stack_id);
            shared2 = (set2_fds[i].ostat.stack_id ==
                                  set2_fds[j].ostat.stack_id);

            if (shared1 != shared2)
            {
                ERROR("Stacks of RPC servers %d and %d from the first set "
                      "are %sshared, whereas stacks of RPC servers %d "
                      "and %d from the second set are %sshared",
                      i, j, shared1 ? "" : "not ",
                      i, j, shared2 ? "" : "not ");
                failed = TRUE;
            }
        }
    }

    for (i = 0; i < RPC_SRV_CNT; i++)
    {
        rpc_close(set1[i], set1_fds[i].fd);
        rpc_close(set2[i], set2_fds[i].fd);
    }

    return !failed;
}

#define STACK_NAME1 "name1"
#define STACK_NAME2 "name2"

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_iut = NULL;
    int             scope1;
    int             scope2;
    te_bool         all_threads1;
    te_bool         all_threads2;
    const char     *object = NULL;

    int who;
    int scope;

    te_bool test_failed = FALSE;

    rcf_rpc_server *set1[RPC_SRV_CNT];
    rcf_rpc_server *set2[RPC_SRV_CNT];

    /*
     * Test preambule.
     */
    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_BOOL_PARAM(all_threads1);
    TEST_GET_BOOL_PARAM(all_threads2);
    TEST_GET_STRING_PARAM(object);
    TEST_GET_ONLOAD_STACK_SCOPE(scope1);
    TEST_GET_ONLOAD_STACK_SCOPE(scope2);

    TEST_STEP("Create two sets of RPC servers, each consisting of: "
              "a process, two other threads in the same process, another "
              "process, another process with different UID.");
    prepare_rpcs(pco_iut, set1);
    prepare_rpcs(pco_iut, set2);

    who = all_threads1 ? ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD;
    scope = scope1;

    TEST_STEP("Call @b onload_set_stackname() on all RPC servers "
              "(except the second of the threads in the first process) in "
              "each set, with parameters according to @p all_threads1 and "
              "@p scope 1 (we exclude one of the threads to check "
              "ONLOAD_ALL_THREADS/ONLOAD_THIS_THREAD difference).");
    set_stackname(set1, who, scope, STACK_NAME1);
    set_stackname(set2, who, scope, STACK_NAME1);

    TEST_STEP("Call @b onload_stackname_save() on all RPC servers "
              "(except the second of the threads in the first process) in "
              "the second set.");
    save_stackname(set2);

    who = all_threads2 ? ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD;
    scope = scope2;

    TEST_STEP("Call @b onload_set_stackname() on all RPC servers "
              "(except the second of the threads in the first process) in "
              "each set, with parameters according to @p all_threads2 and "
              "@p scope 2.");
    set_stackname(set1, who, scope, STACK_NAME2);
    set_stackname(set2, who, scope, STACK_NAME2);

    who = all_threads1 ? ONLOAD_ALL_THREADS : ONLOAD_THIS_THREAD;
    scope = scope1;

    TEST_STEP("Call @b onload_set_stackname() on all RPC servers "
              "(except the second of the threads in the first process) in "
              "the first set, with parameters according to @p all_threads2 and "
              "@p scope 2.");
    set_stackname(set1, who, scope, STACK_NAME1);

    TEST_STEP("Call @b onload_stackname_restore() on all RPC servers "
              "(except the second of the threads in the first process) in "
              "the second set.");
    restore_stackname(set2);

    TEST_STEP("Check that in both sets onload objects created in different "
              "RPC servers are in the same stack or in a dirrerent ones in "
              "exactly the same manner (for example, in both sets simultaneously "
              "the first RPC server shares stack with the forth RPC server, etc).");
    if (compare_servers_sets("Comparing onload_set_stackname() and "
                             "onload_stackname_restore() with the same "
                             "parameters",
                             set1, set2, object, STACK_NAME1) != TRUE)
    {
        ERROR_VERDICT("Calling onload_set_stackname() with "
                      "initial parameters and  "
                      "onload_stackname_restore() "
                      "results in different stack sharing behavior");
        test_failed = TRUE;
    }

    if (test_failed)
        TEST_STOP;
    TEST_SUCCESS;

cleanup:

    destroy_rpcs(set1);
    destroy_rpcs(set2);

    TEST_END;
}
