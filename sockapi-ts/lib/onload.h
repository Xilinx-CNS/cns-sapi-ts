/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * TAPI functions related to OOL-specific testing 
 *
 * @author Konstantin Ushakov <Konstantin.Ushakov@oktetlabs.ru>
 *
 * $Id:
 */

#ifndef __TS_ONLOAD_H__
#define __TS_ONLOAD_H__

#include "sockapi-ts.h"

#include "tapi_sh_env.h"

#include "extensions.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Name of environment variable which is responsible
 * for 'disabling' of acceleration of entire application.
 */
#define EF_DONT_ACCELERATE "EF_DONT_ACCELERATE"

/** Path to te_onload script */
#define PATH_TO_TE_ONLOAD "te_onload"

/**
 * Log only transport errors (see @c CI_TP_LOG_E in Onload headers).
 */
#define SOCKTS_CI_TP_LOG_E "0x1"

/**
 * Control of acceleration via environment.
 *
 * @param rpcs   RPC server
 * @param enable Enable or disable the acceleration
 */
static inline int tapi_onload_acc(rcf_rpc_server *rpcs,
                                  te_bool enable)
{
    RING("%s acceleration for (%s, %s)", enable ? "Enable" : "Disable",
         rpcs->ta, rpcs->name);
    if (!enable)
        return tapi_sh_env_set(rpcs, EF_DONT_ACCELERATE, "1", TRUE, TRUE);
    else
        return tapi_sh_env_unset(rpcs, EF_DONT_ACCELERATE, TRUE, TRUE);
}

/**
 * Get current acceleration status from env point of view.
 *
 * @note This may be overwritten by onload_set_stackname()
 * function call, so it's _only_ from environement point of
 * view.
 *
 * @param rpcs          RPC server
 *
 * @result   is enabled?
 */
static inline te_bool tapi_onload_acc_is_enabled(rcf_rpc_server *rpcs)
{
    char *e;

    e = rpc_getenv(rpcs, EF_DONT_ACCELERATE);
    return !(e != NULL && strcmp(e, "1") == 0);
}

/**
 * Return codes for tapi_onload_check_fd function.
 */
#define TAPI_FD_IS_SYSTEM 0     /* also means 'false' */
#define TAPI_FD_IS_ONLOAD 1
#define TAPI_FD_WRONG_STACK 2
/**
 * Check if given 'fd' is onload one by means of fstat.
 * Note, that if we call OOL fstat it will return proper info,
 * but if system fstat is called it should return char device
 * fd.
 *
 * @param rpcs     PCO
 * @param fd       fd
 * @param exp_stack_name     Expected stack name - NULL means ignore
 *
 *
 * TODO: use private onload API.
 * NOTE: stack names comparison is done with strncmp as we don't know
 * the suffix logic
 */
static inline int tapi_onload_check_fd(rcf_rpc_server *rpcs,
                                       int fd,
                                       const char *exp_stack_name)
{
    tarpc_onload_stat ostat;
    int rc;
    te_bool names_match = TRUE;

    rc = rpc_onload_fd_stat(rpcs, fd, &ostat);

    if (rc && exp_stack_name)
    {
        if (ostat.stack_name == exp_stack_name)
            names_match = TRUE;
        else if (ostat.stack_name != NULL &&
                 strncmp(ostat.stack_name, exp_stack_name,
                         strlen(exp_stack_name)) == 0)
                names_match = TRUE;
        else
            names_match = FALSE;
    }

    RING("FD %d on (%s, %s) is reported to be %s, stackname %s",
         fd, rpcs->ta, rpcs->name, (ostat.stack_id != -1)
         ? "onload" : "system", names_match ? "matched" : "mismatched");


    /* will return false for system
     * (because rc = 0 and names_match is false) */
    if (ostat.stack_id != -1)
        return names_match ? TAPI_FD_IS_ONLOAD : TAPI_FD_WRONG_STACK;
    else
        return TAPI_FD_IS_SYSTEM;
}

/**
 * Get full stackname of a given FD.
 * Function will call TEST_FAIL if called on system fd and
 * close it with rpc_close
 *
 * @param rpcs        PCO
 * @param fd          FD
 *
 * @result stackname, NULL is also a valid one!
 */
static inline char * tapi_onload_get_stackname(rcf_rpc_server *rpcs,
                                               int fd)
{
    tarpc_onload_stat ostat;
    int rc;

    rc = rpc_onload_fd_stat(rpcs, fd, &ostat);
    if (rc == 0)
    {
        rpc_close(rpcs, fd);
        TEST_FAIL("%s() function called on system fd",
                  __FUNCTION__);
    }

    return ostat.stack_name;
}

/**
 * Simplified function which only checks if the FD is onload or system
 */
#define tapi_onload_is_onload_fd(pco_, s_) \
    tapi_onload_check_fd((pco_), (s_), NULL)

/*---------------------- scope to/from string conversion ---------*/
typedef struct {
    int scope;
    char *name;
} tapi_onload_scope_map_elem;

#define ONLOAD_SCOPE_MAP \
    {"USER", (int)ONLOAD_SCOPE_USER},               \
    {"THREAD", (int)ONLOAD_SCOPE_THREAD},           \
    {"PROCESS", (int)ONLOAD_SCOPE_PROCESS},         \
    {"GLOBAL", (int)ONLOAD_SCOPE_GLOBAL},           \
    {"NOCHANGE", (int)ONLOAD_SCOPE_NOCHANGE}

#define TEST_GET_ONLOAD_STACK_SCOPE(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, ONLOAD_SCOPE_MAP)

static inline const char * tapi_onload_scope2str(int scope)
{
    struct param_map_entry maps[] = {
        ONLOAD_SCOPE_MAP,
        { NULL, 0 },
    };
    int i = 0;

    do {
        if (maps[i].num_val == scope)
            return maps[i].str_val;
    } while (maps[++i].str_val != NULL);

    return "UNKNOWN";
}

/**
 * Create object of given type.
 * If type is 'pipe' - second FD is closed.
 *
 * @param rpcs         PCO handle
 * @param object_type  Type of the object to be checked
 * @param expectation  Is the @p object_type expected to be
 *                     accelerated.
 *
 * @result FD 
 */
extern int tapi_onload_object_create(rcf_rpc_server *rpcs,
                                     const char *object_type);

/**
 * Function checks that FDs which correspond to
 * certain object types created on given PCOs have
 * stacknames which have common prefix @p prefix and
 * may be have an exact match.
 *
 * @param rpcs1        PCO one
 * @param rpcs2        PCO two
 * @param object_type  Type of the object to check
 * @param prefix       Prefix to check
 * @param exact_match  Must or must not full names match.
 *
 * @result -1 or 0 in case of success.
 */
extern int tapi_onload_compare_stack_names(rcf_rpc_server *rpcs1,
                                           rcf_rpc_server *rpcs2,
                                           const char *object_type,
                                           const char *prefix,
                                           te_bool exact_match);
/**
 * Match stack names from tarpc_onload_stat structures.
 *
 * @param ostat1    The first structure
 * @param ostat1    The second structure
 *
 * @return @c TRUE is stack names match, @c FALSE otherwise
 */
static inline te_bool ostat_stack_names_match(tarpc_onload_stat *ostat1,
                                              tarpc_onload_stat *ostat2)
{
    if (ostat1->stack_name_null != ostat2->stack_name_null ||
        (!ostat1->stack_name_null && !ostat2->stack_name_null &&
         strcmp(ostat1->stack_name, ostat2->stack_name) != 0))
        return FALSE;

    return TRUE;
}

/**
 * Match stack name from tarpc_onload_stat structure with a prefix
 * string.
 *
 * @param ostat      The structure storing Onload stack name
 * @param stack_name
 *
 * @return @c TRUE is stack names match, @c FALSE otherwise
 */
static inline te_bool ostat_stack_name_match_str(tarpc_onload_stat *ostat,
                                                 const char *stack_name)
{
    if ((ostat->stack_name_null && stack_name != NULL) ||
        (!ostat->stack_name_null && stack_name == NULL) ||
        (!ostat->stack_name_null && stack_name != NULL &&
         strncmp(ostat->stack_name, stack_name,
                 strlen(stack_name)) != 0))
        return FALSE;

    return TRUE;
}

/**
 * Is epoll fd accelerated in current OOL configuration.
 * object is provided to simplify 'if' calls in particular
 * tests.
 */
#define TAPI_ONLOAD_EPOLL_ACC(object_) \
    (strcmp(object_, "epoll") != 0 || 0 /* is accelerated */)

/**
 * Expectations for tapi_onload_check_object
 */
#define TAPI_FD_ONLOAD TRUE
#define TAPI_FD_SYSTEM FALSE

/**
 * Check that object is accelerated/not-accelerated.
 *
 * @param rpcs          PCO handle
 * @param object        object type
 * @param expectation   expectation
 * @param name          expected name of the stack
 *
 * @result Will jump in case of failure 
 */
/* note: this is a macro so we can have __FUNCTION__/__LINE__ set correctly
 * in the log
 */
#define TAPI_ONLOAD_CHKOBJ_STACK(rpcs_ , object_ , expectation_, name_) \
    do {                                                                \
        int s;                                                          \
        int status;                                                     \
                                                                        \
        s = tapi_onload_object_create(rpcs_, object_);                  \
        status = tapi_onload_check_fd(rpcs_, s, name_);                 \
        rpc_close(rpcs_, s);                                            \
                                                                        \
        if ((status ^ (expectation_) &&                                 \
            TAPI_ONLOAD_EPOLL_ACC(object_)) ||                          \
            status == TAPI_FD_WRONG_STACK)                              \
            TEST_FAIL("(%s, %s): object '%s' is reported "              \
                      "to be %s which does not"                         \
                      "match expectations%s", (rpcs_)->ta,            \
                      (rpcs_)->name,                                    \
                      object_, status ? "onload" : "system",            \
                      (status == TAPI_FD_WRONG_STACK) ?                 \
                      " stacknames mismatch." : "");                    \
                                                                        \
        RING("(%s, %s): object '%s' was reported as %s which matches the " \
             "expectations", (rpcs_)->ta, (rpcs_)->name,                \
             object_, status ? "onload" : "system");                    \
    } while(0)

#define TAPI_ONLOAD_CHKOBJ(rpcs_ , object_ , expectation_) \
    TAPI_ONLOAD_CHKOBJ_STACK(rpcs_, object_, expectation_, NULL)

/**
 * Determine whether Onload socklib exists or not.
 *
 * @param ta          Test Agent name
 *
 * @return @c TRUE if exists
 */
static inline te_bool tapi_onload_lib_exists(const char *ta)
{
    cfg_val_type     val_type;
    char            *socklib = NULL;

    val_type = CVT_STRING;
    cfg_get_instance_fmt(&val_type, &socklib, "/local:%s/socklib:",
                         ta);

    return !te_str_is_null_or_empty(socklib);
}

/**
 * Check if it is L5 run.
 * 
 * @return @c TRUE if Onload acceleration is used.
 */
static inline te_bool
tapi_onload_run(void)
{
    char *l5_run = getenv("L5_RUN");

    if (l5_run != NULL && strcmp(l5_run, "true") == 0)
        return TRUE;

    return FALSE;
}

/**
 * Check if the socket is cached or not.
 * 
 * @param rpcs  RPC server
 * @param sock  File descriptor to be checked
 * 
 * @return @c TRUE if the socket is cached.
 */
extern te_bool tapi_onload_socket_is_cached(rcf_rpc_server *rpcs, int sock);

/**
 * Determine is the socket is cached with checking for lock contention
 *
 * @param rpcs1                 RPC server to check caching of socket
 * @param sock                  File descriptor to be checked
 * @param rpcs2                 RPC server to check sockcache_contention
 * @param sockcache_contention  Value of sockcache_contention obtained earlier
 *
 * @return @c TRUE if the socket is cached.
 */
extern te_bool tapi_onload_check_socket_caching(
    rcf_rpc_server *rpcs1, int sock, rcf_rpc_server *rpcs2,
    int sockcache_contention);

/**
 * Get an Onload stats value using "onload_stackdump lots".
 * 
 * @param rpcs  RPC server handler
 * @param name  Field name
 * 
 * @return The stats field value.
 */
extern int tapi_onload_get_stats_val(rcf_rpc_server *rpcs,
                                     const char *name);

/**
 * Get allowed for using Onload cache
 *
 * @param rpcs   RPC server handler
 * @param active Type of cache (active, passive)
 * @param reuse  Return @c TRUE if there is cached socket which can be reused
 *
 * @note The function uses onload stackdump, so pattern may change.
 *
 * @return The cache length.
 */
extern int tapi_onload_get_free_cache(rcf_rpc_server *rpcs,
                                      te_bool active, te_bool *reuse);

/**
 * Possible reset actions.
 */
typedef enum {
    SOCKTS_RESET_NIC_WORLD = 0,     /**< Use Onload utility @b cmdclient with
                                         command "reboot". */
    SOCKTS_RESET_ETHTOOL,           /**< Reset NIC using ethtool. */
    SOCKTS_RESET_DOWN_UP,           /**< Put NIC down/up. */
    SOCKTS_RESET_UNKNOWN,           /**< Invalid enum value - upper limit. */
} sockts_reset_mode;

#define SOCKTS_RESET_MODE  \
    { "world", SOCKTS_RESET_NIC_WORLD },            \
    { "ethtool", SOCKTS_RESET_ETHTOOL },            \
    { "down_up", SOCKTS_RESET_DOWN_UP }

/**
 * Reset a network interface. Resetting interface can be not @p ifname
 * interface, but interface(-s) which is parent of the specified one.
 *
 * @note The function jumps to @c cleanup in case of failure.
 *
 * @param ta        Test agent name
 * @param ifname    Interface name
 * @param mode      How to reset NIC or put it down/up
 */
extern void sockts_reset_interface(const char *ta, const char *ifname,
                                   sockts_reset_mode mode);

/**
 * Get current onload stack name
 *
 * @param rpcs       RPC server
 *
 * @return stack name, NULL is also a valid one!
*/
static inline char * tapi_onload_get_cur_stackname(rcf_rpc_server *rpcs)
{
    char *stackname;
    int   s;

    s = rpc_socket(rpcs, RPC_AF_INET, RPC_SOCK_STREAM, RPC_PROTO_DEF);

    stackname = tapi_onload_get_stackname(rpcs, s);

    rpc_close(rpcs, s);

    return stackname;
}

/**
 * Check if onload stack exists by stack id.
 *
 * @param rpcs      RPC server handle.
 * @param stak_id   Stack id
 *
 * @return @c TRUE if the stack is exists.
 */
static inline te_bool tapi_onload_stack_exists(rcf_rpc_server *rpcs,
                                               int stack_id)
{
    char     *out_cmd_buf = NULL;
    te_bool   is_existing = FALSE;

    RPC_AWAIT_IUT_ERROR(rpcs);
    rpc_shell_get_all(rpcs, &out_cmd_buf,
                      "cat /proc/driver/onload/stacks | grep ^%d:", -1, stack_id);

    if (strcmp(out_cmd_buf, "") != 0)
        is_existing = TRUE;

    free(out_cmd_buf);

    return is_existing;
}

/**
 * Get Onload stacks number.
 *
 * @param rpcs      RPC server handle.
 *
 * @return Stacks number.
 */
extern int tapi_onload_stacks_number(rcf_rpc_server *rpcs);

/**
 * Check that there is only one Onload stack, report a verdict if it is not
 * true.
 *
 * @param rpcs      RPC server handle.
 *
 * @return Status code:
 *      @retval 0                            Only one Onload stack is observed
 *      @retval TE_RC(TE_TAPI, TE_ENOENT)    No Onload stacks
 *      @retval TE_RC(TE_TAPI, TE_ETOOMANY)  More than one stack
 */
extern te_errno tapi_onload_check_single_stack(rcf_rpc_server *rpcs);

/**
 * Check that number of sockets which are not cached owing
 * to lock contention did not increase.
 *
 * @param rpcs                 RPC server
 * @param sockcache_contention Value of sockcache_contention obtained earlier
 *
 * @note The function should not be called on an RPC server
 *       that uses socket caching.
 * @return @c TRUE if sockcache_contention has not been increased
 */
static inline te_bool tapi_onload_check_sockcache_contention(
    rcf_rpc_server *rpcs, int sockcache_contention)
{
    if (tapi_onload_get_stats_val(rpcs, "sockcache_contention") >
        sockcache_contention)
    {
        RING_VERDICT("Socket was not cached owing to "
                     "lock contention");
        return FALSE;
    }

    return TRUE;
}

/**
 * Copy the specified script from sapi-ts/scripts to agent directory.
 *
 * @param rpcs        RPC server handle.
 * @param script_name Name of the script to copy.
 *
 * @return rc Status code.
 */
extern te_errno tapi_onload_copy_sapi_ts_script(rcf_rpc_server *rpcs,
                                                const char *script_name);

/**
 * Check that sfc module parameter "rss_cpus" is equal to 1, fail with error
 * if it is not.
 *
 * @param rpcs        RPC server handle.
 */
extern void tapi_onload_check_single_rss_cpus(rcf_rpc_server *rpcs);

/**
 * Set Onload module parameter value and save previous value
 * if it is necessary.
 *
 * @param rpcs          RPC server handle.
 * @param name          Name of Onload module parameter
 * @param val           New value
 * @param[out] old_val  Where to save existing value (can be @c NULL)
 * @param log_restore   If @c is TRUE, print to /dev/kmsg that the value is
 *                      restored, otherwise, a new value is set
 */
extern void tapi_onload_module_param_set(rcf_rpc_server *rpcs,
                                         const char *name,
                                         const char *val,
                                         char **old_val,
                                         te_bool log_restore);

/**
 * Set Onload module ci_tp_log value and save previous value
 *
 * @param rpcs          RPC server handle
 * @param val           New value
 * @param[out] old_val  Where to save existing value
 */
extern void tapi_onload_module_ci_tp_log_set(rcf_rpc_server *rpcs,
                                             const char *val,
                                             char **old_val);

/**
 * Restore Onload module ci_tp_log value
 *
 * @param rpcs          RPC server handle
 * @param val           Value to restore
 */
extern void tapi_onload_module_ci_tp_log_restore(rcf_rpc_server *rpcs,
                                                 const char *val);

/**
 * Restore Onload module ci_tp_log value and print a message to kernel log
 * Should be used in cleanup section of a test.
 *
 * @param rpcs          RPC server handle
 * @param val           Value to restore
 */
#define CLEANUP_RPC_RESTORE_CI_TP_LOG_LVL(_rpcs, _val) \
    do {                                                                      \
        if (_rpcs != NULL && _val != NULL)                                    \
        {                                                                     \
            rpc_wait_status _rc;                                              \
            CLEANUP_CHECK_RC(cfg_set_instance_fmt(CFG_VAL(STRING, _val),      \
                             "/agent:%s/module:onload/parameter:ci_tp_log",   \
                             _rpcs->ta));                                     \
            RPC_AWAIT_IUT_ERROR(_rpcs);                                       \
            _rc = rpc_system_ex(_rpcs, "echo 'sockapi-ts: restore Onload "    \
                    "module parameter ci_tp_log to %s' > /dev/kmsg", _val);   \
            if (_rc.value != 0)                                               \
                ERROR("%s(): failed to write a message to /dev/kmsg on IUT",  \
                      __func__);                                              \
        }                                                                     \
    } while(0)

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif  /* !__TS_ONLOAD_H__ */
