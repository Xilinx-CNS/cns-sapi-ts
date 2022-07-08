/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** 
 * UNIX daemons and utilities 
 * Auxiliary definitios and functions.
 * 
 * @author Elena A. Vengerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */
 
#ifndef __SERVICES_H__
#define __SERVICES_H__

/**
 * Make new address with non-used port basing on existing address.
 * 
 * @param base          base address
 * @param wildcard      if TRUE, allocate wildcard address
 *
 * @return new address or NULL
 */
static inline struct sockaddr *
make_address(rcf_rpc_server *pco, const struct sockaddr *base,
             te_bool wildcard)
{
    socklen_t        baselen = te_sockaddr_get_size(base);
    struct sockaddr *addr = calloc(1, baselen);
    uint16_t         port;
    
    if (addr == NULL)
    {
        ERROR("Out of memory");
        return NULL;
    }
    
    if (!wildcard)
        memcpy(addr, base, baselen);
    else
        addr->sa_family = base->sa_family;
        
    if (tapi_allocate_port(pco, &port) != 0)
    {
        ERROR("Cannot allocate port");
        free(addr);
        return NULL;
    }
    te_sockaddr_set_port(addr, htons(port));
    
    return addr;
}

/**< OS type enumeration constants */
typedef enum { OS_LINUX, OS_SOLARIS, OS_FREEBSD } os_t;

/**
 * Gets PCO's OS type.
 * 
 * @param pco_iut       PCO, OS type to get for
 *
 * @return OS type enumeration constant
 */
static inline os_t
OS(rcf_rpc_server *pco_iut)
{
    char   *buf;
    size_t s;
    os_t os;

    /** Get OS name */
    rpc_shell_get_all(pco_iut, &buf, "uname", -1);

    /** Remove trailing '\n's */
    if ((s = strlen(buf)) > 0)
        while (buf[s - 1] == '\n' && s > 0)
            s--;

    buf[s] = '\0';

    if (strcmp(buf, "Linux") == 0)
        os = OS_LINUX;
    else if (strcmp(buf, "SunOS") == 0)
        os = OS_SOLARIS;
    else if (strcmp(buf, "FreeBSD") == 0)
        os = OS_FREEBSD;
    else
    {
        free(buf);
        TEST_FAIL("Unknown OS (%s) TA runs on", buf);
    }

    free(buf);
    return os;
}

#define MAKE_ADDRESS(_pco, _res, _base, _wildcard)  \
    CHECK_NOT_NULL(_res = make_address(_pco, _base, _wildcard))

/** Helpful macros */
#define __MAKE_STRING(x) #x
#define MAKE_STRING(x) __MAKE_STRING(x)

/** Tester user uid */
#define USER_UID        10000
/** Tester user name */
#define USER_NAME       TE_USER_PREFIX MAKE_STRING(USER_UID)
/** Tester user home directory */
#define USER_HOME       "/tmp/" USER_NAME 
/** Create tester user on the specified Test Agent */
#define USER_CREATE(_ta) \
    do {                                                                  \
        cfg_handle _handle;                                               \
        int        _err;                                                  \
                                                                          \
        if ((_err = cfg_add_instance_fmt(&_handle, CVT_NONE, NULL,        \
                                 "/agent:%s/user:" USER_NAME, _ta)) != 0) \
        {                                                                 \
            TEST_FAIL("Cannot create tester user on the TA %s", _ta);     \
        }                                                                 \
    } while (0)

/** X server display number */
#define X_SERVER_NUMBER         50

/** VNC server display number */
#define VNC_SERVER_NUMBER       60

/** Start Xvfb on the TA */
#define XVFB_ADD(_ta) \
    do {                                                                \
        int _err =                                                      \
            cfg_add_instance_fmt(&handle, CVT_NONE, NULL,               \
                                 "/agent:%s/Xvfb:%d", _ta,              \
                                 X_SERVER_NUMBER);                      \
                                                                        \
        if (_err != 0)                                                  \
        {                                                               \
            TEST_FAIL("Cannot configure Xvfb :%d on the %s",            \
                      X_SERVER_NUMBER, _ta);                            \
        }                                                               \
    } while (0)

#define XVFB_DEL(_ta) \
    do {                                                                \
        cfg_del_instance_fmt(FALSE, "/agent:%s/Xvfb:%d", _ta,           \
                             X_SERVER_NUMBER);                          \
    } while (0)

/** Start VNC server on the TA */
#define VNCSERVER_ADD(_ta) \
    do {                                                                \
        int _err =                                                      \
            cfg_add_instance_fmt(&handle, CVT_NONE, NULL,               \
                                 "/agent:%s/vncserver:%d",              \
                                 _ta, VNC_SERVER_NUMBER);               \
                                                                        \
        if (_err != 0)                                                  \
        {                                                               \
            TEST_FAIL("Cannot configure vncserver :%d on the %s",       \
                      VNC_SERVER_NUMBER, _ta);                          \
        }                                                               \
    } while (0)

/** Check output of spawned 'pwd' command */
#define CHECK_WHOAMI_OUTPUT(_rpcs, _fd, _pid) \
    do {                                                                \
        char _aux_buf[strlen(USER_NAME) + 1];                           \
        memset(&_aux_buf, 0, sizeof(_aux_buf));                         \
                                                                        \
        rpc_waitpid(_rpcs, _pid, NULL, 0);                              \
        _pid = -1;                                                      \
        rpc_read(_rpcs, _fd, _aux_buf, strlen(USER_NAME));              \
                                                                        \
        if (strcmp(_aux_buf, USER_NAME) != 0)                           \
            TEST_FAIL("whoami command returned %s instead " USER_NAME,  \
                      _aux_buf);                                        \
    } while (0)

#define TELNET_LOGIN(_rpcs, _addr, _handle) \
    do {                                                                     \
        int _rc;                                                             \
                                                                             \
        if ((_rc = tapi_cli_csap_remote_create((_rpcs)->ta, 0,               \
                       TAPI_CLI_CSAP_TYPE_TELNET,                            \
                       _addr, TAPI_CLI_TELNET_PORT_DFLT,                     \
                       TAPI_CLI_PROMPT_TYPE_PLAIN,                           \
                       tapi_cli_debian_cprompt_dflt,                         \
                       TAPI_CLI_PROMPT_TYPE_PLAIN,                           \
                       tapi_cli_telnet_lprompt_dflt, USER_NAME,              \
                       TAPI_CLI_PROMPT_TYPE_PLAIN,                           \
                       tapi_cli_telnet_pprompt_dflt, USER_NAME,              \
                       &(_handle))) != 0)                                    \
         {                                                                   \
            TEST_FAIL("Cannot login to the %s from TA %s via telnet; "       \
                      " errno %r", _addr, (_rpcs)->ta, _rc);                 \
         }                                                                   \
    } while (0)

#define TELNET_LOGOUT(_rpcs, _handle) \
    do {                                                                  \
        int _rc;                                                          \
        if ((_rpcs) != NULL && (_handle) != CSAP_INVALID_HANDLE &&        \
            (_rc = tapi_tad_csap_destroy((_rpcs)->ta, 0, _handle)) != 0)    \
        {                                                                 \
            ERROR("Failed to remove TELNET CSAP; errno %r", _rc);         \
            result = -1;                                                  \
        }                                                                 \
    } while (0)

/** 
 * Send/receive data via socket pair. DATA_BULK, rx_buf and tx_buf should
 * be defined.
 *
 * @param _sender      RPC server for data sending
 * @param _s_sender    socket for data sending
 * @param _receiver    RPC server for data receiving
 * @param _s_receiver  socket for data receiving
 */
#define DATA_SEND_RECV(_sender, _s_sender, _receiver, _s_receiver) \
    do {                                                                \
        int len;                                                        \
                                                                        \
        te_fill_buf(tx_buf, DATA_BULK);                               \
        memset(rx_buf, 0, sizeof(rx_buf));                              \
        RPC_WRITE(len, _sender, _s_sender, tx_buf, DATA_BULK);          \
        if (len != DATA_BULK)                                           \
            TEST_FAIL("Incorrect number of bytes is transferred");      \
        len = rpc_read(_receiver, _s_receiver, rx_buf, sizeof(rx_buf));  \
        if (len != DATA_BULK)                                           \
            TEST_FAIL("Incorrect number of bytes is transferred");      \
        if (memcmp(tx_buf, rx_buf, DATA_BULK) != 0)                     \
            TEST_FAIL("Data are corrupted");                            \
    } while (0)


/**
 * Macro checks if corresponding service is installed on the
 * agent by checking corresponding configuration subtree
 * presence.
 *
 * Verdict is echoed in case service is missing.
 *
 * @param ta_   Test agent on which service should be checked
 * @param service_name_ Service to check
 */
#define TEST_CHECK_SERVICE(ta_, service_name_)      \
    do                                                          \
    {                                                           \
        if (service_check(ta_, (#service_name_)) == 0)          \
        {                                                       \
            TEST_VERDICT("Service %s is missing on agent %s",   \
                         (#service_name_), (ta_));               \
        }                                                       \
    } while (0)


/**
 * Function checks service presence on a given agent.
 *
 * @param ta            Test agent on which service presence should be
 *                      checked.
 * @param service_name  Name of the service to be checked.
 *
 * @return   0 - service is missing
 *           1 - service is present
 *           jmp - failed to get service status
 * */
static inline int
service_check(const char *ta, const char *service_name)
{
    int rc;
    int status;

    rc = cfg_get_instance_fmt(CVT_INTEGER, &status,
                              "/agent:%s/%s:",
                              ta, service_name);
    RING("Service check for '%s' returned %r", __FUNCTION__,
         service_name, rc);
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
        return 0;
    else if (rc == 0)
        return 1;
    else
        TEST_FAIL("Failed to get %s service status from agent %s: %r",
                  service_name, ta, rc);

    return 0;
}

#endif /* __SERVICES_H__ */
