/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * Tools testing
 */

/**
 * @page tools-ssh_port_fwd_clnt SSH port forwarding on the client side
 *
 * @objective Check that SSH server performs TCP forwarding properly.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_two_nets_iut_first
 * @param tester    Tester end of the client:
 *                  - @c tst1
 *                  - @c tst2
 * @param server    PCO of TCP server:
 *                  - @c iut
 *                  - @c tst1
 *                  - @c tst2
 * @param client    PCO of TCP client:
 *                  - @c iut
 *                  - @c tst1
 *                  - @c tst2
 *
 * @par Scenario:
 *
 * @author Pavel Liulchak <Pavel.Liulchak@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tools/ssh_port_fwd_clnt"

#include "tapi_ssh.h"
#include "sockapi-test.h"
#include "tapi_job_factory_rpc.h"
#include "onload.h"
#include "tools_lib.h"

/**
 * Max length of string representation of connection to be forwarded
 * @note an example of representation: [bind_address:]port:host:hostport
 */
#define SSH_PORT_FWD_CLNT_MAX_FORWARDING_BUF_LENGTH 50

/**
 * Amount of trials to establish connection via tunnel
 * @note The value is dictated by the cases when five
 *       attempts were not enough to establish connection.
 */
#define SSH_PORT_FWD_CLNT_CONNECTION_ATTEMPTS 8

static rcf_rpc_server *pco_iut = NULL;
static rcf_rpc_server *pco_tst1 = NULL;
static rcf_rpc_server *pco_tst2 = NULL;

static const struct sockaddr  *iut_addr1 = NULL;
static const struct sockaddr  *iut_addr2 = NULL;
static const struct sockaddr  *tst1_addr = NULL;
static const struct sockaddr  *tst2_addr = NULL;

/** Data corresponding to one secure tunnel */
typedef struct ssh_port_fwd_clnt_tunnel {
    rcf_rpc_server  *tst;                    /**< Tester end of the client */
    rcf_rpc_server  *srv;                    /**< TCP server PCO */
    rcf_rpc_server  *clnt;                   /**< TCP client PCO */

    const struct sockaddr *tst_addr;         /**< Address corresponding to tester */
    struct sockaddr_storage srv_addr;        /**< TCP server address */
    struct sockaddr_storage proxy_addr;      /**< Proxy address */

    te_bool remote_port_forwarding;          /**< Port forwarding type */

    tapi_job_factory_t     *factory;         /**< Tunnel job factory */
    tapi_ssh_t             *tunnel;          /**< Tunnel app handle */
    tapi_job_wrapper_t     *wrap;            /**< Tunnel wrapper instance handle */
    uint16_t port;                           /**< Port on which remote host sshd is run */

    int s_srv;                               /**< Socket for listening on the TCP */
    int s_clnt[2];                           /**< Client sockets */
    int s_acc[2];                            /**< Socket for accepted connections */
} ssh_port_fwd_clnt_tunnel_t;

/**
 * Context initializer for tunnel data.
 *
 * @param tdata        tunnel data context.
 *
 */
static void
init_tunnel_data(ssh_port_fwd_clnt_tunnel_t *tdata)
{
    tdata->tst = NULL;
    tdata->srv = NULL;
    tdata->clnt = NULL;

    tdata->tst_addr = NULL;

    tdata->factory = NULL;
    tdata->tunnel = NULL;
    tdata->wrap = NULL;

    tdata->s_srv = tdata->s_clnt[0] =
    tdata->s_clnt[1] = tdata->s_acc[0] =
    tdata->s_acc[1] = -1;
}

/**
 * Get RPC server via related host parameter.
 *
 * @param host        host parameter.
 *
 * @return RPC server.
 */
static rcf_rpc_server*
retrieve_pco_via_host_param(tools_lib_ssh_host host)
{
    switch(host)
    {
        case TOOLS_LIB_SSH_IUT:
            return pco_iut;

        case TOOLS_LIB_SSH_TST1:
            return pco_tst1;

        case TOOLS_LIB_SSH_TST2:
            return pco_tst2;

        default:
            return NULL;
    }
}

/**
 * Get TST RPC server address.
 *
 * @param host        host parameter related with a TST side.
 *
 * @return TST server address.
 */
static const struct sockaddr*
retrieve_tst_sockaddr_via_host_param(tools_lib_ssh_host host)
{
    switch(host)
    {
        case TOOLS_LIB_SSH_TST1:
            return tst1_addr;

        case TOOLS_LIB_SSH_TST2:
            return tst2_addr;

        default:
            return NULL;
    }
}

/**
 * Get IUT RPC server address within net shared with TST side.
 *
 * @param tst_host        host parameter related with a TST side.
 *
 * @note It is assumed that host with @p pco_tst2 is connected with
 * @p pco_iut via different network segment than one connecting
 * @p pco_tst1 and @p pco_iut.
 *
 * @return IUT server address.
 */
static const struct sockaddr*
retrieve_iut_sockaddr_via_tst_host_param(tools_lib_ssh_host tst_host)
{
    switch(tst_host)
    {
        case TOOLS_LIB_SSH_TST1:
            return iut_addr1;

        case TOOLS_LIB_SSH_TST2:
            return iut_addr2;

        default:
            return NULL;
    }
}

/**
 * Check by host parameter if host is IUT.
 *
 * @param host        host parameter.
 *
 * @return @c TRUE if host is IUT.
 */
static inline te_bool
host_is_iut(tools_lib_ssh_host host)
{
    switch(host)
    {
        case TOOLS_LIB_SSH_IUT:
            return TRUE;
        default:
            return FALSE;
    }
}

/**
 * Get RPC server address within net shared with TST side.
 *
 * @param host_param        host parameter.
 * @param tst_host_param    host parameter related with a TST side.
 *
 * @return RPC server address.
 */
static const struct sockaddr*
retrieve_sockaddr_via_host_params(tools_lib_ssh_host host_param,
                                  tools_lib_ssh_host tst_host_param)
{
    const struct sockaddr *addr;

    if (host_is_iut(host_param))
        addr = retrieve_iut_sockaddr_via_tst_host_param(tst_host_param);
    else
        addr = retrieve_tst_sockaddr_via_host_param(host_param);

    CHECK_NOT_NULL(addr);

    return addr;
}

/**
 * Fill data about the tunnel.
 *
 * @param tdata         The tunnel data to set.
 * @param tester        Param related with tester end PCO.
 * @param server        Param related with TCP server PCO.
 * @param client        Param related with TCP client PCO.
 *
 */
static void
prepare_tunnel_data(ssh_port_fwd_clnt_tunnel_t *tdata,
                    tools_lib_ssh_host tester,
                    tools_lib_ssh_host server,
                    tools_lib_ssh_host client)
{
    CHECK_NOT_NULL(tdata->tst = retrieve_pco_via_host_param(tester));
    CHECK_NOT_NULL(tdata->tst_addr = retrieve_tst_sockaddr_via_host_param(tester));

    CHECK_NOT_NULL(tdata->srv = retrieve_pco_via_host_param(server));
    CHECK_RC(tapi_sockaddr_clone(tdata->srv,
                                 retrieve_sockaddr_via_host_params(server, tester),
                                 &tdata->srv_addr));

    CHECK_NOT_NULL(tdata->clnt = retrieve_pco_via_host_param(client));
    CHECK_RC(tapi_sockaddr_clone(tdata->clnt,
                                 retrieve_sockaddr_via_host_params(client, tester),
                                 &tdata->proxy_addr));

    tdata->remote_port_forwarding = !host_is_iut(client);
    tdata->port = ntohs(te_sockaddr_get_port(tdata->tst_addr));
}

/**
 * Create the SSH tunnel for TCP forwarding.
 *
 * @note In case of local and remote port forwarding the comandlines
 *       look like:
 *       ssh -g -N -L proxy_port:srv_ip:srv_port -p @p tdata->port tst_ip
 *       ssh -g -N -R proxy_port:srv_ip:srv_port -p @p tdata->port tst_ip
 *       where
 *       - proxy_port is a @p client port from which connections forward.
 *       - srv_ip is address of @p server.
 *       - srv_port is a @p server port to which connections forward.
 *       - @p tdata->port is a @p tester port on which sshd is run.
 *       - tst_ip is address of @p tester.
 *
 * @param tdata     Data about the tunnel to create.
 *
 */
static void
create_tunnel(ssh_port_fwd_clnt_tunnel_t *tdata)
{
    char forwarding_buf[SSH_PORT_FWD_CLNT_MAX_FORWARDING_BUF_LENGTH];
    uint16_t proxy_port;
    uint16_t srv_port;
    const char *srv_ip = NULL;
    char *tst_ip = NULL;
    tapi_ssh_client_opt tunnel_opt = tapi_ssh_client_opt_default_opt;

    proxy_port = ntohs(te_sockaddr_get_port(SA(&tdata->proxy_addr)));
    srv_port = ntohs(te_sockaddr_get_port(SA(&tdata->srv_addr)));

    srv_ip = te_sockaddr_get_ipstr(SA(&tdata->srv_addr));

    if (srv_ip == NULL)
        TEST_FAIL("Can't detect server host to forward to");

    te_snprintf(forwarding_buf, sizeof(forwarding_buf),
                "%d:%s:%d", proxy_port, srv_ip, srv_port);

    tst_ip = te_ip2str(tdata->tst_addr);

    RING("Prepare the tunnel options");
    tunnel_opt.gateway_ports = TRUE;
    tunnel_opt.forbid_remote_commands_execution = TRUE;

    if (tdata->remote_port_forwarding)
        tunnel_opt.remote_port_forwarding = forwarding_buf;
    else
        tunnel_opt.local_port_forwarding = forwarding_buf;

    tunnel_opt.login_name = TOOLS_LIB_SSH_DEFAULT_USER_NAME;
    tunnel_opt.port = tdata->port;
    tunnel_opt.destination = tst_ip;

    tools_ssh_prepare_client_file_paths_options(pco_iut, &tunnel_opt);

    RING("Create the tunnel job");
    CHECK_RC(tapi_job_factory_rpc_create(pco_iut, &(tdata->factory)));
    CHECK_RC(tapi_ssh_create_client(tdata->factory, &(tunnel_opt), &(tdata->tunnel)));

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        const char *tool = PATH_TO_TE_ONLOAD;
        const char *tool_argv[2] = {
            PATH_TO_TE_ONLOAD,
            NULL
        };
        CHECK_RC(tapi_ssh_client_wrapper_add(tdata->tunnel, tool, tool_argv,
                                             TAPI_JOB_WRAPPER_PRIORITY_DEFAULT,
                                             &tdata->wrap));
    }

    RING("Start the tunnel");
    CHECK_RC(tapi_ssh_start_app(tdata->tunnel));

    RING("Wait the tunnel start");
    TAPI_WAIT_NETWORK;

    free(tst_ip);

    tools_ssh_free_client_file_paths_strings(&tunnel_opt);
}

/**
 * Create TCP connections via the SSH tunnel.
 *
 * @param tdata     Data about the tunnel through which connections
 *                  to be created.
 *
 */
static void
create_connections(ssh_port_fwd_clnt_tunnel_t *tdata)
{
    int rc;
    unsigned int i = 0;

    if (tdata->remote_port_forwarding)
        te_sockaddr_set_loopback(SA(&tdata->proxy_addr));

    tdata->s_srv = rpc_create_and_bind_socket(tdata->srv, RPC_SOCK_STREAM,
                                              RPC_PROTO_DEF, FALSE, FALSE,
                                              SA(&tdata->srv_addr));
    rpc_listen(tdata->srv, tdata->s_srv, 2);

    tdata->s_clnt[0] = rpc_socket(tdata->tst, RPC_AF_INET,
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);
    tdata->s_clnt[1] = rpc_socket(tdata->clnt, RPC_AF_INET,
                                  RPC_SOCK_STREAM, RPC_PROTO_DEF);

    /* Perform several connection till the tunnel is up */
    do {
        RPC_AWAIT_ERROR(tdata->tst);
        rc = rpc_connect(tdata->tst, tdata->s_clnt[0], SA(&tdata->proxy_addr));

        if (rc != 0)
        {
            if (RPC_ERRNO(tdata->tst) == RPC_ECONNREFUSED)
            {
                TAPI_WAIT_NETWORK;
            }
            else
            {
                TEST_FAIL("connect() call returned unexpected errno %s",
                errno_rpc2str(RPC_ERRNO(tdata->tst)));
            }
        }
    } while ((rc == -1) && ((++i) < SSH_PORT_FWD_CLNT_CONNECTION_ATTEMPTS));

    tdata->s_acc[0] = rpc_accept(tdata->srv, tdata->s_srv,
                                 NULL, NULL);

    rpc_connect(tdata->clnt, tdata->s_clnt[1], SA(&tdata->proxy_addr));
    tdata->s_acc[1] = rpc_accept(tdata->srv, tdata->s_srv,
                                 NULL, NULL);
}

/**
 * Send/receive data via socket pair over SSH tunnel.
 *
 * @param tdata     Data about the tunnel through which connection
 *                  to be checked.
 */
static void
check_connections(ssh_port_fwd_clnt_tunnel_t *tdata)
{
    sockts_test_connection(tdata->tst, tdata->s_clnt[0],
                           tdata->srv, tdata->s_acc[0]);

    sockts_test_connection(tdata->srv, tdata->s_acc[0],
                           tdata->tst, tdata->s_clnt[0]);

    sockts_test_connection(tdata->clnt, tdata->s_clnt[1],
                           tdata->srv, tdata->s_acc[1]);

    sockts_test_connection(tdata->srv, tdata->s_acc[1],
                           tdata->clnt, tdata->s_clnt[1]);
}

int
main(int argc, char *argv[])
{
    rcf_rpc_server *pco_tst = NULL;
    const struct sockaddr  *tst_addr = NULL;

    tapi_job_factory_t*         tst_sshd_factory = NULL;
    tapi_ssh_server_opt         tst_sshd_opt = tapi_ssh_server_opt_default_opt;
    tapi_ssh_t*                 tst_sshd;

    tools_ssh_key_data iut_key =
        TOOLS_SSH_RSA_KEY_DATA_INIT(TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME);
    tools_ssh_key_data tst_key =
        TOOLS_SSH_RSA_KEY_DATA_INIT(TOOLS_LIB_SSH_RSA_HOSTKEY_NAME);

    ssh_port_fwd_clnt_tunnel_t tdata;

    tools_lib_ssh_host tester;
    tools_lib_ssh_host server;
    tools_lib_ssh_host client;

    init_tunnel_data(&tdata);

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_iut, iut_addr1);
    TEST_GET_ADDR(pco_iut, iut_addr2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_ENUM_PARAM(tester, TOOLS_LIB_SSH_HOST);
    TEST_GET_ENUM_PARAM(server, TOOLS_LIB_SSH_HOST);
    TEST_GET_ENUM_PARAM(client, TOOLS_LIB_SSH_HOST);

    CHECK_NOT_NULL(pco_tst = retrieve_pco_via_host_param(tester));
    CHECK_NOT_NULL(tst_addr = retrieve_tst_sockaddr_via_host_param(tester));

    TEST_STEP("Create public and private ssh keys both on server and client side.");
    CHECK_RC(tools_ssh_create_keys(pco_iut, &iut_key));
    CHECK_RC(tools_ssh_create_keys(pco_tst, &tst_key));

    TEST_STEP("Copy client public ssh key to the server authorized_keys file.");
    CHECK_RC(tapi_cfg_key_append_public(pco_iut->ta, iut_key.name,
                                        pco_tst->ta, "authorized_keys"));

    TEST_STEP("Create empty sshd_config file.");
    tools_ssh_create_empty_sshd_config_file(pco_tst);

    TEST_STEP("Prepare tunnel data.");
    prepare_tunnel_data(&tdata, tester, server, client);

    TEST_STEP("Prepare ssh server (detached sshd) options.");
    tst_sshd_opt.port = ntohs(te_sockaddr_get_port(tst_addr));
    tools_ssh_prepare_server_file_paths_options(pco_tst, &tst_sshd_opt);

    TEST_STEP("Create ssh server (sshd) job.");
    CHECK_RC(tapi_job_factory_rpc_create(pco_tst, &tst_sshd_factory));
    CHECK_RC(tapi_ssh_create_server(tst_sshd_factory, &tst_sshd_opt, &tst_sshd));

    TEST_STEP("Start ssh server (sshd).");
    CHECK_RC(tapi_ssh_start_app(tst_sshd));

    TEST_STEP("Wait to allow ssh server (sshd) launch.");
    TAPI_WAIT_NETWORK;

    TEST_STEP("Create the tunnel.");
    create_tunnel(&tdata);

    TEST_STEP("Create connections through the tunnel.");
    create_connections(&tdata);

    TEST_STEP("Check connections through the tunnel.");
    check_connections(&tdata);

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_ssh_kill_app(tst_sshd, SIGTERM));
    CLEANUP_CHECK_RC(tapi_ssh_destroy_app(tst_sshd));

    CLEANUP_RPC_CLOSE(tdata.srv, tdata.s_srv);
    CLEANUP_RPC_CLOSE(tdata.srv, tdata.s_acc[0]);
    CLEANUP_RPC_CLOSE(tdata.srv, tdata.s_acc[1]);
    CLEANUP_RPC_CLOSE(tdata.tst, tdata.s_clnt[0]);
    CLEANUP_RPC_CLOSE(tdata.clnt, tdata.s_clnt[1]);

    CLEANUP_CHECK_RC(tapi_ssh_kill_app(tdata.tunnel, SIGTERM));
    CLEANUP_CHECK_RC(tapi_ssh_destroy_app(tdata.tunnel));
    free(tdata.wrap);

    tools_ssh_free_server_file_paths_strings(&tst_sshd_opt);

    CLEANUP_CHECK_RC(tapi_cfg_key_del(pco_iut->ta, iut_key.name));
    CLEANUP_CHECK_RC(tapi_cfg_key_del(pco_tst->ta, tst_key.name));

    TEST_END;
}