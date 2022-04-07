/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/*
 * Socket API Test Suite
 * Tools testing
 */

/**
 * @page tools-ssh_client Check OpenSSH connection establishing
 *
 * @objective Check that SSH client can connect to the SSH server (sshd)
 *            using `true` comand.
 *
 * @param env       Testing environment:
 *                  - @ref arg_types_env_two_nets_iut_first
 * @param server    PCO of ssh server (sshd):
 *                  - @c tst1
 *                  - @c tst2
 *
 * @par Scenario:
 *
 * @author Pavel Liulchak <Pavel.Liulchak@oktetlabs.ru>
 */

#define TE_TEST_NAME  "tools/ssh_client"

#include "tapi_ssh.h"
#include "sockapi-test.h"
#include "tapi_job.h"
#include "tapi_job_factory_rpc.h"
#include "onload.h"
#include "tools_lib.h"

/**
 * SSH request command
 */
#define SSH_CLIENT_COMMAND "true"

int
main(int argc, char *argv[])
{
    tapi_job_factory_t*    iut_ssh_factory = NULL;
    tapi_job_factory_t*    tst_sshd_factory = NULL;

    tapi_ssh_client_opt    iut_ssh_opt =
                                tapi_ssh_client_opt_default_opt;
    tapi_ssh_server_opt    tst_sshd_opt =
                                tapi_ssh_server_opt_default_opt;

    tapi_ssh_t*            iut_ssh = NULL;
    tapi_ssh_t*            tst_sshd = NULL;

    tools_ssh_key_data iut_key =
        TOOLS_SSH_RSA_KEY_DATA_INIT(TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME);
    tools_ssh_key_data tst_key =
        TOOLS_SSH_RSA_KEY_DATA_INIT(TOOLS_LIB_SSH_RSA_HOSTKEY_NAME);

    tapi_job_wrapper_t *wrap = NULL;

    rcf_rpc_server        *pco_iut = NULL;
    rcf_rpc_server        *pco_tst1 = NULL;
    rcf_rpc_server        *pco_tst2 = NULL;
    rcf_rpc_server        *pco_tst = NULL;

    const struct sockaddr *tst1_addr;
    const struct sockaddr *tst2_addr;
    const struct sockaddr *tst_addr;

    tools_lib_ssh_host server;

    TEST_START;
    TEST_GET_PCO(pco_iut);
    TEST_GET_PCO(pco_tst1);
    TEST_GET_PCO(pco_tst2);
    TEST_GET_ADDR(pco_tst1, tst1_addr);
    TEST_GET_ADDR(pco_tst2, tst2_addr);

    TEST_GET_ENUM_PARAM(server, TOOLS_LIB_SSH_HOST);

    switch(server)
    {
        case TOOLS_LIB_SSH_TST1:
            pco_tst = pco_tst1;
            tst_addr = tst1_addr;
            break;

        case TOOLS_LIB_SSH_TST2:
            pco_tst = pco_tst2;
            tst_addr = tst2_addr;
            break;

        default:
            TEST_FAIL("Unknown server parameter");
    }

    TEST_STEP("Create public and private ssh keys both on server and client side.");
    CHECK_RC(tools_ssh_create_keys(pco_iut, &iut_key));
    CHECK_RC(tools_ssh_create_keys(pco_tst, &tst_key));

    TEST_STEP("Copy client public ssh key to the server authorized_keys file.");
    CHECK_RC(tapi_cfg_key_append_public(pco_iut->ta, iut_key.name,
                                        pco_tst->ta, "authorized_keys"));

    TEST_STEP("Create empty sshd_config file.");
    tools_ssh_create_empty_sshd_config_file(pco_tst);

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

    TEST_STEP("Prepare ssh client options.");
    iut_ssh_opt.login_name = TOOLS_LIB_SSH_DEFAULT_USER_NAME;
    iut_ssh_opt.port = tst_sshd_opt.port;
    iut_ssh_opt.destination = te_ip2str(tst_addr);
    iut_ssh_opt.command = SSH_CLIENT_COMMAND;
    tools_ssh_prepare_client_file_paths_options(pco_iut, &iut_ssh_opt);

    TEST_STEP("Create ssh client job.");
    CHECK_RC(tapi_job_factory_rpc_create(pco_iut, &iut_ssh_factory));
    CHECK_RC(tapi_ssh_create_client(iut_ssh_factory, &iut_ssh_opt, &iut_ssh));

    if (tapi_onload_lib_exists(pco_iut->ta))
    {
        const char *tool = PATH_TO_TE_ONLOAD;
        const char *tool_argv[2] = {
            PATH_TO_TE_ONLOAD,
            NULL
        };
        CHECK_RC(tapi_ssh_client_wrapper_add(iut_ssh, tool, tool_argv,
                                            TAPI_JOB_WRAPPER_PRIORITY_DEFAULT,
                                            &wrap));
    }

    TEST_STEP("Start ssh client.");
    CHECK_RC(tapi_ssh_start_app(iut_ssh));

    TEST_STEP("Wait for completion ssh client request.");
    CHECK_RC(tapi_ssh_wait_app(iut_ssh, TAPI_SSH_APP_WAIT_TIME_MS));

    TEST_SUCCESS;

cleanup:
    CLEANUP_CHECK_RC(tapi_ssh_kill_app(tst_sshd, SIGTERM));

    CLEANUP_CHECK_RC(tapi_ssh_destroy_app(iut_ssh));
    CLEANUP_CHECK_RC(tapi_ssh_destroy_app(tst_sshd));

    tools_ssh_free_client_file_paths_strings(&iut_ssh_opt);
    tools_ssh_free_server_file_paths_strings(&tst_sshd_opt);

    free(wrap);
    free(iut_ssh_opt.destination);

    CLEANUP_CHECK_RC(tapi_cfg_key_del(pco_iut->ta, iut_key.name));
    CLEANUP_CHECK_RC(tapi_cfg_key_del(pco_tst->ta, tst_key.name));

    TEST_END;
}