/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Implementations of common functions for tools package.
 *
 * @author Pavel Liulchak <Pavel.Liulchak@oktetlabs.ru>
 */

#include "te_str.h"
#include "tapi_rpc_unistd.h"
#include "tapi_rpc_misc.h"
#include "tools_lib.h"
#include "tapi_file.h"

/* See description in tools_lib.h */
te_errno
tools_ssh_create_keys(rcf_rpc_server *rpcs,
                      tools_ssh_key_data *key_data)
{
    return tapi_cfg_key_add(rpcs->ta, key_data->name,
                            key_data->manager, key_data->type,
                            key_data->size, TAPI_CFG_KEY_MODE_NEW);
}

/* See description in tools_lib.h */
void
tools_ssh_create_empty_sshd_config_file(rcf_rpc_server *rpcs)
{
    char *rpcs_ta_tmp_dir = NULL;
    char *rpcs_ta_sshd_config_file = NULL;

    CHECK_RC(cfg_get_instance_fmt(NULL, &rpcs_ta_tmp_dir,
                                  "/agent:%s/tmp_dir:", rpcs->ta));

    rpcs_ta_sshd_config_file = te_str_concat(rpcs_ta_tmp_dir, "sshd_config");
    CHECK_RC(tapi_file_create_ta(rpcs->ta, rpcs_ta_sshd_config_file, "%s", ""));

    free(rpcs_ta_sshd_config_file);
    free(rpcs_ta_tmp_dir);
}

/* See description in tools_lib.h */
void
tools_ssh_prepare_client_file_paths_options(rcf_rpc_server *rpcs,
                                            tapi_ssh_client_opt *client_opt)
{
    char *rpcs_ta_tmp_dir = NULL;

    CHECK_RC(cfg_get_instance_fmt(NULL, &rpcs_ta_tmp_dir,
                                  "/agent:%s/tmp_dir:", rpcs->ta));

    client_opt->user_known_hosts_file = te_str_concat(rpcs_ta_tmp_dir, "known_hosts");
    client_opt->identity_file =
                        tapi_cfg_key_get_private_key_path(rpcs->ta,
                                                          TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME);

    if (client_opt->identity_file == NULL)
    {
        TEST_FAIL("Cannot get identity key path for '%s' on %s",
                  TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME, rpcs->ta);
    }

    free(rpcs_ta_tmp_dir);
}

/* See description in tools_lib.h */
void
tools_ssh_free_client_file_paths_strings(tapi_ssh_client_opt *client_opt)
{
    free(client_opt->user_known_hosts_file);
    free(client_opt->identity_file);
}

/* See description in tools_lib.h */
void
tools_ssh_prepare_server_file_paths_options(rcf_rpc_server *rpcs,
                                            tapi_ssh_server_opt *server_opt)
{
    char *rpcs_ta_tmp_dir = NULL;

    CHECK_RC(cfg_get_instance_fmt(NULL, &rpcs_ta_tmp_dir,
                                  "/agent:%s/tmp_dir:", rpcs->ta));

    server_opt->authorized_keys_file = te_str_concat(rpcs_ta_tmp_dir, "authorized_keys");
    server_opt->pid_file = te_str_concat(rpcs_ta_tmp_dir, "sshd.pid");
    server_opt->config_file = te_str_concat(rpcs_ta_tmp_dir, "sshd_config");
    server_opt->host_key_file =
                        tapi_cfg_key_get_private_key_path(rpcs->ta,
                                                          TOOLS_LIB_SSH_RSA_HOSTKEY_NAME);

    if (server_opt->host_key_file == NULL)
    {
        TEST_FAIL("Cannot get hostkey file path for '%s' on %s",
                  TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME, rpcs->ta);
    }

    free(rpcs_ta_tmp_dir);
}

/* See description in tools_lib.h */
void
tools_ssh_free_server_file_paths_strings(tapi_ssh_server_opt *server_opt)
{
    free(server_opt->authorized_keys_file);
    free(server_opt->pid_file);
    free(server_opt->config_file);
    free(server_opt->host_key_file);
}