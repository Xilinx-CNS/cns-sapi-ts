/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2022 OKTET Labs Ltd. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Common definitions for tools package.
 *
 * @author Pavel Liulchak <Pavel.Liulchak@oktetlabs.ru>
 */

#ifndef __TS_TOOLS_LIB_H__
#define __TS_TOOLS_LIB_H__

#include "sockapi-test.h"
#include "tapi_ssh.h"
#include "tapi_job.h"
#include "tapi_job_factory_rpc.h"
#include "tapi_cfg_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * User name to log in as on the remote machine.
 */
#define TOOLS_LIB_SSH_DEFAULT_USER_NAME "root"

/**
 * Identity key file filename.
 */
#define TOOLS_LIB_SSH_RSA_IDENTITY_KEY_NAME "rsa_identity"

/**
 * Hostkey file filename.
 */
#define TOOLS_LIB_SSH_RSA_HOSTKEY_NAME "rsa_hostkey"

/** Enum representation of hosts involved in the testing */
typedef enum {
    TOOLS_LIB_SSH_IUT = 0,  /**< Use pco_iut */
    TOOLS_LIB_SSH_TST1,     /**< Use pco_tst1 */
    TOOLS_LIB_SSH_TST2,     /**< Use pco_tst2 */
} tools_lib_ssh_host;

/**
 * List for TEST_GET_ENUM_PARAM() macro to obtain an argument
 * of tools_lib_ssh_host type
 */
#define TOOLS_LIB_SSH_HOST \
    {"iut", TOOLS_LIB_SSH_IUT},     \
    {"tst1", TOOLS_LIB_SSH_TST1},   \
    {"tst2", TOOLS_LIB_SSH_TST2}

/**
 * Macro for ssh key data structure initialization.
 */
#define TOOLS_SSH_RSA_KEY_DATA_INIT(_name) { \
    .name = _name,                           \
    .manager = TAPI_CFG_KEY_MANAGER_SSH,     \
    .type = TAPI_CFG_KEY_TYPE_SSH_RSA,       \
    .size = TAPI_CFG_KEY_SIZE_RECOMMENDED,   \
}

/** Data about key to create */
typedef struct tools_ssh_key_data
{
    const char *name;
    tapi_cfg_key_manager manager;
    tapi_cfg_key_type type;
    tapi_cfg_key_size size;
} tools_ssh_key_data;

/**
 * Create public and private keys according to @p key_data.
 *
 * @param rpcs                  RPC server handle.
 * @param key_data              Data about key to create.
 *
 * @return Status code.
 */
extern te_errno tools_ssh_create_keys(rcf_rpc_server *rpcs,
                                      tools_ssh_key_data *key_data);

/**
 * Create empty sshd_config file.
 *
 * @note It is useful to create an empty custom configuration file
 *       to prevent sshd from usage default one /etc/ssh/sshd_config
 *       that may be a cause of errors related with deprecation options.
 *
 * @param rpcs                  RPC server handle.
 */
extern void tools_ssh_create_empty_sshd_config_file(rcf_rpc_server *rpcs);

/**
 * Prepare paths to files in the client options structure.
 *
 * @note Use #tools_ssh_free_client_file_paths_strings to free the
 *       allocated strings that keep files paths
 *
 * @param rpcs                  RPC server handle.
 * @param client_opt            Client command line options.
 *
 * @sa tools_ssh_free_client_file_paths_strings
 */
extern void tools_ssh_prepare_client_file_paths_options(rcf_rpc_server *rpcs,
                                                        tapi_ssh_client_opt *client_opt);

/**
 * Free paths to files in the client options structure.
 *
 * @param client_opt            Client command line options.
 *
 * @sa tools_ssh_prepare_client_file_paths_options
 */
extern void tools_ssh_free_client_file_paths_strings(tapi_ssh_client_opt *client_opt);

/**
 * Prepare paths to files in the server options structure.
 *
 * @note Use #tools_ssh_free_server_file_paths_strings to free the
 *       allocated strings that keep files paths
 *
 * @param rpcs                  RPC server handle.
 * @param server_opt            Server command line options.
 *
 * @sa tools_ssh_free_server_file_paths_strings
 */
extern void tools_ssh_prepare_server_file_paths_options(rcf_rpc_server *rpcs,
                                                        tapi_ssh_server_opt *server_opt);

/**
 * Free paths to files in the server options structure.
 *
 * @param server_opt            Server command line options.
 *
 * @sa tools_ssh_prepare_server_file_paths_options
 */
extern void tools_ssh_free_server_file_paths_strings(tapi_ssh_server_opt *server_opt);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __TS_TOOLS_LIB_H__ */