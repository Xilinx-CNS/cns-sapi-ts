/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * Socket API Test Suite
 * Basic Socket API
 */

/** @file
 *
 * Specific definitions for basic/terminate_waitpid_prologue and
 * basic/terminate_waitpid.
 *
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __BASIC_TERMINATE_WAITPID_PROLOGUE_H__
#define __BASIC_TERMINATE_WAITPID_PROLOGUE_H__

#define TERM_WAITPID_PARSER_EVENT   "released_with_lock_stuck"

/**
 * Configurator path to the event which handle the pattern
 * "released with lock stuck".
 */
#define TERM_WAITPID_PARSER_CONFSTR_EV  \
    "/agent:"SERIAL_LOG_PARSER_AGENT    \
    "/parser:"SERIAL_LOG_PARSER_NAME    \
    "/event:"TERM_WAITPID_PARSER_EVENT

#endif /* __BASIC_TERMINATE_WAITPID_PROLOGUE_H__ */
