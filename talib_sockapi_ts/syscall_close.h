/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
#ifndef __SYSCALL_H__
#define __SYSCALL_H__
/** @file
 * @brief sapi-ts Test Agent Library
 *
 * Headers for various close() system call implementations.
 *
 * @author Ivan V. Soloducha <Ivan.Soloducha@oktetlabs.ru>
 *
 * $Id$
 */
#include "te_config.h"

#if defined(__x86_64__) || defined(__i386__)
#ifdef __unix__
#if (SIZEOF_VOID_P == 4)
/* 
 * Perform close() system call via interrupt
 * (80h for Linux, 91h for SunOS)
 */
extern int close_interrupt(int fd);
#else
/* Perform close() system call via syscall command */
extern int close_syscall(int fd);
#endif
#endif

#if (defined(__linux__) && (SIZEOF_VOID_P == 4))
/*
 * Perform close() system call via sysenter command
 *
 * @param fd    file descriptor
 * @param enter vsyscall page entrance point, detected in Agent's main()
 *
 * @return      status code
 */ 
extern int close_sysenter(int fd, const void *enter);
#endif /* Linux on 32-bit platform */
#endif /* Enabled only on x86 */
#endif /* __SYSCALL_H__ */
