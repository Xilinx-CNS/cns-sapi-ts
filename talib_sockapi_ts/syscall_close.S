/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief sapi-ts Test Agent Library
 *
 * Various close() system call implementations on Assembler.
 *
 * @author Ivan V. Soloducha <Ivan.Soloducha@oktetlabs.ru>
 *
 * $Id$
 */

#ifdef __CYGWIN__
#undef __unix__
#endif

#if defined(__unix__) && (defined(__x86_64__) || defined(__i386__))

#ifdef __linux__

#include <asm/unistd.h>
#if HAVE_ASM_GENERIC_ERRNO_H
#include <asm-generic/errno.h>
#else
#include <asm/errno.h>
#endif

#else /* Solaris */

#define _ASM
#include <sys/syscall.h>
#define EOPNOTSUPP      122

#endif /* Linux */

/* Define close() system call constant */
#ifndef SYS_close
#define SYS_close __NR_close
#endif

#include "te_config.h"
#if (SIZEOF_VOID_P == 4)
/* This is 32-bit code, therefore it must be compiled for 32-bit target. */

        .globl close_interrupt
        .type close_interrupt,@function
close_interrupt:
        pushl %ebx;
        movl  8(%esp), %ebx;      /* Function argument to ebx */
        movl  $SYS_close, %eax;   /* Syscall constant to eax */
#ifdef __linux__
        int   $0x80;              /* Perform system call */
        neg   %eax;               /* Linux int80 returns -errno */
#else        
/* 
   Solaris close() system call gets its argument from second stack frame,
   so push %ebx twice.
 */
        pushl %ebx;                             
        pushl %ebx;
        int   $0x91;
        popl  %ebx;
        popl  %ebx;               /* Solaris system call */
#endif  /* Linux */      
        popl  %ebx;               /* Restore modified register */
        ret;
#else
/* This is 64-bit code */
        .globl close_syscall
        .type close_syscall,@function
close_syscall:
        pushq %rbx;
        movq  $SYS_close, %rax;
        movq  16(%rsp), %rbx;
#ifdef __linux__
        syscall;
        neg   %rax;
#else
        pushq %rbx;
        pushq %rbx;
        syscall;
        popq  %rbx;
        popq  %rbx;
#endif        
        popq  %rbx;
        ret;
#endif  /* 32-bit platform */

#ifdef __linux__
#if (SIZEOF_VOID_P == 4)
        
        .globl close_sysenter
        .type close_sysenter,@function
close_sysenter:
        pushl %ebp;
        movl  12(%esp), %ebp;     /* %ebp = vsyscall page address */
        movw  5(%ebp), %ax;       /* sysenter command at offset 5 */
        movw  $0x340f, %bx;
        cmpw  %ax, %bx;
        jne   ._cs_no_sysenter;
        movl  $SYS_close, %eax;
        movl  8(%esp), %ebx;

        call *%ebp;
        neg   %eax;
        popl  %ebp;
        ret;
._cs_no_sysenter:
        movl  $EOPNOTSUPP, %eax;  /* no sysenter command found */
        popl  %ebp;
        ret;
#endif  /* 32-bit close() via sysenter */        
#endif  /* Linux */        

#endif /* Unix */       
