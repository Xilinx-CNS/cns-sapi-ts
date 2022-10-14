# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
if cc.has_header_symbol('unistd.h', 'environ')
    c_args += [ '-DHAVE_ENVIRON_DECLARED' ]
endif

t = 'struct mmsghdr'
if cc.has_type(t, prefix: '#include <sys/socket.h>')
    conf.set('HAVE_' + t.to_upper().underscorify(), 1)
endif

code_prefix_signal_h = '''
#include <signal.h>
'''

t = 'union sigval'
union_sigval_members = [
    'sigval_int',
    'sival_int',
]
foreach m : union_sigval_members
    if cc.has_member(t, m, prefix: code_prefix_signal_h)
        c_args += [ '-DHAVE_' + t.to_upper().underscorify() + '_' +
                    m.to_upper().underscorify() ]
    endif
endforeach

t = 'siginfo_t'
struct_siginfo_t_members = [
    'si_sigval',
    'si_value',
]
foreach m : struct_siginfo_t_members
    if cc.has_member(t, m, prefix: code_prefix_signal_h)
        c_args += [ '-DHAVE_' + t.to_upper().underscorify() + '_' +
                    m.to_upper().underscorify() ]
    endif
endforeach

check_headers = [
    'asm-generic/errno.h',
    'sys/epoll.h',
]
foreach h : check_headers
    if cc.has_header(h)
        c_args += [ '-DHAVE_' + h.to_upper().underscorify() ]
    endif
endforeach

#
# Check declarations of onload extensions
#
oo_extensions_h = [
    'ONLOAD_DELEGATED_SEND_RC_NOCWIN',
    'onload_socket_unicast_nonaccel',
]

talib_dir = include_directories('.')
foreach h : oo_extensions_h
    have_decl = 'HAVE_DECL_' + h.to_upper().underscorify()
    if cc.has_header_symbol('extensions.h', h, include_directories: talib_dir)
        c_args += [ '-D' + have_decl + '=1' ]
    endif
endforeach

oo_extensions_h = [
    'onload_delegated_send_tcp_advance',
    'onload_delegated_send_tcp_update',
]

#
# This checks whether function's implementation is available
# (it is declared as inline in header). In such case we
# should not try to resolve it dynamically.
#
foreach h : oo_extensions_h
    if cc.has_function(h, include_directories: talib_dir,
                       prefix: '#include "extensions.h"')
        have_def = 'HAVE_IMPL_' + h.to_upper().underscorify()
        c_args += [ '-D' + have_def + '=1' ]
    endif
endforeach


oo_extensions_h = [
    'onload_zc_hlrx_recv_zc',
]

foreach h : oo_extensions_h
    have_decl = 'HAVE_DECL_' + h.to_upper().underscorify()
    if cc.has_header_symbol('extensions_zc_hlrx.h', h, include_directories: talib_dir)
        c_args += [ '-D' + have_decl + '=1' ]
    endif
    if cc.has_header_symbol('extensions_zc.h', h, include_directories: talib_dir)
        c_args += [ '-D' + have_decl + '=1' ]
    endif
endforeach

sources += files('rpc.c')
sources += files('syscall_close.S')

build_lib = 'static'
te_libs += [
    'loggerta',
    'rpcserver',
]
