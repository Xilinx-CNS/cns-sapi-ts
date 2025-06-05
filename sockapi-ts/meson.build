# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.

project('sockapi-ts', 'c',
    version : '1.0.0',
)

te_path = get_option('te_path')
te_libdir = get_option('te_libdir')
add_project_arguments(get_option('te_cflags').split(), language: 'c')
add_project_link_arguments(get_option('te_ldflags').split(), language: 'c')

cc = meson.get_compiler('c')

te_tests_info_sh = find_program(join_paths(te_path, 'te_tests_info.sh'))

test_deps = [
    dependency('threads'),
]

test_deps += [ cc.find_library('m'), cc.find_library('pcap') ]

# The line below would produce empty dependencies on systems
# having no tirpc - it is not a problem.
dep_tirpc = dependency('libtirpc', required: false)

test_deps += [ dep_tirpc ]

te_libs = [
    'asn',
    'bsapi',
    'comm_net_engine',
    'confapi',
    'conf_oid',
    'ipc',
    'logger_core',
    'logger_ten',
    'logic_expr',
    'ndn',
    'tapi',
    'tapi_bpf',
    'tapi_env',
    'tapi_job',
    'tapi_rpc',
    'tapi_serial',
    'tapi_tad',
    'tapi_tcp_states',
    'tapi_tool',
    'tools',
    'trc',
    'rcfapi',
    'rpc_types',
    'rcfunix',
    'rcfrpc',
    'rpcxdr'
]

foreach lib : te_libs
    test_deps += cc.find_library(lib, dirs: te_libdir)
endforeach

onload_tslib_dir = run_command('sh', '-c', 'echo ${SFC_ONLOAD_LIB}').stdout().strip()
message('Using SFC_ONLOAD_LIB: ' + onload_tslib_dir)

#
# Check declarations of onload extensions
#
oo_extensions_h = [
    'ONLOAD_DELEGATED_SEND_RC_NOCWIN',
    'onload_socket_unicast_nonaccel',
]
tmp = run_command('sh', '-c', 'echo ${SOCKAPI_TS_LIBDIR}').stdout().strip()
talib_dir = include_directories(tmp + '/talib_sockapi_ts')

foreach h : oo_extensions_h
    have_decl = 'HAVE_DECL_' + h.to_upper().underscorify()
    if cc.has_header_symbol('extensions.h', h, include_directories: talib_dir)
         add_project_arguments('-D' + have_decl + '=1', language: 'c')
    endif
endforeach

oo_extensions_h = [
    'onload_zc_hlrx_recv_zc',
]

foreach h : oo_extensions_h
    have_decl = 'HAVE_DECL_' + h.to_upper().underscorify()
    if cc.has_header_symbol('extensions_zc.h', h, include_directories: talib_dir)
         add_project_arguments('-D' + have_decl + '=1', language: 'c')
    endif
    if cc.has_header_symbol('extensions_zc_hlrx.h', h, include_directories: talib_dir)
         add_project_arguments('-D' + have_decl + '=1', language: 'c')
    endif
endforeach

lib_dir = include_directories('lib', onload_tslib_dir)

subdir('lib')

test_deps += declare_dependency(include_directories: lib_dir,
                                link_with: ts_sockapi_lib)

tests = [
    'prologue',
    'gateways_epilogue',
    'epilogue',
]

package_dir = 'sockapi-ts'
package_tests_c = []

foreach test : tests
    test_exe = test
    test_c = test + '.c'
    package_tests_c += [ test_c ]
    executable(test_exe, test_c, install: true, install_dir: package_dir,
               dependencies: test_deps)
endforeach

install_data([ 'mainpage.dox', 'package.xml' ],
             install_dir: package_dir)

packages = [
    'aio',
    'arp',
    'attacks',
    'basic',
    'bnbvalue',
    'bpf',
    'checksum',
    'congestion',
    'epoll',
    'fcntl',
    'ifcfg',
    'ioctls',
    'iomux',
    'level5',
    'libinit',
    'multicast',
    'nonblock',
    'performance',
    'pmtu',
    'reuseport',
    'route',
    'sendfile',
    'sendrecv',
# Package services is broken: see ON-8461, ST-1834
#    'services',
    'signal',
    'sockopts',
    'tcp',
    'timestamps',
    'tools',
    'udp',
    'usecases',
]

mydir = package_dir
foreach package : packages
    package_dir = join_paths(mydir, package)
    package_tests_c = []
    subdir(package)
endforeach
