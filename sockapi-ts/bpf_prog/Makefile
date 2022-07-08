# SPDX-License-Identifier: Apache-2.0
# (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved.
CLANG = clang
LLC = llc

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(SRCS))
IRS = $(patsubst %.c,%.ll,$(SRCS))

CFLAGS ?=

define check_bpf_func
$(shell grep -q -s FN\($(1)\) /usr/include/linux/bpf.h && echo '-DHAVE_BPF_FUNC_$(1)')
endef

HAVE += $(call check_bpf_func,sk_lookup_tcp)
HAVE += $(call check_bpf_func,sk_lookup_udp)
HAVE += $(call check_bpf_func,sk_release)

define check_bpf_map
$(shell grep -q -s $(1), /usr/include/linux/bpf.h && echo '-DHAVE_$(1)')
endef

HAVE += $(call check_bpf_map,BPF_MAP_TYPE_CGROUP_STORAGE)
HAVE += $(call check_bpf_map,BPF_MAP_TYPE_REUSEPORT_SOCKARRAY)

CFLAGS += ${HAVE}
all: ${OBJS}

clean:
	rm -f ${OBJS} ${IRS}

%.o: %.c
	$(CLANG) -S \
	-target bpf \
	$(CFLAGS) \
	-Wall \
	-Wno-unused-value \
	-Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Werror \
	-O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
