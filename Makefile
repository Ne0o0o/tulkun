.ONESHELL:
SHELL = /bin/sh

#
# CMD
#

CMD_CLANG ?= clang
CMD_CUT ?= cut
CMD_GO ?= go
CMD_MKDIR ?= mkdir
CMD_RM ?= rm
CMD_TR ?= tr
# check tools
.check_%:
#
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

#
# output dir
#

OUTPUT_DIR = ./dist

$(OUTPUT_DIR):
#
	@$(CMD_MKDIR) -p $@
	$(CMD_MKDIR) -p $@/libbpf
	$(CMD_MKDIR) -p $@/libbpf/obj


BPF_VCPU = v2

#
# environment
#
UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

ifeq ($(UNAME_M),x86_64)
	ARCH = x86_64
	LINUX_ARCH = x86
	GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
	ARCH = arm64
	LINUX_ARCH = arm64
	GO_ARCH = arm64
endif

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

.checkver_$(CMD_CLANG): \
	| .check_$(CMD_CLANG)
#
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	touch $@ # avoid target rebuilds over and over due to inexistent file


#
# libbpf (statically linked)
#

LIBBPF_SRC = ./pkg/ebpf/libbpf/src
LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDFLAGS =

$(OUTPUT_DIR)/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \
	| .checkver_$(CMD_CLANG) $(OUTPUT_DIR)
#
	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/) \
		OBJDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/obj) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers

#
# tulkun ebpf object
#

TULKUN_EBPF_OBJ_SRC = ./pkg/ebpf/c/tulkun.bpf.c
TULKUN_EBPF_OBJ_SRC_TEST = ./pkg/ebpf/c/tulkun.bpf-test.c

TULKUN_EBPF_OBJ_HEADERS = $(shell find pkg/ebpf/c -name *.h)
TULKUN_EBPF_OBJ_HEADERS_DIR = ./pkg/ebpf/c/

.PHONY: bpf
bpf: $(OUTPUT_DIR)/tulkun.bpf.o

$(OUTPUT_DIR)/tulkun.bpf.o: \
	$(OUTPUT_DIR)/libbpf/libbpf.a \
	$(TULKUN_EBPF_OBJ_SRC) \
	$(TULKUN_EBPF_OBJ_HEADERS)
#
	$(CMD_CLANG) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		-DCORE \
		-I $(TULKUN_EBPF_OBJ_HEADERS_DIR) \
		-I $(OUTPUT_DIR)/libbpf/ \
		-target bpf \
		-O2 -g \
		-march=bpf -mcpu=$(BPF_VCPU) \
		-c $(TULKUN_EBPF_OBJ_SRC) \
		-o $@

$(OUTPUT_DIR)/tulkun.bpf-test.o: \
	$(OUTPUT_DIR)/libbpf/libbpf.a \
	$(TULKUN_EBPF_OBJ_SRC_TEST) \
	$(TULKUN_EBPF_OBJ_HEADERS)
#
	$(CMD_CLANG) \
		-D__TARGET_ARCH_$(LINUX_ARCH) \
		-D__BPF_TRACING__ \
		-DCORE \
		-I $(TULKUN_EBPF_OBJ_HEADERS_DIR) \
		-I $(OUTPUT_DIR)/libbpf/ \
		-target bpf \
		-O2 -g \
		-march=bpf -mcpu=$(BPF_VCPU) \
		-c $(TULKUN_EBPF_OBJ_SRC_TEST) \
		-o $@

# use go net instead of cgo
GO_TAGS_EBPF = netgo
GO_LDFLAGS_EBPF = '-w -extldflags "-static"'

LIBBPF_OBJ = $(abspath $(OUTPUT_DIR)/libbpf/libbpf.a)
CGO_CFLAGS_STATIC = "-I$(abspath $(OUTPUT_DIR)/libbpf)"
CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_OBJ)"

.PHONY: tulkun-ebpf
tulkun-ebpf: $(OUTPUT_DIR)/tulkun.bpf.o
	CC=$(CMD_CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
				$(CMD_GO) build \
				-tags $(GO_TAGS_EBPF) \
				-ldflags=$(GO_LDFLAGS_EBPF) \
				-o $@ \
				./cmd/tulkun-ebpf

.PHONY: test
test: $(OUTPUT_DIR)/tulkun.bpf.o
	CC=$(CMD_CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
				$(CMD_GO) build \
				-tags $(GO_TAGS_EBPF) \
				-ldflags=$(GO_LDFLAGS_EBPF) \
				-o $@ \
				./cmd/tulkun-test

.PHONY: clean
clean:
	$(CMD_RM) -rf $(OUTPUT_DIR)
	$(CMD_RM) tulkun-ebpf
