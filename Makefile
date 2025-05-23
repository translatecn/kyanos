V:=2
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ./libbpf/src)
BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX))
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
APPS = kyanos
CFLAGS := -O2 -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) kyanos kyanos.log

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
# 只在 $(LIBBPF_SRC) 中的 .c、.h 文件或 Makefile 更新后，才会重新构建 $(LIBBPF_OBJ)。
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
    $(call msg,LIB,$@)
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

GO_FILES := $(shell find $(SRC_DIR) -type f -name '*.go' | sort)

.PHONY: build-bpf
build-bpf: $(LIBBPF_OBJ) $(wildcard bpf/*.[ch]) | $(OUTPUT)
	TARGET=amd64 go generate ./bpf/
	TARGET=arm64 go generate ./bpf/

kyanos: $(GO_FILES)
	$(call msg,BINARY,$@)
	apt install musl musl-tools -y
	export CC=musl-gcc && export CGO_LDFLAGS="-Xlinker -rpath=. -static" && go build

.PHONY: kyanos-compress
kyanos-compress: $(GO_FILES)
	echo 123123
	$(call msg,BINARY,$@)
	export CC=musl-gcc && export CGO_LDFLAGS="-Xlinker -rpath=. -static" && go build && upx -9 kyanos


.PHONY: btfgen
btfgen:
	./bpf/btfgen.sh $(BUILD_ARCH) $(ARCH_BPF_NAME)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

.PHONY: test
test: test-go

.PHONY: test-go
test-go:
	go test -v ./...

.PHONY: format
format: format-go

.PHONY: format-go
format-go:
	goimports -w .
	gofmt -s -w .

.PHONY: format-md
format-md:
	find . -type f -name "*.md" | xargs npx prettier --write
	find docs/cn -type f -name "*.md" | xargs npx md-padding -i
	find . -type f -name "*_CN.md" | xargs npx md-padding -i

.PHONY: dlv
dlv:
	chmod +x kyanos && dlv --headless --listen=:2345 --api-version=2 --check-go-version=false exec ./kyanos

.PHONY: kyanos-debug
kyanos-debug: $(GO_FILES)
	$(call msg,BINARY,$@)
	export CC=musl-gcc && export CGO_LDFLAGS="-Xlinker -rpath=. -static" && go build -gcflags "all=-N -l"

.PHONY: remote-debug
remote-debug: build-bpf kyanos-debug dlv
