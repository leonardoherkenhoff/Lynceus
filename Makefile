# eBPFNetFlowLyzer Build System
# Standardized Makefile for C-Native eBPF Network Feature Extraction
# 
# Targets:
#   all:   Builds Kernel XDP object and User-Space Daemon
#   clean: Purges build artifacts
#
# Requirements: clang, libbpf, libelf, zlib

CLANG ?= clang
LLC ?= llc
OPT ?= opt
BPFTOOL ?= bpftool

# --- Directories ---
SRC_DIR = src
EBPF_DIR = $(SRC_DIR)/ebpf
DAEMON_DIR = $(SRC_DIR)/daemon
BUILD_DIR = build

# --- Build Targets ---
EBPF_OBJ = $(BUILD_DIR)/main.bpf.o
DAEMON_BIN = $(BUILD_DIR)/loader

# --- Compilation Flags ---
CFLAGS = -g -O2 -Wall -Wextra
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I$(EBPF_DIR) -Wall -Wno-missing-declarations -Wno-compare-distinct-pointer-types
LDFLAGS = -lbpf -lelf -lz -lm

all: $(BUILD_DIR) $(EBPF_OBJ) $(DAEMON_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Data Plane (In-Kernel XDP Hook)
$(EBPF_OBJ): $(EBPF_DIR)/main.bpf.c $(EBPF_DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Control Plane (User-Space Daemon utilizing libbpf)
$(DAEMON_BIN): $(DAEMON_DIR)/loader.c
	$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
