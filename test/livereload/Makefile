# Live Reload Test Makefile
#
# Builds both native and APE versions for testing

CC ?= cc
COSMOCC ?= cosmocc

CFLAGS = -O2 -g -Wall -Wextra
LDFLAGS =

# Source paths
E9PATCH_DIR = ../../src/e9patch
WASM_DIR = $(E9PATCH_DIR)/wasm

# Live reload and its dependencies
LIVERELOAD_SRC = $(E9PATCH_DIR)/e9livereload.c
E9APE_SRC = $(E9PATCH_DIR)/e9ape.c
E9BINARYEN_SRC = $(WASM_DIR)/e9binaryen.c
E9WASM_HOST_SRC = $(WASM_DIR)/e9wasm_host.c

ALL_SRCS = $(LIVERELOAD_SRC) $(E9APE_SRC) $(E9BINARYEN_SRC) $(E9WASM_HOST_SRC) $(WAMR_SRCS)

# Include paths
VENDOR_DIR = $(E9PATCH_DIR)/vendor
WAMR_DIR = $(VENDOR_DIR)/wamr
WAMR_INCLUDE = $(WAMR_DIR)/core/iwasm/include
WAMR_PLATFORM = $(WAMR_DIR)/core/shared/platform/cosmopolitan
WAMR_COMMON = $(WAMR_DIR)/core/iwasm/common
INCLUDES = -I$(E9PATCH_DIR) -I$(WASM_DIR) -I$(GEN_DIR) -I$(WAMR_INCLUDE) -I$(WAMR_DIR)

# WAMR source files
WAMR_SRCS = $(WAMR_COMMON)/wasm_runtime_common.c $(WAMR_PLATFORM)/platform_init.c

# Generated types (from cosmo-bde root)
# Path: upstream/e9studio/test/livereload -> ../../../../gen/domain
GEN_DIR = ../../../../gen/domain
GEN_TYPES = $(GEN_DIR)/livereload_types.c

.PHONY: all clean native ape test demo simple standalone

all: native

# Standalone livereload (unified procmem API, uses cosmo-bde generated types)
# No sudo needed if you own the target process!
E9PROCMEM_SRC = $(E9PATCH_DIR)/e9procmem.c

standalone: target livereload
	@echo "Standalone build complete (unified procmem API)"
	@echo "  ./target     - Test target program"
	@echo "  ./livereload - Live reload with hot-patching"
	@echo ""
	@echo "Usage: ./livereload <PID> [source_file]"
	@echo "(sudo only needed if patching another user's process)"

livereload: livereload.c $(E9PROCMEM_SRC) $(GEN_TYPES)
	$(CC) $(CFLAGS) -I$(E9PATCH_DIR) -I$(GEN_DIR) -o $@ $^

# Simple test (no WAMR dependency) - quick proof of concept
simple: target test_simple
	@echo "Simple test build complete"
	@echo "  ./target      - Test target program"
	@echo "  ./test_simple - Simple live reload (no WAMR)"

test_simple: test_simple.c
	$(CC) $(CFLAGS) -o $@ $<

# Native build (for local testing)
native: target test_livereload
	@echo "Native build complete"
	@echo "  ./target          - Test target program"
	@echo "  ./test_livereload - Live reload driver"

target: target.c
	$(CC) $(CFLAGS) -o $@ $<

test_livereload: test_livereload.c $(ALL_SRCS) $(GEN_TYPES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# APE build (portable)
ape: target.ape test_livereload.ape
	@echo "APE build complete (portable across Linux/macOS/Windows/BSD)"

target.ape: target.c
	$(COSMOCC) $(CFLAGS) -o $@ $<

test_livereload.ape: test_livereload.c $(ALL_SRCS) $(GEN_TYPES)
	$(COSMOCC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Demo: run target in background and attach livereload
demo: native
	@echo "Starting live reload demo..."
	@echo ""
	@echo "1. Starting target in background..."
	@./target &
	@sleep 1
	@echo ""
	@echo "2. Target PID: $$(pgrep -f './target')"
	@echo ""
	@echo "3. Starting live reload watcher..."
	@echo "   (Edit target.c and save to see hot-patching)"
	@echo ""
	@./test_livereload $$(pgrep -f './target') .

# Run tests
test: native
	@echo "Running live reload unit tests..."
	@# TODO: Add unit tests
	@echo "No unit tests yet"

clean:
	rm -f target test_livereload target.ape test_livereload.ape livereload test_simple
	rm -f *.o
	rm -rf .e9cache
