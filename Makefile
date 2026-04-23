# ----- Project -----
CLIENT_TARGET := PQ_VPN_Client
SERVER_TARGET := PQ_VPN_Server
TEST_TARGET := test_runner
CXX := g++
CC  := gcc
#CXX := clang++
WARN := -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion #-Werror
STD := -std=c++23
OPT := -O2
DEP := -MMD -MP
INCLUDES := -Iclient -Iserver -Itests -Icore -Icore/os/$(PLATFORM) -Icore/cryptography -Icore/utils -Icore/network -Icore/handshake -Icore/session -Icore/config

# ----- Verbosity -----
# V=low (errors only), V=medium (default, file-level), V=high (everything)
V ?= medium

ifeq ($(V),low)
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS :=
else ifeq ($(V),high)
  Q :=
  CMAKE_QUIET :=
  SHOW_PROGRESS := 1
else
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS := 1
endif

# ----- File Extensions -----
CXX_EXT := cpp

# ----- Makefile Config -----
MAKEFLAGS += --no-print-directory

# ----- Default target -----
.DEFAULT_GOAL := help

# ----- Platform -----
UNAME_S := $(shell uname -s)
ifeq ($(OS),Windows_NT)
  PLATFORM := windows
else ifeq ($(UNAME_S),Linux)
  PLATFORM := linux
else ifeq ($(UNAME_S),Darwin)
  PLATFORM := macos
else
  $(error Unsupported OS: $(UNAME_S))
endif

# ----- Lib Detections -----
LIB_CFLAGS      :=
LDFLAGS         :=
OPENSSL_FOUND   := yes
OPENSSL_VERSION :=

# Extract "X.Y.Z" from the OpenSSL header (no binary execution needed — works under sudo).
get_openssl_bin_version = $(shell grep 'OPENSSL_VERSION_STR' $(1)/include/openssl/opensslv.h 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

# Return "yes" if "X.Y[.Z]" satisfies >= 3.5, "no" otherwise.
check_openssl_version = $(shell \
  v="$(1)"; \
  major=$$(printf '%s' "$$v" | cut -d. -f1); \
  minor=$$(printf '%s' "$$v" | cut -d. -f2); \
  if [ -n "$$major" ] && [ -n "$$minor" ] && \
     { [ "$$major" -gt 3 ] 2>/dev/null || \
       { [ "$$major" -eq 3 ] 2>/dev/null && [ "$$minor" -ge 5 ] 2>/dev/null; }; }; then \
    echo yes; \
  else echo no; fi)

ifeq ($(PLATFORM),macos)
  # Prefer the versioned formula so we get 3.5 explicitly.
  OPENSSL_PREFIX ?= $(or $(shell brew --prefix openssl@3.5 2>/dev/null),$(shell brew --prefix openssl 2>/dev/null))
  ifneq ($(strip $(OPENSSL_PREFIX)),)
    OPENSSL_VERSION := $(call get_openssl_bin_version,$(OPENSSL_PREFIX))
    ifeq ($(call check_openssl_version,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
      LDFLAGS    += -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
    else
      OPENSSL_FOUND := no
    endif
  else
    OPENSSL_FOUND := no
  endif

else ifeq ($(PLATFORM),linux)
  ifneq ($(strip $(OPENSSL_PREFIX)),)
    # User-specified prefix: verify the version then use it.
    OPENSSL_VERSION := $(call get_openssl_bin_version,$(OPENSSL_PREFIX))
    ifeq ($(call check_openssl_version,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
      ifneq ($(wildcard $(OPENSSL_PREFIX)/lib64),)
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib64
      else
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
      endif
      LDFLAGS += -lssl -lcrypto
    else
      OPENSSL_FOUND := no
    endif
  else
    # No prefix set: try pkg-config, then auto-detect /usr/local/openssl-3.5.
    OPENSSL_VERSION := $(shell pkg-config --modversion openssl 2>/dev/null)
    ifeq ($(call check_openssl_version,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += $(shell pkg-config --cflags openssl)
      LDFLAGS    += $(shell pkg-config --libs openssl)
    else ifneq ($(wildcard /usr/local/openssl-3.5/bin/openssl),)
      OPENSSL_PREFIX  := /usr/local/openssl-3.5
      OPENSSL_VERSION := $(call get_openssl_bin_version,$(OPENSSL_PREFIX))
      ifeq ($(call check_openssl_version,$(OPENSSL_VERSION)),yes)
        LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
        ifneq ($(wildcard $(OPENSSL_PREFIX)/lib64),)
          LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib64
        else
          LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
        endif
        LDFLAGS += -lssl -lcrypto
      else
        OPENSSL_FOUND := no
      endif
    else
      OPENSSL_FOUND := no
    endif
  endif

else ifeq ($(PLATFORM),windows)
  OPENSSL_VERSION := $(shell openssl version 2>/dev/null | awk '{print $$2}')
  ifneq ($(strip $(OPENSSL_VERSION)),)
    ifeq ($(call check_openssl_version,$(OPENSSL_VERSION)),yes)
      LDFLAGS += -lssl -lcrypto -lws2_32
    else
      OPENSSL_FOUND := no
    endif
  else
    OPENSSL_FOUND := no
  endif
endif

ifeq ($(OPENSSL_FOUND),no)
$(info )
$(info ERROR: OpenSSL 3.5 or later is required but was not found.)
$(info )
$(info   Required : OpenSSL >= 3.5)
$(info   Found    : $(if $(strip $(OPENSSL_VERSION)),$(OPENSSL_VERSION),not found))
$(info )
$(info   Install OpenSSL 3.5 and point the build at it using one of:)
$(info )
$(info   Linux / macOS -- set a prefix:)
$(info     export OPENSSL_PREFIX=/usr/local/openssl-3.5)
$(info     make <target>)
$(info )
$(info   Linux -- update pkg-config search path:)
$(info     export PKG_CONFIG_PATH=/usr/local/openssl-3.5/lib64/pkgconfig)
$(info     make <target>)
$(info )
$(info   macOS -- install via Homebrew:)
$(info     brew install openssl@3.5)
$(info )
$(error Build aborted: OpenSSL 3.5+ not found)
endif

# ==============================================================================
# Bundled Libraries
# ==============================================================================
LIBSDIR     := libs
LIBS_OBJDIR := $(LIBSDIR)/obj

# Auto-discover all lib subdirectories (excluding obj/)
LIB_SUBDIRS   := $(shell find $(LIBSDIR) -mindepth 1 -maxdepth 1 -type d ! -name obj 2>/dev/null)
LIB_INCLUDES  := $(addprefix -I,$(LIB_SUBDIRS))

# Split libs into cmake-based and generic (plain source)
CMAKE_LIB_DIRS   := $(foreach dir,$(LIB_SUBDIRS),$(if $(wildcard $(dir)/CMakeLists.txt),$(dir)))
GENERIC_LIB_DIRS := $(filter-out $(CMAKE_LIB_DIRS),$(LIB_SUBDIRS))

# ------------------------------------------------------------------------------
# cmake-based libs
# ------------------------------------------------------------------------------
CMAKE_LIB_NAMES   := $(foreach dir,$(CMAKE_LIB_DIRS),$(notdir $(dir)))
CMAKE_LIB_STAMPS  := $(foreach name,$(CMAKE_LIB_NAMES),$(LIBS_OBJDIR)/$(name)/.built)
CMAKE_LIB_ARCHIVES = $(foreach name,$(CMAKE_LIB_NAMES),$(wildcard $(LIBS_OBJDIR)/$(name)/*.a))

$(LIBS_OBJDIR)/%/.built: $(LIBSDIR)/%/CMakeLists.txt
	$(if $(SHOW_PROGRESS),@echo "[CMAKE] Configuring $*")
	@mkdir -p $(LIBS_OBJDIR)/$*
	$(Q)cmake -S "$(LIBSDIR)/$*" -B "$(LIBS_OBJDIR)/$*" \
		-DCMAKE_BUILD_TYPE=Release \
		-DBUILD_SHARED_LIBS=OFF \
		-DCMAKE_C_COMPILER=$(CC) \
		-DCMAKE_CXX_COMPILER=$(CXX) \
		"-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=$(CURDIR)/$(LIBS_OBJDIR)/$*" \
		$(CMAKE_QUIET)
	$(if $(SHOW_PROGRESS),@echo "[CMAKE] Building $*")
	$(Q)cmake --build "$(LIBS_OBJDIR)/$*" --config Release $(CMAKE_QUIET)
	@touch $@
	$(if $(SHOW_PROGRESS),@echo "[CMAKE] $* built -> $(LIBS_OBJDIR)/$*/")

.PHONY: cmake-libs
cmake-libs: $(CMAKE_LIB_STAMPS)

# ------------------------------------------------------------------------------
# Generic libs (no CMakeLists.txt): compile .c/.cpp with standard flags
# ------------------------------------------------------------------------------
LIB_OTHER_C_SRCS   := $(foreach dir,$(GENERIC_LIB_DIRS),$(wildcard $(dir)/*.c))
LIB_OTHER_CXX_SRCS := $(foreach dir,$(GENERIC_LIB_DIRS),$(wildcard $(dir)/*.$(CXX_EXT)))
LIB_OTHER_C_OBJS   := $(patsubst $(LIBSDIR)/%.c,$(LIBS_OBJDIR)/%.o,$(LIB_OTHER_C_SRCS))
LIB_OTHER_CXX_OBJS := $(patsubst $(LIBSDIR)/%.$(CXX_EXT),$(LIBS_OBJDIR)/%.o,$(LIB_OTHER_CXX_SRCS))
LIB_OTHER_ALL_OBJS := $(LIB_OTHER_C_OBJS) $(LIB_OTHER_CXX_OBJS)
LIB_OTHER_ALL_DEPS := $(LIB_OTHER_ALL_OBJS:.o=.d)

# ----- Directories -----
OBJDIR := obj
BINDIR := bin

# ----- Source & Dependencies -----
CORE_SRCS   := $(wildcard core/*.$(CXX_EXT)) $(wildcard core/os/$(PLATFORM)/*.$(CXX_EXT)) $(wildcard core/cryptography/*.$(CXX_EXT)) $(wildcard core/utils/*.$(CXX_EXT)) $(wildcard core/network/*.$(CXX_EXT)) $(wildcard core/handshake/*.$(CXX_EXT)) $(wildcard core/session/*.$(CXX_EXT)) $(wildcard core/config/*.$(CXX_EXT))
CLIENT_SRCS := $(wildcard client/*.$(CXX_EXT))
SERVER_SRCS := $(wildcard server/*.$(CXX_EXT))
TEST_SRCS   := $(wildcard tests/*.$(CXX_EXT))

# Client library sources (no main.cpp)
CLIENT_LIB_SRCS := $(filter-out client/main.cpp,$(CLIENT_SRCS))

CORE_OBJS        := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CORE_SRCS))
CLIENT_OBJS      := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CLIENT_SRCS))
CLIENT_LIB_OBJS  := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CLIENT_LIB_SRCS))
SERVER_OBJS      := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(SERVER_SRCS))
TEST_OBJS        := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(TEST_SRCS))

CORE_DEPS   := $(CORE_OBJS:.o=.d)
CLIENT_DEPS := $(CLIENT_OBJS:.o=.d)
SERVER_DEPS := $(SERVER_OBJS:.o=.d)
TEST_DEPS   := $(TEST_OBJS:.o=.d)

# ----- Flags -----
CXXFLAGS := $(STD) $(WARN) $(OPT) $(DEP) $(INCLUDES) $(LIB_INCLUDES) $(LIB_CFLAGS)
CFLAGS   := -O2 -MMD -MP $(INCLUDES) $(LIB_INCLUDES) $(LIB_CFLAGS)

# ==============================================================================
# Compilation Rules
# ==============================================================================

$(LIBS_OBJDIR)/%.o: $(LIBSDIR)/%.c
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CC]  $<")
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(LIBS_OBJDIR)/%.o: $(LIBSDIR)/%.$(CXX_EXT)
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CXX] $< (lib)")
	$(Q)$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/%.o: %.$(CXX_EXT)
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CXX] $<")
	$(Q)$(CXX) $(CXXFLAGS) -c $< -o $@

# ==============================================================================
# Build Targets
# ==============================================================================
.PHONY: libs core client server test run

libs: cmake-libs $(LIB_OTHER_ALL_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Bundled libraries built")

core: libs $(CORE_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Core built")

client: $(BINDIR)/$(CLIENT_TARGET)

server: $(BINDIR)/$(SERVER_TARGET)

test: $(BINDIR)/$(TEST_TARGET)

# Common convenience target
run: run-client

# ----- Executables -----
$(BINDIR)/$(CLIENT_TARGET): libs $(CLIENT_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $(BINDIR)/$(CLIENT_TARGET)")
	$(Q)$(CXX) $(CLIENT_OBJS) $(CORE_OBJS) $(LIB_OTHER_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Built $(BINDIR)/$(CLIENT_TARGET)")

$(BINDIR)/$(SERVER_TARGET): libs $(SERVER_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $(BINDIR)/$(SERVER_TARGET)")
	$(Q)$(CXX) $(SERVER_OBJS) $(CORE_OBJS) $(LIB_OTHER_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Built $(BINDIR)/$(SERVER_TARGET)")

$(BINDIR)/$(TEST_TARGET): libs $(TEST_OBJS) $(CLIENT_LIB_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $(BINDIR)/$(TEST_TARGET)")
	$(Q)$(CXX) $(TEST_OBJS) $(CLIENT_LIB_OBJS) $(CORE_OBJS) $(LIB_OTHER_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Built $(BINDIR)/$(TEST_TARGET)")

# ----- Run Targets -----
.PHONY: run-client run-server run-test

run-client: client
	@echo "[makefile] Running $(BINDIR)/$(CLIENT_TARGET)"
	@./$(BINDIR)/$(CLIENT_TARGET)

run-server: server
	@echo "[makefile] Running $(BINDIR)/$(SERVER_TARGET)"
	@./$(BINDIR)/$(SERVER_TARGET)

FILTER ?=

run-test: test
	@echo "[makefile] Running $(BINDIR)/$(TEST_TARGET)$(if $(FILTER), [filter: $(FILTER)],)"
	@"./$(BINDIR)/$(TEST_TARGET)" $(if $(FILTER),"$(FILTER)",)

# ----- Cleanup Targets -----
.PHONY: clean clean-logs clean-all

clean:
	@echo "[makefile] Removing $(OBJDIR)/ and $(BINDIR)/"
	@rm -rf $(OBJDIR) $(BINDIR)

clean-logs:
	@echo "[makefile] Removing log files"
	@rm -f *.log

clean-all:
	@$(MAKE) clean
	@echo "[makefile] Removing $(LIBS_OBJDIR)/"
	@rm -rf $(LIBS_OBJDIR)
	@$(MAKE) clean-logs

# ----- Help -----
.PHONY: help

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build Targets:"
	@echo "  libs           Build bundled libraries only"
	@echo "  core           Build core library (and libs)"
	@echo "  client         Build $(CLIENT_TARGET) (and all dependencies)"
	@echo "  server         Build $(SERVER_TARGET) (and all dependencies)"
	@echo "  test           Build $(TEST_TARGET) (and all dependencies)"
	@echo ""
	@echo "Run Targets:"
	@echo "  run            Alias for run-client"
	@echo "  run-client     Build and run $(CLIENT_TARGET)"
	@echo "  run-server     Build and run $(SERVER_TARGET)"
	@echo "  run-test       Build and run $(TEST_TARGET) (FILTER=<str> to run matching tests only)"
	@echo ""
	@echo "Cleanup Targets:"
	@echo "  clean          Remove app binaries and objects ($(OBJDIR)/, $(BINDIR)/)"
	@echo "  clean-logs     Remove all log files"
	@echo "  clean-all      Remove everything (app + libs + logs)"
	@echo ""
	@echo "Other:"
	@echo "  help           Show this message"
	@echo ""
	@echo "Bundled libraries:"
	@echo "  cmake: $(if $(CMAKE_LIB_NAMES),$(CMAKE_LIB_NAMES),(none))"
	@echo "  generic: $(if $(GENERIC_LIB_DIRS),$(notdir $(GENERIC_LIB_DIRS)),(none))"

# ----- Include dependencies if present -----
-include $(CORE_DEPS) $(CLIENT_DEPS) $(SERVER_DEPS) $(TEST_DEPS) $(LIB_OTHER_ALL_DEPS)
