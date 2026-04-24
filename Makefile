# Project
CLIENT_TARGET := PQ_VPN_Client
SERVER_TARGET := PQ_VPN_Server
TEST_TARGET := test_runner
CXX := g++
CC := gcc
WARN := -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
STD := -std=c++23
OPT := -O2
DEP := -MMD -MP
INCLUDES := -Iclient -Iserver -Itests -Icore \
  -Icore/os/$(PLATFORM) -Icore/cryptography -Icore/utils \
  -Icore/network -Icore/handshake -Icore/session -Icore/config

CXX_EXT := cpp
MAKEFLAGS += --no-print-directory
.DEFAULT_GOAL := help

# Verbosity (V=low|medium|high, default=medium)
V ?= medium

ifeq ($(V),high)
  Q :=
  CMAKE_QUIET :=
  SHOW_PROGRESS := 1
else ifeq ($(V),low)
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS :=
else
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS := 1
endif

# Platform Detection
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

# OpenSSL Detection
# OPENSSL_FOUND starts as "no". Build targets depend on require-openssl which
# errors if it stays "no", so clean and help are never blocked.
LIB_CFLAGS :=
LDFLAGS :=
OPENSSL_FOUND := no
OPENSSL_VERSION :=

# Read version string from opensslv.h - no binary required
openssl_hdr_ver = $(shell grep 'OPENSSL_VERSION_STR' "$(1)/include/openssl/opensslv.h" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

# Returns "yes" if version >= 3.5
openssl_ok = $(shell \
  maj=$$(printf '%s' "$(1)" | cut -d. -f1); \
  min=$$(printf '%s' "$(1)" | cut -d. -f2); \
  if [ -n "$$maj" ] && [ -n "$$min" ] && \
     { [ "$$maj" -gt 3 ] 2>/dev/null || \
       { [ "$$maj" -eq 3 ] 2>/dev/null && [ "$$min" -ge 5 ] 2>/dev/null; }; }; \
  then echo yes; else echo no; fi)

# macOS - Homebrew
ifeq ($(PLATFORM),macos)
  OPENSSL_PREFIX ?= $(or \
    $(shell brew --prefix openssl@3.5 2>/dev/null), \
    $(shell brew --prefix openssl 2>/dev/null))
  ifneq ($(strip $(OPENSSL_PREFIX)),)
    OPENSSL_VERSION := $(call openssl_hdr_ver,$(OPENSSL_PREFIX))
    ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
      LDFLAGS += -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
      OPENSSL_FOUND := yes
    endif
  endif

# Linux - Arch, Debian, Fedora, ect
else ifeq ($(PLATFORM),linux)
  ifneq ($(strip $(OPENSSL_PREFIX)),)
    OPENSSL_VERSION := $(call openssl_hdr_ver,$(OPENSSL_PREFIX))
    ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
      ifneq ($(wildcard $(OPENSSL_PREFIX)/lib64),)
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib64
      else
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
      endif
      LDFLAGS += -lssl -lcrypto
      OPENSSL_FOUND := yes
    endif
  else
    # 1. pkg-config (works on Arch, Debian, Fedora, etc.)
    OPENSSL_VERSION := $(shell pkg-config --modversion openssl 2>/dev/null)
    ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += $(shell pkg-config --cflags openssl 2>/dev/null)
      LDFLAGS += $(shell pkg-config --libs openssl 2>/dev/null)
      OPENSSL_FOUND := yes
    else
      # 2. Conventional manual install fallback
      ifneq ($(wildcard /usr/local/openssl-3.5/include/openssl/opensslv.h),)
        OPENSSL_PREFIX := /usr/local/openssl-3.5
        OPENSSL_VERSION := $(call openssl_hdr_ver,$(OPENSSL_PREFIX))
        ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
          LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
          ifneq ($(wildcard $(OPENSSL_PREFIX)/lib64),)
            LDFLAGS += -L$(OPENSSL_PREFIX)/lib64 -Wl,-rpath,$(OPENSSL_PREFIX)/lib64
          else
            LDFLAGS += -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
          endif
          LDFLAGS += -lssl -lcrypto
          OPENSSL_FOUND := yes
        endif
      endif
    endif
  endif

# Windows - MinGW / MSYS2 / Cygwin
else ifeq ($(PLATFORM),windows)
  ifneq ($(strip $(OPENSSL_PREFIX)),)
    OPENSSL_VERSION := $(call openssl_hdr_ver,$(OPENSSL_PREFIX))
    ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
      LIB_CFLAGS += -I$(OPENSSL_PREFIX)/include
      LDFLAGS += -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto -lws2_32
      OPENSSL_FOUND := yes
    endif
  else
    OPENSSL_VERSION := $(shell openssl version 2>/dev/null | awk '{print $$2}')
    ifeq ($(call openssl_ok,$(OPENSSL_VERSION)),yes)
      LDFLAGS += -lssl -lcrypto -lws2_32
      OPENSSL_FOUND := yes
    endif
  endif
endif

# Guard: build targets depend on this, clean/help do not.
# The ifeq is evaluated at parse time so the recipe is either present (fails)
# or absent (no-op) depending on detection results above.
.PHONY: require-openssl
require-openssl:
ifeq ($(OPENSSL_FOUND),no)
	@echo ""
	@echo "ERROR: OpenSSL >= 3.5 is required but was not found."
	@echo "  Detected : $(if $(strip $(OPENSSL_VERSION)),$(OPENSSL_VERSION),(not found))"
	@echo ""
	@echo "  Linux  - pkg-config:  export PKG_CONFIG_PATH=/path/to/openssl-3.5/lib64/pkgconfig"
	@echo "  Linux  - prefix:      export OPENSSL_PREFIX=/path/to/openssl-3.5 && make <target>"
	@echo "  macOS  - Homebrew:    brew install openssl@3.5"
	@echo "  Windows - prefix:     set OPENSSL_PREFIX=C:\\openssl-3.5 && make <target>"
	@echo ""
	@exit 1
endif

# Bundled Libraries
LIBSDIR := libs
LIBS_OBJDIR := $(LIBSDIR)/obj

LIB_SUBDIRS := $(shell find $(LIBSDIR) -mindepth 1 -maxdepth 1 -type d ! -name obj 2>/dev/null)
LIB_INCLUDES := $(addprefix -I,$(LIB_SUBDIRS))

CMAKE_LIB_DIRS := $(foreach d,$(LIB_SUBDIRS),$(if $(wildcard $(d)/CMakeLists.txt),$(d)))
GENERIC_LIB_DIRS := $(filter-out $(CMAKE_LIB_DIRS),$(LIB_SUBDIRS))

CMAKE_LIB_NAMES := $(foreach d,$(CMAKE_LIB_DIRS),$(notdir $(d)))
CMAKE_LIB_STAMPS := $(foreach n,$(CMAKE_LIB_NAMES),$(LIBS_OBJDIR)/$(n)/.built)
CMAKE_LIB_ARCHIVES = $(foreach n,$(CMAKE_LIB_NAMES),$(wildcard $(LIBS_OBJDIR)/$(n)/*.a))

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
	$(if $(SHOW_PROGRESS),@echo "[CMAKE] $* -> $(LIBS_OBJDIR)/$*/")

.PHONY: cmake-libs
cmake-libs: require-openssl $(CMAKE_LIB_STAMPS)

LIB_C_SRCS := $(foreach d,$(GENERIC_LIB_DIRS),$(wildcard $(d)/*.c))
LIB_CXX_SRCS := $(foreach d,$(GENERIC_LIB_DIRS),$(wildcard $(d)/*.$(CXX_EXT)))
LIB_C_OBJS := $(patsubst $(LIBSDIR)/%.c,$(LIBS_OBJDIR)/%.o,$(LIB_C_SRCS))
LIB_CXX_OBJS := $(patsubst $(LIBSDIR)/%.$(CXX_EXT),$(LIBS_OBJDIR)/%.o,$(LIB_CXX_SRCS))
LIB_ALL_OBJS := $(LIB_C_OBJS) $(LIB_CXX_OBJS)
LIB_ALL_DEPS := $(LIB_ALL_OBJS:.o=.d)

# Application Sources & Objects
OBJDIR := obj
BINDIR := bin

CORE_SRCS := \
  $(wildcard core/*.$(CXX_EXT)) \
  $(wildcard core/os/$(PLATFORM)/*.$(CXX_EXT)) \
  $(wildcard core/cryptography/*.$(CXX_EXT)) \
  $(wildcard core/utils/*.$(CXX_EXT)) \
  $(wildcard core/network/*.$(CXX_EXT)) \
  $(wildcard core/handshake/*.$(CXX_EXT)) \
  $(wildcard core/session/*.$(CXX_EXT)) \
  $(wildcard core/config/*.$(CXX_EXT))

CLIENT_SRCS := $(wildcard client/*.$(CXX_EXT))
SERVER_SRCS := $(wildcard server/*.$(CXX_EXT))
TEST_SRCS := $(wildcard tests/*.$(CXX_EXT))
CLIENT_LIB_SRCS := $(filter-out client/main.cpp,$(CLIENT_SRCS))

CORE_OBJS := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CORE_SRCS))
CLIENT_OBJS := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CLIENT_SRCS))
CLIENT_LIB_OBJS := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(CLIENT_LIB_SRCS))
SERVER_OBJS := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(SERVER_SRCS))
TEST_OBJS := $(patsubst %.$(CXX_EXT),$(OBJDIR)/%.o,$(TEST_SRCS))

CORE_DEPS := $(CORE_OBJS:.o=.d)
CLIENT_DEPS := $(CLIENT_OBJS:.o=.d)
SERVER_DEPS := $(SERVER_OBJS:.o=.d)
TEST_DEPS := $(TEST_OBJS:.o=.d)

CXXFLAGS := $(STD) $(WARN) $(OPT) $(DEP) $(INCLUDES) $(LIB_INCLUDES) $(LIB_CFLAGS)
CFLAGS := -O2 -MMD -MP $(INCLUDES) $(LIB_INCLUDES) $(LIB_CFLAGS)

# Compilation Rules
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

# Build Targets
.PHONY: libs core client server test run

libs: cmake-libs $(LIB_ALL_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Libraries built")

core: libs $(CORE_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Core built")

client: require-openssl $(BINDIR)/$(CLIENT_TARGET)
server: require-openssl $(BINDIR)/$(SERVER_TARGET)
test: require-openssl $(BINDIR)/$(TEST_TARGET)
run: run-client

$(BINDIR)/$(CLIENT_TARGET): libs $(CLIENT_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $@")
	$(Q)$(CXX) $(CLIENT_OBJS) $(CORE_OBJS) $(LIB_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)

$(BINDIR)/$(SERVER_TARGET): libs $(SERVER_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $@")
	$(Q)$(CXX) $(SERVER_OBJS) $(CORE_OBJS) $(LIB_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)

$(BINDIR)/$(TEST_TARGET): libs $(TEST_OBJS) $(CLIENT_LIB_OBJS) $(CORE_OBJS)
	@mkdir -p $(BINDIR)
	$(if $(SHOW_PROGRESS),@echo "[LINK] $@")
	$(Q)$(CXX) $(TEST_OBJS) $(CLIENT_LIB_OBJS) $(CORE_OBJS) $(LIB_ALL_OBJS) $(CMAKE_LIB_ARCHIVES) -o $@ $(LDFLAGS)

# Run Targets
.PHONY: run-client run-server run-test
FILTER ?=

run-client: client
	@echo "[run] $(BINDIR)/$(CLIENT_TARGET)"
	@./$(BINDIR)/$(CLIENT_TARGET)

run-server: server
	@echo "[run] $(BINDIR)/$(SERVER_TARGET)"
	@./$(BINDIR)/$(SERVER_TARGET)

run-test: test
	@echo "[run] $(BINDIR)/$(TEST_TARGET)$(if $(FILTER), [filter: $(FILTER)],)"
	@"./$(BINDIR)/$(TEST_TARGET)" $(if $(FILTER),"$(FILTER)",)

# Cleanup
.PHONY: clean clean-logs clean-all

clean:
	@echo "[clean] Removing $(OBJDIR)/ $(BINDIR)/"
	@rm -rf $(OBJDIR) $(BINDIR)

clean-logs:
	@echo "[clean] Removing log files"
	@rm -f *.log

clean-all:
	@$(MAKE) clean
	@echo "[clean] Removing $(LIBS_OBJDIR)/"
	@rm -rf $(LIBS_OBJDIR)
	@$(MAKE) clean-logs

# Help
.PHONY: help
help:
	@echo "Usage: make [V=low|medium|high] <target>"
	@echo ""
	@echo "Build:"
	@echo "  libs         Build bundled libraries"
	@echo "  core         Build core (includes libs)"
	@echo "  client       Build $(CLIENT_TARGET)"
	@echo "  server       Build $(SERVER_TARGET)"
	@echo "  test         Build $(TEST_TARGET)"
	@echo ""
	@echo "Run:"
	@echo "  run          Alias for run-client"
	@echo "  run-client   Build and run $(CLIENT_TARGET)"
	@echo "  run-server   Build and run $(SERVER_TARGET)"
	@echo "  run-test     Build and run $(TEST_TARGET)  (FILTER=<str>)"
	@echo ""
	@echo "Clean:"
	@echo "  clean        Remove $(OBJDIR)/ and $(BINDIR)/"
	@echo "  clean-logs   Remove log files"
	@echo "  clean-all    Remove everything including $(LIBS_OBJDIR)/"
	@echo ""
	@echo "Environment:"
	@echo "  Platform : $(PLATFORM)"
	@echo "  OpenSSL  : $(if $(filter yes,$(OPENSSL_FOUND)),$(OPENSSL_VERSION) [OK],$(if $(strip $(OPENSSL_VERSION)),$(OPENSSL_VERSION) [REQUIRES >= 3.5],(not found - install OpenSSL 3.5+)))"
	@echo "  Libs     : cmake=$(if $(CMAKE_LIB_NAMES),$(CMAKE_LIB_NAMES),(none))  generic=$(if $(GENERIC_LIB_DIRS),$(notdir $(GENERIC_LIB_DIRS)),(none))"

-include $(CORE_DEPS) $(CLIENT_DEPS) $(SERVER_DEPS) $(TEST_DEPS) $(LIB_ALL_DEPS)
