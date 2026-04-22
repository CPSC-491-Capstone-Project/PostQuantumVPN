# ----- Project -----
CLIENT_TARGET := PQ_VPN_Client
SERVER_TARGET := PQ_VPN_Server
TEST_TARGET := test_runner
CXX := g++-12
CC  := gcc
#CXX := clang++
WARN := -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion #-Werror
STD := -std=c++23
OPT := -O2
DEP := -MMD -MP
INCLUDES := -Iclient -Iserver -Itests -Icore -Icore/os/$(PLATFORM) -Icore/cryptography -Icore/utils -Icore/network -Icore/handshake -Icore/session

# ----- Verbosity -----
# V=low (errors only), V=medium (default, file-level), V=high (everything)
V := medium

ifeq ($(V),low)
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS :=
else ifeq ($(V),high)
  Q :=
  CMAKE_QUIET :=
  SHOW_PROGRESS := 1
else
  # medium (default)
  Q := @
  CMAKE_QUIET := > /dev/null 2>&1
  SHOW_PROGRESS := 1
endif

# ----- File Extensions -----
CXX_EXT := cpp

# ----- makefile Config -----
MAKEFLAGS += --no-print-directory

# ----- Default target  -----
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
ifeq ($(PLATFORM),macos)
	OPENSSL_PREFIX := $(shell brew --prefix openssl 2>/dev/null)
	ifdef OPENSSL_PREFIX
		LIB_CFLAGS := -I$(OPENSSL_PREFIX)/include
		LDFLAGS := -L$(OPENSSL_PREFIX)/lib -lssl -lcrypto
	else
		OPENSSL_FOUND := no
	endif
else ifeq ($(PLATFORM),linux)
	OPENSSL_CHECK := $(shell pkg-config --exists openssl 2>/dev/null && echo yes || echo no)
	ifeq ($(OPENSSL_CHECK),yes)
		LIB_CFLAGS := $(shell pkg-config --cflags openssl)
		LDFLAGS := $(shell pkg-config --libs openssl)
	else
		OPENSSL_FOUND := no
	endif
else ifeq ($(PLATFORM),windows)
	OPENSSL_CHECK := $(shell where openssl >nul 2>&1 && echo yes || echo no)
	ifeq ($(OPENSSL_CHECK),yes)
		LIB_CFLAGS :=
		LDFLAGS := -lssl -lcrypto -lws2_32
	else
		OPENSSL_FOUND := no
	endif
endif

ifeq ($(OPENSSL_FOUND),no)
$(info )
$(info  ERROR: OpenSSL development libraries not found.)
$(info  Please install OpenSSL and ensure headers are in your include path.)
$(info )
$(error OpenSSL is required to build this project)
endif

# ==============================================================================
# Bundled Libraries
# ==============================================================================
LIBSDIR     := libs
LIBS_OBJDIR := $(LIBSDIR)/obj
 
# Auto-discover all lib subdirectories (excluding obj/)
LIB_SUBDIRS  := $(shell find $(LIBSDIR) -mindepth 1 -maxdepth 1 -type d ! -name obj)
LIB_INCLUDES := $(addprefix -I,$(LIB_SUBDIRS))
 
# Split libs into cmake-based and generic (plain source)
CMAKE_LIB_DIRS  := $(foreach dir,$(LIB_SUBDIRS),$(if $(wildcard $(dir)/CMakeLists.txt),$(dir)))
GENERIC_LIB_DIRS := $(filter-out $(CMAKE_LIB_DIRS),$(LIB_SUBDIRS))

# ------------------------------------------------------------------------------
# cmake-based libs: each produces a .a in libs/obj/<libname>/
#
# Convention:
#   Source dir:  libs/<libname>/          (must contain CMakeLists.txt)
#   Build dir:   libs/obj/<libname>/      (cmake build tree)
#   Output:      libs/obj/<libname>/*.a   (static library archive)
#
# The makefile calls cmake configure + build once. cmake handles all
# platform-specific flags, SIMD detection, assembly selection, etc.
# ------------------------------------------------------------------------------
CMAKE_LIB_NAMES   := $(foreach dir,$(CMAKE_LIB_DIRS),$(notdir $(dir)))
CMAKE_LIB_BUILDS  := $(foreach name,$(CMAKE_LIB_NAMES),$(LIBS_OBJDIR)/$(name))
CMAKE_LIB_STAMPS  := $(foreach name,$(CMAKE_LIB_NAMES),$(LIBS_OBJDIR)/$(name)/.built)
 
# Collect all .a files from cmake builds (resolved after build via wildcard in link step)
# We use a function to find them at link time since cmake chooses the name
CMAKE_LIB_ARCHIVES = $(foreach name,$(CMAKE_LIB_NAMES),$(wildcard $(LIBS_OBJDIR)/$(name)/*.a))
 
# Build rule for each cmake lib: configure + build, then stamp
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
	$(Q)cmake --build $(LIBS_OBJDIR)/$* --config Release $(CMAKE_QUIET)
	@touch $@
	$(if $(SHOW_PROGRESS),@echo "[CMAKE] $* built -> $(LIBS_OBJDIR)/$*/")
 
# Phony target so "make libs" can depend on all cmake stamps
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
CORE_SRCS   := $(wildcard core/*.$(CXX_EXT)) $(wildcard core/os/$(PLATFORM)/*.$(CXX_EXT)) $(wildcard core/cryptography/*.$(CXX_EXT)) $(wildcard core/utils/*.$(CXX_EXT)) $(wildcard core/network/*.$(CXX_EXT)) $(wildcard core/handshake/*.$(CXX_EXT)) $(wildcard core/session/*.$(CXX_EXT))
CLIENT_SRCS := $(wildcard client/*.$(CXX_EXT))
SERVER_SRCS := $(wildcard server/*.$(CXX_EXT))
TEST_SRCS   := $(wildcard tests/*.$(CXX_EXT))

# Client library sources (no main.cpp) — linked into the test binary so
# client_tests.hpp can exercise the Client class.
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
CFLAGS   := -O2 -MMD -MP $(INCLUDES) $(LIB_INCLUDES)

# ==============================================================================
# Compilation Rules
# ==============================================================================
 
# ----- Generic bundled libs: C -----
$(LIBS_OBJDIR)/%.o: $(LIBSDIR)/%.c
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CC]  $<")
	$(Q)$(CC) $(CFLAGS) -c $< -o $@
 
# ----- Generic bundled libs: C++ -----
$(LIBS_OBJDIR)/%.o: $(LIBSDIR)/%.$(CXX_EXT)
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CXX] $< (lib)")
	$(Q)$(CXX) $(CXXFLAGS) -c $< -o $@
 
# ----- Project C++ objects -----
$(OBJDIR)/%.o: %.$(CXX_EXT)
	@mkdir -p $(dir $@)
	$(if $(SHOW_PROGRESS),@echo "[CXX] $<")
	$(Q)$(CXX) $(CXXFLAGS) -c $< -o $@

# ==============================================================================
# Build Targets
# ==============================================================================
.PHONY: libs core client server test
 
libs: cmake-libs $(LIB_OTHER_ALL_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Bundled libraries built")
 
core: libs $(CORE_OBJS)
	$(if $(SHOW_PROGRESS),@echo "[makefile] Core built")
 
client: $(BINDIR)/$(CLIENT_TARGET)
 
server: $(BINDIR)/$(SERVER_TARGET)
 
test: $(BINDIR)/$(TEST_TARGET)
 
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
	@echo "  run-client     Build and run $(CLIENT_TARGET)"
	@echo "  run-server     Build and run $(SERVER_TARGET)"
	@echo "  run-test       Build and run $(TEST_TARGET)  (FILTER=<str> to run matching tests only)"
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



