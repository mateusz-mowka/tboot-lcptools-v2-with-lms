# Google Test Makefile for crypto module tests

ROOTDIR ?= $(CURDIR)/../..
include $(ROOTDIR)/Config.mk

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -g -I$(ROOTDIR)/include \
            -I$(ROOTDIR)/lcptools-v2 \
            -I$(ROOTDIR)/safestringlib/include \
            -DNO_TBOOT_LOGLVL

# Add IPPC includes and defines when building with IPPC
ifdef USE_IPPC
CXXFLAGS += -DUSE_IPPC -DIPPCP_PREVIEW_LMS -DIPPCP_PREVIEW_ML_DSA \
            -I$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/include \
            -I$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/build/.build/RELEASE/include
endif

# Link against liblcp.a from parent dir, plus gtest, crypto, safestring
LDFLAGS  := -L$(ROOTDIR)/lcptools-v2 \
            -L$(ROOTDIR)/safestringlib

ifdef USE_IPPC
LDFLAGS  += -L$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/build/.build/RELEASE/lib \
            -Wl,-rpath,$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/build/.build/RELEASE/lib
endif



LIBS     := -llcp -lcrypto -lz -lsafestring -lgtest -lgtest_main -lpthread

ifdef USE_IPPC
LIBS     += -lippcp
endif

TEST_SRCS := crypto_test.cpp
TEST_BINS := $(TEST_SRCS:.cpp=)

.PHONY: all clean test

all: $(TEST_BINS)

crypto_test: crypto_test.cpp $(ROOTDIR)/lcptools-v2/liblcp.a
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $< $(LIBS) -o $@

test: $(TEST_BINS)
	@echo "=== Running crypto unit tests ==="
	@for t in $(TEST_BINS); do ./$$t --gtest_color=yes || exit 1; done

clean:
	rm -f $(TEST_BINS) *.o *~
