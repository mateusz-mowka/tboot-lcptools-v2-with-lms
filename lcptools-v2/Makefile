# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# lcptools makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk


LCP2_TARGETS := \
	lcp2_mlehash    \
	lcp2_crtpol    \
	lcp2_crtpollist \
	lcp2_crtpolelt

# Build IPPC library if USE_IPPC is set
ifdef USE_IPPC
IPPC_DEP := ippc_lib
else
IPPC_DEP :=
endif

.PHONY: ippc_lib
ippc_lib:
	$(MAKE) -C ippc build

lcp2 : $(IPPC_DEP) $(LCP2_TARGETS)


#
# universal rules
#

build : $(IPPC_DEP) $(LCP2_TARGETS)


dist : install


install :
	@set -e; for i in  $(LCP2_TARGETS);\
	do \
		$(MAKE) DISTDIR=$(DISTDIR) INST_TARGET=$(DISTDIR)/usr/sbin/$$i do_install; \
	done

.PHONY: do_install
do_install : $(INST_TARGET)

$(INST_TARGET) : $(notdir $(INST_TARGET))
	[ -d $(DISTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DISTDIR)/usr/sbin
	$(INSTALL_PROG) -t $(DISTDIR)/usr/sbin $^


clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(LCP2_TARGETS)

mrproper : clean


distclean : clean

#
# dependencies
#

LDFLAGS += -L.


# LCP v2

POLELT_PLUGINS := custom_elt.o mle_elt_legacy.o pconf_legacy.o sbios_elt.o stm_elt.o pconf2_elt.o mle_elt.o

LCP2_LIB := liblcp.a

LIBS += -lcrypto -llcp -lz $(ROOTDIR)/safestringlib/libsafestring.a

# Add IPPC library if USE_IPPC is set
ifdef USE_IPPC
LIBS += -L$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/build/.build/RELEASE/lib -lippcp
LDFLAGS += -Wl,-rpath,$(ROOTDIR)/lcptools-v2/ippc/cryptography-primitives/build/.build/RELEASE/lib
endif


ifdef USE_IPPC
LCP_CRYPTO_OBJ := crypto_ippc.o
else
LCP_CRYPTO_OBJ := crypto_OpenSSL.o
endif

$(LCP2_LIB) : pol.o poldata.o pollist2.o pollist2_1.o polelt.o lcputils.o hash.o pollist1.o crypto.o $(LCP_CRYPTO_OBJ)
	$(AR) rc $@ $^

lcp2_crtpolelt : crtpolelt.o $(POLELT_PLUGINS) $(LCP2_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

lcp2_crtpollist : crtpollist.o $(POLELT_PLUGINS) $(LCP2_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

lcp2_crtpol : crtpol.o $(POLELT_PLUGINS) $(LCP2_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

lcp2_mlehash : mlehash.o $(LCP2_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

#
# implicit rules
#

HDRS := $(wildcard $(ROOTDIR)/include/*.h) $(wildcard $(CURDIR)/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DNO_TBOOT_LOGLVL -c $< -o $@
