# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# Grand Unified Makefile for tboot
#

# define ROOTDIR
export ROOTDIR=$(CURDIR)

# import global build config
include Config.mk

# (txt-test is not included because it requires pathing to Linux src)

# Conditionally set SUBDIRS based on USE_IPPC
ifdef USE_IPPC
SUBDIRS := tboot safestringlib lcptools-v2/ippc lcptools-v2 tb_polgen utils docs
$(info Building with IPPC support enabled)
else
SUBDIRS := tboot safestringlib lcptools-v2 tb_polgen utils docs
endif

#
# build rules
#

#
#    manifest
#
.PHONY: manifest

dist-lcptools-v2/ippc:
	$(MAKE) -C lcptools-v2/ippc dist
manifest : build
	lcptools/lcp_mlehash tboot/tboot.gz > mle_file
	lcptools/lcp_crtpol -t 0 -m mle_file -o policy_file


#
#    install
#
install :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) install-$$i; \
	done

install-% :
	$(MAKE) -C $* install


#
#    build
#
build :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) build-$$i; \
	done

build-% :
	$(MAKE) -C $* build


#
#    dist
#
dist : $(patsubst %,dist-%,$(SUBDIRS))
	[ -d $(DISTDIR) ] || $(INSTALL_DIR) $(DISTDIR)
	$(INSTALL_DATA) COPYING $(DISTDIR)
	$(INSTALL_DATA) README.md $(DISTDIR)

dist-% :
	$(MAKE) -C $* dist


#
#    world
#
# build tboot and tools, and place them in the install directory.
# 'make install' should then copy them to the normal system directories
.PHONY: world
world :
	$(MAKE) clean
#
# Explicit rule for subdir with slash (for recursive make)
	$(MAKE) -C lcptools-v2/ippc build
	$(MAKE) dist
build-lcptools-v2/ippc:
	$(MAKE) -C lcptools-v2/ippc build


#
#    clean
#
clean :
	rm -f *~ include/*~ docs/*~
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) clean-$$i; \
	done

clean-% :
	$(MAKE) -C $* clean


#
#    distclean
#
distclean :
	@set -e; for i in $(SUBDIRS); do \
		$(MAKE) distclean-$$i; \
	done

distclean-% :
	$(MAKE) -C $* distclean


#
#    mrproper
#
# Linux name for GNU distclean
mrproper : distclean


#
#    help
#
.PHONY: help
help :
	@echo 'Installation targets:'
	@echo '  install          - build and install everything'
	@echo '  install-*        - build and install the * module'
	@echo ''
	@echo 'Building targets:'
	@echo '  dist             - build and install everything into local dist directory'
	@echo '  world            - clean everything'
	@echo ''
	@echo 'Cleaning targets:'
	@echo '  clean            - clean tboot and tools'
	@echo '  distclean        - clean and local downloaded files'
	@echo ''
	@echo '  uninstall        - attempt to remove installed tools'
	@echo '                     (use with extreme care!)'

#
#    uninstall
#
# Use this target with extreme care!
.PHONY: uninstall
uninstall : D=$(DESTDIR)
uninstall :
	rm -rf $(D)/boot/tboot*
