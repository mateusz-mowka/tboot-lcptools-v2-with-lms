SUBMODULE_DIR = cryptography-primitives
CMAKE_BUILD_DIR = $(SUBMODULE_DIR)/build
CMAKE_INSTALL_PREFIX ?= $(DESTDIR)/usr/local
IPPCP_LIB = $(CMAKE_BUILD_DIR)/.build/RELEASE/lib/libippcp.a

.PHONY: install clean distclean dist

$(SUBMODULE_DIR)/CMakeLists.txt:
	@echo "Initializing cryptography-primitives submodule..."
	git submodule update --init --recursive $(SUBMODULE_DIR)

$(IPPCP_LIB): $(SUBMODULE_DIR)/CMakeLists.txt
	@echo "Building cryptography-primitives..."
	mkdir -p $(CMAKE_BUILD_DIR)
	cd $(CMAKE_BUILD_DIR) && CC=gcc CXX=g++ cmake .. \
		-DARCH=intel64 \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_INSTALL_PREFIX=$(CMAKE_INSTALL_PREFIX) \
		-DCMAKE_C_FLAGS="-Wno-unused-variable" \
		-DCMAKE_CXX_FLAGS="-Wno-unused-variable"
	cd $(CMAKE_BUILD_DIR) && $(MAKE) all -j4

build: $(IPPCP_LIB)

install: build
	@echo "Installing cryptography-primitives..."
	cd $(CMAKE_BUILD_DIR) && $(MAKE) install

clean:
	@echo "Cleaning cryptography-primitives..."
	rm -rf $(CMAKE_BUILD_DIR)

distclean: clean

dist: build