SUBMODULE_DIR = cryptography-primitives
CMAKE_BUILD_DIR = $(SUBMODULE_DIR)/build
IPPCP_LIB = $(CMAKE_BUILD_DIR)/.build/RELEASE/lib/libippcp.a
NPROC ?= $(or $(shell nproc 2>/dev/null),4)

.PHONY: build clean

$(SUBMODULE_DIR)/CMakeLists.txt:
	@echo "Initializing cryptography-primitives submodule..."
	git submodule update --init --recursive $(SUBMODULE_DIR)

$(IPPCP_LIB): $(SUBMODULE_DIR)/CMakeLists.txt
	@echo "Building cryptography-primitives..."
	mkdir -p $(CMAKE_BUILD_DIR)
	cd $(CMAKE_BUILD_DIR) && CC=gcc CXX=g++ cmake .. -DARCH=intel64 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-Wno-unused-variable" -DCMAKE_CXX_FLAGS="-Wno-unused-variable"
	cd $(CMAKE_BUILD_DIR) && $(MAKE) all -j$(NPROC)

build: $(IPPCP_LIB)

clean:
	@echo "Cleaning cryptography-primitives..."
	rm -rf $(CMAKE_BUILD_DIR)