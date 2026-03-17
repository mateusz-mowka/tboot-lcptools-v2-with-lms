# lcptools-v2 — Build & Test Guide

## Prerequisites

### Required (all builds)

| Package | Purpose |
|---------|---------|
| **gcc** / **g++** | C99 and C++17 compiler |
| **GNU make** | Build system |
| **OpenSSL** (libssl-dev / openssl-devel, ≥ 1.1; **≥ 3.5 for ML-DSA-87**) | Cryptographic backend & key generation |
| **zlib** (zlib1g-dev / zlib-devel) | Compression support |
| **SafeStringLib** | Safe C string operations (built from `safestringlib/` in the repo root) |

Build SafeStringLib first if it hasn't been built yet:

```sh
make -C ../safestringlib
```

### Required for IPPC backend (`USE_IPPC=1`)

| Package | Purpose |
|---------|---------|
| **Intel IPP Crypto** | IPPC cryptographic backend (built from `ippc/` sub-directory) |

The IPPC library is built automatically when `USE_IPPC=1` is passed to `make`.

### Required for unit tests (Google Test)

| Package | Purpose |
|---------|---------|
| **Google Test** (libgtest-dev) | C++ unit test framework |

Install on Debian/Ubuntu:

```sh
sudo apt install libgtest-dev
```

### Required for functional tests

| Package | Purpose |
|---------|---------|
| **Python 3** (≥ 3.6) | Test runner |
| **PyYAML** | Test matrix configuration parsing |

```sh
pip3 install pyyaml
```

The functional tests invoke `lcp2_crtpollist`, `lcp2_crtpolelt`, `lcp2_crtpol`,
and `lcp2_mlehash`, which may require **root privileges** when accessing
TPM-related paths. Run with `sudo` if needed.

---

## Building

### OpenSSL backend (default)

```sh
make
```

This builds the four LCP tools:
`lcp2_crtpollist`, `lcp2_crtpolelt`, `lcp2_crtpol`, `lcp2_mlehash`.

> **Note:** LMS/HSS signature support is only available with the IPPC
> backend. The OpenSSL backend returns an error for LMS operations.

> **Note:** When signing with LMS, `lcp2_crtpollist` displays an
> interactive confirmation prompt reminding the user about LMS private
> key and state protection. Pass `--force` (or `-f`) to skip the prompt
> (e.g. in scripts or automated test runs).

### IPPC backend

```sh
make USE_IPPC=1
```

When `USE_IPPC=1` is set, the IPPC library under `ippc/` is built
automatically. LMS/HSS signature support is provided natively by IPPC.

### Clean build

```sh
make clean            # OpenSSL artefacts
make USE_IPPC=1 clean # IPPC artefacts
```

### Build output

All binaries and `liblcp.a` are produced in the `lcptools-v2/` directory.

---

## Running Tests

### Unit tests (Google Test)

The unit tests are in `tests/crypto_test.cpp` and cover hashing, RSA,
ECDSA, NULL-parameter guards, and ML-DSA-87. LMS tests require the
IPPC backend.

#### Build and run with OpenSSL backend

```sh
cd tests
make clean && make test
```

#### Build and run with IPPC backend

```sh
cd tests
make clean && make USE_IPPC=1 test
```

The `make test` target compiles the test binary and runs it with
`--gtest_color=yes`. Individual tests can be selected via Google Test
filter syntax:

```sh
./crypto_test --gtest_filter='RsaTest.*'
./crypto_test --gtest_filter='EccTest.SignVerify_ECDSA'
```

### Functional tests (Python)

The functional test suite (`tests/functional_test.py`) is a config-driven
test runner that exercises the full tool chain across both crypto backends.
It reads test definitions from `tests/test_matrix.yaml`.

Test categories:

1. **Sign & Verify** — cross-backend list signing and verification
2. **Show** — `--show` output consistency across backends
3. **Policy** — cross-backend policy creation
4. **Tamper** — negative tests with corrupted lists
5. **Element** — element creation consistency

#### Run all tests (builds both backends automatically)

```sh
cd tests
sudo python3 functional_test.py
```

#### Common options

```sh
# Skip the build step (reuse previously built binaries)
sudo python3 functional_test.py --skip-build

# Skip LMS tests (useful when LMS keys are not available)
sudo python3 functional_test.py --skip-lms

# Provide LMS key base path (without extension)
# Expects {path}.pub, {path}.prv, {path}.aux
sudo python3 functional_test.py --lms-keys /path/to/lms_m24_h20_w4

# Verbose output (shows tool invocations and failure details)
sudo python3 functional_test.py --verbose

# Use a custom test matrix
sudo python3 functional_test.py --config my_matrix.yaml
```

#### Customising the test matrix

Edit `tests/test_matrix.yaml` to add new algorithms, key types, or list
versions. No Python code changes are needed — the runner generates test
cases automatically from the YAML configuration.

The YAML file has five top-level sections:

| Section | Purpose |
|---------|---------|
| `keys` | Key definitions (type, size/curve, source files) |
| `signatures` | Signature configs → cross-backend test matrix |
| `policy` | Policy creation parameters and `--sign` flags |
| `elements` | Element payloads for list creation |
| `tamper` | Negative-test pattern for corrupted lists |

##### Adding a new signature algorithm

1. **Define a key** under `keys`:

   ```yaml
   keys:
     my_rsa4096:
       type: rsa
       bits: 4096
   ```

   Supported key types and their fields:

   | Type | Required fields |
   |------|-----------------|
   | `rsa` | `bits` (e.g. 2048, 3072) |
   | `ec` | `curve` (e.g. secp256k1, secp384r1) |
   | `mldsa` | `openssl`, `ld_library_path` (keys generated externally via `openssl genpkey -algorithm ML-DSA-87`) |
   | `lms` | `copy_from: {pub, priv, aux}` source file paths (relative to `lcptools-v2/`, or absolute via `--lms-keys`) |

2. **Add a signature entry** under `signatures`:

   ```yaml
   signatures:
     - sigalg: rsa
       hashalg: sha256
       key: my_rsa4096
       list_versions: ["0x200", "0x201", "0x300"]
   ```

   Each entry generates a full cross-backend matrix
   (create × sign × verify) for every listed version.

   Optional fields:

   - `supported_backends: [ippc]` — restrict which backends can
     sign/verify (defaults to all).
   - `skip_flag: skip_lms` — ties this config to a `--skip-*` CLI flag
     so it can be skipped at runtime.

3. **Add policy sign flags** (if the algorithm supports `lcp2_crtpol`):

   ```yaml
   policy:
     sign_flags:
       rsa: [--sign, rsa-4096-sha256]
   ```

   Algorithms listed in `policy.skip_sigalgs` (e.g. `mldsa`, `lms`)
   are excluded from policy creation tests.

##### Adding a new list version

Append the version string to `list_versions` in the relevant
`signatures` entry:

```yaml
- sigalg: ecdsa
  hashalg: sha256
  key: ec256
  list_versions: ["0x200", "0x201", "0x300", "0x400"]
```

##### Adding a new element type

Append an entry under `elements`. The first element is also used as the
payload when creating policy lists in other tests:

```yaml
elements:
  - name: sbios_sha384
    type: sbios
    hashalg: sha384
    hash: "aa bb cc ..."
```

##### Changing the tamper test source

Update `tamper.source_pattern` to match a different signed list glob:

```yaml
tamper:
  source_pattern: "signed_rsapss_sha256_0x300_*.lst"
```

---

## Directory Layout (tests)

```
tests/
├── Makefile              # Google Test build rules
├── crypto_test.cpp       # Unit tests
├── functional_test.py    # Functional test runner
├── test_matrix.yaml      # Test matrix configuration
└── functional_work/      # Working directory (created at runtime)
```
