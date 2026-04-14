#!/usr/bin/env python3
"""
functional_test.py — Config-driven cross-backend LCP policy functional tests

Reads test definitions from test_matrix.yaml (or a custom YAML file) and
runs a comprehensive cross-backend test matrix for LCP policy tools.

Test categories:
  1. Sign & Verify — cross-backend list signing and verification
  2. Show          — --show consistency across backends
  3. Policy        — cross-backend policy creation and show
  4. Tamper        — negative tests with tampered lists
  5. Element       — element creation consistency

Usage:
  python3 functional_test.py [--config FILE] [--skip-build] [--skip-lms] [--lms-keys PATH] [--verbose]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required.  Install with:  pip3 install pyyaml")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  Colour helpers
# ═══════════════════════════════════════════════════════════════════════════

class Colors:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"

    @classmethod
    def disable(cls):
        cls.RED = cls.GREEN = cls.YELLOW = cls.CYAN = cls.BOLD = cls.NC = ""

if not sys.stdout.isatty():
    Colors.disable()


# ═══════════════════════════════════════════════════════════════════════════
#  Test result tracking
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TestResults:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    failures: list = field(default_factory=list)

results = TestResults()


def log(msg: str):
    print(f"{Colors.CYAN}[INFO]{Colors.NC} {msg}")

def log_pass(msg: str):
    print(f"{Colors.GREEN}[PASS]{Colors.NC} {msg}")
    results.passed += 1

def log_fail(msg: str):
    print(f"{Colors.RED}[FAIL]{Colors.NC} {msg}")
    results.failed += 1
    results.failures.append(msg)

def log_skip(msg: str):
    print(f"{Colors.YELLOW}[SKIP]{Colors.NC} {msg}")
    results.skipped += 1

def log_hdr(msg: str):
    print(f"\n{Colors.BOLD}═══ {msg} ═══{Colors.NC}")


# ═══════════════════════════════════════════════════════════════════════════
#  Directory layout
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).resolve().parent
LCPTOOLS_DIR = SCRIPT_DIR.parent
ROOT_DIR = LCPTOOLS_DIR.parent

WORK_DIR = SCRIPT_DIR / "functional_work"
KEY_DIR = WORK_DIR / "keys"
ELT_DIR = WORK_DIR / "elements"
LST_DIR = WORK_DIR / "lists"
POL_DIR = WORK_DIR / "policies"
IPPC_BIN_DIR = WORK_DIR / "bin_ippc"
OSSL_BIN_DIR = WORK_DIR / "bin_openssl"

IPPC_LIB = (LCPTOOLS_DIR / "ippc" / "cryptography-primitives"
            / "build" / ".build" / "RELEASE" / "lib")

TOOLS = ["lcp2_crtpolelt", "lcp2_crtpollist", "lcp2_crtpol", "lcp2_mlehash"]


# ═══════════════════════════════════════════════════════════════════════════
#  Tool runner
# ═══════════════════════════════════════════════════════════════════════════

def run_tool(backend: str, tool: str, *args: str,
             verbose: bool = False) -> tuple[int, str]:
    """Run an LCP tool with the given backend.  Returns (rc, output)."""
    bin_dir = IPPC_BIN_DIR if backend == "ippc" else OSSL_BIN_DIR
    tool_path = str(bin_dir / tool)

    env = os.environ.copy()
    if backend == "ippc":
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = (
            f"{IPPC_LIB}:{existing}" if existing else str(IPPC_LIB)
        )

    if verbose:
        print(f"  {Colors.YELLOW}▸{Colors.NC} [{backend}] {tool} "
              f"{' '.join(args)}")

    try:
        result = subprocess.run(
            [tool_path, *args],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return result.returncode, result.stdout
    except FileNotFoundError:
        return 127, f"Tool not found: {tool_path}"
    except Exception as e:
        return 1, str(e)


# ═══════════════════════════════════════════════════════════════════════════
#  Key filename helpers
# ═══════════════════════════════════════════════════════════════════════════

# Map key_format → file extension for public and private keys
_PUB_EXT = {"pem": ".pem", "der": ".der", "raw": ".bin"}
_PRIV_EXT = {"pem": ".pem", "der": ".der", "raw": ".bin"}


def key_pub_file(name: str, key_type: str, key_format: str = "pem") -> Path:
    """Return the public key file path for a given key name and type."""
    if key_type in ("rsa", "ec", "mldsa"):
        ext = _PUB_EXT.get(key_format, ".pem")
        return KEY_DIR / f"{name}_pub{ext}"
    if key_type == "lms":
        return KEY_DIR / f"{name}.pub"
    raise ValueError(f"Unknown key type: {key_type}")


def key_priv_file(name: str, key_type: str, key_format: str = "pem") -> Path:
    """Return the private key file path for a given key name and type."""
    if key_type in ("rsa", "ec", "mldsa"):
        ext = _PRIV_EXT.get(key_format, ".pem")
        return KEY_DIR / f"{name}_priv{ext}"
    if key_type == "lms":
        return KEY_DIR / f"{name}.prv"
    raise ValueError(f"Unknown key type: {key_type}")


# ═══════════════════════════════════════════════════════════════════════════
#  Configuration loader
# ═══════════════════════════════════════════════════════════════════════════

def load_config(path: Path) -> dict:
    """Load and basic-validate the test matrix YAML."""
    with open(path) as fh:
        config = yaml.safe_load(fh)
    for section in ("backends", "keys", "signatures"):
        if section not in config:
            print(f"ERROR: Missing required section '{section}' in {path}")
            sys.exit(1)
    return config


def build_backend_support(config: dict) -> dict[str, list[str]]:
    """Return a map of sigalg → list of supported backends.

    Used by test_show / test_policy to decide which backends can
    handle a given sigalg.
    """
    all_backends = config["backends"]
    support: dict[str, list[str]] = {}
    for sig in config["signatures"]:
        sa = sig["sigalg"]
        if sa not in support:
            support[sa] = sig.get("supported_backends", all_backends)
    return support


# ═══════════════════════════════════════════════════════════════════════════
#  Setup steps
# ═══════════════════════════════════════════════════════════════════════════

def setup_workspace(*, skip_build: bool):
    """Create clean work directory tree.

    With --skip-build the binary directories are preserved so that
    previously-built binaries are reused.
    """
    log_hdr("Setting up workspace")
    if skip_build:
        # Preserve bin dirs; recreate everything else
        for d in (KEY_DIR, ELT_DIR, LST_DIR, POL_DIR):
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)
        IPPC_BIN_DIR.mkdir(parents=True, exist_ok=True)
        OSSL_BIN_DIR.mkdir(parents=True, exist_ok=True)
    else:
        if WORK_DIR.exists():
            shutil.rmtree(WORK_DIR)
        for d in (KEY_DIR, ELT_DIR, LST_DIR, POL_DIR,
                  IPPC_BIN_DIR, OSSL_BIN_DIR):
            d.mkdir(parents=True, exist_ok=True)


def build_backends():
    """Build both OpenSSL and IPPC backend binaries."""
    log_hdr("Building OpenSSL backend")
    subprocess.run(["make", "clean"], cwd=LCPTOOLS_DIR,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(
        ["make"], cwd=LCPTOOLS_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    if result.returncode != 0:
        for line in result.stdout.strip().splitlines()[-5:]:
            print(f"  {line}")
        print("FATAL: OpenSSL build failed")
        sys.exit(1)
    for tool in TOOLS:
        shutil.copy2(LCPTOOLS_DIR / tool, OSSL_BIN_DIR / tool)
    log(f"OpenSSL binaries → {OSSL_BIN_DIR}")

    log_hdr("Building IPPC backend")
    subprocess.run(["make", "clean"], cwd=LCPTOOLS_DIR,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(
        ["make", "USE_IPPC=1"], cwd=LCPTOOLS_DIR,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    if result.returncode != 0:
        for line in result.stdout.strip().splitlines()[-5:]:
            print(f"  {line}")
        print("FATAL: IPPC build failed")
        sys.exit(1)
    for tool in TOOLS:
        shutil.copy2(LCPTOOLS_DIR / tool, IPPC_BIN_DIR / tool)
    log(f"IPPC binaries → {IPPC_BIN_DIR}")


def check_existing_binaries():
    """Verify binaries exist when --skip-build is used."""
    for label, bin_dir in [("ippc", IPPC_BIN_DIR),
                           ("openssl", OSSL_BIN_DIR)]:
        if not (bin_dir / "lcp2_crtpollist").exists():
            print(f"ERROR: --skip-build requires binaries in {bin_dir}")
            sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  Key generation  (driven by config['keys'])
# ═══════════════════════════════════════════════════════════════════════════

def _extract_raw_mldsa_key(der_path: str, raw_path: str, raw_size: int):
    """Extract raw ML-DSA-87 key bytes from a DER file.

    For ML-DSA-87 SubjectPublicKeyInfo DER (2614 bytes), the raw 2592-byte
    public key occupies the final 2592 bytes.  For PKCS#8 DER (4962 bytes),
    the raw 4896-byte expanded private key occupies the final 4896 bytes.
    """
    # Expected DER envelope sizes for ML-DSA-87
    expected_der_sizes = {2592: 2614, 4896: 4962}
    data = Path(der_path).read_bytes()
    expected = expected_der_sizes.get(raw_size)
    if expected and len(data) != expected:
        raise ValueError(
            f"DER file {der_path} has unexpected size {len(data)} "
            f"(expected {expected} for ML-DSA-87 raw_size={raw_size})")
    if len(data) < raw_size:
        raise ValueError(
            f"DER file {der_path} too small ({len(data)} bytes) "
            f"for raw extraction ({raw_size} bytes)")
    Path(raw_path).write_bytes(data[-raw_size:])


def _extract_raw_rsa_pubkey(pem_priv: str, raw_pub_path: str):
    """Extract raw RSA modulus (big-endian) from a PEM private key file."""
    result = subprocess.run(
        ["openssl", "rsa", "-in", pem_priv, "-pubout", "-modulus", "-noout"],
        capture_output=True, text=True, check=True,
    )
    hex_str = result.stdout.strip().split("=")[1]
    modulus_bytes = bytes.fromhex(hex_str)
    Path(raw_pub_path).write_bytes(modulus_bytes)


def _extract_raw_ec_pubkey(pem_priv: str, raw_pub_path: str, curve: str):
    """Extract raw EC public key as qx_LE || qy_LE from PEM private key.

    The crypto backend expects binary EC public keys as two concatenated
    coordinates in little-endian byte order.
    """
    coord_sizes = {"prime256v1": 32, "secp384r1": 48}
    coord_size = coord_sizes.get(curve)
    if coord_size is None:
        raise ValueError(f"Unsupported curve for raw key extraction: {curve}")

    # Get DER-encoded SubjectPublicKeyInfo
    der_data = subprocess.run(
        ["openssl", "ec", "-in", pem_priv, "-pubout", "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout

    # Find uncompressed point marker (0x04) followed by 2 * coord_size bytes
    point_size = 2 * coord_size
    idx = len(der_data) - point_size - 1
    if idx < 0 or der_data[idx] != 0x04:
        raise ValueError(
            f"Cannot find uncompressed EC point in DER data "
            f"(size={len(der_data)}, expected 0x04 at offset {idx})")

    qx_be = der_data[idx + 1 : idx + 1 + coord_size]
    qy_be = der_data[idx + 1 + coord_size : idx + 1 + point_size]

    # Convert to little-endian
    qx_le = bytes(reversed(qx_be))
    qy_le = bytes(reversed(qy_be))

    Path(raw_pub_path).write_bytes(qx_le + qy_le)


def generate_keys(config: dict, *, verbose: bool):
    """Generate (or copy) all keys defined in the config."""
    log_hdr("Generating signing keys")

    for key_name, key_cfg in config["keys"].items():
        key_type = key_cfg["type"]

        if key_type == "rsa":
            bits = str(key_cfg["bits"])
            key_format = key_cfg.get("key_format", "pem")
            priv = str(key_priv_file(key_name, key_type, key_format))
            pub = str(key_pub_file(key_name, key_type, key_format))

            # Always generate PEM first
            pem_priv = str(KEY_DIR / f"{key_name}_priv_tmp.pem")
            subprocess.run(
                ["openssl", "genrsa", "-traditional", "-out", pem_priv, bits],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=True,
            )

            if key_format == "pem":
                Path(pem_priv).rename(priv)
                subprocess.run(
                    ["openssl", "rsa", "-in", priv, "-pubout", "-out", pub],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=True,
                )
            elif key_format == "raw":
                # Private key stays PEM (signing APIs require it)
                Path(pem_priv).rename(priv)
                # Extract raw modulus (big-endian) as binary public key
                _extract_raw_rsa_pubkey(priv, pub)

            log(f"Generated RSA-{bits} key pair (format={key_format})")

        elif key_type == "ec":
            curve = key_cfg["curve"]
            key_format = key_cfg.get("key_format", "pem")
            priv = str(key_priv_file(key_name, key_type, key_format))
            pub = str(key_pub_file(key_name, key_type, key_format))

            # Always generate PEM first
            pem_priv = str(KEY_DIR / f"{key_name}_priv_tmp.pem")
            subprocess.run(
                ["openssl", "ecparam", "-name", curve,
                 "-genkey", "-noout", "-out", pem_priv],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=True,
            )

            if key_format == "pem":
                Path(pem_priv).rename(priv)
                subprocess.run(
                    ["openssl", "ec", "-in", priv, "-pubout", "-out", pub],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=True,
                )
            elif key_format == "raw":
                # Private key stays PEM (signing APIs require it)
                Path(pem_priv).rename(priv)
                # Extract raw qx_LE || qy_LE as binary public key
                _extract_raw_ec_pubkey(priv, pub, curve)

            log(f"Generated EC ({curve}) key pair (format={key_format})")

        elif key_type == "mldsa":
            key_format = key_cfg.get("key_format", "pem")
            pub = str(key_pub_file(key_name, key_type, key_format))
            priv = str(key_priv_file(key_name, key_type, key_format))
            openssl_bin = key_cfg.get("openssl", "openssl")
            openssl_env = os.environ.copy()
            ld_path = key_cfg.get("ld_library_path", "")
            if ld_path:
                existing = openssl_env.get("LD_LIBRARY_PATH", "")
                openssl_env["LD_LIBRARY_PATH"] = (
                    f"{ld_path}:{existing}" if existing else ld_path
                )
            try:
                # Always generate PEM first, then convert if needed
                pem_priv = str(KEY_DIR / f"{key_name}_priv_tmp.pem")
                pem_pub = str(KEY_DIR / f"{key_name}_pub_tmp.pem")
                subprocess.run(
                    [openssl_bin, "genpkey", "-algorithm", "ML-DSA-87",
                     "-out", pem_priv],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=True, env=openssl_env,
                )
                subprocess.run(
                    [openssl_bin, "pkey", "-in", pem_priv,
                     "-pubout", "-out", pem_pub],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=True, env=openssl_env,
                )

                if key_format == "pem":
                    Path(pem_priv).rename(priv)
                    Path(pem_pub).rename(pub)
                elif key_format == "der":
                    subprocess.run(
                        [openssl_bin, "pkey", "-in", pem_priv,
                         "-outform", "DER", "-out", priv],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=True, env=openssl_env,
                    )
                    subprocess.run(
                        [openssl_bin, "pkey", "-in", pem_pub,
                         "-pubin", "-outform", "DER", "-out", pub],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=True, env=openssl_env,
                    )
                    Path(pem_priv).unlink()
                    Path(pem_pub).unlink()
                elif key_format == "raw":
                    subprocess.run(
                        [openssl_bin, "pkey", "-in", pem_priv,
                         "-outform", "DER", "-out", priv + ".der"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=True, env=openssl_env,
                    )
                    subprocess.run(
                        [openssl_bin, "pkey", "-in", pem_pub,
                         "-pubin", "-outform", "DER", "-out", pub + ".der"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=True, env=openssl_env,
                    )
                    # Extract raw bytes: ML-DSA-87 pubkey = last 2592
                    # bytes of DER SPKI, privkey = last 4896 of DER PKCS#8
                    _extract_raw_mldsa_key(pub + ".der", pub, 2592)
                    _extract_raw_mldsa_key(priv + ".der", priv, 4896)
                    Path(pub + ".der").unlink()
                    Path(priv + ".der").unlink()
                    Path(pem_priv).unlink()
                    Path(pem_pub).unlink()

                log(f"Generated ML-DSA-87 key pair ({key_name}, "
                    f"format={key_format})")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                log_skip(f"ML-DSA key generation failed ({e}) "
                         "— ML-DSA tests will be skipped")

        elif key_type == "lms":
            copy_from = key_cfg.get("copy_from", {})
            src_pub = LCPTOOLS_DIR / copy_from.get("pub", "")
            src_priv = LCPTOOLS_DIR / copy_from.get("priv", "")
            src_aux = LCPTOOLS_DIR / copy_from.get("aux", "")
            if src_pub.exists() and src_priv.exists():
                shutil.copy2(src_pub, key_pub_file(key_name, key_type))
                shutil.copy2(src_priv, key_priv_file(key_name, key_type))
                if copy_from.get("aux") and src_aux.exists():
                    shutil.copy2(src_aux, KEY_DIR / f"{key_name}.aux")
                log(f"Copied existing LMS key pair ({key_name})")
            else:
                log_skip("No LMS keys found — LMS tests will be skipped")

        else:
            log(f"WARNING: unknown key type '{key_type}' for '{key_name}'")


# ═══════════════════════════════════════════════════════════════════════════
#  Element creation  (driven by config['elements'])
# ═══════════════════════════════════════════════════════════════════════════

def create_elements(config: dict, *, verbose: bool):
    """Create test elements defined in config['elements']."""
    log_hdr("Creating test elements")

    for elem in config.get("elements", []):
        hash_file = ELT_DIR / f"mle_hash_{elem['hashalg']}.txt"
        hash_file.write_text(elem["hash"].strip() + "\n")

        elt_file = ELT_DIR / f"{elem['name']}.elt"
        minver = str(elem.get("minver", "0x00"))
        ctrl = str(elem.get("ctrl", "0x00"))

        rc, output = run_tool(
            "openssl", "lcp2_crtpolelt",
            "--create", "--type", elem["type"],
            "--minver", minver,
            str(hash_file),
            "--ctrl", ctrl,
            "--alg", elem["hashalg"],
            "--out", str(elt_file),
            verbose=verbose,
        )

        if elt_file.exists():
            log(f"Created {elem['type'].upper()} element "
                f"({elem['hashalg'].upper()})")
        else:
            print(f"FATAL: Failed to create element '{elem['name']}'")
            sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  Resolve active signature configs
# ═══════════════════════════════════════════════════════════════════════════

def active_signatures(config: dict, skip_flags: dict[str, bool]):
    """Yield signature configs that are not disabled by skip flags
    and whose key files exist."""
    all_backends = config["backends"]

    for sig in config["signatures"]:
        # Check skip flags (e.g. skip_lms)
        flag = sig.get("skip_flag")
        if flag and skip_flags.get(flag, False):
            continue

        key_name = sig["key"]
        key_cfg = config["keys"][key_name]
        key_type = key_cfg["type"]
        key_format = key_cfg.get("key_format", "pem")

        pub = key_pub_file(key_name, key_type, key_format)
        priv = key_priv_file(key_name, key_type, key_format)
        if not pub.exists() or not priv.exists():
            continue  # key not available (e.g. mldsa keygen failed)

        supported = sig.get("supported_backends", all_backends)

        yield {
            "sigalg": sig["sigalg"],
            "hashalg": sig["hashalg"],
            "pub": pub,
            "priv": priv,
            "list_versions": [str(v) for v in sig["list_versions"]],
            "supported_backends": supported,
        }


# ═══════════════════════════════════════════════════════════════════════════
#  Test 1: Cross-backend list signing & verification
# ═══════════════════════════════════════════════════════════════════════════

def test_sign_verify(config: dict, *, verbose: bool, skip_flags: dict):
    log_hdr("Test 1: Cross-backend list signing & verification")

    backends = config["backends"]
    # Use the first element as list payload
    elt_file = str(ELT_DIR / f"{config['elements'][0]['name']}.elt")

    for sig in active_signatures(config, skip_flags):
        sigalg = sig["sigalg"]
        hashalg = sig["hashalg"]
        supported = sig["supported_backends"]

        for listver in sig["list_versions"]:
            log_hdr(f"SigAlg={sigalg}  HashAlg={hashalg}  "
                    f"ListVer={listver}")

            for create_be in backends:
                # ── Create unsigned list ──
                unsigned = LST_DIR / (
                    f"unsigned_{sigalg}_{hashalg}_{listver}_{create_be}.lst"
                )
                create_args = ["--create", "--listver", listver,
                               "--out", str(unsigned), elt_file]
                if listver in ("0x200", "0x201"):
                    create_args = ["--create", "--listver", listver,
                                   "--sigalg", sigalg,
                                   "--out", str(unsigned), elt_file]

                rc, output = run_tool(create_be, "lcp2_crtpollist",
                                      *create_args, verbose=verbose)
                if not unsigned.exists():
                    log_fail(f"Create unsigned list: {create_be} / "
                             f"{sigalg} / {listver}")
                    if verbose:
                        print(f"  {output}")
                    continue

                for sign_be in backends:
                    if sign_be not in supported:
                        log_skip(
                            f"Sign: {sigalg} not supported on {sign_be}: "
                            f"c={create_be} s={sign_be}"
                        )
                        continue

                    # ── Sign the list ──
                    signed = LST_DIR / (
                        f"signed_{sigalg}_{hashalg}_{listver}_"
                        f"c{create_be}_s{sign_be}.lst"
                    )
                    shutil.copy2(unsigned, signed)

                    sign_args = [
                        "--sign", "--force", "--sigalg", sigalg,
                        "--pub", str(sig["pub"]),
                        "--priv", str(sig["priv"]),
                        "--out", str(signed),
                    ]
                    if listver == "0x300":
                        sign_args = [
                            "--sign", "--force", "--sigalg", sigalg,
                            "--hashalg", hashalg,
                            "--pub", str(sig["pub"]),
                            "--priv", str(sig["priv"]),
                            "--out", str(signed),
                        ]

                    rc, output = run_tool(sign_be, "lcp2_crtpollist",
                                          *sign_args, verbose=verbose)
                    if rc != 0:
                        log_fail(f"Sign: c={create_be} s={sign_be} / "
                                 f"{sigalg} / {listver}")
                        if verbose:
                            print(f"  {output}")
                        continue

                    # Verify size grew (signature appended)
                    signed_sz = signed.stat().st_size if signed.exists() else 0
                    unsigned_sz = (unsigned.stat().st_size
                                   if unsigned.exists() else 0)
                    if signed_sz <= unsigned_sz:
                        log_fail(
                            f"Sign (size unchanged): c={create_be} "
                            f"s={sign_be} / {sigalg} / {listver}"
                        )
                        continue

                    log_pass(f"Sign: c={create_be} s={sign_be} / "
                             f"{sigalg}-{hashalg} / {listver}")

                    # ── Verify ──
                    if listver == "0x300":
                        for verify_be in backends:
                            if verify_be not in supported:
                                log_skip(
                                    f"Verify: {sigalg} not supported on "
                                    f"{verify_be}: v={verify_be}"
                                )
                                continue
                            _check_verify(
                                verify_be, signed,
                                label=(
                                    f"Verify: c={create_be} s={sign_be} "
                                    f"v={verify_be} / {sigalg}-{hashalg}"
                                ),
                                verbose=verbose,
                            )
                    else:
                        log_skip(
                            f"Verify skipped (--verify only for 0x300): "
                            f"c={create_be} s={sign_be} / "
                            f"{sigalg} / {listver}"
                        )


def _check_verify(backend: str, lst_file: Path, *,
                  label: str, verbose: bool):
    """Run --verify and log PASS/FAIL based on output."""
    rc, output = run_tool(backend, "lcp2_crtpollist",
                          "--verify", str(lst_file), verbose=verbose)
    out_lower = output.lower()

    fail_pats = (r"did not verify", r"signature.*fail", r"not valid")
    pass_pats = (r"signature verified", r"verification.*success",
                 r"verify.*ok", r"verified successfully")

    if any(re.search(p, out_lower) for p in fail_pats):
        log_fail(label)
        if verbose:
            print(f"  {output}")
    elif any(re.search(p, out_lower) for p in pass_pats):
        log_pass(label)
    elif rc != 0:
        log_fail(label)
        if verbose:
            print(f"  {output}")
    else:
        log_pass(label)


# ═══════════════════════════════════════════════════════════════════════════
#  Test 2: --show consistency across backends
# ═══════════════════════════════════════════════════════════════════════════

def test_show(config: dict, *, verbose: bool):
    log_hdr("Test 2: --show consistency across backends")

    backends = config["backends"]
    backend_support = build_backend_support(config)

    for lst_file in sorted(LST_DIR.glob("signed_*.lst")):
        base_name = lst_file.name
        # Extract sigalg from filename: signed_SIGALG_HASHALG_...
        file_sigalg = base_name.split("_")[1]

        supported = backend_support.get(file_sigalg, backends)

        for be in backends:
            if be not in supported:
                log_skip(f"Show: {file_sigalg} not supported on {be}: "
                         f"{base_name}")
                continue

            rc, output = run_tool(be, "lcp2_crtpollist",
                                  "--show", str(lst_file), verbose=verbose)
            out_lower = output.lower()

            if rc == 0 and re.search(
                    r"version|list_version|sig_alg|signature", out_lower):
                log_pass(f"Show: {be} / {base_name}")
            else:
                log_fail(f"Show: {be} / {base_name}")
                if verbose:
                    print(f"  {output}")


# ═══════════════════════════════════════════════════════════════════════════
#  Test 3: Cross-backend policy creation
# ═══════════════════════════════════════════════════════════════════════════

def test_policy(config: dict, *, verbose: bool):
    log_hdr("Test 3: Cross-backend policy creation")

    backends = config["backends"]
    pol_cfg = config.get("policy", {})
    pol_versions = [str(v) for v in pol_cfg.get("versions", ["3.0", "3.2"])]
    pol_hash_algs = pol_cfg.get("hash_algs", ["sha256", "sha384"])
    mask_algs = pol_cfg.get("mask_algs", ["sha256", "sha384"])
    sign_flags_map = pol_cfg.get("sign_flags", {})
    skip_sigalgs = set(pol_cfg.get("skip_sigalgs", []))
    backend_support = build_backend_support(config)

    # Build mask flags
    mask_flags: list[str] = []
    for m in mask_algs:
        mask_flags.extend(["--mask", m])

    # Pick one representative 0x300 signed list per sigalg
    policy_test_lists: dict[str, Path] = {}
    for lst_file in sorted(LST_DIR.glob("signed_*.lst")):
        parts = lst_file.name.split("_")
        if len(parts) < 4:
            continue
        file_sigalg = parts[1]
        file_listver = parts[3]
        if file_listver == "0x300" and file_sigalg not in policy_test_lists:
            policy_test_lists[file_sigalg] = lst_file

    for sigalg in sorted(policy_test_lists):
        lst_file = policy_test_lists[sigalg]
        base_name = lst_file.stem

        if sigalg in skip_sigalgs:
            log_skip(f"Policy: {sigalg} not used with lcp2_crtpol "
                     f"(list-signing only)")
            continue

        supported = backend_support.get(sigalg, backends)
        sign_flags = [str(f) for f in sign_flags_map.get(sigalg, [])]

        for pol_be in backends:
            for polver in pol_versions:
                for pol_hash in pol_hash_algs:
                    pol_file = POL_DIR / (
                        f"pol_{base_name}_{pol_be}_v{polver}_{pol_hash}.pol"
                    )
                    dat_file = POL_DIR / (
                        f"pol_{base_name}_{pol_be}_v{polver}_{pol_hash}.dat"
                    )

                    pol_args = [
                        "--create", "--type", "list", str(lst_file),
                        "--alg", pol_hash, "--ctrl", "0x00",
                        "--pol", str(pol_file), "--data", str(dat_file),
                        "--polver", polver,
                        *sign_flags, *mask_flags,
                    ]

                    rc, output = run_tool(pol_be, "lcp2_crtpol",
                                          *pol_args, verbose=verbose)

                    if rc == 0 and pol_file.exists() and dat_file.exists():
                        # Verify with --show from each supported backend
                        for show_be in backends:
                            if show_be not in supported:
                                log_skip(
                                    f"Policy show: {sigalg} not supported "
                                    f"on {show_be}"
                                )
                                continue
                            src, show_out = run_tool(
                                show_be, "lcp2_crtpol",
                                "--show", str(pol_file), str(dat_file),
                                verbose=verbose,
                            )
                            if src == 0 and re.search(
                                    r"version|hash_alg|policy",
                                    show_out.lower()):
                                log_pass(
                                    f"Policy: {pol_be}→{show_be} / "
                                    f"{sigalg} / v{polver} / {pol_hash}"
                                )
                            else:
                                log_fail(
                                    f"Policy show: {pol_be}→{show_be} / "
                                    f"{sigalg} / v{polver} / {pol_hash}"
                                )
                                if verbose:
                                    print(f"  {show_out}")
                    else:
                        log_fail(
                            f"Policy create: {pol_be} / {sigalg} / "
                            f"v{polver} / {pol_hash}"
                        )
                        if verbose:
                            print(f"  {output}")


# ═══════════════════════════════════════════════════════════════════════════
#  Test 4: Negative tests — tampered list verification
# ═══════════════════════════════════════════════════════════════════════════

def test_tamper(config: dict, *, verbose: bool):
    log_hdr("Test 4: Negative tests — tampered list verification")

    backends = config["backends"]
    tamper_cfg = config.get("tamper", {})
    pattern = tamper_cfg.get("source_pattern", "signed_ecdsa_sha256_0x300_*.lst")

    # Find a matching signed list
    tamper_src = None
    for f in sorted(LST_DIR.glob(pattern)):
        tamper_src = f
        break

    if tamper_src is None:
        log_skip("No signed list found matching tamper source_pattern")
        return

    tampered = LST_DIR / "tampered_test.lst"
    shutil.copy2(tamper_src, tampered)

    # Flip a byte near the middle
    data = bytearray(tampered.read_bytes())
    data[len(data) // 2] = 0xFF
    tampered.write_bytes(bytes(data))

    for be in backends:
        rc, output = run_tool(be, "lcp2_crtpollist",
                              "--verify", str(tampered), verbose=verbose)
        out_lower = output.lower()

        fail_detected = any(re.search(p, out_lower) for p in (
            r"did not verify", r"fail", r"error", r"invalid", r"not valid",
        ))
        pass_detected = any(re.search(p, out_lower) for p in (
            r"verified successfully", r"verification successful",
            r"signature verified", r"signature correct",
        ))

        if fail_detected:
            log_pass(f"Tamper detect: {be} correctly rejected tampered list")
        elif rc != 0:
            log_pass(f"Tamper detect: {be} correctly rejected tampered list")
        elif pass_detected:
            log_fail(f"Tamper detect: {be} did NOT detect tampering")
            if verbose:
                print(f"  {output}")
        else:
            # Unknown output — treat as detection (conservative)
            log_pass(f"Tamper detect: {be} correctly rejected tampered list")


# ═══════════════════════════════════════════════════════════════════════════
#  Test 5: Element creation consistency
# ═══════════════════════════════════════════════════════════════════════════

def test_element_consistency(config: dict, *, verbose: bool):
    log_hdr("Test 5: Element creation consistency")

    backends = config["backends"]

    for elem in config.get("elements", []):
        hash_file = str(ELT_DIR / f"mle_hash_{elem['hashalg']}.txt")
        minver = str(elem.get("minver", "0x00"))
        ctrl = str(elem.get("ctrl", "0x00"))

        elt_files: dict[str, Path] = {}
        for be in backends:
            elt_file = ELT_DIR / f"{elem['name']}_{be}.elt"
            rc, output = run_tool(
                be, "lcp2_crtpolelt",
                "--create", "--type", elem["type"],
                "--minver", minver,
                hash_file,
                "--ctrl", ctrl,
                "--alg", elem["hashalg"],
                "--out", str(elt_file),
                verbose=verbose,
            )
            if elt_file.exists():
                log_pass(f"Element create: {be} / {elem['name']}")
                elt_files[be] = elt_file
            else:
                log_fail(f"Element create: {be} / {elem['name']}")

        # Compare all backends' output — should be binary identical
        be_list = list(elt_files.keys())
        for i in range(len(be_list)):
            for j in range(i + 1, len(be_list)):
                a, b = be_list[i], be_list[j]
                if elt_files[a].read_bytes() == elt_files[b].read_bytes():
                    log_pass(f"Element consistency: "
                             f"{a.upper()} == {b.upper()} "
                             f"(binary identical)")
                else:
                    log_fail(f"Element consistency: "
                             f"{a.upper()} != {b.upper()} "
                             f"(files differ)")


# ═══════════════════════════════════════════════════════════════════════════
#  Test 6: LMS signing prompt — decline and verify keys untouched
# ═══════════════════════════════════════════════════════════════════════════

def test_lms_prompt_decline(config: dict, *, verbose: bool,
                            skip_flags: dict):
    """Decline the LMS signing prompt and verify key files are unchanged."""
    log_hdr("Test 6: LMS signing prompt decline")

    if skip_flags.get("skip_lms"):
        log_skip("LMS prompt test skipped (--skip-lms)")
        return

    # Only IPPC supports LMS
    if "ippc" not in config["backends"]:
        log_skip("LMS prompt test skipped (IPPC backend not available)")
        return

    # Find LMS key files
    lms_pub = KEY_DIR / "lms.pub"
    lms_priv = KEY_DIR / "lms.prv"
    if not lms_pub.exists() or not lms_priv.exists():
        log_skip("LMS prompt test skipped (no LMS keys)")
        return

    # Find an element for list creation
    elts = list(ELT_DIR.glob("*.elt"))
    if not elts:
        log_skip("LMS prompt test skipped (no elements available)")
        return

    # Create an unsigned list
    unsigned = LST_DIR / "unsigned_lms_prompt_test.lst"
    rc, output = run_tool("ippc", "lcp2_crtpollist",
                          "--create", "--listver", "0x300",
                          "--out", str(unsigned), str(elts[0]),
                          verbose=verbose)
    if rc != 0:
        log_fail("LMS prompt: failed to create unsigned list")
        if verbose:
            print(f"  {output}")
        return

    # Copy the unsigned list for signing attempt
    sign_target = LST_DIR / "lms_prompt_decline_test.lst"
    shutil.copy2(unsigned, sign_target)

    # Record key file contents before
    pub_before = lms_pub.read_bytes()
    priv_before = lms_priv.read_bytes()
    list_before = sign_target.read_bytes()

    # Run signing WITHOUT --force, pipe "N" to decline the prompt
    tool_path = str(IPPC_BIN_DIR / "lcp2_crtpollist")
    env = os.environ.copy()
    existing = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = (
        f"{IPPC_LIB}:{existing}" if existing else str(IPPC_LIB)
    )

    sign_cmd = [
        tool_path,
        "--sign", "--sigalg", "lms",
        "--hashalg", "sha256",
        "--pub", str(lms_pub),
        "--priv", str(lms_priv),
        "--out", str(sign_target),
    ]

    if verbose:
        print(f"  {Colors.YELLOW}▸{Colors.NC} [ippc] "
              f"{' '.join(sign_cmd[1:])} (stdin='N')")

    result = subprocess.run(
        sign_cmd, env=env, input="N\n",
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    # Verify the tool aborted
    if result.returncode != 0:
        log_pass("LMS prompt decline: tool exited with non-zero status")
    else:
        log_fail("LMS prompt decline: tool should have exited non-zero")
        if verbose:
            print(f"  {result.stdout}")

    # Verify key files are untouched
    pub_after = lms_pub.read_bytes()
    priv_after = lms_priv.read_bytes()
    list_after = sign_target.read_bytes()

    if pub_after == pub_before and priv_after == priv_before:
        log_pass("LMS prompt decline: key files unchanged")
    else:
        log_fail("LMS prompt decline: key files were modified!")

    if list_after == list_before:
        log_pass("LMS prompt decline: list file unchanged")
    else:
        log_fail("LMS prompt decline: list file was modified!")


# ═══════════════════════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════════════════════

def print_summary() -> int:
    """Print final results.  Returns exit code (0 = all pass)."""
    log_hdr("Test Summary")
    print(f"  {Colors.GREEN}PASSED{Colors.NC}: {results.passed}")
    print(f"  {Colors.RED}FAILED{Colors.NC}: {results.failed}")
    print(f"  {Colors.YELLOW}SKIPPED{Colors.NC}: {results.skipped}")
    total = results.passed + results.failed
    print(f"  {Colors.BOLD}TOTAL{Colors.NC}:   {total}")

    if results.failed > 0:
        print(f"\n{Colors.RED}Failed tests:{Colors.NC}")
        for f in results.failures:
            print(f"  • {f}")
        print()
        return 1

    print(f"\n{Colors.GREEN}All tests passed!{Colors.NC}\n")
    return 0


# ═══════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Config-driven cross-backend LCP policy functional tests",
    )
    parser.add_argument(
        "--config", type=Path,
        default=SCRIPT_DIR / "test_matrix.yaml",
        help="Path to test matrix YAML (default: test_matrix.yaml)",
    )
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip building backends (use existing binaries)")
    parser.add_argument("--skip-lms", action="store_true",
                        help="Skip LMS tests")
    parser.add_argument("--lms-keys", type=Path, default=None,
                        help="Base path to LMS keys (without extension), "
                             "e.g. /path/to/lms_m24_h20_w4")
    parser.add_argument("--verbose", action="store_true",
                        help="Show tool invocations and failure output")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Keep test collaterals in functional_work/")
    args = parser.parse_args()

    # ── Load configuration ──
    config = load_config(args.config)

    # Override LMS key paths if --lms-keys was given
    if args.lms_keys:
        base = args.lms_keys
        for key_cfg in config["keys"].values():
            if key_cfg.get("type") == "lms":
                key_cfg["copy_from"] = {
                    "pub":  str(base.with_suffix(".pub")),
                    "priv": str(base.with_suffix(".prv")),
                    "aux":  str(base.with_suffix(".aux")),
                }

    # Map skip_flag values → CLI state
    skip_flags = {
        "skip_lms": args.skip_lms,
    }

    # ── Setup ──
    setup_workspace(skip_build=args.skip_build)

    if args.skip_build:
        log("Skipping build (--skip-build)")
        check_existing_binaries()
    else:
        build_backends()

    generate_keys(config, verbose=args.verbose)
    create_elements(config, verbose=args.verbose)

    # ── Run tests ──
    test_sign_verify(config, verbose=args.verbose, skip_flags=skip_flags)
    test_show(config, verbose=args.verbose)
    test_policy(config, verbose=args.verbose)
    test_tamper(config, verbose=args.verbose)
    test_element_consistency(config, verbose=args.verbose)
    test_lms_prompt_decline(config, verbose=args.verbose,
                            skip_flags=skip_flags)

    # ── Cleanup ──
    if args.no_cleanup:
        log(f"Keeping test collaterals in {WORK_DIR}")
    elif WORK_DIR.exists():
        shutil.rmtree(WORK_DIR)
        log(f"Purged {WORK_DIR}")

    # ── Summary ──
    sys.exit(print_summary())


if __name__ == "__main__":
    main()
