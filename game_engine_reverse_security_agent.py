#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Game Engine Reverse & Security Analysis Agent
=============================================

A local, static-analysis-first agent for authorized game-engine reverse engineering
and security review.

Scope:
- File and directory triage
- Hashing, entropy, magic detection
- ASCII / UTF-16LE string extraction
- Game engine fingerprinting: Unity, Unreal, Godot, Cocos2d-x, Source-like indicators
- PE analysis via optional `pefile`
- ELF analysis via optional `pyelftools`
- Risk-rule matching for suspicious APIs / anti-debug / injection / network / crypto indicators
- Markdown and JSON report generation

This tool intentionally does NOT implement:
- anti-cheat bypass
- code injection
- process memory modification
- exploit delivery
- credential theft
- malware behavior

Install optional dependencies:
    pip install pefile pyelftools rich

Run:
    python ge_security_agent.py scan /path/to/game --out report.md --json report.json
    python ge_security_agent.py scan /path/to/file.exe --deep --max-file-mb 512

Python: 3.9+
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as _dt
import hashlib
import json
import math
import os
import re
import struct
import sys
import textwrap
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
except Exception:  # pragma: no cover
    ELFFile = None

try:
    from rich.console import Console  # type: ignore
    from rich.progress import track  # type: ignore
except Exception:  # pragma: no cover
    Console = None
    track = None


# -----------------------------
# Configuration
# -----------------------------

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "Library",  # Unity project cache; can be very large
    "Temp",
    "Obj",
    "obj",
    "BuildCache",
    "DerivedDataCache",  # Unreal
    "Saved",  # Unreal logs/cache; still useful sometimes, skipped by default
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".ocx",
    ".so", ".dylib", ".bundle",
    ".bin", ".dat", ".pak", ".ucas", ".utoc", ".pck", ".assets",
    ".apk", ".ipa",
}

TEXT_EXTENSIONS = {
    ".txt", ".log", ".ini", ".cfg", ".json", ".xml", ".yaml", ".yml",
    ".toml", ".lua", ".js", ".ts", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".shader", ".hlsl", ".glsl", ".metal", ".usf",
}

ARCHIVE_EXTENSIONS = {".zip", ".jar", ".apk", ".ipa"}

MAX_STRING_SCAN_BYTES_DEFAULT = 32 * 1024 * 1024


# -----------------------------
# Rule sets
# -----------------------------

RULES: Dict[str, Dict[str, Any]] = {
    "windows_injection_api": {
        "severity": "high",
        "description": "Windows process injection / remote memory operation indicators",
        "patterns": [
            "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
            "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx",
            "MapViewOfFile", "NtMapViewOfSection", "RtlCreateUserThread",
        ],
        "tags": ["windows", "injection", "memory"],
    },
    "windows_driver_or_kernel_touchpoints": {
        "severity": "high",
        "description": "Windows driver / kernel interface indicators",
        "patterns": [
            "DeviceIoControl", "CreateFileA", "CreateFileW", "\\\\.\\",
            "NtLoadDriver", "ZwLoadDriver", "MmCopyVirtualMemory", "PsLookupProcessByProcessId",
            "ObRegisterCallbacks", "PsSetLoadImageNotifyRoutine", "IoCreateDevice",
        ],
        "tags": ["windows", "driver", "kernel"],
    },
    "anti_debug_or_vm": {
        "severity": "medium",
        "description": "Anti-debugging, anti-VM, or environment detection indicators",
        "patterns": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "BeingDebugged", "ProcessDebugPort", "ProcessDebugFlags",
            "rdtsc", "cpuid", "VMware", "VirtualBox", "Microsoft Hv", "KVMKVMKVM",
            "ptrace", "/proc/self/status", "TracerPid",
        ],
        "tags": ["anti-debug", "anti-vm"],
    },
    "dynamic_loading": {
        "severity": "medium",
        "description": "Dynamic module loading / symbol resolution indicators",
        "patterns": [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "FreeLibrary",
            "dlopen", "dlsym", "dlclose", "NSCreateObjectFileImageFromFile",
        ],
        "tags": ["loader", "dynamic"],
    },
    "network_stack": {
        "severity": "medium",
        "description": "Network communication indicators",
        "patterns": [
            "WinHttpOpen", "WinHttpSendRequest", "WinHttpReadData",
            "InternetOpenA", "InternetOpenW", "InternetConnect", "HttpSendRequest",
            "WSAStartup", "socket", "connect", "send", "recv", "curl_easy_perform",
            "UnityWebRequest", "HttpClient", "WebSocket", "SteamNetworkingSockets",
        ],
        "tags": ["network"],
    },
    "crypto_or_obfuscation": {
        "severity": "medium",
        "description": "Crypto, hashing, packing, or obfuscation indicators",
        "patterns": [
            "AES", "RSA", "ChaCha", "Salsa20", "RC4", "MD5", "SHA1", "SHA256",
            "BCryptEncrypt", "CryptEncrypt", "CryptAcquireContext", "EVP_Encrypt",
            "UPX", "Themida", "VMProtect", "Enigma Protector", "Obfuscator",
        ],
        "tags": ["crypto", "obfuscation"],
    },
    "mobile_hooking_or_instrumentation": {
        "severity": "medium",
        "description": "Mobile instrumentation or hooking framework indicators",
        "patterns": [
            "frida", "gum-js-loop", "xposed", "substrate", "CydiaSubstrate",
            "Magisk", "zygisk", "ptrace", "inlineHook", "MSHookFunction",
        ],
        "tags": ["mobile", "hooking"],
    },
    "game_script_sensitive_terms": {
        "severity": "low",
        "description": "Game logic terms that may deserve review in scripts or managed assemblies",
        "patterns": [
            "godmode", "aimbot", "wallhack", "speedhack", "teleport", "unlock_all",
            "debug_menu", "developer_console", "admin_command", "cheat", "ban", "anti_cheat",
        ],
        "tags": ["game-logic", "review"],
    },
}

ENGINE_RULES: Dict[str, Dict[str, Any]] = {
    "Unity": {
        "filenames": [
            "UnityPlayer.dll", "GameAssembly.dll", "global-metadata.dat", "Assembly-CSharp.dll",
            "resources.assets", "sharedassets0.assets", "UnityFramework", "libunity.so", "libil2cpp.so",
        ],
        "path_parts": ["Managed", "il2cpp_data", "StreamingAssets", "Data/Managed"],
        "strings": ["UnityEngine", "MonoBehaviour", "global-metadata.dat", "il2cpp", "UnityPlayer"],
        "extensions": [".assets", ".bundle"],
    },
    "Unreal Engine": {
        "filenames": [
            "UE4Game.exe", "UnrealEditor.exe", "CrashReportClient.exe", "UnrealPak.exe",
            "pakchunk0-Windows.pak", "AssetRegistry.bin",
        ],
        "path_parts": ["Engine/Binaries", "Content/Paks", "Binaries/Win64", "Binaries/Linux"],
        "strings": ["/Script/Engine", "FNamePool", "GNames", "GUObjectArray", "UObject", "Unreal Engine"],
        "extensions": [".pak", ".ucas", ".utoc", ".uasset", ".umap"],
    },
    "Godot": {
        "filenames": ["project.godot", "data.pck", "engine.cfg"],
        "path_parts": [".godot", "res://"],
        "strings": ["Godot Engine", "project.godot", "res://", "user://"],
        "extensions": [".pck", ".tscn", ".scn", ".gd"],
    },
    "Cocos2d-x": {
        "filenames": ["libcocos2d.dll", "libcocos2dcpp.so", "project.json", "main.lua"],
        "path_parts": ["cocos", "src/app", "frameworks/runtime-src"],
        "strings": ["cocos2d", "Cocos2d-x", "CCDirector", "LuaStack", "jsb_"],
        "extensions": [".lua", ".jsc", ".luac"],
    },
    "Source-like": {
        "filenames": ["engine.dll", "client.dll", "server.dll", "tier0.dll", "vstdlib.dll"],
        "path_parts": ["steamapps/common"],
        "strings": ["Source Engine", "VClient", "VEngineClient", "CreateInterface"],
        "extensions": [".vpk", ".bsp", ".mdl"],
    },
}

MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"MZ", "PE/COFF executable"),
    (b"\x7fELF", "ELF binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit big-endian"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit little-endian"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit big-endian"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "GZip archive"),
    (b"UnityFS", "Unity AssetBundle"),
    (b"UnityRaw", "Unity raw asset"),
    (b"UnityWeb", "Unity web asset"),
]

UNREAL_PAK_MAGIC_LE = 0x5A6F12E1
UNREAL_PAK_MAGIC_BE = 0xE1126F5A


# -----------------------------
# Data models
# -----------------------------

@dataclasses.dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    evidence: List[str]
    tags: List[str]


@dataclasses.dataclass
class FileReport:
    path: str
    size: int
    sha256: str
    md5: str
    file_type: str
    entropy: Optional[float]
    extension: str
    engine_hints: Dict[str, int]
    findings: List[Finding]
    strings_sample: List[str]
    metadata: Dict[str, Any]
    errors: List[str]


@dataclasses.dataclass
class ScanSummary:
    root: str
    started_at: str
    finished_at: str
    files_seen: int
    files_analyzed: int
    files_skipped: int
    total_bytes_analyzed: int
    engine_scores: Dict[str, int]
    severity_counts: Dict[str, int]
    top_findings: Dict[str, int]


@dataclasses.dataclass
class ScanReport:
    summary: ScanSummary
    files: List[FileReport]


# -----------------------------
# Utilities
# -----------------------------

class AgentError(Exception):
    pass


class Log:
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.console = Console() if Console else None

    def info(self, msg: str) -> None:
        if self.console:
            self.console.print(f"[cyan][*][/cyan] {msg}")
        else:
            print(f"[*] {msg}")

    def warn(self, msg: str) -> None:
        if self.console:
            self.console.print(f"[yellow][!][/yellow] {msg}")
        else:
            print(f"[!] {msg}")

    def debug(self, msg: str) -> None:
        if not self.verbose:
            return
        if self.console:
            self.console.print(f"[dim][debug][/dim] {msg}")
        else:
            print(f"[debug] {msg}")


def safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def read_prefix(path: Path, n: int = 4096) -> bytes:
    with path.open("rb") as f:
        return f.read(n)


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def shannon_entropy_from_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def entropy_file(path: Path, max_bytes: int = 8 * 1024 * 1024) -> Optional[float]:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return round(shannon_entropy_from_bytes(data), 4)
    except Exception:
        return None


def detect_magic(prefix: bytes, path: Path) -> str:
    for sig, desc in MAGIC_SIGNATURES:
        if prefix.startswith(sig):
            return desc

    lower = path.name.lower()
    if lower.endswith(".pak") and len(prefix) >= 4:
        first = struct.unpack("<I", prefix[:4])[0]
        if first in (UNREAL_PAK_MAGIC_LE, UNREAL_PAK_MAGIC_BE):
            return "Unreal Pak archive"
        # Unreal pak magic can be near the footer, so extension is still meaningful.
        return "Possible Unreal Pak archive"

    if lower.endswith(".ucas"):
        return "Unreal IO Store container"
    if lower.endswith(".utoc"):
        return "Unreal IO Store table of contents"
    if lower.endswith(".pck"):
        return "Godot PCK package"
    if lower.endswith(".assets"):
        return "Unity assets file"
    if lower.endswith(".bundle"):
        return "Asset bundle / binary bundle"
    if lower.endswith(".vpk"):
        return "Valve VPK package"

    # Basic text heuristic.
    if prefix:
        printable = sum(1 for b in prefix if b in b"\t\r\n" or 32 <= b <= 126)
        ratio = printable / max(1, len(prefix))
        if ratio > 0.92:
            return "Text-like file"

    return "Unknown / data"


_ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16LE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){5,}"))


def extract_strings(path: Path, max_bytes: int = MAX_STRING_SCAN_BYTES_DEFAULT, limit: int = 5000) -> List[str]:
    """Extract ASCII and UTF-16LE strings. Keeps order roughly by match offset."""
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return []

    matches: List[Tuple[int, str]] = []
    for m in _ASCII_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-8", errors="ignore")
            if s:
                matches.append((m.start(), s))
        except Exception:
            pass

    for m in _UTF16LE_RE.finditer(data):
        try:
            s = m.group(0).decode("utf-16le", errors="ignore")
            if s:
                matches.append((m.start(), s))
        except Exception:
            pass

    matches.sort(key=lambda x: x[0])

    seen = set()
    out: List[str] = []
    for _, s in matches:
        clean = s.strip()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(clean)
        if len(out) >= limit:
            break
    return out


def normalize_for_search(s: str) -> str:
    return s.lower().replace("\\", "/")


def is_probably_interesting(path: Path) -> bool:
    ext = path.suffix.lower()
    if ext in BINARY_EXTENSIONS or ext in TEXT_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
        return True
    name = path.name.lower()
    interesting_names = {
        "global-metadata.dat", "project.godot", "assetregistry.bin",
        "unityplayer.dll", "gameassembly.dll", "libil2cpp.so", "libunity.so",
    }
    return name in interesting_names


def iter_files(root: Path, ignore_dirs: Sequence[str]) -> Iterable[Path]:
    if root.is_file():
        yield root
        return

    ignored = set(ignore_dirs)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignored]
        base = Path(dirpath)
        for filename in filenames:
            yield base / filename


# -----------------------------
# Engine detection
# -----------------------------

class EngineDetector:
    @staticmethod
    def detect(path: Path, root: Path, strings: Sequence[str], file_type: str) -> Dict[str, int]:
        rel = normalize_for_search(safe_relpath(path, root))
        name = path.name
        ext = path.suffix.lower()
        joined_strings = "\n".join(strings[:2000])
        joined_lower = joined_strings.lower()

        scores: Dict[str, int] = defaultdict(int)

        for engine, rule in ENGINE_RULES.items():
            for fn in rule.get("filenames", []):
                if name.lower() == fn.lower():
                    scores[engine] += 8
                elif fn.lower() in rel:
                    scores[engine] += 4

            for part in rule.get("path_parts", []):
                if normalize_for_search(part) in rel:
                    scores[engine] += 4

            for pattern in rule.get("strings", []):
                if pattern.lower() in joined_lower:
                    scores[engine] += 5

            if ext in rule.get("extensions", []):
                scores[engine] += 3

        if "Unity" in file_type:
            scores["Unity"] += 8
        if "Unreal" in file_type:
            scores["Unreal Engine"] += 8
        if "Godot" in file_type:
            scores["Godot"] += 8

        return dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True))


# -----------------------------
# Static risk analysis
# -----------------------------

class RuleMatcher:
    @staticmethod
    def match(strings: Sequence[str]) -> List[Finding]:
        if not strings:
            return []
        # Case-sensitive matching keeps API names meaningful, but we also do lower fallback.
        full = "\n".join(strings)
        full_lower = full.lower()
        findings: List[Finding] = []

        for rule_id, rule in RULES.items():
            evidence = []
            for pat in rule["patterns"]:
                if pat in full or pat.lower() in full_lower:
                    evidence.append(pat)
            if evidence:
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        severity=rule["severity"],
                        description=rule["description"],
                        evidence=sorted(set(evidence)),
                        tags=list(rule.get("tags", [])),
                    )
                )
        return findings


# -----------------------------
# PE / ELF / Archive analyzers
# -----------------------------

class PEAnalyzer:
    @staticmethod
    def analyze(path: Path) -> Dict[str, Any]:
        if pefile is None:
            return {"available": False, "reason": "Install optional dependency: pip install pefile"}

        result: Dict[str, Any] = {"available": True}
        try:
            pe = pefile.PE(str(path), fast_load=False)
            result["machine"] = hex(pe.FILE_HEADER.Machine)
            result["timestamp"] = PEAnalyzer._timestamp(pe.FILE_HEADER.TimeDateStamp)
            result["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
            result["subsystem"] = getattr(pe.OPTIONAL_HEADER, "Subsystem", None)
            result["image_base"] = hex(getattr(pe.OPTIONAL_HEADER, "ImageBase", 0))
            result["entry_point"] = hex(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
            result["sections"] = PEAnalyzer._sections(pe)
            result["imports"] = PEAnalyzer._imports(pe)
            result["exports"] = PEAnalyzer._exports(pe)
            result["signing"] = PEAnalyzer._security_directory(pe)
            result["overlay_size"] = PEAnalyzer._overlay_size(path, pe)
            result["is_dotnet_hint"] = PEAnalyzer._dotnet_hint(pe)
            pe.close()
        except Exception as e:
            result["error"] = repr(e)
        return result

    @staticmethod
    def _timestamp(ts: int) -> str:
        try:
            return _dt.datetime.utcfromtimestamp(ts).isoformat() + "Z"
        except Exception:
            return str(ts)

    @staticmethod
    def _sections(pe: Any) -> List[Dict[str, Any]]:
        out = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            data = s.get_data()[:2 * 1024 * 1024]
            out.append({
                "name": name,
                "virtual_address": hex(s.VirtualAddress),
                "virtual_size": int(s.Misc_VirtualSize),
                "raw_size": int(s.SizeOfRawData),
                "entropy": round(shannon_entropy_from_bytes(data), 4) if data else 0.0,
                "characteristics": hex(s.Characteristics),
            })
        return out

    @staticmethod
    def _imports(pe: Any) -> Dict[str, List[str]]:
        imports: Dict[str, List[str]] = {}
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "<unknown>"
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                else:
                    funcs.append(f"ord:{imp.ordinal}")
            imports[dll] = funcs[:500]
        return imports

    @staticmethod
    def _exports(pe: Any) -> List[str]:
        out: List[str] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return out
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                out.append(exp.name.decode("utf-8", errors="replace"))
            else:
                out.append(f"ord:{exp.ordinal}")
        return out[:1000]

    @staticmethod
    def _security_directory(pe: Any) -> Dict[str, Any]:
        try:
            idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            return {
                "has_security_directory": bool(sec.VirtualAddress and sec.Size),
                "virtual_address": hex(sec.VirtualAddress),
                "size": int(sec.Size),
            }
        except Exception:
            return {"has_security_directory": False}

    @staticmethod
    def _overlay_size(path: Path, pe: Any) -> int:
        try:
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is None:
                return 0
            return max(0, path.stat().st_size - overlay_offset)
        except Exception:
            return 0

    @staticmethod
    def _dotnet_hint(pe: Any) -> bool:
        try:
            idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            desc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            return bool(desc.VirtualAddress and desc.Size)
        except Exception:
            return False


class ELFAnalyzer:
    @staticmethod
    def analyze(path: Path) -> Dict[str, Any]:
        if ELFFile is None:
            return {"available": False, "reason": "Install optional dependency: pip install pyelftools"}

        result: Dict[str, Any] = {"available": True}
        try:
            with path.open("rb") as f:
                elf = ELFFile(f)
                result["elfclass"] = elf.elfclass
                result["endianness"] = elf.little_endian and "little" or "big"
                result["machine"] = elf["e_machine"]
                result["type"] = elf["e_type"]
                result["entry"] = hex(elf["e_entry"])
                result["sections"] = ELFAnalyzer._sections(elf)
                result["imports"] = ELFAnalyzer._dynamic_symbols(elf, imported=True)
                result["exports"] = ELFAnalyzer._dynamic_symbols(elf, imported=False)
                result["needed_libraries"] = ELFAnalyzer._needed_libraries(elf)
        except Exception as e:
            result["error"] = repr(e)
        return result

    @staticmethod
    def _sections(elf: Any) -> List[Dict[str, Any]]:
        out = []
        for sec in elf.iter_sections():
            try:
                out.append({
                    "name": sec.name,
                    "type": sec["sh_type"],
                    "addr": hex(sec["sh_addr"]),
                    "size": int(sec["sh_size"]),
                    "flags": int(sec["sh_flags"]),
                })
            except Exception:
                continue
        return out

    @staticmethod
    def _dynamic_symbols(elf: Any, imported: bool) -> List[str]:
        out: List[str] = []
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            return out
        for sym in dynsym.iter_symbols():
            name = sym.name
            if not name:
                continue
            is_undef = sym["st_shndx"] == "SHN_UNDEF"
            if imported and is_undef:
                out.append(name)
            elif not imported and not is_undef:
                out.append(name)
        return out[:1000]

    @staticmethod
    def _needed_libraries(elf: Any) -> List[str]:
        out: List[str] = []
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is None:
            return out
        for tag in dynamic.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                out.append(tag.needed)
        return out


class ArchiveAnalyzer:
    @staticmethod
    def analyze(path: Path, max_entries: int = 300) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if path.suffix.lower() not in ARCHIVE_EXTENSIONS:
            return result
        if not zipfile.is_zipfile(path):
            return {"zip_like": False}
        try:
            with zipfile.ZipFile(path, "r") as zf:
                infos = zf.infolist()
                names = [i.filename for i in infos[:max_entries]]
                result.update({
                    "zip_like": True,
                    "entry_count": len(infos),
                    "entries_sample": names,
                    "apk_hint": ArchiveAnalyzer._apk_hint(names),
                    "ipa_hint": ArchiveAnalyzer._ipa_hint(names),
                })
        except Exception as e:
            result["error"] = repr(e)
        return result

    @staticmethod
    def _apk_hint(names: Sequence[str]) -> bool:
        needed = {"AndroidManifest.xml", "classes.dex"}
        return any(n in needed for n in names) or any(n.startswith("lib/") and n.endswith(".so") for n in names)

    @staticmethod
    def _ipa_hint(names: Sequence[str]) -> bool:
        return any(n.startswith("Payload/") and n.endswith(".app/") for n in names) or any(n.startswith("Payload/") for n in names)


# -----------------------------
# File analyzer
# -----------------------------

class FileAnalyzer:
    def __init__(self, root: Path, args: argparse.Namespace, log: Log) -> None:
        self.root = root
        self.args = args
        self.log = log
        self.max_file_bytes = int(args.max_file_mb * 1024 * 1024)
        self.string_scan_bytes = int(args.string_scan_mb * 1024 * 1024)

    def analyze(self, path: Path) -> Optional[FileReport]:
        errors: List[str] = []
        try:
            st = path.stat()
        except Exception as e:
            return FileReport(
                path=safe_relpath(path, self.root), size=0, sha256="", md5="",
                file_type="stat-error", entropy=None, extension=path.suffix.lower(),
                engine_hints={}, findings=[], strings_sample=[], metadata={}, errors=[repr(e)]
            )

        if st.st_size > self.max_file_bytes:
            if not self.args.include_large:
                return None

        if not self.args.all_files and not is_probably_interesting(path):
            return None

        rel = safe_relpath(path, self.root)
        metadata: Dict[str, Any] = {}
        strings: List[str] = []
        prefix = b""
        file_type = "Unknown"
        sha256 = ""
        md5 = ""
        ent: Optional[float] = None

        try:
            prefix = read_prefix(path)
            file_type = detect_magic(prefix, path)
        except Exception as e:
            errors.append(f"magic: {repr(e)}")

        try:
            sha256, md5 = hash_file(path)
        except Exception as e:
            errors.append(f"hash: {repr(e)}")

        try:
            ent = entropy_file(path)
        except Exception as e:
            errors.append(f"entropy: {repr(e)}")

        try:
            strings = extract_strings(path, max_bytes=self.string_scan_bytes, limit=self.args.max_strings)
        except Exception as e:
            errors.append(f"strings: {repr(e)}")

        # PE/ELF/archive metadata.
        if prefix.startswith(b"MZ"):
            metadata["pe"] = PEAnalyzer.analyze(path)
            # Add imports/exports into synthetic string pool for better rule matching.
            pe_meta = metadata.get("pe", {})
            for dll, funcs in pe_meta.get("imports", {}).items():
                strings.append(dll)
                strings.extend(funcs)
            strings.extend(pe_meta.get("exports", []))

        if prefix.startswith(b"\x7fELF"):
            metadata["elf"] = ELFAnalyzer.analyze(path)
            elf_meta = metadata.get("elf", {})
            strings.extend(elf_meta.get("imports", []))
            strings.extend(elf_meta.get("exports", []))
            strings.extend(elf_meta.get("needed_libraries", []))

        if path.suffix.lower() in ARCHIVE_EXTENSIONS:
            metadata["archive"] = ArchiveAnalyzer.analyze(path)
            archive_meta = metadata.get("archive", {})
            strings.extend(archive_meta.get("entries_sample", []))

        engine_hints = EngineDetector.detect(path, self.root, strings, file_type)
        findings = RuleMatcher.match(strings)

        # High-entropy heuristic for possible compression/packing/encryption.
        if ent is not None and ent >= 7.5 and path.suffix.lower() in BINARY_EXTENSIONS:
            findings.append(Finding(
                rule_id="high_entropy_binary_region",
                severity="low",
                description="High entropy in sampled bytes; may indicate compression, packing, encrypted asset data, or normal packed assets",
                evidence=[f"entropy={ent}"],
                tags=["entropy", "packing", "assets"],
            ))

        # Game-engine-specific context hints.
        metadata["triage_notes"] = self._triage_notes(path, file_type, engine_hints, findings, metadata)

        return FileReport(
            path=rel,
            size=st.st_size,
            sha256=sha256,
            md5=md5,
            file_type=file_type,
            entropy=ent,
            extension=path.suffix.lower(),
            engine_hints=engine_hints,
            findings=findings,
            strings_sample=self._curated_strings_sample(strings, findings),
            metadata=metadata,
            errors=errors,
        )

    @staticmethod
    def _curated_strings_sample(strings: Sequence[str], findings: Sequence[Finding]) -> List[str]:
        wanted = set()
        for f in findings:
            for e in f.evidence:
                wanted.add(e.lower())

        sample: List[str] = []
        for s in strings:
            sl = s.lower()
            if any(w in sl for w in wanted):
                sample.append(s[:240])
            if len(sample) >= 60:
                return sample

        # Fallback to useful-looking strings.
        keywords = [
            "unity", "unreal", "godot", "cocos", "engine", "script", "asset",
            "http", "socket", "debug", "anti", "driver", "kernel", "metadata",
        ]
        for s in strings:
            sl = s.lower()
            if any(k in sl for k in keywords):
                sample.append(s[:240])
            if len(sample) >= 60:
                break
        return sample

    @staticmethod
    def _triage_notes(
        path: Path,
        file_type: str,
        engine_hints: Dict[str, int],
        findings: Sequence[Finding],
        metadata: Dict[str, Any],
    ) -> List[str]:
        notes: List[str] = []
        ext = path.suffix.lower()
        name = path.name.lower()

        if engine_hints:
            best_engine, score = next(iter(engine_hints.items()))
            if score >= 8:
                notes.append(f"Strong {best_engine} indicator; prioritize engine-specific asset and script review.")
            elif score >= 4:
                notes.append(f"Possible {best_engine} indicator; verify with surrounding directory context.")

        if name == "global-metadata.dat":
            notes.append("Unity IL2CPP metadata file; correlate with GameAssembly/libil2cpp for managed type and method recovery.")
        if name in {"gameassembly.dll", "libil2cpp.so"}:
            notes.append("Unity IL2CPP runtime binary; useful for static symbol/string triage and metadata correlation.")
        if ext in {".pak", ".ucas", ".utoc"}:
            notes.append("Unreal packaged asset container; review asset registry and packaging settings before deep extraction.")
        if ext in {".pck"}:
            notes.append("Godot packed game data; review project metadata and exported scripts/assets where authorized.")
        if ext in {".lua", ".luac", ".jsc"}:
            notes.append("Script-like asset; inspect for debug commands, admin paths, unsafe eval/load behavior, or plaintext secrets.")

        severities = Counter(f.severity for f in findings)
        if severities.get("high"):
            notes.append("High-severity API indicators found; verify whether they are legitimate engine/runtime dependencies or custom security-sensitive code.")
        if metadata.get("pe", {}).get("overlay_size", 0) > 1024 * 1024:
            notes.append("Large PE overlay detected; may be installer data, packed payload, appended assets, or benign overlay.")
        if metadata.get("pe", {}).get("is_dotnet_hint"):
            notes.append(".NET/CLR hint detected; managed decompilation may be more productive than native disassembly.")

        if not notes:
            notes.append("No immediate engine/security-specific triage note generated.")
        return notes


# -----------------------------
# Report generation
# -----------------------------

class ReportBuilder:
    @staticmethod
    def build(root: Path, started_at: str, finished_at: str, files_seen: int, skipped: int, reports: List[FileReport]) -> ScanReport:
        engine_scores: Dict[str, int] = defaultdict(int)
        severity_counts: Dict[str, int] = defaultdict(int)
        finding_counts: Dict[str, int] = defaultdict(int)
        total_bytes = 0

        for fr in reports:
            total_bytes += fr.size
            for engine, score in fr.engine_hints.items():
                engine_scores[engine] += score
            for finding in fr.findings:
                severity_counts[finding.severity] += 1
                finding_counts[finding.rule_id] += 1

        summary = ScanSummary(
            root=str(root),
            started_at=started_at,
            finished_at=finished_at,
            files_seen=files_seen,
            files_analyzed=len(reports),
            files_skipped=skipped,
            total_bytes_analyzed=total_bytes,
            engine_scores=dict(sorted(engine_scores.items(), key=lambda kv: kv[1], reverse=True)),
            severity_counts=dict(sorted(severity_counts.items())),
            top_findings=dict(sorted(finding_counts.items(), key=lambda kv: kv[1], reverse=True)),
        )
        return ScanReport(summary=summary, files=reports)

    @staticmethod
    def to_json(report: ScanReport) -> str:
        def convert(obj: Any) -> Any:
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
        return json.dumps(report, ensure_ascii=False, indent=2, default=convert)

    @staticmethod
    def to_markdown(report: ScanReport, top_n: int = 80) -> str:
        s = report.summary
        lines: List[str] = []
        lines.append("# Game Engine Reverse & Security Analysis Report")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Root: `{s.root}`")
        lines.append(f"- Started: `{s.started_at}`")
        lines.append(f"- Finished: `{s.finished_at}`")
        lines.append(f"- Files seen: **{s.files_seen}**")
        lines.append(f"- Files analyzed: **{s.files_analyzed}**")
        lines.append(f"- Files skipped: **{s.files_skipped}**")
        lines.append(f"- Bytes analyzed: **{s.total_bytes_analyzed:,}**")
        lines.append("")

        lines.append("## Engine Fingerprint Scores")
        lines.append("")
        if s.engine_scores:
            lines.append("| Engine | Score |")
            lines.append("|---|---:|")
            for engine, score in s.engine_scores.items():
                lines.append(f"| {engine} | {score} |")
        else:
            lines.append("No strong engine fingerprint detected.")
        lines.append("")

        lines.append("## Finding Severity Counts")
        lines.append("")
        if s.severity_counts:
            lines.append("| Severity | Count |")
            lines.append("|---|---:|")
            for sev in ["high", "medium", "low"]:
                if sev in s.severity_counts:
                    lines.append(f"| {sev} | {s.severity_counts[sev]} |")
        else:
            lines.append("No rule findings detected.")
        lines.append("")

        lines.append("## Top Rule Hits")
        lines.append("")
        if s.top_findings:
            lines.append("| Rule | Count |")
            lines.append("|---|---:|")
            for rule, count in list(s.top_findings.items())[:20]:
                lines.append(f"| `{rule}` | {count} |")
        else:
            lines.append("No rule hits.")
        lines.append("")

        prioritized = ReportBuilder._prioritize_files(report.files)
        lines.append(f"## Prioritized Files, Top {min(top_n, len(prioritized))}")
        lines.append("")
        for idx, fr in enumerate(prioritized[:top_n], 1):
            lines.extend(ReportBuilder._file_section(idx, fr))
            lines.append("")

        lines.append("## Review Guidance")
        lines.append("")
        lines.append("- Treat rule hits as triage signals, not proof of malicious behavior.")
        lines.append("- For Unity IL2CPP, correlate `global-metadata.dat` with `GameAssembly.dll` or `libil2cpp.so`.")
        lines.append("- For Unreal, correlate `.pak/.ucas/.utoc` with `AssetRegistry.bin` and build configuration artifacts.")
        lines.append("- Confirm authorization before extracting proprietary assets or decompiling managed code.")
        lines.append("- Prioritize custom game binaries/scripts over standard engine runtime files when assessing security risk.")
        return "\n".join(lines)

    @staticmethod
    def _prioritize_files(files: Sequence[FileReport]) -> List[FileReport]:
        sev_weight = {"high": 100, "medium": 30, "low": 8}

        def score(fr: FileReport) -> Tuple[int, int, int]:
            finding_score = sum(sev_weight.get(f.severity, 1) for f in fr.findings)
            engine_score = sum(fr.engine_hints.values())
            meta_score = 0
            if fr.metadata.get("pe") or fr.metadata.get("elf"):
                meta_score += 10
            if fr.extension in {".dll", ".exe", ".so", ".pak", ".ucas", ".utoc", ".pck", ".assets"}:
                meta_score += 5
            return (finding_score + engine_score + meta_score, finding_score, fr.size)

        return sorted(files, key=score, reverse=True)

    @staticmethod
    def _file_section(idx: int, fr: FileReport) -> List[str]:
        lines: List[str] = []
        lines.append(f"### {idx}. `{fr.path}`")
        lines.append("")
        lines.append(f"- Type: `{fr.file_type}`")
        lines.append(f"- Size: `{fr.size:,}` bytes")
        lines.append(f"- SHA256: `{fr.sha256}`")
        lines.append(f"- Entropy(sampled): `{fr.entropy}`")
        if fr.engine_hints:
            hints = ", ".join(f"{k}={v}" for k, v in list(fr.engine_hints.items())[:5])
            lines.append(f"- Engine hints: {hints}")

        notes = fr.metadata.get("triage_notes", [])
        if notes:
            lines.append("- Triage notes:")
            for note in notes[:6]:
                lines.append(f"  - {note}")

        if fr.findings:
            lines.append("")
            lines.append("Findings:")
            for finding in fr.findings:
                ev = ", ".join(f"`{e}`" for e in finding.evidence[:15])
                more = "" if len(finding.evidence) <= 15 else f" ... +{len(finding.evidence)-15} more"
                lines.append(f"- **{finding.severity}** `{finding.rule_id}`: {finding.description}. Evidence: {ev}{more}")

        pe = fr.metadata.get("pe")
        if isinstance(pe, dict) and pe.get("available"):
            lines.append("")
            lines.append("PE metadata:")
            lines.append(f"- Timestamp: `{pe.get('timestamp')}`")
            lines.append(f"- Machine: `{pe.get('machine')}`")
            lines.append(f"- Entry point: `{pe.get('entry_point')}`")
            lines.append(f"- Signed security directory: `{pe.get('signing', {}).get('has_security_directory')}`")
            lines.append(f"- Overlay size: `{pe.get('overlay_size')}`")
            imports = pe.get("imports", {})
            if imports:
                dlls = ", ".join(list(imports.keys())[:12])
                lines.append(f"- Imported DLLs sample: {dlls}")

        elf = fr.metadata.get("elf")
        if isinstance(elf, dict) and elf.get("available"):
            lines.append("")
            lines.append("ELF metadata:")
            lines.append(f"- Class: `{elf.get('elfclass')}`")
            lines.append(f"- Machine: `{elf.get('machine')}`")
            lines.append(f"- Type: `{elf.get('type')}`")
            needed = elf.get("needed_libraries", [])
            if needed:
                lines.append(f"- Needed libs: {', '.join(needed[:20])}")

        archive = fr.metadata.get("archive")
        if isinstance(archive, dict) and archive.get("zip_like"):
            lines.append("")
            lines.append("Archive metadata:")
            lines.append(f"- Entries: `{archive.get('entry_count')}`")
            lines.append(f"- APK hint: `{archive.get('apk_hint')}`")
            lines.append(f"- IPA hint: `{archive.get('ipa_hint')}`")

        if fr.strings_sample:
            lines.append("")
            lines.append("String sample:")
            for ss in fr.strings_sample[:15]:
                lines.append(f"- `{ReportBuilder._escape_inline_code(ss)}`")

        if fr.errors:
            lines.append("")
            lines.append("Errors:")
            for e in fr.errors:
                lines.append(f"- `{ReportBuilder._escape_inline_code(e)}`")
        return lines

    @staticmethod
    def _escape_inline_code(s: str) -> str:
        return s.replace("`", "\\`").replace("\n", "\\n")[:300]


# -----------------------------
# Agent orchestration
# -----------------------------

class GameEngineSecurityAgent:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.log = Log(verbose=args.verbose)

    def scan(self, target: Path) -> ScanReport:
        target = target.expanduser().resolve()
        if not target.exists():
            raise AgentError(f"Target not found: {target}")

        root = target if target.is_dir() else target.parent
        started = _dt.datetime.utcnow().isoformat() + "Z"

        ignore_dirs = list(DEFAULT_IGNORE_DIRS)
        if self.args.no_ignore:
            ignore_dirs = []
        if self.args.ignore_dir:
            ignore_dirs.extend(self.args.ignore_dir)

        files = list(iter_files(target, ignore_dirs=ignore_dirs))
        files_seen = len(files)
        self.log.info(f"Files discovered: {files_seen}")

        analyzer = FileAnalyzer(root=root, args=self.args, log=self.log)
        reports: List[FileReport] = []
        skipped = 0

        iterable: Iterable[Path]
        if track and not self.args.no_progress:
            iterable = track(files, description="Analyzing files...")
        else:
            iterable = files

        if self.args.workers <= 1:
            for p in iterable:
                fr = analyzer.analyze(p)
                if fr is None:
                    skipped += 1
                else:
                    reports.append(fr)
        else:
            # Keep progress simple: submit all then collect. Analyzer is stateless enough for threads.
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as ex:
                future_to_path = {ex.submit(analyzer.analyze, p): p for p in files}
                futures_iter: Iterable[concurrent.futures.Future[Optional[FileReport]]]
                if track and not self.args.no_progress:
                    futures_iter = track(concurrent.futures.as_completed(future_to_path), total=len(future_to_path), description="Analyzing files...")
                else:
                    futures_iter = concurrent.futures.as_completed(future_to_path)
                for fut in futures_iter:
                    try:
                        fr = fut.result()
                        if fr is None:
                            skipped += 1
                        else:
                            reports.append(fr)
                    except Exception as e:
                        p = future_to_path[fut]
                        skipped += 1
                        self.log.warn(f"Failed to analyze {p}: {e!r}")

        finished = _dt.datetime.utcnow().isoformat() + "Z"
        report = ReportBuilder.build(
            root=root,
            started_at=started,
            finished_at=finished,
            files_seen=files_seen,
            skipped=skipped,
            reports=reports,
        )
        return report


# -----------------------------
# CLI
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ge_security_agent.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Local static analysis agent for game-engine reverse engineering and security review.",
        epilog=textwrap.dedent(
            """
            Examples:
              python ge_security_agent.py scan ./GameFolder --out report.md --json report.json
              python ge_security_agent.py scan ./GameAssembly.dll --deep --max-file-mb 512
              python ge_security_agent.py scan ./apk_or_game.apk --all-files --workers 4
            """
        ),
    )

    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a file or directory")
    scan.add_argument("target", help="File or directory to scan")
    scan.add_argument("--out", default="game_engine_security_report.md", help="Markdown report output path")
    scan.add_argument("--json", default=None, help="Optional JSON report output path")
    scan.add_argument("--max-file-mb", type=float, default=256, help="Skip files larger than this unless --include-large is set")
    scan.add_argument("--include-large", action="store_true", help="Analyze files even when larger than --max-file-mb")
    scan.add_argument("--string-scan-mb", type=float, default=32, help="Bytes per file to scan for strings, in MB")
    scan.add_argument("--max-strings", type=int, default=5000, help="Max extracted strings per file")
    scan.add_argument("--all-files", action="store_true", help="Analyze all file extensions instead of known-interesting files")
    scan.add_argument("--deep", action="store_true", help="Convenience flag: larger string scan and include large files")
    scan.add_argument("--workers", type=int, default=1, help="Parallel worker threads")
    scan.add_argument("--ignore-dir", action="append", default=[], help="Additional directory name to ignore; can be repeated")
    scan.add_argument("--no-ignore", action="store_true", help="Do not use default ignored directories")
    scan.add_argument("--no-progress", action="store_true", help="Disable progress display")
    scan.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")

    return p


def apply_deep_defaults(args: argparse.Namespace) -> None:
    if getattr(args, "deep", False):
        args.include_large = True
        args.string_scan_mb = max(args.string_scan_mb, 128)
        args.max_strings = max(args.max_strings, 20000)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    apply_deep_defaults(args)

    if args.command == "scan":
        agent = GameEngineSecurityAgent(args)
        try:
            report = agent.scan(Path(args.target))
        except AgentError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

        md = ReportBuilder.to_markdown(report)
        out_path = Path(args.out).expanduser().resolve()
        out_path.write_text(md, encoding="utf-8")
        print(f"[+] Markdown report written: {out_path}")

        if args.json:
            json_path = Path(args.json).expanduser().resolve()
            json_path.write_text(ReportBuilder.to_json(report), encoding="utf-8")
            print(f"[+] JSON report written: {json_path}")

        # Print short console summary.
        s = report.summary
        print("\n=== Summary ===")
        print(f"Files seen:      {s.files_seen}")
        print(f"Files analyzed:  {s.files_analyzed}")
        print(f"Files skipped:   {s.files_skipped}")
        print(f"Engine scores:   {s.engine_scores or {}}")
        print(f"Severity counts: {s.severity_counts or {}}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
