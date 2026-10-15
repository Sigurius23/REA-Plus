"""Provider catalog for AERE.

The catalog distinguishes shipped built-ins from external tools and bridges.
Presence on PATH is not treated as proof of compatibility or support.
"""

from __future__ import annotations

import os
import shutil
from typing import Any


_EXTERNAL = [
    {
        "id": "ghidra.mcp",
        "name": "Ghidra + Ghidra MCP",
        "role": "native static analysis / agent bridge",
        "status": "external-not-connected",
        "upstream": "https://github.com/NationalSecurityAgency/ghidra",
        "bridge": "https://github.com/bethington/ghidra-mcp",
        "capabilities": ["disassembly", "decompilation", "functions", "references"],
        "limitations": ["AERE v0.2 does not invoke or connect to this provider."],
    },
    {
        "id": "ida.hexrays.mcp",
        "name": "IDA + official Hex-Rays MCP",
        "role": "native static analysis / agent bridge",
        "status": "external-not-connected",
        "upstream": "https://hex-rays.com/ida-pro",
        "bridge": "https://github.com/HexRaysSA/ida-mcp",
        "capabilities": ["disassembly", "decompilation where licensed", "IDAPython", "database analysis"],
        "limitations": ["AERE v0.2 does not invoke or connect to this provider."],
    },
    {
        "id": "binaryninja.mcp",
        "name": "Binary Ninja first-party MCP",
        "role": "native static analysis / agent bridge",
        "status": "external-not-connected",
        "upstream": "https://binary.ninja/",
        "bridge": "https://docs.binary.ninja/guide/mcp.html",
        "capabilities": ["functions", "disassembly", "IL", "decompiled text", "references"],
        "limitations": ["AERE v0.2 does not invoke or connect to this provider; edition and OS affect MCP availability."],
    },
    {
        "id": "hopper.mcp",
        "name": "Hopper built-in MCP",
        "role": "native static analysis / agent bridge",
        "status": "external-not-connected",
        "upstream": "https://www.hopperapp.com/",
        "bridge": "https://www.hopperapp.com/faq.html",
        "capabilities": ["disassembly", "pseudocode", "debugging", "scripting"],
        "limitations": ["AERE v0.2 does not invoke or connect to this provider; target/platform/licensing limits apply."],
    },
    {
        "id": "radare2.mcp",
        "name": "radare2 + radare2-mcp",
        "role": "native static analysis / agent bridge",
        "status": "external-not-connected",
        "upstream": "https://github.com/radareorg/radare2",
        "bridge": "https://github.com/radareorg/radare2-mcp",
        "capabilities": ["binary inspection", "disassembly", "agent bridge"],
        "limitations": ["AERE v0.2 does not invoke or connect to this provider."],
    },
]

_TOOLS = {
    "jadx": ("Android DEX/APK decompiler", "https://github.com/skylot/jadx"),
    "apktool": ("Android resources and Smali", "https://github.com/iBotPeaches/Apktool"),
    "adb": ("Android device bridge", "https://developer.android.com/tools/adb"),
    "ilspycmd": (".NET CLI decompiler", "https://github.com/icsharpcode/ILSpy"),
    "cfr": ("JVM bytecode decompiler", "https://github.com/leibnitz27/cfr"),
    "java": ("JDK runtime", "https://adoptium.net/"),
    "gdb": ("Native debugger (not connected)", "https://www.sourceware.org/gdb/"),
    "lldb": ("Native debugger (not connected)", "https://lldb.llvm.org/"),
    "frida": ("Runtime instrumentation CLI (not connected)", "https://github.com/frida/frida"),
    "r2": ("radare2 CLI (not connected)", "https://github.com/radareorg/radare2"),
    "ghidraRun": ("Ghidra launcher", "https://github.com/NationalSecurityAgency/ghidra"),
    "analyzeHeadless": ("Ghidra headless analyzer", "https://github.com/NationalSecurityAgency/ghidra"),
}


def catalog() -> list[dict[str, Any]]:
    """Return implementation status and non-invasive tool discovery.

    Discovery checks PATH or an explicitly configured path. It never launches
    the discovered program, parses a target, or treats presence as a verified
    adapter.
    """
    entries: list[dict[str, Any]] = [
        {
            "id": "builtin.probe",
            "name": "AERE static format probe",
            "role": "built-in read-only triage",
            "status": "implemented",
            "available": True,
            "capabilities": ["bounded magic identification", "ZIP metadata classification"],
            "limitations": ["A file signature is a candidate classification, not proof of engine or behavior."],
        },
        {
            "id": "builtin.strings.ascii",
            "name": "AERE bounded ASCII strings",
            "role": "built-in read-only triage",
            "status": "implemented",
            "available": True,
            "capabilities": ["bounded printable ASCII extraction", "byte offsets", "secret-like value redaction"],
            "limitations": ["No UTF-16 extraction, semantic string decoding, or decompilation."],
        },
        {
            "id": "builtin.zip.metadata",
            "name": "AERE ZIP central-directory listing",
            "role": "built-in read-only triage",
            "status": "implemented",
            "available": True,
            "capabilities": ["archive member names and metadata", "unsafe path flags"],
            "limitations": ["The metadata-only listing does not read member contents."],
        },
        {
            "id": "builtin.android.apk",
            "name": "AERE Android APK structure inspector",
            "role": "built-in read-only package analysis",
            "status": "implemented",
            "available": True,
            "capabilities": ["text/binary Android manifest fields", "bounded DEX identifier tables", "APK member index", "optional capped in-memory raster previews"],
            "limitations": ["No JADX/Apktool decompilation, resource-table resolution, signature verification, device access, runtime instrumentation, or proprietary texture decoding."],
        },
        {
            "id": "builtin.steam.install",
            "name": "AERE Steam install and VPK inspector",
            "role": "built-in read-only game-install analysis",
            "status": "implemented",
            "available": True,
            "capabilities": ["Steam appmanifest VDF parsing", "bounded approved-root file inventory", "heuristic engine candidates", "VPK v1/v2 directory-tree metadata", "optional capped loose-image previews"],
            "limitations": ["No game execution, VPK/PAK/Unity/Godot member extraction, proprietary texture decoding, or title/build compatibility certification."],
        },
    ]
    for command, (description, upstream) in _TOOLS.items():
        configured = os.environ.get(f"AERE_TOOL_{command.upper()}")
        resolved = configured if configured and os.path.isfile(configured) else shutil.which(command)
        entries.append(
            {
                "id": f"tool.{command}",
                "name": command,
                "role": description,
                "status": "discovered-not-integrated" if resolved else "not-found",
                "present_on_path": bool(resolved),
                "adapter_connected": False,
                "verified": False,
                "resolved_path": resolved,
                "upstream": upstream,
                "limitations": ["Tool presence is not a verified or connected AERE provider."],
            }
        )
    entries.extend(_EXTERNAL)
    return entries
