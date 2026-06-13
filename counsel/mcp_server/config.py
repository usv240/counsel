"""
COUNSEL MCP Server configuration.

All paths and tool locations are driven by environment or a config file.
Nothing is hardcoded. On SIFT Workstation, SIFT tool paths are auto-detected.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolPaths:
    """Paths to forensic binaries on the analysis workstation."""
    # Eric Zimmerman Tools (SIFT Workstation paths)
    recmd: str = ""           # RECmd.exe / rla.exe
    pecmd: str = ""           # PECmd.exe (Prefetch)
    amcache_parser: str = ""  # AmcacheParser.exe
    mft_ecmd: str = ""        # MFTECmd.exe

    # Memory analysis
    volatility: str = ""      # vol.py / vol3

    # Network analysis
    tshark: str = ""          # tshark
    zeek: str = ""            # zeek

    # YARA
    yara: str = ""            # yara

    # Event log analysis
    evtx_dump: str = ""       # evtx_dump / python-evtx

    def __post_init__(self) -> None:
        self._auto_detect()

    def _auto_detect(self) -> None:
        """Auto-detect tool binaries from PATH and known SIFT locations."""
        candidates = {
            "recmd": [
                # SIFT shell wrappers (preferred - no mono needed)
                "rla", "RECmd",
                # SIFT absolute .exe paths (run via mono auto-detected in run_tool_subprocess)
                "/usr/share/doc/recmd/rla.exe", "/opt/SIFT/bin/rla.exe",
                "RECmd.exe", "rla.exe",
            ],
            "pecmd": [
                "PECmd",
                "/usr/share/doc/pecmd/PECmd.exe", "/opt/SIFT/bin/PECmd.exe",
                "PECmd.exe",
            ],
            "amcache_parser": [
                "AmcacheParser",
                "/usr/share/doc/amcacheparser/AmcacheParser.exe",
                "AmcacheParser.exe",
            ],
            "mft_ecmd": [
                "MFTECmd",
                "/usr/share/doc/mftecmd/MFTECmd.exe", "MFTECmd.exe",
            ],
            "volatility": [
                "vol3", "vol", "volatility3", "volatility",
                os.path.expanduser("~/.local/bin/vol3"),
                os.path.expanduser("~/.local/bin/vol"),
                "/usr/local/bin/vol3", "/opt/SIFT/bin/vol3",
            ],
            "tshark": ["tshark", "/usr/bin/tshark"],
            "zeek": ["zeek", "/usr/local/zeek/bin/zeek"],
            "yara": ["yara", "/usr/bin/yara"],
            "evtx_dump": [
                "evtx_dump", "evtxdump",
                os.path.expanduser("~/.local/bin/evtx_dump"),
                "/usr/local/bin/evtx_dump",
            ],
        }
        for attr, paths in candidates.items():
            if getattr(self, attr):
                continue  # already set by env/config
            for p in paths:
                found = shutil.which(p)
                if found:
                    setattr(self, attr, found)
                    break


@dataclass
class ServerConfig:
    """Top-level configuration for the COUNSEL MCP server."""
    # Required: evidence root (read-only mount)
    evidence_root: Path = field(default_factory=lambda: Path(
        os.environ.get("COUNSEL_EVIDENCE_ROOT", "/mnt/evidence")
    ))

    # Run identifiers
    run_id: str = field(default_factory=lambda: os.environ.get("COUNSEL_RUN_ID", ""))

    # Ledger path
    ledger_path: Path = field(default_factory=lambda: Path(
        os.environ.get("COUNSEL_LEDGER_PATH", "/tmp/counsel-ledger.jsonl")
    ))

    # Corroboration rules directory
    rules_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("COUNSEL_RULES_DIR", str(Path(__file__).parent.parent / "rules"))
    ))

    # Tool paths (auto-detected if not set)
    tools: ToolPaths = field(default_factory=ToolPaths)

    # Parse limits
    max_records_per_call: int = int(os.environ.get("COUNSEL_MAX_RECORDS", "200"))
    max_string_length: int = int(os.environ.get("COUNSEL_MAX_STRING_LEN", "512"))
    tool_timeout_seconds: int = int(os.environ.get("COUNSEL_TOOL_TIMEOUT", "120"))

    # Evidence integrity
    evidence_sha256: str = os.environ.get("COUNSEL_EVIDENCE_SHA256", "")

    def validate(self) -> list[str]:
        """Return list of validation errors (empty = config is valid)."""
        errors = []
        if not self.evidence_root.exists():
            errors.append(f"evidence_root does not exist: {self.evidence_root}")
        if not self.run_id:
            errors.append("COUNSEL_RUN_ID must be set")
        return errors

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Build config entirely from environment variables."""
        return cls()
