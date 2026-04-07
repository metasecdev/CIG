# Threat Hunting Automation — Implementation Plan

## Metadata

- **Date:** 2026-04-07
- **Project:** Cyber Intelligence Gateway (CIG) — Phase C Threat Hunting
- **Phase:** C (Threat Hunting)
- **Status:** Planning

---

## Overview

This plan covers four implementation items:

1. **Signature Hunting Workflow** — YARA/ATT&CK output scanning captured network data
2. **Sigma Rules to CIG Detection** — wire CIGSignatureDeliverer to call ThreatMatcher API, add rules endpoints
3. **Phase C Playbook Automation** — executable hunt playbooks via API
4. **Deprecation Fixes** — swap `datetime.utcnow()` for `datetime.now(datetime.UTC)`

Each phase is structured as a checklist that can be executed step by step.

---

## Phase 1: Signature Hunting Workflow

**Goal:** Create a `HuntRunner` class that uses YARA/ATT&CK output to scan captured network data (PCAPs, DNS logs, HTTP logs).

### Step 1.1 — Create HuntRunner class

Create `/Users/wo/code/app/malware/hunt_runner.py`:

```python
"""HuntRunner — executes hunt queries against captured network data."""

import logging
import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import uuid

from app.malware.results import IOC
from app.malware.plugins.attack_mapper import ATTACKMapper
from app.capture.pcap import PacketAnalyzer
from app.models.database import Database

logger = logging.getLogger(__name__)


@dataclass
class HuntQuery:
    """A single hunt query to execute."""
    data_source: str  # "pcap", "dns_logs", "http_logs", "alert_history"
    query: str  # BPF filter, YARA rule, or SQL predicate
    query_type: str  # "bpf", "yara", "sql", "pattern"
    purpose: str = ""


@dataclass
class HuntResult:
    """Result from a single hunt query."""
    query: HuntQuery
    matches: List[Dict[str, Any]]
    match_count: int
    executed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    errors: List[str] = field(default_factory=list)


@dataclass
class HuntReport:
    """Complete hunt execution report."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str = ""
    hypothesis: str = ""
    techniques: List[str] = field(default_factory=list)
    results: List[HuntResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    executed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    total_matches: int = 0


class HuntRunner:
    """Executes hunt playbooks against captured network data."""

    def __init__(self, db: Database, pcap_dir: str = "data/pcaps",
                 dns_log_dir: str = "data/logs/dns",
                 http_log_dir: str = "data/logs/http"):
        self.db = db
        self.pcap_dir = Path(pcap_dir)
        self.dns_log_dir = Path(dns_log_dir)
        self.http_log_dir = Path(http_log_dir)
        self.packet_analyzer = PacketAnalyzer(db)
        self.attack_mapper = ATTACKMapper()

    # -------------------------------------------------------------------------
    # ATT&CK technique -> hunt query mapping
    # -------------------------------------------------------------------------

    def get_queries_for_technique(self, technique_id: str) -> List[HuntQuery]:
        """Return hunt queries for a given ATT&CK technique ID."""
        query_map = {
            "T1059": [  # PowerShell C2
                HuntQuery(
                    data_source="pcap",
                    query="dns and query contains \"powershell\"",
                    query_type="bpf",
                    purpose="Find DNS queries for PowerShell-related domains"
                ),
                HuntQuery(
                    data_source="pcap",
                    query='http and user-agent contains "powershell"',
                    query_type="bpf",
                    purpose="Find HTTP requests from PowerShell"
                ),
                HuntQuery(
                    data_source="dns_logs",
                    query=r"[a-z0-9]{8,16}\.[a-z]{2,6}",
                    query_type="pattern",
                    purpose="Detect domain generation algorithms (DGA)"
                ),
            ],
            "T1055": [  # Process Injection
                HuntQuery(
                    data_source="pcap",
                    query='http.request.uri contains ".dll"',
                    query_type="bpf",
                    purpose="Find DLL download requests"
                ),
                HuntQuery(
                    data_source="pcap",
                    query="tcp.flags.push and tcp.window_size < 1000",
                    query_type="bpf",
                    purpose="Detect potential hollow process behavior"
                ),
            ],
            "T1027": [  # Obfuscated File Delivery
                HuntQuery(
                    data_source="pcap",
                    query='http.content_type contains "octet-stream"',
                    query_type="bpf",
                    purpose="Find binary file downloads"
                ),
                HuntQuery(
                    data_source="pcap",
                    query="[A-Za-z0-9+/]{100,}={0,2}$",
                    query_type="yara",
                    purpose="Detect base64-encoded content"
                ),
            ],
            "T1218": [  # Rundll32 Execution
                HuntQuery(
                    data_source="pcap",
                    query='tcp and (http contains "rundll32" or http contains "DLL")',
                    query_type="bpf",
                    purpose="Find rundll32 network activity"
                ),
                HuntQuery(
                    data_source="http_logs",
                    query="rundll32",
                    query_type="pattern",
                    purpose="Detect rundll32 User-Agent"
                ),
            ],
            "T1071": [  # Application Layer Protocol (C2)
                HuntQuery(
                    data_source="dns_logs",
                    query="dynamic dns",
                    query_type="pattern",
                    purpose="Detect dynamic DNS C2"
                ),
            ],
        }
        return query_map.get(technique_id, [])

    # -------------------------------------------------------------------------
    # Query execution
    # -------------------------------------------------------------------------

    def execute_bpf_query(self, bpf_filter: str, pcap_paths: List[Path]) -> List[Dict[str, Any]]:
        """Execute a BPF filter against PCAP files using tcpdump."""
        matches = []
        for pcap_path in pcap_paths:
            if not pcap_path.exists():
                continue
            try:
                cmd = ["tcpdump", "-r", str(pcap_path), "-n", bpf_filter, "-v"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0 and result.stdout.strip():
                    # Parse tcpdump output lines
                    for line in result.stdout.splitlines():
                        matches.append({
                            "pcap": str(pcap_path),
                            "match": line.strip(),
                            "source": "tcpdump"
                        })
            except subprocess.TimeoutExpired:
                logger.warning(f"tcpdump timeout on {pcap_path}")
            except Exception as e:
                logger.error(f"tcpdump error on {pcap_path}: {e}")
        return matches

    def execute_yara_query(self, yara_rule: str, pcap_paths: List[Path]) -> List[Dict[str, Any]]:
        """Execute a YARA rule against PCAP files."""
        matches = []
        try:
            import yara
            for pcap_path in pcap_paths:
                if not pcap_path.exists():
                    continue
                try:
                    # Compile inline YARA rule
                    rules = yara.compile(source=yara_rule)
                    # Scan the PCAP file
                    for match in rules.match(str(pcap_path)):
                        matches.append({
                            "pcap": str(pcap_path),
                            "rule": match.rule,
                            "strings": [str(s) for s in match.strings],
                            "source": "yara"
                        })
                except Exception as e:
                    logger.error(f"YARA scan error on {pcap_path}: {e}")
        except ImportError:
            logger.warning("yara-python not installed; YARA scanning unavailable")
        return matches

    def execute_pattern_query(self, pattern: str, log_dir: Path,
                               file_pattern: str = "*.jsonl") -> List[Dict[str, Any]]:
        """Execute a regex pattern against log files in a directory."""
        matches = []
        regex = re.compile(pattern)
        for log_file in log_dir.glob(file_pattern):
            try:
                with open(log_file, "r") as f:
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            try:
                                log_entry = json.loads(line)
                                log_entry["_log_file"] = str(log_file)
                                log_entry["_line_num"] = line_num
                                matches.append(log_entry)
                            except json.JSONDecodeError:
                                matches.append({
                                    "_log_file": str(log_file),
                                    "_line_num": line_num,
                                    "_raw": line.strip()
                                })
            except Exception as e:
                logger.error(f"Pattern query error on {log_file}: {e}")
        return matches

    def execute_sql_query(self, sql_predicate: str) -> List[Dict[str, Any]]:
        """Execute a SQL predicate against the alert history."""
        matches = []
        try:
            conn = self.db.db_path if hasattr(self.db, 'db_path') else self.db
            import sqlite3
            with sqlite3.connect(conn) as c:
                # Build the full query
                query = f"SELECT * FROM alerts WHERE {sql_predicate} LIMIT 1000"
                cursor = c.execute(query)
                columns = [desc[0] for desc in cursor.description]
                for row in cursor.fetchall():
                    matches.append(dict(zip(columns, row)))
        except Exception as e:
            logger.error(f"SQL query error: {e}")
        return matches

    def get_pcap_files(self, since: Optional[datetime] = None) -> List[Path]:
        """Get all PCAP files, optionally filtered by start time."""
        if not self.pcap_dir.exists():
            return []
        pcap_files = list(self.pcap_dir.glob("*.pcap"))
        pcap_files += list(self.pcap_dir.glob("*.pcap.gz"))
        return sorted(pcap_files, key=lambda p: p.stat().st_mtime, reverse=True)

    # -------------------------------------------------------------------------
    # Full hunt execution
    # -------------------------------------------------------------------------

    def run_hunt(self, playbook: "HuntPlaybook") -> HuntReport:
        """Execute a complete hunt playbook and return a report."""
        report = HuntReport(
            playbook_id=playbook.id,
            hypothesis=playbook.hypothesis.get("statement", ""),
            techniques=[t.get("technique_id", "") for t in playbook.ttps]
        )

        all_pcaps = self.get_pcap_files()

        for ttp in playbook.ttps:
            technique_id = ttp.get("technique_id", "")
            hunt_queries = ttp.get("hunt_queries", [])

            # If no explicit queries, use the technique map defaults
            if not hunt_queries:
                hunt_queries = self.get_queries_for_technique(technique_id)

            for hq in hunt_queries:
                result = HuntResult(query=hq, matches=[], match_count=0)

                try:
                    if hq.query_type == "bpf":
                        result.matches = self.execute_bpf_query(hq.query, all_pcaps)
                    elif hq.query_type == "yara":
                        result.matches = self.execute_yara_query(hq.query, all_pcaps)
                    elif hq.query_type == "pattern":
                        if hq.data_source == "dns_logs":
                            result.matches = self.execute_pattern_query(
                                hq.query, self.dns_log_dir
                            )
                        elif hq.data_source == "http_logs":
                            result.matches = self.execute_pattern_query(
                                hq.query, self.http_log_dir
                            )
                    elif hq.query_type == "sql":
                        result.matches = self.execute_sql_query(hq.query)

                    result.match_count = len(result.matches)
                    report.total_matches += result.match_count

                    if result.matches:
                        report.findings.append({
                            "technique_id": technique_id,
                            "purpose": hq.purpose,
                            "matches": result.matches[:10],  # First 10 for brevity
                            "total": result.match_count
                        })

                except Exception as e:
                    result.errors.append(str(e))
                    logger.error(f"Hunt query error ({technique_id}): {e}")

                report.results.append(result)

        return report


# -----------------------------------------------------------------------------
# HuntPlaybook dataclass (referenced from Phase 3)
# -----------------------------------------------------------------------------

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class HuntTTP:
    """A TTP entry in a hunt playbook."""
    technique_id: str
    name: str = ""
    hunt_queries: List[HuntQuery] = field(default_factory=list)


@dataclass
class HuntPlaybook:
    """A threat hunt playbook."""
    id: str = field(default_factory=lambda: f"HUNT-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    author: str = ""
    created: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    updated: str = ""
    status: str = "active"  # active, archived
    hypothesis: Dict[str, Any] = field(default_factory=dict)
    ttps: List[HuntTTP] = field(default_factory=list)
    data_sources: List[Dict[str, str]] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    references: List[Dict[str, str]] = field(default_factory=list)
```

**Verification:** File created at `/Users/wo/code/app/malware/hunt_runner.py` with `HuntRunner`, `HuntQuery`, `HuntResult`, `HuntReport`, and `HuntPlaybook` classes.

### Step 1.2 — Register HuntRunner in the malware orchestrator

In `/Users/wo/code/app/malware/orchestrator.py`, add the HuntRunner import and wire it in:

```python
from app.malware.hunt_runner import HuntRunner
```

Also update `__init__` to optionally accept a database reference:

```python
def __init__(self, db=None):
    self.plugins: List[AnalysisPlugin] = []
    self.running = False
    self.db = db
```

### Step 1.3 — Add HuntRunner to API routes

In `/Users/wo/code/app/malware/api/routes.py`, add import:

```python
from app.malware.hunt_runner import HuntRunner, HuntPlaybook, HuntTTP, HuntQuery
```

Add hunt runner instance alongside the orchestrator:

```python
# Initialize hunt runner
_hunt_runner: Optional[HuntRunner] = None

def get_hunt_runner() -> HuntRunner:
    if _hunt_runner is None:
        _hunt_runner = HuntRunner(db=None)  # db passed via init_app
    return _hunt_runner
```

Expose it via `init_app`:

```python
def init_app(database=None, hunt_runner=None):
    global _hunt_runner
    _hunt_runner = hunt_runner
```

---

## Phase 2: Sigma Rules to CIG Detection

**Goal:** Wire `CIGSignatureDeliverer` to actually call ThreatMatcher API endpoints, add `POST /api/intel/rules` and `GET /api/intel/rules` to the main CIG API, auto-push rules after analysis, and support rule lifecycle management.

### Step 2.1 — Add `POST /api/intel/rules` and `GET /api/intel/rules` to main CIG API

In `/Users/wo/code/app/api/routes.py`, add these routes after the existing intel endpoints (~line 498):

```python
# --- Rule Management Endpoints ---

class RuleRequest(BaseModel):
    name: str
    type: str  # "yara", "sigma"
    content: str
    priority: int = 3
    confidence: float = 0.5
    attack_technique: Optional[str] = None
    source_sample: str = ""
    generated_at: Optional[str] = None


class RuleResponse(BaseModel):
    id: str
    name: str
    type: str
    enabled: bool
    priority: int
    confidence: float
    attack_technique: Optional[str] = None
    source_sample: str = ""
    created_at: str


@app.post("/api/intel/rules", response_model=RuleResponse)
async def create_intel_rule(request: RuleRequest):
    """Create or update a detection rule (YARA or Sigma) in ThreatMatcher."""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    rule_id = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    # Store in database via ThreatMatcher's db
    db = get_db()
    conn = db.db_path
    import sqlite3
    try:
        with sqlite3.connect(conn) as c:
            c.execute("""
                INSERT INTO intel_rules
                (id, name, type, content, enabled, priority, confidence,
                 attack_technique, source_sample, created_at)
                VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            """, (rule_id, request.name, request.type, request.content,
                  request.priority, request.confidence,
                  request.attack_technique, request.source_sample, created_at))
    except Exception as e:
        logger.error(f"Failed to store rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to store rule")

    logger.info(f"Created rule: {request.name} ({request.type})")

    return RuleResponse(
        id=rule_id,
        name=request.name,
        type=request.type,
        enabled=True,
        priority=request.priority,
        confidence=request.confidence,
        attack_technique=request.attack_technique,
        source_sample=request.source_sample,
        created_at=created_at,
    )


@app.get("/api/intel/rules", response_model=List[RuleResponse])
async def list_intel_rules(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    rule_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    """List all detection rules in ThreatMatcher."""
    db = get_db()
    conn = db.db_path
    import sqlite3

    query = "SELECT * FROM intel_rules WHERE 1=1"
    params = []
    if rule_type:
        query += " AND type = ?"
        params.append(rule_type)
    if enabled is not None:
        query += " AND enabled = ?"
        params.append(1 if enabled else 0)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rules = []
    try:
        with sqlite3.connect(conn) as c:
            cursor = c.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                r = dict(zip(columns, row))
                rules.append(RuleResponse(
                    id=r["id"],
                    name=r["name"],
                    type=r["type"],
                    enabled=bool(r["enabled"]),
                    priority=r["priority"],
                    confidence=r["confidence"],
                    attack_technique=r.get("attack_technique"),
                    source_sample=r.get("source_sample", ""),
                    created_at=r["created_at"],
                ))
    except Exception as e:
        logger.error(f"Failed to list rules: {e}")

    return rules


@app.get("/api/intel/rules/{rule_id}", response_model=RuleResponse)
async def get_intel_rule(rule_id: str):
    """Get a specific rule by ID."""
    db = get_db()
    conn = db.db_path
    import sqlite3

    try:
        with sqlite3.connect(conn) as c:
            cursor = c.execute(
                "SELECT * FROM intel_rules WHERE id = ?", (rule_id,)
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Rule not found")
            columns = [desc[0] for desc in cursor.description]
            r = dict(zip(columns, row))
            return RuleResponse(
                id=r["id"],
                name=r["name"],
                type=r["type"],
                enabled=bool(r["enabled"]),
                priority=r["priority"],
                confidence=r["confidence"],
                attack_technique=r.get("attack_technique"),
                source_sample=r.get("source_sample", ""),
                created_at=r["created_at"],
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to get rule")


@app.delete("/api/intel/rules/{rule_id}")
async def delete_intel_rule(rule_id: str):
    """Delete (revoke) a rule from ThreatMatcher."""
    db = get_db()
    conn = db.db_path
    import sqlite3

    try:
        with sqlite3.connect(conn) as c:
            c.execute("DELETE FROM intel_rules WHERE id = ?", (rule_id,))
            if c.rowcount == 0:
                raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "deleted", "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete rule")


@app.post("/api/intel/rules/{rule_id}/enable")
async def enable_intel_rule(rule_id: str):
    """Enable a rule."""
    db = get_db()
    conn = db.db_path
    import sqlite3

    try:
        with sqlite3.connect(conn) as c:
            c.execute("UPDATE intel_rules SET enabled = 1 WHERE id = ?", (rule_id,))
            if c.rowcount == 0:
                raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "enabled", "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to enable rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable rule")


@app.post("/api/intel/rules/{rule_id}/disable")
async def disable_intel_rule(rule_id: str):
    """Disable a rule without deleting it."""
    db = get_db()
    conn = db.db_path
    import sqlite3

    try:
        with sqlite3.connect(conn) as c:
            c.execute("UPDATE intel_rules SET enabled = 0 WHERE id = ?", (rule_id,))
            if c.rowcount == 0:
                raise HTTPException(status_code=404, detail="Rule not found")
        return {"status": "disabled", "rule_id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to disable rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable rule")
```

### Step 2.2 — Add `intel_rules` table to the database schema

In `/Users/wo/code/app/models/database.py`, add this table creation in `_init_db()`:

```python
# Intel rules table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS intel_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        priority INTEGER DEFAULT 3,
        confidence REAL DEFAULT 0.5,
        attack_technique TEXT,
        source_sample TEXT,
        created_at TEXT NOT NULL
    )
""")
```

### Step 2.3 — Auto-push rules after malware analysis

In `/Users/wo/code/app/malware/api/routes.py`, modify the `analyze_sample` endpoint to push signatures after analysis. Find the `analyze_sample` function and add this after the result is obtained:

```python
# After analysis completes, push signatures to ThreatMatcher
if result.signatures:
    cig_sig_deliverer = None
    for plugin in orchestrator.plugins:
        if isinstance(plugin, CIGSignatureDeliverer):
            cig_sig_deliverer = plugin
            break
    if cig_sig_deliverer:
        try:
            cig_sig_deliverer.deliver_from_analysis_result(
                analysis_result=result,
                source_sample=sample_id,
            )
        except Exception as e:
            logger.warning(f"Failed to push signatures to ThreatMatcher: {e}")
```

### Step 2.4 — Update CIGSignatureDeliverer to use `/api/intel/rules`

The `CIGSignatureDeliverer` already posts to `/api/intel/rules` (line 61 in `cig_signature_deliverer.py`). Verify that endpoint is correctly wired to the main CIG API as done in Step 2.1. Also update `revoke_rule` to use `DELETE /api/intel/rules/{rule_name}` which is already implemented in Step 2.1.

---

## Phase 3: Phase C Playbook Automation

**Goal:** Make hunt playbooks executable via API. Use the 4 playbooks from the threat hunting design doc as built-ins.

### Step 3.1 — Define HuntPlaybook dataclass and 4 built-in playbooks

Create `/Users/wo/code/app/malware/hunt_playbooks.py`:

```python
"""Built-in hunt playbooks for Phase C threat hunting."""

import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class HuntQuerySpec:
    """A hunt query specification."""
    data_source: str
    query: str
    query_type: str = "bpf"  # bpf, yara, sql, pattern
    purpose: str = ""


@dataclass
class HuntTTPSpec:
    """A TTP specification within a playbook."""
    technique_id: str
    name: str = ""
    hunt_queries: List[HuntQuerySpec] = field(default_factory=list)


@dataclass
class HuntPlaybookSpec:
    """A threat hunt playbook specification."""
    id: str
    name: str
    author: str
    created: str
    updated: str = ""
    status: str = "active"
    hypothesis: Dict[str, Any] = field(default_factory=dict)
    ttps: List[HuntTTPSpec] = field(default_factory=list)
    data_sources: List[Dict[str, str]] = field(default_factory=list)
    workflow: Dict[str, Any] = field(default_factory=dict)
    findings_template: Dict[str, Any] = field(default_factory=dict)
    references: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "author": self.author,
            "created": self.created,
            "updated": self.updated,
            "status": self.status,
            "hypothesis": self.hypothesis,
            "ttps": [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "hunt_queries": [
                        {
                            "data_source": q.data_source,
                            "query": q.query,
                            "query_type": q.query_type,
                            "purpose": q.purpose,
                        }
                        for q in t.hunt_queries
                    ]
                }
                for t in self.ttps
            ],
            "data_sources": self.data_sources,
            "workflow": self.workflow,
            "findings_template": self.findings_template,
            "references": self.references,
        }


# =============================================================================
# Built-in Playbooks (from threat hunting design doc, Section 3)
# =============================================================================

PLAYBOOK_T1059 = HuntPlaybookSpec(
    id="HUNT-T1059-001",
    name="PowerShell-based C2 Detection",
    author="CIG Phase C",
    created=datetime.now().strftime("%Y-%m-%d"),
    hypothesis={
        "statement": "Malware using PowerShell for command and control will exhibit "
                     "distinctive patterns in DNS queries or HTTP requests — particularly "
                     "encoded commands, long random subdomain strings, or frequent queries "
                     "to dynamic DNS providers.",
        "confidence": "high",
        "affected_malware": [],
    },
    ttps=[
        HuntTTPSpec(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            hunt_queries=[
                HuntQuerySpec(
                    data_source="pcap",
                    query='dns and query contains "powershell"',
                    query_type="bpf",
                    purpose="Find DNS queries for PowerShell-related domains"
                ),
                HuntQuerySpec(
                    data_source="pcap",
                    query='http and user-agent contains "powershell"',
                    query_type="bpf",
                    purpose="Find HTTP requests from PowerShell"
                ),
                HuntQuerySpec(
                    data_source="dns_logs",
                    query=r"[a-z0-9]{8,16}\.[a-z]{2,6}",
                    query_type="pattern",
                    purpose="Detect domain generation algorithms (DGA)"
                ),
            ],
        ),
    ],
    data_sources=[
        {"name": "PCAP captures", "location": "data/pcaps/", "retention": "30 days"},
        {"name": "DNS query logs", "location": "data/logs/dns/", "retention": "30 days"},
        {"name": "Alert history", "location": "SQLite: data/cig.db", "retention": "30 days"},
    ],
    workflow={
        "manual_steps": [
            "Export PCAP for suspect time window",
            "Analyze DNS queries for patterns (entropy, length, frequency)",
            "Extract HTTP payloads for further analysis",
            "Submit suspicious samples to malware analysis",
        ],
        "automated_rules": [
            {"rule_name": "sigma_powershell", "type": "sigma"},
            {"rule_name": "yara_powershell", "type": "yara"},
        ],
    },
    findings_template={
        "severity": "high",
        "description": "Suspicious PowerShell C2 detected",
        "recommended_actions": [
            "Isolate affected host",
            "Submit samples for analysis",
            "Update firewall rules",
            "Block associated domains/IPs",
        ],
    },
    references=[
        {"type": "mitre_attack", "id": "T1059"},
    ],
)


PLAYBOOK_T1055 = HuntPlaybookSpec(
    id="HUNT-T1055-001",
    name="Process Injection Indicators",
    author="CIG Phase C",
    created=datetime.now().strftime("%Y-%m-%d"),
    hypothesis={
        "statement": "Malware performing process injection will exhibit suspicious DLL "
                     "loading patterns, memory allocation with executable permissions, "
                     "or cross-process thread creation visible in network behavior.",
        "confidence": "high",
        "affected_malware": [],
    },
    ttps=[
        HuntTTPSpec(
            technique_id="T1055",
            name="Process Injection",
            hunt_queries=[
                HuntQuerySpec(
                    data_source="pcap",
                    query='http.request.uri contains ".dll"',
                    query_type="bpf",
                    purpose="Find DLL download requests"
                ),
                HuntQuerySpec(
                    data_source="pcap",
                    query="tcp.flags.push and tcp.window_size < 1000",
                    query_type="bpf",
                    purpose="Detect potential hollow process behavior"
                ),
            ],
        ),
    ],
    data_sources=[
        {"name": "PCAP captures", "location": "data/pcaps/", "retention": "30 days"},
        {"name": "HTTP flow logs", "location": "data/logs/http/", "retention": "30 days"},
    ],
    workflow={
        "manual_steps": [
            "Extract DLL-related HTTP flows from PCAP",
            "Calculate entropy of downloaded DLLs (packed = high entropy)",
            "Submit suspicious DLLs to malware analysis",
            "Check VirusTotal for known malicious DLLs",
        ],
        "automated_rules": [
            {"rule_name": "yara_dll_entropy", "type": "yara"},
            {"rule_name": "sigma_process_creation", "type": "sigma"},
        ],
    },
    findings_template={
        "severity": "high",
        "description": "Suspicious process injection indicators",
        "recommended_actions": [
            "Analyze DLL in sandbox",
            "Block associated domains",
            "Monitor for follow-up C2 activity",
        ],
    },
    references=[
        {"type": "mitre_attack", "id": "T1055"},
    ],
)


PLAYBOOK_T1027 = HuntPlaybookSpec(
    id="HUNT-T1027-001",
    name="Obfuscated File Delivery",
    author="CIG Phase C",
    created=datetime.now().strftime("%Y-%m-%d"),
    hypothesis={
        "statement": "Malware delivering obfuscated files via HTTP will transmit "
                     "base64-encoded content, XOR-obfuscated payloads, or encrypted "
                     "archives detectable by examining HTTP body entropy.",
        "confidence": "medium",
        "affected_malware": [],
    },
    ttps=[
        HuntTTPSpec(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            hunt_queries=[
                HuntQuerySpec(
                    data_source="pcap",
                    query='http.content_type contains "octet-stream"',
                    query_type="bpf",
                    purpose="Find binary file downloads"
                ),
                HuntQuerySpec(
                    data_source="pcap",
                    query=r"[A-Za-z0-9+/]{100,}={0,2}$",
                    query_type="yara",
                    purpose="Detect base64-encoded content"
                ),
            ],
        ),
    ],
    data_sources=[
        {"name": "PCAP captures", "location": "data/pcaps/", "retention": "30 days"},
        {"name": "HTTP flow logs", "location": "data/logs/http/", "retention": "30 days"},
    ],
    workflow={
        "manual_steps": [
            "Extract HTTP POST/GET bodies from suspect flows",
            "Attempt base64 decoding — if successful and contains binary headers (MZ, ELF), flag",
            "Calculate entropy of payloads — values > 6.5 may indicate encryption/packing",
            "Submit decoded content to malware analysis",
        ],
        "automated_rules": [
            {"rule_name": "yara_base64_pe", "type": "yara"},
            {"rule_name": "yara_high_entropy", "type": "yara"},
            {"rule_name": "sigma_http_binary", "type": "sigma"},
        ],
    },
    findings_template={
        "severity": "medium",
        "description": "Obfuscated file delivery detected",
        "recommended_actions": [
            "Decode and analyze payload",
            "Submit to malware analysis",
            "Block associated download source",
        ],
    },
    references=[
        {"type": "mitre_attack", "id": "T1027"},
    ],
)


PLAYBOOK_T1218 = HuntPlaybookSpec(
    id="HUNT-T1218-001",
    name="Rundll32 Execution Detection",
    author="CIG Phase C",
    created=datetime.now().strftime("%Y-%m-%d"),
    hypothesis={
        "statement": "Malware using rundll32.exe for signed binary proxy execution "
                     "will exhibit distinctive process creation patterns, DLL loads "
                     "via command-line invocation, or network connections from "
                     "unusual source processes.",
        "confidence": "high",
        "affected_malware": [],
    },
    ttps=[
        HuntTTPSpec(
            technique_id="T1218",
            name="System Binary Proxy Execution (Rundll32)",
            hunt_queries=[
                HuntQuerySpec(
                    data_source="pcap",
                    query='tcp and (http contains "rundll32" or http contains "DLL")',
                    query_type="bpf",
                    purpose="Find rundll32 network activity"
                ),
                HuntQuerySpec(
                    data_source="http_logs",
                    query="rundll32",
                    query_type="pattern",
                    purpose="Detect rundll32 User-Agent"
                ),
            ],
        ),
    ],
    data_sources=[
        {"name": "PCAP captures", "location": "data/pcaps/", "retention": "30 days"},
        {"name": "HTTP flow logs", "location": "data/logs/http/", "retention": "30 days"},
    ],
    workflow={
        "manual_steps": [
            "Identify all HTTP flows where User-Agent indicates rundll32",
            "Extract and analyze downloaded DLLs",
            "Correlate network activity with host-based alerts",
            "Submit suspicious DLLs for analysis",
        ],
        "automated_rules": [
            {"rule_name": "sigma_rundll32_cmdline", "type": "sigma"},
            {"rule_name": "yara_rundll32_network", "type": "yara"},
        ],
    },
    findings_template={
        "severity": "high",
        "description": "Rundll32 suspicious execution detected",
        "recommended_actions": [
            "Isolate affected host",
            "Analyze downloaded DLL",
            "Review parent process chain",
            "Block associated C2 infrastructure",
        ],
    },
    references=[
        {"type": "mitre_attack", "id": "T1218"},
    ],
)


# Registry of all built-in playbooks
BUILT_IN_PLAYBOOKS: List[HuntPlaybookSpec] = [
    PLAYBOOK_T1059,
    PLAYBOOK_T1055,
    PLAYBOOK_T1027,
    PLAYBOOK_T1218,
]

PLAYBOOK_REGISTRY: Dict[str, HuntPlaybookSpec] = {
    pb.id: pb for pb in BUILT_IN_PLAYBOOKS
}


def get_playbook(playbook_id: str) -> Optional[HuntPlaybookSpec]:
    return PLAYBOOK_REGISTRY.get(playbook_id)


def list_playbooks() -> List[HuntPlaybookSpec]:
    return list(PLAYBOOK_REGISTRY.values())


def register_custom_playbook(playbook: HuntPlaybookSpec) -> None:
    PLAYBOOK_REGISTRY[playbook.id] = playbook
```

**Verification:** File created at `/Users/wo/code/app/malware/hunt_playbooks.py` with 4 built-in playbooks.

### Step 3.2 — Add hunt API routes to malware API

In `/Users/wo/code/app/malware/api/routes.py`, add the hunt playbook endpoints:

```python
# --- Hunt Playbook Models ---

class PlaybookCreateRequest(BaseModel):
    name: str
    author: str = "analyst"
    hypothesis: Dict[str, Any]
    ttps: List[Dict[str, Any]] = []
    data_sources: List[Dict[str, str]] = []
    workflow: Dict[str, Any] = {}
    findings_template: Dict[str, Any] = {}
    references: List[Dict[str, str]] = []


class PlaybookResponse(BaseModel):
    id: str
    name: str
    author: str
    created: str
    updated: str
    status: str
    hypothesis: Dict[str, Any]
    ttps: List[Dict[str, Any]]
    data_sources: List[Dict[str, str]]
    workflow: Dict[str, Any]
    findings_template: Dict[str, Any]
    references: List[Dict[str, str]]


# --- Hunt Routes ---

@router.get("/hunt/playbooks", response_model=List[PlaybookResponse])
async def list_hunt_playbooks():
    """List all available hunt playbooks (built-in + custom)."""
    from app.malware.hunt_playbooks import list_playbooks
    playbooks = list_playbooks()
    return [PlaybookResponse(**pb.to_dict()) for pb in playbooks]


@router.get("/hunt/playbooks/{playbook_id}", response_model=PlaybookResponse)
async def get_hunt_playbook(playbook_id: str):
    """Get a specific hunt playbook by ID."""
    from app.malware.hunt_playbooks import get_playbook
    pb = get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return PlaybookResponse(**pb.to_dict())


@router.post("/hunt/playbooks", response_model=PlaybookResponse)
async def create_hunt_playbook(request: PlaybookCreateRequest):
    """Create a custom hunt playbook."""
    import uuid
    from app.malware.hunt_playbooks import HuntPlaybookSpec, HuntTTPSpec, HuntQuerySpec, register_custom_playbook

    playbook_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"
    pb = HuntPlaybookSpec(
        id=playbook_id,
        name=request.name,
        author=request.author,
        created=datetime.now().strftime("%Y-%m-%d"),
        updated=datetime.now().strftime("%Y-%m-%d"),
        hypothesis=request.hypothesis,
        ttps=[
            HuntTTPSpec(
                technique_id=t.get("technique_id", ""),
                name=t.get("name", ""),
                hunt_queries=[
                    HuntQuerySpec(
                        data_source=q.get("data_source", ""),
                        query=q.get("query", ""),
                        query_type=q.get("query_type", "bpf"),
                        purpose=q.get("purpose", ""),
                    )
                    for q in t.get("hunt_queries", [])
                ],
            )
            for t in request.ttps
        ],
        data_sources=request.data_sources,
        workflow=request.workflow,
        findings_template=request.findings_template,
        references=request.references,
    )
    register_custom_playbook(pb)
    return PlaybookResponse(**pb.to_dict())


@router.post("/hunt/run/{playbook_id}")
async def run_hunt_playbook(playbook_id: str):
    """Execute a hunt playbook and return results."""
    from app.malware.hunt_playbooks import get_playbook

    pb = get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Convert HuntPlaybookSpec to HuntPlaybook for HuntRunner
    from app.malware.hunt_playbooks import HuntTTPSpec, HuntQuerySpec
    from app.malware.hunt_runner import HuntRunner, HuntPlaybook as RunnerPlaybook, HuntTTP, HuntQuery

    runner_pb = RunnerPlaybook(
        id=pb.id,
        name=pb.name,
        hypothesis=pb.hypothesis,
        ttps=[
            HuntTTP(
                technique_id=t.technique_id,
                name=t.name,
                hunt_queries=[
                    HuntQuery(
                        data_source=q.data_source,
                        query=q.query,
                        query_type=q.query_type,
                        purpose=q.purpose,
                    )
                    for q in t.hunt_queries
                ],
            )
            for t in pb.ttps
        ],
    )

    # Get HuntRunner instance
    runner = get_hunt_runner()
    report = runner.run_hunt(runner_pb)

    return {
        "playbook_id": playbook_id,
        "playbook_name": pb.name,
        "hunt_id": report.id,
        "total_matches": report.total_matches,
        "findings": report.findings,
        "executed_at": report.executed_at,
        "techniques_executed": [t.technique_id for t in pb.ttps],
    }


@router.get("/hunt/results/{hunt_id}")
async def get_hunt_results(hunt_id: str):
    """Get results for a completed hunt (in-memory store for now)."""
    # HuntRunner returns results directly; for persistence, store in DB
    raise HTTPException(status_code=501, detail="Hunt result persistence not yet implemented")
```

### Step 3.3 — Wire HuntRunner into FastAPI app initialization

In `/Users/wo/code/app/api/routes.py`, update `init_app` to accept and store a `HuntRunner` instance:

```python
def init_app(
    database: Database,
    matcher: ThreatMatcher,
    scheduler=None,
    filter_engine=None,
    dshield_poller=None,
    report_ingestion=None,
    hunt_runner=None,   # NEW
):
    global _db, _threat_matcher, threat_matcher, _scheduler, _filter_engine, _dshield_poller, _report_ingestion, _hunt_runner
    _db = database
    _threat_matcher = matcher
    threat_matcher = matcher
    _scheduler = scheduler
    _filter_engine = filter_engine
    _dshield_poller = dshield_poller
    _report_ingestion = report_ingestion
    _hunt_runner = hunt_runner   # NEW
```

Also update `get_hunt_runner()` to use the global:

```python
def get_hunt_runner():
    if _hunt_runner is None:
        raise HTTPException(status_code=503, detail="Hunt runner not initialized")
    return _hunt_runner
```

---

## Phase 4: Fix Deprecation Warnings — `datetime.utcnow()` to `datetime.now(datetime.UTC)`

**Goal:** Replace all `datetime.utcnow()` with `datetime.now(datetime.UTC)` across the codebase to fix Python 3.12+ deprecation warnings.

**Rule:** `datetime.utcnow()` is deprecated since Python 3.12. Replace with:
```python
from datetime import datetime, UTC
# Instead of: datetime.utcnow()
# Use:          datetime.now(UTC)
```

For `.isoformat()` timestamps, use `datetime.now(UTC).isoformat()`.

### Step 4.1 — Fix `app/malware/samples.py`

```python
# Line 19: submitted_at field default
# Before:
submitted_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
# After:
submitted_at: str = field(default_factory=lambda: datetime.now().isoformat())
```

Also update the import:
```python
from datetime import datetime, UTC
```

### Step 4.2 — Fix `app/malware/results.py`

```python
# Line 36: Signature.generated_at default
# Before:
generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
# After:
generated_at: str = field(default_factory=lambda: datetime.now().isoformat())

# Line 56: AnalysisResult.completed_at default
# Before:
completed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
# After:
completed_at: str = field(default_factory=lambda: datetime.now().isoformat())
```

Also update the import:
```python
from datetime import datetime, UTC
```

### Step 4.3 — Fix `app/malware/plugins/yara_generator.py`

```python
# Line 6: import
from datetime import datetime, UTC

# Line 34:
date = datetime.now().strftime("%Y-%m-%d")

# Line 74:
date = datetime.now().strftime("%Y-%m-%d")
```

### Step 4.4 — Fix `app/malware/plugins/attack_mapper.py`

No `datetime.utcnow()` calls in this file — no changes needed.

### Step 4.5 — Fix `app/malware/plugins/stix_exporter.py`

```python
# Line 4: import
from datetime import datetime, UTC

# Line 30:
bundle_id = f"bundle--{datetime.now().strftime('%Y%m%d%H%M%S')}"

# Line 60:
"valid_from": datetime.now().isoformat() + "Z",

# Line 87:
bundle_id = f"bundle--{datetime.now().strftime('%Y%m%d%H%M%S')}"
```

### Step 4.6 — Fix `app/malware/plugins/sigma_generator.py`

No `datetime.utcnow()` calls in this file — no changes needed.

### Step 4.7 — Fix `app/malware/orchestrator.py`

No `datetime.utcnow()` calls in this file — no changes needed.

### Step 4.8 — Fix `app/malware/api/routes.py`

```python
# Line 7: import
from datetime import datetime, UTC

# Line 151: datetime.fromtimestamp — no change needed (not utcnow)

# Line 287:
completed_at=datetime.now().isoformat(),

# Line 417, 418, 422:
"created": datetime.now().isoformat(),
"modified": datetime.now().isoformat(),
"valid_from": datetime.now().isoformat(),
```

### Step 4.9 — Fix `app/models/database.py`

```python
# Line 7: import
from datetime import datetime, timedelta, UTC

# Line 19: Alert.timestamp default
timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

# Line 48: PcapFile.start_time default
start_time: str = field(default_factory=lambda: datetime.now().isoformat())

# Line 68: Indicator.first_seen default
first_seen: str = field(default_factory=lambda: datetime.now().isoformat())

# Line 69: Indicator.last_seen default
last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

# Line 609:
now = datetime.now().isoformat()

# Line 669:
activity.get("timestamp", datetime.now().isoformat()),
```

### Step 4.10 — Fix `app/matching/engine.py`

```python
# Line 10: import
from datetime import datetime, UTC

# Line 194, 204, 213: feed update interval checks
# Before:
or (datetime.utcnow() - last).total_seconds() > settings.misp_update_interval
# After:
or (datetime.now(UTC) - last).total_seconds() > settings.misp_update_interval

# Similar pattern for lines 204, 213

# Lines 245, 260, 275, 291, 307, 323, 335, 351: stats timestamps
# Before:
self.stats["last_misp_update"] = datetime.utcnow().isoformat()
# After:
self.stats["last_misp_update"] = datetime.now(UTC).isoformat()

# Line 442:
timestamp=datetime.now(UTC).isoformat(),
```

### Step 4.11 — Fix `app/capture/pcap.py`

```python
# Line 12: import
from datetime import datetime, UTC

# Line 48:
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# Line 106:
start_time=datetime.now().isoformat(),

# Line 227:
timestamp=datetime.now().isoformat(),

# Line 346, 370, 404, 468, 489, 510: all Alert timestamps
# Before:
timestamp=datetime.utcnow().isoformat(),
# After:
timestamp=datetime.now().isoformat(),
```

---

## Implementation Order

Execute phases in this order to manage dependencies:

1. **Phase 4 first** — Fix deprecations in shared models (`results.py`, `samples.py`, `database.py`) so all downstream changes use the correct datetime API.
2. **Phase 2 next** — Add `/api/intel/rules` endpoints to the main CIG API. This creates the API surface that Phase 3's HuntRunner will call.
3. **Phase 3 second** — Create `hunt_playbooks.py` with the 4 built-in playbooks, then add the hunt API routes.
4. **Phase 1 last** — Create `HuntRunner` class in `hunt_runner.py`, wire it into the orchestrator, and integrate with the API.

---

## File Summary

| File | Action |
|------|--------|
| `/Users/wo/code/app/malware/hunt_runner.py` | **CREATE** — HuntRunner, HuntQuery, HuntResult, HuntReport, HuntPlaybook, HuntTTP |
| `/Users/wo/code/app/malware/hunt_playbooks.py` | **CREATE** — HuntPlaybookSpec, HuntTTPSpec, HuntQuerySpec + 4 built-in playbooks |
| `/Users/wo/code/app/malware/orchestrator.py` | **MODIFY** — add `db` parameter, import HuntRunner |
| `/Users/wo/code/app/malware/api/routes.py` | **MODIFY** — add hunt routes, auto-push signatures after analysis |
| `/Users/wo/code/app/api/routes.py` | **MODIFY** — add `/api/intel/rules` CRUD endpoints, init_app with hunt_runner |
| `/Users/wo/code/app/models/database.py` | **MODIFY** — add `intel_rules` table, fix `datetime.utcnow()` |
| `/Users/wo/code/app/malware/samples.py` | **MODIFY** — fix `datetime.utcnow()` |
| `/Users/wo/code/app/malware/results.py` | **MODIFY** — fix `datetime.utcnow()` |
| `/Users/wo/code/app/malware/plugins/yara_generator.py` | **MODIFY** — fix `datetime.utcnow()` |
| `/Users/wo/code/app/malware/plugins/attack_mapper.py` | **NO CHANGE** — no utcnow calls |
| `/Users/wo/code/app/malware/plugins/stix_exporter.py` | **MODIFY** — fix `datetime.utcnow()` |
| `/Users/wo/code/app/malware/plugins/sigma_generator.py` | **NO CHANGE** — no utcnow calls |
| `/Users/wo/code/app/matching/engine.py` | **MODIFY** — fix `datetime.utcnow()` |
| `/Users/wo/code/app/capture/pcap.py` | **MODIFY** — fix `datetime.utcnow()` |

---

## Acceptance Criteria

After implementation:

- [ ] `GET /api/malware/hunt/playbooks` returns all 4 built-in playbooks
- [ ] `POST /api/malware/hunt/playbooks` creates a custom playbook
- [ ] `POST /api/malware/hunt/run/{playbook_id}` executes a hunt and returns matches
- [ ] `POST /api/intel/rules` creates a YARA/Sigma rule in ThreatMatcher
- [ ] `GET /api/intel/rules` lists all active rules
- [ ] `DELETE /api/intel/rules/{rule_id}` revokes a rule
- [ ] `POST /api/malware/analyze/{sample_id}` auto-pushes generated signatures to ThreatMatcher
- [ ] `datetime.utcnow()` deprecation warnings resolved in all files listed in Phase 4
- [ ] Hunt findings correlate back to malware analysis samples via `source_sample` field
- [ ] Hunt results include technique ID, matched data source, and raw match data

---

### Critical Files for Implementation

- `/Users/wo/code/app/malware/plugins/cig_signature_deliverer.py` — existing signature delivery logic that must be wired to `/api/intel/rules`
- `/Users/wo/code/app/api/routes.py` — main CIG API where `/api/intel/rules` endpoints must be added
- `/Users/wo/code/app/malware/hunt_playbooks.py` — new file defining HuntPlaybookSpec and 4 built-in playbooks
- `/Users/wo/code/app/matching/engine.py` — ThreatMatcher engine; provides database and packet analysis integration for HuntRunner
- `/Users/wo/code/docs/superpowers/specs/2026-04-07-threat-hunting-design.md` — source of truth for 4 playbook definitions and integration architecture
