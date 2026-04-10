# Exploit-DB Malware Integration Plan

## Goal
Integrate Exploit-DB into the malware analysis section, create IOCs for each exploit, and match them against known and future exploits collected.

---

## Step 1: Add `malware_iocs` Table to Database

**File:** `app/models/database.py`

New table to store IOCs derived from malware analysis and exploit data:

```python
@dataclass
class MalwareIOC:
    """IOC from malware analysis linked to Exploit-DB"""
    id: str
    ioc_type: str           # ip, domain, hash, url, cve, mutex, registry
    value: str
    source: str             # "exploitdb", "malware_analysis", "cve_match"
    confidence: float       # 0.0 - 1.0
    tags: str              # comma-separated (edb_id, platform, etc.)
    linked_edb_id: str     # EDB-ID if linked to exploit
    linked_cve: str         # CVE ID if exploit has CVE reference
    first_seen: str
    last_seen: str
    exploit_description: str  # Description from exploit if available
    matched_count: int = 0
```

New table:
```sql
CREATE TABLE malware_iocs (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    tags TEXT,
    linked_edb_id TEXT,
    linked_cve TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    exploit_description TEXT,
    matched_count INTEGER DEFAULT 0
)
-- Unique constraint on value+source
-- Indexes on ioc_type, value, linked_edb_id, linked_cve
```

Methods to add:
- `insert_malware_ioc(ioc: MalwareIOC)`
- `bulk_insert_malware_iocs(iocs: List[MalwareIOC])`
- `get_malware_iocs(limit, ioc_type, source, linked_edb_id, linked_cve)`
- `get_malware_ioc_by_value(value: str, ioc_type: str)`
- `check_malware_ioc(value: str, ioc_type: str) -> Optional[MalwareIOC]`
- `increment_ioc_match_count(ioc_id: str)`
- `get_malware_ioc_stats()`

---

## Step 2: Create ExploitDB Malware Plugin

**File:** `app/malware/plugins/exploitdb_plugin.py`

New plugin that:
1. On analysis completion, extracts IOCs and enriches with Exploit-DB context
2. Links malware IOCs to known exploits via CVE matching
3. Updates `malware_iocs` table with Exploit-DB derived data

```python
class ExploitDBMalwarePlugin(AnalysisPlugin):
    """Links malware IOCs to Exploit-DB exploits."""

    @property
    def name(self) -> str:
        return "exploitdb_malware"

    @property
    def priority(self) -> int:
        return 60  # Runs after IOC extraction

    def can_handle(self, sample: Sample) -> bool:
        return True  # Works on any sample with IOCs

    def analyze(self, sample: Sample) -> dict:
        # 1. Load IOCs from analysis result
        # 2. For each IOC, check if it matches any CVE in Exploit-DB
        # 3. Create MalwareIOC entries with exploit context
        # 4. Return enrichment data
```

---

## Step 3: Create IOC Matching Service

**File:** `app/malware/ioc_matcher.py`

Service that:
1. Checks extracted IOCs against Exploit-DB CVE database
2. When a CVE is found in an IOC, retrieves all linked exploits
3. Generates alerts/matches when IOCs correlate with known exploits
4. Updates match counts for future prioritization

```python
class IOCMatcher:
    """Match malware IOCs against Exploit-DB exploits."""

    def __init__(self, db: Database):
        self.db = db
        self.exploitdb_feed = ExploitDBFeed(db)

    def match_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Check if IOC matches any Exploit-D entries."""
        # For CVE IOCs: direct lookup in exploits table
        # For IP/domain/hash: check if associated CVEs exist

    def match_and_store(self, iocs: List[IOC]) -> List[MalwareIOC]:
        """Match IOCs and store enriched results."""

    def get_exploits_for_ioc(self, ioc_type: str, ioc_value: str) -> List[Exploit]:
        """Get all exploits related to an IOC value."""
```

---

## Step 4: Enrich IOC Extractor with Exploit-DB Context

**File:** `app/malware/plugins/ioc_extractor.py` (modify)

Update `extract_from_strings()` to:
1. Extract CVE IDs from strings (using regex)
2. Tag IOCs with linked CVEs
3. Return enriched IOC list with Exploit-DB links

New method:
```python
def extract_cves_from_text(self, text: str) -> List[str]:
    """Extract CVE IDs from any text."""
    cve_pattern = r"CVE-\d{4}-\d{4,}"
    return re.findall(cve_pattern, text)
```

---

## Step 5: Update API Routes

**File:** `app/malware/api/routes.py`

New endpoints:
- `GET /api/malware/iocs` - List all malware IOCs
- `GET /api/malware/iocs/{ioc_id}` - Get specific IOC with exploit links
- `GET /api/malware/iocs/cve/{cve_id}` - Get IOCs linked to a CVE
- `GET /api/malware/iocs/edb/{edb_id}` - Get IOCs linked to an exploit
- `POST /api/malware/iocs/match` - Re-run matching on stored IOCs

---

## Step 6: Integrate into ThreatMatcher

**File:** `app/matching/engine.py`

Add Exploit-DB to the feed update loop:
- `_update_exploitdb()` method
- Stats tracking for `exploitdb_exploits` and `exploitdb_iocs`
- Health check integration

---

## Key Design Decisions

1. **Two IOC stores**: Keep existing `indicators` table for generic threat feeds, use new `malware_iocs` for malware-specific analysis with exploit linkage.

2. **CVE as the link**: CVEs are the common denominator - exploits contain CVEs, malware may reference CVEs, so matching happens via CVE correlation.

3. **Lazy matching**: When new IOCs are analyzed, match against Exploit-DB. Results stored so re-analysis isn't needed.

4. **Match counting**: `matched_count` tracks how often an IOC correlated with an exploit - higher = more significant.

---

## Files to Modify/Create

| File | Action |
|------|--------|
| `app/models/database.py` | Add MalwareIOC class, table, methods |
| `app/malware/plugins/exploitdb_plugin.py` | **Create new** - exploit enrichment |
| `app/malware/ioc_matcher.py` | **Create new** - matching service |
| `app/malware/plugins/ioc_extractor.py` | Add CVE extraction |
| `app/malware/api/routes.py` | Add IOC endpoints |
| `app/matching/engine.py` | Integrate Exploit-DB feed |
| `app/feeds/exploitdb.py` | Add bulk IOC creation helper |

---

## Data Flow

```
Malware Sample
    ↓
IOC Extraction (ioc_extractor)
    ↓
CVE Detection → ExploitDBMalwarePlugin
    ↓
IOC Matcher ←→ Exploit-DB Database
    ↓
MalwareIOCs Stored (with links)
    ↓
API / Alerts / Signatures
```
