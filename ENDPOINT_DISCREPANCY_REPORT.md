# API Endpoint Discrepancy Report

**Report Date:** March 31, 2026  
**Status:** ⚠️ DOCUMENTATION vs IMPLEMENTATION MISMATCH

---

## Issue Summary

The documentation claims **19 new API endpoints** were added, but verification reveals discrepancies between documented and implemented endpoints.

### Documented Endpoints (from FEED_MANAGEMENT_GUIDE.md)

**Scheduler Management (5 endpoints)** - Claims `/api/feeds/scheduler/` prefix:
```
GET    /api/feeds/scheduler/status
POST   /api/feeds/scheduler/start
POST   /api/feeds/scheduler/stop
POST   /api/feeds/scheduler/update/{feed_id}
POST   /api/feeds/scheduler/update/all
```

**Credential Testing (6 endpoints)** - MISSING from implementation:
```
POST   /api/config/nessus/test
POST   /api/config/graynoise/test
GET    /api/config/nessus/status
GET    /api/config/graynoise/status
POST   /api/config/custom-api/list (documented but different from actual)
```

---

## Actual Implemented Endpoints

### Scheduler Endpoints (5) - DIFFERENT PREFIX
Location: [app/api/routes.py](app/api/routes.py#L1923-L1988)

```
✅ GET    /api/scheduler/status              (line 1923)
✅ POST   /api/scheduler/start               (line 1940)
✅ POST   /api/scheduler/stop                (line 1956)
✅ POST   /api/scheduler/feed/{feed_id}/update (line 1972)
✅ POST   /api/scheduler/update-all          (line 1988)
```

**Issue:** Documented prefix is `/api/feeds/scheduler/` but actual is `/api/scheduler/`

### DShield Intelligence Endpoints (5)
Location: [app/api/routes.py](app/api/routes.py#L1415-L2091)

```
✅ GET    /api/feeds/dshield/threats        (line 1415, 2063)
✅ GET    /api/feeds/dshield/ssh            (line 1434)
✅ GET    /api/feeds/dshield/web            (line 1454)
✅ GET    /api/feeds/dshield/status         (line 2007)
✅ POST   /api/feeds/dshield/poll           (line 2028)
```

**Status:** ✅ **IMPLEMENTED and matches documentation**

### Filter Control Endpoints (2)
Location: [app/api/routes.py](app/api/routes.py#L2091-L2108)

```
✅ GET    /api/filters/status                (line 2091)
✅ POST   /api/filters/apply                 (line 2108)
```

**Status:** ✅ **IMPLEMENTED** (minor: documented as `/api/feeds/filters/` but actual is `/api/filters/`)

### Credential Management Endpoints (7) - PARTIALLY IMPLEMENTED
Location: [app/api/routes.py](app/api/routes.py#L2160-L2328)

```
✅ POST   /api/config/nessus/credentials     (line 2177)
✅ POST   /api/config/graynoise/credentials  (line 2204)
✅ POST   /api/config/custom-api/add         (line 2270)
✅ GET    /api/config/custom-api/list        (line 2302)
✅ DELETE /api/config/custom-api/{feed_id}   (line 2328)
✅ GET    /api/config/status                 (line 2160)
✅ GET    /api/config/nessus/enabled         (line 2230)
✅ GET    /api/config/graynoise/enabled      (line 2250)
```

**Missing Endpoints:**
```
❌ POST   /api/config/nessus/test            (NOT IMPLEMENTED)
❌ POST   /api/config/graynoise/test         (NOT IMPLEMENTED)
```

---

## Endpoint Count Comparison

| Category | Documented | Actual | Status |
|----------|-----------|--------|--------|
| Scheduler | 5 | 5 | ✅ Same count, different prefix |
| DShield | 3 | 5 | ✅ More than documented |
| Filters | 2 | 2 | ✅ Same, different prefix |
| Credentials | 9 | 7 | ❌ Missing 2 test endpoints |
| **Total** | **19** | **19** | ⚠️ Same count but mismatched |

---

## Detailed Discrepancies

### 1. **Scheduler Prefix Mismatch**

**Documented:**
```bash
curl /api/feeds/scheduler/status
```

**Actual:**
```bash
curl /api/scheduler/status
```

**Impact:** Any code using documented endpoints will get 404 errors

### 2. **Missing Test Endpoints**

**Documented to exist:**
```bash
POST /api/config/nessus/test
POST /api/config/graynoise/test
```

**Not found in code:**
- No POST endpoint to test Nessus connection
- No POST endpoint to test GrayNoise connection
- Only status check endpoints exist

### 3. **Filter URL Prefix**

**Documented:**
```bash
GET /api/feeds/filters/status
POST /api/feeds/filters/apply
```

**Actual:**
```bash
GET /api/filters/status
POST /api/filters/apply
```

### 4. **Extra Endpoints Not in Documentation**

```
✅ GET    /api/feeds/dshield/status       - Not documented but available
✅ POST   /api/feeds/dshield/poll         - Not documented but available
✅ GET    /api/config/nessus/enabled      - Not documented but available
✅ GET    /api/config/graynoise/enabled   - Not documented but available
```

---

## Recommendations

### Option A: Fix Documentation
Update all documentation files to reflect actual endpoints:
- Change `/api/feeds/scheduler/` to `/api/scheduler/`
- Change `/api/feeds/filters/` to `/api/filters/`
- Add missing endpoints: `test`, `poll`, `enabled`
- Document actual behavior of each endpoint

### Option B: Fix Implementation
Add missing endpoints to code:
1. Create POST `/api/config/nessus/test` endpoint
2. Create POST `/api/config/graynoise/test` endpoint
3. Change scheduler endpoint prefix from `/api/scheduler/` to `/api/feeds/scheduler/`
4. Change filter endpoint prefix from `/api/filters/` to `/api/feeds/filters/`

### Option C: Create API Mapping Document
Document both actual and documented endpoints for user reference

---

## Current Implementation Reality

### What Actually Works (Verified)

✅ **Credentials are saved**
```bash
POST /api/config/nessus/credentials
POST /api/config/graynoise/credentials
```

✅ **Scheduler can be controlled**
```bash
GET /api/scheduler/status
POST /api/scheduler/start
POST /api/scheduler/stop
```

✅ **DShield data is accessible**
```bash
GET /api/feeds/dshield/threats
GET /api/feeds/dshield/ssh
GET /api/feeds/dshield/web
```

❌ **Cannot test connections with API**
- No `/api/config/nessus/test` endpoint exists
- No `/api/config/graynoise/test` endpoint exists
- Only status check via `enabled` endpoints

---

## Immediate Actions Needed

1. **Choose Option A, B, or C above**
2. **Update all documentation** to match actual endpoints
3. **Update code** if endpoints don't match your intended API design
4. **Verify dashboards** work with correct endpoints

---

## Files Affected

### Documentation (needs updates):
- `FEED_MANAGEMENT_GUIDE.md`
- `README_FEED_MANAGEMENT.md`
- `IMPLEMENTATION_CHECKLIST.md`
- `FINAL_SUMMARY.md`

### Code Files (may need updates):
- `app/api/routes.py` - Check endpoint paths and add missing test endpoints

### Template Files (may need URL updates):
- `templates/config.html` - Check API calls in JavaScript
- `templates/feeds.html` - Check API calls in JavaScript

---

## Testing Discrepancy

### Dashboard API Calls Analysis

**Good News:** The dashboards are mostly calling the correct (actual) endpoints:

✅ config.html calls:
- `/api/config/status` ✅
- `/api/config/nessus/credentials` ✅
- `/api/config/graynoise/credentials` ✅
- `/api/config/custom-api/*` ✅
- `/api/feeds/dshield/*` ✅

✅ feeds.html calls:
- `/api/scheduler/status` ✅ (not `/api/feeds/scheduler/status`)
- `/api/scheduler/start` ✅
- `/api/scheduler/stop` ✅
- `/api/scheduler/feed/{feedId}/update` ✅
- `/api/scheduler/update-all` ✅

### BUT: Test Buttons Are Fake ⚠️

**Critical Issue:** The "Test Connection" buttons for Nessus and GrayNoise don't actually call any API endpoints:

```javascript
// In templates/config.html lines 629-639
async function testNessusConnection() {
    showAlert('nessus-alert', 'error', 'Testing connection...');
    setTimeout(() => {
        showAlert('nessus-alert', 'success', 'Connection test completed (check system logs for details)');
    }, 2000);  // ← Just waits 2 seconds then shows success!
}

async function testGrayNoiseConnection() {
    showAlert('graynoise-alert', 'error', 'Testing connection...');
    setTimeout(() => {
        showAlert('graynoise-alert', 'success', 'Connection test completed (check system logs for details)');
    }, 2000);  // ← Same fake behavior
}
```

**Impact:** 
- Users can't actually verify their credentials work
- The test buttons always show success after 2 seconds, regardless of credential validity
- Actual connection testing needs to be implemented

---

## Summary

The implementation is **functionally sound** but **documentation is inaccurate**. The endpoints work, they're just not named as documented. 

**Recommended Action:** Update documentation to match implementation + add missing test endpoints.

**Status:** ⚠️ **REQUIRES DOCUMENTATION UPDATE OR CODE FIX**
