# mfpandas-racfhound

## Purpose

Standalone Python package that transforms a parsed mfpandas IRRDBU00 object into BloodHound OpenGraph JSON for RACF attack path analysis.

Designed to be:
- **Usable by `racfhound`** (the pipeline repo) as a library dependency
- **Usable as an optional mfpandas plugin** — Henri can expose `racf.to_bloodhound()` by integrating this package, without making it a hard dependency
- **Independently releasable** — Jonathan can version and release this package without coordinating with mfpandas releases

## Repository Structure

```
mfpandas_racfhound/
  __init__.py       Public API: to_bloodhound(racf, ...) → dict
  exporter.py       Orchestration: two-pass build (nodes → edges)
  graph.py          Graph state: node/edge registry with deduplication
  nodes.py          Pass 1: node builders (groups, users, datasets, resources, ...)
  edges.py          Pass 2: edge builders (membership, access, surrogate, ...)
  generics.py       RACF wildcard (generic profile) matching and specificity ranking

tests/
  conftest.py       Fixtures using mfpandas-parsed test dumps
  test_nodes.py     Unit tests for Pass 1
  test_edges.py     Unit tests for Pass 2
  test_integration.py  End-to-end tests against reference dump
```

## Public API

```python
from mfpandas_racfhound import to_bloodhound

graph = to_bloodhound(
    racf,                           # mfpandas.IRRDBU00, already parsed
    apf_libs={"SYS1.LINKLIB"},      # APF library DSNs (uppercase)
    parmlib_datasets={"SYS1.PARMLIB"},
    proclib_datasets={"SYS1.PROCLIB"},
)
# Returns: {"graph": {"nodes": [...], "edges": [...]}}
```

## Architecture

### Two-pass approach

**Pass 1 — nodes** (`nodes.py`): iterates each mfpandas DataFrame once to build all node kinds. Nodes are required before edges so that `get_type()` can resolve principal kinds.

**Pass 2 — edges** (`edges.py`): iterates DataFrames again to build edges. Uses the populated `Graph.userids` / `Graph.groupids` sets from Pass 1 to resolve auth-IDs to their correct node kind.

### Graph registry (`graph.py`)

`Graph` holds:
- `nodes: dict` — `{node_id: node_dict}`, deduplicated by `seen_nodes`
- `edges: list` — all edges (duplicates allowed; BloodHound deduplicates on import)
- `userids: set`, `groupids: set` — populated during Pass 1 for `get_type()` resolution

### Generic profile matching (`generics.py`)

RACF dataset profiles can use wildcards (`*`, `%`, `**`). Generic profiles are matched against known APF/PARMLIB/PROCLIB datasets. The most specific matching profile controls access to each concrete dataset. Specificity is ranked by: longer literal prefix → fewer wildcards.

## Reference Implementation

The legacy monolithic script at `racfhound/legacy/importer/opengraph-pandas.py` is the reference implementation. The package here is a refactored extraction of that script into a proper package structure.

The legacy test suite at `racfhound/legacy/importer/tests/` covers:
- All 10 feature areas (group-scoped SPECIAL/OPER, TSO, passticket keys, per-connect revoke, certificates, ICSF key access, orphans, MFA, protected users, password algo)
- Baseline graph sanity (subgroup direction, APF flagging, UACC edges, surrogate chains)

Use `legacy/importer/tests/conftest.py` as reference for the fixture-building approach.

## Background Knowledge

- **Jonathan's wiki**: `/home/jonathan/Obsidian/Obsidian Vault/Mainframe/wiki/`
  - `racf/formats/irrdbu00-record-types.md` — record type codes and field prefixes
  - `racf/concepts/` — RACF concepts
  - `racf/techniques/` — escalation techniques

## mfpandas Integration (Optional Plugin)

To expose `racf.to_bloodhound()` from mfpandas itself:

```python
# In mfpandas IRRDBU00 class:
def to_bloodhound(self, **kwargs):
    try:
        from mfpandas_racfhound import to_bloodhound
        return to_bloodhound(self, **kwargs)
    except ImportError:
        raise ImportError("Install mfpandas-racfhound for BloodHound export support")
```

This keeps mfpandas-racfhound as an optional extra and allows it to be installed separately.

## Graph Model

Identical to the racfhound pipeline repo — see that repo's CLAUDE.md for the full node/edge catalogue and exploitation notes.

## IRRDBU00 Record Types

| Record | DataFrame attribute | Key fields used |
|--------|-------------------|-----------------|
| `0100` | `racf.groups` | `GPBD_NAME`, `GPBD_SUPGRP_ID`, `GPBD_OWNER_ID` |
| `0101` | `racf.subgroups` | `GPSGRP_NAME`, `GPSGRP_SUBGRP_ID` |
| `0102` | `racf.connects` | `GPMEM_NAME`, `GPMEM_MEMBER_ID`, `GPMEM_AUTH` |
| `0120` | `racf.groupOMVS` | `GPOMVS_NAME`, `GPOMVS_GID` |
| `0200` | `racf.users` | `USBD_NAME`, `USBD_SPECIAL`, `USBD_OPER`, `USBD_AUDITOR`, `USBD_ROAUDIT`, `USBD_REVOKE`, `USBD_NOPWD`, `USBD_PWD_ALG`, `USBD_PHR_ALG` |
| `0202` | `racf.userClasses` | `USCLA_NAME`, `USCLA_CLASS` |
| `0205` | `racf.connectData` | `USCON_NAME`, `USCON_GRP_ID`, `USCON_GRP_SPECIAL`, `USCON_GRP_OPER`, `USCON_REVOKE` |
| `0207` | `racf.userCERTname` | `USCERT_NAME`, `USCERT_CERTLABL`, `USCERT_CERT_NAME` |
| `020A` | `racf.userMFAfactor` | `USMFA_NAME`, `USMFA_FACTOR_NAME` |
| `0220` | `racf.userTSO` | `USTSO_NAME`, `USTSO_LOGON_PROC` |
| `0270` | `racf.userOMVS` | `USOMVS_NAME`, `USOMVS_UID`, `USOMVS_HOME_PATH`, `USOMVS_PROGRAM` |
| `0400` | `racf.datasets` | `DSBD_NAME`, `DSBD_OWNER_ID`, `DSBD_GENERIC`, `DSBD_UACC`, `DSBD_WARNING` |
| `0404` | `racf.datasetAccess` | `DSACC_NAME`, `DSACC_AUTH_ID`, `DSACC_ACCESS` |
| `0500` | `racf.generals` | `GRBD_NAME`, `GRBD_OWNER_ID`, `GRBD_UACC`, `GRBD_WARNING` |
| `0505` | `racf.generalAccess` | `GRACC_CLASS_NAME`, `GRACC_NAME`, `GRACC_AUTH_ID`, `GRACC_ACCESS` |
| `0530` | `racf.generalSSIGNON` | `GRSIGN_NAME`, `GRSIGN_KEY_LABEL` |
| `0540` | `racf.generalSTDATA` | `GRST_NAME`, `GRST_USER_ID`, `GRST_GROUP_ID`, `GRST_TRUSTED`, `GRST_PRIVILEGED` |
| `05G1` | `racf.generalICSFsymexportKeylabel` | `GRCSFK_NAME`, `GRCSFK_LABEL` |
