# mfpandas-racfhound

Transforms a parsed mfpandas `IRRDBU00` object into BloodHound OpenGraph JSON. See the workspace `../CLAUDE.md` for the graph model, domain concepts, record types, and attack chains.

## Public API

```python
from mfpandas_racfhound import to_bloodhound

graph = to_bloodhound(
    racf,                           # mfpandas.IRRDBU00, already parsed
    apf_libs={"SYS1.LINKLIB"},
    parmlib_datasets={"SYS1.PARMLIB"},
    proclib_datasets={"SYS1.PROCLIB"},
)
# Returns: {"graph": {"nodes": [...], "edges": [...]}}
```

## Architecture

```
mfpandas_racfhound/
  __init__.py       Public API
  exporter.py       Two-pass orchestration
  graph.py          Node/edge registry with deduplication
  nodes.py          Pass 1: node builders
  edges.py          Pass 2: edge builders
  generics.py       RACF wildcard profile matching

tests/
  conftest.py       Fixtures from mfpandas-parsed test dumps
  test_nodes.py     Pass 1 unit tests
  test_edges.py     Pass 2 unit tests
  test_integration.py  End-to-end against reference dump
```

### Two-pass approach

**Pass 1 — nodes** (`nodes.py`): builds all node kinds first so `get_type()` can resolve principal kinds in Pass 2.

**Pass 2 — edges** (`edges.py`): uses `Graph.userids` / `Graph.groupids` populated in Pass 1 to emit correctly-typed edges.

### Graph registry (`graph.py`)

`Graph` holds `nodes: dict`, `edges: list`, `userids: set`, `groupids: set`. Nodes are deduplicated by ID; edges are not (BloodHound deduplicates on import).

### Generic profile matching (`generics.py`)

Wildcard dataset profiles (`*`, `%`, `**`) are matched against known APF/PARMLIB/PROCLIB datasets. The most-specific matching profile controls access to each concrete dataset. Specificity: longer literal prefix → fewer wildcards.

## mfpandas Plugin Hook

To expose `racf.to_bloodhound()` from mfpandas without a hard dependency:

```python
def to_bloodhound(self, **kwargs):
    try:
        from mfpandas_racfhound import to_bloodhound
        return to_bloodhound(self, **kwargs)
    except ImportError:
        raise ImportError("Install mfpandas-racfhound for BloodHound export support")
```

## Reference Implementation

`racfhound/legacy/importer/opengraph-pandas.py` is the reference. The legacy test suite at `racfhound/legacy/importer/tests/` covers all 10 feature areas and baseline graph sanity — use it as the guide when writing tests here.
