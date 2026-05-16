# mfpandas-racfhound

Transforms a parsed [mfpandas](https://github.com/wizardofzos/mfpandas) IRRDBU00 object into [BloodHound](https://github.com/SpecterOps/BloodHound) OpenGraph JSON for RACF attack path analysis.

## Installation

```bash
pip install mfpandas-racfhound
```

Requires Python 3.10+ and `mfpandas`.

## Usage

Parse your IRRDBU00 unload with mfpandas, then pass it to `to_bloodhound`:

```python
import time
from mfpandas import IRRDBU00
from mfpandas_racfhound import to_bloodhound

racf = IRRDBU00(irrdbu00="/path/to/irrdbu00.dump")
racf.parse()
while racf._state < IRRDBU00.STATE_READY:
    time.sleep(0.1)

graph = to_bloodhound(
    racf,
    apf_libs={"SYS1.LINKLIB", "SYS1.SVCLIB"},
    parmlib_datasets={"SYS1.PARMLIB"},
    proclib_datasets={"SYS1.PROCLIB"},
)
```

`to_bloodhound` returns a dict ready for upload to the BloodHound API:

```python
{
    "graph": {
        "nodes": [...],
        "edges": [...]
    }
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `racf` | `mfpandas.IRRDBU00` | Parsed IRRDBU00 instance |
| `apf_libs` | `set[str]` | APF library DSNs (uppercase). Used to resolve generic dataset profiles to concrete APF libraries. |
| `parmlib_datasets` | `set[str]` | PARMLIB dataset DSNs |
| `proclib_datasets` | `set[str]` | PROCLIB dataset DSNs |

All DSN sets are optional and default to empty. Without them, generic profile resolution against APF/PARMLIB/PROCLIB libraries is skipped.

### Writing output to a file

```python
import json

with open("racf_opengraph.json", "w") as f:
    json.dump(graph, f)
```

### Uploading to BloodHound

```python
import httpx

resp = httpx.post(
    "https://<bloodhound-host>/api/v2/graphs/upload",
    headers={"Authorization": f"Bearer {token}"},
    json=graph,
)
resp.raise_for_status()
```

## mfpandas integration

`mfpandas-racfhound` can be wired into the `mfpandas.IRRDBU00` class as an optional plugin, exposing `racf.to_bloodhound()` directly without making it a hard dependency:

```python
# In mfpandas IRRDBU00 class:
def to_bloodhound(self, **kwargs):
    try:
        from mfpandas_racfhound import to_bloodhound
        return to_bloodhound(self, **kwargs)
    except ImportError:
        raise ImportError("Install mfpandas-racfhound for BloodHound export support")
```

Once wired up, users can call:

```python
graph = racf.to_bloodhound(apf_libs={"SYS1.LINKLIB"})
```

## Running tests

```bash
pip install pytest
pytest
```

The test suite uses a self-contained fixture dump built from raw IRRDBU00 records — no external files or mainframe access required.

To run a specific test file:

```bash
pytest tests/test_generics.py    # wildcard matching and specificity unit tests
pytest tests/test_integration.py # end-to-end graph output tests
```
