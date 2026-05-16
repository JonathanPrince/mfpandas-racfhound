"""mfpandas-racfhound — BloodHound OpenGraph exporter for mfpandas RACF data.

Public API:

    from mfpandas_racfhound import to_bloodhound

    graph = to_bloodhound(
        racf,                       # mfpandas.IRRDBU00 instance (already parsed)
        apf_libs=set(),             # APF library DSNs
        parmlib_datasets=set(),     # PARMLIB dataset DSNs
        proclib_datasets=set(),     # PROCLIB dataset DSNs
    )
    # graph is a dict: {"graph": {"nodes": [...], "edges": [...]}}
"""

from .exporter import to_bloodhound

__all__ = ["to_bloodhound"]
