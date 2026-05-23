"""Orchestrates the two-pass node/edge build."""

from .graph import Graph
from .generics import controlling_profile
from .nodes import build_nodes
from .edges import build_edges


def to_bloodhound(
    racf,
    apf_libs: set | None = None,
    parmlib_datasets: set | None = None,
    proclib_datasets: set | None = None,
) -> dict:
    """Transform a parsed mfpandas IRRDBU00 object into a BloodHound OpenGraph dict.

    Args:
        racf: mfpandas.IRRDBU00 instance (already parsed via parse_fancycli or similar)
        apf_libs: set of APF library DSNs (uppercase)
        parmlib_datasets: set of PARMLIB dataset DSNs (uppercase)
        proclib_datasets: set of PROCLIB dataset DSNs (uppercase)

    Returns:
        dict with shape {"graph": {"nodes": [...], "edges": [...]}}
    """
    apf_libs          = {s.upper() for s in (apf_libs          or set())}
    parmlib_datasets  = {s.upper() for s in (parmlib_datasets  or set())}
    proclib_datasets  = {s.upper() for s in (proclib_datasets  or set())}

    g = Graph()

    # Pass 1: nodes
    build_nodes(g, racf, apf_libs, parmlib_datasets, proclib_datasets)

    # Build profile control maps before Pass 2.
    # The controlling profile for a concrete dataset is the most-specific profile
    # covering it, resolved against the COMPLETE profile set (every base profile
    # plus every ACL profile) so that a specific profile shadows broader generics.
    ds_df = racf.datasets
    da_df = racf.datasetAccess

    all_profiles = set(
        ds_df["DSBD_NAME"].str.strip().str.upper()
    ) | set(
        da_df["DSACC_NAME"].str.strip().str.upper()
    )

    def ctrl(ds_set):
        return {ds: controlling_profile(ds, all_profiles) for ds in ds_set}

    control_maps = (ctrl(apf_libs), ctrl(parmlib_datasets), ctrl(proclib_datasets))

    # Pass 2: edges
    build_edges(g, racf, control_maps)

    return g.to_opengraph()
