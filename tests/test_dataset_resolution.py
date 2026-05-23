"""
End-to-end regression tests for most-specific dataset profile resolution.

Scenario (the bug this guards against):
  - SYS1.* grants ALTER to USERA            (broad generic)
  - SYS1.CSSLIB grants ALTER to ADMGRP only (more-specific profile, UACC NONE)
  - SYS1.CSSLIB is an APF library

RACF resolves access via the single most-specific matching profile. SYS1.CSSLIB
has its own profile, so SYS1.* must NOT grant USERA any access to SYS1.CSSLIB.
"""
import time

import pytest

from mfpandas import IRRDBU00
from mfpandas_racfhound import to_bloodhound

from tests.conftest import _r0100, _r0200, _r0400, _r0404, has_edge


def _run(dump_text: str, apf_libs: set, tmp_path):
    dump = tmp_path / "racf.dump"
    dump.write_text(dump_text)
    racf = IRRDBU00(irrdbu00=str(dump))
    racf.parse()
    while racf._state < IRRDBU00.STATE_READY:
        time.sleep(0.05)
    result = to_bloodhound(racf, apf_libs=apf_libs)
    return {
        "nodes": {n["id"]: n for n in result["graph"]["nodes"]},
        "edges": result["graph"]["edges"],
    }


@pytest.fixture(scope="module")
def shadow_graph(tmp_path_factory):
    lines = [
        _r0100("SYS1",   owner="IBMUSER"),
        _r0100("ADMGRP", owner="IBMUSER"),
        _r0200("USERA"),
        # SYS1.CSSLIB is a more-specific profile (generic, UACC NONE) than SYS1.*
        _r0400("SYS1.*",       generic="YES", owner="IBMUSER", uacc="NONE"),
        _r0400("SYS1.CSSLIB",  generic="YES", owner="IBMUSER", uacc="NONE"),
        _r0404("SYS1.*",       "USERA",  "ALTER"),
        _r0404("SYS1.CSSLIB",  "ADMGRP", "ALTER"),
    ]
    dump = "\n".join(l.rstrip() for l in lines) + "\n"
    return _run(dump, {"SYS1.CSSLIB"}, tmp_path_factory.mktemp("shadow"))


def test_specific_profile_blocks_broader_generic(shadow_graph):
    # USERA's SYS1.* ALTER must NOT leak onto SYS1.CSSLIB.
    assert not has_edge(shadow_graph, "RACFCanWrite",
                        "RACFUser", "USERA", "RACFDataset", "SYS1.CSSLIB")


def test_specific_profile_acl_still_applies(shadow_graph):
    # ADMGRP's direct ALTER on SYS1.CSSLIB is preserved.
    assert has_edge(shadow_graph, "RACFCanWrite",
                    "RACFGroup", "ADMGRP", "RACFDataset", "SYS1.CSSLIB")


def test_no_generic_covers_from_shadowed_profile(shadow_graph):
    # SYS1.* does not "cover" SYS1.CSSLIB, since SYS1.CSSLIB controls itself.
    assert not has_edge(shadow_graph, "RACFGenericCovers",
                        "RACFDataset", "SYS1.*", "RACFDataset", "SYS1.CSSLIB")
