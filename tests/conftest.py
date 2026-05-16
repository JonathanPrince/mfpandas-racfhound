"""
Fixtures and helpers for mfpandas-racfhound tests.

Record builders adapted from racfhound/legacy/importer/tests/conftest.py.
Byte offsets match irrdbu00-offsets.json (1-indexed).
"""
import time
from pathlib import Path

import pytest

from mfpandas import IRRDBU00
from mfpandas_racfhound import to_bloodhound


# ── Low-level record builder ───────────────────────────────────────────────────

def _build_mfp_record(rt: str, fields: list, total_len: int) -> str:
    """Build a fixed-width IRRDBU00 record. fields = [(start_1idx, end_1idx, value)]."""
    buf = bytearray(b' ' * total_len)
    for start, end, value in [(1, 4, rt)] + fields:
        width = end - start + 1
        s = str(value)
        buf[start - 1:end] = (s[:width] if len(s) >= width else s.ljust(width)).encode()
    return buf.decode().rstrip() + '\n'


def _r0100(name, supgrp="", owner="IBMUSER", uacc="NONE"):
    return _build_mfp_record("0100", [
        (6, 13, name), (15, 22, supgrp), (35, 42, owner), (44, 51, uacc)
    ], 60)


def _r0101(parent, subgroup):
    return _build_mfp_record("0101", [(6, 13, parent), (15, 22, subgroup)], 30)


def _r0102(group, member, auth="USE"):
    return _build_mfp_record("0102", [(6, 13, group), (15, 22, member), (24, 31, auth)], 35)


def _r0200(name, special="NO", oper="NO", revoke="NO", auditor="NO", roaudit="NO",
           programmer="", defgrp="SYS1", nopwd="", pwd_alg="", phr_alg=""):
    return _build_mfp_record("0200", [
        (6, 13, name), (40, 43, special), (45, 48, oper), (50, 53, revoke),
        (75, 94, programmer), (96, 103, defgrp),
        (386, 389, auditor), (391, 394, nopwd),
        (592, 603, pwd_alg), (613, 624, phr_alg), (634, 637, roaudit),
    ], 640)


def _r0205(user, group, grp_special="NO", grp_oper="NO", revoke="NO"):
    return _build_mfp_record("0205", [
        (6, 13, user), (15, 22, group),
        (24, 33, "2024-01-01"), (35, 42, "IBMUSER"),
        (64, 71, "NONE"), (73, 77, "00000"),
        (79, 82, "NO"), (84, 87, grp_special), (89, 92, grp_oper),
        (94, 97, revoke), (99, 102, "NO"), (104, 107, "NO"), (109, 112, "NO"),
    ], 112)


def _r0207(user, cert_name, label=""):
    return _build_mfp_record("0207", [
        (6, 13, user), (15, 260, cert_name), (262, 293, label)
    ], 294)


def _r0220(user, logon_proc=""):
    return _build_mfp_record("0220", [
        (6, 13, user), (150, 157, logon_proc)
    ], 222)


def _r020A(user, factor_name, active_date=""):
    return _build_mfp_record("020A", [
        (6, 13, user), (15, 34, factor_name), (36, 54, active_date)
    ], 54)


def _r0270(user, uid="", home=""):
    return _build_mfp_record("0270", [
        (6, 13, user), (15, 24, uid), (26, 1048, home)
    ], 1050)


def _r0400(name, generic="NO", owner="IBMUSER", uacc="NONE", warning="NO"):
    return _build_mfp_record("0400", [
        (6, 49, name), (58, 61, generic), (74, 81, owner),
        (129, 136, uacc), (484, 487, warning),
    ], 490)


def _r0404(name, authid, access="READ"):
    return _build_mfp_record("0404", [(6, 49, name), (58, 65, authid), (67, 74, access)], 80)


def _r0500(name, class_name, owner="IBMUSER", uacc="NONE", warning="NO"):
    return _build_mfp_record("0500", [
        (6, 251, name), (253, 260, class_name),
        (282, 289, owner), (337, 344, uacc), (660, 663, warning),
    ], 700)


def _r0505(name, class_name, authid, access="READ"):
    return _build_mfp_record("0505", [
        (6, 251, name), (253, 260, class_name),
        (262, 269, authid), (271, 278, access),
    ], 290)


def _r0530(name, class_name="PTKTDATA", protection="*MASKED*", key_label=""):
    return _build_mfp_record("0530", [
        (6, 251, name), (253, 260, class_name),
        (262, 325, protection), (327, 390, key_label),
        (392, 403, "KEYMASKED"), (405, 414, "0000000000"), (416, 419, "NO"),
    ], 420)


def _r0540(task_name, user_id="", group_id="", trusted="NO", privileged="NO", trace="NO"):
    return _build_mfp_record("0540", [
        (6, 251, task_name), (253, 260, "STARTED"),
        (262, 269, user_id), (271, 278, group_id),
        (280, 283, trusted), (285, 288, privileged), (290, 293, trace),
    ], 295)


def _r05G1(name, class_name, key_label):
    return _build_mfp_record("05G1", [
        (6, 251, name), (253, 260, class_name), (262, 325, key_label)
    ], 326)


# ── Fixture dump ───────────────────────────────────────────────────────────────

def _build_fixture_dump() -> str:
    """
    Minimal IRRDBU00 covering all graph behaviours under test:

    Groups   : SYS1, TESTGRP (→SYS1), NESTCHLD (→TESTGRP), PRIVGRP (→SYS1)
    Users    : ADMINUSR (SPECIAL+OPER, pwd_alg=KDFAES256), NORMLUSR, REVOKUSR,
               STCUSR (SPECIAL, nopwd=PRO), NESTDUSR
    Datasets : APF.TESTLIB (discrete), APF.* / APF.** (generics),
               OPEN.DATASET (UACC=UPDATE), WARN.DATASET (WARNING=YES)
    APF list : APF.TESTLIB, APF.OPEN  (APF.OPEN has no discrete profile)
    Resources: BPX.SUPERUSER/FACILITY, ADMINUSR.SUBMIT/SURROGAT
    STC      : TESTPROC.* → STCUSR / TESTGRP, TRUSTED=YES
    Extra    : 0205 group-scoped SPECIAL/OPER/revoke, 0220 TSO, 0207 cert,
               020A MFA, CSFKEYS resource, 05G1 key label, orphan ACL,
               0530 passticket key
    """
    lines = []

    def r(fn, *args, **kw):
        lines.append(fn(*args, **kw).rstrip())

    # Groups
    r(_r0100, "SYS1",     supgrp="",        owner="IBMUSER",  uacc="NONE")
    r(_r0100, "TESTGRP",  supgrp="SYS1",    owner="ADMINUSR", uacc="NONE")
    r(_r0100, "NESTCHLD", supgrp="TESTGRP", owner="ADMINUSR", uacc="NONE")
    r(_r0100, "PRIVGRP",  supgrp="SYS1",    owner="ADMINUSR", uacc="NONE")
    r(_r0101, "SYS1",     "TESTGRP")
    r(_r0101, "SYS1",     "PRIVGRP")
    r(_r0101, "TESTGRP",  "NESTCHLD")
    r(_r0102, "TESTGRP",  "NORMLUSR",  "USE")
    r(_r0102, "TESTGRP",  "REVOKUSR",  "USE")
    r(_r0102, "PRIVGRP",  "NORMLUSR",  "JOIN")
    r(_r0102, "NESTCHLD", "NESTDUSR",  "USE")

    # Users
    r(_r0200, "ADMINUSR", special="YES", oper="YES", pwd_alg="KDFAES256")
    r(_r0200, "NORMLUSR")
    r(_r0200, "REVOKUSR", revoke="YES")
    r(_r0200, "STCUSR",   special="YES", nopwd="PRO")
    r(_r0200, "NESTDUSR")

    # OMVS
    r(_r0270, "ADMINUSR", uid="0", home="/")

    # Datasets
    r(_r0400, "APF.TESTLIB",  generic="NO",  owner="ADMINUSR", uacc="NONE")
    r(_r0400, "APF.*",        generic="YES", owner="ADMINUSR", uacc="NONE")
    r(_r0400, "APF.**",       generic="YES", owner="ADMINUSR", uacc="NONE")
    r(_r0400, "OPEN.DATASET", generic="NO",  owner="ADMINUSR", uacc="UPDATE")
    r(_r0400, "WARN.DATASET", generic="NO",  owner="ADMINUSR", uacc="NONE", warning="YES")
    r(_r0404, "APF.TESTLIB", "ADMINUSR", "ALTER")
    r(_r0404, "APF.*",       "NORMLUSR", "UPDATE")
    r(_r0404, "APF.**",      "ADMINUSR", "ALTER")

    # General resources
    r(_r0500, "BPX.SUPERUSER",   "FACILITY", owner="ADMINUSR", uacc="NONE")
    r(_r0500, "ADMINUSR.SUBMIT", "SURROGAT", owner="ADMINUSR", uacc="NONE")
    r(_r0505, "BPX.SUPERUSER",   "FACILITY", "PRIVGRP",   "READ")
    r(_r0505, "ADMINUSR.SUBMIT", "SURROGAT", "NORMLUSR",  "READ")

    # Started task
    r(_r0540, "TESTPROC.*", user_id="STCUSR", group_id="TESTGRP", trusted="YES")

    # Group-scoped SPECIAL / OPER / per-connect revoke (0205)
    r(_r0205, "ADMINUSR", "TESTGRP", grp_special="YES")
    r(_r0205, "NORMLUSR", "TESTGRP", grp_oper="YES")
    r(_r0205, "REVOKUSR", "TESTGRP", revoke="YES")

    # TSO segment (0220)
    r(_r0220, "ADMINUSR", logon_proc="ISPFPROC")

    # Certificate (0207)
    r(_r0207, "ADMINUSR",
      cert_name="00.CN=AdminUser.O=TestOrg.C=US",
      label="ADMINCERT")

    # MFA factor (020A)
    r(_r020A, "ADMINUSR", factor_name="TOTP", active_date="2024-01-15")

    # CSFKEYS resource + ACL + key label (0500 + 0505 + 05G1)
    r(_r0500, "CRYPTOKEY", "CSFKEYS", owner="ADMINUSR", uacc="NONE")
    r(_r0505, "CRYPTOKEY", "CSFKEYS", "ADMINUSR", "READ")
    r(_r05G1, "CRYPTOKEY", "CSFKEYS", "TEST.CRYPTO.KEY")

    # Orphan ACL entry (GHOSTUSR not defined as user or group)
    r(_r0505, "BPX.SUPERUSER", "FACILITY", "GHOSTUSR", "READ")

    # Passticket key profile (0530)
    r(_r0500, "PTKTAPPL", "PTKTDATA", owner="ADMINUSR", uacc="NONE")
    r(_r0530, "PTKTAPPL", "PTKTDATA", "*MASKED*", "TEST.PTKT.KEY")

    return "\n".join(lines) + "\n"


# ── Session-scoped fixture ─────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def graph(tmp_path_factory):
    """
    Parse the fixture dump with mfpandas, run to_bloodhound(), and return:
        {'nodes': {node_id: node_dict}, 'edges': [edge_dict, ...]}
    """
    work = tmp_path_factory.mktemp("racf")
    dump = work / "racf.dump"
    dump.write_text(_build_fixture_dump())

    racf = IRRDBU00(irrdbu00=str(dump))
    racf.parse()
    while racf._state < IRRDBU00.STATE_READY:
        time.sleep(0.05)

    result = to_bloodhound(
        racf,
        apf_libs={"APF.TESTLIB", "APF.OPEN"},
        parmlib_datasets={"SYS1.PARMLIB"},
        proclib_datasets={"SYS1.PROCLIB"},
    )
    return {
        "nodes": {n["id"]: n for n in result["graph"]["nodes"]},
        "edges": result["graph"]["edges"],
    }


# ── Test helpers ───────────────────────────────────────────────────────────────

def node(graph, label: str, key: str):
    return graph["nodes"].get(f"{label.upper()}_{key.upper()}")


def has_edge(graph, kind: str, start_label: str, start_key: str,
             end_label: str, end_key: str) -> bool:
    sid = f"{start_label.upper()}_{start_key.upper()}"
    eid = f"{end_label.upper()}_{end_key.upper()}"
    return any(
        e["kind"] == kind
        and e["start"]["value"] == sid
        and e["end"]["value"] == eid
        for e in graph["edges"]
    )


def edges_of(graph, kind):
    return [e for e in graph["edges"] if e["kind"] == kind]


def edge_pairs(graph, kind):
    return {
        (e["start"]["value"].split("_", 1)[1],
         e["end"]["value"].split("_", 1)[1])
        for e in edges_of(graph, kind)
    }


def node_props(graph, node_id):
    return graph["nodes"].get(node_id, {}).get("properties", {})
