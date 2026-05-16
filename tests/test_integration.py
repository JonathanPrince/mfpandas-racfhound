"""
Integration tests for mfpandas-racfhound.

All tests use the session-scoped `graph` fixture from conftest.py, which parses
the fixture IRRDBU00 dump with mfpandas and runs to_bloodhound() directly.

Covers the same ground as the legacy test suite:
  test_graph.py  — node existence, group structure, privileges, dataset access, UACC,
                   FACILITY, SURROGAT, started tasks, OMVS
  test_pandas.py — features 1–10 (0205 group-scoped edges, TSO, certs, MFA,
                   CSFKEYS, ICSF key label, orphans, passticket keys, pwd props)
"""
import pytest
from .conftest import node, has_edge, edges_of, edge_pairs, node_props


# ── Node existence ────────────────────────────────────────────────────────────

class TestNodes:
    def test_all_users_exist(self, graph):
        for uid in ("ADMINUSR", "NORMLUSR", "REVOKUSR", "STCUSR", "NESTDUSR"):
            assert node(graph, "RACFUser", uid), f"Missing RACFUser {uid}"

    def test_all_groups_exist(self, graph):
        for gid in ("SYS1", "TESTGRP", "NESTCHLD", "PRIVGRP"):
            assert node(graph, "RACFGroup", gid), f"Missing RACFGroup {gid}"

    def test_profiled_datasets_exist(self, graph):
        for ds in ("APF.TESTLIB", "APF.*", "APF.**", "OPEN.DATASET", "WARN.DATASET"):
            assert node(graph, "RACFDataset", ds), f"Missing RACFDataset {ds}"

    def test_synthetic_apf_dataset_exists(self, graph):
        n = node(graph, "RACFDataset", "APF.OPEN")
        assert n is not None
        assert n["properties"].get("isAPF") is True

    def test_privilege_nodes_exist(self, graph):
        for priv in ("SPECIAL", "OPERATIONS", "TRUSTED"):
            assert node(graph, "RACFPrivilege", priv), f"Missing RACFPrivilege {priv}"

    def test_started_task_node_exists(self, graph):
        assert node(graph, "RACFStartedTask", "TESTPROC.*")

    def test_bpx_superuser_resource_exists(self, graph):
        assert node(graph, "RACFResource", "BPX.SUPERUSER")

    def test_public_node_exists(self, graph):
        assert node(graph, "RACFUser", "PUBLIC")

    def test_revoked_user_property(self, graph):
        n = node(graph, "RACFUser", "REVOKUSR")
        assert n["properties"].get("USBD_REVOKE") in ("Y", "YES")


# ── Group structure ───────────────────────────────────────────────────────────

class TestGroupStructure:
    def test_testgrp_subgroup_of_sys1(self, graph):
        assert has_edge(graph, "RACFHasSubgroup", "RACFGroup", "SYS1", "RACFGroup", "TESTGRP")

    def test_privgrp_subgroup_of_sys1(self, graph):
        assert has_edge(graph, "RACFHasSubgroup", "RACFGroup", "SYS1", "RACFGroup", "PRIVGRP")

    def test_nestchld_subgroup_of_testgrp(self, graph):
        assert has_edge(graph, "RACFHasSubgroup", "RACFGroup", "TESTGRP", "RACFGroup", "NESTCHLD")

    def test_normlusr_member_of_testgrp(self, graph):
        assert has_edge(graph, "RACFMemberOf", "RACFUser", "NORMLUSR", "RACFGroup", "TESTGRP")

    def test_normlusr_use_authority_on_testgrp(self, graph):
        assert has_edge(graph, "RACFGroupAuth_USE", "RACFUser", "NORMLUSR", "RACFGroup", "TESTGRP")

    def test_normlusr_join_authority_on_privgrp(self, graph):
        assert has_edge(graph, "RACFGroupAuth_JOIN", "RACFUser", "NORMLUSR", "RACFGroup", "PRIVGRP")

    def test_revokusr_member_of_testgrp(self, graph):
        assert has_edge(graph, "RACFMemberOf", "RACFUser", "REVOKUSR", "RACFGroup", "TESTGRP")

    def test_nestdusr_member_of_nestchld(self, graph):
        assert has_edge(graph, "RACFMemberOf", "RACFUser", "NESTDUSR", "RACFGroup", "NESTCHLD")


# ── User privileges ───────────────────────────────────────────────────────────

class TestUserPrivileges:
    def test_adminusr_has_special(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFUser", "ADMINUSR", "RACFPrivilege", "SPECIAL")

    def test_adminusr_has_operations(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFUser", "ADMINUSR", "RACFPrivilege", "OPERATIONS")

    def test_stcusr_has_special(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFUser", "STCUSR", "RACFPrivilege", "SPECIAL")

    def test_normlusr_has_no_special(self, graph):
        assert not has_edge(graph, "RACFHasPrivilege", "RACFUser", "NORMLUSR", "RACFPrivilege", "SPECIAL")


# ── Dataset access — specificity ──────────────────────────────────────────────

class TestDatasetSpecificity:
    def test_adminusr_can_write_discrete_apf_testlib(self, graph):
        assert has_edge(graph, "RACFCanWrite", "RACFUser", "ADMINUSR", "RACFDataset", "APF.TESTLIB")

    def test_normlusr_can_write_apf_star_profile_node(self, graph):
        assert has_edge(graph, "RACFCanWrite", "RACFUser", "NORMLUSR", "RACFDataset", "APF.*")

    def test_normlusr_can_write_apf_open_via_controlling_generic(self, graph):
        # APF.OPEN has no discrete profile → controlled by APF.* (most specific match)
        assert has_edge(graph, "RACFCanWrite", "RACFUser", "NORMLUSR", "RACFDataset", "APF.OPEN")

    def test_adminusr_cannot_write_apf_open_via_less_specific_generic(self, graph):
        # APF.** loses specificity contest to APF.* → no concrete expansion for ADMINUSR
        assert not has_edge(graph, "RACFCanWrite", "RACFUser", "ADMINUSR", "RACFDataset", "APF.OPEN")

    def test_normlusr_cannot_write_discrete_apf_testlib_via_generic(self, graph):
        # Discrete profile blocks generic APF.* from expanding to APF.TESTLIB
        assert not has_edge(graph, "RACFCanWrite", "RACFUser", "NORMLUSR", "RACFDataset", "APF.TESTLIB")

    def test_generic_covers_edge_emitted(self, graph):
        assert has_edge(graph, "RACFGenericCovers", "RACFDataset", "APF.*", "RACFDataset", "APF.OPEN")

    def test_generic_covers_not_emitted_for_discrete_dataset(self, graph):
        assert not has_edge(graph, "RACFGenericCovers", "RACFDataset", "APF.*",  "RACFDataset", "APF.TESTLIB")
        assert not has_edge(graph, "RACFGenericCovers", "RACFDataset", "APF.**", "RACFDataset", "APF.TESTLIB")


# ── Dataset access — UACC and WARNING ────────────────────────────────────────

class TestDatasetUACC:
    def test_public_can_write_uacc_update_dataset(self, graph):
        assert has_edge(graph, "RACFCanWrite", "RACFUser", "PUBLIC", "RACFDataset", "OPEN.DATASET")

    def test_public_can_read_warning_mode_dataset(self, graph):
        assert has_edge(graph, "RACFCanRead", "RACFUser", "PUBLIC", "RACFDataset", "WARN.DATASET")

    def test_no_uacc_edge_for_none_uacc_dataset(self, graph):
        assert not has_edge(graph, "RACFCanRead",  "RACFUser", "PUBLIC", "RACFDataset", "APF.TESTLIB")
        assert not has_edge(graph, "RACFCanWrite", "RACFUser", "PUBLIC", "RACFDataset", "APF.TESTLIB")


# ── FACILITY / BPX resources ──────────────────────────────────────────────────

class TestFacilityResources:
    def test_privgrp_can_read_bpx_superuser_resource(self, graph):
        assert has_edge(graph, "RACFCanRead", "RACFGroup", "PRIVGRP", "RACFResource", "BPX.SUPERUSER")

    def test_privgrp_has_bpx_superuser_privilege(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFGroup", "PRIVGRP", "RACFPrivilege", "BPX.SUPERUSER")


# ── SURROGAT ──────────────────────────────────────────────────────────────────

class TestSurrogat:
    def test_normlusr_is_surrogate_for_adminusr(self, graph):
        assert has_edge(graph, "RACFSurrogateFor", "RACFUser", "NORMLUSR", "RACFUser", "ADMINUSR")


# ── Started tasks ─────────────────────────────────────────────────────────────

class TestStartedTasks:
    def test_testproc_runs_as_stcusr(self, graph):
        assert has_edge(graph, "RACFStartedTaskRunsAs", "RACFStartedTask", "TESTPROC.*", "RACFUser", "STCUSR")

    def test_testproc_group_is_testgrp(self, graph):
        assert has_edge(graph, "RACFStartedTaskGroup", "RACFStartedTask", "TESTPROC.*", "RACFGroup", "TESTGRP")

    def test_testproc_has_trusted_privilege(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFStartedTask", "TESTPROC.*", "RACFPrivilege", "TRUSTED")

    def test_stcusr_inherits_trusted(self, graph):
        assert has_edge(graph, "RACFHasPrivilege", "RACFUser", "STCUSR", "RACFPrivilege", "TRUSTED")

    def test_started_task_trusted_property(self, graph):
        n = node(graph, "RACFStartedTask", "TESTPROC.*")
        assert n["properties"]["trusted"] is True

    def test_started_task_privileged_property(self, graph):
        n = node(graph, "RACFStartedTask", "TESTPROC.*")
        assert n["properties"]["privileged"] is False


# ── OMVS ──────────────────────────────────────────────────────────────────────

class TestOMVS:
    def test_adminusr_omvs_uid(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("omvs_uid") == "0"

    def test_adminusr_omvs_home(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("omvs_home") == "/"


# ── Feature 1: Group-scoped SPECIAL (0205) ────────────────────────────────────

class TestGroupScopeSpecial:
    def test_edge_emitted(self, graph):
        assert ("ADMINUSR", "TESTGRP") in edge_pairs(graph, "RACFGroupScopeSpecial")

    def test_not_emitted_without_flag(self, graph):
        assert ("NORMLUSR", "TESTGRP") not in edge_pairs(graph, "RACFGroupScopeSpecial")


# ── Feature 2: Group-scoped OPER (0205) ───────────────────────────────────────

class TestGroupScopeOper:
    def test_edge_emitted(self, graph):
        assert ("NORMLUSR", "TESTGRP") in edge_pairs(graph, "RACFGroupScopeOper")

    def test_not_emitted_without_flag(self, graph):
        assert ("ADMINUSR", "TESTGRP") not in edge_pairs(graph, "RACFGroupScopeOper")


# ── Feature 3: Per-connect revoke (0205) ──────────────────────────────────────

class TestGroupRevoke:
    def test_edge_emitted(self, graph):
        assert ("REVOKUSR", "TESTGRP") in edge_pairs(graph, "RACFGroupRevoke")

    def test_not_emitted_without_flag(self, graph):
        assert ("ADMINUSR", "TESTGRP") not in edge_pairs(graph, "RACFGroupRevoke")


# ── Feature 4: TSO segment (0220) ─────────────────────────────────────────────

class TestTSO:
    def test_has_tso_property(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("hasTSO") is True

    def test_tso_logon_proc(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("tso_logon_proc") == "ISPFPROC"

    def test_no_tso_without_record(self, graph):
        assert "hasTSO" not in node_props(graph, "RACFUSER_NORMLUSR")


# ── Feature 5: Certificates (0207) ───────────────────────────────────────────

class TestCertificates:
    def test_certificate_node_created(self, graph):
        cert_nodes = [n for n in graph["nodes"].values() if "RACFCertificate" in n["kinds"]]
        assert len(cert_nodes) >= 1

    def test_certificate_node_name(self, graph):
        names = {n["properties"]["name"]
                 for n in graph["nodes"].values()
                 if "RACFCertificate" in n["kinds"]}
        assert "ADMINCERT" in names

    def test_certificate_for_edge(self, graph):
        targets = {e["end"]["value"].split("_", 1)[1]
                   for e in edges_of(graph, "RACFCertificateFor")}
        assert "ADMINUSR" in targets


# ── Feature 6: MFA factors (020A) ────────────────────────────────────────────

class TestMFA:
    def test_mfa_factor_node_created(self, graph):
        names = {n["properties"]["name"]
                 for n in graph["nodes"].values()
                 if "RACFMFAFactor" in n["kinds"]}
        assert "TOTP" in names

    def test_has_mfa_property(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("hasMFA") is True

    def test_has_mfa_factor_edge(self, graph):
        assert ("ADMINUSR", "TOTP") in edge_pairs(graph, "RACFHasMFAFactor")

    def test_no_mfa_without_record(self, graph):
        assert "hasMFA" not in node_props(graph, "RACFUSER_NORMLUSR")


# ── Feature 7: CSFKEYS ACL → RACFCanAccessKey ────────────────────────────────

class TestCSFKEYS:
    def test_can_access_key_edge(self, graph):
        assert ("ADMINUSR", "CRYPTOKEY") in edge_pairs(graph, "RACFCanAccessKey")


# ── Feature 8: ICSF key label (05G1) ─────────────────────────────────────────

class TestICSFKeyLabel:
    def test_key_label_property(self, graph):
        assert node_props(graph, "RACFRESOURCE_CRYPTOKEY").get("key_label") == "TEST.CRYPTO.KEY"


# ── Feature 9: Orphan ACL entries ────────────────────────────────────────────

class TestOrphans:
    def test_orphan_node_created(self, graph):
        assert graph["nodes"].get("RACFUNDEFINED_GHOSTUSR") is not None

    def test_orphan_is_orphan_property(self, graph):
        assert node_props(graph, "RACFUNDEFINED_GHOSTUSR").get("isOrphan") is True

    def test_defined_user_not_orphan(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("isOrphan") is not True


# ── Feature 10: Passticket key profile (0530) ─────────────────────────────────

class TestPassticketKeys:
    def test_has_passticket_key_flag(self, graph):
        assert node_props(graph, "RACFRESOURCE_PTKTAPPL").get("hasPassticketKey") is True

    def test_ptkt_key_label(self, graph):
        assert node_props(graph, "RACFRESOURCE_PTKTAPPL").get("ptkt_key_label") == "TEST.PTKT.KEY"

    def test_masked_key_not_stored(self, graph):
        assert node_props(graph, "RACFRESOURCE_PTKTAPPL").get("ptkt_key_label") != "*MASKED*"


# ── User node properties ──────────────────────────────────────────────────────

class TestUserProperties:
    def test_pwd_alg(self, graph):
        assert node_props(graph, "RACFUSER_ADMINUSR").get("pwd_alg") == "KDFAES256"

    def test_nopwd_pro(self, graph):
        assert node_props(graph, "RACFUSER_STCUSR").get("nopwd") == "PRO"

    def test_nopwd_blank_for_normal_user(self, graph):
        assert not node_props(graph, "RACFUSER_NORMLUSR").get("nopwd")
