"""Pass 2: build edges from mfpandas DataFrames."""

from .graph import Graph, _v, is_yes, make_id
from .nodes import FACILITY_PRIVILEGE_TYPES, STGADMIN_PRIVILEGE_TYPES, PRIVILEGE_FIELDS


def build_edges(g: Graph, racf, control_maps: tuple[dict, dict, dict]):
    apf_control, parmlib_control, proclib_control = control_maps

    _subgroups(g, racf)
    _connects(g, racf)
    _group_omvs(g, racf)
    _user_privileges(g, racf)
    _user_clauth(g, racf)
    _user_omvs(g, racf)
    _dataset_ownership_uacc(g, racf)
    _dataset_acl(g, racf, apf_control, parmlib_control, proclib_control)
    _general_ownership_uacc(g, racf)
    _general_acl(g, racf)
    _started_task_edges(g, racf)
    _connect_data(g, racf)
    _tso(g, racf)
    _ssignon(g, racf)
    _certificates(g, racf)
    _icsf_key_labels(g, racf)
    _mfa(g, racf)
    _orphans(g, racf)


def _subgroups(g: Graph, racf):
    for _, row in racf.subgroups.iterrows():
        parent   = _v(row["GPSGRP_NAME"])
        subgroup = _v(row["GPSGRP_SUBGRP_ID"])
        if parent and subgroup:
            g.add_edge("RACFHasSubgroup", "RACFGroup", parent, "RACFGroup", subgroup)


def _connects(g: Graph, racf):
    for _, row in racf.connects.iterrows():
        member_id  = _v(row["GPMEM_MEMBER_ID"])
        group_name = _v(row["GPMEM_NAME"])
        if member_id and group_name:
            g.add_edge("RACFMemberOf", "RACFUser", member_id, "RACFGroup", group_name)
            auth = _v(row.get("GPMEM_AUTH")) or "USE"
            g.add_edge("RACFGroupAuth_" + auth, "RACFUser", member_id, "RACFGroup", group_name)


def _group_omvs(g: Graph, racf):
    for _, row in racf.groupOMVS.iterrows():
        gk  = _v(row["GPOMVS_NAME"])
        gid = _v(row.get("GPOMVS_GID"))
        if gk and gid:
            g.set_prop("RACFGroup", gk, "omvs_gid", gid)


def _user_privileges(g: Graph, racf):
    for _, row in racf.users.iterrows():
        uk = _v(row["USBD_NAME"])
        for field, priv in PRIVILEGE_FIELDS:
            if is_yes(row.get(field)):
                g.add_edge("RACFHasPrivilege", "RACFUser", uk, "RACFPrivilege", priv)


def _user_clauth(g: Graph, racf):
    uc_df = racf.userClasses
    if not uc_df.empty and "USCLA_NAME" in uc_df.columns:
        for _, row in uc_df.iterrows():
            uk         = _v(row["USCLA_NAME"])
            class_name = _v(row["USCLA_CLASS"])
            if uk and class_name:
                g.add_edge("RACFClassAuth", "RACFUser", uk, "RACFClass", class_name)


def _user_omvs(g: Graph, racf):
    for _, row in racf.userOMVS.iterrows():
        uk  = _v(row["USOMVS_NAME"])
        nid = make_id("RACFUser", uk)
        if nid not in g.nodes:
            continue
        for dest, src in (
            ("omvs_uid",  "USOMVS_UID"),
            ("omvs_home", "USOMVS_HOME_PATH"),
            ("omvs_prgm", "USOMVS_PROGRAM"),
        ):
            val = _v(row.get(src))
            if val:
                g.nodes[nid]["properties"][dest] = val


def _map_access(access_level: str) -> str:
    level = access_level.upper()
    if level in {"UPDATE", "ALTER", "CONTROL"}:
        return "RACFCanWrite"
    if level == "EXECUTE":
        return "RACFCanExecute"
    return "RACFCanRead"


def _dataset_ownership_uacc(g: Graph, racf):
    for _, row in racf.datasets.iterrows():
        dataset = _v(row["DSBD_NAME"])
        owner   = _v(row.get("DSBD_OWNER_ID"))
        if owner and dataset:
            g.add_edge("RACFOwns", g.get_type(owner), owner, "RACFDataset", dataset)
        uacc = _v(row.get("DSBD_UACC")).upper()
        if uacc and uacc != "NONE":
            g.add_edge(_map_access(uacc), "RACFUser", "PUBLIC",
                       "RACFDataset", dataset,
                       props={"via": "UACC", "Authorization": uacc})
        if is_yes(row.get("DSBD_WARNING")):
            g.add_edge("RACFCanRead", "RACFUser", "PUBLIC",
                       "RACFDataset", dataset, props={"via": "WARNING_MODE"})


def _dataset_acl(g: Graph, racf, apf_control, parmlib_control, proclib_control):
    for _, row in racf.datasetAccess.iterrows():
        profile  = _v(row["DSACC_NAME"]).upper()
        authid   = _v(row.get("DSACC_AUTH_ID"))
        auth_lvl = _v(row.get("DSACC_ACCESS"))
        relation = _map_access(auth_lvl)
        if not (profile and authid):
            continue
        principal_type = g.get_type(authid)
        g.add_edge(relation, principal_type, authid, "RACFDataset", profile,
                   props={"Authorization": auth_lvl})
        for control_map in (apf_control, parmlib_control, proclib_control):
            for concrete_ds, controller in control_map.items():
                if controller == profile:
                    g.add_edge(relation, principal_type, authid, "RACFDataset", concrete_ds,
                               props={"via_generic_profile": profile, "Authorization": auth_lvl})
                    g.add_generic_covers(profile, concrete_ds)


def _general_ownership_uacc(g: Graph, racf):
    for _, row in racf.generals.iterrows():
        resource = _v(row["GRBD_NAME"])
        owner    = _v(row.get("GRBD_OWNER_ID"))
        if owner and resource:
            g.add_edge("RACFOwns", g.get_type(owner), owner, "RACFResource", resource)
        uacc = _v(row.get("GRBD_UACC")).upper()
        if uacc and uacc != "NONE":
            g.add_edge(_map_access(uacc), "RACFUser", "PUBLIC",
                       "RACFResource", resource,
                       props={"via": "UACC", "Authorization": uacc})
            if resource in FACILITY_PRIVILEGE_TYPES or resource in STGADMIN_PRIVILEGE_TYPES:
                g.add_edge("RACFHasPrivilege", "RACFUser", "PUBLIC",
                           "RACFPrivilege", resource, props={"via": "UACC"})
        if is_yes(row.get("GRBD_WARNING")):
            g.add_edge("RACFCanRead", "RACFUser", "PUBLIC",
                       "RACFResource", resource, props={"via": "WARNING_MODE"})


def _general_acl(g: Graph, racf):
    for _, row in racf.generalAccess.iterrows():
        class_name = _v(row.get("GRACC_CLASS_NAME"))
        authid     = _v(row.get("GRACC_AUTH_ID"))
        resource   = _v(row.get("GRACC_NAME"))
        access     = _v(row.get("GRACC_ACCESS"))

        if class_name == "SURROGAT" and access == "READ":
            if "." in resource:
                target_user = resource.split(".")[0].strip()
                if authid and target_user:
                    g.add_edge("RACFSurrogateFor",
                               g.get_type(authid), authid,
                               g.get_type(target_user), target_user)

        elif class_name in ("FACILITY", "STGADMIN"):
            if authid and resource:
                principal_type = g.get_type(authid)
                relation       = _map_access(access)
                g.add_edge(relation, principal_type, authid, "RACFResource", resource)
                if resource in FACILITY_PRIVILEGE_TYPES or resource in STGADMIN_PRIVILEGE_TYPES:
                    g.add_edge("RACFHasPrivilege", principal_type, authid,
                               "RACFPrivilege", resource)

        elif class_name == "PTKTDATA":
            if authid and resource.upper().startswith("IRRPTAUTH."):
                parts = resource.split(".")
                if len(parts) >= 3:
                    target_user = parts[-1]
                    if target_user and target_user != "*":
                        g.add_edge("RACFPassticketFor",
                                   g.get_type(authid), authid,
                                   g.get_type(target_user), target_user)

        elif class_name == "CSFKEYS":
            if authid and resource:
                g.add_edge("RACFCanAccessKey",
                           g.get_type(authid), authid,
                           "RACFResource", resource)


def _started_task_edges(g: Graph, racf):
    for _, row in racf.generalSTDATA.iterrows():
        task_name = _v(row["GRST_NAME"])
        user_id   = _v(row.get("GRST_USER_ID"))
        group_id  = _v(row.get("GRST_GROUP_ID"))
        if not task_name:
            continue
        if user_id:
            g.add_edge("RACFStartedTaskRunsAs", "RACFStartedTask", task_name, "RACFUser", user_id)
        if group_id:
            g.add_edge("RACFStartedTaskGroup", "RACFStartedTask", task_name, "RACFGroup", group_id)
        if is_yes(row.get("GRST_TRUSTED")):
            g.add_edge("RACFHasPrivilege", "RACFStartedTask", task_name, "RACFPrivilege", "TRUSTED")
            if user_id:
                g.add_edge("RACFHasPrivilege", "RACFUser", user_id, "RACFPrivilege", "TRUSTED")
        if is_yes(row.get("GRST_PRIVILEGED")):
            g.add_edge("RACFHasPrivilege", "RACFStartedTask", task_name, "RACFPrivilege", "PRIVILEGED")
            if user_id:
                g.add_edge("RACFHasPrivilege", "RACFUser", user_id, "RACFPrivilege", "PRIVILEGED")


def _connect_data(g: Graph, racf):
    for _, row in racf.connectData.iterrows():
        user  = _v(row.get("USCON_NAME"))
        group = _v(row.get("USCON_GRP_ID"))
        if not (user and group):
            continue
        if is_yes(row.get("USCON_GRP_SPECIAL")):
            g.add_edge("RACFGroupScopeSpecial", "RACFUser", user, "RACFGroup", group)
        if is_yes(row.get("USCON_GRP_OPER")):
            g.add_edge("RACFGroupScopeOper", "RACFUser", user, "RACFGroup", group)
        if is_yes(row.get("USCON_REVOKE")):
            g.add_edge("RACFGroupRevoke", "RACFUser", user, "RACFGroup", group)


def _tso(g: Graph, racf):
    for _, row in racf.userTSO.iterrows():
        uk   = _v(row.get("USTSO_NAME"))
        proc = _v(row.get("USTSO_LOGON_PROC"))
        nid  = make_id("RACFUser", uk)
        if nid in g.nodes:
            g.nodes[nid]["properties"]["hasTSO"] = True
            if proc:
                g.nodes[nid]["properties"]["tso_logon_proc"] = proc


def _ssignon(g: Graph, racf):
    for _, row in racf.generalSSIGNON.iterrows():
        resource  = _v(row.get("GRSIGN_NAME"))
        key_label = _v(row.get("GRSIGN_KEY_LABEL"))
        nid = make_id("RACFResource", resource)
        if nid in g.nodes:
            g.nodes[nid]["properties"]["hasPassticketKey"] = True
            if key_label and key_label != "*MASKED*":
                g.nodes[nid]["properties"]["ptkt_key_label"] = key_label


def _certificates(g: Graph, racf):
    for _, row in racf.userCERTname.iterrows():
        label    = _v(row.get("USCERT_CERTLABL"))
        certname = _v(row.get("USCERT_CERT_NAME"))
        user     = _v(row.get("USCERT_NAME"))
        key = label or certname[:64]
        if key and user:
            g.add_edge("RACFCertificateFor",
                       "RACFCertificate", f"{user}.{key}",
                       "RACFUser", user)


def _icsf_key_labels(g: Graph, racf):
    for _, row in racf.generalICSFsymexportKeylabel.iterrows():
        resource = _v(row.get("GRCSFK_NAME"))
        label    = _v(row.get("GRCSFK_LABEL"))
        nid = make_id("RACFResource", resource)
        if nid in g.nodes and label:
            g.nodes[nid]["properties"]["key_label"] = label


def _mfa(g: Graph, racf):
    mfa_df = racf.userMFAfactor
    if mfa_df.empty:
        return
    for _, row in mfa_df.iterrows():
        user  = _v(row.get("USMFA_NAME"))
        fname = _v(row.get("USMFA_FACTOR_NAME"))
        nid   = make_id("RACFUser", user)
        if nid in g.nodes:
            g.nodes[nid]["properties"]["hasMFA"] = True
        if user and fname:
            g.add_edge("RACFHasMFAFactor", "RACFUser", user, "RACFMFAFactor", fname)


def _orphans(g: Graph, racf):
    ds_orphans, gr_orphans = racf.orphans
    for orphan_df, auth_col in (
        (ds_orphans, "DSACC_AUTH_ID"),
        (gr_orphans, "GRACC_AUTH_ID"),
    ):
        if orphan_df.empty or auth_col not in orphan_df.columns:
            continue
        for auth_id in orphan_df[auth_col].str.strip().dropna().unique():
            auth_id = str(auth_id)
            nid = make_id("RACFUndefined", auth_id)
            if nid in g.nodes:
                g.nodes[nid]["properties"]["isOrphan"] = True
            else:
                g.add_node("RACFUndefined", auth_id, {"name": auth_id, "isOrphan": True})
