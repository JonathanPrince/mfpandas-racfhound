"""Pass 1: build nodes from mfpandas DataFrames."""

from .graph import Graph, _v, is_yes, make_id

FACILITY_PRIVILEGE_TYPES = frozenset({
    "BPX.SUPERUSER",
    "BPX.FILEATTR.APF",
    "BPX.FILEATTR.PROGCTL",
    "IRR.PASSWORD.RESET",
})

STGADMIN_PRIVILEGE_TYPES = frozenset({
    "STGADMIN.ADR.DUMP",
    "STGADMIN.ADR.RESTORE",
})

PRIVILEGE_FIELDS = [
    ("USBD_SPECIAL", "SPECIAL"),
    ("USBD_OPER",    "OPERATIONS"),
    ("USBD_AUDITOR", "AUDITOR"),
    ("USBD_ROAUDIT", "ROAUDIT"),
]


def build_nodes(g: Graph, racf, apf_libs: set, parmlib_datasets: set, proclib_datasets: set):
    # Synthetic PUBLIC node
    g.add_node("RACFUser", "PUBLIC", {"name": "PUBLIC", "description": "All users / public"})
    g.userids.add("PUBLIC")

    _groups(g, racf)
    _users(g, racf)
    _datasets(g, racf)
    _generals(g, racf)
    _user_classes(g, racf)
    _started_tasks(g, racf)
    _certificates(g, racf)
    _mfa_factors(g, racf)
    _special_datasets(g, apf_libs, parmlib_datasets, proclib_datasets)


def _groups(g: Graph, racf):
    for _, row in racf.groups.iterrows():
        gk = _v(row["GPBD_NAME"])
        if not gk:
            continue
        g.groupids.add(gk)
        g.add_node("RACFGroup", gk, {
            "name":           gk,
            "GPBD_SUPGRP_ID": _v(row.get("GPBD_SUPGRP_ID")),
            "GPBD_OWNER_ID":  _v(row.get("GPBD_OWNER_ID")),
            "GPBD_UACC":      _v(row.get("GPBD_UACC")),
        })


def _users(g: Graph, racf):
    for _, row in racf.users.iterrows():
        uk = _v(row["USBD_NAME"])
        if not uk:
            continue
        g.userids.add(uk)
        g.add_node("RACFUser", uk, {
            "name":             uk,
            "displayname":      uk,
            "description":      _v(row.get("USBD_PROGRAMMER")),
            "domain":           "RACF",
            "USBD_REVOKE":      _v(row.get("USBD_REVOKE")),
            "USBD_SPECIAL":     _v(row.get("USBD_SPECIAL")),
            "USBD_DEFGRP_ID":   _v(row.get("USBD_DEFGRP_ID")),
            "pwd_alg":          _v(row.get("USBD_PWD_ALG")),
            "phr_alg":          _v(row.get("USBD_PHR_ALG")),
            "nopwd":            _v(row.get("USBD_NOPWD")),
        })
        for field, priv in PRIVILEGE_FIELDS:
            if is_yes(row.get(field)):
                g.add_node("RACFPrivilege", priv, {"name": priv})


def _datasets(g: Graph, racf):
    for _, row in racf.datasets.iterrows():
        dsname = _v(row["DSBD_NAME"])
        if not dsname:
            continue
        g.add_node("RACFDataset", dsname, {
            "name":    dsname,
            "owner":   _v(row.get("DSBD_OWNER_ID")),
            "generic": is_yes(row.get("DSBD_GENERIC")),
            "warning": is_yes(row.get("DSBD_WARNING")),
        })


def _generals(g: Graph, racf):
    for _, row in racf.generals.iterrows():
        resource = _v(row["GRBD_NAME"])
        if not resource:
            continue
        props = {"name": resource, "warning": is_yes(row.get("GRBD_WARNING"))}
        if resource in FACILITY_PRIVILEGE_TYPES or resource in STGADMIN_PRIVILEGE_TYPES:
            g.add_node("RACFPrivilege", resource, {"name": resource, **props})
        g.add_node("RACFResource", resource, props)


def _user_classes(g: Graph, racf):
    uc_df = racf.userClasses
    if not uc_df.empty and "USCLA_CLASS" in uc_df.columns:
        for cname in uc_df["USCLA_CLASS"].str.strip().dropna().unique():
            if cname:
                g.add_node("RACFClass", cname, {"name": cname})


def _started_tasks(g: Graph, racf):
    for _, row in racf.generalSTDATA.iterrows():
        task_name  = _v(row["GRST_NAME"])
        trusted    = is_yes(row.get("GRST_TRUSTED"))
        privileged = is_yes(row.get("GRST_PRIVILEGED"))
        if not task_name:
            continue
        g.add_node("RACFStartedTask", task_name, {
            "name":       task_name,
            "trusted":    trusted,
            "privileged": privileged,
            "trace":      is_yes(row.get("GRST_TRACE")),
            "user_id":    _v(row.get("GRST_USER_ID")),
            "group_id":   _v(row.get("GRST_GROUP_ID")),
        })
        if trusted:
            g.add_node("RACFPrivilege", "TRUSTED",    {"name": "TRUSTED"})
        if privileged:
            g.add_node("RACFPrivilege", "PRIVILEGED", {"name": "PRIVILEGED"})


def _certificates(g: Graph, racf):
    for _, row in racf.userCERTname.iterrows():
        label    = _v(row.get("USCERT_CERTLABL"))
        certname = _v(row.get("USCERT_CERT_NAME"))
        owner    = _v(row.get("USCERT_NAME"))
        key = label or certname[:64]
        if key and owner:
            g.add_node("RACFCertificate", f"{owner}.{key}", {
                "name":      key,
                "cert_name": certname,
                "owner":     owner,
            })


def _mfa_factors(g: Graph, racf):
    mfa_df = racf.userMFAfactor
    if not mfa_df.empty:
        for fname in mfa_df["USMFA_FACTOR_NAME"].str.strip().dropna().unique():
            if fname:
                g.add_node("RACFMFAFactor", fname, {"name": fname})


def _special_datasets(g: Graph, apf_libs: set, parmlib_datasets: set, proclib_datasets: set):
    for ds in apf_libs:
        g.add_node("RACFDataset", ds, {"name": ds, "isAPF": True})
        g.nodes[make_id("RACFDataset", ds)]["properties"]["isAPF"] = True
    for ds in proclib_datasets:
        g.add_node("RACFDataset", ds, {"name": ds, "isPROCLIB": True})
        g.nodes[make_id("RACFDataset", ds)]["properties"]["isPROCLIB"] = True
    for ds in parmlib_datasets:
        g.add_node("RACFDataset", ds, {"name": ds, "isPARMLIB": True})
        g.nodes[make_id("RACFDataset", ds)]["properties"]["isPARMLIB"] = True
