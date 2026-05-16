"""OpenGraph node/edge registry with deduplication."""


def _v(val) -> str:
    if val is None:
        return ""
    try:
        import math
        if math.isnan(float(val)):
            return ""
    except (TypeError, ValueError):
        pass
    return str(val).strip()


def is_yes(val) -> bool:
    return _v(val).upper() in ("YES", "Y")


def make_id(label: str, key: str) -> str:
    return f"{label.upper()}_{key.upper()}"


class Graph:
    def __init__(self):
        self.nodes: dict = {}
        self.edges: list = []
        self._seen_nodes: set = set()
        self._seen_covers: set = set()
        self.userids:  set = set()
        self.groupids: set = set()

    # ── Node helpers ──────────────────────────────────────────────────────────

    def add_node(self, label: str, key: str, props: dict):
        key = _v(key)
        if not key:
            return
        node_id = make_id(label, key)
        if node_id in self._seen_nodes:
            return
        self._seen_nodes.add(node_id)
        clean = {k: v for k, v in props.items() if v is not None and v != ""}
        clean.setdefault("name", key)
        self.nodes[node_id] = {"id": node_id, "kinds": [label], "properties": clean}

    def set_prop(self, label: str, key: str, prop: str, value):
        nid = make_id(label, key)
        if nid in self.nodes:
            self.nodes[nid]["properties"][prop] = value

    # ── Edge helpers ──────────────────────────────────────────────────────────

    def add_edge(self, kind: str, start_label: str, start_key: str,
                 end_label: str, end_key: str, props: dict | None = None):
        start_key = _v(start_key)
        end_key   = _v(end_key)
        if not start_key or not end_key:
            return
        start_id = make_id(start_label, start_key)
        end_id   = make_id(end_label,   end_key)
        for nid, label, key in ((start_id, start_label, start_key), (end_id, end_label, end_key)):
            if nid not in self._seen_nodes:
                self.add_node(label, key, {"undefined": True})
        self.edges.append({
            "kind":  kind,
            "start": {"value": start_id, "match_by": "id"},
            "end":   {"value": end_id,   "match_by": "id"},
            "properties": {k: v for k, v in (props or {}).items() if v is not None and v != ""},
        })

    def add_generic_covers(self, generic_profile: str, concrete_ds: str):
        key = (generic_profile, concrete_ds)
        if key not in self._seen_covers:
            self._seen_covers.add(key)
            self.add_edge("RACFGenericCovers", "RACFDataset", generic_profile,
                          "RACFDataset", concrete_ds)

    # ── Principal resolution ──────────────────────────────────────────────────

    def normalize_owner(self, owner: str) -> str:
        o = _v(owner).upper()
        return "PUBLIC" if o == "*" else o

    def get_type(self, owner: str) -> str:
        o = self.normalize_owner(owner)
        if o in self.userids:
            return "RACFUser"
        if o in self.groupids or o == "PUBLIC":
            return "RACFGroup"
        self.add_node("RACFUndefined", o, {"name": o})
        return "RACFUndefined"

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_opengraph(self) -> dict:
        return {"graph": {"nodes": list(self.nodes.values()), "edges": self.edges}}
