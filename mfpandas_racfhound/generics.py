"""RACF generic (wildcard) dataset profile matching and specificity ranking."""

import re

_cache: dict = {}


def to_regex(pat: str) -> re.Pattern:
    pat = (pat or "").strip().upper()
    if pat in _cache:
        return _cache[pat]
    quals = pat.split(".")
    rx = "^"
    first = True
    for q in quals:
        if q == "**":
            rx += r"(?:\.[^.]+)*"
            first = False
            continue
        if not first:
            rx += r"\."
        first = False
        q_rx = re.escape(q)
        q_rx = q_rx.replace(r"\*", r"[^.]*").replace(r"\%", r"[^.]").replace("%", r"[^.]")
        rx += q_rx
    rx += "$"
    _cache[pat] = re.compile(rx)
    return _cache[pat]


def specificity(profile_name: str) -> tuple:
    """Higher specificity = longer literal prefix, fewer wildcards."""
    prefix_len = next(
        (i for i, ch in enumerate(profile_name) if ch in ("*", "%")),
        len(profile_name),
    )
    double_star = profile_name.count("**")
    single_star = profile_name.count("*") - 2 * double_star
    breadth = double_star * 2 + single_star + profile_name.count("%")
    return (prefix_len, -breadth)


def controlling_profile(target: str, discrete_names: set, generic_profiles: set) -> str | None:
    """Return the most-specific generic profile that covers target, or None."""
    if target in discrete_names:
        return None
    candidates = [p for p in generic_profiles if to_regex(p).match(target)]
    return max(candidates, key=specificity) if candidates else None
