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


def controlling_profile(target: str, profiles: set) -> str | None:
    """Return the most-specific profile that covers target, or None.

    RACF resolves access to a dataset using the single most-specific matching
    profile. A discrete (or fully-qualified) profile matches only its exact name;
    a generic profile matches per its wildcard pattern. The most specific match
    (longest literal prefix, fewest wildcards) controls — every broader profile is
    shadowed. `profiles` must therefore be the complete profile set (discrete and
    generic), not just wildcard profiles, or a more-specific profile that happens
    to lack an explicit ACL entry would be missed and a broader generic would
    wrongly win.
    """
    candidates = [p for p in profiles if to_regex(p).match(target)]
    return max(candidates, key=specificity) if candidates else None
