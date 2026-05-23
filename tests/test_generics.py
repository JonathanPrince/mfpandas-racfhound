"""
Unit tests for generics.py — wildcard matching and specificity ranking.
Adapted from racfhound/legacy/importer/tests/test_unit.py.
"""
from mfpandas_racfhound.generics import to_regex, specificity, controlling_profile


class TestToRegex:
    def test_single_star_matches_one_qualifier(self):
        r = to_regex("SYS1.*")
        assert r.match("SYS1.LINKLIB")
        assert not r.match("SYS1.LINK.LIB")
        assert not r.match("OTHER.LINKLIB")

    def test_double_star_matches_multiple_qualifiers(self):
        r = to_regex("SYS1.**")
        assert r.match("SYS1.A")
        assert r.match("SYS1.A.B.C")

    def test_double_star_matches_zero_additional_qualifiers(self):
        assert to_regex("SYS1.**").match("SYS1")

    def test_double_star_does_not_match_different_prefix(self):
        assert not to_regex("SYS1.**").match("OTHER.A")

    def test_percent_matches_single_character(self):
        r = to_regex("SYS%.LINK")
        assert r.match("SYS1.LINK")
        assert not r.match("SYS12.LINK")
        assert not r.match("SYS.LINK")

    def test_discrete_profile_matches_exactly(self):
        r = to_regex("SYS1.PARMLIB")
        assert r.match("SYS1.PARMLIB")
        assert not r.match("SYS1.PARMLIBX")
        assert not r.match("SYS1.PARML")

    def test_pattern_uppercased_before_compile(self):
        assert to_regex("sys1.*").match("SYS1.LINKLIB")

    def test_apf_star_matches_one_qualifier(self):
        r = to_regex("APF.*")
        assert r.match("APF.OPEN")
        assert r.match("APF.TESTLIB")
        assert not r.match("APF.A.B")

    def test_apf_doublestar_matches_deep_name(self):
        r = to_regex("APF.**")
        assert r.match("APF.OPEN")
        assert r.match("APF.A.B")


class TestSpecificity:
    def test_single_star_beats_double_star_at_equal_prefix(self):
        assert specificity("APF.*") > specificity("APF.**")

    def test_longer_prefix_beats_shorter(self):
        assert specificity("SYS1.A.*") > specificity("SYS1.*")

    def test_discrete_name_beats_single_star(self):
        assert specificity("SYS1.LINKLIB") > specificity("SYS1.*")

    def test_percent_same_breadth_as_single_star(self):
        assert specificity("AAAA.%") == specificity("AAAA.*")

    def test_double_star_costs_two_breadth_units(self):
        s, d = specificity("APF.*"), specificity("APF.**")
        assert s[1] > d[1]

    def test_returns_tuple(self):
        result = specificity("SYS1.*")
        assert isinstance(result, tuple) and len(result) == 2


class TestControllingProfile:
    def test_own_discrete_profile_controls(self):
        # A dataset's own profile is its most-specific match and controls it.
        assert controlling_profile("APF.TESTLIB", {"APF.TESTLIB", "APF.*", "APF.**"}) == "APF.TESTLIB"

    def test_most_specific_generic_wins(self):
        assert controlling_profile("APF.OPEN", {"APF.*", "APF.**"}) == "APF.*"

    def test_no_match_returns_none(self):
        assert controlling_profile("OTHER.LIB", {"APF.*"}) is None

    def test_double_star_wins_when_only_candidate(self):
        assert controlling_profile("APF.OPEN", {"APF.**"}) == "APF.**"

    def test_specific_profile_shadows_broader_generic(self):
        # Regression: SYS1.CSSLIB has its own profile, so SYS1.* must not control it
        # even though SYS1.* matches — the more-specific profile wins.
        assert controlling_profile("SYS1.CSSLIB", {"SYS1.*", "SYS1.CSSLIB"}) == "SYS1.CSSLIB"

    def test_more_specific_generic_without_acl_shadows(self):
        # A more-specific generic shadows the broader one regardless of ACL entries.
        assert controlling_profile("SYS1.CSSLIB", {"SYS1.*", "SYS1.CSS*"}) == "SYS1.CSS*"
