"""Prop handling: namespaces, shorthand shapes, and coercion."""

from __future__ import annotations

import pytest

from oscalgen.util import (
    DEFAULT_PROP_NS,
    OscalGenError,
    as_prop,
    as_props,
    date_or_none,
    prune,
)

NS = "https://acme.example.com/ns"


def test_mapping_shorthand_expands_to_props():
    props = as_props({"a": "1", "b": 2}, NS)
    assert props == [
        {"ns": NS, "name": "a", "value": "1"},
        {"ns": NS, "name": "b", "value": "2"},
    ]


def test_qualified_names_keep_their_own_namespace():
    assert as_prop("cisa:foo", "bar", NS) == {"name": "cisa:foo", "value": "bar"}


def test_unqualified_names_get_the_default_namespace():
    assert as_prop("foo", "bar")["ns"] == DEFAULT_PROP_NS


def test_list_of_mappings_accepts_class_and_remarks():
    props = as_props(
        [{"name": "pci", "value": "yes", "class": "oscal-implementation", "remarks": "r"}], NS
    )
    assert props == [
        {"ns": NS, "name": "pci", "value": "yes", "class": "oscal-implementation", "remarks": "r"}
    ]


def test_explicit_ns_in_list_form_wins():
    assert as_props([{"name": "p", "value": "v", "ns": "urn:x"}])[0]["ns"] == "urn:x"


def test_props_entry_without_a_name_is_rejected():
    with pytest.raises(OscalGenError, match="missing required key 'name'"):
        as_props([{"value": "v"}])


def test_scalar_props_entry_is_rejected():
    with pytest.raises(OscalGenError, match="must be mappings"):
        as_props(["just-a-string"])


def test_prune_drops_empty_containers_and_blanks():
    assert prune({"a": "", "b": [], "c": {}, "d": None, "e": " ", "f": "x", "g": [0]}) == {
        "f": "x",
        "g": [0],
    }


def test_prune_keeps_protected_keys_even_when_empty():
    assert prune({"a": {}, "keep": {}}, protect=("keep",)) == {"keep": {}}


def test_prune_preserves_false_and_zero():
    assert prune({"a": False, "b": 0}) == {"a": False, "b": 0}


def test_date_or_none_accepts_dates_and_strings():
    import datetime as dt

    assert date_or_none(dt.date(2026, 1, 2)) == "2026-01-02"
    assert date_or_none(dt.datetime(2026, 1, 2, 3, 4)) == "2026-01-02"
    assert date_or_none("2026-01-02") == "2026-01-02"
    assert date_or_none(None) is None