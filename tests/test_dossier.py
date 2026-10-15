"""Labels, full-name ambiguity, conflicts, corroboration, dossier consistency."""
from unisint.resolve import assess
from unisint.synthesis import build_dossier


def E(id, type, value, source="t", basis="observed", parent=None, **meta):
    return {"id": id, "type": type, "value": value, "source": source, "basis": basis,
            "meta": {"sources": [source], **meta},
            "provenance": [{"parent_id": parent, "parent_value": None, "rel": "r"}]}


SEED_NAME = E("n0", "full_name", "Ada Lovelace", source="input", basis="seed",
              identity_link="seed")


def test_full_name_seed_yields_only_candidates():
    """Entering a common name must not turn namesakes into findings."""
    ents = [SEED_NAME,
            E("u1", "username", "adalovelace", "name_permute", "candidate", "n0"),
            E("r1", "url", "https://example.org/ada-lovelace-bio", "web_search",
              "candidate", "n0", kind="search_result", term_in_snippet=True,
              caveat="mentions the search term — not verified to be about you")]
    d = build_dossier({"mode": "self", "entities": ents})
    assert d["accounts"] == []
    assert d["counts"]["accounts_strong"] == 0
    assert d["search_results"][0]["assessment"]["label"] == "candidate"
    assert "not verified" in " ".join(d["search_results"][0]["assessment"]["unknown"])
    assert d["identifiers"]["username"][0]["assessment"]["label"] == "candidate"


def test_handle_match_is_unconfirmed_and_explains_why():
    ents = [E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("a", "account", "https://gitlab.com/ada", "gitlab", parent="s",
              identity_link="handle_match", site="GitLab", url_origin="api")]
    a = assess(ents[1], ents)
    assert a.label == "handle_match"
    assert any("ownership not confirmed" in u for u in a.unknown)
    assert any("URL supplied by api" in s for s in a.supports)
    assert "link not checked" in a.unknown


def test_corroborated_when_profile_lists_a_seed():
    ents = [E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("se", "email", "ada@corp.com", "input", "seed", identity_link="seed"),
            E("a", "account", "https://github.com/ada", "github", parent="s",
              identity_link="handle_match", site="GitHub"),
            E("le", "email", "ada@corp.com", "github", parent="s",
              identity_link="handle_profile")]
    # the seeded email and the listed email are the same entity in the engine;
    # here the listed record represents that observation.
    a = assess(ents[2], ents)
    assert a.label == "corroborated_handle"
    assert any("lists your seeded email" in s for s in a.supports)


def test_conflicting_name_is_flagged_missing_name_is_unknown():
    ents = [SEED_NAME,
            E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("a1", "account", "https://gitlab.com/ada", "gitlab", parent="s",
              identity_link="handle_match", site="GitLab"),
            E("n1", "full_name", "Bob Smith", "gitlab", parent="s", on="GitLab @ada"),
            E("a2", "account", "https://keybase.io/ada", "keybase", parent="s",
              identity_link="handle_match", site="Keybase")]
    a1 = assess(ents[2], ents)
    assert a1.conflicting and "Bob Smith" in a1.conflicts[0]
    a2 = assess(ents[4], ents)
    assert not a2.conflicting
    assert any("no display name" in u for u in a2.unknown)


def test_shared_name_token_is_weak_support_not_proof():
    ents = [SEED_NAME,
            E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("a", "account", "https://gitlab.com/ada", "gitlab", parent="s",
              identity_link="handle_match", site="GitLab"),
            E("n", "full_name", "Ada L.", "gitlab", parent="s")]
    a = assess(ents[2], ents)
    assert a.label == "handle_match"                  # not upgraded by a name
    assert any("weak: names are common" in s for s in a.supports)


def test_broken_link_shown_with_conflict_and_flag():
    acc = E("a", "account", "https://site.example/u", "sherlock",
            identity_link="handle_match", site="Site")
    acc["validation"] = {"state": "soft_404", "detail": "page text indicates not found"}
    d = build_dossier({"mode": "self", "entities": [acc]})
    item = d["accounts"][0]
    assert item["validation"]["state"] == "soft_404"
    assert item["assessment"]["conflicting"]
    assert any("failed validation" in r for r in d["risk_flags"])


def test_names_reported_with_location_not_as_subject_name():
    ents = [E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("n", "full_name", "Someone Else", "maigret", parent="s",
              on="Twitch (handle match)")]
    d = build_dossier({"mode": "self", "entities": ents})
    assert d["names_on_profiles"] == [{"name": "Someone Else", "on": "Twitch (handle match)",
                                       "source": "maigret", "basis": "observed"}]
    assert "names" not in d                                # no "likely names" claim


def test_recon_infrastructure_split_by_scope():
    ents = [E("d", "domain", "corp.com", "input", "seed"),
            E("h1", "host", "api.corp.com", "crtsh", parent="d"),
            E("h2", "host", "aspmx.l.google.com", "dns", parent="d"),
            E("h3", "host", "blog.corp.com", "web_search", "candidate", "d")]
    d = build_dossier({"mode": "recon", "entities": ents,
                       "scope": {"domains": ["corp.com"], "ips": []}})
    assert d["infrastructure"]["in_scope_hosts"] == ["api.corp.com"]
    assert d["infrastructure"]["out_of_scope_hosts"] == ["aspmx.l.google.com"]
    assert d["infrastructure"]["candidate_hosts"] == ["blog.corp.com"]
    assert d["remediation"] == []                          # self-audit only


def test_unconfirmed_accounts_get_conditional_remediation():
    ents = [E("s", "username", "ada", "input", "seed", identity_link="seed"),
            E("a", "account", "https://gitlab.com/ada", "gitlab", parent="s",
              identity_link="handle_match", site="GitLab")]
    d = build_dossier({"mode": "self", "entities": ents})
    step = d["remediation"][0]
    assert step["title"].startswith("If https://gitlab.com/ada is yours")
    assert "may belong to someone else" in step["action"]


def test_dossier_and_export_share_the_same_urls():
    """The UI and exports render dossier[...]['url']; it must equal the stored,
    normalised entity URL (no re-derivation from usernames)."""
    acc = E("a", "account", "https://github.com/ada", "github",
            identity_link="handle_match", site="GitHub", url="https://github.com/ada")
    d = build_dossier({"mode": "self", "entities": [acc]})
    assert d["accounts"][0]["url"] == acc["meta"]["url"] == acc["value"]
