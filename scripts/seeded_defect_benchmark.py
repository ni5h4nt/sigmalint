#!/usr/bin/env python3
"""Seeded-defect benchmark for sigmalint.

Injects controlled defects into clean Sigma rules (e.g. from the public
SigmaHQ corpus) and measures whether the relevant sigmalint rule fires
post-mutation. Recall and collateral firings are reported per mutator.

Deterministic: seed=42; reproducibility is per-corpus-snapshot.

Usage:
    seeded_defect_benchmark.py \
        --corpus /path/to/sigma/rules \
        --sigmalint .venv/bin/sigmalint \
        --out seeded_defect_results.json
"""

from __future__ import annotations

import argparse
import io
import json
import random
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ruamel.yaml import YAML

SEED = 42
SAMPLE_SIZE = 50
SIGMAHQ_COMMIT = "994da16651194500b607a3007186c29779e1f961"


def _yaml() -> YAML:
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.width = 4096
    return y


def load_rule(path: Path):
    """Return (data, raw_text) or (None, raw_text) on parse failure."""
    raw = path.read_text(encoding="utf-8")
    try:
        return _yaml().load(io.StringIO(raw)), raw
    except Exception:
        return None, raw


def dump_rule(data) -> str:
    buf = io.StringIO()
    _yaml().dump(data, buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Mutators: each takes (data, raw_text) and returns (mutated_text, ok)
# or (None, False) if not applicable. Mutators should be side-effect free
# on the input (operate on a deep copy or fresh load).
# ---------------------------------------------------------------------------


def _deep_reload(raw: str):
    return _yaml().load(io.StringIO(raw))


def _iter_tags(data):
    return data.get("tags") if isinstance(data, dict) else None


def can_revoke_attack_tag(data, raw):
    tags = _iter_tags(data) or []
    return any(isinstance(t, str) and re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in tags)


def mut_revoke_attack_tag(data, raw):
    d = _deep_reload(raw)
    tags = d.get("tags") or []
    for i, t in enumerate(tags):
        if isinstance(t, str) and re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t):
            tags[i] = "attack.t1086"
            return dump_rule(d), True
    return None, False


def can_unknown_attack_tag(data, raw):
    return can_revoke_attack_tag(data, raw)


def mut_unknown_attack_tag(data, raw):
    d = _deep_reload(raw)
    tags = d.get("tags") or []
    for i, t in enumerate(tags):
        if isinstance(t, str) and re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t):
            tags[i] = "attack.t9999"
            return dump_rule(d), True
    return None, False


_MODIFIER_RE = re.compile(r"^([A-Za-z0-9_]+)\|endswith(\|.*)?$")


def _find_endswith_field(data):
    """Find `<field>|endswith` in a *dict* selector (not list-of-dicts).

    Restricted to dict selectors because sigmalint v0.1.0's TAX002 walker
    (rules/taxonomy.py:_walk_detection_fields) only iterates dict selectors;
    list-of-dict selectors are skipped. Sampling on cases the rule cannot
    see would conflate mutator design with detector coverage.
    """
    det = data.get("detection") if isinstance(data, dict) else None
    if not isinstance(det, dict):
        return None
    for sel_name, sel in det.items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for key in list(sel.keys()):
            if isinstance(key, str) and _MODIFIER_RE.match(key):
                return (sel_name, key)
    return None


def can_misspell_modifier(data, raw):
    return _find_endswith_field(data) is not None


def mut_misspell_modifier(data, raw):
    d = _deep_reload(raw)
    found = _find_endswith_field(d)
    if not found:
        return None, False
    sel_name, key = found
    new_key = key.replace("|endswith", "|endswtih", 1)
    sel = d["detection"][sel_name]
    # Rebuild dict preserving order
    new_sel = type(sel)()
    for k, v in sel.items():
        if k == key:
            new_sel[new_key] = v
        else:
            new_sel[k] = v
    d["detection"][sel_name] = new_sel
    return dump_rule(d), True


def _find_field_named(data, name):
    """Find a field whose base name is `name` inside a *dict* selector.

    Restricted to dict selectors (see _find_endswith_field for rationale):
    sigmalint v0.1.0's TAX001 walker skips list-of-dict selectors, so a
    mutation inside one is invisible to the detector.
    """
    det = data.get("detection") if isinstance(data, dict) else None
    if not isinstance(det, dict):
        return None
    for sel_name, sel in det.items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for key in sel:
            if not isinstance(key, str):
                continue
            base = key.split("|", 1)[0]
            if base == name:
                return (sel_name, key)
    return None


# Categories that the bundled Sigma taxonomy (fields.yml) populates.
# TAX001 short-circuits to "known" for any other category (see
# data/taxonomy.py SigmaTaxonomy.is_known), so the mutator is invisible
# outside this set. Restricting candidates avoids false negatives that
# would otherwise reflect taxonomy coverage rather than mutator efficacy.
_KNOWN_CATEGORIES_WITH_IMAGE = {
    "process_creation",
    "network_connection",
    "registry_event",
    "file_event",
    "dns_query",
}


def can_unknown_field(data, raw):
    if not isinstance(data, dict):
        return False
    ls = data.get("logsource") or {}
    if not isinstance(ls, dict):
        return False
    if ls.get("category") not in _KNOWN_CATEGORIES_WITH_IMAGE:
        return False
    return _find_field_named(data, "Image") is not None


def mut_unknown_field(data, raw):
    d = _deep_reload(raw)
    found = _find_field_named(d, "Image")
    if not found:
        return None, False
    sel_name, key = found
    new_key = key.replace("Image", "Imagee", 1)
    sel = d["detection"][sel_name]
    new_sel = type(sel)()
    for k, v in sel.items():
        if k == key:
            new_sel[new_key] = v
        else:
            new_sel[k] = v
    d["detection"][sel_name] = new_sel
    return dump_rule(d), True


def can_empty_falsepositives(data, raw):
    if not isinstance(data, dict):
        return False
    fp = data.get("falsepositives")
    if not isinstance(fp, list) or not fp:
        return False
    # Must currently NOT be "Unknown" only
    norm = [str(x).strip().lower() for x in fp]
    return any(n and n != "unknown" for n in norm)


def mut_empty_falsepositives(data, raw):
    d = _deep_reload(raw)
    d["falsepositives"] = ["Unknown"]
    return dump_rule(d), True


def _condition_str(data):
    det = data.get("detection") if isinstance(data, dict) else None
    if not isinstance(det, dict):
        return None
    cond = det.get("condition")
    return cond if isinstance(cond, str) else None


def can_strip_filter_on_noisy(data, raw):
    """Process_creation rules with a `not <selector>` in condition."""
    if not isinstance(data, dict):
        return False
    ls = data.get("logsource") or {}
    if not isinstance(ls, dict) or ls.get("category") != "process_creation":
        return False
    cond = _condition_str(data)
    if not cond:
        return False
    m = re.search(r"\band\s+not\s+([A-Za-z0-9_*]+)\b", cond)
    if not m:
        return False
    filt = m.group(1)
    det = data["detection"]
    if filt.endswith("*"):
        prefix = filt[:-1]
        return any(k.startswith(prefix) and k != "condition" for k in det)
    return filt in det


def mut_strip_filter_on_noisy(data, raw):
    """Remove every `and not <selector>` clause and drop those selectors.

    Some rules carry multiple negated filters (e.g., one per noisy
    sub-pattern). Stripping just one would leave FP003's gate satisfied;
    we remove them all so the rule becomes the unconditioned form that
    FP003 is designed to flag.
    """
    d = _deep_reload(raw)
    cond = _condition_str(d)
    if not cond:
        return None, False
    pattern = re.compile(r"\band\s+not\s+([A-Za-z0-9_*]+)\b")
    filters = pattern.findall(cond)
    if not filters:
        return None, False
    new_cond = pattern.sub("", cond)
    new_cond = re.sub(r"\s+", " ", new_cond).strip()
    d["detection"]["condition"] = new_cond
    for filt in filters:
        # Handle wildcard like `filter_*`
        if filt.endswith("*"):
            prefix = filt[:-1]
            for k in list(d["detection"].keys()):
                if k != "condition" and k.startswith(prefix):
                    del d["detection"][k]
        elif filt in d["detection"]:
            del d["detection"][filt]
    return dump_rule(d), True


def can_invalid_uuid(data, raw):
    return isinstance(data, dict) and isinstance(data.get("id"), str)


def mut_invalid_uuid(data, raw):
    d = _deep_reload(raw)
    d["id"] = "not-a-uuid"
    return dump_rule(d), True


def can_break_yaml(data, raw):
    return data is not None


def mut_break_yaml(data, raw):
    # Insert a stray colon at top — break parse by appending dangling key.
    lines = raw.splitlines()
    # Insert ":::" line after first non-comment line
    for i, ln in enumerate(lines):
        if ln.strip() and not ln.lstrip().startswith("#"):
            lines.insert(i + 1, "::: : :")
            break
    return "\n".join(lines) + "\n", True


def can_clear_refs_high(data, raw):
    if not isinstance(data, dict):
        return False
    lvl = data.get("level")
    if not isinstance(lvl, str) or lvl.lower() not in ("high", "critical"):
        return False
    refs = data.get("references")
    return isinstance(refs, list) and len(refs) > 0


def mut_clear_refs_high(data, raw):
    d = _deep_reload(raw)
    d["references"] = []
    return dump_rule(d), True


@dataclass
class Mutator:
    name: str
    target_rule: str
    can: Callable
    mutate: Callable


MUTATORS = [
    Mutator("revoke_attack_tag", "ATK002", can_revoke_attack_tag, mut_revoke_attack_tag),
    Mutator("unknown_attack_tag", "ATK001", can_unknown_attack_tag, mut_unknown_attack_tag),
    Mutator("misspell_modifier", "TAX002", can_misspell_modifier, mut_misspell_modifier),
    Mutator("unknown_field", "TAX001", can_unknown_field, mut_unknown_field),
    Mutator("empty_falsepositives", "META004", can_empty_falsepositives, mut_empty_falsepositives),
    Mutator("strip_filter_on_noisy", "FP003", can_strip_filter_on_noisy, mut_strip_filter_on_noisy),
    Mutator("invalid_uuid", "META001b", can_invalid_uuid, mut_invalid_uuid),
    Mutator("break_yaml", "SCHEMA001", can_break_yaml, mut_break_yaml),
    Mutator("clear_references_high_level", "META003", can_clear_refs_high, mut_clear_refs_high),
]


# ---------------------------------------------------------------------------
# Linting
# ---------------------------------------------------------------------------


def lint_paths(sigmalint: str, paths: list[Path]) -> dict[str, list[str]]:
    """Return {abs_path: [rule_id, ...]} for findings."""
    if not paths:
        return {}
    cmd = [sigmalint, "lint", "--format", "json", "--fail-on", "never"]
    cmd.extend(str(p) for p in paths)
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if not out.stdout.strip():
        sys.stderr.write(out.stderr)
        raise RuntimeError("sigmalint produced no output")
    data = json.loads(out.stdout)
    result = {}
    for f in data["files"]:
        result[str(Path(f["path"]).resolve())] = [x["rule_id"] for x in f.get("findings", [])]
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def collect_rule_files(corpus: Path) -> list[Path]:
    roots = []
    for name in [
        "rules",
        "rules-emerging-threats",
        "rules-threat-hunting",
        "rules-compliance",
        "rules-dfir",
    ]:
        p = corpus / name
        if p.is_dir():
            roots.append(p)
    files = []
    for r in roots:
        files.extend(sorted(r.rglob("*.yml")))
    return files


def sigmalint_commit(sigmalint: str) -> str:
    # Best-effort: search parent dirs for a git repo
    p = Path(sigmalint).resolve()
    for parent in [p.parent, *p.parents]:
        if (parent / ".git").exists():
            try:
                r = subprocess.run(
                    ["git", "-C", str(parent), "rev-parse", "--short", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                return r.stdout.strip()
            except Exception:
                pass
    return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True, type=Path)
    ap.add_argument("--sigmalint", required=True, type=str)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--sample-size", type=int, default=SAMPLE_SIZE)
    args = ap.parse_args()

    rng = random.Random(SEED)

    print(f"[1/4] Enumerating rules under {args.corpus}", file=sys.stderr)
    all_files = collect_rule_files(args.corpus)
    print(f"      {len(all_files)} rule files", file=sys.stderr)

    print("[2/4] Loading and parsing rules", file=sys.stderr)
    loaded: list[tuple[Path, object, str]] = []
    for p in all_files:
        try:
            data, raw = load_rule(p)
        except Exception:
            continue
        if data is None:
            continue
        loaded.append((p, data, raw))
    print(f"      {len(loaded)} parseable", file=sys.stderr)

    print("[3/4] Baseline lint (all rules, batched)", file=sys.stderr)
    # Batch to avoid huge argv. Lint per-directory subsets.
    baseline: dict[str, list[str]] = {}
    BATCH = 200
    paths_only = [p for p, _, _ in loaded]
    for i in range(0, len(paths_only), BATCH):
        chunk = paths_only[i : i + BATCH]
        baseline.update(lint_paths(args.sigmalint, chunk))
        print(f"      baseline {i + len(chunk)}/{len(paths_only)}", file=sys.stderr)

    print("[4/4] Mutate & lint per mutator", file=sys.stderr)
    results = []
    for mut in MUTATORS:
        # Candidate filter: applicable AND target rule does not already fire
        pool = []
        for p, data, raw in loaded:
            base_findings = baseline.get(str(p.resolve()), [])
            if mut.target_rule in base_findings:
                continue
            try:
                if mut.can(data, raw):
                    pool.append((p, data, raw))
            except Exception:
                continue
        pool_size = len(pool)
        n = min(args.sample_size, pool_size)
        sample = rng.sample(pool, n) if n else []

        print(f"  - {mut.name} -> {mut.target_rule}: pool={pool_size}, n={n}", file=sys.stderr)

        if n == 0:
            results.append(
                {
                    "mutator": mut.name,
                    "target_rule": mut.target_rule,
                    "candidate_pool_size": 0,
                    "samples_tested": 0,
                    "recall": None,
                    "true_positives": 0,
                    "missed": 0,
                    "mean_collateral_findings": None,
                    "missed_examples": [],
                }
            )
            continue

        # Write mutated copies to a temp dir; lint as batch.
        with tempfile.TemporaryDirectory(prefix=f"seeded_{mut.name}_") as td:
            tdp = Path(td)
            mapping = []  # (original_path, tmp_path)
            for idx, (p, data, raw) in enumerate(sample):
                try:
                    mutated_text, ok = mut.mutate(data, raw)
                except Exception as e:
                    sys.stderr.write(f"    mutate error on {p}: {e}\n")
                    continue
                if not ok or mutated_text is None:
                    continue
                tmp = tdp / f"{idx:04d}_{p.name}"
                tmp.write_text(mutated_text, encoding="utf-8")
                mapping.append((p, tmp))

            tmp_paths = [t for _, t in mapping]
            mfindings: dict[str, list[str]] = {}
            for i in range(0, len(tmp_paths), BATCH):
                chunk = tmp_paths[i : i + BATCH]
                mfindings.update(lint_paths(args.sigmalint, chunk))

            tp = 0
            missed_examples = []
            collateral_totals = []
            for orig, tmp in mapping:
                post = mfindings.get(str(tmp.resolve()), [])
                base = baseline.get(str(orig.resolve()), [])
                if mut.target_rule in post:
                    tp += 1
                else:
                    if len(missed_examples) < 5:
                        missed_examples.append(str(orig.relative_to(args.corpus)))
                # Collateral: post-mutation findings not in baseline,
                # excluding the target rule itself.
                base_set = set(base)
                extras = [r for r in post if r != mut.target_rule and r not in base_set]
                collateral_totals.append(len(extras))

            denom = len(mapping)
            recall = tp / denom if denom else None
            mean_coll = sum(collateral_totals) / denom if denom else None
            results.append(
                {
                    "mutator": mut.name,
                    "target_rule": mut.target_rule,
                    "candidate_pool_size": pool_size,
                    "samples_tested": denom,
                    "recall": round(recall, 4) if recall is not None else None,
                    "true_positives": tp,
                    "missed": denom - tp,
                    "mean_collateral_findings": round(mean_coll, 4)
                    if mean_coll is not None
                    else None,
                    "missed_examples": missed_examples,
                }
            )

    payload = {
        "version": "0.1.0",
        "sigmalint_commit": sigmalint_commit(args.sigmalint),
        "sigmahq_commit": SIGMAHQ_COMMIT,
        "seed": SEED,
        "results": results,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Human-readable summary
    print()
    print(f"Seeded-defect benchmark (seed={SEED}, sigmalint={payload['sigmalint_commit']})")
    print(f"{'mutator':32s} {'target':10s} {'pool':>6s} {'N':>4s} {'recall':>8s} {'coll':>6s}")
    for r in results:
        rec = "n/a" if r["recall"] is None else f"{r['recall']:.3f}"
        mc = r["mean_collateral_findings"]
        coll = "n/a" if mc is None else f"{mc:.2f}"
        print(
            f"{r['mutator']:32s} {r['target_rule']:10s} "
            f"{r['candidate_pool_size']:>6d} {r['samples_tested']:>4d} "
            f"{rec:>8s} {coll:>6s}"
        )
    print(f"\nWritten: {args.out}")


if __name__ == "__main__":
    main()
