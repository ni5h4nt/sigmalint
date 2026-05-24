# SigmaHQ Corpus Analysis — Calibration Shift

Analysis run against the SigmaHQ corpus snapshot under the following data versions:

| dataset | version |
|---|---|
| `sigma_schema` | `2.1.0` |
| `attack` | `v19.1` |
| `taxonomy` | `sigma@v0.1` |
| `modifiers` | `2.1.0` |
| `attack_logsource_map` | `v0.1` |
| `corpus` | `None` |

Reproducibility: re-running `sigmalint lint` on the same SigmaHQ commit with these `data_versions` must yield the same `findings` array and therefore the same pre/post score columns below.

## Validity rate

- files scanned: **3132**
- valid (no SCHEMA error): **3132** (100.00%)

## Mean total score — calibration delta

| formula | mean total |
|---|---|
| pre-fix `100 - sum(penalty)` | 99.6150 |
| post-fix `100 * (1 - sum/max_penalty)` | 99.0723 |
| delta (new - old) | -0.5427 |

## Total-score histogram

| bucket | pre-fix | post-fix |
|---|---:|---:|
| [0,50) | 0 | 0 |
| [50,75) | 0 | 0 |
| [75,90) | 0 | 2 |
| [90,95) | 0 | 5 |
| [95,98) | 5 | 303 |
| [98,99) | 65 | 1018 |
| [99,99.5) | 1250 | 293 |
| [99.5,99.8) | 301 | 763 |
| [99.8,100] | 1511 | 748 |

## Per-dimension mean score (pre vs post)

| dimension | pre-fix mean | post-fix mean | delta | max_penalty cap |
|---|---:|---:|---:|---:|
| attack | 99.9853 | 99.9633 | -0.0220 | 40.0 |
| taxonomy | 99.9655 | 99.8851 | -0.0804 | 30.0 |
| fp_risk | 98.7053 | 96.7633 | -1.9420 | 40.0 |
| metadata | 99.5425 | 99.2374 | -0.3051 | 60.0 |
| redundancy | 100.0000 | 100.0000 | +0.0000 | 20.0 |
| style | 99.6638 | 98.8793 | -0.7845 | 30.0 |

## Top 15 findings by rule_id

| rank | rule_id | count |
|---:|---|---:|
| 1 | META004 | 1316 |
| 2 | FP003 | 1271 |
| 3 | STY003 | 1053 |
| 4 | FP004 | 98 |
| 5 | FP001 | 38 |
| 6 | META001b | 37 |
| 7 | TAX001 | 35 |
| 8 | ATK004 | 31 |
| 9 | FP002 | 30 |
| 10 | ATK003 | 15 |
| 11 | META003 | 2 |
| 12 | TAX002 | 1 |

## 10 lowest-scoring rules under the post-fix formula

| rank | total | path | findings |
|---:|---:|---|---|
| 1 | 89.20 | `sigmahq/rules/windows/network_connection/net_connection_win_wuauclt_network_connection.yml` | `FP004`, `META004`, `TAX001`, `TAX001`, `TAX001`, `TAX001`, `TAX001` |
| 2 | 89.50 | `sigmahq/rules/windows/network_connection/net_connection_win_python.yml` | `FP004`, `TAX001`, `TAX001`, `TAX001`, `TAX001`, `TAX001` |
| 3 | 91.20 | `sigmahq/rules/web/proxy_generic/proxy_ua_malware.yml` | `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP002`, `FP004`, `META004` |
| 4 | 92.20 | `sigmahq/rules/windows/network_connection/net_connection_win_susp_binary_no_cmdline.yml` | `FP003`, `META004`, `TAX001`, `TAX001`, `TAX001` |
| 5 | 93.50 | `sigmahq/rules/windows/network_connection/net_connection_win_rundll32_net_connections.yml` | `FP004`, `TAX001`, `TAX001`, `TAX001` |
| 6 | 93.67 | `sigmahq/rules/windows/file/file_event/file_event_win_net_cli_artefact.yml` | `STY003`, `TAX001`, `TAX001`, `TAX001` |
| 7 | 93.87 | `sigmahq/rules/windows/file/file_event/file_event_win_ntds_dit_uncommon_parent_process.yml` | `FP003`, `META004`, `STY003`, `TAX001`, `TAX001` |
| 8 | 95.70 | `sigmahq/rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml` | `FP003`, `FP004`, `META004`, `TAX001` |
| 9 | 95.70 | `sigmahq/rules/windows/process_creation/proc_creation_win_susp_child_process_as_system_.yml` | `META004`, `TAX001`, `TAX001` |
| 10 | 95.87 | `sigmahq/rules/windows/file/file_event/file_event_win_exchange_webshell_drop.yml` | `FP003`, `META004`, `STY003`, `TAX001` |

## Per-dimension finding-count distribution (per file)

| dimension | mean | median | p90 |
|---|---:|---:|---:|
| attack | 0.015 | 0.000 | 0.000 |
| taxonomy | 0.011 | 0.000 | 0.000 |
| fp_risk | 0.459 | 0.000 | 1.000 |
| metadata | 0.433 | 0.000 | 1.000 |
| redundancy | 0.000 | 0.000 | 0.000 |
| style | 0.336 | 0.000 | 1.000 |

## Notes for the paper

- The calibration delta is small but systematic. Under the pre-fix anchor, the *absolute* penalty units are identical regardless of how many rules a dimension contains, so a single warning in `redundancy` (2 rules, current max_penalty = 20) and a single warning in `metadata` (6 rules, current max_penalty = 60) both drop a dim_score by the same 3 points — meaning the redundancy violation receives effectively a third of the proportional weight. The post-fix formula re-anchors each dimension to its own ceiling: the same warning now drops redundancy by 15 percentage points and metadata by 5. The directions of the per-dimension means in the table above reflect this: dimensions whose max_penalty is below 100 (every quality dimension under v0.1's rule counts) attract *more* penalty per finding under the new formula, and the mean total drops accordingly. This is the intended calibration — the formula now reports rate of firing, not absolute count.
- SCHEMA004 produces zero findings across the corpus snapshot. The validity gate therefore exercises SCHEMA001 (YAML) and SCHEMA002-003 (structural schema) almost exclusively in practice; SCHEMA004 acts as a guard against a class of malformations that the public SigmaHQ corpus does not contain.
- The top three findings (META004, FP003, STY003) account for the bulk of the corpus's quality penalty. Future calibration work should explore whether their default severities are correctly tuned.
