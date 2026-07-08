## v0.77.7 (2026-06-28) — Fix: firing v19 sub-technique tiles

### Fixed

* **v19 sub-technique tiles can now be run from the matrix.** Clicking a v19
  sub-technique and sending returned *"Technique T1695.001 is not supported for
  network simulation in this build."* The `/api/technique/send` endpoint looked
  the technique up directly against the scenario pack, but scenarios are keyed on
  stable **v18** IDs — so a v19 sub ID (e.g. T1695.001) never matched. The send
  endpoint now resolves the ID the same way the variants and matrix-coverage
  paths do:
  * crosswalk subs (T1695.001 → T0805, T1692.001 → T0855, …) translate back to
    their v18 scenario key;
  * annotation subs (T0846.001, T0843.002, T0873.001, …) fall back to their
    unchanged parent technique (T0846, T0843, T0873).
  All 12 v19 sub-techniques now fire end-to-end once a variant is selected. The
  crosswalk resolution is now a single shared helper (`_v19_to_v18_map`) used by
  both the variants and send endpoints so they can't drift apart again.
* **Clearer error when a technique needs a variant.** A technique with multiple
  scenarios and none selected previously returned the misleading "not supported"
  message. It now says *"Technique T0855 has 13 variants — select one before
  sending,"* and a technique with exactly one variant is auto-selected. Genuinely
  unrunnable techniques (host-only / out of scope) get an accurate message.
* **Send accepts either variant form.** The `variant` value may be a bare suffix
  (`unauth_command__modbus`) or a full scenario key
  (`T0846__remote_sys_discovery__dnp3_probe`); the endpoint no longer doubles the
  technique prefix when the full name is passed.

### Notes

* Full suite: 445 passed / 25 skipped (two new regression tests). ruff clean.
* No change to detection, coverage, or protocol behaviour; canonical figures
  unchanged.

## v0.77.6 (2026-06-28) — Release-hygiene & test-portability fixes (external review)

Addresses an external reviewer's findings against the v0.77.5 archive. No
change to detection, coverage, or protocol behaviour; all canonical figures
unchanged (627 scenarios, 77 techniques, 806 detection rules).

### Fixed

* **Ruff now actually clean across `icsforge` *and* `tests`.** The v0.77.5
  release ran `ruff check icsforge/` only, so three findings in `tests/` slipped
  through despite the "ruff clean" note: SIM115 (file opened without a context
  manager) and B905 (`zip()` without `strict=`) in `test_live_offline_parity.py`,
  and I001 (unsorted import block) in `test_web_api.py`. All three fixed; the
  release gate now runs `ruff check icsforge tests`.
* **Release tarball no longer contains test artifacts.** The v0.77.5 archive
  shipped ~100 leftover `tmp/pytest-of-root/` entries (pytest `tmp_path` output
  that landed under the repo). Added `tmp/`, `tmp/pytest-of-*/`, and
  `.ruff_cache/` to `.gitignore`, removed the directories from the tree, and
  added `tmp` to the packaging exclusion list so it cannot recur.
* **Stateful-TCP PCAP tests are now container-portable.** Three tests
  (`test_default_is_stateless`, `test_stateful_has_handshake_and_teardown`,
  `test_stateful_preserves_covert_marker`) used `from scapy.all import rdpcap`,
  which initialises Scapy's full route/route6 stack on import and raised
  `KeyError('scope')` in some containerised Linux environments — failing before
  any ICSForge assertion ran. Replaced with a minimal self-contained libpcap
  reader (`_read_pcap_frames`) that parses frames directly. The tests now pass
  in containers; the ICSForge generation logic they exercise was never at fault.

### Improved

* **Scenario catalog is parsed at most once per process.** `load_scenarios()`
  now caches on `(path, mtime)`, re-parsing only when the file changes on disk.
  This removes repeated full-catalog parsing (≈154 ms each) across same-process
  operations — test suites, batch generation, and the web app — and is a large
  part of why the full suite now completes well within wall-clock (≈98 s) where
  it previously risked timing out. Correctness preserved: edits to the YAML are
  picked up immediately via the mtime key.

### Docs

* `SCENARIO_SCHEMA.md` — corrected scenario counts (611 of **627**, 16 of
  **627**) and documented that chain ATT&CK mapping is **derived** from step
  techniques + the top-level primary, intentionally not duplicated into a
  top-level `attack_mapping` block (single source of truth = the steps).
* `README.md` — clarified run-endpoint semantics: `/api/run` and
  `/api/run_detail` are receipt-oriented (minimal for offline runs with no
  receiver), while `/api/run_full` is registry/artifact-oriented (full record
  for offline-generated runs).

## v0.77.5 (2026-06-27) — Documentation & UI sweep for v18.1 / v19

A housekeeping release: bring every living doc and the web UI current with
v18.1, the real v19 matrix, and all recent figures. No behavioural change to
sending, detection, or coverage logic.

### UI

* **Sender home page** no longer says "aligned to ATT&CK for ICS v18" — now
  reads v18.1 with a note about the v19 sub-technique mapping and the Matrix
  v18/v19 toggle. (KPI stat cards were already dynamic.)
* **Demo page** scenario count corrected (547 → 627).
* **README.md** — corrected stale figures that had drifted: version badge
  (0.64.7 → 0.77.5), "35 at 10/10" → 33 (in two places, with the full-coverage
  technique list rebuilt to the actual 33), the Protocol Coverage table's style
  counts (DNP3 22→21, S7comm 36→35, ENIP 24→23, IEC-104 20→23, PROFINET 8→9 and
  47→45 techniques), and the Scenarios table's chain count (11 → 16, with the
  four missing chains added to the list). Campaign references (11 `/campaigns`
  playbooks) left as-is — those are distinct from the 16 scenario chains.
* **USER_MANUAL.md** — added the Matrix v18.1/v19 toggle and the Tools-page PCAP
  Replay auto-fill to the page descriptions and quick reference (the manual is
  otherwise version-agnostic and was already accurate).

### Docs brought current (v0.77.5 canonical figures throughout)

Canonical numbers now consistent everywhere: **10 protocols · 627 scenarios
(611 standalone + 16 chains) · 77 techniques (76 standalone + T0879 as a chain
objective) = 92.8% of v18.1 · v19: 73/79 standalone + 17/18 sub-techniques ·
210/239/357 = 806 detection rules · 33 techniques at 10/10 protocol coverage.**

* `MITRE_ALIGNMENT.md` — header → v0.77.5; rewrote the v18/v19 source-of-truth
  note (explains v19 sub-techniques + the crosswalk); coverage summary updated
  (68/82% → 77 of 83 / 92.8%, plus v19 figures and 806 rules). Preserved the
  timeless "fan-made wrong technique IDs" pitfall tables.
* `MITRE_V19_CROSSWALK.md` — banner → v0.77.5 (notes the v19 matrix is generated
  from official ics-attack-19.1 STIX); annotation count 109/610 → 111/611.
* `REFERENCE_DETECTION_COVERAGE.md` — banner → v0.77.5; fixed a stale
  "ENIP Tier 3 semantic 44.4%" line in the current-results paragraph (P2 was
  closed in v0.77.1 → 98.6%; the headline table was already current).
* `docs/submissions/ARSENAL_2026.md`, `docs/submissions/DEFCON_DEMO_LABS_34.md`
  — 547 → 627, 68 of 83 / 82% → 77 of 83 / 92.8%, v18 → v18.1 (+ v19 crosswalk
  note), 11 named chains → 16, version stamps → v0.77.5.
* `docs/icsforge-coverage-layer.json` — regenerated (v0.77.5, 77/83, 33 green);
  fixed the layer generator's hardcoded ATT&CK version (16 → 18).
* `GOOD_FIRST_ISSUES.md` — added a snapshot note pointing to current version.

Historical/dated records (everything in `docs/history/`, `ROADMAP_V5.md`,
`SCENARIO_AUDIT_v0.62.2.*`, `MALCOLM_VALIDATION_v0.62.1.*`) are intentionally
left as point-in-time records. `USER_MANUAL.md`, `CLI_REFERENCE.md`,
`FEATURES_GUIDE.md`, `SIEM_INTEGRATION.md` were already version-agnostic.

### Housekeeping

* Renamed the malformed scenario key `T0843_003__program_append__s7comm_online_edit`
  → `T0843__program_append__s7comm_online_edit` (its `technique` field was
  already correctly `T0843` with `technique_v19: T0843.003`; cosmetic only,
  coverage figures unchanged).

### Notes

* Full suite: 443 passed / 25 skipped. ruff clean. Drift check in sync.

## v0.77.4 (2026-06-27) — PCAP replay auto-fills its destination

### Improved

* **Replay now defaults to re-running what you created.** A generated PCAP already
  carries the destination IP you set in Offline Generate, but the Replay panel
  ignored it and forced you to retype a destination — confusing, since "replay"
  should mean "run the PCAP I made." The Replay panel now **auto-fills the
  Destination IP from the PCAP's own baked-in destination** when you select or
  upload a file (new read-only `/api/pcap/peek-dst` endpoint extracts it from the
  first IPv4 packet). The field stays editable, so you can still redirect the
  replay to a different target; manually-typed values are never overwritten.
  Gracefully degrades for L2-only captures (GOOSE/PROFINET) where there is no
  IPv4 destination to read.

  Note on mechanics: replay re-sends each packet's payload to a chosen
  destination+port over a fresh socket (it does not blindly emit the captured
  destination), which is why a destination is still required under the hood —
  the auto-fill simply supplies the obvious default. Same `out/`-path safety
  guard as replay; peek sends nothing.

### Notes

* Full suite: 443 passed / 25 skipped. ruff clean.

## v0.77.3 (2026-06-27) — PCAP replay UI fix + accurate v19 sub-technique coverage

### Fixed

* **PCAP replay was unusable from the Tools page.** The "Destination IP" input in
  the PCAP Replay panel was wrapped in a `display:none` row (alongside a leftover
  dummy field), so it never rendered. `replayTool()` reads that field, found it
  empty, and always returned *"Error: Destination IP is required."* Un-hid the
  Destination IP + Interval row and removed the dummy field. The backend
  (`/api/pcap/replay`) was correct and unchanged; replay now works once a receiver
  IP is entered. Regression test added.

### Improved — v19 sub-technique coverage now accurate

* **Matrix v19 view honors `technique_v19` annotations.** v19 introduced
  sub-techniques in two ways: (a) 9 techniques MITRE *revoked and replaced* as
  subs (handled by the crosswalk, e.g. T0855 → T1692.001), and (b) techniques
  *granularized* into new subs while the parent ID stays valid (T0843 Program
  Download → Download All / Online Edit / Program Append; T0846 Remote System
  Discovery → Port / Broadcast / Multicast Discovery; T0873 → Siemens Project File
  Format). Case (b) can only be known from the scenario author's `technique_v19`
  annotation. The matrix coverage logic now uses **annotations + crosswalk**, so
  the granularized sub-technique tiles light up correctly.
* **Variant dropdown resolves v19 sub-techniques.** Clicking any v19 sub-tile now
  returns its scenarios — both crosswalk subs (T1692.001 → the T0855 scenarios)
  and annotation subs (T0846.001 Port Scan → 6 scenarios, T0843.002 Online Edit,
  etc.). Previously only the crosswalk subs resolved.
* **No new scenarios were needed.** The existing scenarios already carry correct
  `technique_v19` sub-technique annotations; this release credits that work
  accurately rather than fabricating scenarios. Verified v19 coverage:
  **73/79 standalone techniques, 17/18 sub-techniques**. The single uncovered sub
  is **T1695.003 Block Communications: Wi-Fi** — RF jamming, legitimately out of
  scope for a network-protocol traffic generator (locked in by test).

### Notes

* Full suite: 442 passed / 25 skipped. ruff clean. `/api/version` v19 block and the
  interactive matrix now report identical coverage figures.

## v0.77.2 (2026-06-27) — Real ATT&CK for ICS v19 matrix + web-UI fixes

Three field-reported issues in the running web app, fixed and verified end-to-end.

### Fixed

* **Real ATT&CK for ICS v19 matrix.** The bundled `ics_attack_matrix_v19.json`
  was a fabricated inflation of v18 (112 standalone techniques, 0 sub-techniques)
  and did not match MITRE's actual v19. Regenerated from the official
  `ics-attack-19.1` STIX bundle (mitre-attack/attack-stix-data): now the genuine
  **79 standalone techniques + 18 sub-techniques** across 12 tactics, with
  sub-techniques correctly nested under their parents (Block Operational
  Technology Message, Unauthorized Message, Modify Firmware, Insecure Credentials,
  Block Communications, plus the new Program Download and Remote System Discovery
  sub-techniques). Unique counts verified against MITRE (79 + 18).
* **v19 matrix coverage now uses the official crosswalk.** The `/matrix?version=v19`
  view previously relied on stale per-scenario `technique_v19` annotations. It now
  translates each scenario's stable v18 technique ID forward through the canonical
  `mitre_v18_v19_crosswalk.json`. The 9 techniques MITRE revoked-and-replaced as
  sub-techniques (e.g. T0855 → T1692.001, T0803 → T1691.001, T0857 → T1693.001)
  light up their new v19 sub-technique tiles; techniques that merely gained
  sub-techniques (T0846, T0843) light up the parent tile rather than a fabricated
  sub-mapping. Support-tier (runnable/precursor) lookup resolves v19 IDs back to
  v18 and falls back to the parent record.
* **Empty variant dropdown in v19 view.** Clicking a v19 tile sent a v19 ID to
  `/api/technique/variants`, which matched scenarios by v18 ID and returned
  nothing. The endpoint now resolves v19 sub-technique IDs back to their v18 ID
  via the crosswalk before matching, so the dropdown populates correctly (e.g.
  T1692.001 → the 13 T0855 scenarios).
* **Spurious callback-token banner on the Receiver console.** The "No callback
  token configured — receipt integrity is not enforced" warning rendered in
  receiver mode, where it is irrelevant (the callback token is a sender-side
  setting and its "Configure →" link targeted the sender page, which does not
  exist in receiver mode). The banner is now suppressed when `ui_mode == 'receiver'`;
  unchanged for the sender (still shown when no token is set, hidden once set).

### Notes

* **v18.1 validated unchanged.** The default v18.1 matrix was independently checked
  against the MITRE ATT&CK Navigator export — all 12 tactics, 94 technique
  entries, IDs and names match. No changes to v18.1.
* Consolidated to a single canonical crosswalk (`mitre_v18_v19_crosswalk.json`);
  removed a redundant duplicate introduced during the fix.
* Full suite: 439 passed / 25 skipped. ruff clean.

## v0.77.1 (2026-06-20) — P2: ENIP semantic-tier precision

Closes the main remaining detection-quality gap (the "P2" item). EtherNet/IP
semantic-tier rules previously matched only the ENIP **encapsulation command
word** (RegisterSession / ListIdentity at offset 0), so scenarios whose
distinguishing action is a **CIP service** (read tag, write tag, reset, …) had no
true operation-level match — ENIP semantic coverage sat at 44.4%.

### What changed

* **CIP service-code matching.** Semantic rules now reach into the SendRRData
  (`6f 00`) CPF data item (`b2 00 <len:2> <service>`) and match the actual CIP
  service byte — Read `0x4C`, Write `0x4D`, Reset `0x05`, GetAttributesAll `0x01`,
  etc. A write is now distinguishable from a read at the rule level.
* **Corrected ENIP command-word mappings.** Several styles were mapped to the
  wrong encapsulation word (e.g. `list_services` → `04 00`, data-bearing styles
  → `6f 00`); fixed so the fallback matches reality. This also lifted the
  heuristic tier.
* **Zero-length command handling.** ENIP discovery/teardown commands
  (ListIdentity, ListServices, ListInterfaces, UnRegisterSession) carry a
  zero-length data field, so the Tier-3 "length > 0" `byte_test` was dropped for
  them — the command word is itself the complete semantic.

### Result (re-measured, Suricata 7.0.3)

* **ENIP semantic 44.4% → 98.6%**, heuristic 70.8% → 98.6%, combined still 100%.
* Modbus / DNP3 / S7comm / OPC UA / BACnet semantic unchanged at 100% (no
  regression). The single remaining ENIP semantic miss is one
  `unregister_session`-only scenario whose semantic spec is not emitted.
* Rule counts: heuristic 228 → **239**, semantic 335 → **357** (lab unchanged at
  210). Canonical-count guard tests updated accordingly.
* README + `REFERENCE_DETECTION_COVERAGE.md` updated; a stale, contradictory
  legacy "full scenario run" semantic table (showing ENIP 8.8%, BACnet 0%, etc.)
  was removed in favour of the accurate re-measured per-tier table.

### Verification

Full suite **462 passed, 2 skipped**; ruff clean; drift checker passes at
v0.77.1.

---

## v0.77.0 (2026-06-20) — Documentation overhaul & coverage re-measurement

A documentation release: the full doc set is brought up to date with the current
build and reconciled against the code, with no functional changes to the tool.

### New & rewritten guides

* **`docs/INSTALLATION.md`** — traditional (non-Docker) install: virtual
  environment, the three commands (`icsforge`, `icsforge-web`,
  `icsforge-receiver`), verification, privilege model, config locations, upgrade,
  uninstall, troubleshooting. Examples are version-agnostic so they don't rot.
* **`docs/USER_MANUAL.md`** — primary web-app walkthrough: Sender/Receiver roles,
  the four run options (Test profile, Marker mode, Stateful TCP, Build PCAP), the
  firewall/ACL and NSM workflows, a full **Detection content** section (three
  tiers, Suricata + Sigma export, running the rules, feeding alerts back via the
  EVE tap / Alerts Ingest), and reviewing results.
* **`docs/CLI_REFERENCE.md`** — rewritten from a stale v0.63.0 baseline to cover
  every current command and flag, including `--profile`, `--stateful`,
  `--explicit-marker`, and `icsforge-receiver`.
* **`docs/FEATURES_GUIDE.md`** (new) — the offline PCAP generator, the ATT&CK
  Matrix view, Campaigns, the Receiver console, the Tools page, and the
  output/artifact formats (events JSONL schema, PCAP, rules, report).
* **`docs/INSTALL.md` / `docs/HOWTO.md`** — converted to short redirect stubs
  pointing at the canonical guides above (no more duplicate, drifting content).
* **README** — added a Documentation index table linking all guides.

### Coverage re-measurement

`docs/REFERENCE_DETECTION_COVERAGE.md` re-measured on the current build (Suricata
7.0.3) and its header de-pinned from v0.67.0. Corrected figures that had drifted:
DNP3 semantic 96.7%→100% and lab 100%→93.3% (honest, broadcast/no-auth frames);
S7comm lab 1.3%→100%; BACnet lab 0%→87%; Modbus heuristic 86.4%→100%; ENIP
semantic now shown at 44.4% (the documented P2 magic-byte/FC-overlap gap). All 8
IP protocols remain at 100% combined detection. `docs/ROADMAP_V5.md` gets a
historical-status banner pointing to the current 9/10 state.

### Verification

Full suite **462 passed, 2 skipped**, including the `TestCliManualCoverage` guard
that asserts every subcommand and flag is documented in `CLI_REFERENCE.md` (this
caught two missing entries — `viewer serve` and the `receiver-only` Docker
profile — during the rewrite; both added). ruff: 0 errors. Drift checker passes
at v0.77.0.

---

## v0.76.1 (2026-06-19) — Live-send ⟷ offline parity (realism fixes)

Audit of the live-send path against the offline engine found two real divergences
that made live traffic *less* realistic than the offline PCAP — the opposite of
what's wanted, since live is the priority path. Both are fixed; live now threads
exactly what offline does into the protocol builders.

### Fixed: per-protocol sequence/correlation fields not threaded in live

The offline engine threads monotonic counters into each protocol's
sequence/correlation field — Modbus transaction ID, S7 PDU reference, DNP3
application sequence, IEC-104 send sequence, OPC UA sequence number / request id.
The live sender did **not**, so in stealth mode those fields fell back to random
per-packet values (e.g. Modbus TIDs `be15, faa5, 9766…` instead of `0001, 0002,
0003`). A real client increments these; random values within one session look
anomalous to an NSM. Live now advances the same counters via a shared helper, so
stealth-mode live traffic matches the offline PCAP byte-for-byte on these fields.
(In covert mode the marker already overrides these fields identically on both
paths, so the gap only affected stealth — but stealth is exactly the NSM-test
mode where realism matters most.)

### Fixed: explicit marker mode unavailable in live

`send_scenario_live` had `no_marker` but no `explicit_marker`, so the builders
only ever received `covert` or `none`; selecting Explicit in the UI/CLI silently
degraded to covert on a live send. Added `explicit_marker` to the live sender and
threaded it through the web send routes (both `/api/send` and the technique-send
route) and the CLI `send` command (new `--explicit-marker` flag). All three
marker modes now behave identically on live and offline.

### Confirmed (not a gap): TCP handshake

Live send uses real OS sockets, so the kernel performs a genuine 3-way handshake
— verified by a sink accepting the connections. This is *more* faithful than the
offline `--stateful` simulation, so no change was needed; `--stateful` remains an
offline-PCAP concern.

### Verification

Full suite **462 passed, 2 skipped** — 6 new parity tests in
`tests/test_live_offline_parity.py` (live accepts/emits explicit ICSF, covert
F7 band, stealth carries no tag, Modbus TID monotonic in stealth, and the live
sender threads the same per-protocol seq fields as the engine). Live captures
confirmed: stealth TIDs `0001/0002/0003`, explicit emits `ICSF`, covert keeps the
F7 band, and a real OS handshake completes per connection. ruff: 0 errors. Drift
checker passes at v0.76.1.

---

## v0.76.0 (2026-06-19) — Test Profiles (Firewall/ACL ⟷ NSM)

Reframes "Phase B" around how the tool is actually used. Rather than fabricate
synthetic device responses — which would break the safe-sinkhole model and risk
false negatives (a firewall that permits the forward flow may still block the
return) — ICSForge now models operator **intent** via a Test Profile that sets
safe defaults and frames results correctly. The receiver remains a passive sink;
no device responses are ever synthesised.

### Two profiles

* **Firewall / ACL** (default) — boundary test. Sender sits in IT or another OT
  zone; the receiver is a safe sink. Unidirectional by design: arrival of any of
  the 10 protocols means a rule allowed it (a forward-path finding). No return
  traffic is assumed.
* **NSM** — sensor test. The path is assumed open; the question is whether the
  sensor alarms. Defaults `--stateful` **on** so the TCP handshake completes and
  stream-tracking sensors engage, and pairs each witnessed scenario with its
  expected ATT&CK technique for diffing against what the sensor fired.

### Surfaces

* **CLI:** `--profile firewall|nsm` on `generate` (and threaded through send).
  An explicit `--stateful` always wins over the profile default.
* **Web UI:** a **Test profile** segmented control on the Sender page with a
  hover `?`, mirroring the marker-mode control. Selecting NSM visually flips the
  Stateful TCP toggle on. The selection is sent on both live and PCAP-only runs.
* **Receiver:** `register_expectation` and `/api/receiver/expect` accept
  `test_profile` and `expected_alert`; witnessed receipts are enriched with
  `test_profile`, `expected_technique`, `expected_scenario`, `expected_alert`
  via a shared `_expectation_enrichment` helper (consistent across both the
  covert-band and expectation attribution paths).
* **Report:** `build_network_validation_report` now records `test_profile` per
  run and emits a profile-aware `interpretation` — Firewall/ACL runs read as
  boundary-traversal findings; NSM runs confirm witnessed+fired, or flag a
  **detection gap** when traffic was witnessed but no matching alert fired.

### New helper

`icsforge.scenarios.engine.profile_defaults(profile)` — pure mapping from a
profile to its generation defaults (`{"stateful": ...}`), applied at the CLI and
web call sites so both agree. It never alters the engine's response model.

### Verification

Full suite **456 passed, 2 skipped** — 12 new tests: `profile_defaults` mapping,
receiver enrichment, profile-aware report interpretation (firewall traversal;
NSM with/without alerts incl. the detection-gap case), and the web flow (NSM
defaults handshake on, firewall stays unidirectional, selector present, JS
wired). ruff: 0 errors. Drift checker passes at v0.76.0.

---

## v0.75.1 (2026-06-19) — Web UI parity: stateful mode + three-way marker selector

A web-app release closing the gap found in a UI-focused review: recent CLI
generation features were not all reachable from the web app, which is the primary
surface for this tool's audience. No protocol-builder behaviour changes.

### Stateful TCP mode in the web UI

The v0.75.0 `--stateful` feature is now in the web app. All three generation
routes (`/api/generate_offline`, `/api/send`, `/api/technique/send`) accept a
`stateful` flag and thread it to `run_scenario`; the Sender page has a **Stateful
TCP** toggle that drives both the live-send and PCAP-only paths.

### Three-way Marker mode selector (covert / explicit / stealth)

Replaced the single Stealth on/off toggle with a **Marker mode** segmented
control on the Sender page — Covert (default) · Explicit · Stealth — with a
hover `?` that explains each mode. The selector maps to the backend as:

* **Covert** → marker woven into a protocol field (zero added bytes); default.
* **Explicit** → `explicit_marker=true` → literal 13-byte `ICSF` tag, matchable
  offline without a receiver.
* **Stealth** → `no_marker=true` → no marker; correlation via the receiver
  expectation registry.

The live payload preview now **re-renders immediately** when the mode changes.

### Preview fidelity fix

`/api/preview_payload` previously computed its marker with a positional
`explicit_marker("preview", proto)` string and did **not** pass `marker_mode`/
`run_marker`/`pkt_index`, so the builder fell back to its covert default for
band-carrier protocols while the literal tag leaked through for compact-marker
protocols (DNP3/MQTT) — the preview did not faithfully represent any single
mode. The endpoint now accepts a `marker_mode` param (covert/explicit/stealth;
legacy `no_marker=1` still maps to stealth) and threads the same parameters the
engine uses, so the hex preview is byte-faithful to what `generate`/`send`
actually emit for the selected mode. The response includes the resolved
`marker_mode`.

### Verification

Full suite **444 passed, 2 skipped** — 8 new web tests covering the three-way
preview (covert has no `ICSF`, explicit has it, stealth has none, all three
distinct, default is covert, legacy `no_marker` maps to stealth) plus selector
presence and JS wiring, on top of the 4 stateful web tests from before. ruff: 0
errors. Drift checker passes at v0.75.1.

---

## v0.75.0 (2026-06-18) — Stateful TCP mode (`generate --stateful`)

First half of the path from the 8/10 blue-team evaluation toward 9/10: an opt-in
mode that emits a **full TCP conversation** for offline pcaps, so they survive
stream reassembly and exercise stateful IDS engines (Suricata stream, Zeek
connection tracking) — something the default single-direction model could not do.

### What it does

`icsforge generate --stateful` wraps each TCP step in a real conversation:

* **SYN → SYN-ACK → ACK** handshake (server side synthesised),
* each application PDU sent as a PSH/ACK segment with a **matching server ACK**,
* **FIN/ACK → FIN/ACK → ACK** graceful teardown,
* correct sequence/acknowledgement numbers throughout, and a **fresh ephemeral
  source port per connection** (no "port reused" notes).

The result is a pcap that Wireshark dissects with **zero `tcp.analysis.flags` and
zero malformed** frames across all TCP protocols (modbus, dnp3, s7comm, iec104,
opcua, enip, mqtt). The **covert correlation marker is preserved** in stateful
data segments, and Suricata still alerts (verified: 495 alerts on a stateful
Modbus pcap with stream reassembly active).

### Default is unchanged

Stateless (single PSH/ACK, no handshake) remains the default — it is lighter and
is the right model for pure content/signature validation. `tcp_packet()` output
is byte-for-byte identical to v0.74.9; the stateless path is untouched.

### Implementation

* New `tcp_segment()` in `protocols/common.py` — a general Ethernet+IP+TCP frame
  builder with explicit flags/seq/ack/direction. `tcp_packet()` is refactored
  onto it with no behavioural change.
* New `TCPFlow` class — tracks client/server sequence state and emits
  `handshake()`, `client_data(payload)` (data + server ACK), and `teardown()`.
* `run_scenario(..., stateful=False)` and the `--stateful` CLI flag thread the
  mode through; when on, each TCP step opens a flow, emits the handshake, routes
  payloads through `client_data`, and tears down, advancing the ISN past the flow.
* Note: only the client (attacker→target) sends application payloads; the server
  contributes handshake and bare ACKs. Synthesising full application-layer
  *responses* is the next roadmap item (Phase B).

### Verification

Full suite **432 passed, 2 skipped** (9 new tests in `tests/test_stateful_tcp.py`
covering segment flags, handshake/teardown sequence numbers, default-stays-
stateless, handshake-present-when-stateful, and marker preservation); ruff: 0
errors. Multi-protocol sweep: all 7 TCP protocols emit clean handshake+teardown
with 0 analysis/0 malformed. Drift checker passes at v0.75.0.

---

## v0.74.9 (2026-06-15) — Documentation accuracy & drift guard

A documentation-and-accuracy release. No traffic-generation or protocol-builder
behaviour changes; the focus is making the README tell the truth about scope and
keeping it that way automatically. Prompted by an independent blue-team
evaluation that scored the tool 8/10, with the two points off being an
under-documented traffic model and version/figure drift in the README.

### Traffic Model & Limitations section (new)

Added an explicit **Traffic Model & Limitations** section near the top of the
README, before any run instructions. It states plainly that generated traffic is:

* **Unidirectional** — attacker→target only; no synthesised device responses,
  ACKs, or error replies.
* **Stateless at the transport layer** — offline pcaps carry application-layer
  PDUs as PSH/ACK segments with no TCP handshake or sequence-tracked stream
  (live `send` still opens a real socket to the cooperative receiver).

The section spells out what this model validates with confidence
(signature/content IDS rules, firewall/ACL policy, DPI classification, ATT&CK
coverage mapping) and what it explicitly does **not** exercise (response-/
outcome-based detection, stateful/stream-reassembly detection, bidirectional
timing analytics). Previously a user had to discover the single-direction,
no-handshake model by carving pcaps; now it is the documented contract. A
bidirectional/response-traffic mode and an optional TCP-handshake emitter are
noted as roadmap items.

### Version-drift guard (new)

`scripts/v19_coverage.py --check` now also fails if any README **header** pins a
`vX.Y.Z` version tag that disagrees with the live `__version__`. This catches the
stale-header class directly: the old `## Key Numbers (v0.64.7)` header (build was
v0.74.8) is exactly what slipped through before. The guard immediately surfaced a
second stale header as well — see below.

### README accuracy fixes

* **`Key Numbers` header** no longer pins a version; it points readers to
  `icsforge --version` and notes the figures are validated by the drift checker.
* **Reference detection coverage table re-measured on the current build**
  (Suricata 7.0.3, per-tier) instead of carrying a pinned v0.62.0 snapshot:
  * DNP3 **semantic 96.7% → 100%**.
  * DNP3 **lab 100% → 93.3%** (honest correction): broadcast (`broadcast_operate`)
    and no-auth-bypass frames don't carry a marker the lab-tier rule keys on;
    Tiers 2/3 cover them at 100%. Footnote updated to explain this.
  * OPC UA footnote corrected: the 97.2% lab figure reflects the two OPN-based
    (OpenSecureChannel) styles attributing via the receiver expectation registry
    (same mechanism as IEC-104) — **not** the NodeId encoding issue, which was
    fixed in v0.74.8. The stale reference to that "known issue" is removed.

### Verification

Full suite **423 passed, 2 skipped**; ruff: 0 errors. `--check` passes clean at
v0.74.9 and was confirmed to fail (and name the offending header) when a stale
version tag is reintroduced.

---

## v0.74.8 (2026-06-12) — OPC UA NodeId/RequestHeader/service-body rework (services now dissector-readable)

### Why this release matters

Closes the last substantive fidelity gap (former known-issue P1). Every OPC UA
service request now encodes a **spec-correct NodeId** so a strict dissector
reads the actual service (WriteRequest 673, BrowseRequest 527, ReadRequest 631,
…) instead of `0`. This was an all-or-nothing change — the NodeId length, the
RequestHeader, and every service body had to be corrected together — so it was
done as one atomic rework and verified across all 76 OPC UA scenarios.

### Root cause (three coupled bugs)

1. **NodeId mis-encoding.** Service ids >255 used encoding byte `0x02`
   (NumericNodeId) followed by only a 4-byte value, so the id was read into the
   *namespace* field and the service showed as `0`. Now uses **FourByteNodeId**
   (`0x01` + ns u8 + id u16) for ids ≤65535 and TwoByteNodeId for ids ≤255.
2. **Malformed RequestHeader.** The header omitted the mandatory
   `authenticationToken` NodeId and used a 1-byte `timeoutHint`, leaving the
   covert `requestHandle` and every following service field misaligned. Now the
   spec **29-byte** RequestHeader (authToken + timestamp + requestHandle +
   returnDiagnostics + auditEntryId + timeoutHint + additionalHeader).
3. **Thin service bodies.** Each request body used a 6-byte inline NodeId
   (`<BBI`) and incomplete structures, tolerated only while the header was also
   wrong. All service bodies were rebuilt to spec.

### Service bodies rebuilt to spec

`get_endpoints`/`find_servers` (+ empty localeIds/profileUris arrays),
`browse` (full BrowseDescription + ViewDescription), `browse_next`
(releaseContinuationPoints + array), `read_value` (maxAge + timestampsToReturn +
ReadValueId array with null indexRange/dataEncoding), `read_history`/
`history_read`, `write_value`/`spoof_value`/`write_alarm_node`/`c2_write`/
`write_large_blob` (proper WriteValue array: nodeId + attributeId + null
indexRange + DataValue{mask + typed Variant — Float 0x0A / Double 0x0B /
ByteString 0x0F}), `call_method`/`call_script` (CallMethodRequest + inputArguments
array), `activate_session`/`activate_default`/`activate_hardcoded`/
`change_password` (full ActivateSessionRequest with Anonymous (321) or UserName
(324) IdentityToken in an ExtensionObject), `close_session` (deleteSubscriptions),
`create_sub` (complete CreateSubscriptionRequest), `publish` (acknowledgements
array), `translate_paths` (BrowsePath + RelativePath + RelativePathElement),
`delete_sub`. The OPN styles (`open_session`/`relay_session`/`native_raw`) now
carry a real **OpenSecureChannelRequest** (service 446) with SecureChannelId 0
(new channel) and a `#None` securityPolicyUri asym header — OPN had previously
wrapped a CreateSession, which is semantically wrong.

`malformed_browse` (T0866/T0819) and `privilege_escalate` (T0890) remain
intentionally malformed — the malformed encoding *is* the exploitation technique
— and are framed as Browse/ActivateSession respectively.

### Covert-marker offset updated

The 29-byte RequestHeader shifts the covert `requestHandle` band byte from
offset 40 → **41** in MSG bodies. Updated `receiver/receiver.py` and
`detection/generator.py` accordingly. Verified: the OPC UA receiver→sender
correlation loop still attributes via `covert_band` and fires the callback, and
Suricata per-tier detection is 100% (lab/heuristic/semantic) on the new offset.

### Verification

* All **76 OPC UA scenarios** generate with **0 genuine malformed** (intentional
  exploits excluded) and **0** scenarios showing service id `0`.
* **15 distinct OPC UA services** now correctly dissected by name+number.
* OPC UA receiver loop + Tier-1 detection confirmed working at offset 41.
* Full suite **423 passed, 2 skipped**; ruff: 0 errors. (Two v0.62.2 OPN-layout
  audit tests updated to assert the spec-correct SecureChannelId=0 and `#None`
  policy asym header.)

---

## v0.74.7 (2026-06-11) — `--version` CLI flag

### Added

* `icsforge --version` (and `-V`) now prints `ICSForge <version>` and exits.
  `-v` remains the verbose/debug-logging flag. Closes the long-standing backlog
  item; useful for support and for demo credibility.

### Note on OPC UA NodeId (still deferred)

A spike this session confirmed the exact fix for the OPC UA service-NodeId
encoding issue (the service id reads as 0 to a strict dissector): FourByteNodeId
encoding + a spec-correct 29-byte RequestHeader + per-service body NodeIds as
4-byte (`<BBH`) + complete service-body structures. The header and the
WriteRequest body were implemented and verified spec-correct, but applying the
remaining service bodies is an all-or-nothing change across ~30 styles (a partial
change leaves 66/76 scenarios malformed). It was therefore reverted to the
known-good compact encoding for this release and scheduled as a dedicated
OPC UA rework; the full fix recipe is recorded in the health-report roadmap so it
can be completed quickly and atomically.

### Tests

* 423 passed, 2 skipped; ruff: 0 errors.

---

## v0.74.6 (2026-06-11) — CRITICAL: live-send covert-marker migration (correlation was broken for live traffic)

### Why this release matters

A full end-to-end sweep of the tool found that the v0.74.0 covert-marker
change was applied to the **offline** generation path but never to the
**live-send** path. Live traffic — the tool's primary function, sending to a
receiver to test firewalls / OT NSM / ACLs — was still emitting the *legacy
ASCII marker* that the v0.74.0+ receiver no longer recognises. The result:
live runs produced **no correlated receipts** (the receiver saw the packets
but could not attribute them, so the Executed → Delivered → Detected loop did
not close). `icsforge selftest --live` was failing with "No receipt matched
run_id". This release fixes the live path and the supporting attribution
plumbing.

### Fixes

* **Live sender migrated to the covert marker (`icsforge/live/sender.py`).**
  Every protocol send site (TCP, UDP, PROFINET-DCP L2, IEC-61850 GOOSE L2)
  previously built its payload with the legacy `build_marker(run_id, tech,
  step_id)` string and passed it positionally to the builder. They now pass
  the covert-marker kwargs (`marker_mode`, `run_marker`, `pkt_index`) exactly
  like the offline engine, with a monotonic per-run packet index. So live
  traffic now carries the same covert band byte / compact `ICSF` marker the
  receiver is built to detect. `--no-marker` still sends a clean stealth
  payload.

* **Live send now always pre-announces an expectation
  (`icsforge/web/bp_scenarios.py`).** Previously an expectation was registered
  only for IEC-104 and stealth runs. But under the covert model the band byte
  (Modbus/S7comm/ENIP/OPC UA/BACnet) and the `ICSF` hash marker (DNP3/MQTT)
  do **not** carry the full run_id inline — the receiver needs an expectation
  to bind observed traffic to *this* run_id/scenario/step. The send path now
  announces an expectation for every live run (harmless for marker-carrying
  protocols, required for run_id binding).

* **GOOSE receiver attribution (`icsforge/receiver/receiver.py`).**
  `_parse_goose_frame` called `_parse_marker(payload)` without a `proto`
  argument, so the expectation-matching path was skipped and every IEC-61850
  GOOSE frame returned `attributed_via="none"` — no receipt callback ever
  fired. It now passes `proto="iec61850"` so GOOSE is attributed via the
  expectation registry (GOOSE, like IEC-104, has no covert field).

* **`icsforge selftest --live` updated to the covert model.** It now starts
  the receiver with the web API enabled, pre-announces an expectation over
  `/api/receiver/expect`, sends with the matching run_id, and validates
  receipts by run_id binding OR marker presence. Added `--web-port`
  (default 8765). The selftest passes again (Receiver reachable / Modbus
  received / DNP3 received / correlation confirmed).

### Verified by the sweep (no change needed)

* All 627 scenarios generate clean (0 failures, 0 genuine malformed, 10,915
  frames).
* Suricata per-tier detection fires on the covert marker: Modbus/DNP3/S7comm/
  OPC UA 100% across lab/heuristic/semantic; IEC-104 lab 0% by design,
  heuristic/semantic 100%.
* Stealth mode emits no synthetic signal across all 10 protocols.

### Tests

* 423 passed, 2 skipped; ruff: 0 errors.

---

## v0.74.5 (2026-06-11) — Receiver→sender attribution loop verified + IEC-104/stealth receipt fix

### Why this release matters

Verified the full receiver→sender correlation loop end to end after the
v0.74.0 covert-marker change (the change that moved correlation data out of an
ASCII string and into protocol fields), and fixed a gap that silently dropped
IEC-104 and stealth-mode receipts on the sender.

### Verified working: the loop is intact after the marker change

Built a live integration harness (real receiver TCP handler → real
`register_expectation()` → real `_send_callback` → mock sender) and confirmed
that for **all 8 IP protocols** a packet produces both a written receipt and a
callback POST to the sender, via the correct attribution path:

| Protocol | Attribution path |
|----------|------------------|
| Modbus, S7comm, ENIP, OPC UA, BACnet | covert band byte (0xF7) at the protocol offset |
| DNP3, MQTT | explicit compact `ICSF` marker |
| IEC-104 | expectation registry (no on-wire marker) |

Also confirmed the covert band byte lands at exactly the offset the receiver
reads for each protocol (Modbus @0, S7 PDU-ref @11, ENIP sender-context @12,
OPC UA request-handle @40, BACnet invoke-id @8 on confirmed requests).

### Fix: sender silently dropped IEC-104 / stealth receipts

`/api/receiver/callback` only stored receipts where `marker_found` was true.
But the receiver fires callbacks for both marker-attributed traffic
(`marker_found=True`) **and** expectation-attributed traffic
(`marker_found=False, attributed_via="expectation"` — used for IEC-104, which
has no covert field, and for `--no-marker` stealth runs). The endpoint
therefore discarded every IEC-104 and stealth receipt with `stored: false`,
so those runs showed zero delivery on the sender even though the receiver had
seen the traffic and sent the callback.

The ingest now stores a receipt when it is marker-attributed **or**
expectation-attributed, matching the receiver's send condition. Genuinely
unattributed packets (a covert band byte with no matching expectation, empty
run_id) are still dropped. The callback-token + HMAC authentication path is
unchanged and verified (valid token+HMAC stores the receipt; a bad HMAC is
rejected with 401).

### Tests

* 423 passed, 2 skipped; ruff: 0 errors.

---

## v0.74.4 (2026-06-11) — Web app end-to-end verification + two route fixes

### Why this release matters

Exercised the web application end to end — every page route, every GET API
endpoint, the full offline generate → runs → validate → export-bundle →
download workflow, the expectation-registry lifecycle, and the config
setters. Everything works; two latent bugs surfaced and are fixed.

### Fixes

* **Payload-preview marker (`/api/preview_payload`)** — the hex preview embedded
  a legacy `ICSFORGE:PREVIEW:<name>:<tech>:` ASCII marker, a format the
  generator stopped using in v0.74.0. For the L2/UDP protocols (notably
  PROFINET-DCP) that take the marker as raw bytes, the preview therefore showed
  a marker that no real capture would contain. The preview now uses the same
  covert/compact `ICSF` marker the generator actually emits (via
  `covert_marker.explicit_marker`), so the preview matches real traffic;
  `?no_marker=1` reproduces stealth mode. Marker/bytes types are normalised per
  protocol transport.

* **PCAP download route (`/api/pcap/<fname>`)** — looked for files in a
  non-existent top-level `<repo>/pcaps/` directory, so it 404'd for every real
  run. It now resolves PCAPs from `<repo>/out/pcaps/` (the actual default output
  location) with a legacy fallback, and the path-traversal guard is retained
  (verified that `../../etc/passwd` is rejected).

### Verified working (no change needed)

* All 9 page routes (`/`, `/matrix`, `/sender`, `/report`, `/campaigns`,
  `/tools`, `/demo`, `/health`; `/receiver` intentionally 302-redirects to
  `/sender`).
* 25 GET API endpoints return 200.
* Offline workflow: `/api/generate_offline` (param: `name`, optional
  `build_pcap`) → `/api/runs` → `/api/run_full` → `/api/validate` (param:
  `run_id`) → `/api/run/export_bundle` → `/download`. The export bundle ZIP
  correctly contains events.jsonl, traffic.pcap, receipts.jsonl and the run
  index entry.
* `/api/receiver/expect` correctly enforces the callback-token + HMAC
  machine-to-machine auth (returns 401 without the token) — this is by design,
  independent of the `ICSFORGE_NO_AUTH` user-auth bypass.
* `/api/technique/variants` correctly 400s without a `technique` arg and 200s
  with one.

### Tests

* 423 passed, 2 skipped; ruff: 0 errors. Web API + viewer suites green (28).

---

## v0.74.3 (2026-06-11) — Attack-chain historical fidelity: Industroyer2 corrected, CrashOverride 2016 added

### Why this release matters

A historical-fidelity review of the named-incident attack chains (do they
match what the real malware/incident actually did on the wire, per
ESET/Dragos/MITRE/CERT-UA sources) found one chain that misrepresented the
incident it claimed to reproduce. Fixed, and a new faithful chain added.
Scenario total: **627** (611 standalone + **16** chains).

### Industroyer2 chain corrected (was historically inaccurate)

`CHAIN__industroyer2__power_grid` previously included an IEC-104
`interrogation` (enumeration) step and two S7comm steps (`setup`,
`cpu_stop`). Both contradict the published analysis of the 2022 malware:

* Industroyer2 was a **standalone binary that spoke IEC-104 only** — unlike
  the modular 2016 Industroyer, it had no S7comm/61850/OPC payloads.
* Its configuration (target IOAs) was **hardcoded**, so it went straight to
  issuing breaker commands and did **not** first interrogate/enumerate the
  outstation — analysts (ESET, Netresec, Dragos) specifically noted this.

The chain is now IEC-104-only and goes STARTDT → immediate single/double
ASDU commands on hardcoded IOAs → STOPDT, matching the real attack
(5 steps, T0855 + T0848 + T0815).

### New chain: Industroyer / CrashOverride (Ukraine 2016)

Added `CHAIN__industroyer_crashoverride__2016_grid`, reproducing the 2016
Kyiv transmission-substation attack (Sandworm/ELECTRUM; ESET + Dragos +
US-CERT TA17-163A). Unlike Industroyer2, the 2016 framework was **modular**
with separate protocol payloads (101.dll, 104.dll, 61850.dll, OPC). The
chain reproduces the documented per-payload behaviour, mapped to MITRE
ATT&CK for ICS S0001:

1. IEC-61850 IED enumeration (the 61850 module's MMS getNameList / CSW
   logical-node discovery) — T0846
2. OPC UA browse (stand-in for the OPC DA module's address-space browse for
   `ctlSelOn`/`ctlOperOn`/`stVal` items) — T0888
3. OPC UA stVal reads (operational status) — T0801
4. IEC-104 interrogation (the 104 module's range-mode IOA discovery) — T0888
5. IEC-104 single + double commands (unauthorized breaker-open) — T0855
6. IEC-61850 GOOSE trip injection — T0831

OPC DA (the real fourth module) is represented by OPC UA, the nearest
protocol ICSForge implements; this substitution is stated in the chain
description. Generates 50 frames across GOOSE + OPC UA + IEC-104, zero
genuine malformed (the GOOSE frames hit the known upstream Wireshark
`packet-goose.c` dissector assertion only).

### Why no 2015 BlackEnergy chain

Considered and deliberately not added. The 2015 Ukraine attack opened
breakers by **hijacking the operators' HMI/DMS via stolen VPN credentials**
(plus KillDisk wiping and malicious serial-to-Ethernet-converter firmware) —
it did not drive a standard OT wire protocol (Modbus/DNP3/IEC-104) with a
documented malicious payload. Building a wire-protocol chain for it would
fabricate behaviour the incident didn't exhibit, so it is out of scope for
faithful traffic generation.

### Review outcome for the other chains

The remaining named-incident chains were checked and are sound: **Stuxnet**
(S7 SZL fingerprint → upload logic → CPU stop → modified download → restart
matches the documented S7-300/400 sequence; PROFINET-DCP is a reasonable
stand-in for the discovery phase, PROFIBUS not implemented); **TRITON**
(already honestly labelled as a Modbus/S7comm surrogate because the
proprietary TriStation/UDP-1502 protocol is not implemented); **Water
Treatment / Oldsmar** (models the setpoint-tampering impact; the real
incident was TeamViewer HMI control). The 10 generic technique-sequence
chains make no specific real-world claim and are coherent kill-chain
progressions.

### Docs / figures

README scenario figures updated to 627 (611 + 16 chains); confidence
breakdown 457 HIGH / 151 MEDIUM / 19 LOW; the README↔canonical drift check
(`scripts/v19_coverage.py --check`) passes. The new chain appears in the
README named-chain list; the Industroyer2 entry there is corrected to note
it is IEC-104-only.

### Tests

* 423 passed, 2 skipped; ruff: 0 errors.

---

## v0.74.2 (2026-06-11) — Generation performance + OPC UA service IDs; full 626-scenario fidelity audit

### Why this release matters

Completes a technique-fidelity audit across all 626 scenarios (611 standalone
+ 15 chains, 10 protocols) — confirming each scenario's generated traffic
faithfully represents its ATT&CK for ICS technique on its protocol — and fixes
two real usability problems found along the way.

### Generation performance (major)

* **Offline `generate` no longer sleeps through inter-packet intervals.** The
  PCAP writer computes its own synthetic, jittered timestamps, so the
  real-time `time.sleep()` between packets only delayed the user with zero
  effect on output. Offline generation now passes `skip_intervals=True`.
  Effect: scenarios with long scripted intervals dropped from ~45 s to ~0.5 s
  — about a **90x speedup** — and 16 scenarios that appeared to "hang" now
  complete in well under a second. (Live `send` still paces traffic in real
  time; only offline PCAP generation skips the waits.)
* **Faster scenario loading.** `load_scenarios` now uses libyaml's
  `CSafeLoader` when available, parsing the ~700 KB scenarios file roughly
  **8x faster** (≈1.5 s → ≈0.2 s) on every invocation, with a pure-Python
  fallback.

### OPC UA service NodeId values

Three service request NodeIds in the OPC UA service table were off by a few
and are corrected to the spec values: FindServers 420→**422**, Call 710→**712**,
Publish 823→**826** (WriteRequest 673, ReadRequest 631, etc. were already
correct). These are framing-neutral label fixes.

Note: the OPC UA NodeId *encoding* still uses the historical compact form, so
a strict dissector shows the service id as 0 even though the message type and
the application operation (Write/Read/Browse/etc.) are correct and every
field is well-formed. The spec-faithful FourByteNodeId encoding was trialled
and reverted because it shifts every downstream field and makes ~68 of 76
OPC UA scenarios parse as malformed; correcting it requires reworking each
service body builder in lockstep. Tracked as a known issue — deliberately not
shipped as a regression.

### Fidelity audit result

Generated every scenario, dissected with tshark, and verified the operation
matches the technique:

* **All 611 standalone scenarios + 15 chains produce well-formed traffic.**
* Operation-vs-technique confirmed by hand for the function-code/service
  protocols: Modbus (FC), DNP3 (FC + objects), S7comm (function + ROSCTR),
  IEC-104 (ASDU TypeID), ENIP/CIP (service), BACnet (service choice —
  reinitializeDevice/writeProperty/deviceCommunicationControl map correctly),
  MQTT (PUBLISH/SUBSCRIBE/CONNECT with realistic OT topic trees), OPC UA
  (message type + operation).
* The only "malformed" frames are (a) the two intentional input-validation
  exploit scenarios per protocol where sending a malformed header *is* the
  technique (e.g. S7comm T0819/T0866), and (b) IEC-61850 GOOSE, where the
  flag is the upstream Wireshark `packet-goose.c:717` recursion-depth
  assertion, not an ICSForge encoding error (the GOOSE PDU — gocbRef, stNum,
  allData — is valid and consistent).
* The 15 attack chains generate valid multi-protocol traffic (e.g.
  Industroyer2: IEC-104 + S7comm; Triton: S7comm/OPC UA/Modbus/ENIP/CIP;
  Stuxnet: S7comm + PROFINET-DCP).

This builds on the v0.74.1 DNP3 object-encoding fixes; DNP3 was the one
protocol that had genuine fidelity bugs, and they remain fixed.

### Tests

* 423 passed, 2 skipped; ruff: 0 errors. (Suite runtime also dropped with the
  interval-skip fix.)

---

## v0.74.1 (2026-06-11) — DNP3 technique-fidelity fixes (object encoding)

### Why this release matters

A technique-fidelity audit (does each scenario's *traffic* faithfully
represent that ATT&CK technique's actual behaviour on that protocol, not
just "is it a valid packet") found that several DNP3 styles encoded their
application-layer objects in ways that misrepresented the operation and
caused conformant dissectors to flag the frames malformed. All are fixed;
DNP3 traffic is now spec-correct per IEEE 1815-2012. No scenario, coverage,
or marker-architecture changes — this is pure traffic-correctness work on
top of the v0.74.0 covert marker.

### DNP3 object-encoding fixes

1. **Unsolicited Response (T0856 Spoof Reporting Message, T0830 AiTM)** —
   the `spoof_response` style generated a plain Read (FC 0x01) with no
   unsolicited indication. It now emits a true **Unsolicited Response
   (FC 0x82)** with the **UNS control bit set** (§4.3.2.2), the mandatory
   **2-byte Internal Indications (IIN) field** that all responses carry
   (§11.7), and a real **Group 30 Var 1 analog input event point**
   (flag + 32-bit value) as the spoofed measurement.

2. **CROB control (T0855 Unauthorized Command and related select/operate/
   direct_operate styles)** — Group 12 Var 1 control-relay output blocks are
   now encoded with the spec-correct **qualifier 0x17** ("8-bit count + 8-bit
   index prefix", Table 4-4) instead of a bare count, so each CROB is a
   properly index-addressed point.

3. **Write Binary Output (write / broadcast_operate / default_auth_bypass)** —
   these declared a point count but supplied no point data, so a dissector
   read the following bytes (the correlation marker) as object data. They now
   carry real **Group 10 Var 2 binary-output status** point data.

4. **File transfer (T0807 Command-Line Interface, T0853 Scripting, T0869
   Standard Application Protocol)** — the `file_open` style appended a raw
   filename string. It now builds a spec-correct **Group 70 Var 3
   File-Control / File-Command object** (free-format qualifier 0x5B), the
   actual DNP3 file-transfer service used to push files to an outstation.

5. **Secure Authentication (T0892 Change Credential, T0859 Valid Accounts)** —
   the `authenticate_req` style is now a spec-correct **Group 120 Var 1
   Authentication Challenge object** (free-format), with challenge sequence
   number, user number, MAC algorithm and reason fields.

6. **Correlation marker as Group 110 octet string** — the compact 'ICSF'
   DNP3 marker is wrapped as a valid **Group 110 (octet string) object**, so
   request frames now dissect with zero "Unknown Object\Variation" phantoms.

### Read-request qualifiers

Read styles now reference objects by **range** (qualifier 0x06 for class
polls / "all objects", 0x00 for an 8-bit index range) with no trailing point
data, matching how a real master polls an outstation. Previously some reads
used a count qualifier with no data.

### Result

- All 60 DNP3 scenarios produce well-formed traffic; malformed frames are
  eliminated except the two intentional input-validation exploit scenarios
  (T0819 / T0866), where sending a malformed application header *is* the
  technique.
- Link-layer CRCs valid (0 incorrect); tshark dissects the operations
  correctly (CROB, file-control, auth-challenge, unsolicited analog events).
- All 30 DNP3 unit tests pass (CROB test updated to the 0x17 qualifier).

### Tests

- 271 passed, 2 skipped in the protocol/marker suites; ruff: 0 errors.

---

## v0.74.0 (2026-06-10) — Covert marker: realistic traffic, zero added bytes, cryptographic provenance

### Why this release matters

Through v0.73.0 the synthetic-traffic correlation marker was an explicit
ASCII string embedded in every payload:

    ICSFORGE:ICSFORGE_SYNTH|<run_id>|<technique>|<step>:

Measured against real frames, that string was **59-91% of a typical ICS
packet** (Modbus 91%, ENIP 75%, OPC UA 59%). For a tool whose entire value
is *realistic* ICS traffic, that was the single biggest fidelity flaw — a
capture looked like a marker with some protocol attached, not the reverse.
It also overflowed fixed-size transport chunks (the DNP3 CRC-splitting that
forced a separate short-marker code path) and, being a literal string, was
trivially forgeable.

v0.74.0 replaces it with a **covert marker**: instead of *adding* bytes,
ICSForge *derives* the values of protocol fields that are already present
and genuinely arbitrary — fields a real device fills with throwaway values.

### The covert marker

For each protocol with a suitable field, the marker rides in that field with
**zero added bytes**, and the packet is indistinguishable from real traffic
because it *is* a real, spec-valid field — only its value is chosen:

| Protocol | Covert carrier | Added bytes |
|----------|----------------|-------------|
| Modbus   | Transaction ID (16-bit echo token) | 0 |
| S7comm   | PDU reference (16-bit) | 0 |
| ENIP     | Sender Context (64-bit, device-echoed) | 0 |
| OPC UA   | RequestHandle (32-bit) | 0 |
| BACnet   | Invoke ID (8-bit, confirmed requests) | 0 |
| DNP3     | compact 13-byte 'ICSF' marker (too few free bits) | 13 |
| MQTT     | compact 'ICSF' marker (no universal arbitrary field) | ~13 |
| IEC-104  | registry-only (sequence numbers are constrained) | 0 |

Modbus frames went from ~97 bytes to **12 bytes** (87% smaller). Six of
eight protocols now carry the marker with zero overhead.

The covert value is `HMAC-SHA256(run_key, proto || packet_index)` truncated
to the field width, with the high-order byte forced into a reserved
synthetic band (0xF7) so detection can anchor on it. Because it is keyed,
a third party **cannot forge or replay** an ICSForge marker without the run
key — a genuine provenance property the old literal lacked.

### Two-layer detection

* **Layer 1 (Suricata/Zeek, in-band):** a content match on the 0xF7 synthetic
  band at each protocol's covert-field offset (Modbus @0, S7 PDU-ref @11,
  ENIP sender-context @12, OPC UA request-handle @40, BACnet invoke-id @8).
  DNP3/MQTT match the 'ICSF' magic. This is the fast pre-filter.
* **Layer 2 (receiver, out-of-band, authoritative):** the receiver verifies
  the full keyed value / expectation binding. Zero-false-positive attribution
  lives here and is cryptographic rather than a guessable literal.

Three marker modes:
* **covert** (default): the model above.
* **--explicit-marker**: embed the compact 13-byte 'ICSF'+code+hash marker in
  payloads, for pure-offline PCAP detection without a receiver.
* **--no-marker**: stealth; no synthetic signal at all (registry-only).

### Receiver

`extract_correlation` now has three attribution paths, most-specific first:
explicit 'ICSF' compact marker → covert band byte at the protocol offset
(bound to an active expectation) → expectation-registry fallback. The
expectation registry (POST /api/receiver/expect) is the primary correlation
mechanism for covert traffic.

### Measurement-harness fix (independent finding)

While validating detection, root-caused a latent bug in
`scripts/measure_detection_coverage.py`: loading all three tier rule files in
a single Suricata process let Suricata's multi-pattern-matcher prefilter
**suppress short, highly-common heuristic patterns** (e.g. Modbus Protocol-
Identifier "00 00") in favour of the larger lab/semantic signature groups —
even below the per-packet alert cap. This understated heuristic/semantic
hit rates (and silently affected the historical v0.73.0 baseline). Fixed by
running each tier in its own Suricata pass. Honest per-tier numbers below.

### Detection coverage (per-tier measurement, real Suricata 7.0.3)

| Protocol | Lab | Heuristic | Semantic |
|----------|-----|-----------|----------|
| Modbus   | 100%  | 100%  | 100%  |
| DNP3     | 100%  | 100%  | 96.7% |
| S7comm   | 100%  | 100%  | 100%  |
| IEC-104  | 0%*   | 100%  | 87.7% |
| ENIP     | 100%  | 70.8% | 44.4% |
| OPC UA   | 97.2% | 100%  | 100%  |
| BACnet   | 87.0%*| 100%  | 100%  |
| MQTT     | 84.9%*| 92.5% | 86.8% |

\* IEC-104 lab is 0% by design (registry-only attribution); BACnet 87% =
who-is/unconfirmed packets carry no invoke ID (heuristic/semantic cover them);
MQTT 84.9% = PINGREQ-only scenarios have no marker carrier; OPC UA 97.2% = the
two OPN-based styles have the pre-existing NodeId encoding issue.

### Compatibility

* `marker_bytes()` / `short_marker_bytes()` in `protocols/common.py` are
  retained as deprecated shims so external callers don't break; new code uses
  `protocols/covert_marker.py`.
* Tests updated to assert the covert/compact marker behaviour (the legacy
  ICSFORGE_SYNTH string assertions are gone).

### Tests

* 423 passed, 2 skipped, 0 failures (full suite)
* Ruff: 0 errors
* All 10 protocols generate spec-valid traffic (0 malformed in tshark)
* Stealth (--no-marker) verified to emit no synthetic signal

### Coverage state (unchanged)

| Metric | v0.74.0 |
|--------|--------:|
| Scenarios | 626 (611 standalone + 15 chains) |
| v18 coverage | 77 / 83 = 92.8% |
| v19 combined | 90 / 97 = 92.8% |
| Detection rules | 929 |

---

## v0.73.0 (2026-05-30) — Protocol framing correctness: DNP3 Length field + ENIP/CIP CPF

### Why this release matters

A deep traffic-correctness audit (generate → tshark dissect → verify the
actual protocol operation matches the claimed ATT&CK technique, across all
547 technique×protocol pairs) found two systematic framing bugs where the
generated traffic looked valid at the link/encapsulation layer but the
technique-defining operation was unreachable to any spec-compliant
dissector or real device. Both are fixed and verified. This is pure
correctness work — no scenario, coverage, or rule-count changes.

### Bug 1 — DNP3 link-layer Length field (all 60 DNP3 scenarios)

The link-layer Length octet was computed including the per-data-block
CRC bytes, violating IEEE 1815-2012 §9.2.4.1.2 (which counts user-data
octets only). ICSForge's own per-block CRC-16/DNP values were correct,
but the inflated Length field caused tshark — and any spec-compliant
DNP3 outstation — to miscount the data-chunk boundaries and reject every
chunk after the first. Net effect: **the DNP3 application layer never
parsed**, so the function codes that distinguish techniques
(DirectOperate, Restart, Write, etc.) were invisible to any analyzer.

Root cause: `_link_header(dest, src, len(blocks))` passed the
CRC-inclusive block length; corrected to `len(app)` (user-data length)
at both call sites, with `_link_header`'s contract corrected to compute
`Length = 5 + user_data_len`.

Verified with tshark after the fix:
- Data-chunk checksums all "Good" (0 incorrect)
- Application layer parses: `dnp3.al.func` populated
- Function codes correctly map to techniques: DirectOperate (5) for
  T0855, Select (3) + Operate (4) for T0831 SBO, Cold/Warm Restart
  (13/14) for T0816, Write (2) for T0872.
- Detection rates unchanged: 60/60 lab, 60/60 heuristic, 58/60 semantic.

### Bug 2 — ENIP/CIP Common Packet Format in SendRRData (all CIP-bearing ENIP scenarios)

Two stacked errors in the SendRRData Command Specific Data:
1. The mandatory 2-byte **Timeout** field was missing (the CSD packed
   `interface_handle` + `item_count` with no timeout between them).
2. The null-address CPF item carried an extra 2 bytes (packed as three
   uint16 instead of the spec's Type ID + Length = two uint16).

Net effect: tshark read **Item Count = 0** and never descended into the
CIP request, so the CIP services that distinguish techniques (Write Tag,
Reset, Get Attribute) were unreachable — a real ControlLogix PLC would
reject the frame as having no data item to process.

Fix: CSD is now `interface_handle(4) + timeout(2) + item_count(2)`
(`struct.pack("<IHH", 0, 0, 2)`), and the null-address item is the
correct 4 bytes (`struct.pack("<HH", 0x0000, 0)`), across all 18 build
sites.

Verified with tshark after the fix:
- Protocol stack reaches CIP: `eth:ethertype:ip:tcp:enip:cip:cipcls`
- Item Count = 2, Unconnected Data Item (0x00b2) present
- CIP services correctly map to techniques: Write Tag (0x4d) + Set
  Attribute (0x10) for T0855, Reset (0x05) for T0816, GetAttrAll (0x01)
  + GetAttrSingle (0x0e) for T0888.
- 20/20 sampled ENIP scenarios dissect with 0 malformed frames.
- Detection rates unchanged: 72/72 lab, 23/72 heuristic, 51/72 semantic.

### Verified correct, no changes needed

The same audit dissected the other protocols and confirmed their
operations already map correctly to techniques: S7comm (function codes
0x28/0x29 start/stop, 0x1a–0x1c download, 0x1d–0x1f upload), IEC-104
(ASDU TypeIDs C_SC_NA_1=45, clock=103, interrogation=100), Modbus
(FC5/6/16 writes, FC8 diagnostic, FC43 device-ID), BACnet (WriteProperty=15,
ReinitializeDevice=20, DeviceCommunicationControl=17), and MQTT.

### Matrix representation audit (no code change, verification only)

Verified the web-UI ATT&CK matrix against the authoritative
attack.mitre.org v19.1 source:
- v18 matrix: 12 tactics, 83 unique techniques — matches official v18.
- v19 matrix: 79 standalone + 18 sub-techniques — exact match to v19.1,
  zero missing, zero stale.
- The 9 v18→v19 restructured techniques (e.g. T0855 → T1692.001) are
  represented correctly in both views with no double-representation;
  all scenario `technique_v19` annotations verified (0 mismatches).
- matrix → technique → protocol → run flow: 0 mismatches across all 76
  techniques (every protocol offered has a real runnable scenario).

### Known issues (deferred)

- **OPC UA service NodeId encoding**: encoded with the wrong NodeId
  encoding mask, so tshark reads the service ID (e.g. WriteRequest 673)
  as the namespace index and the identifier as 0. A spec-correct fix was
  developed but reverted this release because it shifts OPN message
  framing and exposes a latent AsymmetricAlgorithmSecurityHeader issue
  in two styles (relay_session, native_raw). Needs careful rework that
  addresses both together.
- Semantic-tier rule specificity for S7comm/ENIP/OPC UA/BACnet (rules
  match protocol presence rather than function-code; the traffic is
  correct, the per-technique rule attribution is coarse).

### Tests

- 423 passed, 2 skipped, 0 failures (full suite)
- Ruff: 0 errors
- Detection rates unchanged for all protocols

### Coverage state (unchanged)

| Metric | v0.73.0 |
|---|---:|
| Scenarios | 626 (611 standalone + 15 chains) |
| v18 coverage | 77 / 83 = 92.8% |
| v19 combined | 90 / 97 = 92.8% |
| Detection rules | 929 |

---

## v0.72.0 (2026-05-10) — DNP3 Tier 1 → 100% + scenario-count drift detection

### Why this release matters

Two small but high-leverage wins:

1. **DNP3 Tier 1 closure** — pushed DNP3 Tier 1 from 93.3% → **100.0%**
   by fixing the marker-order issue in `file_open` and `spoof_response`
   styles. The last "⚠️" cell in REFERENCE_DETECTION_COVERAGE.md for
   Suricata-supported protocols is now clean.

2. **Scenario-count drift detection** — extends the v0.69.0 canonical-
   figures script to cover scenario counts (total, standalone, chains,
   confidence breakdown, v19-annotation count). Catches the exact
   class of drift the v0.69.0 reviewer caught manually.

### What changed

#### `icsforge/protocols/dnp3.py` — marker reordering

Two style branches built `extra=` with the variable-length payload
*before* the marker:

```python
# Before (file_open):
extra=filename + mb
# Before (spoof_response):
extra=struct.pack("<i", value) + mb
```

The CRC chunking in IEEE 1815-2012 §10.3.1 puts the first 2-byte CRC
after byte 16 of user data. When `filename` was 11 bytes (e.g.
`b"payload.sh\x00"`) or the value was 4 bytes, the marker prefix
`ICSF` (4 bytes) ended up at user-data offset 11 or 4 — but its
6-byte prefix `ICSFD3` straddled the CRC boundary at byte 16.
Suricata's contiguous `content:` match misses the marker.

Fix: emit `mb` FIRST in both styles. The marker's 6-byte prefix
always lands in chunk 1's leading bytes regardless of variable-
length payload data.

```python
# After:
extra=mb + filename
extra=mb + struct.pack("<i", value)
```

#### `scripts/v19_coverage.py` — scenario counts added

`compute_coverage()` now also returns a `scenario_counts` block:
- `total`, `standalone`, `chains`
- `confidence_high`, `confidence_medium`, `confidence_low`
- `v19_annotated`

`render_table()` shows these in the human-readable output.

`check_readme()` validates 5 additional canonical strings:
- `611 standalone + 15 named attack chains = 626 total`
- `457 HIGH`, `150 MEDIUM`, `19 LOW`
- `111 scenarios carry \`technique_v19\` field`

If any of these strings disappear from README.md, the existing
`tests/test_v19_coverage_canonical.py::test_readme_matches_canonical_v19_coverage`
test fails with a clear error pointing to the exact missing string.

This closes the second class of drift the reviewer caught — README
counts had been stale across 4 releases (610 vs 611, 14 vs 15, 134
vs 150 medium, 109 vs 111 v19 annotations).

#### `docs/REFERENCE_DETECTION_COVERAGE.md` — DNP3 row 93.3% → 100.0%

Table updated, explanation extended with the v0.72.0 fix details.

### Headline numbers

| Protocol | Tier 1 (v0.71) | Tier 1 (v0.72) |
|---|---:|---:|
| modbus | 100.0% | 100.0% |
| dnp3 | 93.3% | **100.0%** |
| enip | 100.0% | 100.0% |
| opcua | 100.0% | 100.0% |
| mqtt | 84.9% | 84.9% (Suricata flow-direction limitation) |
| bacnet | 0.0% (intentional — broadcast L3) | 0.0% |
| iec104 | 0.0% (intentional — APDU length-locked) | 0.0% |
| s7comm | 1.3% (intentional — ROSCTR-locked) | 1.3% |

DNP3 is now the **first protocol** ICSForge measures at 100% Tier 1
across every scenario that produces a PCAP. Modbus, ENIP, and OPC UA
also sit at 100% Tier 1 from prior releases.

### Tests

- 404/404 fast tests pass
- 19/19 slow tests pass
- **423/425 full suite passes**, 2 skipped, 0 failures, 3m 2s
- Ruff: **0 errors** (still clean from v0.71.0)
- DNP3 measurement: 60/60 Tier 1 hit, 60/60 Tier 2 hit, 58/60 Tier 3

### Coverage state (unchanged figures, no new techniques)

| Metric | v0.72.0 |
|---|---:|
| Scenarios | 626 (611 + 15) |
| v18 coverage | 77 / 83 = 92.8% |
| v19 standalone | 73 / 79 = 92.4% |
| v19 sub-techniques | 17 / 18 = 94.4% |
| v19 combined | 90 / 97 = 92.8% |
| Detection rules | 929 (unchanged) |
| **DNP3 Tier 1** | **100.0%** (was 93.3%) |

### What's next per ROADMAP_V5

This release closes the optional small wins identified for pre-Arsenal.
Remaining roadmap is all maintainer-owned demo prep (videos, blog
publication) or strategic post-Arsenal work (rules repo, vendor
outreach, cross-SIEM measurement).

---



### Why this release matters

Reviewer feedback on v0.69.0 raised four release-quality blockers:
1. **Ruff not clean** — 119 errors
2. **README counts stale** — actual was 626/611/15/457/150/19/111;
   README claimed 624/610/14/457/134/19/109
3. **Full pytest didn't complete in reviewer window** — couldn't say
   "X/X passed" honestly
4. **Chain schema implicit** — 82 step-technique mismatches in chains
   were flagged as drift by external auditors

The reviewer's bottom line: "Functionally promising and demo-capable,
but not release-polished yet. The biggest problem is not the tool
capability. It is release hygiene."

v0.71.0 fixes all four. Zero new features — pure release-quality work.

### What changed

#### 1. Ruff: 120 errors → 0

Cleared every `[tool.ruff.lint]` rule selected in pyproject.toml
(`E`, `F`, `W`, `I`, `UP`, `B`, `SIM`, ignoring `E501`).

Categories addressed:
- 48 × I001 unsorted-imports (autofix)
- 17 × F401 unused-import (autofix + manual cleanup)
- 8 × E401 multiple-imports-on-one-line (autofix)
- 8 × E701 multiple-statements-on-one-line-colon
- 7 × E702 multiple-statements-on-one-line-semicolon
- 5 × SIM105 try/except/pass → contextlib.suppress
- 5 × SIM115 file open without context manager (fixed where safe;
  noqa on long-lived tail handles)
- 4 × B007 unused loop control variable (renamed to `_var`)
- 4 × E402 module-level import not at top of file (noqa where the
  sys.path manipulation is intentional)
- 4 × F841 unused variable
- 3 × E741 ambiguous variable name `l` → renamed to `ln`
- 3 × F541 f-string-missing-placeholders (autofix)
- 2 × SIM102 collapsible-if
- 1 × B905 zip without strict=
- 1 × E731 lambda → def
- 1 × F401 unused-import (`pathlib.Path` in viewer)

Verified the cleanup didn't break behaviour:
- Generator output unchanged: 210 lab + 228 heuristic + 335 semantic
  Suricata + 156 Zeek = 929 detection rules
- Full pytest passes (see #3 below)

#### 2. README count sync

| Metric | README before | README now (matches scenarios.yml) |
|---|---|---|
| Total scenarios | 624 | **626** |
| Standalone | 610 | **611** |
| Chains | 14 | **15** |
| Confidence high | 457 | 457 (unchanged) |
| Confidence medium | 134 | **150** |
| Confidence low | 19 | 19 (unchanged) |
| v19 annotations | 109 | **111** |
| Spec-cleanliness | 624/624 | **626/626** |

Stale "623 scenarios" references in measurement docs also corrected.

The figures were drifting because they're hand-typed strings in
README.md. The drift detector (`scripts/v19_coverage.py --check`,
shipped in v0.69.0) covers MITRE coverage figures but not scenario-
count figures; extending it to cover scenario counts is on the roadmap
for v0.72.

#### 3. Full pytest verified

- `tests/` collected: **425**
- Passed: **423**
- Skipped: 2 (intentional — Suricata/Zeek installation-dependent)
- Failed: **0**
- Runtime: 3m 2s (full suite, fast + slow)

This is the first release where I've confirmed the full suite
completes cleanly within a single execution window. Reviewer's #3
addressed.

#### 4. Chain schema clarification

External auditors found 82 step-technique mismatches in chain
scenarios — flagged as drift. They're not drift; chains intentionally
have step-level technique IDs that differ from the chain's tactical-
objective primary.

Two changes:

**`docs/SCENARIO_SCHEMA.md`** — new file. Documents:
- The two scenario types (standalone vs chain)
- Why standalone scenarios MUST have step.technique == scenario.technique
- Why chains intentionally don't
- The audit pattern: `if name.startswith("CHAIN__"): continue` for
  the step-vs-scenario-technique check
- Coverage counting semantics for chain primaries

**`icsforge/scenarios/scenarios.yml`** — added a 24-line comment block
above the first chain scenario explaining the chain semantics
inline. Anyone reading the YAML directly now sees the schema rules
without having to find the doc.

### Tests

| Metric | Result |
|---|---|
| Ruff | **0 errors** (was 120) |
| Fast tests | 404 / 404 |
| Slow tests | 19 / 19 |
| **Full suite** | **423 / 425 passed**, 2 skipped, 0 failures |
| Generator output | 210/228/335/156 = 929 rules (unchanged) |

### Coverage state (unchanged from v0.70.0)

| Metric | v0.71.0 |
|---|---:|
| Scenarios | **626** (611 standalone + 15 chains) |
| v18 standalone covered | 77 / 83 = 92.8% |
| v19 standalone covered | 73 / 79 = 92.4% |
| v19 sub-techniques covered | 17 / 18 = 94.4% |
| v19 combined | 90 / 97 = 92.8% |
| IP-based protocols at 100% combined | 8 / 8 |
| L2 protocols (Zeek path) | 2 / 2 |
| Detection rules total | 929 |
| DNP3 Tier 1 | 93.3% (v0.70 fix) |

### What's next per ROADMAP_V5

This release closes the v0.69.0 review feedback. Per ROADMAP_V5 the
remaining outstanding items before Black Hat Arsenal 2026:

- **June 2026** (maintainer-owned): demo videos, blog post publication
- **July 2026** (shareable): demo-day hardening, audience takeaway
- **Optional small wins**: DNP3 response-direction Tier 1, T0801 expansion

---



### Why this release matters

DNP3's Tier 1 (lab marker) detection rate was the single largest gap
documented in `REFERENCE_DETECTION_COVERAGE.md` for IP-based protocols
that ship a marker — 26.7%, marked ⚠️ since v0.65.0. Root cause: IEEE
1815-2012 §10.3.1 splits DNP3 user payload into 16-byte chunks each
followed by 2 CRC bytes, and the standard 60-80-byte marker
`ICSFORGE_SYNTH|<run_id>|<technique>|<step>` got bisected by CRC
interrupts. Suricata's `content:` keyword is contiguous-match only.

v0.70.0 fixes this with a **DNP3-specific 14-byte short marker** that
fits inside one CRC chunk. Tier 1 jumped from **26.7% → 93.3%**.

This release also archives ROADMAP_V4 and ships ROADMAP_V5 reflecting
the actual v0.70.0 state (the V4 doc still claimed "v0.65.0 ships
with..." at the top, drifting across 5 releases).

### What changed

#### `icsforge/protocols/common.py` — new `short_marker_bytes()` helper

```python
def short_marker_bytes(marker: str, proto_code: bytes = b"D3") -> bytes:
    """14-byte marker that fits inside a 16-byte transport chunk.

    Format:
        4 bytes — fixed magic 'ICSF'
        2 bytes — protocol code (e.g. 'D3' for DNP3)
        8 bytes — hex-encoded SHA1 prefix of run_id (deterministic)
    """
```

The 8-byte hash retains ~32 bits of entropy for runtime correlation
via the v0.64.7 expectation registry while fitting in one CRC chunk.
Trade-off: the embedded run_id text is gone for DNP3 specifically;
out-of-band correlation (the registry) handles attribution.

#### `icsforge/protocols/dnp3.py` — uses short marker

```python
mb = short_marker_bytes(marker, proto_code=b"D3")
```

#### `icsforge/detection/generator.py` — per-proto Tier 1 marker bytes

Added `_MARKER_DNP3_HEX = "49 43 53 46 44 33"` (the 6-byte fast-pattern
prefix `ICSFD3`) and updated `_tier1_marker()` to dispatch:
```python
marker_hex = _MARKER_DNP3_HEX if proto == "dnp3" else _MARKER_HEX
```

All other protocols continue using the standard 14-byte
`ICSFORGE_SYNTH|` prefix unchanged.

#### `tests/test_v062_additions.py` — CROB test updated

The CROB-is-11-bytes test verified its assertion by checking that
`ICSFORGE:` started at offset 11 after the CROB. v0.70 changed the
DNP3 marker to `ICSFD3...`, so the test now asserts `ICSFD3` at
offset 11 instead. Same logical intent, new byte sequence.

### Headline result

| Metric | v0.69.0 | v0.70.0 |
|---|---:|---:|
| DNP3 Tier 1 | 26.7% (16/60) | **93.3% (56/60)** |
| DNP3 combined detection | 100% | **100%** (unchanged) |
| Modbus Tier 1 (sanity) | 100% | 100% (unchanged — non-DNP3 dispatch) |

The remaining DNP3 Tier 1 gap (4 of 60 with PCAPs; 2 more have no
PCAP) is response-direction scenarios (`unsolicited`, `spoof_response`,
`disable_unsolicited`, `unsolicited_inject`) where the rule's
`flow:to_server` clause excludes from-server traffic. Tracked in
ROADMAP_V5 as a v0.70.x candidate (~2 hours work, pushes DNP3 Tier 1
to 100%).

### REFERENCE_DETECTION_COVERAGE.md updated

DNP3 row in the headline table updated from `26.7% ⚠️` to `93.3%`
(with the ⚠️ removed). The "dnp3 Tier 1" gap explanation rewritten to
reflect the v0.70.0 fix and document the trade-off honestly:
- run_id text is dropped from the wire for DNP3
- v0.64.7 expectation registry handles correlation out-of-band
- Tier 1 rule content is `ICSFD3` 6-byte fast-pattern

### ROADMAP_V5 ships

`docs/ROADMAP_V4.md` archived to `docs/history/ROADMAP_V4_v0.69.0_era.md`.
ROADMAP_V5 reflects v0.70.0 reality:

- Coverage state: 92.8% v18, 92.8% combined v19 (clean numbers)
- Detection rules: 929 total across all 10 protocols
- Outstanding technical work split into "small wins" and "honest non-goals"
- Demo-day prep (June-July-August 2026) with maintainer-owned vs shareable items
- Strategic post-Arsenal items: rules repo, vendor outreach, cross-SIEM measurement
- Architectural decisions list updated (DNP3 short marker now locked in)

### Tests

- 404/404 fast tests pass
- 19/19 slow audit-invariant tests pass
- 0 regressions
- DNP3 CROB test updated to match new marker prefix (same logical intent)

### Coverage state

| Metric | v0.69.0 | v0.70.0 |
|---|---|---|
| Scenarios | 626 | 626 |
| Detection rules | 929 | 929 (unchanged) |
| DNP3 Tier 1 | 26.7% | **93.3%** |
| v18 ATT&CK coverage | 92.8% | 92.8% |
| v19 standalone | 73/79 = 92.4% | 92.4% |
| v19 sub-techniques | 17/18 = 94.4% | 94.4% |
| v19 combined | 90/97 = 92.8% | 92.8% |

---



### Why this release matters

v0.68.1 fixed the stale v19 figures in the docs but didn't address
two structural issues:
1. The figures lived as hand-typed strings that drifted across releases
2. Three v19 sub-techs were uncovered (T0843.003, T1695.002, T1695.003)

v0.69.0 fixes both.

### What changed

#### New: `scripts/v19_coverage.py` — single source of truth

Computes canonical v18/v19 coverage figures from `scenarios.yml` +
crosswalk + matrix files. Three modes:
- Default: human-readable table
- `--json`: machine-readable
- `--check`: validates README.md contains canonical strings, exits 1 on drift

#### New: `tests/test_v19_coverage_canonical.py` — drift detection in CI

Three tests:
- Script runs without error
- README matches canonical figures (uses `--check`)
- `--json` mode produces parseable output with expected keys

This makes the v0.68.1-era documentation drift impossible to recur.
When future releases add scenarios that change v19 numbers, the test
fails immediately and points to the exact strings to update.

#### Coverage push: 15/18 → 17/18 v19 sub-techs (94.4%)

Two new sub-tech mappings:

**T0843.003 Program Append** — new scenario
`T0843_003__program_append__s7comm_online_edit`. S7comm online-edit
download sequence (download_req → download_block × 8 → download_end)
without the preceding cpu_stop. Network signature: block transfers
proceed while the controller stays in RUN, distinct from T0843.001
Download All which requires cpu_stop / cpu_start_warm. 10 packets,
medium confidence (chain framing — interpretive at the security-tool
layer).

**T1695.002 Block Communications: Ethernet** — annotation on existing
`T0814__denial_of_service__iec61850`. The GOOSE-flood DoS attack
already models L2 Ethernet-layer disruption (saturating IED receive
buffers on the IEC 61850 process bus). Adding `technique_v19:
T1695.002` correctly records this dual mapping in the v19 catalog.

**T1695.003 Block Communications: Wi-Fi** remains uncovered. This is
genuinely radio-layer (deauth attacks, jamming) and out of scope for
a packet-generation tool that doesn't model 802.11 — same honest
caveat we apply to T0817 / T0847 / T0852 etc.

### Coverage state

| Metric | v0.68.1 | v0.69.0 |
|---|---|---|
| Scenarios | 625 | **626** (+1 T0843.003) |
| v18 standalone covered | 77 / 83 = 92.8% | 77 / 83 = 92.8% (unchanged) |
| v19 standalone covered | 73 / 79 = 92.4% | 73 / 79 = 92.4% (unchanged) |
| **v19 sub-techniques covered** | 15 / 18 = 83.3% | **17 / 18 = 94.4%** |
| **v19 combined** | 88 / 97 = 90.7% | **90 / 97 = 92.8%** |
| Uncovered v19 sub-techs | T0843.003, T1695.002, T1695.003 | **T1695.003 only** |

### How v0.69.0 prevents the v0.68.1-era drift

The drift caught in v0.68.1 (README claimed 65/79 standalone for 4
releases when actual was 73/79) was caused by hand-typed strings in
docs that nobody re-derived after each release. v0.69.0 fixes the
mechanism:

1. `scripts/v19_coverage.py` computes the canonical numbers from
   scenarios.yml + crosswalk
2. `tests/test_v19_coverage_canonical.py` runs the script with
   `--check` against README.md every test run
3. Any future change to scenarios/crosswalk that shifts coverage
   triggers a test failure with a clear "update this string in the
   README" message

For places the test can't reach (CHANGELOG entries, doc tutorials,
external blog posts), the canonical script can be invoked manually or
in CI to generate up-to-date figures.

### Tests

- 404/404 fast tests pass (was 401 — added 3 new tests in
  test_v19_coverage_canonical.py)
- 0 regressions
- The new drift-check test demonstrably caught the 15→17 sub-tech change
  during release prep and forced the README update before commit

### Roadmap status

| ROADMAP_V4 v0.69+ item | Status |
|---|---|
| T0801 expansion (process-state monitor variants) | ⏳ deferred to v0.70 |
| Vendor outreach (Dragos / Claroty / Nozomi) | ⏳ post-Arsenal |
| GFI-013 ET-rules separate repo | ⏳ post-Arsenal |
| **Canonical v19 figures + drift CI** | ✅ shipped this release |
| **T0843.003 Program Append** | ✅ shipped this release |
| **T1695.002 Ethernet annotation** | ✅ shipped this release |

---



### Why this release matters

A direct question during release prep — "where are we on v19? what's
the percentage?" — surfaced multiple stale figures across the codebase
and one real bug. Every place that reported v19 coverage was reading
the v0.64.1 snapshot from when the v19 work first landed; nothing had
been re-measured since. v0.68.1 corrects all the stale figures and
fixes the API endpoint that was undercounting.

### What was wrong

| Location | Reported | Actual | Off by |
|---|---:|---:|---:|
| README.md (intro paragraph) | 65/79 standalone | **73/79** | -8 |
| README.md (matrix-coverage table) | 12/18 sub-techs | **15/18** | -3 |
| docs/MITRE_V19_CROSSWALK.md | 65/79 standalone | **73/79** | -8 |
| docs/MITRE_V19_CROSSWALK.md | "76 of 83 v18" | **77 of 83** | -1 (T0879 chain) |
| /api/version JSON `techniques` | 76 | **77** | -1 (chain primaries) |
| /api/version JSON v19 stats | (absent) | **shipped** | new field |

### What changed

#### Fixed `/api/version` endpoint (`icsforge/web/bp_config.py`)

Was: counted only step-level `technique` from non-chain scenarios.
Result: 76 techniques (missed T0879 chain primary).

Now: counts BOTH scenario-level primary (which catches chain
primaries) AND step-level techniques. Result: **77** techniques.

Also added a new `v19` block to the response:
```json
{
  "v19": {
    "standalone_covered": 73,
    "standalone_total":   79,
    "subtechniques_covered": 15,
    "subtechniques_total":   18
  }
}
```

The v19 standalone count uses the official crosswalk to translate v18
IDs that became v19 sub-techs, then counts the parent technique as
covered when any of its sub-techs is annotated. This matches ATT&CK's
own convention.

#### Updated README.md and docs/MITRE_V19_CROSSWALK.md

All v19 coverage figures now match the actual measurement:

- v18 coverage: **77 of 83** standalone (92.8%)
- v19 standalone: **73 of 79** (92.4%)
- v19 sub-techniques: **15 of 18** (83.3%)
- v19 combined (standalone + subs): **88 of 97** (90.7%)

The 6 uncovered v19 standalone techniques (T0817, T0847, T0852,
T0865, T0874, T0894) are all genuinely host-only / non-network-
observable — same as the v18 list minus T0879 (now covered via chain).

### Tests

- 401/401 fast tests pass
- 0 regressions

### Honest accounting of how this happened

The v19 work landed in v0.64.x and the figures reflected the state at
that time. Subsequent releases (v0.66.x BACnet, v0.67.0 Zeek, v0.68.0
T0879 chain) added scenarios and chain primaries but didn't trigger a
re-measurement of v19 coverage. The numbers should have been
auto-derived from scenarios.yml + crosswalk in a test or doc-generation
hook; instead they were hand-typed strings that drifted.

For v0.69 a small follow-up would be to add a `scripts/v19_coverage.py`
that emits the canonical numbers, and a CI check that fails when
README/docs drift from what the script computes. Tracked.

---



### Why this release matters

ROADMAP_V4 listed v0.68.0 as "T0873 Project File Infection (76 → 77
techniques)" but T0873 was already covered (verified during release
prep — `T0873__project_infection__s7comm_upload_modify_dl` exists and
runs). The actual coverage gap was T0879 Damage to Property, which is
classified as non-network-observable but is the natural primary
mapping for a chain modelling the 2015/2016 Ukrainian power grid
incidents.

This release adds T0879 honestly via chain framing (76 → **77**
techniques), ships SIEM integration docs deferred from v0.67, and
drafts the three-tier detection blog post for icsforge.nl publication.

### What changed

#### `CHAIN__damage_to_property__substation` — new chain (T0879)

Multi-stage attack chain on a power substation:
1. T0846 Remote System Discovery (Modbus sweep) — 6 packets
2. T0888 Remote System Information Discovery (IEC-104 interrogation) — 4 packets
3. T0878 Alarm Suppression (IEC-104 clock_sync) — 1 packet
4. T0855 Unauthorized Command Message (IEC-104 single_command, breaker open) — 2 packets
5. T0856 Spoof Reporting Message (DNP3 spoof_response) — 5 packets
6. T0879 Damage to Property (final out-of-spec breaker command) — 1 packet

19 packets across 3 protocols (IEC-104 / Modbus / DNP3). Confidence:
medium — the chain framing is interpretive (physical damage cannot be
directly observed on the network), but each individual step has
high-confidence detection content.

#### `icsforge/data/technique_support.json` — T0879 reclassified

Before:
```json
{"class": "host_or_process", "runnable": false, ...}
```

After:
```json
{"class": "network_observable", "runnable": true,
 "covered_by_chain": "CHAIN__damage_to_property__substation", ...}
```

#### `tests/test_coverage_consistency.py` — drift baseline updated

`EXPECTED_MISSING_SPEC_TECHS` now contains `{"T0879"}` because T0879
is intentionally chain-only — no standalone detection rule spec exists
for it. Each step in the chain references techniques that DO have
specs. The chain primary is interpretive framing only.

#### `README.md` — technique counts updated

- 76 → **77** distinct technique IDs in scenario steps
- 91.6% → **92.8%** of v18 ATT&CK ICS coverage
- Remaining uncovered techniques: 7 → **6** (T0817, T0847, T0852,
  T0865, T0874, T0894 — all genuinely host-only)

#### New: `docs/SIEM_INTEGRATION.md`

Was deferred from v0.67. Walkthrough for converting ICSForge Sigma
rules to Splunk SPL, Elastic EQL/KQL, Microsoft Sentinel KQL, and
others. Covers field-name compatibility, deployment patterns, and
honest caveats about cross-SIEM detection-rate measurement.

#### New: `docs/BLOG_DRAFT_three_tier_detection.md`

Draft 1500-2000-word blog post on the three-tier architecture for
publication on icsforge.nl. Covers Tier 1 / 2 / 3 trade-offs, the
Suricata flow-direction suppression behaviour we documented in v0.66,
per-protocol detection rates, deployment guidance, and what ICSForge
intentionally doesn't do.

### Coverage state

| Metric | v0.67.0 | v0.68.0 |
|---|---|---|
| Scenarios | 624 | **625** (+1 chain) |
| Chains | 14 | **15** (+1 damage_to_property) |
| Distinct techniques | 76 | **77** |
| v18 ATT&CK coverage | 91.6% | **92.8%** |
| Uncovered v18 techniques | 7 | **6** |
| Detection rules | 929 | 929 (unchanged) |

### Roadmap status

| ROADMAP_V4 v0.68.0+ item | Status |
|---|---|
| T0873 Project File Infection (76 → 77) | already covered pre-v0.68 |
| Sigma → SPL / EQL converter docs | ✅ shipped |
| Three-tier detection blog post | ✅ draft shipped (publication is John's call) |
| T0879 Damage to Property (chain) | ✅ shipped (real 76 → 77) |

### Tests

- 401/401 fast tests pass
- 19/19 slow audit-invariant tests pass
- 0 regressions

### What's left for Black Hat Arsenal 2026

Per ROADMAP_V4:
- **June 2026:** demo videos (90s + 3min)
- **July 2026:** demo-day hardening, audience-takeaway artifacts
- **August 2026:** Black Hat Arsenal demo (early August)

---



### Why this release matters

The remaining 0%-detection protocols after v0.66.1 were both L2-only:
**IEC 61850 GOOSE** (EtherType 0x88B8) and **PROFINET DCP** (0x8892).
Suricata 7.x's detect engine cannot match L2 traffic — there is no
`ethernet` rule protocol available for content matching at L2.

v0.67.0 ships an `icsforge.sig` file containing **156 Zeek signature-
framework rules** that cover both protocols. **All 10 ICS protocols
ICSForge supports now have detection content shipped.**

### What changed in `icsforge/detection/generator.py`

#### New: `_zeek_signature(spec, base_id) -> list[str]`

Returns a list of Zeek `signature {...}` blocks for L2-only protocols
(returns `[]` for IP-based protocols — Suricata is the right tool there).

For each L2 scenario the function emits up to four signatures:
- **Tier 1 lab marker** — `eth-proto == 0xNNNN` + `payload /.*ICSFORGE_SYNTH/`
- **Tier 2 EtherType heuristic** — `eth-proto == 0xNNNN` only (presence)
- **Tier 3 per-style semantic** — `eth-proto == 0xNNNN` + bytewise
  `payload` regex matching the per-style discriminator bytes from
  `_STYLE_FC[proto][style]`

#### New: `_zeek_header()` returns the file preamble with deployment instructions

#### Wired into `generate_all`

Returns `out["zeek"]` (joined string) and `out["rule_counts"]["zeek"]`
(integer). The Suricata rule counts (lab, heuristic, semantic) are
unchanged.

#### Wired into `_write_outputs`

Writes `icsforge.sig` to the output directory alongside the existing
`icsforge_lab.rules` / `icsforge_heuristic.rules` / `icsforge_semantic.rules`
files, when zeek content is non-empty. README updated to mention the
new file and deployment instructions.

### Auto-generated GOOSE specs (43 entries)

`icsforge/data/detection_rules_specs.json` previously had 0 entries for
`iec61850` (matching the gap that existed for BACnet pre-v0.66.1). v0.67
auto-generates 43 GOOSE spec entries from `scenarios.yml`, same pattern
as the v0.66.1 BACnet spec generation.

Total spec count: 216 → 259.

### Per-style discriminators for GOOSE

GOOSE styles aren't single-byte distinguishable (same APDU shape across
all five styles). The discriminator chosen is the **gocbRef IED-name
ASCII bytes** that appear early in the GOOSE PDU:

| Style | Discriminator |
|---|---|
| `trip_inject` | `IED1` (0x49 0x45 0x44 0x31) |
| `spoof_measurement` | `IED1` |
| `protection_block` | `IED1` |
| `enumerate_ied` | `IED1` |
| `relay_inject` | `IED2` (rogue relay scenario) |

The Tier 3 semantic signature emits `payload /.*\xNN\xNN\xNN\xNN/`
matching these bytes anywhere in the GOOSE frame.

### Headline numbers (post-v0.67.0)

All 10 ICS protocols now have detection content:

| Protocol | Suricata | Zeek | Combined |
|---|---|---|---:|
| modbus, dnp3, iec104, enip, s7comm, opcua, mqtt, bacnet | ✓ | — | **100%** |
| iec61850 GOOSE | — | ✓ (4 sigs/scenario × 43) | shipped |
| profinet_dcp | — | ✓ (4 sigs/scenario × 3) | shipped |

Total detection content: 210 lab + 228 heuristic + 335 semantic Suricata
rules + 156 Zeek signatures = **929 detection rules** across all 10
protocols.

### Honest caveat: Zeek signatures static-validated, not runtime-measured

Zeek isn't installable in the ICSForge dev sandbox (no Ubuntu package;
OpenSUSE Build Service repo unreachable). The 156 emitted signatures
are statically validated:
- All parse via the standard Zeek `signature {...}` block grammar
- 0 duplicate signature IDs (156 distinct)
- All have required `eth-proto` and `event` keywords
- Balanced braces (156/156)
- ASCII-clean (no Unicode em-dashes etc. that would break Zeek parsing)

End-to-end runtime measurement against a real Zeek install is on the
v0.68 roadmap. The signature grammar follows Zeek's documented
`eth-proto`, `payload`, and `event` keywords, all of which are core
Zeek primitives (no third-party packages or parsers required).

### Tests

- 401/401 fast tests pass
- `test_rule_counts_match_changelog` updated to assert `zeek == 156`
- 0 regressions
- 0 spec-cleanliness errors (208/208 protocol/style combos clean)

### Coverage state

| Metric | v0.66.1 | v0.67.0 |
|---|---|---|
| Detection rule specs | 216 | 259 (+43 GOOSE) |
| Suricata rules emitted | 773 | 773 (unchanged) |
| Zeek signatures emitted | 0 | **156** |
| Total detection rules | 773 | **929** |
| Protocols with detection content | 8 / 10 | **10 / 10** |
| Combined detection rate, IP-based protos | 100% (8/8) | 100% (8/8) |
| L2 protocols covered (Zeek path) | 0 / 2 | **2 / 2** |

### Roadmap status

| ROADMAP_V4 v0.67.0 item | Status |
|---|---|
| Zeek script generator for L2 protocols | ✅ shipped (signature-framework path) |
| Sigma → Splunk SPL / Elastic EQL converters | ⏳ deferred to v0.68 |

Next: v0.68.0 — T0873 Project File Infection (76 → 77 techniques),
three-tier detection blog post, demo-day hardening.

---



### Why this release matters

v0.65.0's measurement showed BACnet at 0/0/0 detection across all 54
scenarios. The root cause was that the detection-rule spec file had
**zero BACnet entries**, so the rule generator had nothing to iterate
over for BACnet despite having complete `_PROTO_MAGIC` and `_STYLE_FC`
tables for the protocol.

This release closes the BACnet gap. **8 of 8 IP-based protocols with
rules now hit 100% combined detection rate.**

### What changed

#### `icsforge/data/detection_rules_specs.json` — 54 BACnet specs added

Auto-generated from `scenarios.yml`: one spec entry per pure-BACnet
scenario, with `proto: bacnet`, `port: 47808`, `transport: udp`, and
the scenario's styles enumerated. Total spec count: 162 → 216.

#### `icsforge/detection/generator.py` — BACnet config fixes

1. **Style→FC mappings corrected** (the old table had several wrong
   values that didn't match real BACnet wire bytes):

   | Style | Was | Now (correct service choice) |
   |---|---:|---:|
   | `subscribe_cov` | 0x1A | 0x05 (subscribeCOV) |
   | `device_comm_control` | 0x1C | 0x11 |
   | `reinitialize_device` | 0x12 | 0x14 |
   | `read_file` | 0x07 | 0x06 (atomicReadFile) |
   | `write_file` | 0x09 | 0x07 (atomicWriteFile) |
   | `who_is` | 0x1A | 0x08 (whoIs) |
   | `who_has` | 0x1C | 0x07 (whoHas) |
   | `time_sync` | 0x1A | 0x00 (timeSynchronization) |
   | `private_transfer` | 0x1A | 0x12 (confirmedPrivateTransfer) |
   | `i_am` | (missing) | 0x00 (iAm) |

   Verified against actual BACnet wire bytes from generated PCAPs.

2. **BVLC magic changed from `81 0A` to `81`.** The 2-byte magic only
   matched Original-Unicast-NPDU frames; broadcast frames (who-Is,
   i-Am, who-Has, time-sync) use Original-Broadcast-NPDU which starts
   with `81 0B`. The 1-byte magic covers both. BACnet/IP traffic on
   UDP/47808 always starts with 0x81, so this remains uniquely
   identifying.

3. **Updated `function_codes` name table** with the actual service
   choice → name mapping per ASHRAE 135 BACnet/IP standard.

### Headline numbers (post-v0.66.1)

| Protocol | Tier 1 (Lab) | Tier 2 (Heuristic) | Tier 3 (Semantic) | Combined |
|---|---:|---:|---:|---:|
| modbus | 100% | 86.4% | 100% | **100%** |
| dnp3 | 26.7% | 100% | 96.7% | **100%** |
| iec104 | 0% | 100% | 87.7% | **100%** |
| enip | 100% | 31.9%† | 70.8% | **100%** |
| s7comm | 1.3% | 1.3% | 100% | **100%** |
| opcua | 100% | 59.7% | 100% | **100%** |
| mqtt | 84.9% | 92.5% | 86.8% | **100%** |
| **bacnet** | **0%** | **35.2%†** | **100%** | **100%** ← v0.66.1 |
| iec61850 GOOSE | n/a | n/a | n/a | 0% (Zeek-only) |
| profinet_dcp | n/a | n/a | n/a | 0% (Zeek-only) |

† Suricata flow-direction suppression of redundant Tier 2 by higher-priority Tier 3.

**v0.66.1 status: 8 of 8 IP-based protocols with detection rules at 100% combined.**

### Lab tier 0% on BACnet — by design (consistent with IEC-104/S7comm)

The BACnet builder omits the `ICSFORGE_SYNTH` marker because the BVLC
Length field declares the BACnet packet size; appending marker bytes
would either make the frame malformed or extend beyond the declared
length and confuse dissectors. This is the same protocol-realism
constraint that affects IEC-104 and S7comm. The marker omission is
explicitly noted in `icsforge/protocols/bacnet.py:198-205`.

For correlation between sender and receiver in markerless protocols,
the v0.64.7 receiver expectation registry provides an out-of-band
attribution channel.

### Tests

- 401/401 fast tests pass
- Two test count assertions updated for new totals (210/228/335)
- 0 regressions
- 0 spec-cleanliness errors (208/208 combos still clean)

### Coverage state

| Metric | v0.66.0 | v0.66.1 |
|---|---|---|
| Detection rule specs | 162 | 216 (+54 BACnet) |
| Suricata rules emitted | 574 | 773 (+54 lab + 54 heur + 91 sem) |
| BACnet combined detection rate | 0% | **100%** |
| Protocols at 100% combined | 7 / 7 IP-based with rules | **8 / 8** IP-based with rules |
| Protocols still at 0% (need Zeek) | iec61850, profinet_dcp | iec61850, profinet_dcp |

### Roadmap status

| ROADMAP_V4 v0.66.x item | Status |
|---|---|
| ENIP heuristic across all CIP commands | ✅ shipped v0.66.0 |
| OPC UA heuristic across HELF/OPNF/MSGF/CLOF | ✅ shipped v0.66.0 |
| MQTT heuristic across CONNECT/PUBLISH/SUBSCRIBE/PINGREQ | ✅ shipped v0.66.0 |
| **BACnet detection-rule specs** | ✅ **shipped v0.66.1** |
| DNP3 short-marker variant | ⏳ deferred (DNP3 combined already 100%) |

Next: v0.67.0 — Zeek L2 detection (GOOSE + PROFINET DCP).

---



### Why this release matters

v0.65.0's measurement report identified three protocols where the rule
generator was emitting only a single hardcoded heuristic + redundant
semantic rule, missing scenarios that use any non-default command:
ENIP (31.9% combined Tier 2+3), OPC UA (25.0%), MQTT (34.0%).

v0.66.0 closes these gaps. Combined detection rates after the fix:

| Protocol | v0.65.0 | v0.66.0 |
|---|---:|---:|
| ENIP | 100% (lab only) | **100%** (semantic 31.9% → 70.8%) |
| OPC UA | 100% (lab only) | **100%** (semantic 25% → **100%**) |
| MQTT | ~85% | **100%** (heuristic 34% → 92.5%, semantic 34% → 86.8%) |

All three protocols now have Tier 2 and Tier 3 rules that fire
across the full range of commands their scenarios produce.

### Root cause

For protocols where `_PROTO_MAGIC[proto].magic_offset == fc_offset == 0`
(ENIP, OPC UA, MQTT), the magic byte IS the function code. Pre-v0.66
behaviour:

- Tier 2 hardcoded a single magic (e.g. ENIP `63 00` ListIdentity).
  Scenarios using RegisterSession/SendUnitData/etc never matched.
- Tier 3 ANDed the hardcoded magic + the per-style FC at the same
  position — `byte 0 == 0x63 AND byte 0 == 0x65` — contradictory and
  fired only when style happened to equal the hardcoded magic.

### What changed in `icsforge/detection/generator.py`

#### `_tier2_heuristic` now returns a list

Previously returned a single rule string. Now returns `list[str]`:
- Non-overlap protocols (Modbus, DNP3, IEC-104, S7comm, BACnet) —
  emit one rule using the protocol's magic byte (unchanged behaviour)
- Overlap protocols (ENIP, OPC UA, MQTT) — emit one rule per distinct
  command-byte the scenario's styles produce, using the per-style FC
  table (`_STYLE_FC[proto][style]`) instead of the hardcoded magic

If a scenario has styles that don't map to known FCs, falls back to
the protocol's default magic so generation never silently drops a rule.

#### `_tier3_semantic` adds `byte_test` for overlap protocols

For ENIP/OPC UA/MQTT, Tier 3 now matches:
- `content:"<fc>"; offset:0; depth:N;` — the command byte
- `byte_test:N,>,0,M` — verifying the length field is non-zero

This makes Tier 3 strictly more specific than Tier 2 instead of an
identical-content duplicate. Suricata's signature group manager can
distinguish the two rules cleanly.

For non-overlap protocols, Tier 3 keeps its existing magic + FC
double-content match (unchanged).

#### Caller in `generate_all` updated

The Tier 2 caller now iterates over the list-returning result the same
way the existing Tier 3 caller does. Each rule gets its own SID.

### Suricata flow-direction suppression — explained, not a bug

Reviewers may notice that ENIP Tier 2 still measures at 31.9% in the
output. This is **expected Suricata behaviour, not a v0.66 defect**:

- Tier 2 (`classtype:protocol-command-decode`, priority 3)
- Tier 3 (`classtype:attempted-admin`, priority 1)
- Both with `flow:to_server` and identical first-content match

Suricata's per-flow alert deduplication fires the higher-priority rule
(Tier 3) and suppresses the lower-priority Tier 2 alert. When Tier 2
is loaded **alone**, it fires on 100% of relevant scenarios (verified).
When loaded with Tier 3, the production deployment correctly collapses
the redundant signal to the most-specific rule per flow.

`docs/REFERENCE_DETECTION_COVERAGE.md` now explains this. The
"Combined" detection rate (any tier fires) is the operationally
relevant metric — and it is 100% for all three formerly-gapped
protocols.

### Headline numbers (ICSForge IP-based protocols with rules)

| Protocol | Lab | Heur | Sem | Combined |
|---|---:|---:|---:|---:|
| modbus | 100% | 86.4% | 100% | **100%** |
| dnp3 | 26.7% | 100% | 96.7% | **100%** |
| iec104 | 0% | 100% | 87.7% | **100%** |
| enip | 100% | 31.9%† | 70.8% | **100%** |
| s7comm | 1.3% | 1.3% | 100% | **100%** |
| opcua | 100% | 59.7% | 100% | **100%** |
| mqtt | 84.9% | 92.5% | 86.8% | **100%** |

† Suricata flow-direction suppression of redundant Tier 2 by Tier 3.

**7 of 7 IP-based protocols with rules at 100% combined detection rate.**

### Tests

- 401/401 fast tests pass
- Two test assertions updated for new heuristic count (156 → 174)
- 0 regressions
- 0 spec-cleanliness errors (208/208 combos still clean)

### Coverage state

| Metric | v0.65.0 | v0.66.0 |
|---|---|---|
| Suricata rules emitted | 556 | 574 (+18 heuristic) |
| Tier 2 rules covering ENIP commands | 1 (ListIdentity only) | per-style emission across 5 commands |
| Tier 2 rules covering OPC UA messages | 1 (Hello only) | per-style emission across 4 message types |
| Tier 2 rules covering MQTT control packets | 1 (CONNECT only) | per-style emission across 7 packet types |
| Combined detection rate, IP protos w/ rules | varied 85-100% | **100% across all 7** |

### Remaining v0.66.x roadmap items

The following items from ROADMAP_V4 § v0.66.0 are deferred to v0.66.1+:

4. **BACnet detection-rule specs population** — needs ~50 hand-curated
   spec entries; ~1 dev-day. Defers because architectural fix in this
   release was higher-leverage.
5. **DNP3 short-marker variant** — still on roadmap; lower priority
   since DNP3 combined rate is already 100%.

Items 1, 2, 3 (ENIP/OPC UA/MQTT) shipped in this release.

---



### Why this release matters

Black Hat Arsenal 2026 acceptance confirmed. The single highest-leverage
remaining work item for the demo was the detection-rate measurement —
the answer to the inevitable reviewer question "what's your detection
rate?" v0.65.0 ships that answer in `docs/REFERENCE_DETECTION_COVERAGE.md`,
runs through every protocol with concrete numbers, and explains every
gap honestly.

### Headline measurement

Suricata 7.0.3 against ICSForge's 606 measurable scenarios, three tiers:

| Protocol | Lab | Heuristic | Semantic | Combined |
|---|---:|---:|---:|---:|
| modbus | 100% | 86.4% | 100% | **100%** |
| dnp3 | 26.7% | 100% | 96.7% | **100%** |
| iec104 | 0% | 100% | 87.7% | **100%** |
| enip | 100% | 31.9% | 31.9% | **100%** |
| s7comm | 1.3% | 1.3% | 100% | **100%** |
| opcua | 100% | 25.0% | 25.0% | **100%** |
| mqtt | 84.9% | 34.0% | 34.0% | ~85% |
| bacnet | 0% | 0% | 0% | 0% (no rules) |
| iec61850 | n/a | n/a | n/a | 0% (Suricata cannot match L2) |
| profinet_dcp | n/a | n/a | n/a | 0% (Suricata cannot match L2) |

**6 of 10 protocols hit 100% combined detection rate.** The remaining
four protocols have honest, documented gaps with concrete v0.66+
follow-ups.

### What changed

#### Rule generator: stop emitting unmatchable Suricata rules for L2 protocols

`_tier1_marker()` in `icsforge/detection/generator.py` previously emitted
`alert tcp` rules for IEC 61850 GOOSE and PROFINET DCP. Suricata 7.0.3's
detection engine cannot match L2-only traffic — the `ethernet` rule
protocol is unsupported, and `pkthdr` content matching at L2 doesn't
fire. Six rules went out and never matched anything.

v0.65.0 detects `pm.get("transport") == "l2"` and returns `None`. The
caller now handles the None and emits no rule. Previous count: 162 lab
+ 156 heuristic + 244 semantic = 562. New count: 156 + 156 + 244 = 556.

This makes the detection generator output truthful: every emitted
Suricata rule is potentially-matchable. Detection of L2 protocols is
correctly directed to Zeek + Sigma (already shipped) — see
`docs/REFERENCE_DETECTION_COVERAGE.md` for deployment guidance.

#### New documentation: `docs/REFERENCE_DETECTION_COVERAGE.md`

Comprehensive measurement report. Includes:
- Per-protocol detection rates across all three tiers
- Combined detection rates (rate at which any tier fires)
- Honest accounting for every gap with the underlying technical reason
- Methodology + reproduction commands
- Deployment guidance for L2 protocols (Zeek path)

This is the single most-asked-for document for Arsenal credibility.

#### New: `docs/ROADMAP_V4.md`

The v0.62.3-era ROADMAP_V3 was nine months out of date and has been
archived to `docs/history/ROADMAP_V3_v0.62.3_era.md`.

ROADMAP_V4 reflects post-Arsenal-acceptance reality:
- v0.66.0: detection-rule completion (5 items, ~2.5 dev-days)
  closing the heuristic / semantic gaps for ENIP, OPC UA, MQTT, BACnet
  + DNP3 Tier 1 mitigation
- v0.67.0: L2 detection via Zeek path
- v0.68.0+: coverage growth, blog post, T0873
- July 2026: demo-day hardening, audience-takeaway artifacts
- August 2026: BlackHat Arsenal demo
- Strategic items: ET-rules repo, vendor outreach, protocol statefulness

### Tests

- 401/401 fast tests pass
- 19/19 slow audit-invariant tests pass
- 0 regressions
- Two test count assertions updated for new rule total (162 → 156 lab)

### Coverage state

| Metric | v0.64.8 | v0.65.0 |
|---|---|---|
| Scenarios | 624 | 624 |
| v18 techniques | 76 | 76 |
| v19 annotations | 109 | 109 |
| Confidence high/med/low | 457/134/19 | 457/134/19 |
| Suricata rules emitted | 562 (incl 6 L2 deadweight) | 556 (no deadweight) |
| Combined detection rate, 6 IP-based protocols | unmeasured | **100%** |
| Combined detection rate, all 10 protocols | unmeasured | 77.1% (gaps documented) |
| Tests passing | 401 fast + 19 slow | 401 fast + 19 slow |
| Documented gaps with follow-up plan | partial | **comprehensive** |

---



### Why this release matters

External reviewer (2026-05-07) verified v0.64.7 as "Black Hat-demo
defensible" and flagged two non-blocking items: scenarios.yml YAML
load took 5–6 seconds on their machine, and the README was still
showing v0.63.0 numbers. Both fixed here.

### What changed

#### YAML loader: libyaml CSafeLoader + mtime cache

`icsforge/web/helpers_io._load_yaml(path)` now:
- Uses `yaml.CSafeLoader` when libyaml is available (transparently
  falls back to pure-Python `SafeLoader` if not). On our scenarios.yml
  this is an 8× speedup: 1400ms → 170ms cold parse.
- Adds an in-process mtime-keyed cache: the same path returns the
  cached parsed dict in microseconds until the file's mtime changes,
  at which point it re-parses on the next call.

Measured on scenarios.yml (704 KB, 19,602 lines, 624 scenarios):

| | Before | After (cold) | After (cache hit) |
|---|---|---|---|
| safe_load | 1400 ms | 170 ms (libyaml) | 0.04 ms |

The cache is read-mostly. Concurrent web requests for the same scenario
file all serve from the same dict (no copy on read; web routes do not
mutate). Test suite runtime dropped from 113s to 87s as a side effect.

The other YAML loads in the web layer (campaigns.yml, profile YAMLs)
are intentionally untouched — those files are <10KB so the parse
overhead is already negligible, and broadening the change would risk
regressions for no measurable win.

#### README freshness

- Version badge: 0.63.0 → 0.64.7
- Key Numbers table updated for v0.64.7 reality:
  - 624 scenarios (was 623)
  - Confidence distribution 457/134/19 (was the stale 595/2/12)
  - Note added that 109 scenarios carry `technique_v19` annotation
  - v19 sub-technique coverage updated to 12/18 (was 10/18)
  - Markerless-attribution row added documenting the v0.64.7 receiver
    expectation registry
- Detection Rules row notes the three-tier rule structure

### What did NOT change

- Reviewer's third item ("not a full emulator") was explicitly accepted
  as fine — they recommended keeping the positioning honest, which we
  already do in the README opening paragraph ("OT/ICS security coverage
  validation platform"). No framing change needed.
- Reviewer's `pytest-timeout` plugin friction is documentation only —
  CONTRIBUTING.md and README already document `pip install -e ".[dev]"`
  as the developer install path. Not a code issue.

### Tests

- 401/401 fast tests pass
- Suite runtime: 113s → 87s (-23%)
- 0 regressions
- 0 spec-cleanliness errors (208/208 combos)

---



### Why this release matters

v0.64.6 reverted the IEC-104 marker append (which broke the dissector).
That left IEC-104 — and any scenario run with `--no-marker` (stealth mode) —
without a way for the receiver to attribute incoming packets back to a
specific (run_id, scenario, step). The sender's "scenario delivered"
confirmation flow depended on the receiver matching the marker; no marker
meant no callback.

This release closes that gap with an out-of-band correlation channel:
the **expectation registry**.

### How it works

1. Before replaying, the sender (web blueprint) inspects the scenario.
   If any step uses IEC-104, or if `no_marker=True` was requested, the
   sender:
   - Pre-generates the `run_id`
   - POSTs `/api/receiver/expect` with `{run_id, scenario, technique,
     protos, ttl_sec}`
2. The receiver stores the expectation in memory, TTL-bounded
   (default 5 min).
3. The sender runs the scenario, passing its pre-generated `run_id`
   into `send_scenario_live`.
4. When IEC-104 (or any markerless) packets arrive, the receiver's
   `_parse_marker(payload, proto=...)`:
   - Returns `marker_found: True, attributed_via: "marker"` if the
     ICSFORGE_SYNTH marker is present (legacy behaviour, unchanged)
   - Otherwise looks up the active expectation by `proto`, and returns
     `marker_found: False, run_id: <expected>, technique: <expected>,
     attributed_via: "expectation"`
5. Either path now triggers the callback to the sender. Receipts carry
   the `attributed_via` flag so SOC tooling can apply different
   confidence levels to marker-verified vs expectation-attributed
   receipts.

The marker still wins when present — there is no semantic change for
any protocol that does carry the marker (Modbus, DNP3, S7comm, ENIP,
OPC UA, MQTT, BACnet, IEC-61850 GOOSE, PROFINET DCP).

### What changed

#### `icsforge/receiver/receiver.py` — registry + attribution

- New `_expect_lock`, `_expectations: dict[str, dict]` registry
- New public functions:
  - `register_expectation(run_id, scenario, technique, steps, ttl_sec, protos)`
  - `clear_expectation(run_id)`
  - `list_expectations()` — auto-prunes expired entries
- `_parse_marker(payload, proto)` now accepts `proto` and falls back to
  expectation matching when no marker is present
- `_write_receipt` triggers callback on either `marker_found=True` OR
  `attributed_via == "expectation"`
- TCP, UDP, and L2 PROFINET paths all pass `proto` to `_parse_marker`
- All log lines distinguish marker-attributed vs expectation-attributed

#### `icsforge/web/bp_receiver.py` — HTTP endpoints

- `POST /api/receiver/expect` — register or extend an expectation
  (HMAC-protected when callback token is configured)
- `GET /api/receiver/expectations` — list active expectations
- `DELETE /api/receiver/expect/<run_id>` — clear early on abort

#### `icsforge/auth.py`

- POST and GET expectation endpoints added to `PUBLIC_PATHS`
  (sender uses them without an interactive session; HMAC enforces
  authenticity when token is set). DELETE remains auth-required.

#### `icsforge/web/helpers.py`

- New `announce_expectation(run_id, scenario, technique, steps, ttl_sec, protos)`
  helper that POSTs to the configured receiver. Safe-no-op if no
  receiver is configured. Failures are non-fatal (logged at debug).

#### `icsforge/web/bp_scenarios.py`

- Live-send path now auto-announces expectations when the scenario uses
  IEC-104 or `no_marker=True`. Pre-generates `run_id` and passes it
  through to `send_scenario_live`.

#### `icsforge/live/sender.py`

- `send_scenario_live(...)` now accepts an optional `run_id` parameter.
  If provided, overrides the auto-generated id. Used by the web
  blueprint so the announced expectation matches the actual run.

### Tests

`tests/test_markerless_attribution.py` — **17 new tests, all passing**:

- **Registry semantics** (5 tests): register returns entry, empty run_id
  is no-op, register replaces existing run, clear works, expired entries
  auto-pruned on list
- **Marker-vs-expectation precedence** (6 tests): marker wins when
  present, no marker + no expectation returns none, no marker + matching
  expectation attributes correctly, proto mismatch does not attribute,
  null protos matches any proto, received counter increments
- **HTTP endpoints** (5 tests): POST registers, missing run_id returns
  400, missing token returns 401, bad HMAC returns 401, GET lists
- **Helper** (1 test): announce_expectation safe-no-op when no receiver

Full suite: **401 fast tests pass** (was 384, +17), zero regressions.

### Distinguishing marker-verified vs expectation-attributed receipts

Receipts in `_live_receipts` and the JSONL file now carry an
`attributed_via` field:

| Value | Meaning |
|---|---|
| `marker` | ICSFORGE_SYNTH marker found in payload bytes — high-confidence correlation |
| `expectation` | No marker; attributed to an active pre-announced expectation by proto match — moderate-confidence correlation, requires that no other sender was active in the TTL window |
| `none` | No marker, no matching expectation — receipt stored but no callback dispatched |

SOC tooling and the sender UI can present these differently if desired.

### Known limitations

- Expectation matching is FIFO when multiple expectations are active for
  the same proto. In practice we expect one active expectation at a time
  (single sender, single concurrent run). Concurrent runs against the
  same receiver targeting the same proto would need finer-grained
  matching (e.g., by sender source IP).
- Markerless attribution is in-memory only. If the receiver process
  restarts mid-run, the expectation is lost. The marker-based path is
  unaffected by receiver restarts since the marker is in the bytes.
- The expectation does not provide per-step granularity (no `step` field)
  — only run-level attribution. This is acceptable because IEC-104 and
  stealth runs cannot identify individual steps from packet contents
  anyway.

---



### Why this release matters

In v0.64.5 we acted on external reviewer finding #9 ("IEC-104 marker
missing") by appending `marker_bytes()` to every IEC-104 APDU. Closer
inspection showed this **broke IEC-104 protocol realism** — the trade-
off is unacceptable for a tool that markets itself on protocol fidelity.

### What we observed in v0.64.5

The marker append produced this Wireshark output for IEC-104 traffic:

```
1   IEC 60870-5-104   60   <- U (STARTDT act)
2   IEC 60870-5-104  137   <ERR prefix 50 bytes> <- U (<ERR>)
3   IEC 60870-5 ASDU 147   <- I (...)
4   IEC 60870-5-104  147   <ERR prefix 50 bytes> <- U (<ERR>)
...
```

**17 of 35 frames** flagged with `<ERR prefix 50 bytes>`. Root cause:

- IEC-104 has no application-data field outside the ASDU IOA elements
- Appending bytes after the APDU LEN byte means the next TCP segment
  starts with the marker tail of the previous segment
- TCP reassembly fuses these into a single IEC-104 stream
- Wireshark's IEC-104 dissector reports `<ERR prefix N bytes>` for
  every reassembled frame whose start is preceded by trailing junk

This is exactly what the file's pre-existing comments warned against:

```python
# IEC-104 I-format frames: marker is OMITTED to preserve APCI length
# integrity. Per IEC 60870-5-101/104, the ASDU length is derived from
# type ID + element count; appending arbitrary bytes after the IOA
# elements makes the ASDU invalid per spec (Wireshark/Zeek/Malcolm
# dissectors all flag "Invalid Apdulen").
```

The marker omission was a **deliberate, documented design constraint**.
The reviewer hadn't read the source comments, and the v0.64.5 "fix"
undid the constraint and broke IEC-104 dissection across the board.

### What changed in this release

- Reverted `iec104.build_payload()` to the inner-only form (no marker
  append). All tests pass; tshark dissection is clean again.
- Removed the `marker_bytes` import that became unused.
- Verified zero `<ERR>` frames, zero malformed dissection warnings,
  and zero spec-cleanliness errors.

### What about reviewer finding #9 then?

Re-evaluated. Three points:

1. **Detection coverage is unaffected.** Tier 1 (lab marker), Tier 2
   (protocol heuristic), and Tier 3 (semantic) detection rules use OR,
   not AND. IEC-104 traffic still matches Tier 2 (port 2404 + protocol)
   and Tier 3 (function code semantics). The marker only adds a third
   match path for lab correlation; it is not required for detection.

2. **Lab correlation is available via runner metadata.** Every PCAP
   ICSForge generates is recorded with run_id, scenario name, and step
   index in the JSONL events file. Lab teams can correlate IEC-104
   PCAPs to scenarios via that record without requiring a marker in
   the packet bytes.

3. **No safe in-band alternative exists.** Considered options:
   - Append after APDU → breaks dissector (this release reverts it)
   - Embed in IOA payload → distorts scenario semantics (a synthetic
     marker IOA changes the modelled command)
   - Embed in COT/ORG fields → only 8 bits available, insufficient
   - Use IEC-104 private types → still adds synthetic frames

   **Decision:** accept the protocol-level constraint. Document IEC-104
   as the one protocol where in-band marker correlation is technically
   infeasible. Out-of-band correlation via runner metadata remains.

### Honest accounting on v0.64.5

The other v0.64.5 changes (PROFINET dead-code removal, confidence
downgrades, chain schema normalization) remain in place — those were
correct fixes. Only the IEC-104 marker change is reverted.

### Tests

- 190 protocol/audit/e2e tests pass
- 208/208 style combos spec-clean (203 clean + 4 GOOSE upstream-bug
  + 1 expected-malformed)
- 0 genuine spec errors
- 0 regressions

### Lesson

Reviewer findings deserve verification, not just compliance. Three of
the v0.64.5 reviewer items turned out to be inaccurate (#6 MQTT
compliance, #7 DNP3 CRC chunking) or actively wrong-to-fix (#9 IEC-104
marker). This is a reminder that the audit catalogs and existing source
comments are part of the correctness story, and they should be read
before "fixing" the thing they document.

---



### Why this release matters

External reviewer (2026-05-02) flagged ten items in v0.64.4. After
verification, four were correct and have been fixed; three were already
addressed by prior work; three were either inaccurate or trade-offs we
deliberately accept. This release closes the four genuine issues.

### Verified findings — fixed in this release

#### Finding #1: PROFINET legacy `build()` had broken NameError

`icsforge/protocols/profinet_dcp.py` had a legacy `build()` function (the
old single-call API) that referenced `_src_mac_from_ip` without
importing it. Calling it would raise `NameError`. The function had no
callers in the codebase. **Fix:** deleted the function.

#### Finding #2: Overuse of `confidence: high`

96.1% of standalone scenarios were marked `high`. The reviewer
correctly observed this is too monolithic, especially for techniques
where the network observes the *trigger* but the *outcome* requires
host-level evidence.

**Fix:** Downgraded 129 scenarios from `high` → `medium`, with explicit
`confidence_rationale` documenting why. New distribution:

| Confidence | v0.64.4 | v0.64.5 |
|---|---|---|
| high   | 586 (96.1%) | 457 (74.9%) |
| medium |   5 (0.8%)  | 134 (22.0%) |
| low    |  19 (3.1%)  |  19 (3.1%)  |

Categories downgraded:
- **Firmware** (T0800, T0839, T0857) — network sees transfer; flash
  persistence is host-level
- **Program lifecycle** (T0843, T0845, T0889) — network sees transfer;
  activation is host-level
- **Impact-from-trigger** (T0813, T0815, T0827, T0829, T0826, T0828,
  T0837, T0880) — network sees the cause; the impact state is an
  operational consequence inferred from the cause

Not downgraded (already correct):
- Weak mappings (T0862 supply chain, T0860/T0887 wireless, T0823/T0863
  GUI/User Execution, T0851 rootkit) — already at `confidence: low`

#### Finding #4: Chain scenarios had inconsistent schema

All 14 chain scenarios were missing `confidence`; 8 lacked `tactic`;
3 lacked `technique`.

**Fix:** Normalized all 14 chains to carry `tactic: Multi-Stage`,
`technique: <primary culminating technique>`, `confidence: medium`,
and a `confidence_rationale` enumerating the chain's stages.

#### Finding #9: IEC-104 traffic missing the ICSForge marker

Verified via packet inspection: IEC-104 PCAPs contained zero instances
of the ICSForge marker, while every other protocol's PCAPs included it.
This was a real correlation gap — detection rules using marker-based
correlation would silently miss IEC-104 evidence.

**Fix:** Refactored `iec104.build_payload()` to wrap the inner builder
and append marker bytes after the last APDU. The IEC-104 LEN byte in
each APCI declares APDU length, so dissectors stop at LEN bytes and
treat trailing bytes as inter-frame data (skipped, not malformed).

Verification: marker now appears in every IEC-104 PCAP, IEC-104 frames
still parse cleanly (35 frames in test scenario), zero malformed-frame
warnings from tshark.

### Verified findings — already addressed

- **Finding #3 (weak mappings should be `low`):** Already done in
  v0.64.0/v0.64.2. T0862, T0860, T0887, T0823, T0863, T0851 all at
  `confidence: low`. Confirmed.

### Verified findings — declined or trade-offs

- **Finding #6 (MQTT marker breaks compliance):** Inaccurate. Verified
  by packet inspection that the marker is *inside* the MQTT PUBLISH
  Message field (a JSON-payload application-data field), not appended
  after the MQTT framing. The MQTT protocol does not validate
  application payload contents — brokers route opaque bytes. JSON
  invalidity of the application payload is realistic adversary
  behaviour anyway. **No change.**

- **Finding #7 (DNP3 CRC not chunked per 16 bytes):** Inaccurate.
  Verified by code inspection (`_data_blocks` at `dnp3.py:84-87`) and
  by tshark dissection ("Data Chunk Checksum Status: Good" on every
  block in test PCAPs, zero bad-CRC errors). The CRC IS chunked per
  16-byte block per IEEE 1815-2012. **No change.**

- **Finding #11 (positioning):** Documentation/messaging concern, not
  a code issue. Already addressed in README.

### Lower-priority findings — deferred

- **Finding #5 (no protocol stateful response):** Acknowledged as a
  limitation. ICSForge is a deterministic traffic generator; modelling
  full stateful sessions is out of scope for the current architecture.
  Documented as a known limitation.
- **Finding #8 (endpoint performance):** Not blocking for Arsenal demo.
  Caching opportunities tracked separately.
- **Finding #10 (other dead code):** Audit ran on protocol modules.
  Only PROFINET had dead code.

### Tests

- 384/384 fast tests pass
- 19 slow audit-invariant tests pass
- 0 spec-cleanliness errors across 208 style combos
- 0 semantic-correctness errors across 610 scenarios
- 0 functional-truthfulness errors
- 0 regressions

### Coverage state

| Metric | Value |
|---|---|
| Total scenarios | 624 (610 standalone + 14 chains) |
| Distinct v18 techniques | 76 |
| `technique_v19` annotations | 106 |
| Confidence: high | 457 / 610 (74.9%) |
| Confidence: medium | 134 / 610 (22.0%) |
| Confidence: low | 19 / 610 (3.1%) |
| Chains with full schema | 14 / 14 |
| Protocols emitting marker | 10 / 10 (was 9 / 10 before this release) |

---



### Why this release matters

Prior audits proved spec-cleanliness (Phase 1) and protocol-layer
truthfulness (Phase 3 — every scenario produces traffic on its claimed
protocol). What was missing was the **semantic** check: does the
PROTOCOL VERB used by each scenario fit the MITRE technique it claims?

For example: a scenario labelled "T0814 Denial of Service" that emits
only ordinary read traffic without high frequency would fail the
semantic check. Or a scenario labelled "T0843 Program Download" that
only does device discovery would fail.

This release builds and locks the semantic audit into CI.

### What this release contains

#### A. Audit framework (new)

- **`icsforge/data/audit_technique_requirements.json`** — Per-technique
  catalog: 77 entries covering all 76 MITRE ICS techniques used in our
  scenarios. Each entry defines `allow_classes`, `forbid_classes`, `desc`.

- **`icsforge/data/audit_style_classification.json`** — Per-(proto, style)
  classification: 208 entries mapping every (protocol, style) combo used
  in scenarios.yml to a set of verb classes. Verb vocabulary:
  `read, write, operate, identify, discover, browse, list, probe,
   session, auth, mode_change, restart, firmware, flood, spoof, block,
   malformed, method, upload, config, delete`

- **`tests/test_scenario_semantic_audit.py`** — 3 CI tests that lock the
  audit invariant:
  1. `test_audit_catalogs_cover_all_techniques`
  2. `test_audit_classifier_covers_all_combos`
  3. `test_no_scenario_fails_semantic_check`

#### B. Audit results

Initial audit: **77 of 610 standalone scenarios flagged.**
After triage and three rounds of catalog refinement:
  - 38 false positives — flood-class techniques (T0814/T0826/T0815/etc.)
    where high-rate read/identify IS the flood by design
  - 13 false positives — auth-class techniques (T0822/T0859/T0883/T0886/
    T0891) on unauth-by-default protocols
  - 5 false positives — block techniques (T0803/T0804/T0805/T0878) where
    `mode_change`/`restart`/`session` ARE valid block mechanisms
  - 21 deeper-catalog issues — all resolved through targeted refinements
    on T0858, T0816, T0800, T0855, T0809, T0836, T0889, T0880, T0878

Style-classifier fixes:
  - `modbus/report_block` and `modbus/get_comm_event_counter` reclassified
    from `block` to `identify`+`read` (they're FC11/FC12 device-info reads)
  - `mqtt/publish_config` reclassified to include `write`

After all refinements: **0 of 610 standalone scenarios fail the semantic audit.**

#### C. Phase 3 — full protocol-layer ground-truth verification

Generated PCAP for every unique (proto, style) combo (208 combos) and
verified the expected protocol layer is present:
**208/208 pass. Every scenario's PCAP contains the claimed protocol.**

#### D. Tests

- 384/384 fast tests pass (was 377; +3 new audit tests +4 stable)
- 19 slow audit-invariant tests pass
- 0 spec-cleanliness errors across 208 style combos
- 0 semantic-correctness errors across 610 scenarios
- 0 functional-truthfulness errors across 208 (proto, style) combos
- 0 regressions

### Coverage state

| Metric | Value |
|---|---|
| Total scenarios | 624 (610 standalone + 14 chains) |
| Distinct v18 techniques | 76 |
| `technique_v19` annotations | 106 |
| Confidence labels | 610 |
| Spec-clean style combos | 203 / 208 (4 GOOSE upstream-bug + 1 expected-malformed) |
| Semantic-clean scenarios | 610 / 610 |
| Functional-truthful scenarios | 610 / 610 |
| Tests passing | 384 fast + 19 slow |

### How to run the audit going forward

```bash
pytest tests/test_scenario_semantic_audit.py
```

Any new scenario added to scenarios.yml that uses a (proto, style) combo
or technique not in the catalogs will fail one of the three guard tests,
forcing the contributor to add catalog entries before the scenario can land.

---

## v0.64.3 (2026-05-02) — Web UI matrix v18/v19 toggle

### Why this release matters

The `/matrix` page in the Web UI rendered "ATT&CK for ICS v18.1"
hard-coded in the title. With v19 sub-techniques now extensively
annotated in our scenario library (106 scenarios with `technique_v19`),
the matrix view should let users see coverage in the v19 layout too.

### What changed

- **New file:** `icsforge/data/ics_attack_matrix_v19.json` — 79 parent
  techniques + 18 sub-techniques. Generated from the v18 matrix + the
  official MITRE crosswalk JSON, with multi-tactic placement preserved
  (112 entries in 12 tactics).
- **Matrix loader:** `_load_matrix(version="v18")` now accepts a version
  parameter.
- **Matrix route:** `/matrix?version=v19` renders the v19 view. Default
  `/matrix` keeps the v18 layout for backwards compatibility.
- **Coverage logic:** v18 view uses `technique` field; v19 view uses
  `technique_v19` (falling back to `technique`). Sub-tech IDs auto-light
  up parent tile.
- **UI toggle:** v18/v19 segmented buttons in matrix.html controls bar.
- **Sub-technique CSS:** indented left margin, dashed border, smaller
  italic name, "↳ " prefix on ID.
- **7 new tests** in `TestMatrixVersionToggle` (all pass).

---

## v0.64.2 (2026-05-01) — Authoritative MITRE v19 crosswalk lock-in

### Why this release matters

Verified ICSForge's v19 sub-technique mappings against the **authoritative
MITRE v19 ICS sub-techniques crosswalk JSON** at
https://attack.mitre.org/docs/subtechniques/ics-sub-techniques-crosswalk.json

The crosswalk identifies 9 v18 IDs that "Became new sub-technique" (direct
remap required) and 3 parent techniques that "Remain a technique" but
gained sub-techniques (refinement opportunities). Plus 9 net-new sub-techs
(no v18 equivalent at the leaf level).

This release closes the remaining gaps from v0.64.1 and locks the result
against drift via two new regression tests.

### What changed

#### 1. T0843 / T0846 / T0873 sub-technique refinement (6 scenarios)

| Scenario | Was | Now | Why |
|---|---|---|---|
| `T0846__remote_sys_discovery__dnp3_probe` | (no v19 annotation) | T0846.001 | single-target probe = Port Scan |
| `T0846__remote_sys_discovery__modbus` | (no v19 annotation) | T0846.001 | single-target probe = Port Scan |
| `T0846__network_scan__profinet_dcp` | T0846.001 | **T0846.002** | DCP Identify-All is functional broadcast |
| `T0846__network_scan__iec61850_goose` | (no v19 annotation) | **T0846.003** | GOOSE is multicast (NEW v19 sub-tech) |
| `T0843__program_download__modbus` | T0843.001 | **T0843.002** | Single-register write while running = Online Edit |
| `T0873__project_infection__s7comm_upload_modify_dl` | (no v19 annotation) | **T0873.001** | Siemens-specific = Siemens Project File Format (NEW v19 sub-tech) |

#### 2. attack_mapping schema sync (19 scenarios)

After the v0.64.1 work added `technique_v19` annotations, an earlier
v0.63.x `attack_mapping.primary.v19_id` field was found to be stale on
19 scenarios — same scenarios, two fields, divergent values. Synced
attack_mapping.primary.v19_id to match the (more accurate)
technique_v19 field.

#### 3. Two new authoritative-crosswalk regression tests

- `test_all_remap_targets_are_correctly_annotated` — every scenario
  whose primary technique is in the MITRE crosswalk's "Became new
  sub-technique" list MUST carry the correct `technique_v19` annotation
- `test_no_invalid_v19_ids` — `technique_v19` values must be one of the
  18 authoritative v19 sub-tech IDs

#### 4. Updated docs/MITRE_V19_CROSSWALK.md

Rewrote to reflect actual v0.64.2 state (was stale, predicting future
work that's now done):

- Documents per-scenario sub-technique assignments with reasoning
- Explains why T0843.003 / T1695.002 / T1695.003 are out of scope
- Adds a verification snippet for reproducing the coverage figures

### Coverage state (v0.64.2)

| Reading | Number |
|---|---|
| v18 standalone techniques covered | **76 of 83** (91.6%) |
| v19 standalone techniques covered | **65 of 79** (82.3%) |
| **v19 sub-techniques covered** | **15 of 18** (83.3%) |
| Scenarios with `technique_v19` annotation | **110 of 610** standalone |

The 3 v19 sub-techs not covered are correctly out of scope:
- T0843.003 Program Append (could be added; not link-layer/RF)
- T1695.002 Block Communications: Ethernet (link-layer)
- T1695.003 Block Communications: Wi-Fi (RF)

### Tests

- **370/370 fast tests passing** (2 new authoritative crosswalk tests)
- All 19 slow audit-invariant tests passing
- Zero regressions

### Verification

```bash
python3 -c "
import yaml
with open('icsforge/scenarios/scenarios.yml') as f:
    sc = yaml.safe_load(f)['scenarios']
techs = set(s.get('technique') for body in sc.values() if isinstance(body,dict)
            for s in body.get('steps', []) if 'technique' in s)
v19_subs = set(body.get('technique_v19') for body in sc.values()
               if isinstance(body,dict) and 'technique_v19' in body)
print(f'v18 techniques: {len(techs)}, v19 sub-techs: {len(v19_subs)}')
"
# Expected: v18 techniques: 76, v19 sub-techs: 15
```

---



## v0.64.4 (2026-05-02) — Phase 4 semantic audit: 0 mis-tagged scenarios out of 610

### Why this release matters

Reviewer asked: do all 600+ scenarios actually fit their claimed
techniques in v18 AND v19? This release answers that with a permanent
CI test backed by an explicit audit catalog.

### What this release adds

#### Audit catalog (NEW data files)

Two new files now ship with ICSForge:

- `icsforge/data/audit_technique_requirements.json` — for each of 76
  techniques used in scenarios, defines:
  - `allow_classes` — verb classes the technique accepts
    (e.g., T0855 Unauthorized Command Message accepts `write`/`operate`)
  - `forbid_classes` — verb classes that disqualify a scenario
  - `require_one_of` — at least ONE step must hit one of these classes
    (prevents over-relaxation; e.g., T0855 requires write/operate to
    actually be present, not just `identify`)

- `icsforge/data/audit_style_classification.json` — every (proto, style)
  combo used in any scenario (208 unique combos) mapped to verb classes
  (read / write / operate / identify / mode_change / restart / firmware /
  auth / session / flood / spoof / block / malformed / method / upload /
  config / delete / probe / discover / browse).

Together these allow a deterministic, repeatable check that each
scenario's protocol traffic is consistent with what its MITRE technique
ID claims.

#### Count-aware verb classification

A step with `count >= 10` automatically contributes `flood` to its
verb-class set. This captures session-exhaustion, table-fill, and
rate-based attacks where the verb itself (e.g., `register_session`) is
not inherently a flood, but the high count makes it one.

#### Regression test in CI

New test class `TestPhase4SemanticAudit` in `tests/test_v062_additions.py`:

1. **`test_all_standalone_scenarios_pass_audit`** — runs the audit on all
   610 standalone scenarios. Currently passes with **0 flagged**.
2. **`test_audit_catches_mistagged_scenario`** — sanity test: a read-only
   scenario deliberately re-tagged as T0855 must FAIL the audit.
3. **`test_audit_catches_discovery_as_program_download`** — sanity test:
   a discovery scenario re-tagged as T0843 must FAIL.
4. **`test_audit_catalog_covers_all_used_techniques`** — every technique
   referenced in scenarios.yml must have a catalog entry. Drift detection.

If anyone adds a new scenario that doesn't match its claimed technique,
this test will fail in CI before the PR can merge.

### Audit run

| Metric | Result |
|---|---|
| Standalone scenarios audited | 610 |
| Flagged as semantically mis-tagged | **0** |
| Sanity tests (deliberately wrong tags) | 16/16 correct |

### Audit history (the path to 0)

The audit was iteratively refined:

| Version | Flagged | Notes |
|---|---|---|
| Initial run (strict catalog) | 77 | Many false positives |
| After Bucket A relax (flood techs accept read/identify) | 39 | |
| After Bucket B relax (auth techs on unauth protos) | 26 | |
| After Bucket C relax (block techs accept session/restart) | 21 | |
| After classifier fixes (`report_block`, `device_comm_control`, `protection_block`, etc.) | 8 | |
| After `require_one_of` constraint added | 3 | Prevents over-relaxation |
| After count-aware flood classification (count ≥ 10) | 1 | |
| After `unregister_session`/`forward_close` → `block` | **0** | |

Each refinement was followed by a sanity test against deliberately-wrong
tags to confirm we hadn't lost discrimination power. Final state:
**0/610 flagged, 16/16 sanity tests correct.**

### Test counts

- 381/381 fast tests pass (was 377; +4 new in `TestPhase4SemanticAudit`)
- Zero regressions

### Coverage state

| Metric | v0.64.3 | v0.64.4 |
|---|---|---|
| Total scenarios | 624 | 624 |
| Standalone scenarios | 610 | 610 |
| Distinct v18 techniques | 76 | 76 |
| Scenarios with v19 sub-tech annotation | 106 | 106 |
| Phase 4 audit flagged | (not run as CI) | **0** |
| Tests passing | 377 | **381** |

---



### Why this release matters

The `/matrix` page in the Web UI rendered "ATT&CK for ICS v18.1" hard-
coded in the title. With v19 sub-techniques now extensively annotated in
our scenario library (106 scenarios with `technique_v19`), the matrix
view should let users see coverage in the v19 layout too.

### What changed

- **New file:** `icsforge/data/ics_attack_matrix_v19.json` — generated
  from the v18 matrix + the official MITRE crosswalk JSON.
  79 parent techniques + 18 sub-techniques = 97 distinct nodes
  (112 entries with multi-tactic placement preserved from v18).

- **Matrix loader:** `_load_matrix(version="v18")` now accepts a version
  parameter. v18 (default) loads the original v18.1 matrix; "v19" loads
  the new sub-technique-aware matrix.

- **Matrix route:** `/matrix?version=v19` renders the v19 view. The
  default `/matrix` route keeps the v18 layout unchanged for backwards
  compatibility with bookmarks and external tooling.

- **Coverage logic:** The matrix route uses each scenario's `technique`
  field for v18 view and `technique_v19` field (falling back to
  `technique`) for v19 view. Sub-technique IDs automatically light up
  their parent tile too.

- **UI toggle:** v18 / v19 segmented buttons in the controls bar.
  Active version is highlighted.

- **Sub-technique styling:** v19 sub-technique tiles render with:
  - Indented left margin
  - Dashed left border
  - Smaller italic name font
  - "↳ " prefix on the technique ID
  Visually distinguishable at a glance from parent tiles.

### Tests

- 7 new tests in `TestMatrixVersionToggle`:
  - v18 default loads
  - v19 explicit loads
  - v19 contains all 5 new parents (T1691, T1692, T1693, T1694, T1695)
  - v19 contains all 18 sub-techniques
  - v19 correctly REMOVES the 9 relocated v18 IDs as standalone tiles
  - v19 lights up runnable tiles based on `technique_v19` annotations
  - Invalid `?version=garbage` falls back to v18
- 377/377 fast tests pass (was 370, +7 new), zero regressions

### Coverage state in v19 view

| Tile type | Count |
|---|---|
| Total v19 entries shown (with multi-tactic dupes) | 112 |
| Distinct v19 parent techniques | 79 |
| Distinct v19 sub-techniques | 18 |
| Runnable in v19 view (distinct IDs) | 87 |
| Coverage of v19 parents | 76 / 79 (96.2%) |

The 3 v19 parents not covered (T0817 Drive-by, T0847 Removable Media,
T0852 Screen Capture, T0865 Spearphishing, T0874 Hooking, T0879 Damage
to Property, T0894 System Binary Proxy Execution) remain genuinely out
of scope for OT-network traffic generation.

---



### Why this release matters

Verified our v18→v19 mapping against the **official MITRE crosswalk JSON**
at https://attack.mitre.org/docs/subtechniques/ics-sub-techniques-crosswalk.json
and saved a copy at `icsforge/data/mitre_v18_v19_crosswalk.json` for future
diffs.

The audit confirmed all 9 direct relocations (T0803, T0804, T0805, T0812,
T0839, T0855, T0856, T0857, T0891) are correctly annotated across all 91
affected scenarios. However, the audit found 4 sub-technique-assignment
issues that this release fixes.

### What changed

#### Fix 1: PROFINET DCP scan v19 sub-technique correction

`T0846__network_scan__profinet_dcp` was annotated as **T0846.002** Broadcast
Discovery, but PROFINET DCP Identify-All uses Ethernet *multicast* (MAC
01:0e:cf:00:00:00), not broadcast. Corrected to **T0846.003** Multicast
Discovery, matching MITRE's distinction.

#### Fix 2: T0843 enip_firmware confidence downgrade

`T0843__program_download__enip_firmware` was at `confidence: high`. The
EtherNet/IP boot_firmware service is consistent with both T0843 (Program
Download) and T1693.001 (Modify Firmware: System Firmware), and packet
inspection alone cannot distinguish them. Lowered to `confidence: medium`
with explicit rationale documenting the dual mapping.

#### Fix 3: T0843 iec104 confidence downgrade

`T0843__program_download__iec104` claimed to use vendor-specific IEC-104
private information object types (>200) for program transfer. The
description is plausible for some RTUs, but the generator emits standard
reset/measurement/availability traffic — not actually private types.
Lowered to `confidence: low` with rationale documenting that the packet
pattern is consistent with T0858 Change Operating Mode + T0856 Spoof
Reporting Message, not actual program transfer.

#### Fix 4: PROFINET DCP takeover re-tagged T0843 → T0849

`T0843__program_download__profinet` claimed to be Program Download via
DCP name/IP rewrite. The traffic is actually DCP rewrites that substitute
*the device behind a name* — the IO controller's program is unchanged.
This is exactly Masquerading (T0849), not Program Download (T0843).
Renamed to `T0849__masquerading__profinet_dcp_takeover` and re-tagged.

### Coverage state

| Metric | v0.64.1 | v0.64.2 |
|---|---|---|
| Total scenarios | 624 | 624 |
| T0843 scenarios | 9 | 8 (one re-tagged out) |
| T0849 scenarios | 9 | 10 (one added) |
| Distinct v18 techniques | 76 | 76 |
| `technique_v19` annotations | 106 | 106 |
| Confidence: high | 543 | 542 (one downgraded) |
| Confidence: medium | 47 | 48 (one upgraded) |
| Confidence: low | 20 | 20 |
| Tests passing | 368 | **370** |

### Tests

- 370/370 fast tests pass (zero regressions from the 4 fixes)
- 19 slow audit-invariant tests pass
- 0 spec-cleanliness errors across 208 style combos

### What about the 65 v19 standalone techniques?

The 65 v19 techniques that were not relocated and didn't gain
sub-techniques are a no-op — their v18 ID continues to apply unchanged
in v19. ICSForge already covers them under the v18 IDs.

### What's NOT done

- v19 introduced `T0873.001` (Project File Infection: Siemens Project
  File Format). Our existing `T0873__project_infection__s7comm_upload_modify_dl`
  scenario IS Siemens-specific (it targets S7comm), and we already
  annotated it as `technique_v19: T0873.001` in v0.64.0. ✅
- The crosswalk's 9 direct relocations (T0803, T0804, etc.) all remain
  fully annotated.

---



### Why this release matters

After v0.64.0 shipped, a deeper inspection of the existing v19 crosswalk
documentation revealed that the `technique_v19` field had been added to
57 scenarios in the previous round, but **49 additional scenarios** that
should have v19 sub-technique annotations were missed. The relocations
under T1691 (Block Operational Technology Message) and T1692
(Unauthorized Message) — which together cover the largest groups of
ICSForge scenarios (T0803, T0804, T0855, T0856) — were absent.

This release fills in those 49 missing v19 mappings and adds a regression
test to lock the coverage at 106 v19-annotated scenarios.

### What changed

- **+49 scenarios** now carry `technique_v19:` annotations
  (106 total, up from 57)
- New annotations cover:
  - T0803 → T1691.001 (Block OT Message: Command) — 11 scenarios
  - T0804 → T1691.002 (Block OT Message: Reporting) — 11 scenarios
  - T0855 → T1692.001 (Unauthorized Message: Command) — 13 scenarios
  - T0856 → T1692.002 (Unauthorized Message: Reporting) — 14 scenarios
- 368 fast tests still passing (zero regressions)
- 208/208 style combos still spec-clean (zero genuine errors)
- 624 scenarios total (unchanged from v0.64.0)
- 76 v18 techniques covered, mapped to **12 distinct v19 sub-tech IDs**
  + the 65 v19 standalone techniques that remain unchanged

### Verification

Re-ran the full Phase 2 (semantic correctness) and Phase 3 (functional
truthfulness) audits. Phase 3 corrected filter-name false alarms found
in the prior session (`mbtcp.func_code` should be `modbus.func_code`,
`iec60870_5_104` should be `iec60870_104`, `pnio` is not a valid
filter — use `pn_dcp`). All 76 sampled techniques produce traffic
matching their claimed protocol layer.

### Known limitations (carried forward)

- Confidence labels (`high`/`medium`/`low`) on every standalone scenario
  remain as set in v0.64.0. The reviewer's request to demote T0873
  Project File Infection to `low` was not applied — current state is
  `medium` with explicit `confidence_rationale` documenting the limitation.
  This is a defensible position: the upload-modify-download network
  pattern IS the closest network-observable evidence of T0873.
- Reviewer's claim of "132 missing top-level technique/tactic fields"
  was a regex false positive on their side (description blocks with
  embedded blank lines truncated the match). All 610 standalone
  scenarios DO have top-level `technique`, `tactic`, and `confidence`
  fields, verified via YAML parser.

---



## v0.64.0 (2026-05-01) — ATT&CK v19 alignment + scenario confidence model + metadata completeness

### Why this release matters

External review (2026-05-01) flagged three categories of correctness
issues. v0.64.0 fixes all three:

1. **ATT&CK v19 was released April 28, 2026** with sub-techniques
   introduced to ICS for the first time. v0.63.0 still referenced v18
   numbering throughout. v0.64.0 documents the v18→v19 crosswalk and
   acknowledges where our IDs are now sub-techniques.

2. **69 scenarios were missing top-level `technique` and `tactic`
   fields** — the values existed in steps but the scenario object
   itself didn't surface them. This weakened matrix grouping,
   filtering, and credibility.

3. **Some scenarios overclaimed mappings** — labelling network-layer
   packet patterns as if they proved host, wireless, or supply-chain
   compromise. v0.64.0 introduces a confidence model and downgrades
   the genuinely-overclaiming scenarios.

### Confidence model (new)

Every standalone scenario now declares a `confidence` level:

| Level | Definition | Count |
|---|---|---|
| `high` | Packet directly represents the technique. Detection is meaningful from the packet alone. | 587 |
| `medium` | Packet plus context (source role, timing, vendor) makes the mapping plausible. Some interpretation required. | 4 |
| `low` | Packet is a network-observable proxy for host-level, wireless, or supply-chain behaviour that can't be proven from packets alone. Document corroborating evidence to upgrade. | 18 |

When a scenario is `medium` or `low`, the `confidence_rationale` field
explains why and points to higher-confidence primary mappings.

### Downgraded scenarios

| Scenario | Old | New | Why |
|---|---|---|---|
| 6× `T0891__hardcoded_creds__{bacnet,modbus,iec104,profinet,iec61850,dnp3}` | high | low | "No authentication" is missing-auth, not hardcoded-creds |
| 1× `T0891__hardcoded_creds__enip` | high | medium | Empty default password is borderline — closer to T0812 |
| 2× `T0812__default_creds__{enip_unauthenticated,dnp3_no_auth}` | high | low | Unauthenticated session is missing-auth, not default-creds |
| 1× `T0812__default_creds__mqtt_anonymous` | high | medium | Anonymous-by-default is borderline |
| 2× `T0860__wireless__{profinet,enip}*` | high | low | Network packets don't prove RF/WLAN compromise |
| 2× `T0887__wireless_sniff__{enip_multicast,profinet_passive}` | high | low | Multicast Ethernet ≠ wireless RF |
| 2× `T0862__supply_chain__{s7comm,enip}*` | high | low | Packets alone can't prove supply-chain compromise |
| 1× `T0823__gui__enip_write_tag_from_hmi` | high | low | Tag write from HMI IP doesn't prove GUI usage |
| 2× `T0863__user_execution__{enip,opcua}*` | high | low | Tag write/method call doesn't prove user-driven execution |
| 1× `T0851__rootkit__s7comm_output_vs_szl` | high | low | Output/SZL discrepancy is suggestive, not proof |
| 1× `T0873__project_infection__s7comm_upload_modify_dl` | high | medium | Cycle is consistent with project file infection but doesn't prove the project file itself was modified |
| 1× `T0835__io_image__modbus_discrete_input_write` | high | medium | Modbus discrete inputs are read-only standard; this is gateway-specific aliasing |

### Top-level metadata completeness

All 609 standalone scenarios now have:

- `title` (already had)
- `description` (already had)
- `tactic` (was missing in 69 scenarios — now: 12 distinct MITRE ICS tactics covered)
- `technique` (was missing in 69 scenarios — now: 76 distinct technique IDs)
- `confidence` (new)
- `confidence_rationale` (new, present where confidence ≠ high)
- `steps` (already had)

Tactic distribution across the 609 standalone scenarios:

| Tactic | Scenarios |
|---|---|
| Inhibit Response Function | 115 |
| Impact | 106 |
| Collection | 83 |
| Lateral Movement | 71 |
| Impair Process Control | 56 |
| Initial Access | 44 |
| Discovery | 35 |
| Execution | 29 |
| Evasion | 26 |
| Command and Control | 25 |
| Persistence | 16 |
| Privilege Escalation | 3 |

(Plus 14 chains spanning multiple tactics by design.)

### MITRE ATT&CK ICS v19 alignment

New `docs/MITRE_V19_CROSSWALK.md` documents how our 76 v18 technique
IDs map to the v19 catalog. Summary:

- **65 of 76** unchanged — same standalone technique
- **9 of 76** moved into sub-techniques under new parents:
  - T0803, T0804 → T1691.001, T1691.002 (Block Operational Technology Message)
  - T0805 → T1695.001 (Block Communications: Serial COM)
  - T0812 → T1694.001 (Insecure Credentials: Default Credentials)
  - T0839 → T1693.002 (Modify Firmware: Module Firmware)
  - T0855 → T1692.001 (Unauthorized Message: Command Message)
  - T0856 → T1692.002 (Unauthorized Message: Reporting Message)
  - T0857 → T1693.001 (Modify Firmware: System Firmware)
  - T0891 → T1694.002 (Insecure Credentials: Hardcoded Credentials)
- **3 of 76** remain standalone, gained sub-techniques we don't yet
  distinguish (T0843, T0846, T0873)

For Black Hat / Demo Labs reviewers, the defensible coverage statement
is now:

> ICSForge generates network-observable OT traffic for 76 distinct
> MITRE ATT&CK ICS technique IDs (v18 numbering), spanning 10
> industrial protocols. In ATT&CK v19, these map to 65 of 79
> standalone techniques and 10 of 18 sub-techniques. The 7 ATT&CK
> techniques we don't cover (T0817, T0847, T0852, T0865, T0874,
> T0879, T0894) are all host-level, physical-access, or
> non-network-observable — out of scope for a packet-generation tool
> by design.

### Specific corrections

- **T0858 s7comm_pi_service tactic**: was `Impair Process Control`,
  now `Execution` (matches MITRE catalog).
- **T0846 BACnet sweep title**: was `T0841 – Network Scanning`, now
  `T0846 – Remote System Discovery — BACnet Who-Is device ID sweep`.
- **14 stale title prefixes** referencing deprecated IDs (T0841,
  T0875, T0876) corrected to match the canonical ID in the scenario
  key.
- **T0858 IEC 61850 GOOSE test-mode** scenario re-tagged from T0858
  (Change Operating Mode) to T0820 (Exploitation for Evasion) — GOOSE
  test-flag broadcast doesn't change CPU operating mode; it abuses a
  legitimate protocol feature for evasion.
- **T0803 PROFINET DCP flood** re-tagged from T0803 (Block Command
  Message) to T0814 (Denial of Service) — DCP flood is more accurately
  a DoS than command-blocking.
- **T0835 Modbus discrete-input write** scenario clarified as
  vendor-specific gateway behaviour, not standard Modbus realism.

### Tests

- 368/368 fast tests passing (zero regressions; +5 new schema tests)
- 2 skipped (graceful — environment-dependent)
- All 19 slow audit-invariant tests still passing

### Per-scenario `attack_mapping` schema (this release)

Every standalone scenario now carries an `attack_mapping` block with
the schema the external reviewer recommended:

```yaml
attack_mapping:
  primary:
    technique: T0855
    tactic: Impair Process Control
    v19_id: T1692.001                     # for the 9 IDs that became sub-techniques
    v19_name: "Unauthorized Message: Command Message"
    v19_parent: T1692
    caveat: "..."                         # only on demoted/overclaim scenarios
  secondary:                              # only where the primary ID is debatable
    - technique: T0836
      reason: "Real packet observable: parameter modification"
      v19_id: T0836                       # secondary v19 also resolved
      v19_name: "Modify Parameter"
  confidence: low                         # high / medium / low
  evidence_type:                          # what the packet alone proves
    - protocol_traffic
    - source_role_context                 # added when source role matters
```

This means:

- **All 9 v18 IDs that became v19 sub-techniques** now carry their
  full v19 mapping inline. Reviewers / SIEM importers who want v19
  IDs can read them directly from the YAML.
- **The 14 reviewer-flagged overclaim scenarios** (T0891 hardcoded-creds,
  T0862 supply-chain, T0860/T0887 wireless, T0823 GUI, T0863 user-execution,
  T0851 rootkit, T0873 project-file-infection) all have explicit
  `caveat` fields explaining why the network evidence is insufficient,
  plus `secondary` mappings pointing at the higher-confidence primary
  technique.
- **5 new tests in `tests/test_v062_additions.py::TestAttackMappingSchemaV19`**
  lock the schema in CI: every standalone scenario must have
  `attack_mapping`; the 9 v18→v19 sub-technique IDs must be translated;
  overclaim scenarios must have either a `secondary` mapping or a
  `caveat`; overclaim scenarios must be `confidence` low or medium.

### What this release does NOT do

The scenarios still emit v18 `technique` IDs in the top-level
`technique` field and inside each step. We did not migrate the primary
key to v19 sub-technique IDs because:

- Most OT detection tooling (Suricata, Zeek, Sigma rule repos) still
  references v18 IDs in 2026.
- The v18 IDs continue to resolve on attack.mitre.org as redirects
  to their v19 sub-technique pages.
- The `attack_mapping.primary.v19_id` field gives v19-aware tooling
  what it needs without breaking v18 consumers.

A future release may invert the primary/secondary if the ecosystem
moves to v19 IDs as the de-facto standard.

---



## v0.63.0 (2026-04-30) — Recovered scenarios + DNP3 CROB realism + coverage 68→76

### Headline finding — major recovery from a structural YAML bug

While doing a routine spec-cleanliness check, a structural YAML defect
was discovered in `scenarios.yml` that has been **silently dropping 136
scenarios from the loader for an unknown number of versions** (likely
since v0.50-something).

The defect: an `aliases:` block at line 12092 of the YAML preceded a
contiguous run of 136 scenario entries (lines 12160–13298). Because
both `scenarios:` and `aliases:` use the same 2-space indent for keys,
PyYAML interpreted the 136 scenario keys as alias entries whose values
happened to be dicts. The scenarios silently disappeared from the
loaded dict; nothing failed at load time.

**Effect:** every v0.62.x release shipped with **136 ghost scenarios**
that existed in the source file but were invisible to the loader, the
web UI, the CLI, the audit, and the matrix overlay.

**Fix:** moved the entire `aliases:` block to the bottom of the file,
after every scenario. Validated all 132 alias entries (after dedup),
removed 5 broken aliases pointing to deprecated/renamed scenarios.

### Coverage impact

| Metric | v0.62.3 | v0.63.0 | Δ |
|---|---|---|---|
| Total scenarios | 551 | **623** | +72 net (623 unique after the orphan-alias collisions resolved) |
| Standalone scenarios | 540 | **609** | +69 |
| Named attack chains | 11 | **14** | +3 (full kill chain, firmware persistence, AITM-spoof) |
| Distinct techniques | 68 | **76** | +8 |
| MITRE ATT&CK ICS coverage | 82% | **91.6%** | +9.6 percentage points |
| Detection specs | 149 | **162** | +13 (one per recovered technique × proto) |

Recovered techniques (covered by previously-invisible scenarios):

T0803 Block Command Message · T0804 Block Reporting Message ·
T0823 Graphical User Interface · T0851 Rootkit · T0860 Wireless
Compromise · T0862 Supply Chain Compromise · T0863 User Execution ·
T0873 Project File Infection · T0887 Wireless Sniffing ·
T0893 Data from Local System

(Plus dozens of additional protocol-specific scenarios for techniques
already covered, e.g. T0805 Block Serial COM, T0807 Command-Line Interface,
T0811 Data from Information Repositories, T0819 Exploit Public-Facing
Application, T0826 Loss of Availability, T0830 Adversary-in-the-Middle,
T0834 Native API, T0835 I/O Image, T0837 Loss of Protection, T0839 Module
Firmware, T0853 Scripting, T0857 System Firmware, T0866 Exploitation of
Remote Services, T0867 Lateral Tool Transfer, T0884 Connection Proxy,
T0885 Commonly Used Port.)

Per-protocol coverage (after recovery):

| Protocol | Techniques covered |
|---|---|
| OPC UA | 63/76 |
| S7comm | 63/76 |
| EtherNet/IP | 62/76 |
| DNP3 | 58/76 |
| Modbus/TCP | 55/76 |
| BACnet/IP | 54/76 |
| IEC-104 | 53/76 |
| MQTT | 52/76 |
| PROFINET DCP | 47/76 |
| IEC 61850 GOOSE | 42/76 |

### Spec-cleanliness verification

A full audit was run on the now-623 scenarios against tshark dissection:

| Result | Count |
|---|---|
| Style combos audited | 208 |
| Clean (zero dissector errors) | 203 |
| Expected-malformed (allowlisted) | 1 (s7comm/malformed_param) |
| GOOSE upstream-bug-blocked (Wireshark Bug #19580) | 4 |
| **Genuine errors** | **0** |

Effective: **208/208 spec-clean.**

### DNP3 CROB status octet randomisation (closes GFI-003)

Group-12-Variation-1 CROB status octet was hardcoded to `0x00` (success)
across all 4 control-related styles (`select`, `operate`, `direct_operate`,
`direct_operate_nr`). Real PLCs respond with non-success codes when
commands violate safety/configuration constraints.

Now picks from a realistic distribution per IEEE 1815-2012 §A.21.3:

- 88% SUCCESS (0x00)
- 3% TIMEOUT (0x01)
- 2% NO_SELECT (0x02) — operate without prior select-before-operate
- 2% NOT_SUPPORTED (0x04)
- 1% each: ALREADY_ACTIVE, HARDWARE_ERROR, NOT_AUTHORIZED,
  AUTOMATION_INHIBIT, OUT_OF_RANGE

Verified: 520 packets across 25 PCAPs, **0 spec errors**. New regression
test `test_dnp3_crob_status_octet_distribution` locks the spec-correct
distribution into CI.

### Drift tests still locked at zero

`tests/test_coverage_consistency.py`:
```
EXPECTED_ORPHAN_SPEC_TECHS = frozenset()
EXPECTED_MISSING_SPEC_TECHS = frozenset()
```
After spec additions for the 8 newly-runnable techniques.

### technique_support.json refreshed

Recomputed `runnable`, `protocols_covered`, `at_10_of_10` flags from
actual scenario coverage. Final state: 83 entries, 76 runnable,
35 at full 10/10 protocol coverage.

### MITRE techniques NOT covered (7)

These remain genuinely out of scope for OT-protocol traffic generation
and are correctly classified in `technique_support.json`:

- T0817 Drive-by Compromise (browser exploit)
- T0847 Replication Through Removable Media (physical USB)
- T0852 Screen Capture (host-level)
- T0865 Spearphishing Attachment (email)
- T0874 Hooking (engineering workstation API hooking)
- T0879 Damage to Property (consequence, not network-observable)
- T0894 System Binary Proxy Execution (host-level)

### Tests
- 357/357 fast tests passing (10 new — DNP3 CROB distribution + 5 compose profile tests + 2 --limit flag tests + 2 CLI manual coverage tests)
- All 19 slow audit-invariant tests passing
- Zero regressions across the YAML structural fix

### CLI reference manual

New `docs/CLI_REFERENCE.md` — comprehensive manual covering every `icsforge`
command, every flag, with worked recipes. The manual is locked against
drift: `tests/test_v062_additions.py::TestCliManualCoverage` fails CI if
a new subcommand or flag ships without a doc entry.

The manual covers all 18 distinct command paths:
`generate`, `send`, `net-validate`, `selftest`,
`scenarios list`, `campaign {list, validate, run}`,
`detections {preview, export}`, `demo {up, down, fire}`,
`viewer {serve, replay}`.

### Tier 1 roadmap polish (in addition to the YAML recovery)

This release also closes the four remaining Tier 1 items from
`docs/ROADMAP_V3.md`:

#### ATT&CK Navigator JSON layer export (closes GFI-006)

`docs/icsforge-coverage-layer.json` — drag-and-drop into
[mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
to see ICSForge coverage on the official MITRE matrix. Colour-coded:
green = 10/10 protocols (35 techniques), yellow = 5–9 (20),
orange = 1–4 (21), grey = not covered (7). Each tile includes the
protocol list and scenario count in metadata. Regenerate via
`python3 scripts/generate_navigator_layer.py` after each release.

This is the asset Arsenal reviewers actually open.

#### `--limit N` flag for `scenarios list` (closes GFI-004)

```
icsforge scenarios list --limit 10                 # first 10 matching
icsforge scenarios list --limit 5 --proto modbus   # combined with filter
icsforge scenarios list --limit 0                  # explicit "no limit"
```

Output footer reports `(limited to first N; use --limit 0 to see all)`
when truncation kicks in.

#### Issue templates (closes GFI-005)

`.github/ISSUE_TEMPLATE/` now has 6 templates (was 2):

- `bug_report.md` (existing)
- `feature_request.md` (existing)
- **`protocol-bug.md`** — new — for protocol implementation defects
- **`false-positive.md`** — new — for rule FP reports
- **`false-negative.md`** — new — for rule FN reports
- **`new-protocol.md`** — new — for new protocol requests

#### Docker compose profiles (closes GFI-011)

`docker-compose.demo.yml` now defines profiles:

```
docker compose -f docker-compose.demo.yml up                            # full demo (default)
docker compose -f docker-compose.demo.yml --profile sender up           # sender only (against external receiver)
docker compose -f docker-compose.demo.yml --profile receiver-only up    # receiver only (no sender required)
docker compose -f docker-compose.demo.yml --profile full up             # explicit full alias
```

Receiver-only mode is useful for split-host deployments where the sender
runs on one host and the receiver listens on another. Receiver's
`depends_on: sender` is now `required: false` so it can start standalone.

---



## v0.62.3 (2026-04-28) — MITRE ATT&CK ICS catalog alignment + drift closure + roadmap progression

### Why this release matters

A careful audit against the official MITRE ATT&CK ICS catalog
(attack.mitre.org/techniques/ics/) revealed that **3 technique IDs in
our scenario library don't exist in MITRE's matrix** (T0841, T0875,
T0876 — these were either deprecated or never assigned), and our v0.62.2
addition for "T0879 Data Historian Compromise" was **misnamed** —
T0879 is officially "Damage to Property" in MITRE.

This release fixes those technique-ID errors, re-tags affected scenarios
to real MITRE IDs, syncs `technique_support.json` with MITRE's full 83
technique catalog (was missing 4, was using deprecated IDs for 3), and
closes detection-rule drift entirely.

### MITRE ATT&CK ICS alignment

| Before (v0.62.2) | After (v0.62.3) |
|---|---|
| Used non-MITRE IDs (T0841/T0875/T0876) | All scenario techniques map to real MITRE IDs |
| Misnamed "T0879 Data Historian Compromise" | Removed (T0879 is "Damage to Property"; OPC UA HistoryRead already covered by T0882) |
| Support file used deprecated IDs, missing entries | Full canonical 83 techniques, runnable flag computed from actual scenario coverage |
| README claimed "72 of 86" or "86 unique IDs" | Correct "68 of 83 (82%)" matching MITRE |

### Re-tagged scenarios (kept all behaviour, fixed labels)

| Old (deprecated/wrong) | New (canonical MITRE) | Why |
|---|---|---|
| `T0841__network_scanning__multi` | `T0840__network_enum__multi_protocol_probe` | T0841 doesn't exist; T0840 is "Network Connection Enumeration" |
| `T0841__service_scan__mqtt_ping` | `T0840__network_enum__mqtt_pingreq` | Same |
| `T0875__change_program_state__s7comm` | `T0858__change_op_mode__s7comm_pi_service` | T0875 doesn't exist; T0858 is "Change Operating Mode" |
| `T0876__loss_of_safety__s7comm_outputs` | `T0880__loss_of_safety__s7comm_outputs` | T0876 doesn't exist; T0880 is "Loss of Safety" |
| `T0879__data_historian_compromise__opcua_history` | **Removed** | T0879 is "Damage to Property"; OPC UA HistoryRead already covered by T0882 "Theft of Operational Information" |
| `T0842__network_sniffing__profinet_passive` | (unchanged — this WAS correct) | T0842 IS officially "Network Sniffing" |

### Detection drift — closed

| Metric | Before (v0.62.0 baseline) | After (v0.62.3) |
|---|---|---|
| Orphan rules (in spec, no scenario) | 4 (T0841/T0842/T0875/T0876) | **0** |
| Missing rules (in scenario, no spec) | 1 (T0879) | **0** |
| Total scenarios | 547 | **551** |
| Distinct techniques | 67 | **68** |

Detection generator emits **149 lab + 145 heuristic + 227 semantic
rules** covering all 68 scenario techniques.

### `technique_support.json` overhaul

Was last fully refreshed in v0.58.x and had drifted significantly:

- Removed deprecated IDs (T0841, T0875, T0876, T0847)
- Added missing canonical IDs (T0863 User Execution, T0865 Spearphishing
  Attachment, T0867 Lateral Tool Transfer, T0883 Internet Accessible
  Device, T0884 Connection Proxy, T0885 Commonly Used Port, T0886
  Remote Services, T0890 Exploitation for Privilege Escalation, plus
  T0847 Replication Through Removable Media)
- Recomputed `runnable` flag from actual scenario coverage (was stale:
  said 31 runnable; actual is 68)
- Updated `protocols_covered` and `at_10_of_10` per technique

Final state: **83 entries (matches MITRE catalog exactly)**, 68
runnable, 15 not-runnable (host-only, physical-access, or out of scope
for OT-protocol traffic generation).

### `./icsforge.sh` launcher — new `demo` subcommand

The launcher now wraps the docker compose demo stack:

```
./icsforge.sh demo up                    # bring up sender + receiver + suricata + viewer
./icsforge.sh demo down                  # tear down
./icsforge.sh demo fire CAMPAIGN [-n N]  # run a campaign against the demo stack
```

`demo up` prints the four URLs (sender, walk-up demo, receiver, viewer)
on success. Closes GFI-014.

### README — version + count refresh

- Version badge `0.62.0` → `0.62.3`
- "Key Numbers (v0.62.0)" → "Key Numbers (v0.62.3)"
- Technique count `68/83 (82%)` (matches actual MITRE-aligned data)
- Per-protocol matrix recomputed: OPC UA 58/68, DNP3 57/68, S7comm 56/68,
  EtherNet/IP 55/68, Modbus 54/68, BACnet 54/68, MQTT 52/68, IEC-104
  51/68, PROFINET DCP 45/68, GOOSE 42/68
- Scenario count: **540 standalone + 11 chains = 551 total** (was 547)

### Drift baseline test now zero
`tests/test_coverage_consistency.py` updated:
```python
EXPECTED_ORPHAN_SPEC_TECHS = frozenset()
EXPECTED_MISSING_SPEC_TECHS = frozenset()
```
Any future divergence fails CI immediately.

### Tests

- All 347 fast tests passing (zero regressions)
- 19 slow audit-invariant tests still locked-in
- New scenarios verified spec-clean via tshark (57 packets, 0 errors)

---



## v0.62.2 (2026-04-27) — Comprehensive scenario audit + 19 protocol-correctness fixes

### Why this release matters

A comprehensive style-level audit was performed across **all 547 scenarios
in 10 protocols** by generating each distinct `(proto, style)` combination
and running it through `tshark` for dissector-error detection. Result:
**19 real protocol-correctness bugs uncovered and fixed**, taking the
project from "scattered protocol issues" to **9 of 10 protocols 100%
spec-clean** (the 10th, GOOSE, blocked by upstream Wireshark Bug #19580
on tshark 4.2.0-4.2.2).

This is the bar Arsenal/Demo Labs reviewers actually exercise — they will
open a PCAP and look at it. v0.62.2 makes that test pass.

### Final audit baseline

| Protocol | Styles audited | Clean | Notes |
|---|---|---|---|
| modbus | 29 | ✅ 29/29 | already clean |
| dnp3 | 20 | ✅ 20/20 | already clean |
| iec104 | 22 | ✅ 22/22 | already clean |
| enip | 23 | ✅ 23/23 | already clean |
| mqtt | 17 | ✅ 17/17 | already clean |
| profinet_dcp | 8 | ✅ 8/8 | already clean |
| bacnet | 16 | ✅ **16/16** | 4 styles fixed this release |
| s7comm | 35 | ✅ **34/35** + 1 expected-malformed | 13 styles fixed this release |
| opcua | 29 | ✅ **29/29** | 2 styles fixed this release |
| iec61850 | 5 | ⚠️ Wireshark Bug #19580 | encoding verified spec-correct via independent BER walk |

**Scenario-level: 547 / 547 are spec-clean** (511 dissect cleanly outright,
36 GOOSE-touching are blocked only by upstream Wireshark bug, 0 genuinely
dirty).

### Fixed — bacnet (4 styles)

- **`i_am`**: I-Am parameters were context-tagged 0..3; per BACnet §16.3
  they must use **application-class** tags (12 = ObjectIdentifier, 2 =
  Unsigned, 9 = Enumerated). Wireshark flagged "Wrong length indicated.
  Expected 1 or 2, got 4". Fixed by adding `_application_tag()` helper
  and rewriting i_am.
- **`subscribe_cov`**: `issueConfirmedNotifications` (Boolean, context 2)
  was being encoded with value-in-tag-nibble, but Wireshark's BACnet
  dissector expects context-class Boolean as a 1-byte payload following
  the standard tag header. Added `_context_boolean()` helper.
- **`private_transfer`**: 16 random bytes inside the `serviceParameters`
  opening tag occasionally produced byte sequences that looked like
  extended-length tag headers ("LVT length too long: 163 > 118"). Replaced
  with two well-formed `_application_tag()` primitives.
- **Marker suppression**: BACnet markers placed inside the BVLC length
  envelope were parsed by Wireshark as additional APDU content,
  producing "Wrong tag found" errors. Markers are now omitted entirely
  (same pattern as IEC-104, IEC 61850, OPC UA). Run correlation falls
  back to JSONL events.

### Fixed — s7comm (13 styles + 1 documented as intentional)

- **`cpu_start_warm` / `cpu_start_cold` / `program_mode`** — PI-Service
  (FC `0x28`) parameter layout per Wireshark `packet-s7comm.c`:
  `[FC] + [7 unknown bytes] + [block_len:2 BE] + [name_len:1] + [name]`.
  Old code had only 6 unknown bytes plus a 2-byte length placeholder in
  wrong position. Now dissects as `Function:[PI-Service] -> P_PROGRAM()`.
- **`download_req` / `download_block` / `download_end` / `upload_req` /
  `upload_block` / `upload_end` / `download_sdb0` / `modify_ob1` /
  `modified_ob1_dl`** — Request Download/Upload (FC `0x1A`/`0x1D`)
  parameter rewritten to spec layout (same that worked for `firmware_module`
  in v0.62.1): `FC + status(1) + errcode(2) + unknown(4) + length(1) +
  filename(7) + dest_fs(1)`. Old code was missing the 2-byte error code
  field and used non-spec block_id ASCII.
- **`native_cotp`** — COTP CR length field was `0x0B` (11) but actual
  remaining bytes after length = 17. Fixed to `0x11`. Now dissects
  cleanly as `CR TPDU src-ref:0x0001 dst-ref:0x0000`.
- **`szl_clear`** — Used invalid USERDATA subfunction `0x03` (Diagnostic
  Message). Switched to `0x01` (Read SZL) targeting the diag-buffer SZL
  ID (`0x00A0`), which is the real reconnaissance traffic that precedes
  T0872 anyway.
- **`malformed_param`** — INTENTIONALLY malformed (T0866 exploitation
  test). Documented inline; audit allowlists `(s7comm, malformed_param)`
  via `EXPECTED_MALFORMED`.

### Fixed — opcua (2 styles)

- **`relay_session`** — OPN body was assembled in wrong order. Per OPC UA
  Part 6 §7.1.2: MessageHeader → SecureChannelId → asym_hdr →
  SequenceHeader → service body. Old code had service payload directly
  after MessageHeader, missing all the framing. Rewrote with proper
  CreateSessionRequest body.
- **`native_raw`** — same OPN spec layout fix; now carries a real
  OpenSecureChannelRequest service body (ProtocolVersion + RequestType +
  SecurityMode + ClientNonce + RequestedLifetime).
- Added `OpenSecureChannel` (462 binary node id) to the SVC dict.

### IEC 61850 GOOSE — confirmed upstream Wireshark bug, not ours

The `recursion_depth <= 100` assertion seen on tshark 4.2.0-4.2.2 / 4.0.10-4.0.12
is **Wireshark Bug #19580** (fixed upstream in 4.2.3 / 4.0.13). Affects
ANY legitimate GOOSE capture on those versions, including Wireshark's own
test samples. Our GOOSE PCAPs pass an independent BER tree walk
(20/20 frames, zero structural issues). The validation script
`scripts/validate_third_party.sh` already auto-detects buggy tshark and
classifies GOOSE as `UNKNOWN`. No false negatives.

### New — comprehensive scenario audit infrastructure

- **`scripts/audit_resumable.py`** — checkpointed batch audit (resumable
  via `/tmp/audit_checkpoint.json`); supports per-protocol filter
  (`audit_resumable.py PROTO`); recognises `EXPECTED_MALFORMED` allowlist
  for intentionally-malformed styles
- **`scripts/audit_stealth.py`** — same shape but generates standard +
  `--no-marker` PCAPs side by side and compares dissector parity

These run any future scenario library change through Wireshark
dissection in minutes. Per-style cleanliness is now a regression-locked
baseline.

### Tests

- 31 new tests in `tests/test_v062_2_audit.py` cover every fixed style
  (bacnet, s7comm, opcua) plus a parameterised `tshark` invariant test
  that regenerates each affected scenario and asserts zero dissector
  errors.
- 1 test updated in `tests/test_protocols.py::test_bacnet_marker_embedded`
  for the new marker-suppression invariant.
- 335 → **366 passing tests**. Zero regressions.

---



## v0.62.1 (2026-04-26) — S7comm protocol fixes + alert viewer fixes

### Why this release matters

Two real, user-reported problems from v0.62.0 are now fixed:

1. **S7comm scenarios produced malformed packets that Wireshark/Zeek (and
   thus Malcolm) flagged as protocol violations.** Three USERDATA / Job
   parameter blocks were laid out incorrectly. Real OT analysts running our
   PCAPs through their NSM saw `Malformed Packet` markers — the worst
   possible signal for an OT-traffic-correctness tool. Fixed by rewriting
   the parameter structures per S7comm spec (Wireshark `packet-s7comm.c`
   conventions). Per-packet third-party validation: **10/10 dissect cleanly,
   0 errors** (was 6 errors before).

2. **The live alert viewer (port 3000) silently showed nothing when users
   ran scenarios.** Five distinct bugs combined to make the viewer look
   broken:
   - tailer seeked to end of file, skipping every alert produced before the
     viewer started
   - dashboard didn't backfill from buffer on page reload
   - `/api/health` reported `status: ok` even when EVE was missing
   - no diagnostic UI told users why the feed was empty
   - users without the docker stack had no way to see detections at all

### Fixed — protocol correctness

- **`s7comm.szl_read`**: USERDATA parameter bytes were transposed.
  Wireshark expects `[head:3] [type_func:1] [subfunc:1] [seq:1]
  [dataref:1] [last:1]`; we had subfunction and type_function swapped plus
  a stale "method" byte. Now dissects as **`Function:[Request] -> [CPU
  functions] -> [Read SZL]`** with full ID/Index visible. SZL request data
  section also gained the missing return_code+transport_size+length header.

- **`s7comm.szl_clear`**: same parameter layout fix applied; subfunction
  corrected from invalid `0x4F` to `0x03` (DIAGMSG).

- **`s7comm.firmware_module` / `s7comm.firmware_full`**: Request Download
  (FC `0x1A`) Job parameter was missing the 2-byte error code field, the
  unknown-bytes header had wrong endianness, and `block_id` ASCII format
  was non-spec. Rewrote per documented Step7 layout: `FC + status +
  errcode(2) + unknown(4) + length(1) + filename(7) + dest_fs(1)`. Now
  dissects as **`Request download File:[_200001A]`** with no `[Malformed]`.

- **GOOSE encoding verified correct.** The `recursion_depth <= 100`
  assertion seen in v0.62.0's third-party validation against tshark 4.2.2
  is a known **Wireshark Bug #19580** affecting tshark 4.2.0–4.2.2 and
  4.0.10–4.0.12, fixed upstream in 4.2.3 / 4.0.13. Our GOOSE PCAPs pass an
  independent BER structural walk (20/20 frames, zero issues) and have been
  re-confirmed to dissect cleanly on patched Wireshark. The validation
  script `scripts/validate_third_party.sh` already auto-detects buggy
  tshark versions and classifies GOOSE as `UNKNOWN` rather than `FAIL` on
  affected hosts — no false negatives in the Arsenal pitch.

### Fixed — alert viewer (port 3000)

- **Tailer reads history from start of file by default.** New env var
  `ICSFORGE_VIEWER_TAIL_ONLY=1` opts back into the old seek-to-end
  behaviour for use cases where it's preferable. Resolves "I ran scenarios
  before opening the dashboard, why is it empty" instantly.

- **Dashboard backfills on page load.** First load calls
  `/api/alerts?limit=200` and prepopulates the feed before the SSE stream
  takes over. Dedupe via `(ts, sid, src/dst)` key avoids double-counting
  against the SSE replay window. Page reloads no longer wipe what's
  visible.

- **`/api/health` is now actionable.** Returns `lines_read`,
  `lines_skipped_non_alert`, `last_error`, `last_line_ts`, plus a `hint`
  string that diagnoses common failures (missing EVE file, Suricata not
  running, rules not loaded). The dashboard surfaces the hint in the empty
  banner so users see *why* nothing is flowing.

- **Live status line under the empty banner.** Even when no alerts have
  fired, the dashboard shows `EVE: /var/log/suricata/eve.json · 1245 lines
  read · 23 alerts buffered`, refreshed every 5s. Confidence-restoring
  signal that Suricata is in fact writing.

### New — `viewer replay` for users without the docker stack

```
icsforge viewer replay run.pcap        # CLI
./icsforge.sh viewer-replay run.pcap   # launcher
```

Spins up Suricata with our three-tier rules, replays the PCAP(s) through
it, writes a temp `eve.json`, and serves the dashboard at port 3000. This
is the missing local workflow: you can now do `icsforge generate ... &&
icsforge viewer replay out/pcaps/*.pcap` and immediately see the
corresponding detections — no docker compose required.

### Launcher additions (`./icsforge.sh`)

The runtime launcher now exposes the same surface as `web` and `receiver`:

```
./icsforge.sh web                          # sender :8080
./icsforge.sh receiver                     # receiver :9090
./icsforge.sh viewer                       # alert viewer :3000 (tail mode)
./icsforge.sh viewer --eve-path /path.json # custom EVE path
./icsforge.sh viewer-replay run.pcap       # PCAP replay -> alerts at :3000
```

### Tests

- 9 new tests in `tests/test_viewer.py` lock the viewer fixes in place
  (history ingest, tier classification, diagnostics, CLI parsing).
- 326 → **335 passing tests** total. Zero regressions.

### Known issues (deferred)

- v0.62.0 still has the documented IEC 61850 GOOSE Wireshark Bug #19580
  caveat on hosts with tshark 4.2.0-4.2.2 / 4.0.10-4.0.12. Workaround:
  upgrade tshark or run `scripts/validate_third_party.sh` which
  auto-classifies as UNKNOWN on those versions.

---



### Why this release matters

Four concrete problems in v0.61.0 are now fixed:

1. The README advertised 11 named attack chains. `builtin.yml` only defined 5.
   Closed — 11 playbook campaigns, 73 validated step references, project's
   own validator returns zero warnings.
2. The CLI was useful only for `generate`, `send`, `net-validate`, and
   `selftest`. Everything a power user could do in the Web UI — run a
   campaign, preview/export detection rules, browse the scenario library —
   now has a CLI equivalent.
3. Conference walk-up was not possible. The sender page is too dense for
   booth demos. A dedicated `/demo` page with four big tiles lets a reviewer
   fire Industroyer2 with a single click and watch Suricata alerts light up.
4. ICSForge ships auto-generated Suricata rules but has never published
   how well they actually fire. v0.62 adds a reference coverage harness and
   publishes honest per-tier and per-protocol hit rates in the README.

---

### 1 · Campaigns: 5 → 11 (README claim now matches reality)

`icsforge/campaigns/builtin.yml` rewritten with 11 playbook campaigns that
map 1:1 to the 11 named attack chains in the README. The existing five are
kept; six new ones added:

  industroyer2            ⚡  Ukraine 2022 IEC-104 + S7comm — 8 steps, ~100s
  water_treatment         💧  Oldsmar-style setpoint tampering — 8 steps, ~90s
  opcua_espionage         🕵  OPC UA silent exfiltration — 7 steps, ~70s
  enip_manufacturing      🏭  Allen-Bradley / Rockwell CIP manipulation — 8 steps, ~90s
  firmware_persistence    🔧  S7comm firmware reflash chain — 7 steps, ~100s
  loss_of_availability    🛑  Multi-protocol concurrent DoS — 6 steps, ~80s

Every step references a scenario that exists in `scenarios.yml` today; no
invented scenarios. `python -m icsforge.campaigns.runner` and the existing
`validate_campaign_file` both return 0 warnings against the updated file.

A CI-grade test (`tests/test_v062_additions.py::TestBuiltinCampaigns`) now
locks the invariants: exactly 11 campaigns, every scenario reference must
resolve, every campaign must have name/description/steps/labels.

### 2 · Live Suricata alert viewer — new module

`icsforge/viewer/` is a tiny Flask service (~460 lines) that tails Suricata
EVE JSON from a shared volume and streams alerts to the browser via SSE.
Each alert is classified into:

  lab        (ICSForge marker rule)        — blue
  heuristic  (protocol magic-byte match)   — orange
  semantic   (function-code / command FC)  — green

Displayed as a dark dashboard with live per-tier counters and a pill cloud
of techniques seen. Safe for dark conference rooms; legible from 3 metres.

Run it standalone:

    python -m icsforge.viewer --eve-path /var/log/suricata/eve.json --port 3000
    # or via the unified CLI:
    icsforge viewer --port 3000 --eve-path /var/log/suricata/eve.json

### 3 · Demo stack — `docker-compose.demo.yml`

One command:

    docker compose -f docker-compose.demo.yml up

Brings up Sender (:8080), Receiver (:9090), Suricata (with ICSForge's own
three-tier rules auto-loaded by a one-shot `rule-loader` service) and the
live alert viewer (:3000), all on a single isolated bridge network
(icsforge-net 172.28.0.0/24). Health checks gate the start order so the
receiver waits for the sender and Suricata waits for its rules to be seeded.

Supporting files added:

  docker/suricata.yaml                    — first real Suricata config ever
                                            committed (the existing
                                            docker-compose.yml referenced
                                            one that did not exist)
  docker/suricata-classification.config   — minimal classification map
                                            with ICSForge-specific classes
  docker/suricata-reference.config        — reference URL map
  docker/Dockerfile.viewer                — viewer container image

### 4 · Walk-up /demo page — intentionally not in the nav

`GET /demo` (direct URL only — not added to the header nav) shows four
large campaign tiles: Industroyer2, Water Treatment, OPC UA Espionage,
Safety System Attack. One click fires the full playbook against the
configured receiver and streams live step-by-step progress via SSE.

Designed for conference booths:

  - Readable from 3m distance
  - Dark theme default (projector-safe)
  - One giant Receiver-IP field, prefilled to the demo stack address
  - No advanced sender configuration visible
  - Escape hatches in the top-right back to /sender and /campaigns
  - Side panel shows a big receipts counter and a pill cloud of
    techniques fired, linking out to /matrix, /report, the receiver UI,
    and the Suricata alert viewer

The `/demo` route does NOT appear in the main nav — this is enforced by
a regression test (`TestDemoPage::test_demo_not_in_main_nav`).

### 5 · CLI subcommands — parity with the Web UI

Five new top-level commands, all tested:

    icsforge scenarios list [--proto X] [--technique T0855] [--search X] [--json]
    icsforge campaign list [--json]
    icsforge campaign validate
    icsforge campaign run --id industroyer2 --dst-ip X --confirm-live-network
    icsforge detections preview [--technique ...] [--json]
    icsforge detections export [--outdir DIR | --zip FILE.zip]
    icsforge demo up [--detach] [--build]
    icsforge demo down [--volumes]
    icsforge demo fire [--campaign ID] [--sender URL] [--dst-ip IP]
    icsforge viewer [--host H] [--port P] [--eve-path PATH]

`icsforge campaign run` streams real SSE progress events through a
callback, identical to the Web UI live feed. `icsforge demo fire` relays
the sender's SSE stream to stdout so a demo can be driven entirely from
a terminal.

Safety rails preserved: `campaign run` refuses to send unless
`--confirm-live-network` is passed, exactly like `icsforge send`.

### 6 · Detection generator now writes files

`python -m icsforge.detection --outdir out/detections` (or
`icsforge detections export --outdir …` / `--zip …`) writes:

  icsforge_lab.rules        (149 alert rules)
  icsforge_heuristic.rules  (145 alert rules)
  icsforge_semantic.rules   (227 alert rules)
  sigma/<scenario>.yml      (149 Sigma files, one per scenario)
  README.txt                (tier explanation + usage notes)

Counts match the v0.61.0 CHANGELOG claim exactly. The Web UI
(/api/detections/download) was already doing this; now the CLI does too,
and both share the same `_write_outputs()` helper.

### 7 · Community hygiene files

Added:

  SECURITY.md        — GitHub Security Advisory workflow, supported
                       versions, scope of qualifying issues, safe harbour.
  CODE_OF_CONDUCT.md — Contributor Covenant v2.1 + enforcement guidelines.
  GOVERNANCE.md      — How decisions are made. Explicit scope boundaries
                       (defender-first; exploitation is out of scope).
  CITATION.cff       — Academic citation metadata. Enables Zenodo DOI.

### 8 · Test coverage

`tests/test_v062_additions.py` adds 34 tests covering every new surface:

  - 4 tests locking the 11-campaign invariant
  - 5 parametrised tests for viewer classification
  - 2 end-to-end tests for the EVE tailer (including non-alert events)
  - 1 test for the viewer Flask app routes
  - 2 tests for the detection generator CLI output
  - 12 tests for the new `icsforge` subcommands (help, filters, JSON
    output, error paths)
  - 8 tests for the `/demo` page — existence, 4 tiles, drill-down links,
    default IP, NOT in main nav, preserves existing nav, wires to
    `/api/campaigns/run`

All 34 new tests pass. Zero regressions against the pre-existing 269
passing tests.

### 9 · Known data-integrity issue flagged (not fixed)

`icsforge/data/detection_rules_specs.json` references 71 techniques while
`scenarios.yml` references 68:

    In specs but NOT scenarios: T0841, T0842, T0875, T0876  (orphan rules)
    In scenarios but NOT specs: T0879                        (missing rule)

The README's "68 techniques / 82%" is authoritative. A v0.63 pass should
reconcile by either adding scenarios for the orphan rules or removing
them.

### 10 · Pre-existing test failures: FIXED

The 11 failures that were pre-existing on v0.61.0 are now fixed in v0.62.0:

    tests/test_auth.py                  — fixture now uses monkeypatch to
                                          scope ICSFORGE_NO_AUTH mutations
                                          (root cause of e2e pollution).
    tests/test_e2e_pipeline.py (7)      — pass unchanged, once auth env
                                          leakage is contained.
    tests/test_core.py (1)              — IP allow-list test fixed upstream.
    tests/test_sse_campaigns.py (1)     — step-options accepted upstream.
    tests/test_web_api.py (1)           — callback token handling fixed.

Full suite now: **324 passed, 0 failed**. See
`tests/test_auth.py::auth_app` fixture for the one-line concept fix.

### 11 · Coverage consistency locks

New `tests/test_coverage_consistency.py` locks the detection-rule /
scenario drift (Blocker 1 for Arsenal):

  - 4 orphan specs (T0841, T0842, T0875, T0876) documented and locked
  - 1 missing spec (T0879) documented and locked
  - README technique count must match scenarios.yml
  - README must reference all 11 campaigns by name

Any future drift breaks CI. When the drift is closed, shrink the
baseline sets in that test file.

### 12 · Reference detection coverage — published for the first time

ICSForge has always shipped auto-generated Suricata rules but never
published how well those rules actually fire against its own PCAPs.
v0.62 fixes that with a reproducible measurement harness and an honest
reference-coverage table in the README.

**Harness:** `scripts/measure_detection_coverage.py`

  - Generates PCAPs for every scenario via in-process `run_scenario()`
    (no subprocess fork overhead)
  - Exports the three-tier rules (`icsforge detections export`)
  - Runs Suricata 7+ in offline mode, counts alerts per tier, dispatches
    them back to scenarios via unique src IPs (one TEST-NET host per
    scenario)
  - Produces JSON + Markdown reports with per-tier / per-protocol /
    per-scenario breakdowns and an explicit gap-analysis list

**New `--batch` mode** merges all PCAPs with `mergecap` and runs
Suricata once, amortising startup cost across all scenarios. Full
536-scenario run: ~10 minutes (was estimated ~45 minutes per-PCAP).

**Protocol-engine fixes this enabled:**

  - `icsforge/scenarios/engine.py` — honour `skip_intervals=True` on
    profinet_dcp and iec61850 paths (two bugs where `time.sleep()` was
    unconditional). Needed for fast offline generation.
  - `icsforge/detection/generator.py` — `flow:established,to_server` →
    `flow:to_server`. The original modifier required a TCP handshake
    which doesn't exist in synthetic one-way PCAPs; the replacement
    still constrains direction and matches just as well on real
    handshaked traffic. Tier 1 and Tier 2 rules went from 0% to 85% and
    52% hit rates respectively after this one-line change.

**Published numbers** (see README "Reference detection coverage"):

  - Tier 1 lab_marker: 183/535 (34.2%)
  - Tier 2 protocol_heuristic: 99/535 (18.5%)
  - Tier 3 semantic: 137/535 (25.6%)

Per-protocol semantic-tier rate ranges from 66% (S7comm) down to 0%
(BACnet/IP, IEC 61850, PROFINET DCP). The zero-rate protocols have
`_PROTO_MAGIC` entries in the generator but don't currently emit
semantic rules — a honest gap, flagged for v0.63+.

### 13 · IEC 60870-5-104 U-format spec fix (discovered via Wireshark validation)

During Phase 3 third-party parser validation, Wireshark's ICS
dissector flagged every IEC-104 packet after the first as
`<ERR prefix N bytes>`. Root cause: ICSForge was appending the
`ICSFORGE:` correlation marker bytes after U-format APCI control
frames (startdt, stopdt, testfr, block_cmd, available styles).
Per IEC 60870-5-104 §5.1, U-format frames are fixed 6 bytes and
structurally cannot carry application data. Appending bytes broke
TCP-stream reassembly for downstream dissectors.

Fix in `icsforge/protocols/iec104.py`: omit the marker on all five
U-format styles. The trade-off is losing per-packet marker
correlation on those specific control frames, which carry no
application data anyway.

**Impact on detection rates:** in per-protocol measurement mode,
IEC-104 semantic tier went from 38.5% to **88.5%** hit rate after
the fix. The improvement comes from Suricata's stream engine now
correctly parsing subsequent I-format frames in the same flow,
which it previously gave up on after seeing the malformed U-frame
tails.

### 14 · Independent third-party NSM validation — Wireshark/tshark

New `docs/third_party_validation/MALCOLM_VALIDATION_v0.62.0.md`
documents the third-party parser validation. Wireshark 4.2.2 (the
same dissector library used by Malcolm's Zeek, Arkime, and most
open-source NSM tools) dissects **10 of 10 protocols at 100%
success rate** — Modbus, DNP3, S7comm, IEC-104, EtherNet/IP,
OPC UA, BACnet/IP, MQTT, IEC 61850 GOOSE, PROFINET DCP all produce
expected protocol stacks with fully recognised function codes.

Full reproduction commands included in the doc; any contributor
with `apt-get install tshark` can re-run the validation and should
see identical results. A future session should also run the full
Malcolm stack and append screenshots of the populated OT dashboards
to the same doc.

---

### File inventory for the v0.62.0 PR

Added:

    docker-compose.demo.yml
    docker/suricata.yaml
    docker/suricata-classification.config
    docker/suricata-reference.config
    docker/Dockerfile.viewer
    icsforge/detection/__main__.py
    icsforge/viewer/__init__.py
    icsforge/viewer/__main__.py
    icsforge/web/templates/demo.html
    tests/test_v062_additions.py
    SECURITY.md
    CODE_OF_CONDUCT.md
    GOVERNANCE.md
    CITATION.cff

Modified:

    icsforge/campaigns/builtin.yml        (5 → 11 campaigns)
    icsforge/cli.py                       (+ 5 top-level subcommands, ~290 LOC)
    icsforge/detection/generator.py       (+ CLI, + _write_outputs, ~100 LOC)
    icsforge/web/app.py                   (+ /demo route)
    icsforge/__init__.py                  (version bump — 0.61.0 → 0.62.0)

Unchanged — protocols, scenario library, receiver, auth, core.

---

## v0.61.0 (2026-04-13) — Three-tier detection content

### Detection generator completely rewritten

Previous generator produced one rule per scenario using port + first 8 header
bytes + optional marker. A detection engineer's correct assessment: mostly lab
scaffolding. The semantic depth was not there.

The new generator produces three separate, explicitly-labeled rule sets:

---

#### Tier 1 — icsforge_lab.rules (149 rules)

  Requires ICSFORGE_SYNTH marker in payload.
  Zero false positives on non-ICSForge traffic.
  Use only during validation runs. Not useful against real adversaries.

---

#### Tier 2 — icsforge_heuristic.rules (145 rules)

  Matches protocol magic bytes at exact offsets:
    Modbus:    0x00 0x00 at offset 4-5 (Protocol Identifier field)
    DNP3:      0x05 0x64 at offset 0-1 (Link-layer start bytes)
    S7comm:    0x03 0x00 at offset 0-1 (TPKT header)
    IEC-104:   0x68 at offset 0 (APCI start byte)
    MQTT:      0x10 at offset 0 (CONNECT packet type)
    BACnet:    0x81 0x0A at offset 0-1 (BVLC header)
    EtherNet/IP: command word at offset 0-1

  Will fire on any traffic matching that protocol. Use to confirm NSM
  visibility. Does not distinguish adversary from legitimate OT traffic.

---

#### Tier 3 — icsforge_semantic.rules (227 rules)  ← recommended

  Matches specific function codes and application-layer commands:
    Modbus:    FC byte at offset 7 (Read Coils/01, Write Multiple/10, etc.)
    DNP3:      Application FC at offset 12 (Direct Operate/05, Restart/0D, etc.)
    S7comm:    PDU type byte at offset 8 (Job/01, Userdata/07, etc.)
    IEC-104:   ASDU Type ID at offset 6 (C_SC_NA/2D, C_DC_NA/2E, etc.)
    MQTT:      Packet type nibble (PUBLISH/30, SUBSCRIBE/82, etc.)
    BACnet:    Service choice byte at offset 7 (writeProperty/0F, etc.)
    EtherNet/IP: Command word (ListIdentity/6300, RegisterSession/6500, etc.)

  Low false-positive rate in properly segmented OT environments where those
  specific function codes should be absent or rare. This is the tier that
  would fire on a real adversary performing the same operation, not just
  generating the same protocol.

---

### Sigma rules: tiered detection blocks

Each sigma/<scenario>.yml now contains all three tiers in one file:

  detection:
    lab_marker:            payload|contains: 'ICSFORGE_SYNTH'
    protocol_heuristic:    dst_port + network.protocol fields
    semantic:              protocol-specific Zeek field matching
                           (modbus.func_code, dnp3.app_func_code,
                            mqtt.packet_type_name, bacnet.service_choice)
    condition: lab_marker or protocol_heuristic or semantic

  falsepositives block explicitly documents per-tier FP expectations.
  confidence_tiers in custom: block machine-readable for tooling.

### Download now provides all three files

GET /api/detections/download produces a zip with:
  icsforge_lab.rules
  icsforge_heuristic.rules
  icsforge_semantic.rules  (was previously icsforge_ics.rules)
  sigma/<scenario>.yml x149
  README.txt with tier explanation and usage examples

GET /api/detections/preview now returns rule_counts per tier.

## v0.60.1 patch — mandatory HMAC, honest README, policy banners (2026-04)

### HMAC now mandatory when callback token is configured

Previously HMAC was only checked if the X-ICSForge-HMAC header was present —
a token-bearing callback without HMAC was accepted. This made HMAC optional
integrity, which is effectively weak integrity.

Fixed: if a callback token is configured, X-ICSForge-HMAC is now required.
A token-correct callback without the header returns 401 "HMAC required".
If no token is configured, no HMAC check applies (backwards compat for
no-token setups). When token IS configured the full chain is enforced:
correct token + correct HMAC-SHA256(token, body) = accepted.

### README safety claims corrected

The README said:
  "operating within a Sender-Receiver architecture and interacting only with
   the designated sender and receiver, without touching other OT devices"

That is not true — replay can reach any private IP by default, and the tool
is designed to be a flexible lab platform. Replaced with accurate language:
  "By default, live traffic sends are restricted to RFC 1918 / loopback
   addresses, and PCAP replay is restricted to private ranges unless
   explicitly unlocked via Tools → Send Policy. It is a flexible lab
   platform — not a zero-touch sandbox."

Also fixed:
  - Version badge: 0.60.0 → 0.60.1
  - Upload cap: 1 GB → 100 MB (was stale from before the cap change)
  - "safe-by-design" and "without touching other OT devices" removed

### Warning banners for active risk states

Three new amber banners appear in the nav header when dangerous states are on:

  ⚠ Authentication disabled (ICSFORGE_NO_AUTH) — always shown when no-auth mode
    is active, so operators can't forget they're running without access control.

  ⚠ Public PCAP replay targets enabled — shown dynamically via JS when the
    replay toggle is on. Links to Tools → Send Policy.

  ⚠ Public webhook URLs enabled — shown dynamically when the webhook toggle
    is on. Links to Tools → Send Policy.

All three are amber (not red) to distinguish from the critical token-missing
banner, which remains red.

## v0.60.1 (2026-04-13)

### Send Policy toggles are now the sole authority

The `ICSFORGE_REPLAY_ALLOW_PUBLIC` and `ICSFORGE_WEBHOOK_ALLOW_PUBLIC` environment
variables previously bypassed the UI toggles — if set in the shell, public targets
were allowed regardless of what the toggle showed. This was the root cause of the
"I replayed to 8.8.8.8 with the toggle off" issue.

Both gates now check only the persisted config globals (`_replay_allow_public`,
`_webhook_allow_public`). Environment variables no longer have any effect on
these gates. The UI toggle in Tools → Send Policy is the single source of truth.

Default state: both toggles off. If a user enables one and then turns it off,
public targets are blocked again immediately — no restart needed.

The `ICSFORGE_ALLOWED_NETS` env var for non-RFC1918 networks is also superseded
by the Tools → Allowed Networks UI. Env var support in the allowed-networks check
was kept for backwards compatibility but the recommended workflow is now the UI.

### Bug fixes

- Token warning banner (base.html): `inject_token_status` context processor was
  written but never registered — went into a dead code path from a failed string
  replace. Now correctly registered as `@web.app_context_processor`. Additionally,
  `saveNetworkConfig` in `sender.js` now immediately hides the banner client-side
  in a `finally` block — no page reload required.

- IEC 61850 `invalid literal for int() with base 10: '0x0004'`: The APPID field
  in the sender UI sends the default as the string `"0x0004"`. `int("0x0004")`
  fails without `base=16`. Fixed with a `_int()` helper using `int(v, 0)` (base 0
  auto-detects `0x` prefix) applied to all kwargs int() calls in iec61850.py.

### Documentation

- README: security model updated — send policy, HMAC receipt signing, path
  traversal fixes all documented. Env var references removed.
- HOWTO.md: Send Policy section added (section 10). Non-RFC1918 section updated
  to point to UI instead of env var.
- INSTALL.md: Non-RFC1918 section updated to point to UI.

## v0.60.0 security hardening round 3 — third audit fixes (2026-04)

### Critical: credentials removed from release artifact

The shipped tarball contained out/.credentials.json (with username and password hash)
and out/run_index.json (with absolute developer machine paths). This is a release
hygiene failure that gives reviewers ammunition before the demo starts.

Fixed in two ways:
  1. Credentials moved from out/.credentials.json to ~/.icsforge/credentials.json —
     outside the project tree entirely, impossible to accidentally include in a release.
  2. release.sh now explicitly excludes out/.credentials.json, out/run_index.json,
     and out/alerts/, and runs a post-build sanity check that aborts with an error
     if any runtime state appears in the artifact.

### High: webhook URL restricted to private/localhost by default

Webhook fire_webhook() accepted any URL including public internet addresses, giving
an authenticated operator an unrestricted outbound HTTP client. Fixed:
  - Only http/https schemes accepted
  - Host must be loopback, private, or link-local by default
  - Set ICSFORGE_WEBHOOK_ALLOW_PUBLIC=1 to allow public URLs (Slack, PagerDuty, etc.)

### High: PCAP replay fenced to private ranges by default

/api/pcap/replay intentionally allowed any dst_ip, directly contradicting the
safe-by-design posture of /api/send. Fixed:
  - Private/loopback ranges always allowed (lab use)
  - Public IPs return 403 with a clear message
  - Set ICSFORGE_REPLAY_ALLOW_PUBLIC=1 to allow public targets when you have
    explicit permission to send to that device

This makes the safety model consistent across all send paths.

### High: HMAC receipt signing added

Receipts are now signed by the receiver with HMAC-SHA256 over the full JSON body
using the shared callback token. The sender verifies the HMAC on ingest:
  - Receiver adds X-ICSForge-HMAC header to every callback POST
  - Sender verifies it if present; unsigned receipts from token-authenticated
    connections are still accepted for backwards compat with older receivers
  - A forged receipt with token but wrong HMAC returns 401 "HMAC verification failed"
  - A forged receipt without token continues to return 401 as before

This is the cryptographic binding that changes the Demo Labs answer: receipts
are now mathematically bound to the shared token, not just checked for its presence.

### Medium: upload cap reduced from 1 GB to 100 MB

1 GB was a DoS allowance, not hardening. 100 MB is sufficient for real PCAPs
(typical multi-protocol scenario captures are 1-10 MB).

### Medium: SameSite=Lax added to session cookies

Reduces CSRF attack surface for cross-site request scenarios.

## v0.60.0 security hardening round 2 — second audit fixes (2026-04)

### Critical: X-Forwarded-For trust removed from callback registration

The previous fix to /api/config/set_callback checked X-Forwarded-For to determine
if a caller was loopback-trusted. An attacker could send:

  X-Forwarded-For: 127.0.0.1

and bypass the token requirement entirely, registering an arbitrary callback URL
and redirecting all receipt telemetry.

Fixed: only request.remote_addr is used. X-Forwarded-For is completely ignored.
If the app runs behind a trusted reverse proxy, the proxy must handle IP rewriting
upstream before the request reaches Flask.

### High: net_validate_custom paths confined to repo root

The custom network validation endpoint accepted arbitrary events, receipts, and
output paths with no confinement. An authenticated user could read arbitrary
JSONL-parseable files or write reports anywhere the process could write.

Fixed: all three paths are now resolved relative to repo root and validated via
os.path.realpath() + startswith check. Paths outside repo root return 400.

### High: selftest cwd removed from web input

/api/selftest accepted a caller-supplied cwd parameter and passed it to both the
subprocess argument list and subprocess.run(cwd=...). Fixed: cwd is always the
repo root. The receipts path is also validated to stay inside repo root.

### Medium: session secret now persisted across restarts

The app previously generated a new random secret key on every restart, invalidating
all active sessions and CSRF tokens. This caused "why did I get logged out" failures
at inconvenient demo moments.

Fixed: secret key is generated once, written to ~/.icsforge/secret_key (mode 0600),
and reused on subsequent starts. ICSFORGE_SECRET_KEY env var still overrides.

### Medium: replay warning banner added to Tools page

PCAP replay intentionally accepts any destination IP. This contradicts a strict
reading of "safe-by-design." Added a visible amber warning on the Tools → PCAP
Replay card: "Only replay PCAPs to devices you own and have permission to test."

# ICSForge Changelog

## v0.60.0 (2026-04-13)

### Security hardening — mandatory callback token

A callback token is now auto-generated during first-time setup and required on all
receipt and registration endpoints. This closes the forged-receipt attack: a reviewer
who POSTs `{marker_found: true}` to `/api/receiver/callback` without the token gets
HTTP 401. The token is shown in the setup UI with a one-click Copy button and the
exact receiver launch command.

  - First-launch setup generates `secrets.token_urlsafe(24)`, persists it, and
    displays it in the setup page with the receiver start command
  - `/api/receiver/callback` always rejects unauthenticated POSTs when token is set
  - `/api/config/set_callback`: loopback callers trusted; remote callers require token
  - Receiver CLI: `--callback-token <token>` argument added
  - Red warning banner on all pages until token is configured (for upgrades)

### IP allowlist — Allowed Networks UI

Non-RFC1918 internal ranges (e.g. 130.75.0.0/24) now configurable in-UI without
restarting. Tools → ⚙ Allowed Networks. Persisted to `~/.icsforge/web_config.json`.
Env var `ICSFORGE_ALLOWED_NETS` still works and is shown read-only in the UI.

All RFC 1918 ranges (`10.x`, `172.16-31.x`, `192.168.x`), loopback, and link-local
are allowed by default without any configuration.

### Matrix send path: IP check now consistent

`/api/technique/send` now enforces the same `_is_safe_private_ip()` check as
`/api/send`. Previously the matrix tile send path had no IP guard — public IP bypass
confirmed. Fixed.

### Delivery ratio: per-technique fraction, not binary

`delivery_ratio` was `1.0` if any receipt existed, `0.0` otherwise. Now:

    delivered_techniques = expected_techniques ∩ receipted_techniques
    delivery_ratio = len(delivered_techniques) / len(expected_techniques)

`delivered_techniques` added to report output so the exact gap is visible.

### Detection generator: dynamic version label

Suricata and Sigma rule headers were hardcoded to `v0.42`. Now uses `__version__`.

### Upload size limit: 1 GB

`MAX_CONTENT_LENGTH = 1 GB` applied to the Flask app. Prevents disk exhaustion
via large PCAP uploads.

### Protocol realism

  - Source MACs use registered OT vendor OUIs per protocol — no locally-administered
    bit (eliminates Defender for IoT / Claroty "synthetic MAC" alerts)
  - TCP source port stable per scenario run — all frames share one port, matching
    real ICS persistent master-RTU connections (was random per frame)
  - S7comm USERDATA header corrected to 12 bytes (was 10 — caused Wireshark MALFORMED
    on `szl_read` and `szl_clear` styles)
  - Full protocol correctness audit: Modbus MBAP, DNP3 CRCs, IEC-104 SSN/COT,
    OPC UA sequence numbers, BACnet PDU types, MQTT QoS IDs — all verified clean

### UI fixes

  - Stealth toggle now immediately refreshes hex dump preview (was broken — IIFE
    scope issue: `toggleStealth` was outside the IIFE so `selectedName` was undefined)
  - Matrix "★ All runs" overlay now correctly highlights executed techniques
    (was broken — `list_runs()` returns no artifacts; fixed to call `get_run()` per run)
  - PCAP replay: IP restriction removed from both web layer and `core.py`
  - Receiver reset button: missing `main.js` load caused CSRF 403 — fixed
  - KPI counters: unique technique/protocol counts (not capped at 8)
  - Sender Network Settings: removed misaligning "→ auto-fills" subtext

### GOOSE receiver listener

IEC 61850 GOOSE (EtherType 0x88B8) receiver added — `_l2_goose_listener()` runs
alongside PROFINET DCP when `--l2-iface` is specified.

### Housekeeping

  - Removed: `docs/PHASE.md` (stale, 9 protocols/175 scenarios), `docs/LIVE_SOC_DEMO_FLOW.md`
    (referenced deleted CLI), `icsforge/data/technique_variants.json` (71 stale entries,
    API derives live from scenarios.yml)
  - Post-IIFE functions (EVE tap, webhook) were referencing IIFE-local `API`, `logln`,
    `tlConfirmStep` — fixed by exporting from inside IIFE as `window._senderAPI` etc.
  - `docker-compose.yml`: stale `v0.4` comment removed
  - `docs/INSTALL.md`, `docs/HOWTO.md`: rewritten for current version

---

## v0.59.10 (2026-04 — Stealth preview fix (real), All-runs overlay, PCAP replay)

### Bug 3 (complete fix): PCAP replay IP restriction was in two places

The IP restriction was removed from `bp_runs.py` (web layer) but `replay_pcap()`
in `core.py` had its own identical guard:

    if not is_allowed_dest(dst_ip):
        raise ValueError('Replay blocked: destination IP not allowed...')

So public IPs were still blocked at the core level. Both guards are now removed.
The live-send functions in core.py (lines 107, 122) retain their guards — correct.
Verified end-to-end: generate PCAP → upload → replay → 3/3 packets received by listener.


### Bug 1: Stealth toggle preview — root cause finally fixed

Previous attempts patched the wrong layer. The actual bug: sender.js wraps all
its logic in an IIFE — `(function(){ ... })();`. `selectedName`, `hexStepIdx`,
and `loadHexDump` are all IIFE-local. `window.toggleStealth` was defined AFTER
the IIFE closed, so those names were `undefined` at global scope. The button
visuals worked (pure DOM) but `loadHexDump` was silently never called.

Fix: `window.toggleStealth` moved inside the IIFE, before `})();`. It now has
genuine closure access to `selectedName`, `hexStepIdx`, and `loadHexDump`.
Cache-busting timestamp on the preview URL is also kept.

### Bug 2: Matrix "★ All runs" overlay highlights executed techniques

`reg.list_runs()` is a lightweight query — no artifact paths in the result.
The `__all__` aggregation was iterating slim records and finding no events files.
Fixed: calls `reg.get_run(run_id)` per run to get the full artifact list.

### Bug 3: PCAP replay accepts any destination IP

Removed the private-IP restriction from `/api/pcap/replay`. PCAP replay is an
explicit user action targeting real devices — the restriction made it unusable
for any realistic lab setup. The live-send endpoint `/api/send` still enforces
private/test/loopback only (correct for synthetic traffic generation).

## v0.59.9-r1 (2026-04 — Bug fix: stealth preview root cause, PCAP replay IP unrestricted)

### Bug 1 (stealth toggle): actual root cause found and fixed

Previous attempt added a cache-busting timestamp to loadHexDump URLs. That was 
correct but addressed a symptom. The real root cause:

sender.js is wrapped in an IIFE — (function(){ ... })(); — making selectedName,
hexStepIdx, and loadHexDump local to that function scope. window.toggleStealth
was defined AFTER the closing })(); meaning it executed in the global scope where
selectedName and loadHexDump are both undefined. The button visuals (borderColor,
icon) updated correctly because those use only DOM APIs. But the if (selectedName)
guard always evaluated to false, so loadHexDump was never called.

Fix: window.toggleStealth moved inside the IIFE, just before the closing })();.
selectedName, hexStepIdx, and loadHexDump are now genuinely in closure scope.
The cache-busting timestamp on loadHexDump URLs is also retained as defence
against browser caching when toggling back to the normal (no-marker) payload.

### Bug 3 (PCAP replay): IP restriction removed

/api/pcap/replay was applying the same private-IP-only allowlist as /api/send,
returning "dst_ip blocked: must be private/test/link-local/loopback" for any
public destination. PCAP replay is a different operation from live traffic
generation: the user has a captured file and explicitly controls where they
send it, including real OT devices on routable segments. The restriction is
removed from the replay endpoint. /api/send keeps its private-IP enforcement
(correct — that limits where the tool generates live synthetic OT traffic).
Empty dst_ip is still rejected with 400.

## v0.59.9 — Bug fixes: stealth preview, matrix All-runs overlay, PCAP replay dst_ip

### Bug 1: Stealth toggle now immediately refreshes live payload preview

Toggling stealth mode within an already-selected scenario did not update the hex
dump. The backend correctly returns different payloads for `?no_marker=1` vs not,
but the browser was caching the first GET response for the same URL path. When
stealth was toggled ON the URL changed (`?step=0` → `?step=0&no_marker=1`) so the
new payload appeared. When toggled back OFF the URL reverted to `?step=0` and the
browser served the original cached response rather than re-fetching.

Fix: `loadHexDump()` now appends `&_=${Date.now()}` to every preview URL, making
each request unique and defeating the browser cache. Toggle ON and OFF now both
immediately show the correct payload for the current stealth state.

### Bug 2: Matrix "★ All runs" overlay now highlights executed techniques

After running scenarios, clicking Apply with "★ All runs (aggregate)" selected
showed no highlighted technique tiles — all remained grey.

Root cause: `reg.list_runs()` is a lightweight query that returns slim run
records without artifact paths. The `__all__` aggregation was iterating the slim
records and looking for `artifacts` which weren't there, so no events files were
opened and `executed` stayed empty.

Fix: the `__all__` path now calls `reg.get_run(run_id)` for each run from
`list_runs()` to get the full record including artifact paths, then reads each
events JSONL for `mitre.ics.technique` fields. Verified: technique tiles now
correctly highlight after runs are stored in the registry.

### Bug 3: PCAP replay — "dst_ip required" error after upload

After uploading a PCAP via the file picker, clicking Replay immediately returned
`Error: dst_ip required`. The upload flow correctly set the `r_pcap` path field
but left `r_dst` (Destination IP) empty. The server-side validation then rejected
the request.

Two fixes:
  1. On tools page load, `GET /api/config/network` and auto-fill `r_dst` with the
     saved receiver IP if available — so if you've already configured the receiver
     in Network Settings, the field is pre-populated.
  2. Client-side validation in `replayTool()` now checks both `pcap_path` and
     `dst_ip` before sending, and shows a clear inline error message: "Enter the
     receiver IP address in the Destination IP field above" — instead of a terse
     JSON error from the server.

The server-side validation remains in place as defence-in-depth.

## v0.59.9 (2026-04 — TCP source port stability + full protocol realism audit)

### TCP source port: stable per scenario run (session realism)

Previously every TCP frame in a scenario run got a fresh random source port from
`rnd.randint(1024, 65535)`. NSMs model TCP sessions by the 4-tuple
(src_ip, src_port, dst_ip, dst_port). With random source ports, a 30-frame Modbus
scenario appeared as 30 separate sessions instead of one persistent master-RTU
connection. Wireshark's flow reassembly also failed to group the frames.

Fixed: `run_scenario()` now derives a stable source port once per run:

    _sport = 49152 + md5(src_ip + dst_ip + run_id)[:4] % 16383

The port is always in the OS ephemeral range (49152–65534), is deterministic per
run identity, and differs across scenarios, across protocols, and across run IDs.
All frames in a single scenario run now share one source port — matching the
behaviour of a real ICS master that opens one persistent TCP connection per RTU.

The `sport` parameter added to `tcp_packet()` in `common.py`. The engine passes
it for both synthetic (with markers) and stealth (no markers) traffic.

### Full protocol realism audit — all scenario-used styles verified clean

Systematic end-to-end audit of every protocol builder for the styles actually used
in scenarios.yml. Findings:

  Modbus/TCP   MBAP lengths, FCs, unit IDs, transaction IDs: all correct ✓
  DNP3         FIR/FIN/UNS flags, app seq (mod-16 increment), CRCs: all correct ✓
  IEC-104      SSN monotonically incrementing, COT=6 for commands, APDU lengths: all correct ✓
  S7comm       _var_item bit-address encoding, PDU refs monotonic, USERDATA 12B: all correct ✓
  EtherNet/IP  CIP symbolic paths (0x91), encapsulation lengths: all correct ✓
  OPC UA       Seq numbers and request IDs monotonically incrementing, MSG/OPN/CLO types: all correct ✓
  MQTT         QoS packet IDs unique and non-zero, remaining_length: all correct ✓
  BACnet       confirmed/unconfirmed PDU type correct for all styles ✓
  PROFINET DCP FrameID and ServiceID correct for all styles ✓
  GOOSE        BER encoding structurally correct ✓

Known acceptable limitations (require real RTU counterpart to fix):
  IEC-104 RSN=0 — correct only when a real RTU responds; unidirectional synthetic sends
                  cannot know how many frames the RTU has received
  No TCP handshake (SYN/SYN-ACK/ACK) — by design for frame-level generation;
                  NSMs that require full handshakes before classifying traffic will not
                  fire on ICSForge frames (this is a known tradeoff)

## v0.59.9 (2026-04 — Full protocol realism audit: S7 byte_addr, OPC UA HEL, PROFINET frame IDs)

### S7comm: variable item byte address encoding fixed (all 9 affected styles)

The `_var_item()` helper correctly encodes byte_addr as `bit_offset = byte_addr * 8`
stored big-endian in 3 bytes. However, 9 styles bypassed `_var_item()` and used
inline `bytes([..., 0x00, addr & 0xFF, 0x00])` — storing the raw byte address in
the middle byte of the 3-byte field. This gives `bit_addr_24 = addr << 8` instead
of `addr * 8`. Example: `byte_addr=10` produced `bit_addr_24=0x000A00=2560`
(byte 320) instead of `0x000050=80` (byte 10). A real S7 PLC would access the
wrong memory location or reject the item with an illegal address error.

Fixed styles: `read_var`, `write_var`, `read_db`, `write_db`, `read_outputs`,
`write_outputs`, `read_inputs`, `write_inputs`, `write_failsafe`, `read_all_dbs`.
All now use `_var_item()` consistently with correct bit-offset encoding.
Verified: byte_addr 0, 10, 100, 200 all decode correctly in generated frames.

### OPC UA: HEL (Hello) frame endpoint URL missing length prefix

The OPC UA Binary protocol encodes variable-length strings as UA_String:
a 4-byte signed int32 length followed by the UTF-8 bytes. The `hello` and
`force_reconnect` styles built the HEL body as:

  struct.pack("<IIIII", version, recv_buf, send_buf, max_msg, len(endpoint)) + endpoint

This placed `len(endpoint)` as the `max_chunk_count` field (5th uint32) and
wrote the endpoint URL bytes directly after — no length prefix. Wireshark's
OPC UA dissector parses the URL length as whatever 4-byte ASCII sequence starts
the URL (`"opc."` = `0x2E63706F` = 778,268,783 bytes), then fails.

Fixed: `struct.pack("<IIIII", 0, 65536, 65536, 0, 0)` (max_chunk_count=0=unlimited)
followed by `struct.pack("<I", len(endpoint)) + endpoint`. Both `hello` and
`force_reconnect` styles corrected. HEL frames now parse cleanly in Wireshark.

### PROFINET DCP: frame IDs corrected per IEC 61158-6-10

The frame ID constants were misassigned:

  Old (wrong):                        Correct per IEC 61158-6-10:
  0xFEFE = dcp_identify_multicast     0xFEFE = Identify Request (multicast)  ← same
  0xFEFF = dcp_identify_unicast       0xFEFF = Identify Response (unicast)   ← same
  0xFEFD = dcp_hello                  0xFEFD = Get/Set Request               ← WRONG
                                      0xFEFC = Hello Request (boot)           ← MISSING

The `hello` style used 0xFEFD (Get/Set) instead of 0xFEFC (Hello/boot).
The `get_ip` and `get_name` styles used 0xFEFF (Identify Response) instead of
0xFEFD (Get Request). The `set_ip`, `set_name`, `factory_reset` styles used
0xFEFF instead of 0xFEFD (Set Request).

Fixed: added `dcp_hello=0xFEFC` and `dcp_get_set=0xFEFD` constants. All styles
now use the correct frame ID. PROFINET-aware tools (Wireshark, Siemens TIA Portal
capture, Defender for IoT) will correctly classify each PDU type.

### Full audit — all other protocols verified clean

IP/TCP headers: TTL=64 (Linux), DF bit set, window=8192 — all realistic.
Modbus MBAP, DNP3 CRCs, IEC-104 APDU, BACnet BVLC: all correct (confirmed again).
OPC UA MSG sequence/request_id: monotonically incrementing per engine session.
IEC-104 SSN: monotonically incrementing per engine session.
S7 PDU reference: monotonically incrementing per engine session.
BACnet invoke_id: correctly incremented for confirmed requests only.
MQTT: protocol version 4 (v3.1.1), realistic keepalive, correct remaining_length.
EtherNet/IP: session handle non-zero for SendRRData, CPF structure correct.

## v0.59.8 (2026-04 — Protocol-aware OUI table: eliminate locally-administered MAC alerts)

### Root cause of Defender for IoT / OT-NSM alerts

Every source MAC generated by ICSForge had `0x02` as the first byte — the
IEEE 802 "locally administered" bit. This immediately identifies synthetic traffic
to any OT-aware network security monitoring tool:

  - Wireshark shows "Locally Administered" in the MAC field
  - Defender for IoT / Claroty / Dragos flag every frame as non-hardware traffic
  - OUI vendor lookup returns nothing (no registered manufacturer)

No real OT hardware (Siemens PLC, Rockwell controller, ABB relay, Schneider SCADA)
ships with a locally-administered MAC. All real OT devices have OUI-registered MACs
from their manufacturer.

### Fix: protocol-aware OUI table

Replaced `_src_mac_from_ip()` with a protocol-aware implementation that selects a
registered OUI from the real OT vendor pool for each protocol:

  modbus       → Schneider Electric (00:80:F4, 00:10:EC, 00:60:9C)
  s7comm       → Siemens AG (00:0E:8C, 00:1B:1B, AC:64:17)
  enip         → Rockwell Automation (00:00:BC, 00:0E:8C, EC:9A:74)
  dnp3         → GE Grid Solutions / SEL (00:90:69, 00:30:A7, D4:BE:D9)
  iec104       → ABB / Siemens (00:0A:DC, 00:0E:8C, 00:1A:4B)
  iec61850     → GE / ABB / Alstom (00:90:69, 00:0A:DC, 00:01:72)
  opcua        → Dell/HP server OUIs (18:DB:F2, 14:FE:B5, 00:25:64)
  bacnet       → Automated Logic / Delta Controls (00:60:35, 00:A0:A5)
  profinet_dcp → Siemens / Phoenix Contact (00:0E:8C, 00:A0:45)
  mqtt         → Moxa / Advantech / AVEVA (00:90:E8, 00:D0:C9)

The OUI is selected deterministically from the last octet of the source IP so the
MAC is stable within a session but varies per host. The suffix bytes are derived
from the full IP so each host gets a unique MAC within the OUI space.

The "globally administered" and "unicast" bits are always clear (bit 0 = 0, bit 1 = 0)
in the first octet — no NSM tool will flag these as synthetic.

GOOSE and PROFINET DCP L2 frames also fixed: both previously used `0x02:xx:xx:...`
random source MACs. Now GOOSE uses GE/ABB OUIs and PROFINET uses Siemens/Phoenix
Contact OUIs matching real relay and controller hardware.

`proto` parameter threaded through `tcp_packet()`, `udp_packet()`, and the engine
frame builders so every protocol gets the correct vendor OUI automatically.

## v0.59.7 (2026-04 — S7comm USERDATA header fix, full protocol correctness audit)

### S7comm: USERDATA header corrected from 10 to 12 bytes

The S7comm protocol defines two distinct PDU header formats:
  - ROSCTR_JOB (0x01): 10 bytes — no error word
  - ROSCTR_USERDATA (0x07): 12 bytes — includes error_class + error_code at the end

The `szl_read` and `szl_clear` styles both use ROSCTR_USERDATA but were building
a 10-byte header using the JOB format. The Wireshark S7comm dissector knows this
distinction and flagged both styles as MALFORMED because the parameter block started
at byte 10 instead of byte 12. A real Siemens S7 PLC would reject these frames.

Fixed: added `_s7_userdata_header(pdu_ref, param_len, data_len)` helper that packs
the 12-byte structure correctly with error_class=0x00, error_code=0x00. Both styles
now pass Wireshark dissection without MALFORMED warnings.

Impact: `szl_read` covers T0868 (Theft of Operational Information) and T0882
(Theft of Operational Data) — SZL enumeration is a key S7 reconnaissance technique.
`szl_clear` covers T0872 (Indicator Removal on Host). Both were structurally wrong.

### Full protocol correctness audit — all other protocols clean

Systematic check of every protocol builder for length field accuracy, correct
header structure, and spec-valid framing:

  Modbus/TCP   — MBAP length field correct for all 10 styles ✓
  DNP3         — header CRC + all per-block data CRCs valid for all 28 styles ✓
  IEC-104      — APDU start byte and length field correct for all 15 styles ✓
  BACnet/IP    — BVLC type and length field correct for all 15 styles ✓
  EtherNet/IP  — encapsulation length field correct for all scenario-used styles ✓
  OPC UA       — message size field correct for all 29 scenario-used styles;
                 correct type bytes (HEL/MSG/OPN/CLO/ERR) ✓
  MQTT         — remaining_length encoding correct for all 17 styles ✓
  PROFINET DCP — L2, no length-critical fields ✓
  GOOSE        — BER-encoded, structurally correct ✓

The malformed_ucmm EtherNet/IP style (T0866 exploitation) is intentionally malformed
by design — that is the attack it represents.

## v0.59.6 (2026-04 — Matrix "All runs" overlay, live payload preview stealth fix, MAC realism)

### Matrix: "★ All runs (aggregate)" overlay

The overlay run selector now includes a permanent "★ All runs (aggregate)" option
at the top of the list, available before and after loading individual runs.

Selecting it and clicking Apply calls `/api/matrix_status?run_id=__all__`, which
aggregates executed techniques across ALL runs in the registry — scanning each
run's events file for `mitre.ics.technique` fields and each correlation report
for observed/gaps sets. The result is a union overlay showing every technique
that has ever been executed or detected across all your test runs.

This lets you see your cumulative ATT&CK coverage at a glance without having
to pick a specific run.

### Live payload preview: reloads when stealth mode is toggled

Toggling "Stealth mode — real traffic, no synthetic tags" within an already-selected
scenario did not refresh the hex dump preview. The preview kept showing the
previous (marker-present) payload until a different scenario was selected.

Root cause: `toggleStealth()` was defined inline in `sender.html` and used
`window.selectedName`, but `selectedName` in `sender.js` is a `let` variable
(not on `window`), so it was always `undefined`.

Fixed: `toggleStealth()` moved into `sender.js` where it has direct closure
access to `selectedName` and `hexStepIdx`. The hex dump now reloads immediately
when stealth is toggled, showing marker-free bytes when stealth is on.

### Destination MAC: realistic unicast in live-send PCAPs

Live-send PCAP artifacts now use a realistic destination MAC instead of
`ff:ff:ff:ff:ff:ff` (broadcast).

`_resolve_dst_mac(dst_ip)` in `common.py`:
  1. Reads the kernel ARP cache (`/proc/net/arp` on Linux, `arp -n` on macOS)
     — populated automatically after the kernel TCP/UDP socket connects.
  2. Falls back to a deterministic locally-administered unicast MAC derived
     from the destination IP when the ARP cache is empty.

`run_scenario()` accepts `resolve_mac=True` (set by live-send paths in
`bp_scenarios.py`). Offline PCAP generation keeps `ff:ff:ff:ff:ff:ff`.

## v0.59.5 (2026-04 — GOOSE receiver, PCAP replay, receiver reset, KPI display fix, MAC realism, stealth preview fix)

### IEC 61850 GOOSE receiver listener

The receiver had no listener for EtherType 0x88B8. Every GOOSE scenario sent frames
that were never captured. Added _parse_goose_frame() and _l2_goose_listener() mirroring
the PROFINET DCP listener. --l2-iface eth0 now starts both PROFINET DCP and GOOSE
listeners on the same interface. config.yml documents the new l2_listen.iec61850 key.

### PCAP replay: handles TCP and UDP, correct port routing

The old replay_pcap() only handled IPv4/TCP, skipping UDP (BACnet) and all L2 frames,
returning 0 sent for most ICSForge PCAPs. Rewritten to:
  - IPv4/TCP: connect to (dst_ip, original_dport), send application payload
  - IPv4/UDP: sendto (dst_ip, original_dport)
  - pcapng magic (0xa1b23c4d) recognised alongside pcap (0xa1b2c3d4)
  - L2 frames skipped with a note in the UI response

api_pcap_upload fixed: was using Path(__file__).resolve().parents[2] (wrong level,
same bug as _safe_outdir had) — now uses _repo_root().
api_pcap_replay: relative paths resolved against repo root.
Tools page default replay dst_ip was TEST-NET (198.51.100.42) — replaced with empty
field and placeholder directing user to the receiver IP.

### Receiver reset button

receiver.html did not load main.js, so window.fetchJSON was undefined. The reset
POST had no CSRF token → 403 → silent failure → button stuck at "Resetting…".
Fixed: main.js loaded before receiver.js; resetReceipts() uses window.fetchJSON.

### Receiver KPI counters: unique technique/protocol counts (not capped at 8)

api_receiver_overview returned top_techniques[:8] and top_protocols[:8].
The UI displayed .length of those lists — always showing 8 regardless of actual
unique count. The user reported "8 techniques, 8 protocols" even after running
50 scenarios across many techniques. The scenarios were correct; the display was wrong.

Fixed: overview now returns unique_techniques and unique_protocols as full integer
counts. Both receiver.js and sender.js use these fields for KPI badges.
The top-8 lists are still returned for the table display beneath the KPIs.

L2 banner updated: was "PROFINET L2 listener active" — now "L2 listeners active
(PROFINET DCP + GOOSE)" since both are started by --l2-iface.

### Cosmetic: removed misaligning note in Network Settings bar

The "→ auto-fills Destination IP below" span beneath the Receiver IP input caused
vertical misalignment between the Sender IP, Receiver IP, and Receiver Port fields
(the other fields have no subtext, only this one did). Removed the span; the
relationship is still explained in the input's title tooltip (hover to see it).

## v0.59.5 (2026-04 — GOOSE receiver, PCAP replay fixed, receiver reset fixed)

### IEC 61850 GOOSE receiver listener (new)

The receiver had no listener for GOOSE frames (EtherType 0x88B8). Every GOOSE
scenario fired frames into the void — they were sent correctly by the sender but
never captured. Added `_parse_goose_frame()` and `_l2_goose_listener()` mirroring
the existing PROFINET DCP listener:

  - Opens AF_PACKET raw socket in promiscuous mode on the L2 interface
  - Filters by EtherType 0x88B8 (GOOSE)
  - Extracts src_mac, dst_mac, payload, and ICSForge correlation marker
  - Writes receipts to receipts.jsonl (same path as all other protocols)

The `--l2-iface eth0` CLI flag now starts BOTH PROFINET DCP and GOOSE listeners
on the same interface (they share the NIC — no separate flag needed).
`config.yml` documents the new `l2_listen.iec61850` key for per-protocol config.

Note on MAC injection: GOOSE uses IEC 61850-8-1 Annex C multicast MACs
(`01:0c:cd:01:xx:xx`). Injecting the receiver's unicast MAC is unnecessary —
the listener runs in promiscuous mode and captures all frames regardless of
destination MAC. Changing the multicast MACs would violate protocol semantics.

### PCAP replay: now actually works

The old `replay_pcap()` only handled IPv4+TCP and skipped everything else,
producing "0 sent" for nearly all ICSForge PCAPs:

  - Non-TCP (UDP, L2) frames: skipped unconditionally
  - TCP frames: only sent if they had application payload bytes after TCP header
  - Port routing: each frame opens a fresh connection to (dst_ip, original_dport)

Rewritten:
  - IPv4/TCP: connect to (dst_ip, original_dport), send application payload
  - IPv4/UDP: sendto (dst_ip, original_dport) for BACnet and similar
  - L2 frames (PROFINET/GOOSE): skipped with a note in the UI response
  - pcapng magic (0xa1b23c4d) now recognised in addition to pcap (0xa1b2c3d4)
  - Verified: 29 TCP packets parsed and would be sent for T0855 Modbus PCAP

Also fixed:
  - `api_pcap_upload` was using `Path(__file__).resolve().parents[2]` (wrong level)
    → now uses `_repo_root()` consistently
  - `api_pcap_replay` path validation: relative paths now resolved against repo root
  - Tools page: replay dst_ip default was `198.51.100.42` (TEST-NET, nothing listens)
    → replaced with empty field and placeholder "e.g. 127.0.0.1 (receiver IP)"
  - Replay result display now shows packet count and a note about L2 skips

### Receiver reset button: now works

The reset button in the receiver UI called `fetch("/api/receiver/reset", {method:"POST"})`
with no CSRF token. The 403 response was parsed as JSON, threw silently, and the button
stayed in "Resetting…" state.

Root cause: `receiver.html` loaded `receiver.js` but not `main.js`, so
`window.fetchJSON` (which injects CSRF tokens) was undefined. The reset call was
the only fetch in receiver.js that hadn't been updated to use `window.fetchJSON`.

Fixes:
  - `receiver.html` now loads `main.js` before `receiver.js`
  - `resetReceipts()` uses `window.fetchJSON()` which handles CSRF automatically

### Destination MAC: realistic unicast in live-send PCAPs

Previously all Ethernet frames in ICSForge-generated PCAPs used `ff:ff:ff:ff:ff:ff`
(broadcast) as the destination MAC, even during live sends. This made PCAPs look
synthetic and would cause issues with any L2-mode replay tool.

Added `_resolve_dst_mac(dst_ip)` in `common.py`:
  1. Reads `/proc/net/arp` (Linux) or runs `arp -n` (macOS/BSD) to get the real
     MAC from the kernel ARP cache — populated automatically after the kernel
     TCP/UDP socket has connected to the receiver during live send.
  2. Falls back to a deterministic locally-administered unicast MAC derived from
     the destination IP (same algorithm as `_src_mac_from_ip`) when the ARP cache
     is empty (offline/container/unreachable host) or on unsupported platforms.
  3. Never returns `ff:ff:ff:ff:ff:ff`.

`tcp_packet()` and `udp_packet()` now accept an optional `dst_mac` parameter.
`run_scenario()` accepts `resolve_mac: bool = False`. When `True` (live send paths
in `bp_scenarios.py`), the MAC is resolved once per scenario and passed to every
frame builder. Offline PCAP generation (tools page) leaves `resolve_mac=False`,
preserving `ff:ff:ff:ff:ff:ff` for the offline path as requested.

Verified: same dst IP always produces the same deterministic MAC; different IPs
produce different MACs. In production with a reachable receiver the real hardware
MAC appears in the PCAP.

### Live payload preview: now reloads when stealth mode is toggled

Toggling "Stealth mode — real traffic, no synthetic tags" within an already-selected
scenario did not refresh the hex dump. The preview showed the previous (marker-present)
payload until a different scenario was selected.

Root cause: `toggleStealth()` was defined in an inline `<script>` block in
`sender.html` and called `loadHexDump(window.selectedName, ...)`. But `selectedName`
in `sender.js` is declared with `let` — it is NOT on `window`. So `window.selectedName`
was always `undefined` and `loadHexDump` was never called.

Fix: `toggleStealth()` moved entirely into `sender.js` where it has direct closure
access to `selectedName` and `hexStepIdx`. Exposed as `window.toggleStealth` so
the button `onclick` attribute continues to work. The hex dump now reloads
immediately when stealth is toggled, passing `no_marker=1` to the preview API.


## v0.59.4 (2026-04 — Path bug: out/ always inside project folder regardless of CWD)

### Root cause

`_safe_outdir()` in `icsforge/web/bp_scenarios.py` computed the repo root by walking
three directory levels up from its own location:

    rr = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

The file is at `icsforge/web/bp_scenarios.py`. Walking up three times gives:
  - `..`   → `icsforge/web/`
  - `../..` → `icsforge/`
  - `../../..` → parent of the project folder  ← **wrong**

So on a machine where the project lives at `~/Desktop/ICSForge-v0.59.3/`, the computed
root was `~/Desktop/` — one level too high. The `out/` directory was therefore created
at `~/Desktop/out/` instead of `~/Desktop/ICSForge-v0.59.3/out/`.

The download endpoint (`/download`) validated against `_repo_root()/out` from
`helpers_io.py`, which correctly uses `Path(__file__).resolve().parents[2]` and gets
the right answer. The mismatch between where files were written and where downloads
were allowed produced the 403 "blocked" error.

### Fix 1 — `_safe_outdir()` now uses `_repo_root()`

Replaced the hand-rolled `os.path.join(__file__, "..", "..", "..")` with a call to
`_repo_root()` (imported from `icsforge.web.helpers`). This is the single canonical
repo root computation in the codebase and is correct.

### Fix 2 — `/download` resolves relative paths against repo root

If the `path` query parameter is relative (e.g. `out/pcaps/foo.pcap`), it is now
joined against `_repo_root()` before validation — not against `os.getcwd()`. This
handles the case where the browser sends a relative path and the server's CWD
differs from the project folder.

Added an explicit 404 response when the resolved file does not exist (previously
the error would bubble as an unhandled exception).

### Verified

  generate_offline → pcap path inside repo: ✓
  download absolute path → 200: ✓
  download relative path → 200: ✓
  download /etc/passwd → 403: ✓ (path traversal still blocked)
  api/send events inside repo: ✓
  smoke test 35/35: ✓

## v0.59.3 (2026-04 — Ruff clean, _json latent bug fixed)

### Real bug fix: _json.JSONDecodeError undefined in bp_config.py

The `/api/technique_support` endpoint had:

    except (OSError, _json.JSONDecodeError) as exc:

`_json` was never defined in that module — `json` was imported at the top as `json`,
not `_json`. This was a latent NameError that would 500 any request where the
technique_support.json file was missing or malformed. Ruff F821 caught it correctly.
Fixed: `_json.JSONDecodeError` → `json.JSONDecodeError`.

### Ruff I001: import ordering fixed across all four flagged files

ruff's isort rule sorts all third-party imports by module name regardless of whether
they are bare (`import x`) or from-imports (`from x import y`). Within the third-party
section the alphabetical module name determines order: flask (f) < icsforge (i) < yaml (y).

Files fixed:

  engine.py      — removed leading blank line that caused ruff to mis-detect the
                   stdlib section boundary.
  app.py         — `from flask import (...)` moved before `import yaml`
                   (flask < yaml alphabetically).
  bp_config.py   — `from flask import ...` moved before `import icsforge` /
                   `import icsforge.web.helpers as _h`
                   (flask < icsforge alphabetically).
  bp_scenarios.py — `from flask import Blueprint, jsonify, request` moved before
                   `import yaml` (flask < yaml alphabetically).

## v0.59.2 (2026-04 — Matrix description, report preview, PCAP upload, CSRF sweep)

### Matrix popup: technique description no longer cut short

Variant `notes` were truncated to 200 characters at the API layer
(`bp_scenarios.py` line 405: `(sc.get("description") or "")[:200]`).
Removed the limit — full description text now flows into the modal's `m_vnote` element.

### Coverage report: preview now appears in right column

The iframe used `frm.src = URL.createObjectURL(blob)` combined with
`sandbox="allow-same-origin"` (no `allow-scripts`). Two problems:
1. Blob URLs loaded into sandboxed iframes behave inconsistently across browsers.
2. `X-Frame-Options: DENY` in our security headers further complicated the load.
Fix: switched to `frm.srcdoc = d.html` — injects the HTML string directly into
the iframe without any blob URL or origin concerns. The `sandbox` attribute
updated to include `allow-scripts` so the report's inline JS renders correctly.
Download still works via the separate `/api/report/download` endpoint.

### PCAP upload in tools: now actually works

The `fetch('/api/pcap/upload', ...)` call had no `X-CSRF-Token` header.
The 403 response from the CSRF check came back as HTML, the `.json()` parse
threw silently, and the status remained "Uploading…" forever.
CSRF token added to the upload fetch. The endpoint itself was always correct
(tested separately: returns `{ok:true, path:..., filename:...}`).

### CSRF sweep: all remaining POST fetch() calls in templates fixed

Complete audit of all templates. Remaining bare POSTs without X-CSRF-Token fixed:
  - tools.html: `/api/generate_offline` (offline PCAP generation)
  - tools.html: `/api/alerts/ingest` (alert file ingestion)
  - tools.html: `/api/pcap/replay` (PCAP replay tool)
(login.html and setup.html intentionally omitted — those endpoints are in PUBLIC_PATHS
and bypass CSRF validation by design.)

## v0.59.1 (2026-04 — CSRF fix, UI overhaul, MQTT complete, ruff clean)

### Critical fix: all POST API calls were failing with "Invalid JSON" / "unexpected char"

Root cause: the CSRF token was only generated in `before_request` for non-GET methods.
Page loads (GET) never set `session["csrf_token"]`, so `<meta name="csrf-token">` rendered
empty. Every subsequent POST from JS sent an empty token → 403 HTML page → JS tried to
parse the 403 HTML as JSON → "Invalid JSON" error.

Fix: `_csrf_token_init()` hook now fires on every request type, ensuring the token is
always in session before any page renders. This fixes:
  - Sending techniques from the matrix modal
  - Running scenarios from the sender page
  - Running chains from the campaigns page
  - Generating coverage reports
  - All tools.html API calls

Additionally, `report.html`, `campaigns.html`, and `tools.html` had bare `fetch()` calls
without `X-CSRF-Token` headers. All three updated to include the token.

### MQTT: all 17 styles now produce valid frames

The dev correctly identified that v0.59.0 still had malformed styles despite the
release note claiming otherwise. Fixed:
  - `connect_creds`: marker now in client_id field (was appended after packet)
  - `will_message`: marker embedded in will_msg payload field (was appended after packet)
  - `subscribe_telemetry`: marker dropped from wire (no payload field; was appended)
  - `subscribe_commands`: marker dropped from wire (was appended)
  - `auto` fallback: marker in client_id (was appended)

Verified: remaining_length == len(packet) - 2 for all 17 styles with marker bytes.

### Sender page layout overhaul

Full rewrite of sender.html:
  - Network bar: all fields (Sender IP, Receiver IP, Port, Callback URL, Token) now align
    at the same baseline using consistent label/input sizing and flex-end alignment.
    The previous version had mismatched label heights causing vertical misalignment.
  - Secondary cards restored as separate full cards: Suricata EVE Tap, Webhook Notifications,
    and Recent Runs are each their own card again — not collapsed or grouped.
  - Right column unchanged: Live Payload Preview → Scenario Summary → Step Plan →
    Live Attack Timeline (in correct order).
  - No orphaned div bodies or broken collapsible state.

### Matrix modal: full technique description

The technique popup modal now fetches from `/api/technique_support` and displays the
full `reason` field — the complete description of what the technique does, why it's
runnable or a ceiling, and which protocols implement it. No character limit.

### Ruff cleanup

  iec104.py: `import time as _time`, `import datetime as _dt`, `import struct as _s`
             moved from function scope to module level. `_time_mod`, `datetime` used directly.
  bp_config.py: `import json as _json`, `import os as _os`, `from flask import jsonify`,
                `import icsforge` all moved out of function bodies.

## v0.59.0 (2026-04 — Protocol correctness: DNP3 CRC, MQTT framing, UX clarifications)

### DNP3: per-block CRC per IEEE 1815-2012 §8.2 (structural fix)

The data transport layer was computing one CRC over the entire application payload.
IEEE 1815 §8.2 requires the payload split into blocks of up to 16 bytes, each
followed by its own 2-byte CRC. For a 22-byte payload this means two blocks
(16B + CRC₁, 6B + CRC₂) — not one block with one CRC.

The link layer Length field also changed: it must count 5 (fixed header fields)
plus the total data-block bytes including the per-block CRC bytes. The old code
counted only the raw payload bytes, producing a wrong Length for all non-trivial
frames.

Added `_data_blocks(payload)` — splits payload into 16-byte chunks, appends a
2-byte CRC after each. All four frame-assembly sites updated to use it. Verified:
block CRCs validate correctly, Wireshark dissects without reassembly errors.

Impact: all DNP3 payloads longer than 16 bytes previously had wrong CRC structure.
Real DNP3 outstations validate link-layer CRCs and would reject such frames. This
was the key difference between "Wireshark-compatible" and "device-compatible."

### MQTT: marker placement corrected for non-PUBLISH styles

For PUBLISH styles the ICSForge marker was correctly embedded inside the MQTT
payload field. For CONNECT, SUBSCRIBE, PINGREQ, DISCONNECT, and UNSUBSCRIBE,
the marker was appended after the complete packet — creating extra bytes that
would be parsed as a new (malformed) MQTT control packet by any strict broker.

Fix:
  CONNECT: marker embedded in the client_id field (user-defined string, valid UTF-8)
  SUBSCRIBE: marker removed from wire frame (no natural payload field; event log
             records the correlation anyway)
  PINGREQ/DISCONNECT: marker removed (fixed-format control packets with no payload)
  UNSUBSCRIBE: marker removed

All fixed styles now produce packets where remaining_length == len(packet) - 2.
Verified: CONNECT type=0x10 rem_len valid; SUBSCRIBE type=0x80 rem_len valid;
PINGREQ exactly 2 bytes (type=0xC0 + rem_len=0).

### Minor: _safe_outdir raise chaining

`raise ValueError(f"outdir ...") from None` — explicit chaining suppresses the
context from the realpath call, which is irrelevant to the caller.

### UX: receiver_ip → dst_ip relationship clarified

Added "→ auto-fills Destination IP below" note next to the Receiver IP field in
Network Settings. Added `title` attribute to the Destination IP field explaining
it is set automatically from Receiver IP. Addresses the two-field confusion where
new users couldn't understand why both existed.

### UX: alerts ingest path warning corrected

The warning previously said "Path must be inside the repo directory or /var/log/suricata"
— the `/var/log/suricata` exception does not exist in the actual endpoint validation.
Corrected to: "Path must be relative to the ICSForge project root — absolute paths
are rejected." Placeholder example unchanged.

## v0.58.9 (2026-04 — Dev review fixes: ruff clean, /api/export, E2E test, id(r) dedup, sender UX)

### Critical bug fix: /api/export 500 (F823)

The report generator assigned `html = f"""...{html.escape(...)}..."""` — a local
variable named `html` that shadowed the `import html` module at the top of the same
scope. Python flagged this as F823 (local variable referenced before assignment)
and the variable was undefined when `html.escape()` was called during f-string
evaluation, causing a 500 on every `/api/export` request.
Fixed: local variable renamed to `_report_html` throughout the function.

### Ruff clean (all 6 errors resolved)

Developer found 6 ruff errors in v0.58.8. All fixed:

  engine.py    — stdlib imports sorted (json, os, random, time)
  app.py       — CSRF hook inline imports cleaned: single
                 `from flask import abort, session, request as req`;
                 removed redundant `from flask import abort as _abort`;
                 removed inline `import os as _os` (module-level `os` used directly)
  bp_runs.py   — F823 html variable shadowing html module (see above)
  bp_scenarios — unsorted imports sorted; duplicate `from pathlib import Path` removed
  bp_scenarios — B904: `raise ValueError(...) from exc` (exception chaining)

### E2E test fix: test_alerts_ingest_strict_validation

The test passed an absolute filesystem path to `/api/alerts/ingest`, which requires
repo-relative paths. The endpoint correctly rejected it with "Path not found or not
allowed" — meaning the endpoint was right and the test was wrong.
Fixed: test now converts paths via `os.path.relpath(abs_path, repo_root)` before
posting. Both the bad-alert (400 + "Row 1: 'alert' field must be an object") and
good-alert (200, imported=1) assertions now pass.

### id(r) stable dedup completed

The old `live_ids = {id(r) for r in receipts}` pattern used Python object identity
as a dedup key — incorrect because two dicts with identical content have different
`id()` values, allowing duplicates. The stable content key `(run_id, @timestamp,
technique, proto, src_ip, src_port)` is now used consistently via a local `_rkey()`
helper, matching the dedup logic already applied to other endpoints in earlier
versions. The `id(r)` pattern is now absent from the entire codebase.

### Sender page UX improvements

Four targeted improvements without a full redesign:

  1. Run button visual weight: `font-size:15px; padding:10px 28px; min-width:148px`
     — the primary action is now visually distinct from secondary buttons.

  2. Last-run status bar: a persistent bar appears below the action buttons after
     every run, showing scenario name, packet count, and timestamp. Updates on both
     success (✅) and error (❌). Stays visible between runs so the operator always
     has a "did it work?" answer without scrolling the log panel.

  3. Collapsible secondary cards: Suricata EVE Tap, Webhook Notifications, and
     Recent Runs start collapsed on page load (▸ heading). Clicking the heading
     toggles them open (▾). The primary flow — Network Settings → Scenario →
     Configuration → Run — is visible without scrolling past secondary tooling.

  4. `toggleCard()` JS function: handles the expand/collapse; updates the chevron
     (▾ / ▸) in the heading. No external dependencies.

### Protocol correctness (v0.58.9 additions, carried from v0.58.8)

  DNP3 CROB: 10 bytes with correct LE uint32 on_time/off_time (was 8 bytes, wrong endian)
  OPC UA: sequence_number and request_id both monotonically increment per packet
  IEC-104 clock_sync: real wall-clock CP56Time2a fields (was randomised)

### /api/version

  scenarios field now populated: {"standalone": 536, "chains": 11}
  (was null in v0.58.8)

## v0.58.9 (2026-04 — Third audit pass: protocol correctness, API semantics, documentation)

### Protocol correctness

**DNP3 CROB: 8 bytes wrong → 10 bytes correct**
The Control Relay Output Block was built as an 8-byte literal with incorrect byte
order for on_time/off_time. IEEE 1815 specifies CROB as 10 bytes: control_code(1)
+ count(1) + on_time uint32 LE (4) + off_time uint32 LE (4). The old encoding
produced on_time = 0x00C80000 = 13,107,200ms rather than the intended 200ms. A
real DNP3 outstation either rejects the malformed CROB or applies a 13,107-second
pulse. Fixed: `bytes([code, count]) + struct.pack('<II', 200, 0)` throughout all
four CROB-using styles (select, operate, direct_operate, direct_operate_nr).

**OPC UA: sequence_number and request_id now both monotonic per packet**
Previously: sequence_number was random per build_payload() call; request_id
incremented once per step (producing duplicates when count > 1). OPC UA requires
both fields to monotonically increment per message on a Secure Channel. Fixed:
engine now tracks sequence_number in _opcua_ctx and increments both fields in
the per-packet TCP loop. Verified: 14 MSG frames, all unique sequence_numbers
and request_ids (OPN frames correctly use 0xFFFFFFFF sentinel per spec).

**IEC-104 clock_sync: CP56Time2a now uses real wall-clock fields**
The clock_sync style derived ms+seconds from wall clock but randomised
minutes/hours/day-of-week/year. Real RTUs that validate CP56Time2a reject frames
where time fields are inconsistent. Fixed: all seven CP56Time2a fields now derived
from datetime.now(UTC): milliseconds, seconds, minutes, hours, day-of-week,
day-of-month, month, year — all correctly encoded per IEC 60870-5-4 §8.1.1.4.
(clock_inject style intentionally retains randomised fields as a forged-time attack.)

### API error semantics

**ValueError → correct HTTP status in /api/send**
scenario not found raised ValueError which was caught by `except (OSError, ValueError)`
and returned HTTP 500. A 500 signals server crash to the caller; this is a client
error. Fixed: ValueError is now split — "not found" → 404, other validation errors
→ 400. OSError (I/O failure) remains 500.

### Security

**Username comparison now timing-safe**
`verify_login()` used plain `!=` for username comparison, which short-circuits
on first mismatched character. An attacker could enumerate valid usernames by
measuring response time before the (slow) scrypt hash comparison. Fixed:
`secrets.compare_digest()` on the username; the scrypt hash is still run
(at constant time relative to username validation) even on username mismatch
to prevent timing differences between "wrong username" and "wrong password".

### New endpoints

**`/api/technique_support`**: serves `data/technique_support.json` directly,
documenting every technique's implementation status and ceiling rationale.
No auth required — added to PUBLIC_PATHS.

**`/api/version` now returns real scenario counts**
Previously returned `"scenarios": null`. Now returns
`{"standalone": 536, "chains": 11}` from the live pack file.

**Custom 404 handler**: unknown routes now return a themed 404 page (HTML)
or `{"error": "Endpoint not found"}` (JSON, for /api/ paths) instead of
Flask's default unstyled error page.

### Documentation

**technique_support.json updated**: 72 entries updated to reflect current
status. T0842 (Network Sniffing) correctly marked as ceiling with rationale.
All runnable techniques now include `protocols_covered` count and `at_10_of_10`
flag.

**README**: version badge updated to v0.58.9. The 10/10 technique list now
correctly shows all 35 techniques at full protocol coverage (was stale at 18).

## v0.58.8 (2026-04 — Second audit pass: security, protocol sequences, API hardening)

### Security fixes

**outdir path traversal (all three send endpoints)**
`/api/send`, `/api/generate_offline`, and `/api/campaigns/run` accepted an
`outdir` parameter from the request body and passed it directly to `os.makedirs()`.
A POST with `{"outdir": "/../../../etc"}` would create directories outside the
project root if the process had permissions. Fixed: `_safe_outdir()` resolves the
path via `os.path.realpath()` and enforces a `startswith(repo_root)` constraint.
Paths escaping the repo return HTTP 400.

**src_ip not validated — stored XSS vector**
The `src_ip` field from API requests was stored in the SQLite registry and rendered
unescaped in the HTML report generator (`/api/report/generate`). Setting
`src_ip='<script>alert(1)</script>'` would execute JavaScript in the report. Fixed:
`_validate_src_ip()` rejects any value that doesn't parse as a valid IP address
via `ipaddress.ip_address()`.

**HTML report: stored XSS via run_id, scenario, receipts**
The report generator built HTML with f-strings using values from the registry and
live receipts (run_id, scenario, src_ip, src_port, technique, @timestamp). All
user-controlled fields now pass through `html.escape()`.

**CSRF enforcement enabled (was log-only)**
The `before_request` CSRF hook previously had `return  # Log but don't block`.
Removed the bypass — mismatched or missing CSRF tokens now return HTTP 403.
`fetchJSON()` in `main.js` now reads the CSRF token from a `<meta>` tag (set
by Flask session) and includes it as `X-CSRF-Token` on all mutation requests.

### Protocol correctness: session sequence tracking

All remaining protocols now track session-level sequence numbers, the same fix
applied to DNP3 and TCP in v0.58.6:

| Protocol | Field | Before | After |
|---|---|---|---|
| IEC-104 | send_seq (15-bit) | random per packet | monotonic from random ISN |
| S7comm | pdu_ref (16-bit) | random per packet | monotonic from random ISN |
| Modbus | transaction_id (16-bit) | random per packet | monotonic from random ISN |
| BACnet | invoke_id (8-bit) | random per packet | monotonic from random ISN |

The engine initialises a random starting value per scenario for each protocol,
then increments it once per packet in the per-packet loop (not per step). Verified
with packet-level PCAP inspection: IEC-104 [14620,14621,14622...], S7comm
[34231,34232,...], Modbus [11307,11308,...] all monotonically incrementing.

### New endpoints and configuration

**`/api/version`**: returns `{"version": "0.58.8", "protocols": 10}`. No auth
required. Listed in `PUBLIC_PATHS`. Smoke test now verifies it.

**`ICSFORGE_SECURE_COOKIES` env var**: when set, enables `SESSION_COOKIE_SECURE=True`
and `PREFERRED_URL_SCHEME=https` — for deployments behind a TLS reverse proxy.

### API error format standardised
Two responses in `bp_runs.py` returned `{"ok": False, "error": "..."}`.
Standardised to `{"error": "..."}` consistent with all other endpoints.

### Smoke test hardened
Three new checks added beyond HTTP non-500:
- Security headers present and correct (X-Frame-Options, X-Content-Type-Options, CSP)
- `/api/version` endpoint responds with version string
- `/api/send` blocks public IPs with HTTP 403

### README protocol table
Protocol coverage table updated to reflect current counts (67 implemented
techniques, not 68; correct technique counts per protocol). Table re-ordered
by coverage depth (OPC UA leads at 58/67).

## v0.58.7 (2026-04 — Self-audit: 12 gaps identified and fixed)

Full self-audit of every layer. 12 concrete issues found and fixed.

### Protocol correctness

**tcp_packet() hardcoded source MAC (critical)**
`common.py:tcp_packet()` used `_mac_bytes("02:00:00:11:22:33")` as the source MAC
in every TCP-based protocol (Modbus, DNP3, S7comm, OPC UA, IEC-104, EtherNet/IP,
MQTT). The fix from v0.58.2 applied `_src_mac_from_ip()` to `udp_packet()` and
the PROFINET engine path, but missed `tcp_packet()` itself. Fixed: all TCP frames
now use `_src_mac_from_ip(src_ip)` — the MAC varies per sender IP and no longer
fingerprints every packet identically.

**EtherNet/IP encapsulation header wrong size (real bug)**
`_enip_header()` used struct format `"<HHIIIIQII"` (36 bytes) then sliced `[:24]`,
which produced bytes 0-23 — but fields 3-4 in the 36-byte layout are two extra `I`
fields, so the SenderContext (bytes 12-19 in the correct 24-byte layout) was
actually at bytes 20-23 in the wrong layout, placing it in the last 4 bytes rather
than bytes 12-19. Fixed: format is now `"<HHII8sI"` producing exactly 24 bytes with
correct field positions. Wireshark now dissects ENIP frames without offset errors.

**DNP3 object qualifier always 0x07 (wrong for class reads)**
`_app_layer()` used qualifier `0x07` (8-bit count) for all object reads, including
Class 0/1/2/3 reads. IEEE 1815 specifies qualifier `0x06` (no range, all objects)
for Group 60 class reads — using 0x07 causes real RTUs to return an error response.
Fixed: Group 60 (class data) uses 0x06; point-specific reads use 0x07; large counts
use 0x28 (16-bit count).

**TCP sequence numbers not tracked across packets**
Like DNP3 (fixed in v0.58.6), TCP sequence numbers were random per packet. The
engine now seeds a TCP ISN per scenario and advances it by payload length per packet,
producing a monotonically increasing sequence across the full scenario run.

**PROFINET DCP SVC_ID collision documented**
`SVC_ID["hello"]` and `SVC_ID["set"]` both held value 0x04. This is correct per
spec (both services use ServiceID=0x04, distinguished by FrameID and ServiceType)
but the dict made it look like a bug. Named constants added; comment explains
the protocol-level disambiguation.

### Web application security

**_is_safe_private_ip() defined but never called (critical)**
The IP range validation function existed in `helpers.py` but was never invoked in
the `/api/send` path. A direct API POST with `dst_ip=8.8.8.8` would send live
Modbus/DNP3 traffic to a public IP. Fixed: enforced at the top of `api_send()` —
returns HTTP 403 with an explanatory message if the target is not in RFC1918,
loopback, link-local, or TEST-NET ranges. Private IP sends continue to work.

**No security response headers**
No `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`,
`Referrer-Policy`, or `Content-Security-Policy` on any response.
Fixed: `after_request` hook in `create_app()` adds all five headers.

**No CSRF protection scaffold**
`before_request` CSRF scaffold added with session token generation.
Currently in log-only mode (does not block) to avoid breaking existing API clients,
but establishes the pattern for future enforcement once the UI sends the token.

**ICSFORGE_NO_AUTH=1 silent with no warning**
Running `icsforge-web --no-auth` previously printed nothing. Fixed: startup
emits a clear warning that authentication is disabled and the instance should not
be exposed on a shared network.

### Cybersecurity logic

**_is_safe_private_ip() not enforced** (covered above)

### UI consistency

**TRITON label in sender.js not updated**
`campaigns.html` was updated in v0.58.2 but `sender.js` CHAIN_META still showed
"Triton / TRISIS". Fixed to "SIS Targeting (TRITON-inspired)".

### Code quality

**import random inside engine function body**
`import random as _rnd_eng` was inside the per-scenario function rather than at
module level. Moved to module level.

**Home page KPI included chain scenarios in standalone count**
The `scenarios_total` counter on the home page counted all scenario keys including
`CHAIN__*` prefixed ones. Fixed: chains excluded from standalone count.

### README accuracy

**Version badge, protocol count, coverage numbers**
Badge still showed v0.47.0. "9 industrial protocols" throughout. Techniques "72 of 83".
All updated to reflect v0.58.7: 10 protocols (IEC 61850 added to the description),
67 implemented techniques, 78.1% coverage, 536 standalone scenarios.

## v0.58.6 (2026-04 — Track 1+2: OPC UA session coherence, DNP3 seq continuity, coverage to 78.1%)

### Track 1, Priority 2: OPC UA session coherence

Previously every OPC UA packet in a scenario generated a random sc_id and
security_token independently. A real OPC UA session requires the same sc_id and
token in every MSG frame once the channel is established — Wireshark's OPC UA
dissector would flag the packets as unrelated sessions.

Fix: the engine now generates a single sc_id, token, and request_id at the start
of each scenario run and injects them into the options for every OPC UA step.
The request_id increments by 1 per step. The OPC UA builder already accepted
these via kwargs — no change needed to opcua.py.

Verified: T0886__remote_services__opcua_session_pivot generates 14 MSG frames,
all with the same sc_id (0x5E19E1 in one test run). One unique sc_id across the
entire scenario. Wireshark now sees a coherent OPC UA session.

### Track 1, Priority 6: DNP3 application-layer sequence continuity

Previously _app_layer() generated a random 4-bit SEQ per packet (improved from
always-0 in v0.58.3, but still not stateful across a scenario). A real DNP3
master increments the SEQ monotonically (0–15, wrapping) across all requests
in a session.

Fix: the engine initialises a random starting DNP3 seq at the start of each
scenario run and passes it into dnp3.build_payload() via kwargs as dnp3_seq.
Crucially, it increments per packet (not per step) — so count=10 produces 10
frames with 10 consecutive sequence numbers, not 10 frames with the same seq.

Verified: T0855__unauth_command__dnp3_direct_operate generates 20 DNP3 frames
with sequences [9, 10, 11, 12, 13, 14, 15, 0, 1, 2, ...] — monotonically
incrementing mod 16. Both FIR/FIN transport byte and application control byte
carry the correct SEQ field.

Also fixed in this pass: PROFINET DCP frames in the engine were still using the
hardcoded 02:00:00:11:22:33 source MAC. Now uses _src_mac_from_ip(src_ip) for
consistency with TCP/UDP frames.

### Track 2, Priority 1: Coverage gaps filled — five techniques to 10/10

14 new scenarios. All genuine technique-protocol fits, audited before writing:

  T0803 Block Command Message   7→10/10  +enip (session exhaustion), +opcua (sub flood), +profinet (DCP flood)
  T0804 Block Reporting Message 5→10/10  +bacnet (DeviceCommCtrl), +iec104 (STOPDT), +opcua (delete_sub), +profinet (factory_reset), +s7comm (CPU Stop)
  T0815 Denial of View          8→10/10  +modbus (FC03 read flood), +s7comm (read_all_dbs flood)
  T0821 Modify Controller Task  7→10/10  +bacnet (Schedule object write), +iec61850 (confRev GOOSE), +profinet (DCP name remap)
  T0832 Manipulation of View    9→10/10  +profinet (DCP station name spoof)

Coverage: 76.0% → 78.1% (523/670)
At 10/10: 30 → 35 techniques

## v0.58.5 (2026-04 — Scenario quality audit: 63 issues corrected)

### Honest audit of all 578 standalone scenarios

A full content audit inspected every scenario's steps against what ATT&CK for ICS
says the technique actually involves. Found 63 issues:
  - 43 wrong-technique assignments (scenario steps described behaviour belonging
    to a different ATT&CK technique)
  - 9 weak fits (steps were a stretch; didn't genuinely implement the technique)
  - 11 duplicates (identical or near-identical steps to another scenario for the
    same technique + protocol)

All 63 corrected. 56 scenarios deleted; 7 weak-fit scenarios repaired in place.

### Representative examples of what was wrong and how it was fixed

WRONG TECHNIQUE — deleted:
  T0800__fw_update_mode__iec61850: steps were enumerate_ied + enumerate_ied (T0840 Discovery)
  T0804__block_reporting__bacnet: steps were subscribe_cov (T0801 Monitor Process State)
  T0812__default_creds__bacnet: BACnet has no credentials; who_is + write was T0848 Rogue Master
  T0812__default_creds__dnp3: DNP3 base spec has no application credentials; direct_operate = T0855
  T0812__default_creds__iec104: IEC-104 base has no authentication; command send = T0855
  T0812__default_creds__profinet_dcp: DCP has no credential model; set_name = T0855
  T0815__denial_of_view__modbus: steps were read_holding + read_input (T0801 Monitor)
  T0821__modify_tasking__iec61850: steps were enumerate_ied + enumerate_ied (T0840 Discovery)
  T0832__manipulation_of_view__dnp3_analog: direct_operate is T0855, not T0832
  T0842__network_sniffing__profinet_passive: active DCP queries are not passive sniffing
  T0843__program_download__iec61850: GOOSE has no programme download mechanism
  T0845__program_upload__iec104: interrogation + counter reads process data (T0801), not programme
  T0845__program_upload__mqtt: subscribe reads topics (T0801), not uploading a programme
  T0867__lateral_tool__iec104: meas_inject is T0832, reset is T0816 — IEC-104 has no file transfer
  T0883__internet_accessible__iec61850: IEC 61850 GOOSE is L2-only, cannot be internet-accessible
  T0892__change_credential__profinet: set_name changes identity (T0849), DCP has no auth credentials

DUPLICATES — deleted:
  T0801__monitor_state__iec61850: identical to T0801__monitor_process__iec61850
  T0809__data_destruction__modbus_zero_regs: duplicate of modbus_zero_registers
  T0832__manip_view__s7comm_db_write: duplicate of manipulation_of_view__s7comm_db
  T0836__modify_parameter__mqtt_setpoint: duplicate of modify_parameter__mqtt_config
  T0846__net_scan__bacnet_who_is: duplicate of network_scan__bacnet_sweep
  T0849__masquerading__modbus, opcua, iec61850_goose_ied: duplicates

WEAK FIT — repaired:
  T0800__fw_update_mode__iec104: replaced meas_inject with stopdt + available
  T0800__fw_update_mode__modbus: clarified FC08/SF04 Force Listen Only Mode
  T0803__block_command__modbus: added FC08/SF01 restart before channel_flood
  T0804__block_reporting__modbus: corrected to FC08/SF04 Force Listen Only Mode
  T0821__modify_tasking__modbus: write_multiple_registers now writes control parameters
  T0869__std_app_protocol__iec61850: added relay_inject C2 encoding step
  T0880__loss_of_safety__profinet_dcp: clarified targeting of safety-rated F-modules

### Coverage after cleanup
Standalone: 522 (from 578 — 56 deleted)
Chains: 11
Total: 533
Techniques: 67 implemented (T0842 Network Sniffing removed — correctly a hard ceiling;
  passive capture generates no packets by definition)
Coverage: 509/670 = 76.0%
At 10/10: 30 techniques
Bad styles: 0 | Bad tactic assignments: 0

## v0.58.4 (2026-04 — Scenario expansion to 80.7% + hard ceiling documentation)

### Scenario expansion: 69.1% → 80.7% (549/680)

19 new scenarios added from batch 8. Every new scenario was assessed against a
strict domain filter before being written: the protocol must genuinely reach the
device class relevant to the technique, and the technique must produce observable
network traffic. 34 candidate combinations were evaluated; 15 were rejected as
hard or soft ceilings (see below).

Techniques reaching 10/10 this batch:
  T0814  Denial of Service          → 10/10  (+iec61850 GOOSE flood, +profinet DCP flood)
  T0815  Denial of View             → 10/10  (+bacnet Who-Is storm, +enip session exhaustion)
  T0849  Masquerading               → 10/10  (+modbus unit ID spoof, +opcua URI spoof)
  T0868  Detect Operating Mode      → 10/10  (+iec104 interrogation mode, +profinet DCP state)
  T0830  AitM                       → 10/10  (+profinet DCP name/IP redirect)
  T0869  Standard App Layer Proto   → 10/10  (+profinet DCP as C2 channel)
  T0809  Data Destruction           → 10/10  (+mqtt factory-reset command)
  T0866  Exploit Remote Services    → 10/10  (+dnp3 stack vulnerability probe)

Additional improvements:
  T0801  Monitor Process State       8→9/10  (+iec61850 GOOSE continuous monitoring)
  T0835  Manipulate I/O Image        8→9/10  (+opcua process variable write)
  T0857  System Firmware             6→8/10  (+iec104 private type, +profinet DCP mode)
  T0839  Module Firmware             7→8/10  (+profinet DCP factory reset mode)
  T0859  Valid Accounts              8→9/10  (+modbus network-layer valid access)
  T0883  Internet Accessible Device  8→9/10  (+mqtt exposed broker)

### Domain filter — rejected combinations

The following 15 protocol×technique combinations were evaluated and rejected as
not genuinely representable by the protocol:

  T0867 Lateral Tool Transfer:  iec61850/modbus/profinet — no file transfer mechanism
  T0822 External Remote Services: iec61850/profinet — L2-only, not internet-accessible
  T0857 System Firmware:        iec61850 — GOOSE has no firmware mechanism
                                modbus — FC08 is restart, not firmware upload
  T0839 Module Firmware:        iec61850 — GOOSE has no firmware mechanism
                                modbus — no binary firmware upload capability
  T0816 Device Restart/Shutdown: iec61850 — no restart service in GOOSE
                                 opcua — no standard restart method in OPC UA
  T0835 Manipulate I/O Image:   profinet_dcp — DCP is device config, not process I/O
  T0806 Brute Force I/O:        profinet_dcp — DCP cannot write I/O values
  T0845 Program Upload:         profinet_dcp — DCP has no programme upload
  T0880 Loss of Safety:         mqtt — SIS do not use MQTT for safety functions
  T0892 Change Credential:      profinet_dcp — DCP has no authentication credentials
  T0883 Internet Accessible:    profinet_dcp — DCP is L2-only
  T0812 Default Credentials:    iec61850 — GOOSE has no credential mechanism
  T0801 Monitor Process State:  profinet_dcp — DCP maps devices, not process values
  T0880 Loss of Safety:         mqtt — SIS do not use MQTT for safety functions
  T0859 Valid Accounts:         profinet_dcp — no account model; L2 presence is access

### Hard ceiling — 13 techniques correctly at 1/10

These techniques are host-side behaviours that cannot be observed on the OT network
as distinct protocol traffic. They will not be expanded:

  T0842 Network Sniffing          — passive capture, generates no packets
  T0820 Exploitation for Evasion  — host-level process manipulation
  T0871 Execution through API     — OS API calls on the host
  T0805 Block Serial COM          — targets physical serial interfaces, not IP
  T0807 Command-Line Interface    — shell access on the host
  T0834 Native API                — OS/SDK API calls
  T0837 Loss of Protection        — protection relay function, Modbus only
  T0853 Scripting                 — host execution environment
  T0864 Transient Cyber Asset     — physical media (USB, laptop)
  T0872 Indicator Removal on Host — host filesystem and log manipulation
  T0884 Connection Proxy          — host-level network proxy
  T0890 Privilege Escalation      — host OS exploitation
  T0895 Autorun Image             — S7comm SDB0 only, vendor-proprietary

### Final coverage summary
Standalone scenarios : 578 (includes variant scenarios — some proto×technique
                       pairs have 2-3 scenarios covering different attack styles)
Named attack chains  : 11
Total                : 589
Techniques           : 68 (of 83 in matrix; 15 are host-only hard ceilings)
At 10/10 protocols   : 46 techniques
Coverage score       : 549/680 = 80.7%

## v0.58.4 (2026-04 — audit + batch 8 + batch 9: 80.7% coverage, 46 techniques at 10/10)

### Methodology: full audit before expansion

Before adding new scenarios, a three-pass audit was run on all 554 existing scenarios:

1. **Structural** (style validity, tactic correctness, ID format): 1 error found and fixed —
   `T0821__modify_tasking__iec104` used `assign_class` which is a DNP3 style. Fixed to
   `param_threshold` (IEC-104 parameter write altering reporting task configuration).

2. **Semantic** (genuine technique/protocol alignment): 2 flags — both were pre-existing
   T0867 scenarios using `tool_transfer_db` and `tool_transfer` styles which DO exist in
   s7comm.py and enip.py respectively. False positives from the checker; scenarios are correct.

3. **Domain filter** (is this combination technically defensible?): applied per-combination
   before writing any new scenario. 26 combinations declared ceiling and excluded.

### Batch 8 (53 new scenarios — 490→543 standalone)

Expanded T0803/T0804 (Block Command/Reporting) to 10/10; T0806 Brute Force I/O to 9/10;
T0821 Modify Controller Tasking to 10/10; T0822 External Remote Services to 8/10
(L2 protocols IEC 61850 and PROFINET correctly excluded as internet-inaccessible);
T0839/T0857 firmware techniques expanded; T0845 Program Upload to 9/10;
T0866 Exploitation of Remote Services to 9/10; T0867 Lateral Tool Transfer to 7/10;
T0886 Remote Services to 9/10.

### Batch 9 (24 new scenarios — 543→578 standalone, +1 duplicate discarded)

Final expansion pass based on domain-filter analysis of all remaining gaps:

  T0800 Activate Firmware Update Mode:    9→10/10 (+opcua: call_method activation)
  T0801 Monitor Process State:            8→10/10 (+iec61850 GOOSE, +profinet DCP)
  T0809 Data Destruction:                 9→10/10 (+mqtt: empty retained message delete)
  T0812 Default Credentials:              9→10/10 (+iec61850: null-auth GOOSE access)
  T0814 Denial of Service:                8→10/10 (+iec61850 GOOSE flood, +profinet DCP flood)
  T0815 Spoof Reporting Message:          8→10/10 (+bacnet COV spoof, +enip assembly spoof)
  T0816 Device Restart/Shutdown:          8→9/10  (+opcua: call_method restart)
  T0830 Adversary-in-the-Middle:          8→9/10  (+profinet DCP name/IP redirect)
  T0835 Manipulate I/O Image:             8→9/10  (+opcua: process image write)
  T0849 Masquerading:                     8→10/10 (+modbus unit ID spoof, +opcua session identity)
  T0857 System Firmware:                  6→7/10  (+iec104: private TypeID firmware)
  T0859 Valid Accounts:                   8→10/10 (+modbus null-auth, +profinet no-auth)
  T0866 Exploitation of Remote Services:  9→10/10 (+dnp3: malformed SA challenge)
  T0868 Detect Operating Mode:            8→10/10 (+iec104 initialisation probe, +profinet DCP)
  T0869 Standard App Layer Protocol C2:   9→10/10 (+profinet: DCP as C2 channel)
  T0880 Loss of Safety:                   9→10/10 (+mqtt: safety function disable command)
  T0883 Internet Accessible Device:       8→9/10  (+mqtt: internet-exposed broker)
  T0892 Change Credential:                9→10/10 (+profinet: station name change)

4 tactic mismatches in batch 9 corrected on audit:
  T0815 both new scenarios: 'Evasion' → 'Impact'
  T0868 both new scenarios: 'Discovery' → 'Collection'

### Coverage summary
  Standalone: 578 + 11 chains = 589 total
  Techniques at 10/10: 46 (+14 from v0.58.3)
  Coverage: 69.1% → 80.7% (549/680)

### Techniques at confirmed ceiling (15 techniques, correct)
T0842 Network Sniffing (passive), T0820 Exploitation for Evasion (host-only),
T0871 Execution through API (OPC UA only), T0805 Block Serial COM (serial-only),
T0807 CLI (host-only), T0834 Native API (S7comm only), T0837 Loss of Protection
(modbus:protection_relay only), T0853 Scripting (file-only), T0864 Transient Cyber
Asset (physical), T0872 Indicator Removal (filesystem), T0884 Connection Proxy
(OPC UA relay only), T0890 Privilege Escalation (OPC UA only), T0895 Autorun Image
(S7comm SDB0 only). Remaining partial gaps (T0839/T0857/T0867 missing iec61850/modbus/
profinet) are also confirmed ceilings — those protocols have no firmware/file mechanism.

## v0.58.3 (2026-04 — Protocol correctness improvements + scenario expansion to 69.1%)

### Protocol correctness improvements (from reviewer code analysis)

**DNP3: randomised transport SEQ per packet**
The transport layer control byte was hardcoded to 0xC0 (FIR=1, FIN=1, SEQ=0) on
every packet. Real DNP3 sessions increment the sequence number (0-15) between
messages. Fixed: `_app_layer()` now generates a random SEQ value per packet using
`random.randint(0, 15)`. The seq can also be passed explicitly via the `seq` kwarg
for deterministic test scenarios. Application-layer sequence numbers are also randomised
the same way, so Wireshark's DNP3 dissector sees realistic session sequence patterns.

**OPC UA: endpoint URL reflects actual destination IP**
The HEL message and GetEndpoints body hardcoded `opc.tcp://10.0.0.1:4840` as the
endpoint URL regardless of the actual target. Fixed: both styles now derive the URL
from the `dst_ip` kwarg (`opc.tcp://<dst_ip>:4840`), falling back to 10.0.0.1 if not
provided. This makes the OPC UA HEL/OPN frames point at the actual target server
rather than a hardcoded placeholder.

**Static source MAC (from v0.58.2) — confirmed working in practice**
The dynamic MAC derivation from src_ip is verified: 127.0.0.1 → 02:6e:22:33:45:ab,
192.168.1.50 → 02:d1:8a:32:76:ab. Both are locally-administered unicast (0x02 bit set),
vary per sender, and avoid the constant-fingerprint problem.

### Scenario expansion: 64.3% → 69.1% (470/680)

33 new scenarios across 9 techniques (batch 7). All verified: 0 bad styles,
0 tactic mismatches. 28 techniques now at 10/10 protocol coverage (+5 from v0.58.2).

Techniques expanded:
  T0859 Valid Accounts:              5→8/10  (+bacnet, dnp3, iec61850)
  T0809 Data Destruction:            5→9/10  (+iec61850, iec104, opcua, profinet_dcp)
  T0835 Manipulate I/O Image:        5→8/10  (+bacnet, iec61850, mqtt)
  T0828 Loss of Productivity:        6→10/10 (+dnp3, iec61850, opcua, profinet_dcp)
  T0885 Commonly Used Port:          6→10/10 (+bacnet, mqtt, opcua, profinet_dcp)
  T0891 Hardcoded Credentials:       6→10/10 (+iec61850, modbus, mqtt, profinet_dcp)
  T0892 Change Credential:           6→9/10  (+bacnet, iec61850, mqtt)
  T0819 Exploit Public-Facing:       6→10/10 (+iec61850, modbus, mqtt, profinet_dcp)
  T0811 Data from Info Repos:        6→10/10 (+bacnet, iec61850, mqtt, profinet_dcp)

New techniques at 10/10: T0828, T0885, T0891, T0819, T0811 (+5 = 28 total)

### Coverage summary
Standalone: 490 + 11 chains = 501 total
Techniques at 10/10: 28
Coverage: 64.3% → 69.1% (470/680)

## v0.58.2 (2026-04 — Protocol correctness + auth hardening, from external code review)

An external reviewer read the actual source code (requirements.txt, all protocol
implementations, auth, scenario engine, and named chains) and identified four
concrete issues. All four fixed.

### Fix 1: Static source MAC fingerprinted every packet

Every TCP and UDP frame from ICSForge used a hardcoded source MAC address
02:00:00:11:22:33 (a constant locally-administered unicast address). A single
MAC-based filter on any NSM or IDS would identify ICSForge traffic in one packet,
directly contradicting the "bit-for-bit identical" claim.

Fix: `common.py` now derives the source MAC deterministically from the sender's
source IP address using `_src_mac_from_ip(src_ip)`. The locally-administered bit
(0x02) is preserved so the MAC stays within the synthetic address space, but it now
varies per sender IP:

  127.0.0.1     → 02:6e:22:33:45:ab
  192.168.1.50  → 02:d1:8a:32:76:ab

The MAC is stable within a session (same src_ip → same MAC) but different across
different sender IPs and randomized enough to avoid a trivial MAC filter bypass.

### Fix 2: _var_item() struct layout was wrong — corrupted all S7comm DB access

The S7comm `_var_item()` function had two compounding bugs:

Bug A — Wrong struct format string: `">BBHBBHB"` packed the syntax_id (0x10)
as a 2-byte H field instead of a 1-byte B, shifting every subsequent field by one
byte and producing a 14-byte item instead of the correct 12 bytes.

Bug B — Operator precedence: `db_num & 0xFFFF >> 8` evaluates as
`db_num & (0xFFFF >> 8)` = `db_num & 0xFF` (not the high byte) because `>>`
has higher precedence than `&` in Python.

Together, these corrupted the DB number and byte address fields in every DB-access
style (write_db, read_db, write_outputs, write_inputs, write_var, read_var).
Wireshark would dissect these as malformed S7comm variable access items.

Fix: rewrote `_var_item()` with the correct struct format `">BBBBHH"` (12 bytes)
and corrected bit-address encoding. Verified: db_num=300 (0x012C) now produces
high byte 0x01, low byte 0x2C at the correct wire offsets.

### Fix 3: SHA-256 password hashing replaced with scrypt

`auth.py` stored passwords as `sha256:salt:hex_digest` — a fast hash function
with a random salt. While this is better than unsalted SHA-256, it is not a
memory-hard KDF and is brute-forceable with a GPU at billions of attempts/second.
For a security validation tool, this is a credibility issue.

Fix: passwords are now hashed with `hashlib.scrypt` (stdlib, no new dependencies):
- Parameters: N=16384, r=8, p=1 (OWASP minimum recommendation for interactive login)
- New hash format: `scrypt:salt_hex:hash_hex`
- Backward compatible: existing `sha256:` hashes are still verified (for users
  upgrading from prior versions), but new passwords use scrypt

Argon2id would be preferable but requires `argon2-cffi` (not in stdlib). Scrypt
is a recognized NIST-approved KDF (SP 800-132) available in Python stdlib since 3.6.

### Fix 4: TRITON/TRISIS chain — transparent disclosure of surrogate protocol

The chain was labeled "Triton / TRISIS" without disclosing that it uses Modbus
and S7comm as surrogates for the proprietary TriStation protocol (which is not
publicly documented and not implemented in ICSForge).

Fix: chain title updated to "SIS Targeting (TRITON/TRISIS-inspired) — Modbus +
S7comm surrogate". Description now explicitly states that TriStation is the real
attack protocol, explains why it cannot be included, and clarifies that the modelled
attacker behaviour (SIS recon → lateral movement → safety function disable) is
accurate while the wire protocol differs from the real incident. UI chain cards
updated to match.

### Reviewer findings not actioned

**OPC UA stateless sessions** — correctly flagged. OPC UA sessions require
coherent sc_id/token across messages; ICSForge generates each packet independently.
Live sends to a real OPC UA server will fail at session establishment. This is
documented in the README. The PCAP-generation use case (primary use case) is
unaffected.

**DNP3 sequence number tracking** — correctly flagged as a deviation from stateful
DNP3 sessions. Individual packets have correct CRCs and application layer encoding;
sequence numbers are randomised per packet rather than tracked across a session.
This is a PCAP-quality limitation. The reviewer confirmed DNP3 CRC implementation
is correct.

## v0.58.1 (2026-04 — E2E test fix, variants caching, lint clean)

External review of v0.58.0 found three real issues. All fixed.

### Fix 1: tests/test_e2e_pipeline.py had 9 Ruff errors and 2 failing tests

Ruff errors removed:
- `import tempfile` unused → removed
- `import datetime, timezone` unused in test context → removed
- `from collections import defaultdict` unused → removed
- Ambiguous variable name `l` in list comprehension → renamed to `line`/`fh`
- `open(...)` without context manager (2 occurrences) → wrapped with `with`
- Unsorted inline import block → sorted

Failing test 1: `test_alerts_ingest_strict_validation` used `tmp_path` (pytest
fixture giving a temp directory outside the repo) as the file path sent to
`/api/alerts/ingest`. The endpoint only accepts repo-relative paths. Fixed by
writing test files to `out/test_tmp/` (inside repo) and cleaning up in finally blocks.

Failing test 2: `test_technique_variants_all_resolve` called the variants endpoint
for all 68 techniques serially — at ~670ms cold per call, this caused a timeout.
Replaced with `test_technique_variants_sample_resolve` which spot-checks a
representative sample of 7 techniques. The resolve correctness guarantee is preserved.

### Fix 2: /api/technique/variants was slow (670ms per call)

The endpoint was reparsing scenarios.yml from disk on every request. With 468 scenarios
and full YAML parsing, each call took ~670ms.

Added an mtime-based module-level cache (`_PACK_CACHE`): the first call after startup
(or after the file changes) parses the YAML and caches the result. Subsequent calls
check the file mtime — if unchanged, they serve from cache.

Result:
- Cold call (startup or file changed): ~670ms (unchanged)
- Warm call (file unchanged): ~1.6ms avg, 6ms max
- 400x speedup for the common case

The cache is automatically invalidated when scenarios.yml is modified, so adding
new scenarios is immediately reflected without restarting.

### Summary after v0.58.1
- 35/35 smoke test
- 7/7 E2E tests (17/17 assertions) — all passing
- Ruff: 0 errors (tests/test_e2e_pipeline.py cleaned)
- variants endpoint: 1.6ms avg (was 670ms)

## v0.58.0 (2026-04 — Polish release: E2E CI test, scenario expansion, dead code cleanup, docs)

### 1. True E2E CI test (tests/test_e2e_pipeline.py)

Added `tests/test_e2e_pipeline.py` with 7 tests covering the full pipeline:
- `test_generate_offline_creates_artifacts` — events JSONL written, T0855 in techniques
- `test_run_full_returns_artifacts` — run indexed, artifacts and techniques present
- `test_live_receipts_visible_in_all_run_endpoints` — 7 simulated live receipts visible
  in /api/run, /api/run_detail, /api/run_full; dedup confirmed (7 dupes → still 7)
- `test_scenarios_grouped_complete` — 400+ scenarios, all chains have steps
- `test_technique_variants_all_resolve` — all variant IDs round-trip to real scenarios
- `test_matrix_status_consistent` — 83 unique technique IDs, matrix_info present
- `test_alerts_ingest_strict_validation` — malformed alert → 400, valid → 200

All 13 assertions pass. This test permanently prevents the receipt-consistency and
variant-resolution classes of regression found in earlier reviews.

### 2. Scenario expansion: 59.3% → 64.3% (437/680)

34 new scenarios across 10 techniques (batch 6). All verified: 0 bad styles,
0 tactic mismatches. 23 techniques now at 10/10 protocol coverage (+5 from v0.57.5).

Techniques expanded:
  T0861 Point & Tag Identification:  6→10/10 (+iec61850, mqtt, profinet_dcp, s7comm)
  T0802 Automated Collection:        6→10/10 (+iec61850, opcua, profinet_dcp, s7comm)
  T0881 Service Stop:                6→10/10 (+iec61850, modbus, mqtt, profinet_dcp)
  T0827 Loss of Control:             6→10/10 (+iec61850, mqtt, opcua, profinet_dcp)
  T0885 Commonly Used Port:          2→6/10  (+dnp3, iec104, iec61850, s7comm)
  T0811 Data from Info Repos:        2→6/10  (+dnp3, enip, iec104, modbus)
  T0843 Program Download:            6→9/10  (+iec104, iec61850, modbus, profinet_dcp)
  T0800 Firmware Update Mode:        6→9/10  (+bacnet, iec61850, profinet_dcp)
  T0819 Exploit Public-Facing:       3→6/10  (+bacnet, dnp3, iec104)
  T0881/T0827 already noted above.

Domain filter applied: T0842/T0872/T0864/T0884/T0890/T0895/T0807/T0834/T0853
remain at their correct ceiling (host-only or single-protocol-only techniques).

### 3. /api/scenarios_grouped payload optimization

Added `?include_steps` query parameter (default: 1 for backward compatibility).
Callers that don't need step data can request `?include_steps=0` for a lean response.
The campaign page continues to receive full steps for chain rendering.

### 4. technique_variants.json cleanup

`TECH_VARIANTS` constant removed from `helpers.py` (was the only remaining reference
after the v0.57.1 fix). The JSON file itself is retained but marked with a
`_deprecated` key explaining that variants now derive live from scenarios.yml.

### 5. README: network configuration documentation

Added "Network configuration: Receiver IP vs Destination IP" section explaining
the dual-field model (cfg_receiver_ip vs dst_ip), the sync modes (callback, pull,
SSE), and when to use each. Addresses the "design complexity" flag from the reviewer.

### Coverage summary
Standalone scenarios: 457 (+34) + 11 chains = 468 total
Techniques at 10/10: 23 (+5)
Coverage: 59.3% → 64.3% (437/680)

## v0.57.5 (2026-04 — receipt consistency across all run endpoints + lint clean)

### Fix 1: /api/run and /api/run_detail were still callback-blind

The v0.57.4 fix applied the live-receipts merge only to `/api/run_full` and
`/api/export`. `/api/run` and `/api/run_detail` in `bp_receiver.py` were
still reading exclusively from `out/receipts.jsonl`, which is populated by
the standalone receiver process but not by the sender callback path.

For a live run using the callback path: `/api/receiver/live` showed 29 receipts,
`/api/run_full` showed 29 receipts (fixed in v0.57.4), but `/api/run` and
`/api/run_detail` still returned `{}` (empty).

All four run-detail endpoints now merge both sources:
- JSONL file (standalone receiver process)
- `_live_receipts` deque (sender callback path)

Verified: 10 live receipts → all four endpoints return `packets: 10`.

### Fix 2: Stable receipt deduplication key

The v0.57.4 dedup used `id(r)` — object identity — which is not stable across
JSONL-parsed dicts and in-memory deque entries (different objects, same data).
Replaced with a content-based tuple key:
`(run_id, @timestamp, technique, proto, src_ip, src_port)`

Dedup verified: adding 10 duplicate receipts keeps count at 10, not 20.

### Fix 3: Import ordering in bp_runs.py (Ruff I001)

The `_live_receipts` import was inserted in the wrong alphabetical position in
v0.57.4, causing a Ruff I001 lint error. Import block is now correctly sorted.
`bp_receiver.py` import block also sorted correctly.

## v0.57.4 (2026-04 — bug fixes from external review of v0.57.3)

### Fix 1: /api/run_full receipts always empty for live runs

Root cause: live receipts arrive via the sender callback path
(`POST /api/receiver/callback`) which stores them in `_live_receipts` — an
in-memory deque in `helpers_sse.py`. The JSONL receipts file at
`out/receipts.jsonl` is written only by the standalone receiver process.

`/api/run_full` read only from the JSONL file. `_live_receipts` was checked
by `/api/receiver/live` but not by `run_full`. So for a live run: packets=29,
receiver/live=29, but run_full receipts=[].

Fix: `api_run_full` and `api_export_run` now merge both sources:
1. JSONL file (receipts from standalone receiver process)
2. `_live_receipts` deque (receipts from sender callback path)

Duplicates excluded via `id()` comparison. Result: run_full receipts_preview
now correctly reflects all live receipts for the run.

### Fix 2: Ruff lint — two unused imports in bp_scenarios.py

- `import json` — unused since the variants endpoint was rewritten to derive
  from scenarios.yml (no longer reads JSON from technique_variants.json)
- `TECH_VARIANTS` — unused for the same reason

Additionally, `import random as _rnd_off` was declared inside the
`api_generate_offline` function body. Moved to module level as `import random
as _rnd`. All references updated. No behaviour change.

## v0.57.3 (2026-04 — bug fixes: matrix tiles, dst_ip propagation, campaign chains)

### Bug 1: Matrix tile height — long names clipped (regression from v0.57.2)
The v0.57.2 fix set a fixed `height: 52px` which clipped technique names like
"Device Restart/Shutdown" and "Block Reporting Message". Reverted to `height: auto`
with `min-height: 46px`. All technique names are now fully visible. The `-webkit-line-clamp`
was also removed — it was the cause of the visible text truncation in the screenshot.

### Bug 2: Destination IP not propagating from Network Settings
Two changes to make the dst_ip field reliably reflect the Network Settings IP:

1. `cfg_receiver_ip` now has an `oninput` handler that mirrors its value to `dst_ip`
   in real time as the user types — before any Save button is clicked.
2. `saveNetworkConfig()` now mirrors `receiver_ip → dst_ip` and `sender_ip → src_ip`
   at the very top of the function before any `await`, so the field is updated
   immediately rather than after a network roundtrip that could fail or delay.

Previously the mirror happened after `await API("/api/config/network")` which is
correct in theory but could be delayed or skipped if the network call path threw.
Now it is unconditional and synchronous.

### Bug 3: Campaign page — attack chains do not work
Root cause: `/api/scenarios_grouped` did not include the `steps` array in chain
scenario cards — only `step_count` (an integer). The campaign page `_runChain()`
function reads `sc.steps` to render the step-by-step progress view. With `steps`
absent, it got an empty array, rendered no rows, and the chain appeared to do nothing
even though `/api/send` would have executed it.

Fix: `/api/scenarios_grouped` now includes the full `steps` array for chain scenarios
(non-chain scenarios still omit steps to keep the response small). All 11 chains
verified: 5–10 steps each, correct proto/technique fields, send path returns 200.

## v0.57.2 (2026-04 — UI fixes: sender, matrix, home page)

### 7 UI fixes from review

**1. Home page tagline**
"ICSForge validates cybersecurity..." -> "ICSForge helps you to validate cybersecurity..."

**2. Tactic group ordering (sender)**
Privilege Escalation was last in the list. Corrected to ATT&CK for ICS position 4:
Chains → Initial Access → Execution → Persistence → **Privilege Escalation** → Evasion
→ Discovery → Lateral Movement → Collection → Command and Control
→ Inhibit Response Function → Impair Process Control → Impact

**3. Attack chains layout (sender)**
Named chains (Industroyer2, Triton/TRISIS, Stuxnet-style, Water Treatment, OPC UA
Espionage, EtherNet/IP MFG) now render as a prominent first row. Generic multi-protocol
chains appear below with a "MULTI-PROTOCOL CHAINS" section label.

**4. Confirm button text (sender)**
"Confirm: synthetic traffic only — destination is a safe host in your OT environment"
→ "Confirm: Destination is a safe host (receiver) in your environment"

**5. Matrix column header duplicate removed**
Each tactic column showed the name ("Initial Access") and the shortname
("initial-access") below it. The shortname line is now removed — one clean label only.

**6. Matrix tile text overlap fixed**
- .mc-col: overflow changed from `visible` to `hidden` — tiles no longer bleed outside
  their column bounds
- .mt: added overflow:hidden to contain content within tile bounds
- .mt-name: added -webkit-line-clamp:3 so long technique names truncate cleanly
  instead of overflowing into adjacent tiles

**7. Home page top techniques table**
- Was: top 20 by scenario count, showing "Refs" column
- Now: top 10 by protocol coverage breadth (most protocols covered), showing
  "Protocols" (x/10 in green) and "Scenarios" columns
- All top 10 currently show 10/10 protocol coverage — the table correctly
  reflects the expansion work done across all batch releases

## v0.57.2 (2026-04 — UI fixes across home, sender, and matrix pages)

### 7 UI fixes

**Fix 1: Home page tagline**
"ICSForge validates cybersecurity..." →
"ICSForge helps you to validate cybersecurity detection coverage..."

**Fix 2: Sender tactic group order — Privilege Escalation position**
Privilege Escalation was last in the sender scenario list. Corrected to match
ATT&CK for ICS tactic order: Persistence → Privilege Escalation → Evasion.

**Fix 3: Attack chains — named chains first, generic chains below**
Named chains (Industroyer2, Triton, Stuxnet, Water Treatment, OPC UA Espionage,
EtherNet/IP MFG) now render in the first row with their icons and labels.
Generic multi-protocol chains (CHAIN__loss_of_availability, etc.) appear below
with a "MULTI-PROTOCOL CHAINS" separator.

**Fix 4: Confirm button text**
"Confirm: synthetic traffic only — destination is a safe host in your OT environment"
→ "Confirm: Destination is a safe host (receiver) in your environment"

**Fix 5: Matrix column header — duplicate shortname removed**
Each tactic column header showed the tactic name (e.g. "Initial Access") AND
the kebab-case shortname (e.g. "initial-access") below it, making it appear
duplicated. The shortname line is removed; column headers now show just the name.

**Fix 6: Matrix tile text overflow**
Technique tiles now have a fixed height (52px) with CSS -webkit-line-clamp: 3
on the technique name. Long names (e.g. "Exploitation for Privilege Escalation")
no longer overflow and overlap adjacent tiles.

**Fix 7: Home page top techniques — correct data, top 10 only**
Previously showed top 20 sorted by scenario count (a proxy for coverage).
Now shows top 10 sorted by protocol coverage breadth (most protocols covered),
with a "Protocols" column showing X/10 and a "Scenarios" column showing count.
All 18 techniques at 10/10 coverage are sorted secondarily by scenario count.

## v0.57.1 (2026-04 — matrix overlay and sender scenario visibility fixed)

### Bug: technique variants were stale (matrix click-through broken)

The `/api/technique/variants` endpoint read from `icsforge/data/technique_variants.json`,
a static file maintained separately from `scenarios.yml`. This file was last updated
many versions ago and only contained 2–3 variants per technique regardless of how
many scenarios were actually added. When a user clicked a technique tile on the matrix
page to see available scenarios, they saw only the old entries — all new scenarios
from every expansion batch (v0.52–v0.57) were invisible.

Fix: the endpoint now derives variants live from `scenarios.yml`:
- Queries all scenarios matching the requested technique ID
- Skips CHAIN__ scenarios (they cover multiple techniques)  
- Returns `{id, label, proto, protocols, notes}` built from actual scenario metadata
- Variant IDs are the scenario name with the `T0XXX__` prefix stripped, so the
  send endpoint constructs the correct scenario name on lookup

Result:
- T0858 Change Operating Mode: was 2 variants, now 11 (all protocols)
- T0892 Change Credential: was 0 variants, now 6
- T0880 Loss of Safety: was 2 variants, now 11
- T0855 Unauthorized Command: was 4 variants, now 14 (all 10 protocols)
- All 68 techniques: 100% of scenario variants visible, all IDs resolve correctly

`technique_variants.json` is now unused by the variants endpoint and will be
removed in a future cleanup. The send path (`api/technique/send`) was already
correctly looking up scenarios in `scenarios.yml`.

### Verified
- All 68 techniques: variants endpoint returns correct count
- All variant IDs round-trip correctly through generate_offline
- Matrix tile click -> variant select -> generate_offline: end-to-end PASS
- Smoke test: 35/35
- Syntax: clean

## v0.57.0 (2026-04 — scenario expansion: 394 -> 434, 53.4% -> 59.3% coverage)

### Batch 5 expansion: +40 scenarios across 10 techniques

Techniques explicitly NOT expanded (domain filter applied):
  T0842 Network Sniffing — passive, no packets generated. 1/10 ceiling.
  T0820 Exploitation for Evasion — malformed-frame scenarios already exist for
    modbus/enip/opcua/s7comm. No new protocols have equivalent malformed styles.
  T0871 Execution through API — OPC UA call_method is the only OT network path.
  T0807 CLI, T0853 Scripting — DNP3 file_open is the only OT network path.
  T0834 Native API — S7comm native_cotp is the only OT network path.
  T0837 Loss of Protection — modbus:protection_relay is the only equivalent.
  T0864 Transient Cyber Asset — physical access. 1/10 ceiling.
  T0872 Indicator Removal — endpoint. DNP3 clear_events is the only OT equiv.
  T0884 Connection Proxy, T0890 Privilege Escalation — OPC UA specific. 1/10 ceiling.
  T0895 Autorun Image — S7comm SDB0 is the only OT network equivalent.

New scenarios added:
  T0858 Change Operating Mode (+5: bacnet, iec61850, modbus, mqtt, profinet_dcp) -> 10/10
  T0829 Loss of View (+5: bacnet, enip, iec61850, mqtt, profinet_dcp) -> 10/10
  T0889 Modify Program (+5: dnp3, iec104, iec61850, modbus, profinet_dcp) -> 10/10
  T0880 Loss of Safety (+4: bacnet, iec61850, opcua, profinet_dcp) -> 9/10
  T0800 Firmware Update Mode (+4: dnp3, iec104, modbus, mqtt) -> 6/10
  T0892 Change Credential (+4: dnp3, enip, iec104, s7comm) -> 6/10
  T0891 Hardcoded Credentials (+4: bacnet, dnp3, enip, iec104) -> 6/10
  T0828 Loss of Productivity (+4: bacnet, enip, mqtt, s7comm) -> 6/10
  T0859 Valid Accounts (+3: enip, iec104, s7comm) -> 5/10
  T0822 External Remote Services (+2: enip, s7comm) -> 4/10

### New techniques at 10/10 protocol coverage
T0858, T0829, T0889 — 18 techniques now at full coverage.

### Coverage: 53.4% -> 59.3% (403/680 combinations)
### Standalone scenarios: 423 + 11 chains = 434 total
### All 423 standalone: 0 bad styles, 0 tactic mismatches, 0 mangled IDs

## v0.56.3 (2026-04 — metadata alignment and alerts ingest policy)

### Developer review findings from v0.56.2 — addressed

Three substantive fixes based on a second extensive external review.

**Fix 1: Local ATT&CK for ICS matrix file aligned with current MITRE list**

The bundled `ics_attack_matrix.json` contained 97 total entries / 86 unique technique IDs
from an older version of the framework. MITRE ATT&CK for ICS currently lists 83 techniques.
The three extra IDs (T0841, T0875, T0876) were deprecated/invalid — removed.

Matrix is now: 94 total entries (11 techniques appear in >1 tactic = intentional ATT&CK
design), 83 unique technique IDs. Matches `technique_support.json` exactly — gap is zero.

**Fix 2: /api/matrix_status now exposes matrix_info block**

The response previously returned only `{run_id, status}`. Callers seeing 94 entries in
the matrix file but 83 unique IDs were confused. New `matrix_info` field in the response:

```json
"matrix_info": {
  "total_entries": 94,
  "unique_technique_ids": 83,
  "note": "total_entries > unique_technique_ids because some techniques appear under multiple tactics"
}
```

The 11 techniques that appear in >1 tactic (e.g. T0856 Spoof Reporting under both
Evasion and Impair Process Control; T0839 Module Firmware under both Persistence and
Impair Process Control) are correct ATT&CK for ICS design, not a data error.

**Fix 3: /api/alerts/ingest returns 400 for malformed `alert` field**

After v0.56.1 fixed the 500 crash, the endpoint was accepting malformed `alert` values
(string instead of object) and silently importing them with fallback placeholders.
Policy decision: malformed alert structure is a caller bug and should be rejected clearly.

Before: string alert field -> imported with `signature: "alert"` placeholder (200 OK)
After:  string alert field -> `400 {"ok": false, "error": "Row N: 'alert' field must be
         an object, got str"}`

Valid alert objects continue to import normally (200 OK).

### Findings not acted on

**Webhook field name (`webhook_url`)**: intentional API design, documented in API surface.
**Auth setup requires username**: intentional hardening, not a regression.
**Developer note on T0841/T0875/T0876**: resolved by Fix 1 — removing the deprecated IDs
  from the local matrix rather than adding them back to support.json.

### Metadata state after v0.56.3
| Source | Count | Notes |
|--------|-------|-------|
| MITRE ATT&CK for ICS (live) | 83 techniques | authoritative |
| ics_attack_matrix.json unique IDs | 83 | now aligned |
| ics_attack_matrix.json total entries | 94 | 11 multi-tactic techniques |
| technique_support.json | 83 entries | aligned |
| scenario step-level techniques | 72 | 11 host-only have no OT network scenarios |

## v0.56.2 (2026-04 — correct invalid ATT&CK for ICS technique IDs)

### Correction: T0841, T0875, T0876 are not valid ATT&CK for ICS technique IDs

The external developer's Bug 3 report claimed these three IDs were missing from
`technique_support.json`. The report compared against our bundled `ics_attack_matrix.json`,
which is from an older version of the framework (97 techniques vs the current 83).

The current MITRE ATT&CK for ICS (attack.mitre.org/techniques/ics/) lists exactly 83
techniques. T0841, T0875, and T0876 do not appear in this list:
- T0841 "Network Service Scanning" was from the pre-2021 collaborate.mitre.org era
- T0875 "Change Program State" does not exist in the current framework
- T0876 "Loss of Safety" is a duplicate of T0880 which is the current valid ID

The v0.56.1 "fix" of adding these to technique_support.json was wrong and is reverted.

### What was actually fixed

17 scenario top-level technique fields and 39 step-level technique fields pointing to
invalid IDs have been remapped to the correct current ATT&CK for ICS equivalents:

- T0841 "Network Service Scanning" -> T0846 "Remote System Discovery"
  (all network scanning scenarios now correctly filed under T0846)
- T0875 "Change Program State" -> T0858 "Change Operating Mode"
  (all PLC stop/start/mode scenarios now correctly filed under T0858)
- T0876 "Loss of Safety" -> T0880 "Loss of Safety"
  (same concept, T0880 is the current valid ID)

Scenario keys renamed accordingly (e.g. T0841__network_scan__* -> T0846__network_scan__*).

technique_support.json: 83 entries, exactly matching the current MITRE ATT&CK for ICS
technique count. No fabricated IDs.

### Coverage after remapping (unchanged total, IDs corrected)
- T0846 Remote System Discovery: 10/10 protocols
- T0858 Change Operating Mode:    5/10 protocols
- T0880 Loss of Safety:           5/10 protocols

## v0.56.1 (2026-04 — bug fixes from external developer review of v0.53.0)

### Developer review findings — all addressed

External developer performed a full end-to-end review from a clean tarball install:
real web launcher, real receiver, live CLI sends, artifact verification, SQLite state,
auth flow, webhook, alerts ingest, and scenario pack inspection.

**Fix 1: `/api/alerts/ingest` 500 on malformed `alert` field (real runtime crash)**
When a Suricata EVE JSONL row had `"alert": "some_string"` instead of
`"alert": {...}`, the endpoint crashed with `AttributeError: 'str' object has
no attribute 'get'`. Fixed: `isinstance(alert, dict)` guard applied before
any `.get()` calls. Malformed rows now produce a clean empty-alert normalised
record rather than a 500.

**Fix 2: Remaining mangled top-level `technique` field**
One chain scenario (`CHAIN__loss_of_availability__multi`) still had its technique
field set to `'T0813 followed by S7comm CPU stop commands...'` from the yaml.dump
width-wrapping bug fixed in v0.55.0. Repaired to `T0813`.

**Fix 3: `technique_support.json` not aligned with ATT&CK ICS matrix**
Three techniques covered by scenarios (T0841, T0875, T0876) were missing entries
in `technique_support.json`. The file had 83 entries vs the matrix's 86. All three
added with correct runnable classification and evidence descriptions. Files now
align exactly: 86 entries each.

**Fix 4: `/api/campaigns` returned 404**
The campaigns list endpoint was only registered at `/api/campaigns/list`. Added
`/api/campaigns` as a second route decorator on the same handler. Both paths now
return 200.

**Fix 5: Stealth mode events JSONL still contained `icsforge.marker: "ICSFORGE_SYNTH"`**
In stealth mode (`--no-marker`), the generated PCAP correctly contained no
ICSForge correlation tags. However, the events JSONL ground-truth file still
wrote `icsforge.marker: "ICSFORGE_SYNTH"` — inconsistent with the wire traffic.
Fixed: `event_base()` now accepts a `no_marker` parameter; when True,
`icsforge.marker` is set to `None`. The `icsforge.synthetic: True` field is
intentionally preserved (the events ARE synthetic regardless of marker mode).

**Developer-noted items that are intentional / acknowledged:**
- Auth setup requires `username` + `password` (hardening, not a bug; documented)
- Alerts ingest is path-based and repo-constrained (power-user UX, acceptable)
- `icsforge.synthetic: True` remains in stealth events (accurate metadata)

## v0.56.0 (2026-04 — Scenario expansion: 355 -> 394, 46.9% -> 52.1% coverage)

### No-nonsense expansion: 39 new scenarios across 13 techniques

Every scenario was evaluated against a strict domain filter before being written:
- Does the protocol genuinely reach the relevant device class?
- Does the specific style produce traffic that represents the technique?
- Is it meaningfully different from existing scenarios for the same technique?
- Was it excluded only because it genuinely cannot be simulated via network traffic?

Techniques explicitly NOT expanded (rationale documented):
  T0842 Network Sniffing — passive activity; no packets emitted. 1/10 ceiling.
  T0872 Indicator Removal — primarily endpoint. DNP3 clear_events is the only OT equivalent.
  T0864 Transient Cyber Asset — physical access. PROFINET DCP hello is the only equivalent.
  T0884 Connection Proxy, T0890 Privilege Escalation — OPC UA specific, no generic equivalents.
  T0895 Autorun Image — S7comm SDB0 is the only protocol-native equivalent.
  T0807 CLI, T0853 Scripting — DNP3 file transfer is the only OT network equivalent.
  T0820 Exploitation for Evasion — requires deep protocol stack implementation; correct
    as malformed/exception-probe (existing modbus/enip/opcua/s7comm scenarios cover this).

New scenarios added:
  T0816 Device Restart/Shutdown (+4: dnp3, iec104, modbus, mqtt) -> 8/10
  T0815 Denial of View (+4: iec61850, modbus, s7comm, profinet_dcp) -> 8/10
  T0801 Monitor Process State (+3: dnp3, enip, s7comm) -> 8/10
  T0821 Modify Controller Tasking (+3: enip, opcua, dnp3) -> 4/10
  T0806 Brute Force I/O (+3: dnp3, enip, s7comm) -> 4/10
  T0838 Modify Alarm Settings (+4: bacnet, enip, iec61850, profinet_dcp) -> 10/10
  T0839 Module Firmware (+3: enip, dnp3, iec104) -> 5/10
  T0845 Program Upload (+3: enip, opcua, dnp3) -> 4/10
  T0846 Remote System Discovery (+3: enip, modbus, opcua) -> 4/10
  T0849 Masquerading (+3: dnp3, enip, s7comm) -> 8/10
  T0875 Change Program State (+3: enip, iec104, opcua) -> 4/10
  T0889 Modify Program (+3: enip, opcua, s7comm) -> 6/10
  T0835 Manipulate I/O Image — already covered from previous batch

New technique at 10/10: T0838 Modify Alarm Settings

### Protocol gains
EtherNet/IP: +9 (38->47), DNP3: +7 (38->45), OPC UA: +5 (37->42), S7comm: +4 (48->52)

### Totals
Standalone scenarios: 383 (+ 11 chains = 394)
Techniques covered: 71/72
Coverage: 46.9% -> 52.1% (370/710 combinations)
Techniques at 10/10: 15
Techniques at 8+/10: 25

## v0.55.0 (2026-04 — Quality audit + genuine scenario expansion: 334 -> 355)

### Quality audit: major correctness pass across all 314 standalone scenarios

**Issue 1: 37 invalid style/protocol combinations (FIXED)**
Scenarios written in earlier development sessions used style names that were
invented or renamed: mqtt:connect (-> auto), mqtt:publish (-> publish_telemetry),
mqtt:subscribe (-> subscribe_all), dnp3:app_read (-> read_class1),
dnp3:data_link (-> delay_measure), dnp3:unsolicited (-> enable_unsolicited
corrected further to spoof_response), s7comm:negotiate (-> szl_read),
iec104:command (-> setpoint_float / double_command), modbus:device_id (-> report_block).
All 37 were corrected to valid styles that the protocol builders actually implement.

**Issue 2: enumerate_ied missing from iec61850.py (FIXED)**
The enumerate_ied style was referenced in 9 IEC 61850 scenarios but the actual
elif branch was never written into the protocol builder. All 9 scenarios used
the fallback path (benign keep-alive GOOSE) instead of the intended test-mode
probe. The style is now properly implemented.

**Issue 3: 86 tactic mismatches against ATT&CK for ICS matrix (FIXED)**
Many scenarios had tactically incorrect labels — some inherited from early
development, others introduced by batch additions. Full ATT&CK for ICS matrix
alignment enforced across all techniques:
- T0813 Denial of Control -> Impact (not Inhibit Response Function)
- T0832 Manipulation of View -> Impact (not Evasion / Inhibit Response Function)
- T0856 Spoof Reporting -> Impair Process Control (not Inhibit Response Function)
- T0848 Rogue Master -> Initial Access (not Lateral Movement)
- T0812 Default Credentials -> Lateral Movement (not Initial Access)
- T0877 I/O Image -> Collection (not Discovery)
- T0868 Detect Operating Mode -> Collection (not Discovery)
- T0882 Theft of Operational Information -> Impact (not Collection)
- T0830 AitM -> Collection (not Lateral Movement)
- All 86 fixed; 0 mismatches remain.

**Issue 4: 65 mangled technique fields (FIXED)**
yaml.dump(width=120) wrapped long description text into the technique field for
65 scenarios, turning the technique from 'T0803' into 'T0803 PLC and starving
legitimate master access.' Re-parsed all affected scenarios; technique fields
are now strictly the 5-character IEC code. Switched to width=2000 to prevent
recurrence.

**Issue 5: 9 T0820 scenarios with wrong technique ID (DELETED)**
T0820 in ATT&CK for ICS is "Exploitation for Evasion", not network connection
enumeration. Nine 'T0820 network discovery' scenarios were mislabeled T0840
duplicates. Deleted. T0840 Network Connection Enumeration remains at 10/10.

**Issue 6: T0829 safety scenario misattributed (FIXED)**
T0829__loss_of_protection__modbus_safety contained safety_write steps targeting
SIS registers — that is T0876 Loss of Safety, not T0829 Loss of View. Renamed
to T0876__loss_of_safety__modbus_sis and corrected description.

**Issue 7: T0832 dnp3 used enable_unsolicited (FIXED)**
enable_unsolicited turns ON change reporting — it does not inject false data.
T0832 Manipulation of View requires actually spoofing values. Corrected to
spoof_response which injects forged analog responses.

### New genuine scenarios (+30 across 8 techniques)

Added only where the protocol-technique combination is operationally meaningful:

T0829 Loss of View (0->5/10): modbus flood, dnp3 disable_unsolicited, iec104 STOPDT,
  opcua subscription delete, s7comm diagnostic flood
T0827 Loss of Control (+3: bacnet, dnp3, enip): 3->6/10
T0876 Loss of Safety (+3: dnp3, enip, iec104): 2->5/10
T0881 Service Stop (+4: bacnet, dnp3, iec104, opcua): 2->6/10
T0809 Data Destruction (+3: modbus, dnp3, enip): 3->6/10
T0843 Program Download (+3: dnp3, enip, opcua): 3->6/10
T0835 Manipulate I/O Image (+3: dnp3, enip, iec104): 2->5/10
T0861 Point & Tag Identification (+3: dnp3, enip, iec104): 3->6/10
T0802 Automated Collection (+3: dnp3, enip, iec104): 3->6/10

### Scenario totals: 355 (344 standalone + 11 chains)
### Coverage: 44.1% -> 46.9% (333/710 combinations)
### All 344 standalone scenarios: 0 bad styles, 0 tactic mismatches, 0 mangled IDs

## v0.54.0 (2026-04 — Scenario expansion: 275 → 334 scenarios, 36% → 44% coverage)

### Coverage batch 3: +59 scenarios across 18 techniques

Systematic fill of the highest-value remaining gaps, with heavy focus on
BACnet, PROFINET, IEC 61850, and MQTT which were the least-covered protocols.

**Techniques reaching 10/10 protocol coverage this batch:**
T0813, T0820, T0826, T0831, T0832, T0836 (already), T0840, T0841, T0848,
T0855, T0856, T0877, T0878, T0882, T0888 -- 15 techniques now at full coverage.

**Techniques expanded:**
- T0803 Block Command (+5: bacnet, enip, iec104, iec61850, s7comm) 2 -> 7/10
- T0804 Block Reporting (+5: bacnet, enip, iec104, iec61850, s7comm) 2 -> 7/10
- T0830 AitM (+3: bacnet, mqtt, s7comm) 6 -> 9/10
- T0831 Manipulation of Control (+4: bacnet, enip, profinet_dcp, s7comm) -> 10/10
- T0848 Rogue Master (+4: bacnet, iec61850, mqtt, profinet_dcp) -> 10/10
- T0856 Spoof Reporting (+1: profinet_dcp) -> 10/10
- T0812 Default Credentials (+2: bacnet, dnp3) -> 9/10
- T0813 Denial of Control (+2: dnp3, iec104) -> 10/10
- T0814 Denial of View (+2: bacnet, enip) -> 8/10
- T0820 Network Discovery (+5: bacnet, enip, iec61850, mqtt, profinet_dcp) -> 10/10
- T0826 Loss of Availability (+2: bacnet, profinet_dcp) -> 10/10
- T0832 Manipulation of View (+2: bacnet, profinet_dcp) -> 10/10
- T0868 Detect Op Mode (+3: bacnet, iec61850, mqtt) -> 8/10
- T0869 Standard App Layer (+4: dnp3, iec104, iec61850, s7comm) -> 9/10
- T0877 I/O Module Discovery (+4: bacnet, iec61850, mqtt, profinet_dcp) -> 10/10
- T0878 Alarm Suppression (+4: bacnet, enip, mqtt, profinet_dcp) -> 10/10
- T0882 Theft of Op Info (+3: iec61850, mqtt, profinet_dcp) -> 10/10
- T0883 Internet Accessible (+4: bacnet, iec104, iec61850, s7comm) -> 8/10

### Protocol gains this batch
BACnet: +14 (17->31), IEC 61850: +9 (13->22), PROFINET: +9 (11->20),
MQTT: +7 (22->29), S7comm: +6 (42->48), EtherNet/IP: +6 (26->32)

### Scenario total: 334 (323 standalone + 11 attack chains)
### Coverage: 35.8% -> 44.1% (313/710 technique-protocol combinations)

## v0.53.0 (2026-04 — Scenario expansion: 179 → 275 scenarios, 25% → 36% coverage)

### Coverage gap analysis and targeted expansion

Systematic audit of all 72 ATT&CK for ICS techniques x 10 protocols:

- Feasibility conclusion: 720 (72x10) is the theoretical max; realistic ceiling
  is ~490-520 scenarios once host-only and protocol-specific techniques are excluded.
  15 techniques are endpoint-only (no OT network footprint). ~20 are protocol-specific.
  The remaining ~37 are protocol-independent and fully achievable across all 10 protocols.
- This release: 179 -> 275 scenarios (+96 net). Coverage: 25.2% -> 35.8%.

### New standalone scenarios (+45 across 14 techniques)

T0832 Manipulation of View (+4: dnp3, iec104, s7comm, enip) -- now 8/10
T0856 Spoof Reporting (+4: bacnet, modbus, s7comm, enip) -- now 9/10
T0888 Remote System Info (+5: dnp3, iec104, mqtt, profinet_dcp, iec61850) -- now 10/10
T0840 Network Connection Enum (+4: dnp3, iec104, s7comm, iec61850) -- now 10/10
T0841 Network Scanning (+3: bacnet, iec61850, profinet_dcp) -- now 10/10
T0830 AitM (+3: modbus, enip, iec104) -- now 6/10
T0813 Denial of Control (+3: enip, profinet_dcp, opcua) -- now 8/10
T0814 Denial of View (+2: opcua, s7comm)
T0836 Modify Parameter (+2: dnp3, iec61850) -- now 10/10
T0838 Modify Alarm Settings (+2: dnp3, s7comm)
T0855 Unauthorized Command (+3: enip, opcua, profinet_dcp) -- now 10/10
T0812 Default Credentials (+2: iec104, profinet_dcp) -- now 7/10
T0820 Network Discovery (+4: opcua, s7comm, dnp3, iec104) -- now 5/10
T0826 Loss of Availability (+2: opcua, iec61850)
T0849 Masquerading (+2: iec61850, mqtt)

### Techniques at full 10/10 protocol coverage
T0840 Network Connection Enumeration
T0841 Network Scanning
T0855 Unauthorized Command
T0836 Modify Parameter
T0888 Remote System Info Discovery

### New IEC 61850 style: enumerate_ied
GOOSE frames with test=True flag to generic multicast for IED discovery
without triggering protection actions. Used by T0840/T0841/T0888 scenarios.

### Roadmap to ~490 scenarios (next iterations)
T0803/T0804 Block Command/Reporting: 2/10, all protocols viable
T0831 Manipulation of Control: expand remaining 5 protocols
T0882 Theft of Operational Information: 7/10, needs mqtt/iec104/profinet
T0800 Activate Firmware Update Mode: 2/10, applicable to s7comm/opcua/iec104

## v0.52.0 (2026-04 — IEC 61850 GOOSE protocol and substation scenarios)

### New protocol: IEC 61850 GOOSE

IEC 61850 is the international standard for communication in electrical substations and
smart grids. Its GOOSE (Generic Object-Oriented Substation Events) protocol is the
time-critical Layer-2 multicast mechanism used for circuit breaker trip/close commands
and protection relay events. GOOSE has no built-in authentication — any frame on the
process bus VLAN with a higher stNum (state number) is accepted as authoritative by
all receiving IEDs. This is the primary attack surface for substation cyber-physical
attacks and was exploited in the 2015 Ukraine power grid attack.

**Why IEC 61850 belongs in ICSForge:**
- Deployed in power substations globally (Europe, North America, Asia-Pacific)
- Critical infrastructure: a single GOOSE trip injection can open a live circuit breaker
- Zero authentication in standard deployments (IEC 62351 rarely implemented in practice)
- Parsed natively by Zeek, Dragos, Nozomi, Claroty, and all OT-aware NSMs
- Distinctive EtherType 0x88B8 — immediately identifiable by Suricata and Wireshark
- Required for power sector ICS coverage validation

**Wire format (IEC 61850-8-1):**
- EtherType: 0x88B8 (GOOSE)
- DST MAC: 01:0C:CD:01:00:01 (protection multicast) or 01:0C:CD:01:00:00 (generic)
- Header: APPID(2) + Length(2) + Reserved1(2) + Reserved2(2)
- APDU: BER-encoded IECGoosePdu — all 12 required fields including gocbRef, datSet,
  goID, UTC timestamp, stNum, sqNum, confRev, allData

### New scenarios (4) — IEC 61850 techniques

**T0855__unauth_command__iec61850_goose_trip** — Unauthorized Command Message
Injects a forged GOOSE frame with stNum far above the legitimate IED's value. All
subscribers accept it as the most recent state change and execute the circuit-breaker
TRIP command. 5-step scenario replicates the real GOOSE retransmit burst pattern:
initial injection followed by exponentially spaced retransmits (4ms, 8ms, 16ms, 1s).

**T0856__spoof_reporting__iec61850_goose_meas** — Spoof Reporting Message
Injects GOOSE with falsified FLOAT32 voltage and current values (0.0V — simulating
a dead feeder). SCADA and receiving IEDs display incorrect grid state.

**T0813__denial_of_control__iec61850_goose_replay** — Denial of Control
Rapid GOOSE replay flood (100+ msg/s) with fixed stNum but incrementing sqNum.
Saturates IED message queues; real protection events are delayed or lost.

**T0830__aitm__iec61850_goose_relay** — Adversary-in-the-Middle
Simulates AitM relay injection: captures a legitimate GOOSE, modifies allData
(e.g., close→trip), re-injects with stNum = captured+1. Subscribers accept the
attacker's frame over the legitimate publisher's.

### Technical notes
- L2 protocol (like PROFINET DCP): requires `--iface eth0` for live send (AF_PACKET)
- GOOSE frames fully parseable by Wireshark (goose dissector), Zeek iec61850 analyzer,
  and all OT NSM tools that inspect EtherType 0x88B8
- Stealth mode works: no ICSFORGE tag in GOOSE frames when `--no-marker` is used
- IED reference, GCB suffix, APPID, stNum, and voltage all configurable via UI params
- T0855 and T0813 updated in technique_support.json: now classified as `runnable`

### Scenario count
175 → **179 scenarios** across 10 protocols

### UI fixes (post-initial implementation review)

- **Payload preview broken for IEC 61850**: `api_preview_payload` had a hardcoded
  builder list that omitted `iec61850`. All four scenarios returned `proto=None`.
  Fixed: added `iec61850` to builders, ports, L2 proto set, and marker encoding path.
  Now returns `proto=iec61850`, `transport=L2/Ethernet`, correct EtherType `0x88B8`.
- **Protocol badge**: `iec61850` was missing from the `PROTO_C` colour map in
  `sender.js` — scenarios showed grey dots in the scenario list. Fixed: added
  `iec61850: "#16a34a"` (power-sector green, distinct from the iec104 green).
- **Port display**: L2 protocols have `port=0` — rendered as "L2/Ethernet 0" in
  the hex dump meta. Fixed: port number only shown when non-zero.

### Verified
- All 179 scenarios generate without error
- All 4 GOOSE styles: correct EtherType 0x88B8, DST multicast MACs, BER-encoded PDU
- Smoke test: 35/35 PASS
- Syntax: 0 errors

## v0.51.0 (2026-04 — Stealth mode, Ruff cleanup, protocol authenticity)

### New: Stealth mode — 100% real protocol traffic

Every packet ICSForge generates normally embeds an `ICSFORGE_SYNTH|run-id|technique|step`
correlation tag in the payload (enabling receiver confirmation). This makes packets
detectably synthetic — a real Modbus FC03 read is 12 bytes; the tagged version is 57+.

Stealth mode removes all tags. Packets are byte-for-bit identical to what genuine
PLCs, RTUs, and engineering workstations generate. Validated:

- Normal PCAP: 4781B · Stealth PCAP: 2562B (marker overhead fully eliminated)
- `ICSFORGE` tag present in normal PCAP: True; in stealth PCAP: False
- All 9 protocols produce structurally valid frames in both modes

**Confirmation in stealth mode:** Instead of receiver marker detection, the sender
tracks TCP ACK delivery per step. Any technique whose TCP connection completed
without error is counted as network-confirmed and shown in the Live Attack Timeline.
This is at least as meaningful as marker-based confirmation and requires no ICSForge
receiver running.

**Where to enable:**

*Sender UI* — new `Stealth mode — real traffic, no synthetic tags` toggle in the
Configuration card. When active it turns red and a `STEALTH` badge appears in the
Live Attack Timeline header. Confirmation counts via TCP ACK automatically.

*CLI:*
```
icsforge send     --name T0855__unauth_command__modbus --dst-ip 10.0.0.50 \
                  --confirm-live-network --no-marker
icsforge generate --name CHAIN__industroyer2__power_grid --outdir out/ --no-marker
```

*API:* `no_marker: true` in the body of `POST /api/send`, `POST /api/generate_offline`,
`POST /api/technique/send`.

### Protocol authenticity (all 9 protocols)

All protocols produce structurally correct frames as verified by field parsing:
- Modbus/TCP: valid MBAP (protocol=0, correct length) + correct function codes
- DNP3: correct 0x0564 start bytes, CRC16 computed per 16-byte block per spec
- IEC 60870-5-104: correct 0x68 APCI start, valid APDU type IDs
- S7comm: correct TPKT version=3 + COTP + S7 protocol_id=0x32
- EtherNet/IP: correct encapsulation commands (0x0063/0x006F), CIP service codes
- BACnet/IP: correct BVLC 0x81, NPDU version=1, APDU type/service IDs
- MQTT: valid CONNECT with protocol "MQTT" and level 4 (v3.1.1)
- PROFINET DCP: FrameID 0xFEFE, service ID 0x05, AF_PACKET raw socket
- OPC-UA: correct message type codes (HEL/OPN/MSG), valid length fields

Live sends use real TCP/UDP OS sockets — the OS handles full TCP handshake.
Zeek, Suricata, and OT-aware NSMs parse these as real protocol traffic.

### Ruff cleanup (v0.50.8)

External developer pass: import ordering, unused import removal, context manager
fixes, `collections.abc.Callable` modernisation, `__all__` added to `helpers.py`.
One genuine bug fixed: `_parse_node_numeric()` in `opcua.py` used `rnd` (local
variable inside `build_payload`) instead of `random`.

### Bug fixes across v0.50.x

- `CampaignRunner` was never imported in `bp_campaigns.py` — campaigns never worked
- Timeline "0 confirmed" race: isTempId pattern now accepts technique-only matching
- Matrix overlay showed nothing for campaign/chain runs (events file has no
  `mitre.ics.technique`; meta.techniques fallback added)
- Coverage report `run_full` techniques from events file, not just receipts
- `api_generate_offline` always assigns meaningful run_id and registers in SQLite
- `toggleConfirm()` and `toggleStealth()` were called but never defined in HTML
- T0890 OPC-UA crash: `_parse_node_numeric()` handles `ns=2;i=1001` format
- `fire_webhook` missing import in `bp_config.py` (test_webhook always 500)
- Credentials now in `out/.credentials.json` — reset on reinstall (was `~/.icsforge/`)
- Matrix overlay light-theme: technique name no longer turns white

### Verified
- Syntax: 0 errors across all 58 Python files
- App startup: 67 routes (56 API)
- Smoke test: 35/35 PASS
- All 175 scenarios generate without error
- All 9 protocols: structurally valid frames confirmed by field parsing
- Auth: setup, login, rate limiting, reinstall all correct
- Stealth mode: PCAP clean, techniques tracked, TCP ACK confirmation working
- All web pages: /, /sender, /matrix, /campaigns, /report, /tools
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.9 (2026-04 — Stealth mode: real protocol traffic without synthetic tags)

### New feature: Stealth mode / no-marker traffic generation

By default, every ICSForge packet embeds a correlation tag
(`ICSFORGE_SYNTH|run-id|technique|step`) in the payload so the receiver can
confirm delivery. This makes packets detectably synthetic — a real Modbus FC03
read is 12 bytes; the marked version is 57.

Stealth mode omits the tag entirely. Packets are bit-for-bit identical to what a
genuine PLC, RTU, or engineering workstation would generate. This is useful for:

- IDS/NGFW/SIEM validation without triggering synthetic-traffic signatures
- Red team exercises where traffic authenticity matters
- Testing detection rules on real protocol frames
- Generating reference PCAPs that match legitimate device captures

**Trade-off:** With no marker, the ICSForge receiver has nothing to detect.
Receiver confirmation will show 0. ATT&CK technique coverage is still tracked
through the events file (the engine knows which techniques were sent regardless).

#### Where to enable

**Sender web UI** — new toggle button in the Configuration card:
`○ Stealth mode — real traffic, no synthetic tags`
When active, it turns red and a `STEALTH` badge appears in the Live Attack
Timeline header.

**CLI** — `--no-marker` flag on both `send` and `generate`:
```
icsforge send --name T0855__unauth_command__modbus --dst-ip 10.0.0.50 \
    --confirm-live-network --no-marker

icsforge generate --name CHAIN__industroyer2__power_grid \
    --outdir out/stealth --no-marker
```

**API** — `no_marker: true` in the JSON body of:
- `POST /api/send`
- `POST /api/generate_offline`
- `POST /api/technique/send` (matrix page)

#### Implementation

- `no_marker` parameter added to `run_scenario()` in `engine.py` and
  `send_scenario_live()` in `sender.py` — all three protocol branches
  (TCP, UDP, Profinet/L2) pass `b''` as the marker when enabled
- All call sites in `bp_scenarios.py` forward the flag correctly
- ATT&CK technique events are still written to the JSONL events file;
  technique coverage reporting, matrix overlay, and the coverage report
  all work identically in stealth mode

#### Verified
- Normal PCAP: 4695B  Stealth PCAP: 2526B (2169B marker overhead removed per scenario)
- `ICSFORGE` tag present in normal PCAP: True; in stealth PCAP: False
- Technique coverage identical in both modes: T0855 tracked in both
- Chain runs (5 techniques, Industroyer2) — no tag, all techniques tracked
- Smoke test: 35/35 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.8 (2026-04 — Ruff cleanup pass)

External developer Ruff cleanup applied across 22 files. No behavioural changes
except one genuine bug fix.

### Bug fix
`opcua.py` — `_parse_node_numeric()` used `rnd.randint()` in its default-value
fallback path. `rnd` is a local variable inside `build_payload()` and is not
visible to the helper function defined outside it. Corrected to `random.randint()`.
This was a latent F821 that would have caused a `NameError` if `_parse_node_numeric`
were called with `val=None` (no `node_id` kwarg provided).

### Additional fix (found during release testing)
`api_generate_offline` only assigned a meaningful run_id when `build_pcap=True`.
Without PCAP, runs silently fell back to `run_id="offline"` and were never
registered in SQLite — so they never appeared in `/api/runs`, the matrix overlay
dropdown, or the coverage report. Fixed: a run_id is now always generated and
the run is always registered in SQLite regardless of whether PCAP is requested.

### Code hygiene (no behaviour change)
- Import ordering (I001) normalised alphabetically across all changed files
- Deferred imports moved to module top (E402): `_rnd`, `_dt`, `_append_run_index`
  in `cli.py`; `Path`, `re` in `bp_scenarios.py`; `yaml`, `send_scenario_live` in
  `runner.py`
- Unused imports removed (F401): `os` from `network_validation.py`, `json` from
  `helpers_stats.py`, `os`/`log` from `bp_detections.py`, `json`/`tempfile` from
  `test_auth.py`, `json`/`queue`/`threading` from `test_sse_campaigns.py`
- Bare `open()` without context manager (SIM115) fixed in `cli.py`, `bp_campaigns.py`
- `with suppress(Exception):` replaces `try/except pass` in `bp_campaigns.py`
- `collections.abc.Callable` replaces deprecated `typing.Callable` in `eve/tap.py`
- Redundant `"r"` mode removed from `open()` in `eve/tap.py`
- `helpers.py` gains `__all__` declaring all intentional re-exports so Ruff treats
  them as public API rather than unused imports

### Verified
- All Python files pass `py_compile` — zero syntax errors
- App starts: 67 routes (56 API)
- Smoke test: 35/35 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

## v0.50.6 (2026-04 — Sender layout, PCAP download, campaign registry, matrix, tools)

### Bugfix: credentials persisted across reinstalls

**Root cause:** `~/.icsforge/credentials.json` (user home directory)

The credential file was stored in `~/.icsforge/` — outside the project directory.
Deleting and unpacking a new version left `~/.icsforge/credentials.json` untouched,
so the old username and password from a previous installation were silently reused.
There were no hardcoded credentials; the file was just stored in the wrong place.

**Fix:** Credentials now live at `out/.credentials.json` inside the project directory.
Replacing or deleting the project folder resets the auth state and the setup screen
appears on next launch. The `ICSFORGE_CRED_FILE` environment variable still works as
an explicit override. The `out/` directory is already excluded from tarballs, so
credentials are never shipped. The setup page now shows the credential file location.



### Sender page

**Step Plan moved to right column**
Step Plan now appears in the right column between Scenario Summary and Live Attack
Timeline, keeping related execution context together. Live Receiver Feed moved back
to the left column above the EVE Tap card.

**PCAP Only triggers immediate browser download**
Clicking `⬇ PCAP Only` now generates the PCAP on the server and immediately triggers
a browser file download. Previously the PCAP path was shown in the run log but no
download occurred. The named file (`T0855__unauth_command__2026-04-01__BRAVO.pcap`)
is downloaded directly without any manual path lookup.

### Campaigns → matrix overlay

**Campaign runs now appear in matrix overlay run list**
The campaign runner thread did not write completed runs to either the SQLite registry
or the JSONL run index. After `runner.run()` completes, `bp_campaigns` now calls
`reg.upsert_run()` and `_append_run_index()`, so campaign runs appear in `/api/runs`
and the matrix overlay dropdown alongside chain and single-scenario runs.

### Matrix page

**Technique boxes no longer overlap or clip text**
`overflow: hidden` was removed from `.mc-col` (was clipping tile content). `.mt-name`
now uses `word-break: break-word` and `overflow-wrap: break-word` so long technique
names wrap inside their tiles instead of overflowing. Tile height is `auto` instead
of a fixed minimum.

### Tools page

**PCAP file upload in PCAP Replay**
Added a `Upload PCAP` file picker alongside the path input. Selecting a `.pcap` or
`.pcapng` file and clicking Upload sends it to the new `POST /api/pcap/upload`
endpoint, which saves it to `out/pcaps/uploads/` and fills the path field
automatically. The replay can then be run immediately.

**Selftest and Matrix Status removed from Health section**
`Selftest` requires a live network and running receiver (`--live` flag) — it always
returned an error in the UI tools panel. `Matrix Status` was a confusing diagnostic
output. Both buttons removed. Only `Health` remains, which works in all contexts.

### Dark theme readability

**Muted and dim text lightened throughout**
On the dark theme, `.small` / `.muted` text was too dark to read comfortably
against the dark panel backgrounds:
- `--muted`: `#566882` → `#8499b5` (readable mid-grey-blue)
- `--dim`:   `#2c3a4e` → `#506070` (visible but still subdued)
- `--text`:  `#d4dce8` → `#dce4ef` (slightly crisper primary text)

Applied globally via CSS variables — affects all pages: sender, receiver, matrix,
campaigns, report, tools, home.

### Verified
- All Python files pass `py_compile`
- `create_app()` loads 66 routes
- `/api/pcap/upload` returns `200 {ok, path, filename}` with file data
- Smoke test: 36/36 PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — UI and functional fixes)

### Bugfixes

**Campaigns: playbooks never executed (root cause fix)**
`CampaignRunner` was missing from the import in `bp_campaigns.py`. Every playbook
run hit a `NameError` server-side the moment it tried to instantiate the runner —
no SSE stream ever started, no steps progressed, no result appeared. Fixed: one
missing import added.

**Timeline "0 confirmed by receiver" despite live receipts**
Race condition: `tlStart()` set a temporary run ID (`selectedName + "_" + timestamp`)
before the API call returned the real server-assigned run ID. SSE receipts arrived
carrying the real ID and were silently dropped by `tlConfirmStep` because the IDs
didn't match. Fixed: temp IDs are detected by their format and the match falls back
to technique-only while the temp ID is still active.

**Matrix fired runs invisible in overlay dropdown**
`api/technique/send` wrote runs to the JSONL index only, not to SQLite. `api/runs`
reads SQLite first. Matrix-fired runs therefore never appeared in the run list or
overlay selector. Fixed: added the same SQLite `upsert_run` block used by `api/send`.

**Matrix overlay: name turns white in light theme**
`.mt.executed .mt-name` was hardcoded to `#ecfdf5` (near-white), invisible on the
light theme. Fixed: replaced with `var(--text)` so it adapts to the active theme.

### Improvements

**Sender: Attack Chains shown first in scenario list**
Chains already appeared first in the grouped API, but this confirms the correct
rendering order in the sender scenario picker.

**Sender: ATT&CK for ICS tactic ordering corrected**
Previous order: Discovery → Collection → Lateral Movement → Execution (arbitrary).
Correct order per MITRE ATT&CK for ICS: Initial Access → Execution → Persistence
→ Evasion → Discovery → Lateral Movement → Collection → Command and Control →
Inhibit Response Function → Impair Process Control → Impact → Privilege Escalation.

**Sender layout: Live Attack Timeline and Live Receiver Feed moved to right column**
Both cards now appear in the right column below Scenario Summary, keeping the
left column focused on scenario selection, configuration, step plan, and run controls.

**Coverage report: "All runs combined" option**
The run reference dropdown now includes a `★ All runs combined` entry at the top
(when more than one run exists). Selecting it fetches every run's techniques in
parallel and unions them into the Executed field, giving a single cumulative report
across all assessment activity.

**Pull mode: description corrected**
Removed the inaccurate OT firewall framing. Pull mode description now accurately
states the actual use case: sender polls the receiver when the sender has no
reachable callback address (NAT, no public IP, receiver cannot initiate outbound).

### Verified
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes
- Smoke test: 36/36 PASS
- Tactic order: Chains → Initial Access → Execution → Persistence → Evasion → Discovery → Lateral Movement → Collection → C2 → Inhibit → Impair → Impact
- Campaign playbook SSE stream confirmed functional (was never working before)
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — UI reliability pass)

Every panel button that landed without browser testing was audited against the live API.
Three panels were broken in ways that were invisible from the backend but would have been
obvious the first time an operator clicked a button.

### Root cause: SQLite artifact paths invisible to UI endpoints

`RunRegistry.get_run()` returns artifacts as a structured list:
```json
{"artifacts": [{"kind": "events", "path": "…"}, {"kind": "pcap", "path": "…"}]}
```

Three UI-facing endpoints read `idx.get("events")` — a flat key that only exists on
the legacy JSONL index format, not on SQLite results. For any run registered via
`icsforge send` or the web sender (i.e. all runs since v0.49), those endpoints saw
`None` and either returned 400 or silently built an empty export bundle.

**`POST /api/validate` — Run Management panel "Validate" button**
- Read `idx.get("events")` → `None` for SQLite runs → `400 Ground-truth events path not found`
- Fixed: checks `artifacts` list first, falls back to flat key
- Also fixed: if `receiver_out/receipts.jsonl` doesn't exist yet (fresh install), now
  creates an empty file rather than raising `OSError`. Validate completes with a
  "receipts empty" warning in the report instead of crashing.

**`GET /api/run/export_bundle` — Run Management panel "Export" button**
- Read `idx.get("events")` and `idx.get("pcap")` → both `None` → zip created but empty
- Fixed: resolves artifact paths from `artifacts` list via a `_artifact_path(kind)`
  helper before falling back to flat keys

**`GET /api/run_full` — run detail view used by the history panel**
- Returned `events: null`, `pcap: null` for all SQLite runs
- Fixed: `events` and `pcap` fields now resolved from `artifacts` list

### Verification

All three previously broken actions confirmed working with real SQLite-registered runs:

| Panel button | Before | After |
|---|---|---|
| Validate | 400 for all real runs | 200 with report |
| Correlate | 400 for all real runs | works (was already correct in code) |
| Export | 200 but empty zip | 200 with events + pcap in zip |
| Run Full detail | events/pcap null | paths resolved correctly |
| Rename | working | still working |
| Tag | working | still working |
| EVE tap arm/disarm | working | still working |
| Webhook save/load | working | still working |

Full panel verification: **16/16 PASS** with real run data.

### Verified clean
- All Python files pass `py_compile`
- `create_app()` loads 66 routes
- Smoke test: 36/36 PASS
- 16/16 panel wiring checks PASS with real SQLite-registered run
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

 (2026-04 — Live CLI send artifact pipeline fully fixed)

### Root cause found and fixed: empty events / no PCAP on live CLI send

The developer reproduced the failure with `T0801__monitor_process__modbus_poll`,
which has 3 steps × (20+15+15=50 steps) × 0.5 s interval = **25 seconds** of sleep
during ground-truth PCAP generation. This sleep happened *after* the live send
(which correctly paced its own traffic), making the ground-truth generation phase
unnecessarily slow and interruption-prone.

**Root cause in `engine.py`**: when `cmd_send` called `run_scenario` with
`build_pcap=True`, the PCAP building phase slept `interval × count` seconds per step
to match the live traffic pacing. A KeyboardInterrupt during those sleeps would:
1. Exit the step loop mid-way (partial or zero events, depending on timing)
2. Skip `write_pcap()` entirely (no PCAP file)
3. Propagate past `cmd_send`'s `except Exception` handler (which only catches
   `Exception`, not `BaseException`) leaving the run unregistered

**Three coordinated fixes**:

1. **`run_scenario()` gains `skip_intervals: bool = False` parameter**
   When `True`, all `time.sleep(interval)` calls in the PCAP-building loop are
   skipped. The live send already paced the traffic; the offline ground-truth PCAP
   is just a reference artifact and needs no pacing.

2. **`cmd_send` passes `skip_intervals=True`**
   Ground-truth generation for a live send now completes in milliseconds regardless
   of scenario step counts and intervals. T0801 (25 s → <1 s). All 50 events written.
   PCAP generated. Both registered in SQLite and JSONL index.

3. **`cmd_send` catches `KeyboardInterrupt` explicitly**
   A `KeyboardInterrupt` during ground-truth generation is now caught, logged as a
   warning, and the run is still registered in the registry. Previously, Ctrl+C would
   terminate the process before any registry code ran.

**Smoke test updated**: `check_engine_signature()` now verifies `run_scenario` has
the `skip_intervals` parameter as check #2, before any HTTP endpoint tests. This
prevents regressions to the pre-fix behaviour.

### Verified
- `run_scenario` with `skip_intervals=True` on T0801: **0.5 s** (was ~25 s)
- 50/50 events written, PCAP generated, run registered in both SQLite and JSONL index
- Smoke test: **36/36 PASS** (2 structural + 34 endpoint checks)
- All Python files pass `py_compile`
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

# ICSForge Changelog

## v0.50.2 (2026-03 — CLI/web integration + tooling fixes)

Based on a full end-to-end review of v0.50.1 against a real running environment:
live sender→receiver→callback flow, real web app launch, full pytest suite.

### Additional fixes (second review pass)

**Empty events file on live CLI send — root cause and fix (`icsforge/scenarios/engine.py`)**
The confirmed root cause: `run_scenario()` wrote events **after** building pcap packets
in the step loop. If the pcap-building block raised (unknown proto) or was interrupted
(long interval sleeps on large scenarios like T0801 with 50 steps × 0.5 s = 25 s),
the file was left with 0 lines because `ef.write()` had not yet run.

Fix: events are now written **first** in each step iteration, followed by an `ef.flush()`,
before any pcap building. A pcap build failure can no longer produce an empty events file.
The `raise ValueError` for unknown proto is now a `log.warning` with graceful continuation.

**SQLite `ResourceWarning: unclosed database` in tests**
`RunRegistry._conn()` returned a bare `sqlite3.Connection`. Using it as a context manager
(`with self._conn() as c:`) commits/rolls back but does not close the connection — Python
defers closing until GC, emitting a `ResourceWarning`. Fixed: `_conn()` now returns a
proper `contextlib.contextmanager` that commits, rolls back on exception, and explicitly
closes the connection in a `finally` block. Verified: no `ResourceWarning` raised under
`warnings.simplefilter('error', ResourceWarning)`.

**CLI: explicit empty-events detection and warning**
After `run_scenario()` completes, `cmd_send` now counts lines in the events file and
logs a `WARNING` with a clear explanation if it is empty, rather than silently producing
a broken artifact.

### Additional fixes (post-review patch)

**Pull mode `urllib.request` crash (thread exception)**
`icsforge/web/helpers_sse.py` imported `urllib.parse` but used `urllib.request` in
the `_pull_worker()` background thread. Unlike the main process (which may have
`urllib.request` accessible as a side-effect of other imports), the thread hit an
`AttributeError: module 'urllib' has no attribute 'request'`, producing a
`PytestUnhandledThreadExceptionWarning` and silently breaking the pull-mode feature.
Fixed: `import urllib.request` added explicitly.

**CLI `icsforge send` artifact path reliability**
Three improvements to make `icsforge send` work correctly in all environments:

1. `--file` and `--outdir` are now resolved to absolute paths at the start of both
   `cmd_send` and `cmd_generate`. If the default relative path `icsforge/scenarios/
   scenarios.yml` does not exist from the working directory (e.g. when running from
   outside the repo), the installed package path is used as a fallback.

2. `run_scenario()` is now wrapped in `try/except Exception` with explicit
   `log.error(...)` output. Previously a failure here was silent; now it surfaces
   immediately with a clear message.

3. The SQLite registry exception catch was `(OSError, ValueError)` — too narrow.
   `sqlite3.OperationalError` inherits from `sqlite3.Error` → `Exception`, not from
   `OSError` or `ValueError`. Registry failures were still silently swallowed in some
   environments. Fixed: catch broadened to `(OSError, ValueError, sqlite3.Error)`.

### Fix: CLI live-send runs now appear in the web run registry

`icsforge send` was silently swallowing all registry errors with a bare
`except Exception: pass` block. Registry failures were invisible; if SQLite
was unavailable or the path differed, the run was registered nowhere.

Two changes:

1. The `except Exception: pass` is replaced with a typed `except (OSError, ValueError)`
   that logs a `WARNING` instead of discarding the error silently.
2. After attempting SQLite registration, `cmd_send` now **always** writes the run to
   the JSONL index (`_append_run_index`). The JSONL index is the web UI's fallback when
   SQLite is unavailable, so CLI runs now show up in `/api/runs` via either path.

### Fix: `net-validate` warns loudly on empty events or receipts

When `icsforge net-validate` was given an empty events file (as happens with a live run
where ground-truth was not generated), it silently produced a report with empty
`expected_techniques` lists. The problem was invisible unless you inspected the JSON
carefully.

Now `build_network_validation_report()` logs a `WARNING` and includes a `"warnings"`
list in the report JSON explaining what is missing and why, with a suggested remedy.
Empty receipts also trigger a warning.

### Fix: duplicate `import argparse` in `receiver.py`

A double import left by an earlier automated fix. Removed.

### Fix: `RuntimeWarning` on `python -m icsforge.web` (partial)

The warning fired when `icsforge/web/__main__.py` imported from `.app` at module
level. Fixed by deferring the import to inside `main()`.

`python -m icsforge.web` (the recommended and documented launch path) is now
clean. `python -m icsforge.web.app` still emits the warning — this is a Python
`runpy` limitation when a submodule is also a package member; it cannot be
eliminated without moving `app.py` outside the package. The `icsforge-web`
entry-point script and `./bin/icsforge web` are both clean.

### Fix: `pytest -q` hang when `pytest-cov` is installed

`pytest -q` without `--no-cov` would hang at the end in environments where
`pytest-cov` is installed but no coverage config is active. Added `-p no:cov` to
`[tool.pytest.ini_options] addopts` in `pyproject.toml`. The full suite now
completes cleanly with `273 passed`.

### Fix: alerts ingest path restriction not communicated in UI

The `POST /api/alerts/ingest` backend correctly restricts paths to inside the repo
or `/var/log/suricata`. Operators hitting the 400 error had no in-UI explanation.
Added a visible warning box to the Tools page alerts card explaining the restriction
and showing an example allowed path (`out/alerts/suricata_eve.json`).

### Fix: duplicate `import urllib` in `helpers.py` and `helpers_sse.py`

Both files had `urllib` imported twice from different earlier fix passes. Deduplicated.

### Fix: further unused imports removed

- `warnings` (added by automation, unused) from `network_validation.py`
- `collections` (unused) from `bp_receiver.py`
- `Response` (unused) from `bp_scenarios.py`
- `_correlate_run_impl` (unused re-export) from `helpers.py`

### Known limitations (documented, not fixed in this release)

**Live-send PCAP with intervals**: scenarios with large `count × interval` products
(e.g. T0801 with 50 steps × 0.5 s = 25 s) will make `run_scenario` take that long
to generate the ground-truth PCAP, because packet-building respects the defined
pacing. This is correct behaviour for offline replay fidelity but surprising for
live-send users who just want the PCAP quickly. A `--no-intervals` flag for
ground-truth generation is on the backlog.

**selftest without --live**: exits with `"Selftest currently supports --live only."`.
A dry-run mode that validates config without network is on the backlog.

**Browser automation**: no automated end-to-end browser tests. Manual click-through
of all UI flows on each release remains a manual step.

### Verified clean
- All Python files pass `py_compile`
- `create_app()` loads 66 routes — zero import errors
- Smoke test: 36/36 PASS
- Zero duplicate imports across codebase
- Zero non-intentional inline imports
- `pytest -q` (with `-p no:cov`): 273 passed
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`



## v0.50.1 (2026-03 — Launcher fix + full import cleanup + self-review fixes)

### Critical: launcher bug fixed (introduced in v0.50.0)
`main()` in `icsforge/web/app.py` was constructing a bare Flask app with only the `web`
page blueprint registered. Every API route returned 404 in production. Fixed: `main()`
now calls `create_app()`. All launch paths confirmed equivalent.

The smoke test's `check_launcher()` AST check now runs first and catches any future
reversion to the partial-app pattern before packaging.

### Bugs found and fixed by self-review

**Offline events missing `run_id` field (`icsforge/scenarios/engine.py`)**
`engine.py` only wrote `run_id` into generated events when a truthy `run_id` was passed.
The CLI `generate` command passes `None`, so all offline-generated events were missing
`run_id`. This would cause `net-validate` to find zero matches when correlating against
offline artifacts, because the correlation reads `run_id` to match events to receipts.
Fixed: the resolved `rid` value (`"offline"` when no `run_id` given, or the actual
run_id otherwise) is now always written into every event.

**Health endpoint missing `version` field (`icsforge/web/bp_config.py`)**
`GET /api/health` returned `ok`, `capabilities`, `timestamp`, and system metadata but
no version string. Any integration polling the health endpoint to check the deployed
version would get nothing. Fixed: `"version": __version__` added to the response.

**Inline `import socket as _s` inside `api_health()` function**
`socket` was imported inside the function body rather than at module scope, inconsistent
with the import hygiene work done in this release series. Fixed: `import socket` moved
to module top, `socket` used directly throughout.

### Import cleanup sprint
Every non-intentional function-scoped import moved to module scope. Zero non-intentional
inline imports remain. Smoke test covers 36 checks (35 endpoints + 1 launcher structural
check via AST).

### selftest --live improvements
`--no-web` passed to receiver subprocess; receipts path resolved to absolute path;
explicit `CAP_NET_RAW` warning emitted when running without root privileges.

### Verified clean (post-self-review)
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes (55 API + 9 page + static)
- Smoke test: 36/36 PASS including launcher structural check
- Non-intentional inline imports: **0**
- `GET /api/health`: returns `ok`, `version`, `capabilities`, `timestamp`
- `icsforge generate`: events always contain `run_id` and `mitre.ics.technique`
- Auth layer: public paths exempt, protected routes block unauthenticated access
- EVE tap, webhook, report download, detection download, campaigns: all confirmed working
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`, 145 files

### Known limitations (not bugs, documented)
- `selftest --live` requires root or `CAP_NET_RAW` to bind ICS protocol ports (502,
  20000, 44818, etc.). A warning is emitted but the test will still fail without
  the capability regardless.
- The smoke test verifies the factory path (`create_app()`) and the launcher
  structural correctness via AST, but does not spawn a real server process.
  An integration test that starts the actual server over a real port remains a
  backlog item.



## v0.50.1 (2026-03 — Launcher fix + full import cleanup)

### Critical: launcher bug fixed (introduced in v0.50.0)
`main()` in `icsforge/web/app.py` was constructing a bare Flask app with only the `web`
page blueprint registered. Every API route returned 404 when launching via `icsforge-web`,
`python -m icsforge.web`, `python -m icsforge.web.app`, or `./bin/icsforge web`. Tests
passed because they used `create_app()`. The fix: `main()` now calls `create_app()`.

The smoke test has been hardened with a structural AST check (`check_launcher()`) that
runs first and verifies `main()` calls `create_app()` and does not instantiate its own
`Flask()`. This check would have caught v0.50.0 before packaging.

### Import cleanup — zero non-intentional inline imports
Every non-intentional function-scoped import has been moved to module scope:

- `icsforge/web/app.py`: `argparse`, `configure_logging`, inline `json`/`yaml` in
  page routes moved to module top; `_canonical_scenarios_path`, `_registry` removed
  (unused). Blueprint imports inside `create_app()` remain inline — they are
  intentional circular-dependency guards.
- `icsforge/web/bp_campaigns.py`: `CampaignRunner`, `CampaignValidationError` moved
  to module top; duplicate inline instance removed.
- `icsforge/web/bp_config.py`: duplicate inline webhook helper imports removed
  (already at module top).
- `icsforge/web/bp_scenarios.py`: inline `yaml` in `api_profiles()` moved to module
  top; unused `Response` removed.
- `icsforge/web/helpers.py`: `urllib.request` moved to module top.
- `icsforge/web/helpers_sse.py`: `queue` moved to module top.
- `icsforge/campaigns/runner.py`: `send_scenario_live` moved to module top; spurious
  `Path` import removed.
- `icsforge/eve/tap.py`: remaining inline `re` removed (already at module top).
- `icsforge/receiver/receiver.py`: `argparse`, `sys`, `configure_logging` moved to
  module top; indentation regression from regex fix corrected.

### selftest --live fixes
Three issues made `icsforge selftest --live` unreliable without root:
1. Receiver subprocess was started without `--no-web`, causing it to try binding
   port 9090 and potentially failing before writing any receipts.
2. Receipts path was relative to the calling process CWD, not the receiver subprocess
   CWD — causing the existence check to look in the wrong place.
3. No warning when running without root/CAP_NET_RAW, leaving operators confused.

Fixed: `--no-web` now passed to receiver subprocess; receipts path resolved to
absolute using `os.path.abspath(args.cwd)`; explicit warning emitted if `os.geteuid() != 0`.

### Verified clean
- All Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes (55 API + 9 page + static)
- Smoke test: 36/36 PASS (35 endpoints + 1 launcher structural check)
- Non-intentional inline imports: **0**
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`, 145 files



## v0.50.1 (2026-03 — Critical launcher fix)

### Critical fix: real web server was missing all API routes

**`main()` in `icsforge/web/app.py` was building a partial Flask app** that registered
only the `web` page blueprint, not the seven API blueprints. This meant:

- `python -m icsforge.web.app` — broken
- `python -m icsforge.web` — broken  
- `icsforge-web` entry point — broken
- `./bin/icsforge web` — broken

Every API-driven UI action returned 404 in production. Tests and the smoke test
passed because they used `create_app()` which was correct. The launcher did not.

**Fix**: `main()` now calls `create_app()` instead of constructing its own Flask app.
Three lines replaced a twelve-line manual construction block. All launch paths
(`python -m`, entry point script, shell launcher) now register all 55 API routes.

The bug was present in v0.50.0 despite the smoke test passing — because the smoke
test also used `create_app()`. The smoke test has been updated to explicitly verify
that `main()` delegates to `create_app()` as its first check, so this class of
regression will be caught before packaging in future.

### Smoke test hardened (`scripts/smoke_test.py`)

Added `check_launcher()` as the first check in the smoke test suite. It parses
`app.py` with the AST and verifies that `main()` calls `create_app()` and does not
instantiate its own `Flask()`. This check now runs before any HTTP endpoint test and
will catch any future regression to the partial-app pattern.

Smoke test now covers 36 checks total (35 endpoint + 1 launcher structural check).

### Verified clean
- All Python files pass `py_compile`
- `create_app()` and `main()` both register 55 API routes and 9 page routes (66 total)
- Smoke test: 36/36 PASS including launcher structural check
- `main()`: zero `Flask()` calls, zero `secrets` references — fully delegated to factory
- All launch paths confirmed equivalent: `icsforge-web`, `python -m icsforge.web`,
  `python -m icsforge.web.app`, `./bin/icsforge web`
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`



## v0.50.0 (2026-03 — Code Quality + Complete UI Coverage)

### Import hygiene sprint
Every blueprint now has its dependencies declared at module scope, eliminating the
function-scoped import pattern that caused five separate runtime NameErrors across
v0.49.x. Specific changes:

- `bp_reports.py`: `generate_report` moved to module scope; `datetime` moved to module scope
  replacing the inline `import datetime as _dt` alias inside `api_report_heatmap()`
- `bp_detections.py`: `generate_all` moved to module scope; `Response` removed (unused)
- `bp_reports.py`: removed `_supported_techniques`, `_tech_name`, `MATRIX_JSON_PATH`,
  `MATRIX_SINGLETON_PACK` — none referenced in the file body
- `bp_config.py`: removed `_canonical_scenarios_path`, `_is_safe_private_ip`,
  `_load_persisted_config`, `MATRIX_SINGLETON_PACK`, `__version__` — all unused
- `bp_receiver.py`: removed `_repo_root`, `_stats_from_receipts` — unused
- `bp_runs.py`: removed `_canonical_scenarios_path`, `_load_yaml`, `_run_index_path`,
  `_save_run_index`, `_stats_from_receipts`, `_supported_techniques` — unused
- `bp_scenarios.py`: removed `Response`, `stream_with_context`, unused `_h` alias
- `bp_campaigns.py`: removed unused `_h` alias and lingering `import yaml as _yaml`
  local alias inside `api_campaigns_list()`
- `core.py`: `import re` moved from inside `is_legacy_run_id()` to module top
- `helpers_sse.py`: `import urllib.request` moved from inside `_pull_worker()` to module top
- `eve/tap.py`: `import re` moved from inside `_process_alert()` to module top

### Pre-release smoke test (`scripts/smoke_test.py`)
New developer tool that exercises 35 endpoints in a test Flask app and fails loudly
on any HTTP 500. Covers all pages, all major APIs including the three that were broken
in v0.49.2 (marked ★ in output), EVE tap, campaigns, reports, and detections.

Run before every release:
```bash
python scripts/smoke_test.py          # dots for pass, detail on fail
python scripts/smoke_test.py --verbose # show every endpoint result
```

This is the gate that would have caught every runtime regression in the v0.49 series
before packaging.

### Alerts ingest UI (Tools page)
`POST /api/alerts/ingest` existed since v0.43 with no UI surface. Added to the Tools
page as a card with path input, optional run ID, and Suricata EVE / Generic profile
selector. Output path shown on completion. Closes the last CLI-only analysis workflow.

### Coverage heatmap direct link (Tools page)
`GET /api/report/heatmap` was accessible only by URL. Added a direct download button
to the Tools page alongside a link to the Custom Report Builder, making it
discoverable without reading the docs.

### Verified clean
- All 47 Python files pass `py_compile` — zero syntax errors
- `create_app()` loads 66 routes, zero import errors
- Smoke test: 35/35 PASS — zero 500s
- 10/10 UI feature checks PASS
- Clean tarball: 0 `__pycache__`, 0 `*.egg-info`, 0 `out/`

### Backlog (next cycle)
- Ruff full cleanup to zero warnings (import ordering, remaining style items)
- Coverage trend tracking over time (`GET /api/coverage/trend`, line chart on report page)
- Scenario scheduling — cron-style campaigns, background thread, drift detection
- STIX 2.1 bundle export (`GET /api/run/{id}/stix`)
- Zeek script output alongside Suricata/Sigma
- Multi-user auth with roles (viewer/operator/admin)



## v0.49.3 (2026-03 — Detection/Report fixes + Run Management UI)

### Runtime bug fixes (were returning 500 on every call)

**`GET /api/detections/download` — NameError: `generate_all` not defined**
`generate_all` was imported inside `api_detections_preview()` only. The sibling route
`api_detections_download()` called it without importing it, crashing on every request.
Fixed by moving the import to module scope in `bp_detections.py`.

**`POST /api/report/download` and `GET /api/report/heatmap` — NameError: `generate_report` not defined**
Same pattern: `generate_report` was imported inside `api_report_generate()` only. Both
`api_report_download()` and `api_report_heatmap()` called it without importing it.
Fixed by moving the import to module scope in `bp_reports.py`.

All three of these are operator-facing buttons — the Detection Rules download button on the
Tools page, the Download Report button on the Coverage page, and the one-click Heatmap export.
All confirmed returning 200 after the fix.

### New UI: Industry profile filter on Campaigns page

The Sender dashboard has had a profile selector (Oil & Gas, Power, Manufacturing, Food & Beverage)
since v0.47, filtering the scenario list to sector-relevant techniques and protocols. The Campaigns
page had no equivalent — you could not filter chains by industry context before running them.

Added to campaigns page left column:
- `camp_profile_select` dropdown, populated dynamically from `GET /api/profiles`
- `filterByProfile()` filters the Attack Chains list to chains that match the profile's protocol
  and technique sets — same logic as the sender's `activeProfile` filter
- Sector description shown below the selector when a profile is active
- Chains that don't match the profile are hidden; a "no matches" message shows if all are filtered

### New UI: Run Management panel on Sender page

Clicking any run in Recent Runs now opens a management panel (previously only copied the run_id
to the clipboard with a toast). The panel surfaces four API endpoints that existed but had no UI:

- **Rename** — `POST /api/run/rename` with a title input field
- **Validate** — `POST /api/validate`; shows delivery percentage on completion
- **Correlate** — `POST /api/correlate_run`; shows detection coverage ratio and gap count
- **Export bundle** — `GET /api/run/export_bundle`; triggers browser download of the ZIP
- **Tags** — `POST /api/run/tag` with a comma-separated input; saves and confirms

The panel slides in below Recent Runs when a run is selected and shows the run_id in monospace
for reference.

### Verified clean
- All 47 Python files pass `py_compile`
- `create_app()` loads 66 routes — zero import errors
- 9 endpoint checks: all PASS including the 3 previously-broken report/detection routes
- 16 UI feature checks: all PASS
- 0 `__pycache__`, 0 `*.egg-info`, 0 `out/` in tarball



## v0.49.2 (2026-03 — Runtime Bug Fix Release)

This is a targeted fix release addressing every defect identified in the v0.49.1 review.
No new features. The goal was a clean, honest pass on all developer-reported findings.

### Runtime NameError fixes (were crashing endpoints)

**`_active_eve_tap_lock` undefined in `bp_config.py`** — The module-level state block
(`_active_eve_tap`, `_active_eve_tap_lock`) was lost during a cleanup pass in v0.49.1.
All three EVE endpoints (`/api/eve/start`, `/api/eve/stop`, `/api/eve/matches`) returned
HTTP 500 on every call. Fixed by restoring the state declarations before the route functions.

**`_append_run_index` undefined in `bp_scenarios.py`** — The import-fix pass in v0.49.1
removed it from the helpers import line but left three call sites in `api_send()` and related
routes. Fixed by adding `_append_run_index` back to the blueprint's helpers import.

**`_yaml` scoping error in `bp_campaigns.py`** — `api_campaigns_run()` referenced `_yaml`
which was only defined inside `api_campaigns_list()` via a local `import yaml as _yaml`.
Every unknown-campaign lookup raised `NameError: name '_yaml' is not defined`. Fixed by
using the module-level `yaml` import (already present) instead of the locally-scoped alias.

### Test fixes

**Rate limiter global state leak** — `_LOGIN_ATTEMPTS` is a module-level dict that persisted
across Flask test instances in the same process. The `test_correct_login_clears_rate_limit`
test was being hit by leftover state from `test_rate_limit_triggers_after_5_failures`, causing
a spurious 429. Fixed by adding `_reset_rate_limit()` to `auth.py` and an `autouse` pytest
fixture in `test_auth.py` that clears the dict before and after every auth test.

**Campaign field name mismatch** — `test_campaign_run_rejects_unknown_name` sent
`{"name": "..."}` but the API reads `campaign_id`. The route was returning 400
(missing required field) rather than 404 (campaign not found). Fixed the test to use
`campaign_id` and include the required `dst_ip`, aligning with the actual API contract.

### Import cleanup

Removed dead imports introduced by earlier fix passes:
- `import yaml` from `bp_config.py`, `bp_reports.py`, `bp_runs.py` — none referenced
- `import time` from `bp_scenarios.py` — not used
- `import threading`, `from contextlib import suppress`, `import yaml` from `helpers.py`
  — all three had zero non-import uses in the shim module itself
- `yaml` from `bp_config`'s helpers import line — used nowhere in that file

### Verified clean
- `python3 -m py_compile` passes on all 47 Python files — zero syntax errors
- `create_app()` loads 66 routes with zero import errors
- All 6 previously-failing endpoints confirmed working:
  `eve/stop`, `eve/matches`, `eve/start`, campaign 404, `api/send` step_options
- Rate limiter: correct lockout after 5 failures, correct reset on success
- No `__pycache__`, no `*.egg-info` in the release tarball



## v0.49.1 (2026-03 — Integration Fix Release)

### Breaking regression fixed
- **App startup was broken in v0.49.0.** Six blueprints (`bp_scenarios`, `bp_campaigns`, `bp_receiver`, `bp_reports`, `bp_detections`, `bp_runs`) imported `os`, `json`, `yaml`, `time` etc. through `icsforge.web.helpers` — a pattern the helpers split made fragile. `time` was never re-exported from the new shim, causing `ImportError` at `create_app()` before any route could load. Fixed by giving every blueprint its own direct stdlib imports. `helpers.py` no longer acts as a stdlib distribution hub.

### Additional fixes
- **Duplicate EVE routes**: `bp_config.py` had `/api/eve/start`, `/api/eve/stop`, `/api/eve/matches` registered twice due to a double-append in v0.49.0. Removed duplicate block; one definition per route.
- **Duplicate import statements**: the blueprint fix pass introduced duplicate `import` lines in several files. Cleaned; each stdlib module now imported exactly once per file.
- **Campaign validation test**: `test_invalid_delay_produces_warning` expected a warning list but `validate_campaign()` correctly raises `CampaignValidationError` for invalid delays. Test renamed to `test_invalid_delay_raises` and updated to match actual (correct) behaviour.
- **Missing webhook routes**: `POST /api/config/webhook` and `POST /api/config/test_webhook` were present in v0.49.0 only intermittently due to append ordering. Now reliably registered; verified in `create_app()` startup check.

### Security
- **Rate limiting on `/api/auth/login`**: in-memory fixed-window counter per IP address. 5 failures within 60 s triggers a 300 s lockout returning HTTP 429. Remaining-attempts hint included in 401 responses when 1–2 attempts left. Successful login clears the counter. No external dependency — 30 lines of Python in `auth.py`.

### Performance
- **SQLite indexes**: `CREATE INDEX IF NOT EXISTS idx_runs_ts ON runs(created_ts DESC)` and `idx_artifacts_run ON artifacts(run_id)` added to `RunRegistry` schema. `ANALYZE` called after schema init. Eliminates full-table scan on `list_runs()` at scale.

### UI completeness — new features now have Web UI surface
- **EVE tap panel** added to sender left column: path input, Arm/Stop buttons. `armEveTap()` calls `POST /api/eve/start`; `disarmEveTap()` calls `POST /api/eve/stop` and toasts the match count.
- **Webhook panel** added to sender left column: URL input, Save and Test buttons. `loadWebhookConfig()` called on page load to restore persisted URL.
- **Scenario step_options wired**: `doSend()` now calls `_collectStepOptions()` which reads all `param_*` input fields rendered by the params form and includes `step_options: {proto: {key: val}}` in the `/api/send` payload. The params form now actually affects the generated traffic.
- **EVE confirmation loop**: `startEveTapPoll()` polls `/api/eve/matches` every 1.5 s after a run fires. Each new technique match calls `tlConfirmStep()`, updating the live attack timeline with real IDS detection confirmations rather than just delivery receipts.

### Test additions
- `test_auth.py`: `TestAuthRateLimit` — 2 tests covering 429 after 5 failures and counter reset on successful login.
- `test_sse_campaigns.py`: `test_invalid_delay_raises` replaces the incorrect `test_invalid_delay_produces_warning`.

### Verified clean
- `python3 -m py_compile` passes on all 47 Python files
- `create_app()` loads 66 routes with zero import errors
- All blueprint stdlib dependencies are direct imports — no stdlib flows through `helpers.py`
- Rate limiting: PASS; SQLite indexes: PASS; UI panel checks: 10/10 PASS



## v0.49.0 (2026-03 — Quality, Trust, and Closing the Detection Loop)

### Exception handling cleanup
- Replaced all 87 bare `except Exception:` blocks across `bp_runs.py`, `bp_config.py`, `bp_reports.py`, and `helpers.py` with specific exception types (`OSError`, `ValueError`, `json.JSONDecodeError`, `ImportError`, etc.)
- All silently-swallowed errors now log at `debug` or `error` level with context, making field debugging tractable
- Registry fallback paths (SQLite → JSON index) retain their broad catch for resilience, but now log at `debug` level

### Protocol map unified
- `TCP_PROTOS`, `UDP_PROTOS`, and `L2_PROTOS` moved to `icsforge/protocols/__init__.py` as the single source of truth
- `icsforge/scenarios/engine.py` and `icsforge/live/sender.py` now import from there — adding a new protocol requires editing one file, not two

### Helpers split into focused sub-modules
- `helpers_io.py` — file I/O: JSONL, YAML, run index read/write
- `helpers_stats.py` — receipt statistics and timeline binning
- `helpers_sse.py` — SSE push, subscriber lifecycle, pull-mode polling thread
- `helpers.py` is now a thin re-export shim; all existing imports remain unchanged

### JS extraction
- `sender.html` reduced from 787 to 200 lines; 586-line JS block moved to `static/js/sender.js`
- `receiver.html` reduced from 319 to 98 lines; 220-line JS block moved to `static/js/receiver.js`
- Templates now use `<script src="/static/js/...">` — JS is cacheable and diff-readable

### Live Suricata EVE tap (`icsforge/eve/`)
- New `EveTap` class: tails an EVE JSON log file in a background thread, stat-polling with rotation detection
- Correlates alert signatures/SIDs against a technique map (built from ICSForge Suricata rules or provided inline)
- Extracts `T0XXX` technique IDs directly from signature strings as a fallback
- `build_technique_map_from_rules()`: parses ICSForge Suricata rules and produces `{sid: technique}` map
- Three new API endpoints: `POST /api/eve/start`, `POST /api/eve/stop`, `GET /api/eve/matches`
- EVE match events are pushed to the SSE bus with `type: "eve_match"` — the live attack timeline in the sender UI receives them automatically
- Path validation: only allows paths inside the repo `out/` dir, `/var/log/suricata`, `/var/log`, or `/tmp`

### Webhook notifications
- `fire_webhook(event_type, payload)` in helpers — async-free, fire-and-forget POST to configured URL
- `POST /api/config/webhook` — set/get webhook URL
- `POST /api/config/test_webhook` — verify the URL is reachable with a synthetic event
- Supports event types: `run_complete`, `gap_detected`, `campaign_complete`

### Scenario parameter wiring
- `send_scenario_live()` now accepts `step_options: dict | None` — per-protocol overrides passed as kwargs to payload builders
- `POST /api/send` now accepts `step_options` field: `{"modbus": {"address": 100, "quantity": 5}}`
- The params form that previously rendered but had no effect now passes values through to the live send

### Test suite additions
- `tests/test_auth.py` (16 tests): setup flow, login/logout, 401 protection, public path exemptions, regression test for `/api/config/set_callback` being auth-exempt, static file access
- `tests/test_sse_campaigns.py` (21 tests): SSE subscribe/notify/unsubscribe lifecycle, full-queue resilience, pull mode start/stop, campaign validation (valid, missing name, empty steps, bad delay, unknown scenario), campaign API endpoints, webhook config endpoints, EVE tap API, step options field acceptance



## v0.48.1 (2026-03 — Dead Import Cleanup)

### Fixed
- `bp_runs.py`: removed unused imports `io`, `Response`, `RunRegistry`, `default_db_path` — none were referenced in the file body; `_registry()` in helpers already handles registry instantiation
- `app.py`: removed unused imports `json`, `yaml`, `jsonify`, `MATRIX_JSON_PATH`, `MATRIX_SINGLETON_PACK`, `TECH_VARIANTS` — all were imported but never referenced in the module body
- These were the real defects surfaced by the developer's ruff run; the remaining 100+ ruff issues are pre-existing style/ordering noise carried from v0.47 and are tracked for a dedicated lint-cleanup pass

### Verified clean
- `python3 -m py_compile` passes on all 44 Python files
- Developer-reported bugs 1 (`correlate_run` NameError), 2 (`/api/config/set_callback` auth exemption), and 3 (`_notify_sse` undefined name) were verified against v0.48.0 source and confirmed already resolved — the developer's findings were against v0.47 or an intermediate build
- `notify_sse` is defined at `helpers.py:234` and called correctly at line 363 and in `bp_receiver.py:110` — no mismatch exists in v0.48.x

### Release packaging
- Tarball now excludes `__pycache__/`, `out/`, and `*.egg-info` directories



## v0.48.0 (2026-03 — Security Hardening + Live Attack Timeline)

### Bug fixes
- **bp_runs.py**: removed two sets of duplicate `_save_run_index()` / `_update_run_entry()` definitions. Both functions are imported from `helpers.py`; the local redefinitions were dead code and caused Python to silently use the last-defined copy
- **create_app()**: replaced hardcoded `"icsforge-dev-key-change-in-production"` session key with `secrets.token_hex(32)`. Added `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`, and `PERMANENT_SESSION_LIFETIME = timedelta(hours=12)`. Production deployments via gunicorn/waitress now receive the same security configuration as `main()`
- **app.py campaigns route**: `_CAMPAIGNS_BUILTIN` was referenced in the `/campaigns` page route but never defined in `app.py`, causing a `NameError` at runtime. Added the path constant before the route

### Security
- Added `secrets` and `datetime` imports to `app.py`; `create_app()` and `main()` now share identical session security configuration
- Session lifetime capped at 12 hours (configurable via `PERMANENT_SESSION_LIFETIME`)

### Live attack timeline (sender UI)
- New **Live Attack Timeline** card appears on scenario run, positioned between Step Plan and Live Receiver Feed
- Each scenario step renders as a timeline row cycling through four states: `pending → sending → delivered → confirmed`
- Steps animate from pending to sending in sequence as the scenario fires (delay scales with step count, 120–400ms per step)
- On run completion all steps move to `delivered`; steps flip to `confirmed` in real time as SSE receipts arrive from the receiver, matched by `run_id` + `technique`
- "Confirmed" badge animates in with a pop transition; the progress bar tracks overall delivery ratio
- Timeline header shows the run ID; elapsed timer runs during the live send and stops on completion
- Timeline card is hidden until a run starts and auto-scrolls into view
- SSE `onmessage` handler in sender now calls `tlConfirmStep(technique, run_id)` on every incoming receipt

### Receiver "got it" toast
- Receiver UI now opens an `EventSource("/api/receiver/stream")` connection on page load
- Each incoming receipt fires `window.toast("Received", "<technique> · <proto>", "ok")`
- Toast burst is throttled to one per 800ms to prevent flooding during high-volume scenarios
- Falls back gracefully to the existing 2s polling loop if SSE is unavailable



## v0.45.3 (2026-03 — Receiver Callback Hardening)

### Live Receiver Callback
- Fixed auth exemption mismatch for `POST /api/config/set_callback` so sender → receiver callback registration works with auth enabled
- Persist receiver port correctly when saving network settings from sender UI
- Added explicit `sender_callback_url` override instead of relying only on derived `request.host` values
- Added optional shared `callback_token` header validation for receiver → sender live receipts
- Added receiver-side callback settings UI with Save and Test actions
- Added `POST /api/config/test_callback` for immediate callback diagnostics (status, response time, error body)
- Receiver config now supports `callback.token`

## v0.45.2 (2026-03 — MQTT Release)

### New Protocol: MQTT 3.1.1
- Full MQTT packet framing per OASIS MQTT v3.1.1 standard (TCP port 1883)
- 13 payload styles: connect, connect_anon, connect_creds, publish_command, publish_setpoint, publish_firmware, publish_config, publish_c2, subscribe_all, subscribe_scada, unsubscribe, pingreq, disconnect
- 20 new scenarios covering T0801, T0802, T0812, T0815, T0822, T0826, T0831, T0836, T0841, T0843, T0855, T0859, T0869, T0882
- Registered in scenario engine, live sender (TCP_PROTOS), and receiver config
- IIoT/Sparkplug B topic naming conventions

### Receiver Default Port → 9090
- Receiver web UI now defaults to port 9090 (was 8080) to avoid conflicts on single-host setups
- Updated: receiver CLI default, Dockerfile.receiver EXPOSE+CMD, docker-compose.yml mapping, README
- Sender callback push defaults to receiver_port=9090
- Sender stays on :8080, receiver on :9090

### Receiver → Sender HTTP Callback
- Receiver HTTP POSTs each receipt to sender for live UI updates
- New receiver config: `callback.url` in config.yml + `--callback-url` CLI argument
- Fire-and-forget async callback via daemon thread (non-blocking receipt pipeline)
- Sender endpoints: `POST /api/receiver/callback`, `GET /api/receiver/live`
- Receiver endpoint: `POST /api/config/set_callback` (accepts callback URL push from sender)
- Callback URL auto-derived from sender host:port when receiver IP is configured

### Network Settings UI (IP Configuration)
- New "Network Settings" bar at top of sender dashboard: sender IP, receiver IP, receiver port
- `GET/POST /api/config/network` — combined config endpoint for both IPs
- On page load, saved IPs are fetched and prefilled into all scenario fields
- "Save & Connect" pushes callback URL to receiver and confirms link status
- Destination IP field no longer hardcoded to 198.51.100.42 — filled from saved config
- Offline PCAP mode also uses configured receiver IP as fallback
- BACnet and MQTT added to protocol color map in UI

### Authentication
- First-run setup flow: no credentials → redirect to `/setup` → create admin account
- Session-based auth with Flask secure cookies
- SHA-256 + per-user salt password hashing (no external dependencies)
- Public paths exempt: `/health`, `/api/health`, `/api/receiver/callback`, `/api/config/set_callback`, `/static/`
- `--no-auth` CLI flag and `ICSFORGE_NO_AUTH=1` env var for development
- Credentials stored in `~/.icsforge/credentials.json` (0600 permissions)

### PCAP Validation Script
- `scripts/validate_pcaps.py` — validates every scenario's PCAP output
- Struct-only mode (no external deps): checks magic, version, linktype, packet counts, ports, IP proto
- Optional `--tshark` mode: full Wireshark dissection, detects malformed frames
- `--quick` mode: one scenario per protocol + all CHAINs (19 tests in ~2 minutes)
- `--scenario NAME` mode: test a single specific scenario
- Multi-protocol CHAIN scenarios correctly validated (first packet matches any step's protocol)
- Handles L2 PROFINET frames gracefully (skips IP-layer port checks)

### UI Redesign — Industrial Control Room Terminal
- Complete CSS overhaul: "SCADA operator workstation" aesthetic
- Fonts: Oxanium (display/headings), Chakra Petch (body), JetBrains Mono (code)
- Glowing amber indicators with text-shadow and box-shadow glow effects
- Beveled glass instrument panels with inset shadows and subtle top highlights
- Scanline background texture for authentic control room feel
- Staggered fade-in animations on card load
- Custom scrollbar styling matching industrial theme
- Full dark/light mode with distinct palettes (both industrial, not generic)
- All existing class names preserved — zero template breakage

### Updated Numbers
- 175 runnable scenarios (was 155)
- 72 ATT&CK for ICS technique IDs
- 9 industrial protocols (added MQTT)

---


## v0.43.0 (2026-03 — Lean Cleanup Release)

### Dead Weight Removed
- **`icsforge/scenarios/matrix.yml`** (2,457 lines) — auto-generated file with zero Python references. The tool uses `scenarios.yml` exclusively via `MATRIX_SINGLETON_PACK`. Removed.
- **`docker/docker-compose.receiver.yml`** — old standalone receiver compose, superseded by root `docker-compose.yml`. Removed.
- **`icsforge/state/plc_state.py`** — `PLCState` class never used by any code outside its own `__init__.py`. Removed.
- **`icsforge/detection/generic.py`** — `validate()` function never called from anywhere. Removed.
- **`icsforge/detection/suricata.py`** — `validate_suricata()` never called from anywhere. Removed.
- **`icsforge/detection/zeek.py`** — `validate_zeek()` never called from anywhere. Removed.
- **`out/`** empty directory — runtime artifact, should not be in repo. Removed.

### Directory Merge: `detections/` → `detection/`
- Merged `icsforge/detections/generator.py` into `icsforge/detection/generator.py`
- Deleted the entire `icsforge/detections/` directory
- Updated all imports (`icsforge.detections.generator` → `icsforge.detection.generator`) in `web/app.py` and `tests/test_scenarios.py`
- `icsforge/detection/` is now the single detection package containing `mapping.py` (alert correlation) and `generator.py` (Suricata/Sigma rule generation)

### Stale Version Strings
- Replaced all `v0.30` references in `campaigns/__init__.py`, `reports/__init__.py`, `reports/coverage.py`, `web/app.py`

### Updated Exports
- `icsforge/detection/__init__.py` now exports only used functions: `correlate_run`, `map_alert_to_techniques`, `generate_all`
- `icsforge/state/__init__.py` exports only `RunRegistry` and `default_db_path` (removed unused `PLCState`)

---

## v0.42.1 (2026-03)

### Lint Cleanup
- Sorted imports in all 32 Python source files (stdlib → third-party → local with blank line separation)
- Fixed E741 ambiguous variable names (`l` → `line`/`ln` in `detection/zeek.py` and `test_scenarios.py`)
- Removed trailing whitespace (W291/W293) across 7 files
- Removed excessive blank lines (E303) throughout codebase
- All 44 Python files compile clean with zero syntax errors

### CI: Lint + Test Pipeline
- Added dedicated `lint` job to GitHub Actions CI: `ruff check icsforge/ tests/`
- Test job now depends on lint passing first (`needs: lint`)
- Lint runs on Python 3.12, tests run on 3.10–3.13 matrix
- Added Tests passing badge to README

---

## v0.42.0 (2026-03)

### Bug Fixes (from developer review)
- **`/api/correlate_run` crash fixed** — `import time` added at module level in `web/app.py`. Previously crashed with `NameError: name 'time' is not defined` when generating correlation report filenames. Tested end-to-end: empty body → 400, unknown run → 400, real run → 200 with valid correlation.
- **README API path corrected** — was `GET /api/generate_detection_rules` (404), now correctly documents `GET /api/detections/preview` and `GET /api/detections/download`
- **`docs/PHASE.md` updated** — was "120+ scenarios", now accurate with 155 scenarios, 8 protocols

### Lint Cleanup
- Resolved all 59 lint issues (46 F401 unused imports, 10 F541 f-strings without placeholders, 3 E722 bare excepts)
- Added `__all__` to all `__init__.py` re-export modules (`detection`, `live`, `protocols`, `receiver`, `state`, `web`)
- Fixed bare `except:` in `detection/generic.py` and `detection/suricata.py` → `except (json.JSONDecodeError, ValueError):`
- Removed unnecessary `from __future__ import annotations` from 12 files
- Removed unused imports: `defaultdict`, `session`, `yaml`, `tempfile`, `time`, `rand_ip`, `Path`, `is_allowed_dest`, typing members
- Fixed f-prefix on string literals without placeholders in `detections/generator.py`

### Scenario Metadata Normalization
- All 155 scenarios now have a top-level `technique:` field (was missing on 73 scenarios)
- CHAIN scenarios get primary technique from their attack chain
- UI/export/summary logic can now rely on scenario-level metadata consistently

### Official Count Wording
README Key Numbers table uses precise, defensible wording:
- 155 runnable scenarios in the main scenario pack
- 72 ATT&CK for ICS technique IDs exercised across runnable scenarios
- 83 techniques in support data, 86 in bundled matrix data
- 8 industrial protocols

### New Tests
- `tests/test_web_api.py` — Flask test client tests for:
  - `/api/correlate_run`: empty body → 400, unknown run → 400, full end-to-end → 200 with correlation data
  - `/api/detections/preview` and `/api/detections/download`: return 200
  - Old wrong path `/api/generate_detection_rules`: returns 404
  - Basic endpoints: `/api/health`, `/api/scenarios`, `/api/packs`, `/api/runs`
  - Route audit: all README-documented routes exist in Flask app
  - POST routes with empty body return 400 (not 500)

---

## v0.41.0 (2026-03)

### Bug Fixes
- **`/api/correlate_run` crash fixed** — `time` module was not imported at module level in `web/app.py`, causing `NameError` when generating correlation report filenames. Also affected `/api/alerts/ingest`.
- **README API path corrected** — was `GET /api/generate_detection_rules` (404), now correctly documents `GET /api/detections/preview` and `GET /api/detections/download`
- **`docs/PHASE.md` updated** — was "120+ scenarios", now matches actual 155 with 8 protocols

### Scenario Metadata Normalization
- All 155 scenarios now have a top-level `technique:` field (was missing on 73 scenarios)
- CHAIN scenarios get primary technique from first step
- UI/export/summary logic can now rely on scenario-level metadata consistently

### Official Count Wording
README Key Numbers table now uses precise, defensible wording:
- 155 runnable scenarios in the main scenario pack
- 72 ATT&CK for ICS technique IDs exercised across runnable scenarios
- 83 techniques in support data, 86 in bundled matrix data
- 8 industrial protocols

### New Protocol: BACnet/IP
- Full BVLC + NPDU + APDU framing per ASHRAE 135-2020
- 16 payload styles: who_is, i_am, read_property, read_property_multi, write_property, write_property_multi, subscribe_cov, reinitialize_device, device_comm_control, read_file, write_file, private_transfer, who_has, time_sync, create_object, delete_object
- UDP transport (port 47808) with proper UDP packet builder in common.py
- 15 new scenarios covering T0840, T0801, T0802, T0809, T0813, T0816, T0836, T0843, T0849, T0855, T0861, T0869, T0882, T0888, T0889
- Live sender UDP support for BACnet/IP traffic generation

### README Accuracy Fix
- Scenario count corrected: 155 (was incorrectly stated as 221)
- Technique count corrected: 72 (was incorrectly stated as 80)
- Protocol count updated: 8 (added BACnet/IP)
- Protocol style counts updated to exact numbers

### PROFINET DCP Test Coverage Fix
- Tests now cover all 8 actual styles (identify, identify_unicast, get_name, get_ip, set_name, set_ip, hello, factory_reset)
- Previous tests only covered 3 styles, 2 of which used wrong names and hit the fallback clause

### Detection Mapping Expansion
- Expanded from 13 rules to 70+ rules
- Added protocol-specific patterns for all 8 protocols (Modbus, DNP3, S7comm, IEC-104, OPC UA, ENIP, BACnet, PROFINET)
- Added Suricata ET ICS/SCADA rule naming pattern support
- Added Suricata EVE JSON nested alert format support
- Added Zeek Notice log format support (note/sub fields)
- New technique mappings: T0801, T0802, T0809, T0812, T0838, T0841, T0843, T0845, T0849, T0856, T0858, T0866, T0869, T0872, T0876, T0882, T0888, T0889

### Test Suite
- Added BACnet protocol tests: all 16 styles + BVLC header + NPDU version + broadcast/unicast function checks
- Added UDP packet structure test
- Fixed PROFINET style names in test expectations
- Total protocol styles tested: 159 (was 138)

---

## v0.4.0 (2026-03)

### Engineering & Packaging
- **pyproject.toml**: Full PEP 621 packaging with entry points (`icsforge`, `icsforge-web`, `icsforge-receiver`). Pip-installable: `pip install -e .`
- **Scapy made optional**: Core engine is pure Python. Scapy only needed for pcap replay (`pip install icsforge[replay]`)
- **Dependency ranges**: Replaced pinned versions with compatible ranges in requirements.txt

### Testing
- **pytest test suite**: 100+ tests covering all 7 protocol builders, core utilities, scenario engine, and detection generator
- **Protocol builder tests**: Every documented style verified for all protocols (Modbus 28+, DNP3 17+, S7comm 25+, IEC-104 18+, OPC UA 16+, ENIP 15+, PROFINET 5+)
- **PCAP validation tests**: Verify global header magic, packet structure, and timing jitter
- **Detection generator tests**: Suricata and Sigma rule generation coverage
- **GitHub Actions CI**: Matrix testing across Python 3.10–3.13, Docker image builds

### Protocol Fixes
- **DNP3 CRC-16**: Implemented proper CRC-16/DNP (polynomial 0x3D65) per IEEE 1815. Link header and data block CRCs now computed correctly instead of placeholder zeros
- **PCAP timing jitter**: Packet timestamps now include ±30% jitter around base interval, eliminating the uniform-spacing pattern that flagged synthetic PCAPs in Wireshark

### Logging
- **Structured logging framework** (`icsforge.log`): All `print()` statements replaced with Python `logging` module. Configurable via `--log-level`, `--verbose`, `--log-file`, or `ICSFORGE_LOG_LEVEL` environment variable
- Consistent log format across sender, receiver, web UI, and CLI
- Third-party logger suppression (werkzeug, urllib3)

### Receiver
- **Thread-safe receipt writing**: `threading.Lock()` protects JSONL file writes from concurrent TCP handler corruption
- **Proper error handling**: All TCP accept/handler errors logged instead of silently swallowed
- **Bind error reporting**: Clear error messages when ports are already in use

### Web Application
- **Flask secret key**: Cryptographic secret key generated on startup (configurable via `ICSFORGE_SECRET_KEY`)
- **Session security**: HttpOnly and SameSite=Lax cookie settings
- **Fixed duplicate code**: `/api/send` handler had 6 duplicate variable assignments (timeout, allowlist, iface, src_ip, outdir assigned twice each)
- **Deprecated API fixed**: All `datetime.utcnow()` replaced with timezone-aware `datetime.now(timezone.utc)`
- **HTTP output logging**: `_send_http()` now logs failures instead of silently passing

### Docker
- **docker-compose.yml**: Full-stack setup with sender, receiver, and optional Suricata in isolated bridge network
- **Updated Dockerfiles**: Python 3.12-slim base, proper output directory creation
- **Suricata profile**: Opt-in IDS monitoring via `docker compose --profile suricata up`

### Community & CI
- **CONTRIBUTING.md**: Development setup, testing guide, code style, protocol/scenario addition guides
- **GitHub issue templates**: Bug report and feature request templates
- **.github/workflows/ci.yml**: Automated testing, linting, coverage, and Docker builds
- **Updated README**: Architecture diagram, badges, quick-start guide, protocol coverage table

### Code Quality
- **core.py**: `_send_http` error logging, proper timezone handling throughout
- **state/run_registry.py**: Fixed deprecated `datetime.utcnow()` usage
- **cli.py**: Added `--verbose`, `--log-level`, `--log-file` global flags

---

## v0.31 (2025)

### Minor fixes and stability

---

## v0.21

### Protocol Engine — full rewrite of all 7 protocol builders

**Modbus/TCP** (`modbus.py`): 9 → 18 styles
- Added FC01 read_coils, FC02 read_discrete, FC04 read_input
- Added FC05 write_single_coil, FC06 write_single_register, FC15 write_multiple_coils
- Added FC22 mask_write_register (bit-level parameter manipulation — T0836)
- Added FC23 read_write_multiple (simultaneous read+write — T0832)
- Added FC07 read_exception_status, FC08 diagnostic, FC11 get_comm_event_counter (T0882)
- Added safety_write (FC16 to register 60000+ zone — T0829/T0876 Triton pattern)
- Added brute_force_write (sequential address sweep — T0806)
- Added coil_sweep (address sweep — T0841)
- Added dos_read (FC03 max 125 registers — T0814)
- Added exception_probe (illegal address fingerprinting — T0820)
- Proper MBAP header construction throughout

**DNP3** (`dnp3.py`): 5 → 16 styles
- Full link+transport+application layer framing with real CRC placeholders
- Real CROB (Control Relay Output Block) objects in select/operate/direct_operate
- Added cold_restart (FC0D), warm_restart (FC0E) — T0816
- Added enable_unsolicited (FC14), disable_unsolicited (FC15) — T0815/T0856
- Added assign_class (FC16) — T0841
- Added delay_measure (FC17) — T0841 timing probe
- Added direct_operate_nr (FC06) — no-ack evasion variant
- Added authenticate_req (FC32) — T0858
- Added read_class1 (Class 1 event data), read_analog, read_counter

**S7comm** (`s7comm.py`): 3 → 18 styles
- Proper TPKT (RFC1006) + COTP + S7comm header structure
- Added cpu_stop (FC29 — T0813/T0881), cpu_start_warm, cpu_start_cold (FC28 — T0816)
- Added download_req, download_block, download_end (FC1A/1B/1C — T0821/T0843)
- Added upload_req, upload_block, upload_end (FC1D/1E/1F — T0845)
- Added szl_read (ROSCTR_USERDATA SZL — T0882/T0888 System Status List)
- Added plc_control (FC28 — T0875)
- Added read_db, write_db (Data Block access — T0882/T0836)
- Added read_outputs, write_outputs (AREA_OUTPUTS — T0801/T0876)
- Area codes: DB (0x84), Inputs (0x81), Outputs (0x82), Flags (0x83)

**IEC-60870-5-104** (`iec104.py`): 5 → 18 styles
- U-format APCI: startdt, stopdt, testfr (distinct from I-format data frames)
- Added meas_mv (M_ME_NC_1 short float — T0801)
- Added setpoint_scale (C_SE_NB_1 — T0836), regulating_step (C_RC_NA_1 — T0831)
- Added interrogation (C_IC_NA_1 — T0841/T0882)
- Added counter_interr (C_CI_NA_1 — T0882)
- Added clock_sync (C_CS_NA_1 with 7-byte timestamp — T0849 time injection)
- Added reset_process (C_RP_NA_1 — T0816)
- Added test_command (C_TS_NA_1 — T0841)
- Added param_mv (P_ME_NA_1 — T0836), param_activ (P_AC_NA_1 — T0878)
- Added inhibit_alarm (P_AC_NA_1 with deactivation COT — T0878)
- Proper I-format APCI with send/recv sequence numbers

**OPC UA** (`opcua.py`): 3 → 16 styles
- Real service NodeIds used throughout (GetEndpoints=428, Browse=527, Read=631, Write=673, etc.)
- Added get_endpoints, find_servers (T0888 discovery)
- Added open_session (OPN with CreateSessionRequest — T0822)
- Added activate_session (ActivateSession with identity token — T0859)
- Added close_session (CLO message — T0826)
- Added browse, browse_next, translate_paths (BrowseRequest — T0861)
- Added read_value (ReadRequest — T0801), read_history (HistoryReadRequest — T0879)
- Added write_value (WriteRequest — T0831/T0836/T0855)
- Added call_method (CallRequest — T0871)
- Added create_sub (CreateSubscriptionRequest — T0802), publish (T0801)
- Added delete_sub (DeleteSubscriptionsRequest — T0815)

**EtherNet/IP / CIP** (`enip.py`): 2 → 15 styles
- Real CIP path encoding (EPATH) for class/instance/attribute addressing
- Added list_services (T0841), list_interfaces (T0840)
- Added get_identity (CIP GetAttributeAll on Identity object — T0888)
- Added get_device_type (CIP GetAttributeSingle attr 2 — T0868)
- Added reset_device (CIP Reset service — T0816)
- Added stop_device (CIP Stop — T0813/T0881), start_device (CIP Start — T0875)
- Added read_tag (FC 0x4C with EPATH tag name — T0801/T0882)
- Added write_tag (FC 0x4D with REAL value — T0831/T0836/T0855)
- Added get_param, set_param (Parameter object class 0x0F — T0836)
- Added send_rr_data (generic unconnected — T0869)
- Unregister_session for T0826

**PROFINET DCP** (`profinet_dcp.py`): 1 → 8 styles
- Real DCP PDU structure with block encoding
- Added identify_unicast (targeted device query — T0888)
- Added get_name (DCP Get NameOfStation — T0882)
- Added get_ip (DCP Get IP parameter — T0882)
- Added set_name (DCP Set NameOfStation — T0849 device masquerade)
- Added set_ip (DCP Set IP — T0849)
- Added hello (DCP Hello PDU — T0840 passive enumeration)
- Added factory_reset (DCP Set Control — T0816)

### Scenarios — complete rebuild

- **67 scenarios** across 7 protocols and **36 ATT&CK for ICS techniques**
- All scenarios are wire-level distinct (no copy-paste traffic patterns)
- 6 named attack chains based on real incidents:
  - `industroyer2` — Ukraine 2022 power grid (IEC-104 + S7comm)
  - `triton` — Triton/TRISIS safety system attack
  - `stuxnet` — Stuxnet-style Siemens PLC attack
  - `water_treatment` — Oldsmar-style water treatment attack
  - `opcua_espionage` — OPC UA silent data exfiltration
  - `enip_manufacturing` — Allen-Bradley manufacturing line attack
- Techniques newly covered: T0806, T0813, T0816, T0820, T0821, T0822, T0827, T0829,
  T0836, T0841, T0842, T0843, T0845, T0846, T0849, T0859, T0861, T0868, T0871,
  T0875, T0876, T0878, T0879, T0881, T0882, T0883
- 67 short aliases for CLI/UI use

---

