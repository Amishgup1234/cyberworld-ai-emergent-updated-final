# CyberWorld AI — Workflow Transformation Plan

## Objective
Change the primary workflow of the existing CyberWorld AI application from
analyst-triggered predictive simulation to policy-driven automated containment
and verification, and adapt the existing features (digital twin, temporal risk,
target ranking, MITRE, explainability, what-if simulation, replay, metrics,
reports) so they support that new story.

The product remains a controlled prototype / replay environment. No real
endpoint isolation, no real firewalls, no production integrations.

## Product positioning after the change

Primary message: **Detect. Contain. Analyze. Verify.**
Supporting: *Predict. Explain. Assess.*

Description used in the app and README:

> CyberWorld AI is an AI-powered autonomous cyber-containment prototype that
> detects suspicious network activity, automatically contains high-confidence
> compromised systems, analyzes the surrounding network for possible
> propagation, assigns threat-confidence scores to potentially affected hosts,
> applies configurable containment policies, predicts likely attack paths and
> targets, verifies whether propagation has stopped, and generates an incident
> report for a security engineer to investigate and recover affected systems.

The existing visual identity (dark tactical command centre, cyan/purple/orange/
coral, current fonts, glass panels, React Flow topology, existing responsive
and accessibility behaviour) is preserved. No new design system.

## New incident lifecycle

Replaces the current `baseline → emerging-risk → early-warning → confirmation`
timeline. The replay stays chronological; the lifecycle is layered on top.

1. **Baseline** — normal monitoring, no elevated activity.
2. **Detecting** — temporal risk / target-ranking signals begin rising.
3. **Threat Detected** — detection threshold crossed; the primary suspicious host is announced.
4. **Initial Containment** — CARE automatically isolates / restricts the primary host.
5. **Spread Analysis** — surrounding hosts are evaluated for propagation risk.
6. **Host Assessment** — every candidate host receives a threat-confidence score and a CARE decision.
7. **Secondary Containment** — CARE applies the decisions (isolate / restrict / monitor / protect / no action).
8. **Verifying** — subsequent frames are inspected to see whether propagation has stopped.
9. **Contained** *or* **Re-analyzing** — closed loop; up to a bounded number of response cycles.
10. **Report Ready** — a full incident report is auto-assembled.
11. **Engineer Handoff** — clear "investigate / remediate / recover" summary for a human engineer.

Existing internal milestones (`emerging-risk`, `warning`, `confirmation`) remain
available where analytics and tests still rely on them, but the user-facing
lifecycle is the one above.

## Detection trigger (when automation kicks in)

- The existing early-warning condition becomes the automation trigger.
- No manual "Simulate Preventive Action" click is required to start the response.
- The user still controls playback (pause / continue / step / speed / restart / jump to milestone).
- Detection announces:
  - the primary suspicious host,
  - detection confidence,
  - the observed evidence,
  - the current attack stage.

## Choosing the primary suspicious host

Derived deterministically from data that already exists in the scenario:
learned risk, current warning state, digital-twin graph, current target
ranking, observed suspicious behaviour, temporal trend.

Rule of thumb for the current dataset: the first host whose risk reaches the
top of the ladder in the current frame (falling back to the highest-risk host
if several qualify). The predicted next target is kept **visually distinct**
from the suspected compromise — a predicted target is not labelled compromised
unless the scenario data supports it.

## CARE — CyberWorld Autonomous Response Engine

A small, deterministic, configurable policy that turns a threat-confidence
score into one of five actions:

- **ISOLATE** — auto-isolate the host in the replay/lab environment.
- **RESTRICT** — mute or block specific suspicious edges, heightened monitoring.
- **MONITOR** — no traffic changes, elevated observation only.
- **PROTECT** — for critical assets predicted as likely next targets; suspicious paths restricted, monitoring heightened, but the asset is not blindly disconnected.
- **NO_ACTION** — observe only.

**Default thresholds (configurable in Settings):**

| Threat confidence | Ordinary workstation-type host | Mission-critical asset |
| --- | --- | --- |
| ≥ 0.90 | ISOLATE | PROTECT + RESTRICT suspicious paths |
| 0.75 – 0.89 | RESTRICT | PROTECT + heightened monitoring |
| 0.50 – 0.74 | MONITOR | MONITOR |
| < 0.50 | NO_ACTION | NO_ACTION |

These values are presented as *policy configuration*, not universal
cybersecurity truth. Criticality comes from the existing tier / crown-jewel
labels in the scenario data.

Threat confidence is described in the UI as **policy-derived** — not a
separately trained ML probability. It is combined deterministically from
existing signals (learned risk, target-ranking, temporal trend, graph
novelty, observed suspicious edges).

## Spread analysis

After initial containment, CyberWorld automatically evaluates hosts around the
suspected compromise using the existing digital twin: direct neighbours,
recently appeared edges, edge novelty, host risk, incoming activity, temporal
trend, target-ranking position, criticality, observed suspicious signals.

The result is a **Potentially Affected Systems** list, each entry showing:

- Host alias
- Threat confidence (policy-derived)
- Risk level (existing)
- Evidence summary (from existing explainability)
- Asset role / criticality (from existing tier labels)
- CARE decision (ISOLATE / RESTRICT / MONITOR / PROTECT / NO_ACTION)
- Reason for the decision

## Secondary containment and predicted-target protection

- CARE decisions are automatically applied to every affected host.
- The topology visually marks each host with its response state (see below).
- Likely next targets from the existing target-ranking / trajectory system are
  reframed as the **Predicted Attack Path**. Critical predicted targets can be
  marked as PROTECT (suspicious inbound paths restricted, heightened
  monitoring) rather than disconnected.

## Topology, colour language, response states

The React Flow topology stays. It gains explicit response-state indicators
alongside the existing observed / predicted / removed edges:

- **Normal** — existing cyan / healthy.
- **Threatened / predicted** — existing purple, predicted attack path.
- **Suspected compromise** — highlighted primary suspicious host.
- **Auto-isolated** — strong orange/red containment indicator; incident edges muted.
- **Restricted** — orange, suspicious edges muted/blocked while others remain.
- **Monitoring** — subdued orange outline, no traffic changes.
- **Protected** — critical asset badge, suspicious inbound paths restricted.
- **Confirmed malicious / ground truth** — existing coral (when the scenario reveals it).

Text and icon labels accompany every colour so colour is never the only
indicator. Motion is used sparingly and respects `prefers-reduced-motion`.

## Verification loop

After response actions are applied, CyberWorld enters a verification window
that inspects subsequent frames / derived state:

- Verification status (`Verifying` / `Contained` / `Propagation continues`).
- Propagation activity in the window.
- New suspicious hosts / edges detected.
- Risk trend after containment.
- Remaining threatened systems.
- Verification window progress.

Two possible outcomes:

- **Containment successful** — no further suspicious propagation observed
  during the verification window → move to Report.
- **Propagation continues** — automatically re-analyze, run CARE again,
  contain again, verify again.

The loop is capped by a configurable `MAX_RESPONSE_CYCLES` (default **3**).
If still unresolved after the cap, status becomes **Escalation required**
and the case is handed to the engineer.

The original replay stays immutable; containment operates on a derived
incident-response state that is layered on top of the replay.

## Incident report and engineer handoff

Once containment is verified (or the cycle cap is hit), CyberWorld
**automatically** assembles a report. There is no manual "Save Incident"
step for the primary flow — the top-bar Save button is retired for this
workflow, since reports are now the natural output of a completed incident.
The report is persisted, viewable in the Reports tab, and exportable as JSON
(the existing export format is kept).

Report contents:

- Incident ID
- Scenario
- Detection frame / timestamp
- Initial suspicious / compromised host and detection confidence
- Detection evidence
- Attack stage and MITRE mapping
- Automatically isolated / restricted / monitored / protected systems
- Threat-confidence scores per host (policy-derived)
- Predicted attack path
- Containment actions taken (per cycle)
- Verification cycles and outcomes
- Final propagation status
- Before/after response metrics (from existing data)
- Engineer action required

Engineer handoff shown at the end of the incident:

> **CyberWorld** — Detect → Contain → Analyze → Respond → Verify → Report
>
> **Security Engineer** — Investigate → Remediate → Recover

The engineer's next actions are described in copy only (investigate isolated
systems, root-cause analysis, credential review, patch and remediate, recover
systems). No real remediation is performed.

## How existing features get reinterpreted

- **Digital Twin** → live network state used for detection, spread analysis, and containment visualization.
- **Temporal risk model** → attack detection + developing compromise confidence.
- **Early warning** → automation trigger.
- **Target ranking / trajectory** → predicted attack path + likely next targets used for proactive protection.
- **Preventive Action simulation logic** → underlying containment engine invoked automatically by CARE (the manual button no longer starts the primary flow).
- **What-if simulation** → kept as a secondary technical / analyst inspection feature under the What-if / Response Policy Lab tab, with the existing "estimated simulated effect — not causal proof" warning preserved.
- **Threat explanation** → now also explains why a host was isolated / restricted / monitored / protected and why containment was considered successful or not. Adds a **policy-derived** label alongside the existing learned / rule-derived / graph-ranked / simulated / measured labels.
- **MITRE mapping** → unchanged content; used as explanatory context during detection, spread analysis, and report.
- **Attack trajectory** → predicted attack path visualization.
- **Replay timeline** → incident lifecycle replay (Baseline / Detection / Containment / Spread Analysis / Verification / Report as jump-to milestones).
- **Metrics** → keep all existing measured ML metrics; add deterministic workflow metrics (detection frame, initial containment frame, systems isolated / restricted / monitored, verification cycles, propagation stopped y/n, risk before/after, risk reduction). Every value is labelled Replay-derived, Measured, Policy-derived, or Simulated.
- **Warning banner** → repurposed as an incident-response banner with lifecycle-specific messages ("Threat detected — automated containment initiated", "Initial host isolated — analyzing propagation", "2 additional high-confidence systems isolated", "Verifying containment", "Containment successful", "Propagation continues — response cycle 2", "Engineer escalation required").

## Tabs / workspace organisation

Structure is kept; contents are reinterpreted:

- **Overview** → Incident Command (current lifecycle, primary host, response summary).
- **Twin** → Live digital twin, now the central incident map.
- **Forecast** → Predicted Attack Path and likely next targets.
- **XAI** → Decision Explanation (detection + response reasons).
- **MITRE** → unchanged.
- **Simulate** → What-if / Response Policy Lab (secondary technical use).
- **Reports** → Incident reports (auto-generated), with export.
- **Settings** → CARE policy thresholds and existing settings.

## CARE policy settings (in Settings)

Exposed as prototype-level, deterministic values:

- Detection threshold (when to trigger automation).
- Auto-isolate threshold.
- Restrict threshold.
- Monitor threshold.
- `MAX_RESPONSE_CYCLES` (default 3).
- Protect-critical-assets behaviour (on / off).

No authentication, no enterprise policy server.

## Playback and demo behaviour

- The replay does **not** auto-play on load. The user presses Play (this is
  the explicit decision recorded during planning). Once playback reaches the
  detection frame, automation runs without any further clicks.
- All existing replay controls remain: Pause / Continue / Restart / speed
  0.5× / 1× / 2× / step / jump to milestone / keyboard controls.
- The full incident story (Detect → Contain → Analyze → Verify → Report →
  Engineer Handoff) unfolds in roughly the same demo duration as today's
  replay.

## Scope: which scenarios get the new workflow

**All three existing scenarios** — Ransomware Ω-7742, Cloud Credential Heist
γ-3311, and Supply Chain Compromise λ-9018 — support the new workflow. The
scenario switcher continues to work; each scenario derives its own primary
suspicious host, spread analysis, CARE decisions, verification outcome, and
report from its own data.

Existing safe host aliases are kept. The "PC-17 / 100 PCs" text in the brief
is treated as narrative only; the actual demo uses the real host aliases
already in each scenario.

## API and offline parity

- The existing FastAPI backend is extended, not replaced.
- Manual what-if isolation (existing endpoint) continues to work; containment
  calculations are shared with the new automated response path so behaviour
  stays consistent between the two.
- An automated-response abstraction runs the same underlying engine that the
  manual simulation uses — no duplicated logic.
- The deterministic offline bundle continues to work: the full new workflow
  (detection, containment, spread analysis, verification, report) can be
  demonstrated in Offline Mode without the backend, using the same core
  scenario logic. The offline data is extended where necessary rather than
  being hand-authored into the React app.

## Claim discipline

All existing claim boundaries are kept and extended:

- Observed, Learned, Rule-derived, Graph-ranked, Simulated, Measured, and
  Ground truth labels stay.
- **Policy-derived** is added for CARE decisions and threat-confidence scores.
- Containment actions are always shown with a "replay environment" or
  "policy-driven isolation — simulated lab action" qualifier so nothing
  implies a real endpoint was disconnected.
- No claims of production-ready autonomous defense. No implication that a
  predicted target is definitively compromised or that simulated isolation
  proves real-world effectiveness.

## Non-goals (explicitly out of scope)

- No authentication, payments, messaging, chatbot, or unrelated features.
- No real endpoint isolation, firewall, AD, IAM, email, or SMS integrations.
- No third-party SaaS integrations added.
- No redesign of the visual identity, typography, colours, spacing, or
  responsive breakpoints.
- No replacement of the React Flow topology, replay engine, temporal model,
  MITRE mapping, or metrics.
- No fake WebSocket labels; no relabelling offline replay as a live production
  network.
- No PDF report export in this iteration (JSON export stays; PDF remains
  backlog).
- The top-bar "Save Incident" button is retired for the primary flow because
  reports are auto-generated; existing incidents stored in the database are
  preserved.

## Assumptions recorded (decided during planning)

- Playback does **not** auto-start on load.
- All three scenarios use the new workflow.
- Automation trigger reuses the existing early-warning condition.
- Threat confidence is presented and labelled as policy-derived, not as a
  separately trained ML probability.
- Verification window and `MAX_RESPONSE_CYCLES` (default 3) are configurable
  in Settings.
- Critical assets receive PROTECT-first behaviour rather than blind isolation.
- Incident reports are generated automatically at the end of the workflow and
  appear in the Reports tab; JSON export is retained.
- The existing visual identity is preserved unchanged.

## What the user still owns as a decision

Nothing else is blocking. If any of the assumptions above should flip
(for example: auto-play on load, PDF export in this pass, keeping the
manual Save Incident button, tighter or looser CARE thresholds, or a
different default for `MAX_RESPONSE_CYCLES`), that is worth raising now
before the build begins.
