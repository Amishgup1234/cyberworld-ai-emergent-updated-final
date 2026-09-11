# CyberWorld AI — Autonomous Cyber-Containment Prototype

## Original problem statement
"CyberWorld AI is an AI-powered autonomous cyber-containment prototype that detects
suspicious network activity, automatically contains high-confidence compromised
systems, analyzes the surrounding network for possible propagation, assigns
threat-confidence scores to potentially affected hosts, applies configurable
containment policies, predicts likely attack paths and targets, verifies whether
propagation has stopped, and generates an incident report for a security engineer
to investigate and recover affected systems."

Product line: **Detect · Contain · Analyze · Verify · Report**  (supporting: Predict · Explain · Assess).

## Architecture (current)
- **Backend**: FastAPI + Motor · `/app/backend/server.py`
  - Seeds 3 attack scenarios + 3 tenants + CARE settings on startup
  - Frame-level compute: kill-chain probabilities, node risk escalation, edges, MITRE, XAI, targets, KPIs, log tail
  - **Incident lifecycle**: Baseline → Detecting → Threat Detected → Initial Containment → Spread Analysis → Host Assessment → Secondary Containment → Verifying → Contained → Report Ready → Engineer Handoff (`max_response_cycles` bounded)
  - **CARE engine**: policy-derived threat confidence (learned risk + graph novelty + target-ranking) → 5 actions (ISOLATE / RESTRICT / MONITOR / PROTECT / NO_ACTION), PROTECT-first for Crown Jewels + Core Identity
  - **Auto-report** persisted idempotently when Report Ready is reached
- **Frontend**: Vite + React 18 + TS · fully wired to `/api`, existing visual identity preserved
- **Storage**: MongoDB — `scenarios`, `tenants`, `incidents`, `care_settings`

## Endpoints
- `GET /api/health` · `GET /api/tenants` · `GET /api/scenarios` · `GET /api/scenarios/{id}`
- `GET /api/scenarios/{id}/frame/{f}` — returns full frame state + `incident` block (lifecycle, primary suspect, affected systems with CARE decisions, care_settings)
- `POST /api/simulate` — retained for Response Policy Lab (secondary use)
- `POST /api/incidents` · `GET /api/incidents` · `GET /api/incidents/{id}` — manual + auto reports
- `GET /api/care/settings` · `PUT /api/care/settings` — thresholds, verification window, protect-critical

## Rooms (all show the incident banner + IncidentBanner + KpiRow)
- **Incident Command** — lifecycle banner, primary suspect card, affected-systems list, twin with CARE overlays, forecast, XAI, MITRE, response-policy-lab callout, engineer handoff
- **Digital Twin** — CARE containment + response state overlaid on hosts/edges, tier breakdown, affected list
- **Predicted Attack Path** — kill-chain trajectory with frame marker + protect-first callout
- **Decision Explanation** — SHAP evidence + AI reasoning narrative that explains CARE actions and primary suspect
- **MITRE ATT&CK** — unchanged content, frame-aware activation
- **Response Policy Lab** — retained secondary what-if simulator with "estimated simulated effect — not causal proof" warning
- **Incident Reports** — auto-generated bundles (AUTO badge) with peak risk at detection vs end, cycles, propagation status; JSON export; open (jumps to scenario+frame)
- **CARE Policy · Settings** — 6 sliders + toggle wired to backend, live-refreshes frame state

## Claim discipline
Observed · Learned · Rule-derived · Graph-ranked · Simulated · Measured · Ground-truth (existing) + **Policy-derived** (new, for CARE decisions and threat-confidence scores). All containment actions labelled "replay environment / simulated lab action — no real endpoint was disconnected".

## Assumptions honoured (from plan)
- No auto-play on load — user presses Play (initial frame = 0)
- All three scenarios use the new workflow
- Automation trigger = existing early-warning condition (first host at warn/critical)
- Threat confidence presented as policy-derived, not ML probability
- `MAX_RESPONSE_CYCLES=3` + verification window (default 4 frames) configurable in Settings
- Critical assets get PROTECT-first behaviour
- Incident reports auto-assembled at Report Ready; JSON export retained
- Top-bar "Save Incident" button retired; replaced by CARE lifecycle status chip
- Visual identity preserved unchanged

## Non-goals kept
No auth, no real endpoint isolation, no PDF export (JSON only), no third-party SaaS, no design redesign.

## Backlog
- P1 PDF export of incident report
- P1 Playbook automation (save mitigation toggles as named playbooks)
- P2 WebSocket streaming for frames
- P2 Real threat intel enrichment on hover cards
- P3 Authentication + RBAC per tenant
- P3 Historical trend charts across saved incidents
