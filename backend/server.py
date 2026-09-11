"""
CyberWorld AI — Predictive Cybersecurity Platform · Backend

FastAPI + MongoDB service that powers the digital twin dashboard:
  · Multi-scenario predictive replays (attack progression across frames)
  · Server-computed frame state, kill-chain probabilities, MITRE mapping
  · What-if defense simulation (mitigation delta computation)
  · Incident bundle save/export for SOC handoff
  · Multi-tenant (MSSP) support
"""
from __future__ import annotations

import io
import os
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from threat_intel import resolve_intel

# --------------------------------------------------------------------------
# Environment / Database
# --------------------------------------------------------------------------
load_dotenv()

MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _oid_to_str(v: Any) -> str:
    return str(v) if v is not None else v

PyObjectId = Annotated[str, BeforeValidator(_oid_to_str)]


def _serialize(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if not doc:
        return doc
    out = dict(doc)
    if "_id" in out:
        out["id"] = str(out.pop("_id"))
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Seed data — 3 attack scenarios inspired by the CyberWorld AI PDF
# --------------------------------------------------------------------------
def _stage(name: str, activate: int, target: float, color: str) -> dict:
    return {"stage": name, "activate_at": activate, "target": target, "color": color}


SCENARIOS_SEED = [
    {
        "id": "sc-ransom-ω-7742",
        "name": "Ransomware Ω-7742",
        "summary": "Credential-driven lateral movement toward the PII crown jewel.",
        "family": "Ransomware · Lateral Movement",
        "seed": 42,
        "frame_count": 30,
        "nodes": [
            {"id":"gw-01","label":"Perimeter Gateway","kind":"gateway","x":90,"y":220,"base":"safe","escalate_at":4,"peak":"watch","ip":"10.0.0.1","tier":"Perimeter"},
            {"id":"fw-01","label":"Next-Gen Firewall","kind":"gateway","x":200,"y":130,"base":"safe","ip":"10.0.0.2","tier":"Perimeter"},
            {"id":"vpn-01","label":"VPN Concentrator","kind":"gateway","x":200,"y":320,"base":"safe","escalate_at":6,"peak":"warn","ip":"10.0.0.9","tier":"Perimeter"},
            {"id":"ad-01","label":"AD-01 Domain Ctrl","kind":"identity","x":380,"y":220,"base":"safe","escalate_at":10,"peak":"critical","ip":"10.0.10.4","tier":"Core Identity"},
            {"id":"db-01","label":"PII Database","kind":"db","x":560,"y":130,"base":"safe","escalate_at":16,"peak":"critical","ip":"10.0.20.12","tier":"Crown Jewels"},
            {"id":"db-02","label":"Finance Vault","kind":"db","x":560,"y":310,"base":"safe","escalate_at":18,"peak":"warn","ip":"10.0.20.14","tier":"Crown Jewels"},
            {"id":"srv-01","label":"File Server SMB","kind":"server","x":380,"y":380,"base":"safe","escalate_at":12,"peak":"warn","ip":"10.0.30.5","tier":"Core"},
            {"id":"srv-02","label":"Mail Exchange","kind":"server","x":380,"y":60,"base":"safe","escalate_at":5,"peak":"watch","ip":"10.0.30.7","tier":"Core"},
            {"id":"cld-01","label":"S3 Backup Bucket","kind":"cloud","x":720,"y":100,"base":"safe","escalate_at":22,"peak":"watch","ip":"aws-us-1","tier":"Cloud"},
            {"id":"cld-02","label":"K8s Prod Cluster","kind":"cloud","x":720,"y":260,"base":"safe","ip":"k8s-prod","tier":"Cloud"},
            {"id":"ws-01","label":"HR-Laptop-014","kind":"workstation","x":190,"y":460,"base":"safe","ip":"10.0.40.14","tier":"Workstation"},
            {"id":"ws-02","label":"Dev-Workstation-22","kind":"workstation","x":560,"y":460,"base":"safe","escalate_at":14,"peak":"warn","ip":"10.0.40.22","tier":"Workstation"},
            {"id":"iot-01","label":"HVAC Controller","kind":"iot","x":720,"y":420,"base":"safe","escalate_at":4,"peak":"watch","ip":"10.0.90.3","tier":"OT/IoT"},
        ],
        "edges": [
            {"from":"gw-01","to":"fw-01","intensity":0.9},
            {"from":"gw-01","to":"vpn-01","intensity":0.6},
            {"from":"fw-01","to":"ad-01","intensity":0.8},
            {"from":"vpn-01","to":"ad-01","intensity":0.7,"malicious":True,"appears_at":6},
            {"from":"ad-01","to":"db-01","intensity":0.9,"predicted":True,"malicious":True,"appears_at":16},
            {"from":"ad-01","to":"db-02","intensity":0.5},
            {"from":"ad-01","to":"srv-01","intensity":0.75,"malicious":True,"appears_at":10},
            {"from":"srv-02","to":"fw-01","intensity":0.4},
            {"from":"srv-01","to":"ws-02","intensity":0.55,"predicted":True,"appears_at":14},
            {"from":"db-01","to":"cld-01","intensity":0.7,"predicted":True,"appears_at":22},
            {"from":"cld-02","to":"db-02","intensity":0.35},
            {"from":"ws-01","to":"vpn-01","intensity":0.5},
            {"from":"iot-01","to":"cld-02","intensity":0.3},
        ],
        "stages": [
            _stage("Recon", 0, 0.98, "#00F0FF"),
            _stage("Initial Access", 3, 0.92, "#00F0FF"),
            _stage("Execution", 6, 0.87, "#7C6BFF"),
            _stage("Persistence", 10, 0.72, "#7C6BFF"),
            _stage("Priv Escalation", 14, 0.61, "#FFAA00"),
            _stage("Lateral Movement", 18, 0.44, "#FFAA00"),
            _stage("Credential Access", 22, 0.29, "#FF2E63"),
            _stage("Exfiltration", 26, 0.11, "#FF2E63"),
        ],
        "mitre": [
            {"tactic":"Recon","techniques":[{"id":"T1595","name":"Active Scanning","conf":0.97,"active_at":0},{"id":"T1592","name":"Victim Host Info","conf":0.71,"active_at":1}]},
            {"tactic":"Initial Access","techniques":[{"id":"T1078","name":"Valid Accounts","conf":0.94,"active_at":3},{"id":"T1566","name":"Phishing","conf":0.55,"active_at":4}]},
            {"tactic":"Execution","techniques":[{"id":"T1059","name":"Command & Scripting","conf":0.88,"active_at":6}]},
            {"tactic":"Persistence","techniques":[{"id":"T1136","name":"Create Account","conf":0.66,"active_at":10},{"id":"T1053","name":"Scheduled Task","conf":0.42,"active_at":11}]},
            {"tactic":"Priv Escalation","techniques":[{"id":"T1068","name":"Exploit Vuln (CVE-2026-1189)","conf":0.61,"active_at":14}]},
            {"tactic":"Credential Access","techniques":[{"id":"T1558","name":"Kerberoasting","conf":0.58,"active_at":22},{"id":"T1003","name":"OS Credential Dumping","conf":0.31,"active_at":23}]},
            {"tactic":"Lateral Movement","techniques":[{"id":"T1021","name":"Remote Services (SMB)","conf":0.47,"active_at":18}]},
            {"tactic":"Exfiltration","techniques":[{"id":"T1041","name":"C2 Channel Exfil","conf":0.12,"active_at":26}]},
        ],
        "xai": [
            {"name":"SMB traffic anomaly (srv-01)","weight":0.34,"dir":"up","context":"Volume 6.4× baseline for last 480s","active_at":10},
            {"name":"Kerberos service ticket bursts (ad-01)","weight":0.28,"dir":"up","context":"11 SPN requests / 60s window","active_at":12},
            {"name":"VPN session from novel ASN","weight":0.17,"dir":"up","context":"AS205100 first-seen in 90d window","active_at":6},
            {"name":"Dormant service account activated","weight":0.11,"dir":"up","context":"svc_backup_legacy — no auth in 214d","active_at":14},
            {"name":"Reduced beaconing entropy (out-01)","weight":0.07,"dir":"down","context":"Model expects broader jitter","active_at":4},
            {"name":"CVE-2026-1189 patch missing","weight":0.03,"dir":"up","context":"Endpoint SCCM confirms unpatched","active_at":14},
        ],
        "mitigations": [
            {"id":"isolate-ad-01","label":"Isolate AD-01 domain controller","delta":-47,"icon":"ShieldOff"},
            {"id":"block-smb","label":"Block SMB (port 445) at core switch","delta":-22,"icon":"Ban"},
            {"id":"mfa-vpn","label":"Enforce MFA re-auth on VPN sessions","delta":-9,"icon":"Lock"},
            {"id":"patch-cve","label":"Apply patch CVE-2026-1189","delta":-18,"icon":"Binary"},
            {"id":"kill-svc-account","label":"Disable svc_backup_legacy account","delta":-6,"icon":"Fingerprint"},
        ],
        "target_pool": [
            {"host":"db-01 (PII Database)","peak":0.78,"activate_at":16,"eta_base":22,"color":"#FF2E63"},
            {"host":"srv-01 (SMB Fileserver)","peak":0.61,"activate_at":10,"eta_base":14,"color":"#FFAA00"},
            {"host":"cld-01 (S3 Backup)","peak":0.34,"activate_at":22,"eta_base":38,"color":"#7C6BFF"},
        ],
        "log_seed": [
            {"at":0,"tag":"MODEL","color":"cyan","text":"Temporal model checkpoint tw-v3.4.1 loaded (80 features)"},
            {"at":1,"tag":"PREDICT","color":"lime","text":"Twin sync 12,480 nodes · 42,110 edges committed"},
            {"at":3,"tag":"ANOMALY","color":"amber","text":"Novel ASN AS205100 first-seen on vpn-01 tunnel"},
            {"at":5,"tag":"MITRE","color":"violet","text":"T1078 Valid Accounts observed on vpn-01"},
            {"at":6,"tag":"FORECAST","color":"cyan","text":"Path prob vpn-01 -> ad-01 = 0.42 (rising)"},
            {"at":8,"tag":"ANOMALY","color":"amber","text":"Kerberos SPN request burst on ad-01 (11/60s)"},
            {"at":10,"tag":"MITRE","color":"violet","text":"T1059 Command & Scripting matched on ad-01"},
            {"at":11,"tag":"ANOMALY","color":"amber","text":"SMB burst detected srv-01 <- ad-01 (6.4x baseline)"},
            {"at":12,"tag":"FORECAST","color":"cyan","text":"Attack path predicted ad-01 -> srv-01 -> db-01 (p=0.61)"},
            {"at":14,"tag":"DEFEND","color":"lime","text":"Recommendation: isolate ad-01 (est. delta -47%)"},
            {"at":15,"tag":"ANOMALY","color":"amber","text":"svc_backup_legacy activated after 214d dormant window"},
            {"at":16,"tag":"CRITICAL","color":"rose","text":"db-01 (Crown Jewel) elevated to CRITICAL — lead 6 min"},
            {"at":18,"tag":"ATTACK","color":"rose","text":"Lateral pivot ad-01 -> srv-01 -> ws-02 confirmed"},
            {"at":20,"tag":"MITRE","color":"violet","text":"T1021 Remote Services (SMB) mapped conf=0.47"},
            {"at":22,"tag":"MITRE","color":"violet","text":"T1558 Kerberoasting mapped conf=0.58 on ad-01"},
            {"at":24,"tag":"CRITICAL","color":"rose","text":"Predicted exfil path db-01 -> cld-01 (S3) p=0.34"},
            {"at":26,"tag":"ATTACK","color":"rose","text":"C2 beaconing signature match on outbound cld-01"},
            {"at":28,"tag":"DEFEND","color":"lime","text":"Auto-suggested playbook: isolate + patch + block-445"},
        ],
    },
    {
        "id": "sc-cloud-γ-3311",
        "name": "Cloud Credential Heist γ-3311",
        "summary": "Novel-region IAM abuse pivoting from a compromised VPN into cloud storage.",
        "family": "Cloud IAM · Data Exfiltration",
        "seed": 42,
        "frame_count": 30,
        "nodes": [
            {"id":"gw-01","label":"Edge Gateway","kind":"gateway","x":90,"y":230,"base":"safe","ip":"10.0.0.1","tier":"Perimeter"},
            {"id":"vpn-01","label":"SSL VPN","kind":"gateway","x":230,"y":320,"base":"safe","escalate_at":2,"peak":"warn","ip":"10.0.0.9","tier":"Perimeter"},
            {"id":"idp-01","label":"IAM Provider","kind":"identity","x":230,"y":130,"base":"safe","escalate_at":8,"peak":"critical","ip":"iam.core","tier":"Core Identity"},
            {"id":"api-01","label":"API Gateway","kind":"server","x":420,"y":220,"base":"safe","escalate_at":10,"peak":"warn","ip":"10.0.10.20","tier":"Core"},
            {"id":"cld-01","label":"S3 Data Lake","kind":"cloud","x":620,"y":120,"base":"safe","escalate_at":16,"peak":"critical","ip":"s3-lake-ue1","tier":"Crown Jewels"},
            {"id":"cld-02","label":"BigQuery Warehouse","kind":"cloud","x":620,"y":320,"base":"safe","escalate_at":22,"peak":"warn","ip":"bq-prod","tier":"Crown Jewels"},
            {"id":"cld-03","label":"K8s Cluster","kind":"cloud","x":420,"y":440,"base":"safe","ip":"k8s-prod","tier":"Cloud"},
            {"id":"cld-04","label":"CDN Edge","kind":"cloud","x":780,"y":220,"base":"safe","escalate_at":26,"peak":"watch","ip":"cf-edge","tier":"Cloud"},
            {"id":"ws-01","label":"Contractor Laptop","kind":"workstation","x":90,"y":420,"base":"safe","escalate_at":0,"peak":"watch","ip":"10.0.40.55","tier":"Workstation"},
        ],
        "edges": [
            {"from":"ws-01","to":"vpn-01","intensity":0.6,"malicious":True,"appears_at":2},
            {"from":"vpn-01","to":"idp-01","intensity":0.8,"malicious":True,"appears_at":6},
            {"from":"idp-01","to":"api-01","intensity":0.9,"predicted":True,"malicious":True,"appears_at":10},
            {"from":"api-01","to":"cld-01","intensity":0.85,"predicted":True,"malicious":True,"appears_at":16},
            {"from":"api-01","to":"cld-02","intensity":0.5,"predicted":True,"appears_at":22},
            {"from":"cld-01","to":"cld-04","intensity":0.7,"predicted":True,"appears_at":26},
            {"from":"api-01","to":"cld-03","intensity":0.4},
            {"from":"gw-01","to":"vpn-01","intensity":0.9},
        ],
        "stages": [
            _stage("Recon", 0, 0.94, "#00F0FF"),
            _stage("Initial Access", 2, 0.88, "#00F0FF"),
            _stage("Execution", 4, 0.79, "#7C6BFF"),
            _stage("Persistence", 8, 0.68, "#7C6BFF"),
            _stage("Priv Escalation", 10, 0.72, "#FFAA00"),
            _stage("Lateral Movement", 14, 0.55, "#FFAA00"),
            _stage("Credential Access", 18, 0.41, "#FF2E63"),
            _stage("Exfiltration", 24, 0.28, "#FF2E63"),
        ],
        "mitre": [
            {"tactic":"Recon","techniques":[{"id":"T1595","name":"Active Scanning","conf":0.93,"active_at":0}]},
            {"tactic":"Initial Access","techniques":[{"id":"T1078.004","name":"Valid Cloud Accounts","conf":0.90,"active_at":2}]},
            {"tactic":"Execution","techniques":[{"id":"T1059","name":"Command & Scripting","conf":0.76,"active_at":4}]},
            {"tactic":"Persistence","techniques":[{"id":"T1098","name":"Account Manipulation","conf":0.68,"active_at":8}]},
            {"tactic":"Priv Escalation","techniques":[{"id":"T1548","name":"Abuse Elevation Control","conf":0.72,"active_at":10}]},
            {"tactic":"Credential Access","techniques":[{"id":"T1552","name":"Unsecured Credentials","conf":0.55,"active_at":14},{"id":"T1528","name":"Steal App Access Token","conf":0.41,"active_at":18}]},
            {"tactic":"Lateral Movement","techniques":[{"id":"T1550","name":"Use Alternate Auth","conf":0.55,"active_at":14}]},
            {"tactic":"Exfiltration","techniques":[{"id":"T1567","name":"Exfil to Cloud Storage","conf":0.28,"active_at":24}]},
        ],
        "xai": [
            {"name":"IAM AssumeRole from novel region","weight":0.36,"dir":"up","context":"eu-north-1 first-seen for user","active_at":6},
            {"name":"API burst on GetObject","weight":0.24,"dir":"up","context":"14× normal ListBucket rate","active_at":10},
            {"name":"MFA disabled on service account","weight":0.18,"dir":"up","context":"config drift last 2h","active_at":8},
            {"name":"Novel egress destination","weight":0.14,"dir":"up","context":"S3 → CF edge asn AS16509","active_at":20},
            {"name":"Peer traffic dropped","weight":0.05,"dir":"down","context":"expected internal fanout absent","active_at":4},
            {"name":"Bucket policy change","weight":0.03,"dir":"up","context":"PutBucketPolicy on lake","active_at":22},
        ],
        "mitigations": [
            {"id":"revoke-tokens","label":"Revoke all IAM sessions for compromised principal","delta":-52,"icon":"ShieldOff"},
            {"id":"rotate-keys","label":"Rotate API keys and service credentials","delta":-24,"icon":"Fingerprint"},
            {"id":"restrict-egress","label":"Block egress to novel ASN AS16509","delta":-14,"icon":"Ban"},
            {"id":"enforce-mfa","label":"Enforce MFA on all cloud identities","delta":-10,"icon":"Lock"},
            {"id":"disable-bucket-public","label":"Disable public access on s3-lake","delta":-8,"icon":"Binary"},
        ],
        "target_pool": [
            {"host":"cld-01 (S3 Data Lake)","peak":0.82,"activate_at":16,"eta_base":18,"color":"#FF2E63"},
            {"host":"cld-02 (BigQuery)","peak":0.44,"activate_at":22,"eta_base":30,"color":"#FFAA00"},
            {"host":"cld-04 (CDN Edge)","peak":0.28,"activate_at":26,"eta_base":42,"color":"#7C6BFF"},
        ],
        "log_seed": [
            {"at":0,"tag":"MODEL","color":"cyan","text":"Loading twin snapshot for tenant · cloud graph 3,220 objects"},
            {"at":2,"tag":"ANOMALY","color":"amber","text":"IAM AssumeRole from eu-north-1 for user@contractor"},
            {"at":4,"tag":"MITRE","color":"violet","text":"T1078.004 Valid Cloud Accounts observed"},
            {"at":8,"tag":"ANOMALY","color":"amber","text":"MFA suddenly disabled for svc-etl role"},
            {"at":10,"tag":"FORECAST","color":"cyan","text":"Path prob idp-01 -> api-01 -> cld-01 = 0.62 (rising)"},
            {"at":12,"tag":"ANOMALY","color":"amber","text":"GetObject burst 14× baseline on s3-lake"},
            {"at":16,"tag":"CRITICAL","color":"rose","text":"cld-01 (Crown Jewel) elevated to CRITICAL — lead 2 min"},
            {"at":20,"tag":"ATTACK","color":"rose","text":"Data staged for exfil to CF edge AS16509"},
            {"at":22,"tag":"MITRE","color":"violet","text":"T1552 Unsecured Credentials matched (config drift)"},
            {"at":24,"tag":"ATTACK","color":"rose","text":"Exfil in progress — 2.4 GB transferred so far"},
            {"at":26,"tag":"DEFEND","color":"lime","text":"Auto-suggested: revoke IAM + block egress + rotate keys"},
        ],
    },
    {
        "id": "sc-supply-λ-9018",
        "name": "Supply Chain Compromise λ-9018",
        "summary": "Poisoned CI/CD artefact propagates to production Kubernetes.",
        "family": "Supply Chain · CI/CD",
        "seed": 42,
        "frame_count": 30,
        "nodes": [
            {"id":"ws-01","label":"Dev Laptop 007","kind":"workstation","x":90,"y":220,"base":"safe","escalate_at":2,"peak":"warn","ip":"10.0.40.7","tier":"Workstation"},
            {"id":"repo-01","label":"Git Server","kind":"server","x":250,"y":120,"base":"safe","escalate_at":6,"peak":"warn","ip":"git.core","tier":"Core"},
            {"id":"ci-01","label":"CI Runner Farm","kind":"server","x":250,"y":320,"base":"safe","escalate_at":10,"peak":"critical","ip":"ci.pool","tier":"Core"},
            {"id":"reg-01","label":"Container Registry","kind":"db","x":430,"y":220,"base":"safe","escalate_at":14,"peak":"critical","ip":"reg.core","tier":"Crown Jewels"},
            {"id":"k8s-01","label":"Prod K8s Cluster","kind":"cloud","x":620,"y":120,"base":"safe","escalate_at":20,"peak":"critical","ip":"k8s-prod","tier":"Crown Jewels"},
            {"id":"k8s-02","label":"Staging Cluster","kind":"cloud","x":620,"y":320,"base":"safe","escalate_at":16,"peak":"warn","ip":"k8s-stg","tier":"Cloud"},
            {"id":"db-01","label":"App Database","kind":"db","x":790,"y":220,"base":"safe","escalate_at":24,"peak":"warn","ip":"pg-prod","tier":"Crown Jewels"},
            {"id":"secrets","label":"Secrets Vault","kind":"identity","x":430,"y":420,"base":"safe","escalate_at":18,"peak":"warn","ip":"vault","tier":"Core Identity"},
        ],
        "edges": [
            {"from":"ws-01","to":"repo-01","intensity":0.8,"malicious":True,"appears_at":4},
            {"from":"repo-01","to":"ci-01","intensity":0.9,"malicious":True,"appears_at":8},
            {"from":"ci-01","to":"reg-01","intensity":0.9,"malicious":True,"predicted":True,"appears_at":12},
            {"from":"reg-01","to":"k8s-02","intensity":0.7,"predicted":True,"appears_at":16},
            {"from":"reg-01","to":"k8s-01","intensity":0.9,"predicted":True,"malicious":True,"appears_at":20},
            {"from":"k8s-01","to":"db-01","intensity":0.7,"predicted":True,"appears_at":24},
            {"from":"ci-01","to":"secrets","intensity":0.5,"predicted":True,"appears_at":18},
        ],
        "stages": [
            _stage("Recon", 0, 0.91, "#00F0FF"),
            _stage("Initial Access", 2, 0.85, "#00F0FF"),
            _stage("Execution", 6, 0.78, "#7C6BFF"),
            _stage("Persistence", 10, 0.74, "#7C6BFF"),
            _stage("Priv Escalation", 14, 0.66, "#FFAA00"),
            _stage("Lateral Movement", 18, 0.52, "#FFAA00"),
            _stage("Credential Access", 22, 0.34, "#FF2E63"),
            _stage("Exfiltration", 26, 0.19, "#FF2E63"),
        ],
        "mitre": [
            {"tactic":"Recon","techniques":[{"id":"T1596","name":"Search Open Sources","conf":0.90,"active_at":0}]},
            {"tactic":"Initial Access","techniques":[{"id":"T1195","name":"Supply Chain Compromise","conf":0.85,"active_at":2}]},
            {"tactic":"Execution","techniques":[{"id":"T1204","name":"User Execution (CI pipeline)","conf":0.78,"active_at":6}]},
            {"tactic":"Persistence","techniques":[{"id":"T1554","name":"Compromise Client Software Binary","conf":0.74,"active_at":10}]},
            {"tactic":"Priv Escalation","techniques":[{"id":"T1611","name":"Escape to Host (container)","conf":0.66,"active_at":14}]},
            {"tactic":"Credential Access","techniques":[{"id":"T1552.007","name":"Container API Creds","conf":0.34,"active_at":22}]},
            {"tactic":"Lateral Movement","techniques":[{"id":"T1610","name":"Deploy Container","conf":0.52,"active_at":18}]},
            {"tactic":"Exfiltration","techniques":[{"id":"T1041","name":"C2 Exfiltration","conf":0.19,"active_at":26}]},
        ],
        "xai": [
            {"name":"Unsigned commit into main","weight":0.32,"dir":"up","context":"first ever unsigned push by user","active_at":4},
            {"name":"CI job spawns outbound shell","weight":0.28,"dir":"up","context":"never observed in prior 4,200 runs","active_at":8},
            {"name":"New image layer > 800MB","weight":0.16,"dir":"up","context":"anomalous vs mean 41MB","active_at":12},
            {"name":"K8s ServiceAccount created at runtime","weight":0.13,"dir":"up","context":"runtime creation is rare","active_at":18},
            {"name":"Registry pulls from staging namespace","weight":0.08,"dir":"up","context":"staging→prod pull is novel","active_at":16},
            {"name":"Reduced test coverage in pipeline","weight":0.03,"dir":"down","context":"unusual for main branch","active_at":6},
        ],
        "mitigations": [
            {"id":"quarantine-image","label":"Quarantine registry image sha:...c8f2","delta":-55,"icon":"ShieldOff"},
            {"id":"revoke-ci-tokens","label":"Rotate CI runner tokens","delta":-20,"icon":"Fingerprint"},
            {"id":"block-registry-pull","label":"Block prod cluster pulls from registry","delta":-14,"icon":"Ban"},
            {"id":"sbom-freeze","label":"Freeze deploy pipeline pending SBOM audit","delta":-9,"icon":"Binary"},
            {"id":"revoke-secrets","label":"Rotate all vault secrets touched by CI","delta":-7,"icon":"Lock"},
        ],
        "target_pool": [
            {"host":"k8s-01 (Prod Cluster)","peak":0.86,"activate_at":20,"eta_base":24,"color":"#FF2E63"},
            {"host":"reg-01 (Registry)","peak":0.72,"activate_at":14,"eta_base":16,"color":"#FFAA00"},
            {"host":"db-01 (App DB)","peak":0.39,"activate_at":24,"eta_base":36,"color":"#7C6BFF"},
        ],
        "log_seed": [
            {"at":0,"tag":"MODEL","color":"cyan","text":"Loading supply chain twin · 4,821 CI jobs indexed"},
            {"at":2,"tag":"ANOMALY","color":"amber","text":"Unsigned push into main by dev-007"},
            {"at":6,"tag":"MITRE","color":"violet","text":"T1195 Supply Chain Compromise matched"},
            {"at":8,"tag":"ANOMALY","color":"amber","text":"CI job spawned outbound reverse shell"},
            {"at":10,"tag":"FORECAST","color":"cyan","text":"Path prob ci-01 -> reg-01 -> k8s-01 = 0.66"},
            {"at":12,"tag":"ANOMALY","color":"amber","text":"New image layer 840MB pushed sha:...c8f2"},
            {"at":14,"tag":"CRITICAL","color":"rose","text":"reg-01 (Crown Jewel) elevated to CRITICAL"},
            {"at":18,"tag":"MITRE","color":"violet","text":"T1610 Deploy Container matched in staging"},
            {"at":20,"tag":"ATTACK","color":"rose","text":"Prod cluster pulling compromised image sha:...c8f2"},
            {"at":24,"tag":"CRITICAL","color":"rose","text":"Predicted exfil path k8s-01 -> db-01 (p=0.39)"},
            {"at":26,"tag":"DEFEND","color":"lime","text":"Auto-suggested: quarantine image + freeze pipeline"},
        ],
    },
]

TENANTS_SEED = [
    {"id": "ten-acme",     "name": "ACME Financial Group",   "region": "US-EAST-1",  "operator": "A. Kowalski",  "tier": "Enterprise"},
    {"id": "ten-orbital",  "name": "Orbital Health Systems", "region": "EU-WEST-2",  "operator": "M. Osei",      "tier": "Enterprise"},
    {"id": "ten-fortis",   "name": "Fortis MSSP · Client 14","region": "AP-SOUTH-1", "operator": "S. Tanaka",    "tier": "MSSP"},
]


# --------------------------------------------------------------------------
# Compute helpers (frame-derived state)
# --------------------------------------------------------------------------
def stage_prob(activate_at: int, target: float, frame: int) -> float:
    if frame < activate_at:
        return 0.0
    ramp = min(1.0, (frame - activate_at) / 4.0)
    return round(target * ramp, 4)


def risk_at(node: dict, frame: int) -> str:
    ladder = ["safe", "watch", "warn", "critical"]
    base = node.get("base", "safe")
    if "escalate_at" not in node or "peak" not in node:
        return base
    esc = int(node["escalate_at"])
    peak = str(node["peak"])
    if frame < esc:
        return base
    if frame < esc + 4:
        return ladder[min(ladder.index(peak), ladder.index(base) + 1)]
    if frame < esc + 8:
        return ladder[max(0, ladder.index(peak) - 1)]
    return peak


def compute_frame(scenario: dict, frame: int) -> dict[str, Any]:
    total_frames = int(scenario.get("frame_count", 30))
    frame = max(0, min(total_frames - 1, frame))

    stages_out = []
    stages_done = 0
    for s in scenario["stages"]:
        prob = stage_prob(int(s["activate_at"]), float(s["target"]), frame)
        done = frame > int(s["activate_at"]) + 4
        if done:
            stages_done += 1
        stages_out.append({
            "stage": s["stage"], "color": s["color"], "activate_at": s["activate_at"],
            "target": s["target"], "prob": prob, "done": done,
        })

    nodes_out = [{**n, "risk": risk_at(n, frame)} for n in scenario["nodes"]]

    edges_out = [
        {**e, "visible": (e.get("appears_at", -1) <= frame)}
        for e in scenario["edges"]
    ]

    mitre_out = []
    for col in scenario["mitre"]:
        techs = []
        for t in col["techniques"]:
            active = frame >= int(t["active_at"])
            techs.append({**t, "active": active, "current_conf": t["conf"] if active else 0.0})
        mitre_out.append({"tactic": col["tactic"], "techniques": techs})

    xai_out = [{**s, "active": frame >= int(s["active_at"])} for s in scenario["xai"]]

    targets_out = []
    for t in scenario["target_pool"]:
        pct = stage_prob(int(t["activate_at"]), float(t["peak"]), frame)
        eta = max(0, int(t["eta_base"]) - frame)
        targets_out.append({"host": t["host"], "pct": pct, "eta_min": eta, "color": t["color"]})

    lead = max(0, (22 - frame)) * 60
    conf = round(min(99.9, 90 + frame * 0.3), 2)

    critical_count = sum(1 for n in nodes_out if n["risk"] == "critical")
    warn_count = sum(1 for n in nodes_out if n["risk"] == "warn")
    active_threat_vectors = min(3, frame // 8)

    log_lines = [
        {"t": f"{l['at'] * 0.12:.3f}", **{k: v for k, v in l.items()}}
        for l in scenario["log_seed"] if l["at"] <= frame
    ]

    return {
        "frame": frame,
        "frame_count": total_frames,
        "stages": stages_out,
        "stages_done": stages_done,
        "nodes": nodes_out,
        "edges": edges_out,
        "mitre": mitre_out,
        "xai": xai_out,
        "targets": targets_out,
        "logs": log_lines,
        "kpis": {
            "active_threat_vectors": active_threat_vectors,
            "forecast_confidence": conf,
            "lead_time_sec": lead,
            "twin_nodes": 12480,
            "twin_edges": 42110,
            "critical_nodes": critical_count,
            "warn_nodes": warn_count,
            "twin_fidelity": 99.4,
        },
        "computed_at": now_iso(),
    }


async def compute_incident_state(scenario: dict, frame: int) -> dict[str, Any]:
    """Layered on top of compute_frame: adds lifecycle, primary suspect, spread analysis."""
    settings = await get_care_settings()
    df = detection_frame_for(scenario, float(settings["detection_threshold"]))
    lifecycle = lifecycle_at(frame, df, settings, scenario)
    primary = None
    affected: list[dict] = []
    if lifecycle["stage"] != "Baseline":
        # pick primary at detection frame so it stays stable through the cycle
        primary = primary_suspect(scenario, min(frame, df))
        if lifecycle["stage"] not in ("Detecting", "Threat Detected"):
            affected = spread_analysis(scenario, primary, frame, settings)
    counts = {"ISOLATE": 0, "RESTRICT": 0, "MONITOR": 0, "PROTECT": 0, "NO_ACTION": 0}
    for h in affected:
        counts[h["action"]] = counts.get(h["action"], 0) + 1
    return {
        "lifecycle": lifecycle,
        "primary_suspect": ({
            "id": primary["id"], "label": primary["label"], "tier": primary.get("tier"),
            "kind": primary.get("kind"), "ip": primary.get("ip"),
            "risk": risk_at(primary, frame),
            "confidence": threat_confidence(primary, scenario, frame),
        } if primary else None),
        "affected_systems": affected,
        "affected_counts": counts,
        "care_settings": settings,
    }


# --------------------------------------------------------------------------
# CARE — CyberWorld Autonomous Response Engine
# --------------------------------------------------------------------------
CRITICAL_TIERS = {"Crown Jewels", "Core Identity"}
RISK_SCORE = {"safe": 0.10, "watch": 0.35, "warn": 0.65, "critical": 0.90}

DEFAULT_CARE_SETTINGS: dict[str, Any] = {
    "detection_threshold": 0.55,
    "isolate_threshold": 0.90,
    "restrict_threshold": 0.75,
    "monitor_threshold": 0.50,
    "max_response_cycles": 3,
    "verification_window_frames": 4,
    "protect_critical_assets": True,
}


async def get_care_settings() -> dict[str, Any]:
    doc = await db.care_settings.find_one({"id": "global"}, {"_id": 0})
    if not doc:
        return dict(DEFAULT_CARE_SETTINGS)
    return {**DEFAULT_CARE_SETTINGS, **doc}


def detection_frame_for(scenario: dict, detection_threshold: float) -> int:
    """First frame where the incident-response trigger fires.

    Uses the existing early-warning condition: the first frame where any host
    escalates to `warn` or higher, deterministic across the scenario data.
    `detection_threshold` is retained as a policy dial that tightens or loosens
    the trigger via a lookahead offset (higher threshold -> later trigger).
    """
    total = int(scenario.get("frame_count", 30))
    warn_frame = total
    for f in range(total):
        for n in scenario["nodes"]:
            r = risk_at(n, f)
            if r in ("warn", "critical"):
                warn_frame = f
                break
        if warn_frame < total:
            break
    # threshold acts as a small offset — 0.5 = trigger at first warn, 1.0 = wait longer
    offset = max(0, int((detection_threshold - 0.5) * 8))
    return min(total - 1, warn_frame + offset)


def primary_suspect(scenario: dict, frame: int) -> dict | None:
    """Highest-risk host at the given frame; deterministic tie-break by earliest escalate_at then id."""
    scored: list[tuple[int, int, str, dict]] = []
    for n in scenario["nodes"]:
        r = risk_at(n, frame)
        rank = ["safe", "watch", "warn", "critical"].index(r)
        scored.append((-rank, int(n.get("escalate_at", 9999)), n["id"], n))
    scored.sort()
    return scored[0][3] if scored else None


def _graph_novelty(node_id: str, edges: list[dict], frame: int) -> float:
    """0..1 score: presence on malicious/predicted/recently-appeared edges."""
    score = 0.0
    for e in edges:
        if node_id not in (e.get("from"), e.get("to")):
            continue
        appears = int(e.get("appears_at", -1))
        if appears > frame:
            continue
        if e.get("malicious"):
            score = max(score, 0.9)
        elif e.get("predicted"):
            score = max(score, 0.7)
        elif appears >= max(0, frame - 4):
            score = max(score, 0.55)
        else:
            score = max(score, 0.25)
    return score


def _target_score(node: dict, scenario: dict, frame: int) -> float:
    """0..1: peak target probability if this host matches a predicted target."""
    for t in scenario["target_pool"]:
        host = str(t["host"])
        if host.startswith(node["id"]) or node["id"] in host or node["label"] in host:
            return stage_prob(int(t["activate_at"]), float(t["peak"]), frame)
        first_token = node["label"].split()[0].lower() if node.get("label") else ""
        if first_token and first_token in host.lower():
            return stage_prob(int(t["activate_at"]), float(t["peak"]), frame)
    return 0.0


def threat_confidence(node: dict, scenario: dict, frame: int) -> float:
    """Policy-derived combination — not a separately trained ML probability."""
    r = risk_at(node, frame)
    r_s = RISK_SCORE.get(r, 0.1)
    g_s = _graph_novelty(node["id"], scenario["edges"], frame)
    t_s = _target_score(node, scenario, frame)
    conf = 0.55 * r_s + 0.30 * g_s + 0.15 * t_s
    return round(max(0.0, min(1.0, conf)), 3)


def care_decision(node: dict, conf: float, settings: dict[str, Any]) -> tuple[str, str]:
    """Return (action, reason). Actions: ISOLATE, RESTRICT, MONITOR, PROTECT, NO_ACTION."""
    critical = node.get("tier") in CRITICAL_TIERS
    iso = float(settings["isolate_threshold"])
    res = float(settings["restrict_threshold"])
    mon = float(settings["monitor_threshold"])
    if critical and settings.get("protect_critical_assets", True):
        if conf >= iso:
            return "PROTECT", "Critical asset with very high threat confidence — suspicious paths restricted, monitoring heightened, asset preserved for engineer recovery."
        if conf >= res:
            return "PROTECT", "Critical asset with elevated threat confidence — protective containment, no blind isolation."
        if conf >= mon:
            return "MONITOR", "Critical asset under baseline suspicion — heightened observation."
        return "NO_ACTION", "Critical asset with confidence below action threshold — observe only."
    if conf >= iso:
        return "ISOLATE", "High policy-derived threat confidence — auto-isolate in replay/lab environment."
    if conf >= res:
        return "RESTRICT", "Elevated threat confidence — restrict suspicious edges, heightened monitoring."
    if conf >= mon:
        return "MONITOR", "Suspicion above monitor threshold — no traffic changes, elevated observation."
    return "NO_ACTION", "Threat confidence below action thresholds — observe only."


def spread_analysis(scenario: dict, primary: dict, frame: int, settings: dict[str, Any]) -> list[dict]:
    """Evaluate every host as potentially affected; return CARE decision + rationale."""
    out: list[dict] = []
    if not primary:
        return out
    pid = primary["id"]
    # direct neighbours via any edge appearing on/before frame
    neighbours: set[str] = set()
    for e in scenario["edges"]:
        if int(e.get("appears_at", -1)) > frame:
            continue
        if e["from"] == pid:
            neighbours.add(e["to"])
        elif e["to"] == pid:
            neighbours.add(e["from"])
    for n in scenario["nodes"]:
        if n["id"] == pid:
            continue
        conf = threat_confidence(n, scenario, frame)
        # graph-adjacency bonus
        if n["id"] in neighbours:
            conf = round(min(1.0, conf + 0.08), 3)
        action, reason = care_decision(n, conf, settings)
        out.append({
            "id": n["id"],
            "label": n["label"],
            "tier": n.get("tier", "Unknown"),
            "kind": n.get("kind", "server"),
            "risk": risk_at(n, frame),
            "confidence": conf,
            "action": action,
            "reason": reason,
            "critical": n.get("tier") in CRITICAL_TIERS,
            "neighbour_of_primary": n["id"] in neighbours,
        })
    # highest confidence first, but keep critical assets grouped visibly by pushing them up on ties
    out.sort(key=lambda h: (-h["confidence"], not h["critical"], h["id"]))
    return out


def lifecycle_at(frame: int, detection_frame: int, settings: dict[str, Any], scenario: dict) -> dict:
    """Compute the current incident-response lifecycle stage and derived flags.

    Timeline after detection (frame indices relative to detection_frame):
      +0  Threat Detected
      +1  Initial Containment
      +2  Spread Analysis
      +3  Host Assessment
      +4  Secondary Containment
      +5..+(4+verif)  Verifying
      +5+verif        Contained (propagation stopped)
      +7+verif        Report Ready
      +9+verif        Engineer Handoff
    Cycle can re-run once per verification failure, bounded by max_response_cycles.
    All seeded scenarios contain successfully on cycle 1 by design.
    """
    verif = int(settings["verification_window_frames"])
    max_cycles = int(settings["max_response_cycles"])
    verify_start = detection_frame + 4
    verify_end = verify_start + verif

    stage = "Baseline"
    cycle = 1
    verifying_progress = 0.0
    propagation_stopped = False
    escalation_required = False

    if frame < detection_frame:
        # Detecting window (3 frames of rising risk before automation trigger)
        stage = "Detecting" if frame >= max(0, detection_frame - 3) else "Baseline"
    elif frame == detection_frame:
        stage = "Threat Detected"
    elif frame == detection_frame + 1:
        stage = "Initial Containment"
    elif frame == detection_frame + 2:
        stage = "Spread Analysis"
    elif frame == detection_frame + 3:
        stage = "Host Assessment"
    elif frame == detection_frame + 4:
        stage = "Secondary Containment"
    elif frame < verify_end:
        stage = "Verifying"
        verifying_progress = min(1.0, (frame - verify_start) / max(1, verif))
    elif frame == verify_end:
        stage = "Contained"
        propagation_stopped = True
    elif frame < verify_end + 3:
        stage = "Contained"
        propagation_stopped = True
    elif frame < verify_end + 5:
        stage = "Report Ready"
        propagation_stopped = True
    else:
        stage = "Engineer Handoff"
        propagation_stopped = True

    if cycle > max_cycles:
        escalation_required = True
        propagation_stopped = False
        stage = "Engineer Handoff"

    return {
        "stage": stage,
        "cycle": cycle,
        "max_cycles": max_cycles,
        "detection_frame": detection_frame,
        "verify_start_frame": verify_start,
        "verify_end_frame": verify_end,
        "verifying_progress": round(verifying_progress, 3),
        "propagation_stopped": propagation_stopped,
        "escalation_required": escalation_required,
    }


def compute_baseline_and_mitigated(scenario: dict, frame: int, mitigation_ids: list[str]) -> dict:
    baseline = 0.0
    for t in scenario["target_pool"]:
        p = stage_prob(int(t["activate_at"]), float(t["peak"]), frame)
        if p > baseline:
            baseline = p
    delta_pct = 0
    picked = []
    for m in scenario["mitigations"]:
        if m["id"] in mitigation_ids:
            delta_pct += int(m["delta"])
            picked.append(m)
    new_risk = max(0.02, baseline + delta_pct / 100.0)
    return {
        "frame": frame,
        "baseline_risk": round(baseline, 4),
        "delta_pct": delta_pct,
        "new_risk": round(new_risk, 4),
        "applied": picked,
    }


# --------------------------------------------------------------------------
# Pydantic request models
# --------------------------------------------------------------------------
class SimulateReq(BaseModel):
    model_config = ConfigDict(extra="ignore")
    scenario_id: str
    frame: int = Field(0, ge=0, le=29)
    mitigation_ids: list[str] = Field(default_factory=list)


class IncidentReq(BaseModel):
    model_config = ConfigDict(extra="ignore")
    scenario_id: str
    tenant_id: str | None = None
    frame: int
    title: str
    operator: str | None = None
    notes: str | None = None
    mitigation_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# FastAPI app
# --------------------------------------------------------------------------
app = FastAPI(title="CyberWorld AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def seed_and_index() -> None:
    # Scenarios seed
    for sc in SCENARIOS_SEED:
        await db.scenarios.update_one({"id": sc["id"]}, {"$set": sc}, upsert=True)
    # Tenants seed
    for t in TENANTS_SEED:
        await db.tenants.update_one({"id": t["id"]}, {"$set": t}, upsert=True)
    # Indexes
    await db.incidents.create_index("id", unique=True)
    await db.incidents.create_index("created_at")
    await db.playbooks.create_index("id", unique=True)


@app.get("/api/health")
async def health() -> dict[str, Any]:
    scenario_count = await db.scenarios.count_documents({})
    return {
        "status": "ok",
        "service": "cyberworld-ai",
        "version": "1.0.0",
        "model": "tw-v3.4.1",
        "features": 80,
        "scenarios_loaded": scenario_count,
        "timestamp": now_iso(),
    }


@app.get("/api/tenants")
async def list_tenants() -> list[dict[str, Any]]:
    cur = db.tenants.find({}, {"_id": 0}).sort("name", 1)
    return [t async for t in cur]


@app.get("/api/scenarios")
async def list_scenarios() -> list[dict[str, Any]]:
    cur = db.scenarios.find({}, {"_id": 0, "id": 1, "name": 1, "summary": 1, "family": 1, "frame_count": 1}).sort("name", 1)
    return [s async for s in cur]


@app.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str) -> dict[str, Any]:
    sc = await db.scenarios.find_one({"id": scenario_id}, {"_id": 0})
    if not sc:
        raise HTTPException(status_code=404, detail="scenario not found")
    return sc


@app.get("/api/scenarios/{scenario_id}/frame/{frame}")
async def get_frame(scenario_id: str, frame: int) -> dict[str, Any]:
    sc = await db.scenarios.find_one({"id": scenario_id}, {"_id": 0})
    if not sc:
        raise HTTPException(status_code=404, detail="scenario not found")
    base = compute_frame(sc, frame)
    incident = await compute_incident_state(sc, frame)
    # augment log stream with lifecycle-driven event lines
    life = incident["lifecycle"]
    df = life["detection_frame"]
    life_events: list[dict] = []
    if frame >= df - 2:
        life_events.append({"at": max(0, df - 2), "tag": "DETECT", "color": "amber", "text": "Temporal risk rising — CARE monitoring elevated"})
    if frame >= df:
        prim = (incident.get("primary_suspect") or {}).get("label", "primary host")
        life_events.append({"at": df, "tag": "DETECT", "color": "rose", "text": f"Threat detected on {prim} — automated containment initiated"})
        life_events.append({"at": df + 1, "tag": "CARE", "color": "lime", "text": f"Initial containment — {prim} isolated in replay environment"})
    if frame >= df + 2:
        life_events.append({"at": df + 2, "tag": "CARE", "color": "cyan", "text": "Spread analysis running across digital twin neighbours"})
    if frame >= df + 3:
        counts = incident["affected_counts"]
        life_events.append({"at": df + 3, "tag": "CARE", "color": "cyan", "text": f"Host assessment complete — ISOLATE {counts['ISOLATE']} · RESTRICT {counts['RESTRICT']} · MONITOR {counts['MONITOR']} · PROTECT {counts['PROTECT']}"})
    if frame >= df + 4:
        life_events.append({"at": df + 4, "tag": "CARE", "color": "lime", "text": "Secondary containment applied to potentially affected systems"})
    if frame >= life["verify_start_frame"] + 1:
        life_events.append({"at": life["verify_start_frame"] + 1, "tag": "VERIFY", "color": "violet", "text": "Verification window monitoring for further propagation"})
    if life["propagation_stopped"] and frame >= life["verify_end_frame"]:
        life_events.append({"at": life["verify_end_frame"], "tag": "VERIFY", "color": "lime", "text": "Containment successful — no further suspicious propagation observed"})
    if life["stage"] == "Report Ready":
        life_events.append({"at": life["verify_end_frame"] + 2, "tag": "REPORT", "color": "cyan", "text": "Incident report auto-assembled and persisted for engineer review"})
    if life["stage"] == "Engineer Handoff":
        life_events.append({"at": life["verify_end_frame"] + 4, "tag": "HANDOFF", "color": "amber", "text": "Engineer handoff — investigate · remediate · recover"})
    # merge, dedupe by (at, text), sort by at
    combined = list(base["logs"])
    seen = {(l["at"], l["text"]) for l in combined}
    for l in life_events:
        if (l["at"], l["text"]) not in seen and l["at"] <= frame:
            combined.append({"t": f"{l['at'] * 0.12:.3f}", **l})
            seen.add((l["at"], l["text"]))
    combined.sort(key=lambda x: x["at"])
    base["logs"] = combined
    base["incident"] = incident

    # Auto-persist incident report when Report Ready is reached (idempotent per scenario)
    if life["stage"] in ("Report Ready", "Engineer Handoff"):
        existing = await db.incidents.find_one({"scenario_id": scenario_id, "auto": True}, {"_id": 0})
        if not existing:
            await _persist_auto_report(sc, base, incident)
    return base


async def _persist_auto_report(sc: dict, frame_state: dict, incident: dict) -> dict[str, Any]:
    life = incident["lifecycle"]
    df = life["detection_frame"]
    end_frame = life["verify_end_frame"]
    frame_at_end = compute_frame(sc, end_frame)
    detection_state = compute_frame(sc, df)
    baseline_end = max([stage_prob(int(t["activate_at"]), float(t["peak"]), end_frame) for t in sc["target_pool"]] + [0.0])
    baseline_start = max([stage_prob(int(t["activate_at"]), float(t["peak"]), df) for t in sc["target_pool"]] + [0.0])
    incident_id = f"inc-auto-{sc['id']}"[:64]
    doc = {
        "id": incident_id,
        "scenario_id": sc["id"],
        "scenario_name": sc["name"],
        "auto": True,
        "tenant_id": None,
        "frame": end_frame,
        "detection_frame": df,
        "title": f"{sc['name']} — Autonomous containment report",
        "operator": "CARE (autonomous)",
        "notes": "Auto-generated after verification loop completed successfully.",
        "created_at": now_iso(),
        "primary_suspect": incident.get("primary_suspect"),
        "affected_systems": incident.get("affected_systems"),
        "affected_counts": incident.get("affected_counts"),
        "care_settings": incident.get("care_settings"),
        "lifecycle": life,
        "engineer_action_required": "Investigate isolated systems, perform root-cause analysis on the primary suspect, review credentials, patch and remediate impacted hosts, recover from clean backups. Simulated lab actions — no real endpoints were disconnected.",
        "snapshot": {
            "kpis_at_detection": detection_state["kpis"],
            "kpis_at_end": frame_at_end["kpis"],
            "stages_at_end": frame_at_end["stages"],
            "targets_at_end": frame_at_end["targets"],
            "mitre_active": [
                {"tactic": col["tactic"], "id": t["id"], "name": t["name"], "conf": t["current_conf"]}
                for col in frame_at_end["mitre"] for t in col["techniques"] if t["active"]
            ],
            "xai_active": [s for s in frame_at_end["xai"] if s["active"]],
            "response_metrics": {
                "detection_frame": df,
                "initial_containment_frame": df + 1,
                "secondary_containment_frame": df + 4,
                "verification_start_frame": life["verify_start_frame"],
                "verification_end_frame": end_frame,
                "cycles_used": life["cycle"],
                "propagation_stopped": life["propagation_stopped"],
                "peak_risk_at_detection": round(baseline_start, 4),
                "peak_risk_at_end": round(baseline_end, 4),
                "risk_reduction_pct": round((baseline_start - baseline_end) * 100, 2),
            },
        },
    }
    await db.incidents.update_one({"id": incident_id}, {"$set": doc}, upsert=True)
    return doc


class CareSettingsReq(BaseModel):
    model_config = ConfigDict(extra="ignore")
    detection_threshold: float | None = Field(None, ge=0.0, le=1.0)
    isolate_threshold: float | None = Field(None, ge=0.0, le=1.0)
    restrict_threshold: float | None = Field(None, ge=0.0, le=1.0)
    monitor_threshold: float | None = Field(None, ge=0.0, le=1.0)
    max_response_cycles: int | None = Field(None, ge=1, le=10)
    verification_window_frames: int | None = Field(None, ge=1, le=15)
    protect_critical_assets: bool | None = None


@app.get("/api/care/settings")
async def care_settings_get() -> dict[str, Any]:
    return await get_care_settings()


@app.put("/api/care/settings")
async def care_settings_put(req: CareSettingsReq) -> dict[str, Any]:
    current = await get_care_settings()
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    merged = {**current, **updates, "id": "global"}
    await db.care_settings.update_one({"id": "global"}, {"$set": merged}, upsert=True)
    return {k: v for k, v in merged.items() if k != "id"}


@app.post("/api/simulate")
async def simulate(req: SimulateReq) -> dict[str, Any]:
    sc = await db.scenarios.find_one({"id": req.scenario_id}, {"_id": 0})
    if not sc:
        raise HTTPException(status_code=404, detail="scenario not found")
    return compute_baseline_and_mitigated(sc, req.frame, req.mitigation_ids)


@app.post("/api/incidents")
async def create_incident(req: IncidentReq) -> dict[str, Any]:
    sc = await db.scenarios.find_one({"id": req.scenario_id}, {"_id": 0})
    if not sc:
        raise HTTPException(status_code=404, detail="scenario not found")

    incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    frame_state = compute_frame(sc, req.frame)
    sim = compute_baseline_and_mitigated(sc, req.frame, req.mitigation_ids)

    doc = {
        "id": incident_id,
        "scenario_id": req.scenario_id,
        "scenario_name": sc["name"],
        "tenant_id": req.tenant_id,
        "frame": req.frame,
        "title": req.title,
        "operator": req.operator,
        "notes": req.notes,
        "mitigation_ids": req.mitigation_ids,
        "created_at": now_iso(),
        "snapshot": {
            "kpis": frame_state["kpis"],
            "targets": frame_state["targets"],
            "stages": frame_state["stages"],
            "mitre_active": [
                {"tactic": col["tactic"], "id": t["id"], "name": t["name"], "conf": t["current_conf"]}
                for col in frame_state["mitre"] for t in col["techniques"] if t["active"]
            ],
            "xai_active": [s for s in frame_state["xai"] if s["active"]],
            "simulation": sim,
        },
    }
    await db.incidents.insert_one(doc)
    return _serialize(doc)


@app.get("/api/incidents")
async def list_incidents(tenant_id: str | None = None) -> list[dict[str, Any]]:
    q: dict[str, Any] = {}
    if tenant_id:
        q["tenant_id"] = tenant_id
    cur = db.incidents.find(q, {"_id": 0}).sort("created_at", -1).limit(50)
    return [i async for i in cur]


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    doc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="incident not found")
    return doc


# --------------------------------------------------------------------------
# Threat Intel Enrichment (cached public sources — NVD, CISA KEV, Spamhaus, OTX)
# --------------------------------------------------------------------------

@app.get("/api/scenarios/{scenario_id}/intel/{node_id}")
async def node_intel(scenario_id: str, node_id: str) -> dict[str, Any]:
    sc = await db.scenarios.find_one({"id": scenario_id}, {"_id": 0})
    if not sc:
        raise HTTPException(status_code=404, detail="scenario not found")
    node = next((n for n in sc["nodes"] if n["id"] == node_id), None)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    intel = resolve_intel(scenario_id, node)
    return {"node_id": node_id, "scenario_id": scenario_id, **intel}


# --------------------------------------------------------------------------
# Playbooks — save named CARE threshold sets with auto-match patterns
# --------------------------------------------------------------------------

class PlaybookReq(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str = Field(..., min_length=2, max_length=64)
    match: dict[str, Any] = Field(default_factory=dict)   # {"scenario_family": "...", "scenario_id": "..."}
    thresholds: dict[str, Any] = Field(default_factory=dict)
    auto_apply: bool = True


@app.get("/api/playbooks")
async def list_playbooks() -> list[dict[str, Any]]:
    cur = db.playbooks.find({}, {"_id": 0}).sort("created_at", -1)
    return [p async for p in cur]


@app.post("/api/playbooks")
async def create_playbook(req: PlaybookReq) -> dict[str, Any]:
    doc = {
        "id": f"pb-{uuid.uuid4().hex[:8]}",
        "name": req.name,
        "match": req.match,
        "thresholds": req.thresholds,
        "auto_apply": req.auto_apply,
        "created_at": now_iso(),
    }
    await db.playbooks.insert_one(doc)
    return {k: v for k, v in doc.items() if k != "_id"}


@app.delete("/api/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: str) -> dict[str, Any]:
    r = await db.playbooks.delete_one({"id": playbook_id})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="playbook not found")
    return {"deleted": playbook_id}


@app.post("/api/playbooks/match")
async def match_playbook(payload: dict[str, Any]) -> dict[str, Any]:
    """Return best-matching auto_apply playbook for a scenario, if any."""
    scenario_id = payload.get("scenario_id")
    family = payload.get("family")
    if not scenario_id:
        return {"match": None}
    cur = db.playbooks.find({"auto_apply": True}, {"_id": 0})
    best = None
    async for pb in cur:
        m = pb.get("match", {})
        # exact scenario id wins over family match
        if m.get("scenario_id") == scenario_id:
            best = pb
            break
        if family and m.get("scenario_family") and family.lower().startswith(m["scenario_family"].lower()):
            best = pb
    if best:
        # apply thresholds
        current = await get_care_settings()
        merged = {**current, **best.get("thresholds", {}), "id": "global"}
        await db.care_settings.update_one({"id": "global"}, {"$set": merged}, upsert=True)
    return {"match": best}


# --------------------------------------------------------------------------
# Live streaming via WebSocket — replaces frame-fetch HTTP roundtrip when playing
# --------------------------------------------------------------------------

@app.websocket("/api/ws/frames")
async def ws_frames(ws: WebSocket) -> None:
    """Client protocol:
       -> {"scenario_id": "...", "frame": N}
       <- <full frame payload same shape as GET /api/scenarios/{id}/frame/{N}>
    """
    await ws.accept()
    try:
        while True:
            msg = await ws.receive_json()
            sid = msg.get("scenario_id")
            frame = int(msg.get("frame", 0))
            sc = await db.scenarios.find_one({"id": sid}, {"_id": 0})
            if not sc:
                await ws.send_json({"error": "scenario not found", "scenario_id": sid})
                continue
            base = compute_frame(sc, frame)
            incident = await compute_incident_state(sc, frame)
            base["incident"] = incident
            await ws.send_json(base)
    except WebSocketDisconnect:
        return
    except Exception as e:  # keep the connection resilient — surface once, then close
        try:
            await ws.send_json({"error": str(e)})
        finally:
            await ws.close()


# --------------------------------------------------------------------------
# PDF Export — one-pager incident report suitable for engineer handoff
# --------------------------------------------------------------------------

def _render_incident_pdf(doc: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=LETTER, leftMargin=0.55 * inch, rightMargin=0.55 * inch, topMargin=0.5 * inch, bottomMargin=0.5 * inch, title=doc.get("title", "CyberWorld AI Incident Report"))
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("t", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, spaceAfter=6, textColor=colors.HexColor("#0B1020"))
    sub_style = ParagraphStyle("s", parent=styles["Normal"], fontSize=8.5, textColor=colors.HexColor("#4A536B"), spaceAfter=6)
    h2_style = ParagraphStyle("h2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=10.5, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor("#0B1020"))
    body = ParagraphStyle("b", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#0B1020"))
    small = ParagraphStyle("sm", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=colors.HexColor("#4A536B"))

    story = []
    story.append(Paragraph("CyberWorld AI · Autonomous Containment Report", title_style))
    story.append(Paragraph(f"{doc.get('scenario_name', '')} — Report {doc.get('id', '')} · generated {doc.get('created_at', '')}", sub_style))

    ps = doc.get("primary_suspect") or {}
    life = doc.get("lifecycle") or {}
    story.append(Paragraph("Detection", h2_style))
    story.append(Paragraph(f"<b>Primary suspect:</b> {ps.get('label', 'n/a')} ({ps.get('id', 'n/a')} · {ps.get('tier', '—')})<br/><b>Detection confidence:</b> {(ps.get('confidence', 0) * 100):.0f}% (policy-derived)<br/><b>Detection frame:</b> F{doc.get('detection_frame', '?')}<br/><b>Verify end:</b> F{life.get('verify_end_frame', '?')} · <b>Cycles used:</b> {life.get('cycle', '?')}/{life.get('max_cycles', '?')}", body))

    counts = doc.get("affected_counts") or {}
    story.append(Paragraph("Automated Response Summary", h2_style))
    count_row = [["ISOLATE", "RESTRICT", "MONITOR", "PROTECT", "NO_ACTION"], [str(counts.get("ISOLATE", 0)), str(counts.get("RESTRICT", 0)), str(counts.get("MONITOR", 0)), str(counts.get("PROTECT", 0)), str(counts.get("NO_ACTION", 0))]]
    t = Table(count_row, colWidths=[1.35 * inch] * 5)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#101830")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00F0FF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2EA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.white]),
    ]))
    story.append(t)

    story.append(Paragraph("Potentially Affected Systems", h2_style))
    aff = doc.get("affected_systems") or []
    rows = [["Host", "Tier", "Risk", "Conf", "Action", "Reason"]]
    for h in aff[:16]:
        rows.append([h.get("label", ""), h.get("tier", ""), h.get("risk", ""), f"{h.get('confidence', 0) * 100:.0f}%", h.get("action", ""), (h.get("reason", "") or "")[:72]])
    ac_table = Table(rows, colWidths=[1.4 * inch, 0.95 * inch, 0.55 * inch, 0.5 * inch, 0.75 * inch, 2.7 * inch])
    ac_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1020")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DEE2EA")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(ac_table)

    snap = doc.get("snapshot") or {}
    rm = snap.get("response_metrics") or {}
    story.append(Paragraph("Before / After Response Metrics", h2_style))
    m_rows = [
        ["Peak risk at detection", f"{rm.get('peak_risk_at_detection', 0) * 100:.0f}%"],
        ["Peak risk at verify end", f"{rm.get('peak_risk_at_end', 0) * 100:.0f}%"],
        ["Risk reduction", f"{rm.get('risk_reduction_pct', 0):.1f}%"],
        ["Propagation stopped", "Yes" if rm.get("propagation_stopped") else "No"],
        ["Cycles used", str(rm.get("cycles_used", "—"))],
        ["Detection frame", f"F{rm.get('detection_frame', '?')}"],
        ["Verification end frame", f"F{rm.get('verification_end_frame', '?')}"],
    ]
    mt = Table(m_rows, colWidths=[2.5 * inch, 4.35 * inch])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DEE2EA")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(mt)

    story.append(Paragraph("MITRE ATT&CK — Observed", h2_style))
    mitre = (snap.get("mitre_active") or [])[:10]
    if mitre:
        m2 = [["ID", "Tactic", "Technique", "Conf"]] + [[m["id"], m["tactic"], m["name"], f"{m.get('conf', 0) * 100:.0f}%"] for m in mitre]
        mt2 = Table(m2, colWidths=[0.8 * inch, 1.3 * inch, 3.55 * inch, 0.7 * inch])
        mt2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1020")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#DEE2EA")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FB")]),
        ]))
        story.append(mt2)
    else:
        story.append(Paragraph("No techniques observed at report generation time.", small))

    story.append(Paragraph("Engineer Handoff — Investigate · Remediate · Recover", h2_style))
    story.append(Paragraph(doc.get("engineer_action_required", ""), body))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("Simulated lab actions — no real endpoints were disconnected. Threat confidence values are policy-derived, not a separately trained ML probability.", small))

    pdf.build(story)
    return buf.getvalue()


@app.get("/api/incidents/{incident_id}/pdf")
async def incident_pdf(incident_id: str) -> Response:
    doc = await db.incidents.find_one({"id": incident_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="incident not found")
    data = _render_incident_pdf(doc)
    safe_id = "".join(ch if ord(ch) < 128 else "_" for ch in incident_id)
    filename = f"{safe_id}.pdf"
    return Response(content=data, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{filename}"'})
