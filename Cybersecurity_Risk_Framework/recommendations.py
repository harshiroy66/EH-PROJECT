"""
Module 3: Decision Support and Security Recommendations Engine.
Generates rule-based actionable security recommendations and remediation
strategies based on calculated risk scores, risk classifications, and asset types.
"""

from typing import List, Dict, Any


def generate_recommendations(risk_score: float, risk_level: str, asset_type: str = "Server") -> List[Dict[str, str]]:
    """
    Generate actionable security recommendations according to official project rules:
    - LOW RISK: Routine monitoring, regular updates, periodic review.
    - MEDIUM RISK: Apply patches, review permissions, improve configurations.
    - HIGH RISK: Prioritize remediation, apply patches promptly, review network & auth, increase monitoring.
    - CRITICAL RISK: Escalate to security admin, immediate remediation, isolate affected assets, detailed investigation.
    """
    recs: List[Dict[str, str]] = []

    if risk_level == "Critical":
        recs.append({
            "text": "Escalate the issue to the security administrator immediately.",
            "priority": "Critical",
            "timeframe": "Immediate (within 1 hour)",
            "action": "Notify Incident Response Team and CISO office."
        })
        recs.append({
            "text": "Prioritize immediate remediation and emergency vulnerability patching.",
            "priority": "Critical",
            "timeframe": "Within 4 hours",
            "action": "Obtain emergency change approval and deploy security mitigations."
        })
        recs.append({
            "text": "Isolate affected assets from the production network when appropriate and authorized.",
            "priority": "Critical",
            "timeframe": "Immediate",
            "action": "Apply firewall quarantine VLAN or disable compromised external listening ports."
        })
        recs.append({
            "text": "Perform a detailed security investigation and forensic traffic analysis.",
            "priority": "High",
            "timeframe": "Within 24 hours",
            "action": "Inspect SIEM event telemetry, endpoint detection logs, and active connections."
        })

    elif risk_level == "High":
        recs.append({
            "text": "Prioritize vulnerability remediation across all exposed endpoints.",
            "priority": "High",
            "timeframe": "Within 24-48 hours",
            "action": "Assign remediation ticket to specialized infrastructure team."
        })
        recs.append({
            "text": "Apply security patches promptly after testing in staging environment.",
            "priority": "High",
            "timeframe": "Within 48 hours",
            "action": "Deploy vendor security hotfixes and restart vulnerable daemon services."
        })
        recs.append({
            "text": "Review network access controls, port forwardings, and authentication mechanisms.",
            "priority": "High",
            "timeframe": "Within 3 days",
            "action": "Enforce Multi-Factor Authentication (MFA) and restrict ACLs to trusted IP subnets."
        })
        recs.append({
            "text": "Increase monitoring frequency and enable verbose diagnostic telemetry.",
            "priority": "Medium",
            "timeframe": "Ongoing",
            "action": "Tune IDS/IPS alerts and increase audit log retention frequency."
        })

    elif risk_level == "Medium":
        recs.append({
            "text": "Apply recommended security patches during the next maintenance window.",
            "priority": "Medium",
            "timeframe": "Within 7-14 days",
            "action": "Stage and schedule operating system and application package updates."
        })
        recs.append({
            "text": "Review access permissions and enforce the Principle of Least Privilege.",
            "priority": "Medium",
            "timeframe": "Within 10 days",
            "action": "Audit Active Directory/IAM role grants and remove unused administrative accounts."
        })
        recs.append({
            "text": "Improve security configurations against CIS Benchmarks.",
            "priority": "Low",
            "timeframe": "Within 14 days",
            "action": "Harden service configuration files, disable legacy TLS, and restrict unneeded services."
        })

    else:  # Low Risk
        recs.append({
            "text": "Continue routine security monitoring and baseline health checks.",
            "priority": "Low",
            "timeframe": "Routine",
            "action": "Maintain existing SIEM ingestion and weekly log review routines."
        })
        recs.append({
            "text": "Maintain regular security updates and software patch cycles.",
            "priority": "Low",
            "timeframe": "Monthly",
            "action": "Apply standard monthly security rollups."
        })
        recs.append({
            "text": "Review configurations periodically to ensure compliance posture.",
            "priority": "Low",
            "timeframe": "Quarterly",
            "action": "Conduct recurring quarterly compliance assessments and port scans."
        })

    # Asset-type specific guidance
    asset_specific = get_asset_type_guidance(asset_type, risk_level)
    if asset_specific:
        recs.append(asset_specific)

    return recs


def get_asset_type_guidance(asset_type: str, risk_level: str) -> Dict[str, str]:
    """
    Returns asset-specific defensive architecture guidance.
    """
    type_guidance = {
        "Database": {
            "text": "Verify database encryption at rest (AES-256) and enforce parameterized query layers.",
            "priority": "High" if risk_level in ("Critical", "High") else "Medium",
            "timeframe": "Within 7 days",
            "action": "Rotate database service credentials and restrict direct listener port exposure."
        },
        "Server": {
            "text": "Harden host OS kernel parameters, disable unused background daemons, and verify host firewall.",
            "priority": "High" if risk_level in ("Critical", "High") else "Low",
            "timeframe": "Within 7 days",
            "action": "Run CIS-CAT benchmark scan and verify SELinux/AppArmor enforcement."
        },
        "Network": {
            "text": "Audit access control lists (ACLs), verify VLAN segmentation, and inspect VPN gateways.",
            "priority": "High" if risk_level in ("Critical", "High") else "Medium",
            "timeframe": "Within 5 days",
            "action": "Update switch/router firmware to latest vendor release and enforce SNMPv3."
        },
        "Application": {
            "text": "Perform static/dynamic application security testing (SAST/DAST) and deploy WAF rules.",
            "priority": "High" if risk_level in ("Critical", "High") else "Medium",
            "timeframe": "Within 7 days",
            "action": "Validate OWASP Top-10 controls and implement Content Security Policy headers."
        },
        "Computer": {
            "text": "Ensure Endpoint Detection and Response (EDR) agent is active with full disk encryption (BitLocker).",
            "priority": "Medium",
            "timeframe": "Within 7 days",
            "action": "Verify antivirus signatures and block unauthorized USB storage media."
        }
    }
    return type_guidance.get(asset_type)
