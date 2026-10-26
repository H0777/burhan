"""
Insider Threat Behavioral Analyzer
Cyber-Forensic Auditing Framework
Integrating Digital Forensics and Financial Accounting

Evaluates operator actions recorded on the blockchain (InsiderActivityLog),
detecting privilege abuse, collusion with beneficiaries, and unauthorized overrides.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class OperatorActivityMetrics:
    operator_address: str
    total_actions: int
    override_count: int
    after_hours_count: int
    flag_count: int
    max_beneficiary_approvals: int
    rapid_approval_count: int = 0      # Approvals made in < 5 seconds
    reversed_decisions_count: int = 0  # Blocked then immediately overridden
    override_threshold: int = 5
    after_hours_threshold: int = 3
    beneficiary_threshold: int = 10


class InsiderThreatAnalyzer:
    """
    Analyzes authorized operator behaviors to detect insider threats:
    - Privilege abuse (excessive manual overrides)
    - Off-hours unauthorized access
    - Collusion with specific beneficiaries (conflict of interest)
    - Rubber-stamping without due review
    """

    def analyze(self, metrics: OperatorActivityMetrics) -> Dict[str, Any]:
        threat_score = 0.0
        indicators: List[Dict[str, Any]] = []

        # 1. Excessive Warning Overrides
        if metrics.override_count > 0:
            override_ratio = metrics.override_count / max(metrics.total_actions, 1)
            if metrics.override_count >= metrics.override_threshold:
                score_impact = min(35.0 + (metrics.override_count - metrics.override_threshold) * 5.0, 50.0)
                threat_score += score_impact
                indicators.append({
                    "indicator": "EXCESSIVE_COMPLIANCE_OVERRIDES",
                    "severity": "CRITICAL" if metrics.override_count > metrics.override_threshold * 2 else "HIGH",
                    "impact": round(score_impact, 1),
                    "description": (
                        f"Operator bypassed {metrics.override_count} compliance warnings "
                        f"(Threshold: {metrics.override_threshold}). Override ratio is {override_ratio * 100:.1f}%."
                    )
                })
            elif metrics.override_count >= 3:
                score_impact = 15.0
                threat_score += score_impact
                indicators.append({
                    "indicator": "ELEVATED_OVERRIDE_FREQUENCY",
                    "severity": "MEDIUM",
                    "impact": score_impact,
                    "description": f"Operator has {metrics.override_count} overrides recorded."
                })

        # 2. Repeated Approvals for Same Beneficiary (Collusion / Conflict of Interest)
        if metrics.max_beneficiary_approvals >= metrics.beneficiary_threshold:
            score_impact = min(30.0 + (metrics.max_beneficiary_approvals - metrics.beneficiary_threshold) * 3.0, 45.0)
            threat_score += score_impact
            indicators.append({
                "indicator": "BENEFICIARY_COLLUSION_SUSPICION",
                "severity": "CRITICAL",
                "impact": round(score_impact, 1),
                "description": (
                    f"Operator repeatedly authorized transfers to the same beneficiary "
                    f"({metrics.max_beneficiary_approvals} times, Threshold: {metrics.beneficiary_threshold})."
                )
            })
        elif metrics.max_beneficiary_approvals >= 5:
            score_impact = 15.0
            threat_score += score_impact
            indicators.append({
                "indicator": "BENEFICIARY_CONCENTRATION_WARNING",
                "severity": "MEDIUM",
                "impact": score_impact,
                "description": f"Concentrated approvals for a single beneficiary ({metrics.max_beneficiary_approvals} times)."
            })

        # 3. Operations Outside Business Hours
        if metrics.after_hours_count >= metrics.after_hours_threshold:
            score_impact = min(25.0 + (metrics.after_hours_count - metrics.after_hours_threshold) * 4.0, 35.0)
            threat_score += score_impact
            indicators.append({
                "indicator": "HABITUAL_AFTER_HOURS_ACTIVITY",
                "severity": "HIGH",
                "impact": round(score_impact, 1),
                "description": (
                    f"Operator conducted {metrics.after_hours_count} sensitive operations "
                    f"outside business hours (Threshold: {metrics.after_hours_threshold})."
                )
            })
        elif metrics.after_hours_count > 0:
            score_impact = 10.0
            threat_score += score_impact
            indicators.append({
                "indicator": "OCCASIONAL_OFF_HOURS_ACCESS",
                "severity": "LOW",
                "impact": score_impact,
                "description": f"Detected {metrics.after_hours_count} action(s) outside normal working hours."
            })

        # 4. Rubber-Stamping (Fast approvals without due diligence)
        if metrics.rapid_approval_count >= 3:
            score_impact = 20.0
            threat_score += score_impact
            indicators.append({
                "indicator": "RUBBER_STAMPING_APPROVALS",
                "severity": "MEDIUM",
                "impact": score_impact,
                "description": f"Operator cleared {metrics.rapid_approval_count} flagged items in under 5 seconds each."
            })

        # 5. Flip-Flopping Decisions (Block followed by immediate unblock/override)
        if metrics.reversed_decisions_count > 0:
            score_impact = min(15.0 * metrics.reversed_decisions_count, 30.0)
            threat_score += score_impact
            indicators.append({
                "indicator": "DECISION_REVERSAL_ANOMALY",
                "severity": "HIGH",
                "impact": score_impact,
                "description": f"Operator reversed {metrics.reversed_decisions_count} transaction block/clear decisions."
            })

        # Incorporate on-chain contract flags
        if metrics.flag_count > 0:
            score_impact = min(metrics.flag_count * 15.0, 30.0)
            threat_score += score_impact
            indicators.append({
                "indicator": "ON_CHAIN_FLAG_ACCUMULATION",
                "severity": "HIGH",
                "impact": score_impact,
                "description": f"Operator has been flagged by smart contract auto-detection {metrics.flag_count} time(s)."
            })

        # Normalize score
        final_score = min(max(round(threat_score, 1), 0.0), 100.0)

        # Classify threat level
        if final_score >= 70.0:
            threat_level = "CRITICAL"
            recommended_action = "REVOKE_ROLES_AND_QUARANTINE"
        elif final_score >= 45.0:
            threat_level = "HIGH"
            recommended_action = "MANDATE_MULTISIG_FOUR_EYES"
        elif final_score >= 20.0:
            threat_level = "MEDIUM"
            recommended_action = "SUPERVISORY_AUDIT_REVIEW"
        else:
            threat_level = "LOW"
            recommended_action = "NORMAL_MONITORING"

        return {
            "operator_address": metrics.operator_address,
            "insider_threat_score": final_score,
            "threat_level": threat_level,
            "recommended_action": recommended_action,
            "indicators": indicators,
            "total_actions_evaluated": metrics.total_actions
        }
