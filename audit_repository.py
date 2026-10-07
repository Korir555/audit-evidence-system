"""
Audit Evidence System

Automated evidence collection and audit documentation system.
Tracks evidence, findings, and remediation status.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict
import json
from pathlib import Path


class EvidenceType(Enum):
    POLICY = "Policy Documentation"
    ACCESS_LOG = "Access Control Log"
    ENCRYPTION = "Encryption Verification"
    INCIDENT = "Incident Record"
    TRAINING = "Training Record"
    VULNERABILITY = "Vulnerability Report"
    COMPLIANCE = "Compliance Confirmation"
    SYSTEM_LOG = "System Log"


class FindingStatus(Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


class ComplianceStatus(Enum):
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    PARTIAL = "Partial Compliance"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class Evidence:
    """Audit evidence item"""
    
    id: str
    evidence_type: EvidenceType
    requirement: str
    description: str
    file_path: str
    collected_date: datetime
    source: str  # System, manual, automated
    validity_period_months: int = 12
    
    def is_valid(self) -> bool:
        """Check if evidence is still valid"""
        months_old = (datetime.now() - self.collected_date).days // 30
        return months_old <= self.validity_period_months
    
    def to_dict(self):
        return {
            "id": self.id,
            "type": self.evidence_type.value,
            "requirement": self.requirement,
            "description": self.description,
            "file_path": self.file_path,
            "collected_date": self.collected_date.isoformat(),
            "source": self.source,
            "valid": self.is_valid()
        }


@dataclass
class Finding:
    """Audit finding"""
    
    id: str
    requirement: str
    status: FindingStatus
    compliance_status: ComplianceStatus
    description: str
    severity: str  # Critical, High, Medium, Low
    owner: str
    due_date: datetime
    evidence_ids: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    created_date: datetime = field(default_factory=datetime.now)
    closed_date: datetime = None
    
    def to_dict(self):
        return {
            "id": self.id,
            "requirement": self.requirement,
            "status": self.status.value,
            "compliance": self.compliance_status.value,
            "severity": self.severity,
            "owner": self.owner,
            "due_date": self.due_date.isoformat(),
            "evidence_count": len(self.evidence_ids),
            "remediation_steps": self.remediation_steps
        }


class AuditRepository:
    """Centralized audit evidence repository"""
    
    def __init__(self):
        self.evidence_items: Dict[str, Evidence] = {}
        self.findings: Dict[str, Finding] = {}
        self.audit_sessions: List[Dict] = []
    
    def add_evidence(self, evidence: Evidence) -> str:
        """Add evidence to repository"""
        self.evidence_items[evidence.id] = evidence
        return evidence.id
    
    def add_finding(self, finding: Finding) -> str:
        """Add audit finding"""
        self.findings[finding.id] = finding
        return finding.id
    
    def get_evidence_by_type(self, evidence_type: EvidenceType) -> List[Evidence]:
        """Get all evidence of specific type"""
        return [e for e in self.evidence_items.values() 
                if e.evidence_type == evidence_type]
    
    def get_evidence_by_requirement(self, requirement: str) -> List[Evidence]:
        """Get evidence for specific requirement"""
        return [e for e in self.evidence_items.values() 
                if e.requirement == requirement]
    
    def get_valid_evidence(self) -> List[Evidence]:
        """Get all currently valid evidence"""
        return [e for e in self.evidence_items.values() if e.is_valid()]
    
    def get_expired_evidence(self) -> List[Evidence]:
        """Get expired evidence that needs renewal"""
        return [e for e in self.evidence_items.values() if not e.is_valid()]
    
    def get_open_findings(self) -> List[Finding]:
        """Get all open audit findings"""
        return [f for f in self.findings.values() 
                if f.status != FindingStatus.CLOSED]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get critical findings"""
        return [f for f in self.findings.values() 
                if f.severity == "Critical"]
    
    def close_finding(self, finding_id: str):
        """Close audit finding"""
        if finding_id in self.findings:
            self.findings[finding_id].status = FindingStatus.CLOSED
            self.findings[finding_id].closed_date = datetime.now()
    
    def generate_audit_report(self) -> Dict:
        """Generate audit summary report"""
        total_evidence = len(self.evidence_items)
        valid_evidence = len(self.get_valid_evidence())
        expired_evidence = len(self.get_expired_evidence())
        
        total_findings = len(self.findings)
        open_findings = len(self.get_open_findings())
        critical_findings = len(self.get_critical_findings())
        
        return {
            "generated": datetime.now().isoformat(),
            "evidence": {
                "total": total_evidence,
                "valid": valid_evidence,
                "expired": expired_evidence
            },
            "findings": {
                "total": total_findings,
                "open": open_findings,
                "critical": critical_findings,
                "closed": total_findings - open_findings
            },
            "compliance_status": self._calculate_compliance()
        }
    
    def _calculate_compliance(self) -> str:
        """Calculate overall compliance status"""
        if not self.findings:
            return "Unknown"
        
        non_compliant = sum(1 for f in self.findings.values() 
                           if f.compliance_status == ComplianceStatus.NON_COMPLIANT)
        
        if non_compliant == 0:
            return "Compliant"
        elif non_compliant <= len(self.findings) * 0.2:
            return "Partial Compliance"
        else:
            return "Non-Compliant"
    
    def export_to_json(self, filename: str = "audit_report.json"):
        """Export audit repository to JSON"""
        data = {
            "generated": datetime.now().isoformat(),
            "evidence": [e.to_dict() for e in self.evidence_items.values()],
            "findings": [f.to_dict() for f in self.findings.values()],
            "summary": self.generate_audit_report()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename


# Example usage
if __name__ == "__main__":
    repo = AuditRepository()
    
    # Add sample evidence
    evidence1 = Evidence(
        id="EVD-001",
        evidence_type=EvidenceType.POLICY,
        requirement="Data Protection Policy Required",
        description="Information Security Policy signed by leadership",
        file_path="/evidence/policies/information_security_policy.pdf",
        collected_date=datetime.now(),
        source="Manual"
    )
    
    evidence2 = Evidence(
        id="EVD-002",
        evidence_type=EvidenceType.ACCESS_LOG,
        requirement="Access Control Review",
        description="User access review for Q4 2026",
        file_path="/evidence/access_logs/q4_2026_review.xlsx",
        collected_date=datetime.now(),
        source="Automated"
    )
    
    repo.add_evidence(evidence1)
    repo.add_evidence(evidence2)
    
    # Add sample finding
    finding1 = Finding(
        id="FIND-001",
        requirement="Multi-factor authentication",
        status=FindingStatus.IN_PROGRESS,
        compliance_status=ComplianceStatus.PARTIAL,
        description="MFA enabled for 85% of users",
        severity="High",
        owner="IT Security",
        due_date=datetime(2026, 11, 1),
        remediation_steps=["Enable MFA for remaining users", "Monitor enrollment"]
    )
    
    repo.add_finding(finding1)
    
    # Generate report
    report = repo.generate_audit_report()
    print("Audit Report Generated:")
    print(json.dumps(report, indent=2))
    
    # Export
    repo.export_to_json()
    print("\nExported to audit_report.json")
