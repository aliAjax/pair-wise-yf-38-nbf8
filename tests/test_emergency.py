import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src.domain import (
    Actor,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine, current_time
from src.service import DomainService


def _iso(dt):
    return dt.isoformat(timespec="seconds")


class EmergencyAccessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.applicant = Actor("alice", "applicant")
        self.committee = Actor("carl", "committee")
        self.other_committee = Actor("cara", "committee")
        self.auditor = Actor("amy", "auditor")
        self.admin = Actor("root", "admin")
        self.dataset = self.service.create(
            self.admin, "dataset",
            {"name": "Incident Genome Set", "access_policy": "controlled"},
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _ticket_data(self, incident="INC-1", expires_delta=None, **extra):
        if expires_delta is None:
            expires_delta = timedelta(hours=4)
        data = {
            "incident_id": incident,
            "dataset_id": self.dataset["id"],
            "purpose": "事故 INC-1 泄露面排查",
            "expires_at": _iso(current_time() + expires_delta),
        }
        data.update(extra)
        return data

    def _create_ticket(self, actor=None, **extra):
        return self.service.create(
            actor or self.applicant, "emergency_access", self._ticket_data(**extra)
        )

    def test_full_emergency_lifecycle(self):
        ticket = self._create_ticket()
        self.assertEqual(ticket["status"], "pending")
        self.assertEqual(ticket["data"]["applicant_id"], "alice")
        self.assertGreater(ticket["data"]["remaining_seconds"], 3 * 3600)
        self.assertFalse(ticket["data"]["expired"])

        approved = self.service.transition(
            self.committee, ticket["id"], "approve", {}
        )
        self.assertEqual(approved["status"], "active")
        self.assertEqual(approved["data"]["approved_by"], "carl")

        with patch("src.rules.current_time") as later:
            later.return_value = current_time() + timedelta(hours=5)
            self.assertEqual(self.service.get(ticket["id"])["status"], "expired")
        reviewed = self.service.transition(
            self.auditor, ticket["id"], "review",
            {"finding": "compliant", "note": "用途与事故排查一致"},
        )
        self.assertEqual(reviewed["status"], "reviewed")
        self.assertTrue(reviewed["data"]["finished"])

    def test_applicant_cannot_self_approve(self):
        ticket = self._create_ticket()
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.applicant, ticket["id"], "approve", {})

    def test_any_single_committee_member_can_approve(self):
        ticket = self._create_ticket()
        approved = self.service.transition(
            self.other_committee, ticket["id"], "approve", {}
        )
        self.assertEqual(approved["status"], "active")

    def test_auditor_cannot_approve(self):
        ticket = self._create_ticket()
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.auditor, ticket["id"], "approve", {})

    def test_duplicate_open_ticket_same_incident_rejected(self):
        self._create_ticket()
        with self.assertRaises(ValidationError):
            self._create_ticket()

    def test_other_incident_blocked_while_ticket_unreviewed(self):
        self._create_ticket(incident="INC-1")
        with self.assertRaises(ValidationError):
            self._create_ticket(incident="INC-2")

    def test_new_ticket_allowed_after_review_closed(self):
        ticket = self._create_ticket()
        self.service.transition(self.committee, ticket["id"], "approve", {})
        with patch("src.rules.current_time") as later:
            later.return_value = current_time() + timedelta(hours=5)
            self.assertEqual(self.service.get(ticket["id"])["status"], "expired")
        self.service.transition(
            self.auditor, ticket["id"], "review", {"finding": "compliant"}
        )
        followup = self._create_ticket(incident="INC-2")
        self.assertEqual(followup["status"], "pending")

    def test_valid_ordinary_grant_blocks_emergency(self):
        application = self.service.create(
            self.admin, "application",
            {"dataset_id": self.dataset["id"], "applicant_id": "bob",
             "purpose": "research"},
        )
        self.service.transition(application["created_by"] and self.admin,
                                application["id"], "submit", {})
        self.service.transition(
            self.admin, application["id"], "review", {"committee_id": "carl"}
        )
        self.service.transition(
            self.admin, application["id"], "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "noncommercial",
             "expires_at": _iso(current_time() + timedelta(days=2))},
        )
        grant = self.service.create(
            self.admin, "grant",
            {"application_id": application["id"],
             "dataset_id": self.dataset["id"], "recipient": "bob"},
        )
        self.service.transition(
            self.admin, grant["id"], "activate",
            {"starts_at": _iso(current_time() - timedelta(days=1)),
             "expires_at": _iso(current_time() + timedelta(days=1))},
        )
        with self.assertRaises(ValidationError):
            self._create_ticket()

    def test_expired_ordinary_grant_does_not_block(self):
        application = self.service.create(
            self.admin, "application",
            {"dataset_id": self.dataset["id"], "applicant_id": "bob",
             "purpose": "research"},
        )
        self.service.transition(self.admin, application["id"], "submit", {})
        self.service.transition(
            self.admin, application["id"], "review", {"committee_id": "carl"}
        )
        self.service.transition(
            self.admin, application["id"], "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "x",
             "expires_at": "2026-01-01"},
        )
        grant = self.service.create(
            self.admin, "grant",
            {"application_id": application["id"],
             "dataset_id": self.dataset["id"], "recipient": "bob"},
        )
        self.service.transition(
            self.admin, grant["id"], "activate",
            {"starts_at": "2025-01-01", "expires_at": "2026-01-01"},
        )
        ticket = self._create_ticket()
        self.assertEqual(ticket["status"], "pending")

    def test_approve_after_deadline_rejected_and_auto_expired(self):
        ticket = self._create_ticket(expires_delta=timedelta(hours=1))
        fake_now = current_time() + timedelta(hours=2)
        with patch("src.rules.current_time", return_value=fake_now):
            fetched = self.service.get(ticket["id"])
            self.assertEqual(fetched["status"], "expired")
            self.assertEqual(fetched["data"]["remaining_seconds"], 0)
            with self.assertRaises(InvalidTransition):
                self.service.transition(self.committee, ticket["id"], "approve", {})

    def test_pending_ticket_auto_expires_past_deadline(self):
        ticket = self._create_ticket(expires_delta=timedelta(hours=1))
        fake_now = current_time() + timedelta(hours=2)
        with patch("src.rules.current_time", return_value=fake_now):
            items = self.service.list("emergency_access")
        self.assertEqual(items[0]["status"], "expired")

    def test_unauthorized_review_revokes_and_records_reason(self):
        ticket = self._create_ticket()
        self.service.transition(self.committee, ticket["id"], "approve", {})
        with patch("src.rules.current_time") as later:
            later.return_value = current_time() + timedelta(hours=5)
            self.service.get(ticket["id"])
            with self.assertRaises(ValidationError):
                self.service.transition(
                    self.auditor, ticket["id"], "review",
                    {"finding": "unauthorized"},
                )
        revoked = self.service.transition(
            self.auditor, ticket["id"], "review",
            {"finding": "unauthorized", "reason": "访问范围超出事故排查目的"},
        )
        self.assertEqual(revoked["status"], "revoked")
        self.assertEqual(
            revoked["data"]["reason"], "访问范围超出事故排查目的"
        )
        self.assertTrue(revoked["data"]["finished"])

    def test_remediation_note_required_after_revocation(self):
        ticket = self._create_ticket()
        self.service.transition(self.committee, ticket["id"], "approve", {})
        with patch("src.rules.current_time") as later:
            later.return_value = current_time() + timedelta(hours=5)
            self.service.get(ticket["id"])
        self.service.transition(
            self.auditor, ticket["id"], "review",
            {"finding": "unauthorized", "reason": "越权下载"},
        )
        with self.assertRaises(ValidationError):
            self._create_ticket(incident="INC-9")
        followup = self._create_ticket(
            incident="INC-9", remediation_note="已补充越权原因与整改措施"
        )
        self.assertEqual(followup["status"], "pending")

    def test_reviewer_other_than_auditor_denied(self):
        ticket = self._create_ticket()
        self.service.transition(self.committee, ticket["id"], "approve", {})
        with patch("src.rules.current_time") as later:
            later.return_value = current_time() + timedelta(hours=5)
            self.service.get(ticket["id"])
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.committee, ticket["id"], "review", {"finding": "compliant"}
            )

    def test_required_fields_on_create(self):
        with self.assertRaises(ValidationError):
            self.service.create(
                self.applicant, "emergency_access",
                {"dataset_id": self.dataset["id"], "purpose": "x"},
            )

    def test_past_deadline_create_rejected(self):
        with self.assertRaises(ValidationError):
            self._create_ticket(expires_delta=timedelta(hours=-1))


if __name__ == "__main__":
    unittest.main()
