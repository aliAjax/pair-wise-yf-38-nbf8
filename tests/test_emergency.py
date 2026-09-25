import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService

FUTURE = "2099-01-01T00:00:00+00:00"
AFTER_DEADLINE = "2099-01-02T00:00:00+00:00"


class EmergencyTicketTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.applicant = Actor("researcher-1", "applicant")
        self.committee = Actor("committee-1", "committee")
        self.auditor = Actor("auditor-1", "auditor")
        self.dataset = self.service.create(
            self.admin, "dataset", {"name": "Cohort", "access_policy": "controlled"}
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _ticket_data(self, **overrides):
        data = {
            "incident_id": "INC-1",
            "dataset_id": self.dataset["id"],
            "applicant_id": "researcher-1",
            "purpose": "incident forensics",
            "expires_at": FUTURE,
        }
        data.update(overrides)
        return data

    def _create_ticket(self, **overrides):
        return self.service.create(
            self.applicant, "emergency_ticket", self._ticket_data(**overrides)
        )

    def _activate_ticket(self):
        ticket = self._create_ticket()
        return self.service.transition(self.committee, ticket["id"], "approve")

    def _expire_ticket(self, ticket):
        return self.service.transition(
            self.admin, ticket["id"], "expire", {"expired_at": AFTER_DEADLINE}
        )

    def _grant_active_grant(self, starts_at="2026-01-01", expires_at="2099-12-31"):
        grant = self.service.create(
            self.admin,
            "grant",
            {
                "application_id": "APP-9",
                "dataset_id": self.dataset["id"],
                "recipient": "researcher-1",
            },
        )
        return self.service.transition(
            self.admin,
            grant["id"],
            "activate",
            {"starts_at": starts_at, "expires_at": expires_at},
        )

    def test_full_lifecycle(self):
        ticket = self._create_ticket()
        self.assertEqual(ticket["status"], "pending")
        ticket = self.service.transition(self.committee, ticket["id"], "approve")
        self.assertEqual(ticket["status"], "active")
        self.assertEqual(ticket["data"]["approved_by"], "committee-1")
        ticket = self._expire_ticket(ticket)
        self.assertEqual(ticket["status"], "expired")
        ticket = self.service.transition(self.auditor, ticket["id"], "close")
        self.assertEqual(ticket["status"], "closed")
        self.assertEqual(ticket["data"]["reviewed_by"], "auditor-1")

    def test_committee_member_cannot_approve_own_ticket(self):
        ticket = self._create_ticket()
        self_service_committee_member = Actor("researcher-1", "committee")
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self_service_committee_member, ticket["id"], "approve"
            )

    def test_admin_cannot_approve(self):
        ticket = self._create_ticket()
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.admin, ticket["id"], "approve")

    def test_applicant_role_cannot_approve(self):
        ticket = self._create_ticket()
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.applicant, ticket["id"], "approve")

    def test_duplicate_open_ticket_rejected(self):
        self._create_ticket()
        with self.assertRaises(ConflictError):
            self._create_ticket()

    def test_other_incident_same_dataset_allowed(self):
        self._create_ticket()
        second = self._create_ticket(incident_id="INC-2")
        self.assertEqual(second["status"], "pending")

    def test_valid_grant_blocks_ticket(self):
        self._grant_active_grant()
        with self.assertRaises(ConflictError):
            self._create_ticket()

    def test_expired_grant_window_does_not_block(self):
        self._grant_active_grant(starts_at="2019-01-01", expires_at="2020-01-01")
        ticket = self._create_ticket()
        self.assertEqual(ticket["status"], "pending")

    def test_unreviewed_ticket_blocks_next_one(self):
        ticket = self._expire_ticket(self._activate_ticket())
        self.assertEqual(ticket["status"], "expired")
        with self.assertRaises(ConflictError):
            self._create_ticket()
        self.service.transition(self.auditor, ticket["id"], "close")
        follow_up = self._create_ticket()
        self.assertEqual(follow_up["status"], "pending")

    def test_revoke_requires_reason(self):
        ticket = self._expire_ticket(self._activate_ticket())
        with self.assertRaises(ValidationError):
            self.service.transition(self.auditor, ticket["id"], "revoke")
        ticket = self.service.transition(
            self.auditor, ticket["id"], "revoke", {"reason": "data used beyond incident scope"}
        )
        self.assertEqual(ticket["status"], "revoked")
        self.assertEqual(ticket["data"]["reason"], "data used beyond incident scope")
        self.assertEqual(ticket["data"]["revoked_by"], "auditor-1")

    def test_explanation_required_after_revocation(self):
        ticket = self._expire_ticket(self._activate_ticket())
        self.service.transition(
            self.auditor, ticket["id"], "revoke", {"reason": "scope creep"}
        )
        with self.assertRaises(ValidationError):
            self._create_ticket(incident_id="INC-2")
        follow_up = self._create_ticket(
            incident_id="INC-2", explanation="previous access was limited to logs only"
        )
        self.assertEqual(follow_up["status"], "pending")

    def test_expire_before_deadline_rejected(self):
        ticket = self._activate_ticket()
        with self.assertRaises(ValidationError):
            self.service.transition(
                self.admin, ticket["id"], "expire", {"expired_at": "2026-01-01"}
            )

    def test_non_auditor_cannot_review(self):
        ticket = self._expire_ticket(self._activate_ticket())
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.committee, ticket["id"], "close")
        with self.assertRaises(PermissionDenied):
            self.service.transition(
                self.committee, ticket["id"], "revoke", {"reason": "x"}
            )

    def test_viewer_cannot_create(self):
        with self.assertRaises(PermissionDenied):
            self.service.create(
                Actor("guest", "viewer"), "emergency_ticket", self._ticket_data()
            )

    def test_past_deadline_rejected_on_create(self):
        with self.assertRaises(ValidationError):
            self._create_ticket(expires_at="2020-01-01")

    def test_unknown_dataset_rejected(self):
        with self.assertRaises(ValidationError):
            self._create_ticket(dataset_id="missing-dataset")

    def test_approve_after_deadline_rejected(self):
        rules = RuleEngine()
        entity = {
            "kind": "emergency_ticket",
            "status": "pending",
            "data": {"applicant_id": "researcher-1", "expires_at": "2020-01-01"},
        }
        with self.assertRaises(ValidationError):
            rules.validate_transition(self.committee, entity, "approve", {})


if __name__ == "__main__":
    unittest.main()
