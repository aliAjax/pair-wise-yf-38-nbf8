from datetime import datetime, timedelta, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    return {"activated_by": actor.user_id}


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


EMERGENCY_OPEN_STATUSES = ("pending", "active", "expired")


def _validate_emergency_ticket(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")
    now = _utcnow()
    if str(data.get("expires_at")) <= now:
        raise ValidationError("expires_at must be in the future")
    if lookup is None:
        return
    dataset_id = data.get("dataset_id")
    applicant_id = data.get("applicant_id")
    for ticket in lookup("emergency_ticket", "incident_id", data.get("incident_id")) or []:
        if ticket["data"].get("dataset_id") == dataset_id and ticket["status"] in EMERGENCY_OPEN_STATUSES:
            raise ConflictError("an unfinished emergency ticket already exists for this incident and dataset")
    for grant in lookup("grant", "dataset_id", dataset_id) or []:
        if grant["status"] != "active":
            continue
        if grant["data"].get("recipient") != applicant_id:
            continue
        grant_expires = grant["data"].get("expires_at")
        if not grant_expires or valid_grant_window(grant_expires, now):
            raise ConflictError("applicant already holds a valid grant for this dataset")
    revoked_before = any(
        ticket["data"].get("dataset_id") == dataset_id and ticket["status"] == "revoked"
        for ticket in lookup("emergency_ticket", "applicant_id", applicant_id) or []
    )
    if revoked_before and not str(data.get("explanation") or "").strip():
        raise ValidationError("a previous revocation on this dataset requires an explanation")


def _validate_emergency_approve(actor, entity, data, lookup):
    if actor.user_id == entity["data"].get("applicant_id"):
        raise PermissionDenied("applicant cannot approve their own emergency ticket")
    now = _utcnow()
    if str(entity["data"].get("expires_at")) <= now:
        raise ValidationError("emergency ticket deadline has passed")
    return {"approved_by": actor.user_id, "approved_at": now}


def _validate_emergency_expire(actor, entity, data, lookup):
    expired_at = str(data.get("expired_at") or _utcnow())
    if expired_at < str(entity["data"].get("expires_at")):
        raise ValidationError("emergency ticket deadline has not been reached")
    return {"expired_at": expired_at}


def _validate_emergency_close(actor, entity, data, lookup):
    return {"reviewed_by": actor.user_id, "reviewed_at": _utcnow()}


def _validate_emergency_revoke(actor, entity, data, lookup):
    return {"revoked_by": actor.user_id, "revoked_at": _utcnow()}


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application, 'emergency_ticket': _validate_emergency_ticket}
CUSTOM_TRANSITIONS = {('application', 'approve'): _validate_approve, ('grant', 'activate'): _validate_grant_activate, ('emergency_ticket', 'approve'): _validate_emergency_approve, ('emergency_ticket', 'expire'): _validate_emergency_expire, ('emergency_ticket', 'close'): _validate_emergency_close, ('emergency_ticket', 'revoke'): _validate_emergency_revoke}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant', 'emergency_tickets': 'emergency_ticket'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued', 'emergency_ticket': 'pending'}
    TRANSITIONS = {'dataset': {'restrict': (('registered',), 'restricted'), 'publish': (('restricted',), 'published')}, 'application': {'submit': (('draft',), 'submitted'), 'review': (('submitted',), 'under_review'), 'approve': (('under_review',), 'approved'), 'reject': (('under_review',), 'rejected'), 'withdraw': (('submitted', 'under_review'), 'withdrawn')}, 'grant': {'activate': (('issued',), 'active'), 'revoke': (('active',), 'revoked'), 'expire': (('active',), 'expired')}, 'emergency_ticket': {'approve': (('pending',), 'active'), 'expire': (('pending', 'active'), 'expired'), 'close': (('active', 'expired'), 'closed'), 'revoke': (('active', 'expired'), 'revoked')}}
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient'), 'emergency_ticket': ('incident_id', 'dataset_id', 'applicant_id', 'purpose', 'expires_at')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',), ('emergency_ticket', 'revoke'): ('reason',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee'), 'emergency_ticket': ('admin', 'applicant')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee'), ('emergency_ticket', 'approve'): ('committee',), ('emergency_ticket', 'expire'): ('admin', 'committee', 'auditor'), ('emergency_ticket', 'close'): ('auditor',), ('emergency_ticket', 'revoke'): ('auditor',)}

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
