from datetime import datetime, timedelta, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


# 紧急访问单的终态：事后复核完成、认定越权撤销、拒绝。
# 未进入终态的单子都算“未结束”。
EMERGENCY_FINISHED = frozenset({"reviewed", "revoked", "rejected"})
EMERGENCY_OPEN = ("pending", "active", "expired")


def current_time():
    return datetime.now(timezone.utc)


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")
    if _has_unauthorized_history(data.get("dataset_id"), lookup):
        if not str(data.get("remediation_note", "")).strip():
            raise ValidationError(
                "dataset has an unauthorized emergency access record; "
                "remediation_note is required"
            )


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


def _parse_datetime(value):
    if value is None or str(value).strip() == "":
        raise ValidationError("expires_at is required")
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValidationError("expires_at must be an ISO 8601 date or datetime")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def is_past_deadline(expires_at, as_of):
    return _parse_datetime(expires_at) <= as_of


def remaining_seconds(expires_at, as_of):
    return max(0, int((_parse_datetime(expires_at) - as_of).total_seconds()))


def _has_valid_ordinary_grant(dataset_id, lookup, as_of):
    """普通凭证（grant）仍在有效期内时，不受理紧急访问单。"""
    for grant in lookup("grant", "dataset_id", dataset_id) or []:
        if grant["status"] != "active":
            continue
        expires_at = grant["data"].get("expires_at")
        if not expires_at or not is_past_deadline(expires_at, as_of):
            return True
    return False


def _has_unauthorized_history(dataset_id, lookup):
    """该数据集是否曾有紧急访问被认定越权。"""
    for ticket in lookup("emergency_access", "dataset_id", dataset_id) or []:
        if ticket["status"] == "revoked":
            return True
    return False


def _validate_emergency_access(actor, data, lookup):
    dataset_id = data.get("dataset_id")
    if not _find_one(lookup, "dataset", "id", dataset_id):
        raise ValidationError("dataset does not exist")
    if not str(data.get("incident_id", "")).strip():
        raise ValidationError("incident_id is required")
    if not str(data.get("purpose", "")).strip():
        raise ValidationError("purpose is required")
    as_of = current_time()
    deadline = _parse_datetime(data.get("expires_at"))
    if deadline <= as_of:
        raise ValidationError("expires_at must be a future deadline")
    if _has_valid_ordinary_grant(dataset_id, lookup, as_of):
        raise ValidationError(
            "dataset already has a valid ordinary grant; emergency access is not accepted"
        )
    open_tickets = [
        ticket
        for ticket in (lookup("emergency_access", "dataset_id", dataset_id) or [])
        if ticket["status"] not in EMERGENCY_FINISHED
    ]
    if open_tickets:
        same_incident = any(
            str(ticket["data"].get("incident_id")) == str(data.get("incident_id"))
            for ticket in open_tickets
        )
        if same_incident:
            raise ValidationError(
                "同一事故在同一数据集只能保留一张未结束的紧急访问单"
            )
        raise ValidationError("前一张紧急访问单尚未完成事后复核，暂不受理")
    if _has_unauthorized_history(dataset_id, lookup):
        if not str(data.get("remediation_note", "")).strip():
            raise ValidationError(
                "该数据集曾被认定越权，再次申请必须填写 remediation_note 补充说明"
            )
    # 申请人以请求身份为准，防止冒填。
    data["applicant_id"] = actor.user_id


def _validate_emergency_approve(actor, entity, data, lookup):
    # 委员会任一人可批准，但申请人不能自批。
    applicant = entity["data"].get("applicant_id") or entity.get("created_by")
    if actor.user_id and actor.user_id == applicant:
        raise PermissionDenied("申请人不能批准自己的紧急访问单")
    if is_past_deadline(entity["data"].get("expires_at"), current_time()):
        raise InvalidTransition("已过截止时间，紧急访问单已失效，无法批准")
    return {
        "approved_by": actor.user_id,
        "approved_at": current_time().isoformat(timespec="seconds"),
    }


def _validate_emergency_reject(actor, entity, data, lookup):
    return {
        "rejected_by": actor.user_id,
        "rejected_at": current_time().isoformat(timespec="seconds"),
    }


def _validate_emergency_expire(actor, entity, data, lookup):
    if not is_past_deadline(entity["data"].get("expires_at"), current_time()):
        raise InvalidTransition("截止时间未到，紧急访问单仍然有效")
    return {"expired_by": actor.user_id}


def _validate_emergency_review(actor, entity, data, lookup):
    finding = data.get("finding")
    if finding not in ("compliant", "unauthorized"):
        raise ValidationError("finding must be 'compliant' or 'unauthorized'")
    if finding == "unauthorized" and not str(data.get("reason", "")).strip():
        raise ValidationError("认定越权时必须填写撤销原因 reason")
    # 认定越权即撤销凭证，否则正常结案。
    next_status = "revoked" if finding == "unauthorized" else "reviewed"
    extra = {
        "reviewed_by": actor.user_id,
        "reviewed_at": current_time().isoformat(timespec="seconds"),
    }
    return next_status, extra


CUSTOM_CREATE = {
    'dataset': _validate_dataset,
    'application': _validate_application,
    'emergency_access': _validate_emergency_access,
}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('grant', 'activate'): _validate_grant_activate,
    ('emergency_access', 'approve'): _validate_emergency_approve,
    ('emergency_access', 'reject'): _validate_emergency_reject,
    ('emergency_access', 'expire'): _validate_emergency_expire,
    ('emergency_access', 'review'): _validate_emergency_review,
}


class RuleEngine:
    ALIASES = {
        'datasets': 'dataset',
        'applications': 'application',
        'grants': 'grant',
        'emergencies': 'emergency_access',
        'emergency_accesses': 'emergency_access',
    }
    EMERGENCY_FINISHED = EMERGENCY_FINISHED
    INITIAL_STATUS = {
        'dataset': 'registered',
        'application': 'draft',
        'grant': 'issued',
        'emergency_access': 'pending',
    }
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered',), 'restricted'),
            'publish': (('restricted',), 'published'),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review'), 'withdrawn'),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'revoke': (('active',), 'revoked'),
            'expire': (('active',), 'expired'),
        },
        'emergency_access': {
            'approve': (('pending',), 'active'),
            'reject': (('pending',), 'rejected'),
            'expire': (('pending', 'active'), 'expired'),
            # review 的终态由复核结论决定：reviewed 或 revoked。
            'review': (('expired',), 'reviewed'),
        },
    }
    CREATE_REQUIRED = {
        'dataset': ('name', 'access_policy'),
        'application': ('dataset_id', 'applicant_id', 'purpose'),
        'grant': ('application_id', 'dataset_id', 'recipient'),
        'emergency_access': ('incident_id', 'dataset_id', 'purpose', 'expires_at'),
    }
    ACTION_REQUIRED = {
        ('dataset', 'restrict'): ('reason',),
        ('application', 'review'): ('committee_id',),
        ('application', 'approve'): ('approvals', 'terms', 'expires_at'),
        ('application', 'reject'): ('reason',),
        ('application', 'withdraw'): ('reason',),
        ('grant', 'activate'): ('starts_at', 'expires_at'),
        ('grant', 'revoke'): ('reason',),
        ('grant', 'expire'): ('expired_at',),
        ('emergency_access', 'reject'): ('reason',),
        ('emergency_access', 'review'): ('finding',),
    }
    CREATE_ROLES = {
        'dataset': ('admin', 'committee'),
        'application': ('admin', 'applicant'),
        'grant': ('admin', 'committee'),
        'emergency_access': ('admin', 'applicant'),
    }
    ROLE_ACTIONS = {
        'restrict': ('admin', 'committee'),
        'publish': ('admin', 'committee'),
        'submit': ('admin', 'applicant'),
        'review': ('admin', 'committee'),
        'approve': ('admin', 'committee'),
        'reject': ('admin', 'committee'),
        'withdraw': ('admin', 'applicant'),
        'activate': ('admin', 'committee'),
        'revoke': ('admin', 'committee'),
        'expire': ('admin', 'committee'),
        ('emergency_access', 'approve'): ('admin', 'committee'),
        ('emergency_access', 'reject'): ('admin', 'committee'),
        ('emergency_access', 'expire'): ('admin', 'committee', 'auditor'),
        ('emergency_access', 'review'): ('admin', 'auditor'),
    }

    def now(self):
        return current_time()

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
        result = custom(actor, entity, data, lookup) if custom else {}
        # 自定义校验可以返回 patch 字典，或 (下一状态, patch) 元组。
        if isinstance(result, tuple):
            override_status, extra = result
        else:
            override_status, extra = None, result
        patch = dict(data)
        if extra:
            patch.update(extra)
        return override_status or next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
