from uuid import uuid4

from .audit import AuditTrail
from .domain import Actor, ConflictError, NotFoundError
from .rules import EMERGENCY_FINISHED, RuleEngine


SYSTEM_ACTOR = Actor("system", "admin")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    # -- 紧急访问单：到期惰性失效 ---------------------------------------

    def _expire_overdue(self, entity):
        """单张单：过了截止时间且尚未结束，则置为 expired。"""
        if (
            self.rules.normalize_kind(entity["kind"]) != "emergency_access"
            or entity["status"] in EMERGENCY_FINISHED
        ):
            return entity
        from .rules import is_past_deadline

        if entity["status"] != "expired" and is_past_deadline(
            entity["data"].get("expires_at"), self.rules.now()
        ):
            from_status = entity["status"]
            next_status, patch = self.rules.validate_transition(
                SYSTEM_ACTOR, entity, "expire", {}, self._lookup
            )
            merged = dict(entity["data"])
            merged.update(patch)
            expected = entity["version"]
            try:
                entity = self.repository.update_entity(
                    entity["id"], expected, next_status, merged
                )
                self.audit.record(
                    entity["id"], SYSTEM_ACTOR, "expire",
                    from_status, next_status, {"patch": patch, "automatic": True},
                )
            except ConflictError:
                entity = self.repository.get_entity(entity["id"]) or entity
        return entity

    def _sweep_overdue(self, entities):
        result = []
        for entity in entities:
            result.append(self._expire_overdue(entity))
        return result

    def _decorate_emergency(self, entity):
        from .rules import is_past_deadline, remaining_seconds

        now = self.rules.now()
        expires_at = entity["data"].get("expires_at")
        data = dict(entity["data"])
        data["remaining_seconds"] = remaining_seconds(expires_at, now)
        data["expired"] = (
            entity["status"] in ("expired", "revoked", "rejected")
            or is_past_deadline(expires_at, now)
        )
        data["finished"] = entity["status"] in EMERGENCY_FINISHED
        decorated = dict(entity)
        decorated["data"] = data
        return decorated

    def _decorate(self, entity):
        if self.rules.normalize_kind(entity["kind"]) == "emergency_access":
            return self._decorate_emergency(entity)
        return entity

    # -- 用例 -----------------------------------------------------------

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return self._decorate(entity)
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return self._decorate(entity)

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        entity = self._expire_overdue(entity)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return self._decorate(updated)

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return self._decorate(self._expire_overdue(entity))

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        entities = self.repository.list_entities(kind=kind, status=status)
        if kind is None or kind == "emergency_access":
            entities = self._sweep_overdue(entities)
        return [self._decorate(entity) for entity in entities]

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
