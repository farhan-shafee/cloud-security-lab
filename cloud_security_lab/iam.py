"""Restricted IAM parsing and static Allow-statement checks."""

from __future__ import annotations

import re
from fnmatch import fnmatchcase

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.models import PolicyDocument, Statement

SENSITIVE_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
)
CONDITION_KEYS = {
    "aws:RequestedRegion",
    "aws:PrincipalAccount",
    "aws:PrincipalArn",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:PrincipalOrgID",
    "aws:MultiFactorAuthPresent",
    "aws:SecureTransport",
    "sts:ExternalId",
    "iam:PassedToService",
}
CONDITION_OPERATORS = {"StringEquals", "StringLike", "ArnEquals", "ArnLike", "Bool"}


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise FixtureError(f"{context} must be an object")
    return value


def _strings(value: object, context: str) -> tuple[str, ...]:
    values = value if isinstance(value, list) else [value]
    if not values or any(not isinstance(item, str) or not item.strip() for item in values):
        raise FixtureError(f"{context} must be a string or nonempty string array")
    return tuple(values)


def _conditions(value: object) -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    conditions = _object(value, "Condition")
    if not conditions:
        raise FixtureError("Condition must be nonempty when supplied")
    result = []
    for operator, raw_entries in conditions.items():
        if operator not in CONDITION_OPERATORS:
            raise FixtureError(f"unsupported condition operator: {operator}")
        entries = _object(raw_entries, f"Condition.{operator}")
        if not entries:
            raise FixtureError("condition operators must have nonempty key/value objects")
        for key, raw_values in entries.items():
            if key not in CONDITION_KEYS:
                raise FixtureError(f"unsupported condition key: {key}")
            values = _strings(raw_values, f"Condition.{operator}.{key}")
            if operator == "Bool" and any(v not in {"true", "false"} for v in values):
                raise FixtureError("Bool conditions require string true/false values")
            result.append((operator, key, values))
    return tuple(result)


def _principals(value: object) -> tuple[tuple[str, str], ...]:
    if value == "*":
        return (("AWS", "*"),)
    raw = _object(value, "Principal")
    if not raw or set(raw) - {"AWS", "Service"}:
        raise FixtureError("only AWS and Service principals are supported")
    result = []
    for kind, entries in raw.items():
        for principal in _strings(entries, f"Principal.{kind}"):
            if (
                kind == "AWS"
                and principal != "*"
                and not re.fullmatch(
                    r"[0-9]{12}|arn:aws:iam::[0-9]{12}:(?:root|(?:role|user)/[A-Za-z0-9_+=,.@/-]+)",
                    principal,
                )
            ):
                raise FixtureError(f"unsupported AWS principal: {principal}")
            if kind == "Service" and not re.fullmatch(r"[a-z0-9.-]+\.amazonaws\.com", principal):
                raise FixtureError(f"unsupported service principal: {principal}")
            result.append((kind, principal))
    return tuple(result)


def parse_policy(value: object, *, trust: bool = False) -> PolicyDocument:
    document = _object(value, "policy")
    if set(document) - {"Version", "Id", "Statement"} or "Statement" not in document:
        raise FixtureError("policy has unknown fields or missing Statement")
    if "Version" in document and document["Version"] != "2012-10-17":
        raise FixtureError("only policy Version 2012-10-17 is supported")
    if "Id" in document:
        _strings(document["Id"], "policy.Id")
        if not isinstance(document["Id"], str):
            raise FixtureError("policy.Id must be a string")
    statements = document["Statement"]
    raw_statements = statements if isinstance(statements, list) else [statements]
    if not raw_statements:
        raise FixtureError("Statement must be nonempty")
    parsed = []
    sids: set[str] = set()
    for index, raw_statement in enumerate(raw_statements, 1):
        statement = _object(raw_statement, f"Statement[{index}]")
        allowed = {"Sid", "Effect", "Action", "Condition", "Principal" if trust else "Resource"}
        required = {"Effect", "Action", "Principal" if trust else "Resource"}
        if set(statement) - allowed or required - set(statement):
            raise FixtureError(
                f"Statement[{index}] has unsupported fields or missing required fields; "
                "NotAction/NotResource/NotPrincipal are unsupported"
            )
        effect = statement["Effect"]
        if effect not in ("Allow", "Deny"):
            raise FixtureError("Effect must be Allow or Deny")
        sid = statement.get("Sid", f"statement-{index}")
        if not isinstance(sid, str) or not sid.strip() or sid in sids:
            raise FixtureError("statement identifiers must be unique nonempty strings")
        sids.add(sid)
        actions = _strings(statement["Action"], "Action")
        if any(not re.fullmatch(r"\*|[A-Za-z0-9-]+:[A-Za-z0-9*?]+", action) for action in actions):
            raise FixtureError("unsupported Action syntax")
        if trust and any(action.lower() != "sts:assumerole" for action in actions):
            raise FixtureError("trust fixture actions must be sts:AssumeRole")
        resources = () if trust else _strings(statement["Resource"], "Resource")
        if any("${" in resource for resource in resources):
            raise FixtureError("resource policy variables are unsupported")
        arn_pattern = (
            r"arn:aws:[a-z0-9-]+:[a-z0-9*?-]*:"
            r"(?:[0-9]{12}|[0-9*?]*[*?][0-9*?]*|):[^\s]+"
        )
        if any(
            resource != "*" and not re.fullmatch(arn_pattern, resource) for resource in resources
        ):
            raise FixtureError("Resource must be '*' or a commercial-partition AWS ARN pattern")
        principals = _principals(statement["Principal"]) if trust else ()
        conditions = _conditions(statement["Condition"]) if "Condition" in statement else ()
        parsed.append(Statement(sid, str(effect), actions, resources, principals, conditions))
    return PolicyDocument(tuple(parsed))


def inspect_policy(
    document: PolicyDocument, *, account_id: str, trust: bool = False
) -> dict[str, tuple[dict[str, object], ...]]:
    issues: dict[str, list[dict[str, object]]] = {}

    def add(control_id: str, statement: Statement, matched: object) -> None:
        issues.setdefault(control_id, []).append(
            {
                "statement_id": statement.sid,
                "effect": statement.effect,
                "matched": matched,
                "condition_present": bool(statement.conditions),
            }
        )

    for statement in document.statements:
        if statement.effect != "Allow":
            continue
        if trust:
            if any(value == "*" for _, value in statement.principals):
                add("IAM-005", statement, "wildcard Principal")
            external = []
            for kind, principal in statement.principals:
                match = re.fullmatch(r"(?:arn:aws:iam::)?([0-9]{12})(?::root)?", principal)
                if kind == "AWS" and match and match.group(1) != account_id:
                    external.append(principal)
            if external and not statement.conditions:
                add("IAM-006", statement, external)
            continue
        wildcards = [action for action in statement.actions if "*" in action or "?" in action]
        if wildcards:
            add("IAM-001", statement, wildcards)
        if "*" in statement.resources:
            add("IAM-002", statement, "Resource: *")
        sensitive = [
            action
            for action in SENSITIVE_ACTIONS
            if any(fnmatchcase(action.lower(), pattern.lower()) for pattern in statement.actions)
        ]
        if sensitive:
            add("IAM-003", statement, sensitive)
        broad_resources = [
            resource for resource in statement.resources if "*" in resource or "?" in resource
        ]
        if broad_resources and any(
            fnmatchcase("iam:passrole", action.lower()) for action in statement.actions
        ):
            add("IAM-004", statement, broad_resources)
    return {control_id: tuple(evidence) for control_id, evidence in issues.items()}
