"""The IAM linter is structural, never an effective-permissions simulator."""

import pytest

from cloud_security_lab.errors import FixtureError
from cloud_security_lab.iam import inspect_policy, parse_policy


def issues(statement, *, trust=False):
    document = parse_policy({"Version": "2012-10-17", "Statement": statement}, trust=trust)
    return inspect_policy(document, account_id="111122223333", trust=trust)


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/*"},
            set(),
        ),
        (
            {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::example/*"},
            {"IAM-001"},
        ),
        (
            {"Effect": "Allow", "Action": "s3:GetObjec?", "Resource": "arn:aws:s3:::example/*"},
            {"IAM-001"},
        ),
        ({"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}, {"IAM-002"}),
        (
            {
                "Effect": "Allow",
                "Action": "IAM:CreatePolicyVersion",
                "Resource": "arn:aws:iam::111122223333:policy/lab",
            },
            {"IAM-003"},
        ),
        (
            {
                "Effect": "Allow",
                "Action": "iam:Put*Policy",
                "Resource": "arn:aws:iam::111122223333:role/lab",
            },
            {"IAM-001", "IAM-003"},
        ),
        (
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/*",
            },
            {"IAM-004"},
        ),
        (
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::111122223333:role/lab",
            },
            set(),
        ),
        (
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"IAM-001", "IAM-002", "IAM-003", "IAM-004"},
        ),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, set()),
    ],
)
def test_permission_predicates(statement, expected):
    assert set(issues(statement)) == expected


def test_secure_transport_condition_is_structurally_supported():
    assert (
        issues(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/*",
                "Condition": {"Bool": {"aws:SecureTransport": "true"}},
            }
        )
        == {}
    )


def test_resource_policy_variables_are_rejected():
    with pytest.raises(FixtureError, match="unsupported"):
        issues(
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/${aws:username}/*",
            }
        )


@pytest.mark.parametrize(
    "resource",
    [
        "arn:aws:",
        "arn:aws:not-an-arn",
        "arn:aws:s3:::",
        "arn:aws:iam::123:role/test",
        "arn:aws:s3:::bucket with spaces",
    ],
)
def test_malformed_resource_arns_are_rejected(resource):
    with pytest.raises(FixtureError):
        issues({"Effect": "Allow", "Action": "s3:GetObject", "Resource": resource})


def test_deny_and_condition_do_not_cancel_allow_static_lint():
    statement = {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
    }
    assert set(issues([statement, {"Effect": "Deny", "Action": "*", "Resource": "*"}])) == {
        "IAM-001",
        "IAM-002",
        "IAM-003",
        "IAM-004",
    }


@pytest.mark.parametrize(
    ("principal", "condition", "expected"),
    [
        ("*", None, {"IAM-005"}),
        ({"AWS": "*"}, {"StringEquals": {"aws:PrincipalAccount": "111122223333"}}, {"IAM-005"}),
        ({"AWS": "arn:aws:iam::444455556666:root"}, None, {"IAM-006"}),
        ({"AWS": "444455556666"}, None, {"IAM-006"}),
        ({"AWS": "111122223333"}, None, set()),
        ({"AWS": "arn:aws:iam::111122223333:root"}, None, set()),
        ({"AWS": "arn:aws:iam::444455556666:role/vendor"}, None, set()),
        ({"Service": "ec2.amazonaws.com"}, None, set()),
        ({"AWS": "444455556666"}, {"StringEquals": {"sts:ExternalId": "synthetic-vendor"}}, set()),
    ],
)
def test_trust_predicates(principal, condition, expected):
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}
    if condition is not None:
        statement["Condition"] = condition
    assert set(issues(statement, trust=True)) == expected


def test_deny_trust_does_not_create_allow_findings():
    assert (
        issues({"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": "*"}, trust=True) == {}
    )


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"Statement": []},
        {"Statement": [{}]},
        {"Statement": {"Effect": "allow", "Action": "s3:GetObject", "Resource": "*"}},
        {"Statement": {"Effect": "Allow", "NotAction": "s3:GetObject", "Resource": "*"}},
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "*"}},
        {"Statement": {"Effect": "Allow", "Action": [], "Resource": "*"}},
        {"Statement": {"Effect": "Allow", "Action": 1, "Resource": "*"}},
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {},
            }
        },
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"Unsupported": {"k": "v"}},
            }
        },
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"unknown:Key": "v"}},
            }
        },
        {"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "typo": True}},
        {"Version": "2008-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
    ],
)
def test_unsupported_permission_documents_are_rejected(document):
    with pytest.raises(FixtureError):
        parse_policy(document)


def test_not_principal_and_non_assume_trust_actions_are_rejected():
    for statement in [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "NotPrincipal": {"AWS": "111122223333"}},
        {"Effect": "Allow", "Action": "s3:GetObject", "Principal": "*"},
    ]:
        with pytest.raises(FixtureError):
            issues(statement, trust=True)
