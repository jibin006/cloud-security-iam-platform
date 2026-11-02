import sys
from pathlib import Path

import pytest


LAMBDA_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "build-1.3-permission-boundary-vending"
    / "lambda"
)
sys.path.insert(0, str(LAMBDA_SOURCE))

from validators import (  # noqa: E402
    validate_actions,
    validate_service_name,
    validate_team_name,
    validate_trust_principal,
)


@pytest.mark.parametrize("value", ["team-a", "security2", "platform-ops"])
def test_valid_team_names(value):
    validate_team_name(value)


@pytest.mark.parametrize("value", ["TeamA", "team/name", "../admin", ""])
def test_invalid_team_names(value):
    with pytest.raises(ValueError):
        validate_team_name(value)


@pytest.mark.parametrize("value", ["payments-api", "lambda-worker"])
def test_valid_service_names(value):
    validate_service_name(value)


@pytest.mark.parametrize("value", ["PaymentsAPI", "service_name", "service/name", ""])
def test_invalid_service_names(value):
    with pytest.raises(ValueError):
        validate_service_name(value)


def test_valid_non_wildcard_non_iam_actions():
    validate_actions(["s3:GetObject", "logs:PutLogEvents"])


@pytest.mark.parametrize(
    "actions",
    [
        [],
        "s3:GetObject",
        ["s3:*"],
        ["iam:CreateRole"],
        ["s3:GetObject", ""],
        ["s3:GetObject", None],
    ],
)
def test_invalid_action_requests_are_rejected(actions):
    with pytest.raises(ValueError):
        validate_actions(actions)


def test_default_trust_principal_is_lambda_only():
    validate_trust_principal("lambda.amazonaws.com")


@pytest.mark.parametrize("principal", ["ec2.amazonaws.com", "arn:aws:iam::123456789012:root", "*", None])
def test_unapproved_trust_principals_are_rejected(principal):
    with pytest.raises(ValueError):
        validate_trust_principal(principal)
