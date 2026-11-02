import os
import re


ALLOWED_TRUST_PRINCIPALS = frozenset(
    principal.strip()
    for principal in os.environ.get(
        "ALLOWED_TRUST_PRINCIPALS",
        "lambda.amazonaws.com",
    ).split(",")
    if principal.strip()
)


def validate_team_name(team_name: str) -> None:
    if not isinstance(team_name, str) or not re.fullmatch(r"[a-z0-9-]+", team_name):
        raise ValueError("Invalid team name: use lowercase letters, digits, and hyphens")


def validate_service_name(service_name: str) -> None:
    if not isinstance(service_name, str) or not re.fullmatch(r"[a-z0-9-]+", service_name):
        raise ValueError("Invalid service name: use lowercase letters, digits, and hyphens")


def validate_actions(actions: list[str]) -> None:
    if not isinstance(actions, list) or not actions:
        raise ValueError("At least one action is required")

    for action in actions:
        if not isinstance(action, str) or not action.strip():
            raise ValueError("Each IAM action must be a non-empty string")
        if "*" in action:
            raise ValueError(f"Wildcards not allowed: {action}")
        if action.lower().startswith("iam:"):
            raise ValueError(f"IAM actions forbidden: {action}")


def validate_trust_principal(principal: str) -> None:
    if not isinstance(principal, str) or principal not in ALLOWED_TRUST_PRINCIPALS:
        raise ValueError(
            f"Unapproved trust principal: {principal!r}. "
            f"Allowed principals: {sorted(ALLOWED_TRUST_PRINCIPALS)}"
        )
