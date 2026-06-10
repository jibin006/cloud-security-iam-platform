import re
import os


ALLOWED_TRUST_PRINCIPALS = os.environ.get(
    'ALLOWED_TRUST_PRINCIPALS', 
    'lambda.amazonaws.com'
).split(',')


def validate_team_name(team_name: str):

    if not re.match(
        r"^[a-z0-9-]+$",
        team_name
    ):
        raise ValueError(
            "Invalid team name"
        )


def validate_service_name(
    service_name: str
):

    if not re.match(
        r"^[a-z0-9-]+$",
        service_name
    ):
        raise ValueError(
            "Invalid service name"
        )


def validate_actions(
    actions: list
):

    if not actions:
        raise ValueError(
            "At least one action required"
        )

    for action in actions:

        if "*" in action:
            raise ValueError(
                f"Wildcards not allowed: {action}"
            )

        if action.startswith("iam:"):
            raise ValueError(
                f"IAM actions forbidden: {action}"
            )


def validate_trust_principal(
    principal: str
):

    if principal not in (
        APPROVED_TRUST_PRINCIPALS
    ):
        raise ValueError(
            f"Unapproved trust principal: "
            f"{principal}"
        )