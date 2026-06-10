import json
import boto3

from boundary import (
    ensure_boundary_exists
)

from validators import (
    validate_team_name,
    validate_service_name,
    validate_actions,
    validate_trust_principal
)

iam = boto3.client("iam")


def build_trust_policy(
    trust_service: str
):

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": trust_service
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }


def build_permission_policy(
    actions: list
):

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
        ]
    }


def vend_role(
    team_name,
    service_name,
    actions,
    trust_service
):

    validate_team_name(
        team_name
    )

    validate_service_name(
        service_name
    )

    validate_actions(
        actions
    )

    validate_trust_principal(
        trust_service
    )

    boundary_arn = (
        ensure_boundary_exists()
    )

    role_name = (
        f"vended-"
        f"{team_name}-"
        f"{service_name}"
    )

    trust_policy = (
        build_trust_policy(
            trust_service
        )
    )

    permission_policy = (
        build_permission_policy(
            actions
        )
    )

    role_response = (
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=
                json.dumps(
                    trust_policy
                ),
            PermissionsBoundary=
                boundary_arn,
            Description=
                "Created by IAM "
                "Vending Machine"
        )
    )

    role_arn = (
        role_response["Role"]["Arn"]
    )

    policy_name = (
        f"{role_name}-policy"
    )

    policy_response = (
        iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=
                json.dumps(
                    permission_policy
                )
        )
    )

    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn=
            policy_response[
                "Policy"
            ]["Arn"]
    )

    return {
        "role_name": role_name,
        "role_arn": role_arn,
        "boundary": boundary_arn
    }


def lambda_handler(event, context):
    result = vend_role(
        team_name=event['team_name'],
        service_name=event['service_name'],
        actions=event['requested_actions'],
        trust_service=event.get('trust_service', 'lambda.amazonaws.com')
    )
    return {
        "statusCode": 200,
        "body": json.dumps(result)
    }