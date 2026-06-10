import boto3
import json

iam = boto3.client("iam")
sts = boto3.client("sts")

BOUNDARY_POLICY_NAME = "SecurityBoundary-DoNotDelete"

BOUNDARY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowBasicOperations",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "logs:*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "DenyPrivilegeEscalation",
            "Effect": "Deny",
            "Action": [
                "iam:*",
                "organizations:*"
            ],
            "Resource": "*"
        }
    ]
}


def get_boundary_arn() -> str:
    account_id = sts.get_caller_identity()["Account"]

    return (
        f"arn:aws:iam::{account_id}:policy/"
        f"{BOUNDARY_POLICY_NAME}"
    )


def ensure_boundary_exists() -> str:
    boundary_arn = get_boundary_arn()

    try:
        iam.get_policy(
            PolicyArn=boundary_arn
        )

        print(
            f"Boundary exists: {boundary_arn}"
        )

        return boundary_arn

    except iam.exceptions.NoSuchEntityException:

        response = iam.create_policy(
            PolicyName=BOUNDARY_POLICY_NAME,
            PolicyDocument=json.dumps(
                BOUNDARY_DOCUMENT
            ),
            Description=(
                "Mandatory permission boundary "
                "for all vended roles"
            )
        )

        print(
            f"Created boundary: "
            f"{response['Policy']['Arn']}"
        )

        return response["Policy"]["Arn"]