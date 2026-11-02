# cross_account_roles.py
import boto3
import json
import os
from botocore.exceptions import ClientError
from typing import Optional

def create_cross_account_role(
    workload_account_id: str,
    security_account_id: str,
    role_name: str,
    external_id: str,
    workload_profile: str
) -> str:
    """
    Create role in Workload account that Security account can assume.
    
    External ID prevents confused deputy attack.
    
    Confused deputy: a third party service tricks AWS into using
    YOUR role on their behalf because the trust policy only checks
    the principal, not the context.
    External ID is a shared secret that only you know.
    """
    
    session = boto3.Session(profile_name=workload_profile)
    iam = session.client('iam')
    
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{security_account_id}:root"
                },
                "Action": "sts:AssumeRole",
                 "Condition": {
                    "StringEquals": {
                        # External ID prevents confused deputy
                        # Must match what the caller provides
                        "sts:ExternalId": external_id
                     }
                }
            }
        ]
    }
    
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=(
                f"Cross-account role for security tooling account "
                f"{security_account_id}"
            ),
            Tags=[
                {'Key': 'managed-by', 'Value': 'security-team'},
                {'Key': 'trusted-account', 'Value': security_account_id},
                {'Key': 'external-id-required', 'Value': 'true'}
            ]
        )
        
        role_arn = response['Role']['Arn']
        
        # Attach read-only policy for security scanning
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/SecurityAudit'
        )
        
        print(f"Cross-account role created: {role_arn}")
        return role_arn
        
    except iam.exceptions.EntityAlreadyExistsException:
        role = iam.get_role(RoleName=role_name)
        existing_trust = role["Role"].get("AssumeRolePolicyDocument", {})
        if isinstance(existing_trust, str):
            existing_trust = json.loads(existing_trust)
        if existing_trust != trust_policy:
            raise RuntimeError(
                f"Role {role_name} already exists with a different trust policy. "
                "Refusing to treat the existing role as securely configured."
            )
        return role["Role"]["Arn"]


def assume_cross_account_role(
    role_arn: str,
    external_id: str,
    session_name: str,
    security_profile: str,
    session_policy: Optional[dict] = None
) -> dict:
    """
    Assume the cross-account role from the security account.
    
    Session policy reduces permissions FURTHER than the role allows.
    Even if the role has broad permissions, session policy limits
    what this specific session can do.
    
    This is blast radius reduction at the session level.
    """
    
    session = boto3.Session(profile_name=security_profile)
    sts = session.client('sts')
    
    assume_kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "ExternalId": external_id,
        "DurationSeconds": 3600  # 1 hour maximum
    }
    
    # Session policy further restricts permissions
    # Even if role has broader access, this session can only do these actions
    if session_policy:
        assume_kwargs["Policy"] = json.dumps(session_policy)
    
    try:
        response = sts.assume_role(**assume_kwargs)
        
        credentials = response['Credentials']
        print(f"Successfully assumed role: {role_arn}")
        print(f"Session expires: {credentials['Expiration']}")
        
        return credentials
        
    except Exception as e:
        print(f"Failed to assume role: {e}")
        raise


def demonstrate_confused_deputy(
    workload_account_id: str,
    role_name: str,
    security_profile: str
):
    """
    Demonstrate the confused deputy attack and why external ID prevents it.
    
    Confused deputy scenario:
    1. You create a role trusting a third-party service (e.g., monitoring tool)
    2. Attacker also uses that monitoring tool
    3. Attacker tells monitoring tool: scan role X in YOUR account
    4. Without external ID: monitoring tool assumes your role for the attacker
    5. With external ID: monitoring tool cannot assume your role without knowing
       the external ID you set specifically for your relationship
    """
    
    session = boto3.Session(profile_name=security_profile)
    sts = session.client('sts')
    
    role_arn = f"arn:aws:iam::{workload_account_id}:role/{role_name}"
    
    print("=== CONFUSED DEPUTY DEMONSTRATION ===\n")
    
    # Attempt 1: Without external ID - should fail
    print("Attempt 1: Without external ID (should fail)")
    try:
        sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="confused-deputy-test"
            # No ExternalId - should be rejected
        )
        print("ERROR: Role assumed WITHOUT external ID - trust policy is misconfigured")
    except ClientError as e:
        if "AccessDenied" in str(e):
            print("CORRECT: Role assumption rejected without external ID")
            print(f"Error: {e.response['Error']['Message']}")
        else:
            print(f"Unexpected error: {e}")
    
    # Attempt 2: Wrong external ID - should fail
    print("\nAttempt 2: Wrong external ID (should fail)")
    try:
        sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="confused-deputy-test-2",
            ExternalId="wrong-external-id-attacker-guess"
        )
        print("ERROR: Role assumed with WRONG external ID - trust policy is misconfigured")
    except sts.exceptions.ClientError as e:
        if "AccessDenied" in str(e):
            print("CORRECT: Role assumption rejected with wrong external ID")
            print(f"Error: {e.response['Error']['Message']}")
    
    print("\nConclusion: External ID prevents confused deputy attack")
    print("The external ID is a shared secret between you and the trusted principal")
    print("A third-party cannot assume your role on behalf of an attacker")


def create_session_scoped_client(
    role_arn: str,
    external_id: str,
    security_profile: str,
    allowed_actions: list,
    resource_arn: str = "*"
) -> boto3.Session:
    """
    Create an AWS session with minimum permissions for the task.
    
    Even if the role has broad SecurityAudit permissions,
    this session can only perform the specific actions needed.
    
    This is the principle of least privilege applied at runtime.
    """
    
    # Session policy limits to only what this task needs
    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": allowed_actions,
                "Resource": resource_arn
            }
        ]
    }
    
    credentials = assume_cross_account_role(
        role_arn=role_arn,
        external_id=external_id,
        session_name="scoped-security-scan",
        security_profile=security_profile,
        session_policy=session_policy
    )
    
    # Create session with temporary credentials
    scoped_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    return scoped_session

if __name__ == "__main__":
    required = ("WORKLOAD_ACCOUNT_ID", "SECURITY_ACCOUNT_ID", "CROSS_ACCOUNT_EXTERNAL_ID")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise SystemExit(
            "Missing required environment variables: " + ", ".join(missing)
        )

    workload_account_id = os.environ["WORKLOAD_ACCOUNT_ID"]
    security_account_id = os.environ["SECURITY_ACCOUNT_ID"]
    external_id = os.environ["CROSS_ACCOUNT_EXTERNAL_ID"]
    workload_profile = os.environ.get("AWS_WORKLOAD_PROFILE", "security-development")
    security_profile = os.environ.get("AWS_SECURITY_PROFILE", "security-account")
    role_name = os.environ.get("CROSS_ACCOUNT_ROLE_NAME", "CrossAccountSecurityAudit")

    role_arn = create_cross_account_role(
        workload_account_id=workload_account_id,
        security_account_id=security_account_id,
        role_name=role_name,
        external_id=external_id,
        workload_profile=workload_profile,
    )
    print(f"Created role: {role_arn}")

    demonstrate_confused_deputy(
        workload_account_id=workload_account_id,
        role_name=role_name,
        security_profile=security_profile,
    )
