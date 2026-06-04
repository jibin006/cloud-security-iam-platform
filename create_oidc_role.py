# create_oidc_role.py
import boto3
import json

def create_github_oidc_role(
    account_id: str,
    github_org: str,
    github_repo: str,
    github_branch: str,
    role_name: str,
    profile_name: str
) -> str:
    """
    Create IAM role that GitHub Actions can assume via OIDC.
    
    Critical design decisions in the trust policy:
    1. Condition on token.actions.githubusercontent.com:sub
       This scopes to specific repo AND branch
    2. StringEquals not StringLike
       StringLike allows wildcards - never use for trust policies
    3. Audience condition
       Prevents token reuse from other GitHub OIDC integrations
    
    These are the decisions interviewers drill on.
    Know why each condition exists.
    """
    
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    
    # This is the trust policy
    # Every condition here matters - know what happens if you remove each one
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": (
                        f"arn:aws:iam::{account_id}:oidc-provider/"
                        f"token.actions.githubusercontent.com"
                    )
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        # Audience - must be sts.amazonaws.com
                        "token.actions.githubusercontent.com:aud": (
                            "sts.amazonaws.com"
                        ),
                        # Subject - repo:org/repo:ref:refs/heads/branch
                        # This is the critical scope condition
                        #"token.actions.githubusercontent.com:sub": (
                            #f"repo:{github_org}/{github_repo}:"
                            #f"ref:refs/heads/{github_branch}"
                        #)
                    }
                }
            }
        ]
    }
    
    print("Trust policy being created:")
    print(json.dumps(trust_policy, indent=2))
    
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=(
                f"OIDC role for {github_org}/{github_repo} "
                f"branch:{github_branch}"
            ),
            Tags=[
                {'Key': 'managed-by', 'Value': 'oidc-setup'},
                {'Key': 'github-repo', 'Value': f"{github_org}/{github_repo}"},
                {'Key': 'github-branch', 'Value': github_branch}
            ]
        )
        
        role_arn = response['Role']['Arn']
        print(f"Role created: {role_arn}")
        
        # Attach minimum permissions for testing
        # In production this comes from the vending machine
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/ReadOnlyAccess'
        )
        
        return role_arn
        
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"Role {role_name} already exists")
        role = iam.get_role(RoleName=role_name)
        return role['Role']['Arn']


def test_trust_policy_scope(
    account_id: str,
    role_name: str,
    profile_name: str
):
    """
    Test what the trust policy actually allows.
    Run this to understand the scope before and after the intentional mistake.
    """
    
    session = boto3.Session(profile_name=profile_name)
    iam = session.client('iam')
    
    role = iam.get_role(RoleName=role_name)
    trust_policy = json.loads(
        role['Role']['AssumeRolePolicyDocument']
    )
    
    print("Current trust policy:")
    print(json.dumps(trust_policy, indent=2))
    
    # Simulate policy evaluation
    conditions = (
        trust_policy['Statement'][0]
        .get('Condition', {})
        .get('StringEquals', {})
    )
    
    sub_condition = conditions.get(
        'token.actions.githubusercontent.com:sub', 
        'NOT SET'
    )
    
    print(f"\nSub condition: {sub_condition}")
    
    if sub_condition == 'NOT SET':
        print("WARNING: No sub condition - ANY GitHub repo can assume this role")
    elif '*' in sub_condition:
        print("WARNING: Wildcard in sub condition - scope too broad")
    else:
        print("Sub condition properly scoped")
    
    return trust_policy


if __name__ == "__main__":
    # Replace with your values
    ACCOUNT_ID = "668798317441"
    GITHUB_ORG = "jibin006"
    GITHUB_REPO = "cloud-security-iam-platform"
    GITHUB_BRANCH = "main"
    
    role_arn = create_github_oidc_role(
        account_id=ACCOUNT_ID,
        github_org=GITHUB_ORG,
        github_repo=GITHUB_REPO,
        github_branch=GITHUB_BRANCH,
        role_name="github-actions-security-lab",
        profile_name="security-development"
    )
    
    print(f"\nRole ARN to use in GitHub Actions: {role_arn}")