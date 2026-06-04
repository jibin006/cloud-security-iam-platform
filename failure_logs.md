Issue:
GitHub Actions failed to assume AWS role via OIDC.

Root Cause:
Incorrect OIDC provider thumbprint configured in AWS IAM.
AWS could not validate the TLS certificate presented by
token.actions.githubusercontent.com.

Impact:
AssumeRoleWithWebIdentity requests were rejected,
preventing GitHub Actions from obtaining temporary AWS credentials.

Resolution:
Updated IAM OIDC provider with the correct certificate thumbprint
for token.actions.githubusercontent.com and re-ran the workflow.

Lesson Learned:
OIDC trust depends on both JWT validation and certificate trust.
An incorrect thumbprint breaks the trust chain and causes all
federated authentication requests to fail.


# Failure Log: Broad OIDC Trust Policy

## Failure Scenario

I intentionally removed the `token.actions.githubusercontent.com:sub` condition from the IAM role trust policy and left only the audience validation (`aud=sts.amazonaws.com`).

This resulted in any GitHub repository capable of obtaining a valid GitHub OIDC token being able to assume the AWS role.

---

## What was the exact sub claim in the JWT that allowed the exploit?

Expected legitimate claim:

```text
repo:jibin006/cloud-security-iam-platform:ref:refs/heads/main
```

After removing the `sub` condition, AWS no longer validated the repository or branch identity.

Example attacker-controlled repository claim:

```text
repo:attacker-org/malicious-repo:ref:refs/heads/main
```

Both tokens still contained:

```text
aud = sts.amazonaws.com
iss = https://token.actions.githubusercontent.com
```

Because only the audience was validated, AWS accepted tokens from repositories outside the intended trust boundary.

Root cause:

The repository identity contained in the `sub` claim was not validated.

---

## How would CloudTrail show this differently from a legitimate assume?

### Legitimate AssumeRoleWithWebIdentity

```json
{
  "eventName": "AssumeRoleWithWebIdentity",
  "userIdentity": {
    "type": "WebIdentityUser"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::<ACCOUNT_ID>:role/github-actions-security-lab"
  },
  "additionalEventData": {
    "sub": "repo:jibin006/cloud-security-iam-platform:ref:refs/heads/main"
  }
}
```

### Exploit Attempt

```json
{
  "eventName": "AssumeRoleWithWebIdentity",
  "userIdentity": {
    "type": "WebIdentityUser"
  },
  "requestParameters": {
    "roleArn": "arn:aws:iam::<ACCOUNT_ID>:role/github-actions-security-lab"
  },
  "additionalEventData": {
    "sub": "repo:attacker-org/malicious-repo:ref:refs/heads/main"
  }
}
```

Key observation:

The event type is identical.

The difference exists only inside the OIDC claims, specifically the `sub` value.

Without monitoring claim values, both events appear as successful role assumptions.

---

## What is the detection gap between the exploit and the CloudTrail alert?

### Detection Gap

CloudTrail records the event after the role assumption succeeds.

The attacker receives temporary AWS credentials immediately after STS issues them.

Timeline:

1. Attacker obtains GitHub OIDC token.
2. Attacker calls AssumeRoleWithWebIdentity.
3. AWS validates token.
4. AWS issues temporary credentials.
5. Attacker begins AWS actions.
6. CloudTrail event is written.
7. Detection pipeline processes the event.
8. Alert is generated.

The detection occurs after access has already been granted.

### Risk

An attacker can perform actions before detection occurs:

* Read sensitive S3 objects.
* Push malicious container images to ECR.
* Modify deployment artifacts.
* Enumerate IAM permissions.
* Access Secrets Manager data within role scope.

### Mitigation

Detection should not be the primary control.

The primary control is prevention through strict trust policy conditions:

```json
{
  "StringEquals": {
    "token.actions.githubusercontent.com:sub":
      "repo:jibin006/cloud-security-iam-platform:ref:refs/heads/main"
  }
}
```

CloudTrail monitoring acts as a secondary detective control for identifying unexpected repository identities.

---

## Lessons Learned

* Audience validation alone is insufficient.
* The `sub` claim is the primary repository-scoping control.
* OIDC trust policies should explicitly bind trust to repository and branch.
* CloudTrail detects abuse after credentials are issued, not before.
* Prevention at the trust boundary is more effective than relying on post-event detection.
