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


The sub condition restricts role assumption to a specific GitHub repository and branch, preventing other repositories from obtaining AWS credentials. StringEquals is used instead of StringLike to eliminate wildcard-based trust expansion and minimize blast radius. The aud condition ensures the OIDC token was specifically issued for AWS STS, preventing token reuse or confused-deputy scenarios where a token intended for another service is accepted by AWS.


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


## You fixed the exploit by scoping the sub condition. What trade-off did you accept by scoping it to refs/heads/main only — and what is the residual risk you're monitoring for?  


This is exactly the kind of question a build-focused interviewer asks because there is no single "correct" answer. They want to see whether you think in terms of **security vs operational flexibility**.

A strong answer would be:

> I scoped the OIDC trust policy to `refs/heads/main` using the `sub` claim:
>
> ```text
> repo:my-org/my-repo:ref:refs/heads/main
> ```
>
> The security benefit is that only workflows running from the main branch can obtain AWS credentials. A compromised feature branch, fork, or developer experimentation branch cannot directly assume the production role.
>
> The trade-off is reduced deployment flexibility. Feature branches, release branches, hotfix branches, and pull request workflows can no longer use that role. Any workflow outside `main` receives an `AccessDenied` during `AssumeRoleWithWebIdentity`.
>
> To support those workflows safely, I would create separate roles with narrower permissions and different trust conditions rather than broadening the production role.

---

### Residual Risk

Even after fixing the exploit, risk is not zero.

The main residual risk is:

> If an attacker can execute arbitrary GitHub Actions code on the trusted `main` branch, they can still obtain a valid OIDC token and assume the role because the trust policy conditions are satisfied.

Examples:

* Malicious commit merged into `main`
* Compromised maintainer account
* Unsafe workflow execution on `main`
* Supply chain compromise in a third-party GitHub Action
* Secrets exposure that enables unauthorized code execution in the workflow

The trust policy confirms:

```text
This workflow came from the correct repo and branch.
```

It does **not** confirm:

```text
The workflow itself is trustworthy.
```

---

### What I Would Monitor

CloudTrail:

```text
AssumeRoleWithWebIdentity
```

Monitor for:

* Unexpected repository names
* Unexpected branch references
* Unusual session names
* Unusual timestamps
* Large spikes in role assumptions
* Assumptions followed by sensitive API activity

GitHub:

* Direct pushes to `main`
* Changes to workflow files under `.github/workflows/`
* New third-party Actions introduced
* Privileged workflow permission changes

---

### Interview-Level Answer

> By scoping the `sub` claim to `refs/heads/main`, I accepted a reduction in deployment flexibility in exchange for a smaller trust boundary. Feature branches and PR workflows can no longer use the production role. The residual risk is that a workflow running legitimately on `main` can still be malicious if an attacker gains code execution on that branch. Therefore, I monitor `AssumeRoleWithWebIdentity` events, workflow changes, and privileged activity after role assumption because OIDC validates repository identity, not workflow intent.

That's a strong product-company answer because it demonstrates:

1. Understanding of the security control.
2. Awareness of operational impact.
3. Recognition that the control reduces risk rather than eliminating it.
4. Monitoring and detection thinking, not just prevention.

