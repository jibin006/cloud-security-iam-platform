## GitHub Actions failed to assume AWS role via OIDC.

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


## You are a third-party security monitoring vendor. Your service runs in Account X. Your customer gives you a role ARN in Account Y to scan their environment. Your trust policy in Account Y trusts Account X's root. An attacker is also your customer. They tell your service: "scan this role ARN" — and they give you your legitimate customer's role ARN, not their own. Walk me through the assume chain step by step. Where does it break without external ID, and where does external ID stop it? Don't look this up. Reason through it using what you know about how sts:AssumeRole works across accounts. The trust model is the same one you just built in Build 1 — just at a different layer.

Let's walk through it carefully.

---

## Actors

```text
Vendor Account X
|
|-- Security Scanner Service
|
|-- Customer A (legitimate)
|
|-- Customer B (attacker)
```

```text
Customer A AWS Account Y
Role: SecurityAuditRole
```

Trust policy in Account Y:

```json
{
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT_X:root"
  },
  "Action": "sts:AssumeRole"
}
```

No ExternalId.

---

## What You Said

> if external id is not there any thirdparty can assume the role

Not exactly.

This is the most common misunderstanding.

The attacker is **NOT** directly calling STS against Account Y.

They can't.

The trust policy only trusts Account X.

So this call fails:

```text
Attacker AWS Account
        |
        | AssumeRole
        v
Customer A Role
```

because:

```text
Principal != Account X
```

Trust policy rejects it.

---

# The Real Attack

Customer B is also a customer of the vendor.

Customer B submits:

```text
Role ARN:
arn:aws:iam::ACCOUNT_Y:role/SecurityAuditRole
```

to the vendor.

The vendor's scanner now receives:

```text
Scan this role
```

The vendor has no way to know whether:

```text
Role belongs to Customer A
```

or

```text
Role belongs to Customer B
```

---

### Step 1

Vendor scanner starts.

```text
Vendor Scanner
    |
    | AssumeRole
    v
Customer A Role
```

Who is making the STS call?

```text
Vendor Account X
```

---

### Step 2

AWS evaluates trust policy.

Trust policy says:

```json
{
  "Principal": {
    "AWS": "arn:aws:iam::ACCOUNT_X:root"
  }
}
```

AWS asks:

```text
Is caller Account X?
```

Answer:

```text
Yes
```

---

### Step 3

Role assumption succeeds.

Temporary credentials issued.

```text
AssumedRole:
SecurityAuditRole
```

---

### Step 4

Vendor now scans Customer A's account.

But who requested the scan?

```text
Attacker Customer B
```

That's the confused deputy.

The deputy is:

```text
Vendor Scanner
```

It was tricked into using its legitimate authority for the wrong customer.

---

## Where Does It Break Without ExternalId?

It doesn't.

That's the entire problem.

AWS only verifies:

```text
WHO is calling?
```

```text
Account X
```

Trust satisfied.

AWS does not know:

```text
Why is Account X calling?
Which customer requested this?
```

No ExternalId means AWS has no customer context.

So the assume succeeds.

---

# Now Add ExternalId

Customer A configures:

```json
{
  "Condition": {
    "StringEquals": {
      "sts:ExternalId": "customer-a-12345"
    }
  }
}
```

---

### Step 1

Attacker tells vendor:

```text
Scan this role:
arn:aws:iam::ACCOUNT_Y:role/SecurityAuditRole
```

---

### Step 2

Vendor looks up Customer B's configuration.

Vendor sends:

```text
AssumeRole(
  RoleArn=CustomerA,
  ExternalId=customer-b-99999
)
```

because the request came from Customer B.

---

### Step 3

AWS evaluates.

Trust policy requires:

```text
customer-a-12345
```

Received:

```text
customer-b-99999
```

Mismatch.

---

### Step 4

STS returns:

```text
AccessDenied
```

Role assumption blocked.

Attack stopped.

---

## The Key Insight

Your explanation was:

> external id is provided to vendor which prevent confused deputy

That's true, but incomplete.

The critical interviewer-level answer is:

> ExternalId is not preventing an untrusted principal from assuming the role. The trust policy already does that. ExternalId prevents a trusted principal from being tricked into assuming the role on behalf of the wrong customer.

That sentence is the heart of confused deputy.

---


## If the attacker somehow learns Customer A's ExternalId, does the confused deputy attack become possible again? Why or why not?


Let's trace the chain.

### Who is trusted by the role?

```text
Account Y Role Trust Policy

Principal:
Account X (Vendor)
```

NOT:

```text
Attacker Account
```

So even if the attacker learns:

```text
customer-a-12345
```

and runs:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_Y:role/SecurityAuditRole \
  --external-id customer-a-12345
```

from their own AWS account, AWS still checks:

```text
Who is calling?
```

Caller:

```text
Attacker Account
```

Trust policy expects:

```text
Account X
```

Result:

```text
AccessDenied
```

The attacker still cannot directly assume the role.

---

The better question is:

> What if the attacker learns Customer A's ExternalId AND can convince the vendor service to use it?

Now the attack becomes possible again.

Example:

```text
Customer A
ExternalId = customer-a-12345

Customer B (attacker)
Learns customer-a-12345
```

Attacker submits:

```text
Role ARN = Customer A Role
ExternalId = customer-a-12345
```

to the vendor.

Vendor then makes:

```text
AssumeRole(
    RoleArn=CustomerA,
    ExternalId=customer-a-12345
)
```

AWS evaluates:

```text
Trusted Principal?  YES (Vendor Account X)

ExternalId matches? YES
```

Result:

```text
AssumeRole succeeds
```

The confused deputy protection has been bypassed because the vendor was tricked into presenting the correct customer context.

---

This is why senior engineers often say:

> ExternalId is not a secret in the cryptographic sense.

Its purpose is:

```text
Customer A context
≠
Customer B context
```

It helps AWS distinguish which customer relationship the trusted vendor is acting under.

---

Interview answer:

> Learning the ExternalId alone does not allow the attacker to assume the role because the trust policy still only trusts the vendor account. However, if the attacker can cause the trusted vendor to call AssumeRole using Customer A's ExternalId, then the confused deputy protection is defeated. ExternalId protects against customer mix-up by a trusted principal; it does not replace principal authentication or authorization.

That's the distinction interviewers look for. The attack path is:

```text
Attacker
    ↓
Vendor
    ↓
STS AssumeRole
    ↓
Customer Role
```

not:

```text
Attacker
    ↓
STS AssumeRole
    ↓
Customer Role
```

The second path is already blocked by the trust policy. The confused deputy attack is about abusing the **trusted intermediary**, not bypassing trust directly.



## residual risk of external ID

This is the difference between knowing what ExternalId does and understanding the assumptions required for it to work.

Your earlier mental model was:
```text
ExternalId exists
    ↓
Attack blocked
```
The more accurate model is:
```text
ExternalId exists
AND
Vendor correctly binds customer → ExternalId mapping
AND
Customer cannot influence ExternalId value
    ↓
Attack blocked
```
If any of those assumptions fail:
```text
Customer B
    ↓
Supplies RoleArn = CustomerA
Supplies ExternalId = customer-a-12345
    ↓
Vendor forwards both to STS
    ↓
Trust policy satisfied
    ↓
AssumeRole succeeds
```
The control collapses.

This is why ExternalId is fundamentally different from something like:
```text
IAM Principal ARN
MFA
Digital Signature
```
Those are verified by AWS itself.

ExternalId is only a string comparison:
```text
{
  "StringEquals": {
    "sts:ExternalId": "customer-a-12345"
  }
}
```
AWS does not know:

who generated it

whether it is secret

whether it was leaked

whether the vendor got it from a database lookup

whether the customer typed it into an API request

AWS only knows:
```text
Expected value == Presented value ?
```
A senior-level answer would be:

ExternalId mitigates confused deputy by allowing the role owner to require customer-specific context during AssumeRole. However, its effectiveness depends on the vendor enforcing the customer-to-external-ID mapping server-side. If customers can supply arbitrary ExternalId values, an attacker who learns another customer's ExternalId can cause the vendor to present the correct context and bypass the protection. Therefore, ExternalId is a trust-boundary control, not a cryptographic secret.

Notice how that answer is about system design assumptions, not IAM syntax.

That's exactly the level where build-focused Cloud Security interviews operate.
