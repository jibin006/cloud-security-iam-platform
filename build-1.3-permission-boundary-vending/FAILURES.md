# FAILURES.md

## Break 1 — Direct IAM Bypass

### Objective

Attempt to bypass the vending machine and create an IAM role directly using AWS CLI.

### What I Ran

```powershell
aws iam create-role `
  --role-name scp-bypass-test `
  --assume-role-policy-document file://trust.json `
  --profile security-development
```

### What Happened

The role was created successfully.

AWS returned:

```text
RoleName: scp-bypass-test
Arn: arn:aws:iam::668798317441:role/scp-bypass-test
```

### Which Control Fired

None.

No SCP denied the request.

Investigation showed the AWS Organization only had:

```text
FullAWSAccess
```

and no custom SCP denying `iam:CreateRole`.

### What Would Have Happened Without Detection

A developer could:

1. Create a new IAM role
2. Attach AdministratorAccess
3. Trust their own principal
4. Assume the role
5. Gain administrative access

### Security Conclusion

This was a successful bypass.

The intended SCP control was not deployed or enforced.

Remediation: create and attach an SCP denying direct `iam:CreateRole` outside the vending machine.

## Break 1 — Remediation Blocked: SCP Attachment Requires Org Admin

SCP created successfully: p-zd0oo3oe
Attachment blocked: AccessDeniedException on attach-policy

Root cause: IAM profile has organizations:CreatePolicy but not
organizations:AttachPolicy. These are split permissions in this
org — policy authoring and enforcement are separate roles.

Real-world equivalent: Security engineer authors the SCP,
org admin or platform team attaches it after review.
This is correct separation of duties, not a gap.

Compensating control implemented at account level:
VendingMachineLambdaRole execution role policy requires
iam:PermissionsBoundary condition on CreateRole — the Lambda
itself cannot create roles without the boundary regardless
of SCP state.

Residual risk: Other principals with iam:CreateRole in this
account can still bypass the vending machine until the SCP
is attached by an org admin.

---


## Break 2 — Confused Deputy Attempt

### Objective

Attempt to create a role trusted by an external AWS account.

### What I Ran

Invoked the vending machine Lambda with:

```json
{
  "team_name":"attacker",
  "service_name":"exfil",
  "requested_actions":["s3:GetObject"],
  "trust_service":"arn:aws:iam::999999999999:root"
}
```

### What Happened

Lambda returned:

```text
Unapproved trust principal:
arn:aws:iam::999999999999:root
```

No IAM role was created.

Verification:

```powershell
aws iam get-role `
  --role-name vended-attacker-exfil `
  --profile security-development
```

returned:

```text
NoSuchEntity
```

### Which Control Fired

Trust principal validation:

```python
validate_trust_principal()
```

The request was rejected before any IAM API call occurred.

### What Would Have Happened Without This Control

An attacker could create a role trusted by an external AWS account and allow external principals to assume it.

### Security Conclusion

The confused deputy path is closed.

External trust relationships are rejected before resource creation.

---

## Break 3 — Permission Boundary Escalation Attempt

### Objective

Operate as a boundary-constrained role and attempt privilege escalation.

### What I Ran

Assumed:

```text
arn:aws:sts::668798317441:assumed-role/boundary-break-test-role/boundary-break-test
```

Verified:

```powershell
aws sts get-caller-identity
```

returned the assumed role ARN.

#### Attack 1

```powershell
aws iam delete-role-permissions-boundary `
  --role-name boundary-break-test-role
```

Result:

```text
AccessDenied

because no identity-based policy allows
iam:DeleteRolePermissionsBoundary
```

#### Attack 2

```powershell
aws iam attach-role-policy `
  --role-name boundary-break-test-role `
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Result:

```text
AccessDenied

with an explicit deny in a permissions boundary:
SecurityBoundary-DoNotDelete
```

### Which Control Fired

Attack 1:

```text
Implicit deny
```

No identity policy granted the action.

Attack 2:

Boundary statement:

```json
{
  "Sid": "DenyPrivilegeEscalation",
  "Effect": "Deny",
  "Action": [
    "iam:AttachRolePolicy"
  ]
}
```

This explicit deny in the permission boundary blocked the request.

### What Would Have Happened Without These Controls

An attacker could:

1. Attach AdministratorAccess
2. Escalate privileges
3. Create additional privileged identities
4. Establish persistence

### Security Conclusion

Privilege escalation through policy attachment was blocked by the permission boundary.

The test also demonstrated the difference between:

* Implicit deny (no allow exists)
* Explicit deny (boundary enforcement)
