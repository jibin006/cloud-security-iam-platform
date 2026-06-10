# Design Decisions

## Decision 1

Permission boundary attached during CreateRole.

Reason:
Avoid race condition between role creation and boundary attachment.

---

## Decision 2

Trust principals restricted to approved AWS services.

Reason:
Prevents confused deputy and cross-account trust abuse.

---

## Decision 3

SCP blocks CreateRole outside vending machine.

Reason:
Prevents bypass of mandatory controls.

---

## Decision 4

sts:AssumeRole not globally denied.

Reason:
Required for legitimate AWS service integrations.

Blanket deny creates operational burden.

Scoped controls preferred.


## Decision 5

### SCP Attachment Not Enforced by Build Team

**Decision:**
Treat SCP enforcement as an organizational control owned by the AWS Organization administrators and implement a compensating control at the account level.

**Evidence:**

SCP creation succeeded:

```text
PolicyId: p-zd0oo3oe
```

SCP attachment failed:

```text
AccessDeniedException
```

for:

```text
organizations:AttachPolicy
organizations:ListParents
organizations:ListRoots
```

**Reason:**

In this organization, policy authoring and policy attachment are intentionally separated.

The security engineer can create SCPs but cannot attach them to OUs or accounts.

This separation of duties prevents a single engineer from unilaterally enforcing organization-wide controls.

**Compensating Control:**

The Lambda execution role policy enforces:

```json
{
  "Action": "iam:CreateRole",
  "Condition": {
    "StringEquals": {
      "iam:PermissionsBoundary":
      "arn:aws:iam::668798317441:policy/SecurityBoundary-DoNotDelete"
    }
  }
}
```

As a result, the vending machine itself cannot create roles unless the required boundary is attached.

**Residual Risk:**

Any principal outside the vending machine that already possesses:

```text
iam:CreateRole
```

can still bypass the control until the SCP is attached by an organization administrator.

---

## Decision 6

### iam:GetPolicy Uses Resource "*" Instead of Scoped ARN

**Decision:**

Allow:

```json
{
  "Action": "iam:GetPolicy",
  "Resource": "*"
}
```

instead of restricting the action to the boundary policy ARN.

**Evidence:**

After replacing IAMFullAccess with VendingMachineScopedPolicy, Lambda invocation failed with:

```text
AccessDenied

not authorized to perform:
iam:GetPolicy
```

The vending machine could not validate the existence of the permission boundary.

**Initial Attempt:**

```json
{
  "Action": "iam:GetPolicy",
  "Resource":
  "arn:aws:iam::668798317441:policy/SecurityBoundary-DoNotDelete"
}
```

**Result:**

Lambda execution failed.

**Fix:**

Policy version v2 changed:

```json
{
  "Action": "iam:GetPolicy",
  "Resource": "*"
}
```

Lambda subsequently succeeded and vended roles correctly.

**Reason:**

IAM does not consistently support resource-level authorization for every policy retrieval path used by the service APIs.

Using a scoped ARN caused authorization failures during runtime validation.

**Trade-Off:**

This grants read access to IAM policy metadata across the account.

However:

* The action is read-only.
* The Lambda cannot modify policies.
* The Lambda cannot bypass the permission boundary.
* The Lambda retains least privilege while remaining operational.

This decision was validated through failure-first testing rather than documentation assumptions.

