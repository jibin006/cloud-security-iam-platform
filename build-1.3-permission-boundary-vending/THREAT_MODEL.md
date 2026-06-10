# Threat Model

## Assets

* AWS Account
* IAM Roles
* Permission Boundary Policy
* Vending Machine Lambda

## Trusted Components

* Permission Boundary Vending Machine Lambda
* AWS Organizations SCP
* Approved Permission Boundary

## Threat Actors

### Developer with IAM Access

Goal:
Create over-privileged IAM role.

Attack Path:
CreateRole → Attach AdministratorAccess → AssumeRole

Control:
Permission Boundary + SCP

---

### Developer with Vended Role

Goal:
Remove boundary and escalate privileges.

Attack Path:
DeleteRolePermissionsBoundary

Control:
Explicit deny in boundary

---

### Malicious Trust Policy Request

Goal:
Create role trusted by external account.

Attack Path:
Trust policy manipulation

Control:
Trust principal allowlist validation

---

### SCP Bypass Attempt

Goal:
Create role directly using CLI.

Attack Path:
aws iam create-role

Control:
Organizations SCP
