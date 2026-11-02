# cloud-security-iam-platform


## Overview

This repository contains related AWS IAM security labs and prototypes. The components are independently implemented; this is **not yet a deployable, integrated IAM control plane**. The repository covers workload federation, cross-account access, and permission-boundary role vending. IAM drift detection is maintained separately in [IAM Drift Detector](https://github.com/jibin006/iam-drift-detector).\n\nCloud environments often suffer from fragmented identity controls:

* Static credentials embedded in CI/CD systems
* Inconsistent cross-account access patterns
* Excessively privileged IAM roles
* Limited visibility into permission drift and privilege escalation paths

The labs explore controls intended to constrain identity creation and cross-account access. Their security properties must be tested in an AWS sandbox before being treated as operational controls.

The platform consists of four integrated security systems:

1. Workload Identity Federation
2. Cross-Account Access Governance
3. IAM Role Vending Machine
4. IAM Drift Detection

These components are not currently wired into one automated deployment or continuous-monitoring workflow.

---

## Problem Statement

Traditional cloud environments frequently rely on long-lived credentials and manually created IAM roles.

This creates several risks:

* Credential theft
* Unauthorized role assumption
* Privilege escalation
* Trust-policy misconfiguration
* Lack of centralized governance

The objective of this platform is to replace static trust with short-lived, policy-governed identities while providing continuous visibility into IAM risk.

---

## Architecture

### Component 1: Workload Identity Federation

Purpose:

Replace static AWS credentials in CI/CD pipelines.

Controls:

* GitHub OIDC Federation
* Temporary STS credentials
* Scoped trust policies
* Repository restrictions
* Branch restrictions
* Workflow restrictions
* Environment restrictions
* Audience validation

Threats Addressed:

* Credential exfiltration
* Compromised runners
* Malicious pull requests
* Dependency confusion
* Unauthorized deployments

---

### Component 2: Cross-Account Access Governance

Purpose:

Enable secure access across AWS accounts.

Controls:

* Dedicated trust relationships
* External ID support
* Service-principal restrictions
* Confused deputy prevention
* Least-privilege role assumption

Threats Addressed:

* Cross-account abuse
* Trust boundary violations
* Unauthorized role chaining

---

### Component 3: IAM Role Vending Machine

Purpose:

Standardize creation of IAM roles.

Controls:

* Automated role provisioning
* Permission boundary attachment
* Approved trust templates
* Policy validation
* SCP enforcement

Threats Addressed:

* Privilege escalation
* Excessive permissions
* Role creation bypasses

---

### Complementary Project: IAM Drift Detection (separate repository)

Purpose:

Continuously identify identity risk introduced after deployment.

Controls:

* CloudTrail monitoring
* EventBridge automation
* IAM graph analysis
* Privilege escalation detection
* Trust-policy drift detection

Threats Addressed:

* Unauthorized permission expansion
* Policy drift
* Shadow admin creation

---

## Design Decisions

### Why OIDC Instead of Static Credentials?

Short-lived STS credentials reduce credential persistence and eliminate secret rotation overhead.

### Why Permission Boundaries?

Permission boundaries establish a maximum permission ceiling regardless of attached policies.

### Why Separate Detection From Prevention?

Preventive controls reduce risk before deployment.

Detection controls identify risks introduced through operational drift.

A mature security platform requires both.

---

## Intended Security Properties and Current Limits

* The OIDC example creates a repository-and-branch-scoped trust policy; the GitHub Actions workflow validates the short-lived role-assumption path when configured with an AWS role ARN.
* The cross-account example requires an ExternalId, but the role permissions and caller identity still require environment-specific review.
* The role-vending Lambda is a prototype. Its requested-action/resource policy model and its own execution-role permissions need further hardening before production use.
* IAM drift detection is implemented separately; it is not deployed or integrated by this repository.

---

## Future Enhancements

* Agent Identity Scoping
* Runtime Session Policies
* Temporary Agent Permissions
* AI Agent Authorization Controls
* Risk-Based Access Decisions


## Local Validation

The validator tests use synthetic input and do not call AWS:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q tests/
python -m py_compile build-1.3-permission-boundary-vending/lambda/*.py
```

The OIDC workflow is restricted to pushes to `main`; it requires an `AWS_ROLE_ARN` repository secret and a matching AWS trust policy. Pull requests run offline validation only and do not receive `id-token: write`.
