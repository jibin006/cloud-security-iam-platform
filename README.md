# cloud-security-iam-platform


## Overview

Cloud environments often suffer from fragmented identity controls:

* Static credentials embedded in CI/CD systems
* Inconsistent cross-account access patterns
* Excessively privileged IAM roles
* Limited visibility into permission drift and privilege escalation paths

This project implements a cloud-native IAM platform that prevents, governs, and monitors identity access across AWS environments.

The platform consists of four integrated security systems:

1. Workload Identity Federation
2. Cross-Account Access Governance
3. IAM Role Vending Machine
4. IAM Drift Detection

Together these controls establish secure identity boundaries, enforce least privilege, and continuously detect unauthorized changes.

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

### Component 4: IAM Drift Detection

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

## Security Outcomes

* Eliminated long-lived CI/CD credentials
* Enforced least-privilege role creation
* Standardized cross-account trust
* Reduced privilege-escalation opportunities
* Enabled continuous IAM governance

---

## Future Enhancements

* Agent Identity Scoping
* Runtime Session Policies
* Temporary Agent Permissions
* AI Agent Authorization Controls
* Risk-Based Access Decisions
