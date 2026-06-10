# Security Requirements

## SR-1: Centralized Role Creation

Developers must not be able to create IAM roles directly.

## SR-2: Mandatory Permission Boundary

Every role created by the vending machine must have the approved permission boundary attached at creation time.

## SR-3: Boundary Removal Protection

Vended roles must not be able to remove or modify their own permission boundary.

## SR-4: IAM Privilege Escalation Prevention

Vended roles must not be able to create users, roles, policies, policy versions, or access keys.

## SR-5: Trust Policy Validation

Only approved AWS service principals may be trusted.

## SR-6: Evidence-Based Validation

Every security control must be validated through attack simulation and documented evidence.

## SR-7: SCP Enforcement

Direct IAM role creation outside the vending machine must be blocked by SCP.
