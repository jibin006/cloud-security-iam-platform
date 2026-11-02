# Secure Cloud & AI Agent Execution Platform

**An integrated cloud-security and agent-security engineering lab.**

This flagship project demonstrates a governed execution path for AI agents: cloud workload identity, policy-controlled MCP tools, constrained workspace access, per-agent budgets, Kubernetes isolation, infrastructure guardrails, supply-chain controls, telemetry, containment, and adversarial tests.

> **Maturity:** active engineering prototype. The local control-plane core and adversarial tests are executable. Terraform and Kubernetes are reference deployment assets and must be validated in a dedicated AWS/EKS sandbox before production use. No production credentials or live model API are required for the default test path.

## The security thesis

An agent must not gain authority merely because a model requested an action. Every tool invocation is authenticated, authorized against server-side policy, budgeted, constrained to an explicit workspace capability, and recorded in an append-only hash-linked audit log. Prompt content is data, not policy.

The core separation is:

- **Agent runtime:** receives untrusted prompts and proposes tool calls; holds no cloud credentials.
- **Identity broker:** issues short-lived, scoped agent identities.
- **MCP gateway:** validates identity, policy, budgets, and tool arguments before executing a narrow capability.
- **Workspace service:** confines file access to approved paths; rejects traversal, symlink escape, and protected configuration changes.
- **Cloud router / platform identity:** owns workload identity and approved provider connectivity.
- **Kubernetes platform:** applies process, filesystem, network, and workload boundaries.
- **Independent evidence plane:** records allow/deny decisions and supports containment.

## Architecture

~~~text
 GitHub Actions (OIDC)                 AWS IAM / EKS workload identity
          |                                           |
          v                                           v
 Terraform + policy checks  ----->  Platform Identity / Inference Router
          |                                           |
          |                                  short-lived agent identity
          |                                           |
          v                                           v
   Signed image + SBOM                       MCP Tool Gateway
                                                     |
                         +---------------------------+---------------------+
                         |                           |                     |
                         v                           v                     v
                  Tool Policy                  Budget Guard          Audit Chain
                         |                           |                     |
                         +---------------------------+---------------------+
                                                     |
                                              Capability execution
                                                     |
                           +-------------------------+------------------+
                           |                                            |
                           v                                            v
                  Workspace boundary                           Runtime status
             (read roots / patch roots only)                           |
                           |                                            v
                           v                                    Containment control
                  Untrusted repository data
~~~

The Kubernetes manifests place the agent runtime and MCP gateway in separate pods. The agent receives no service-account token and is allowed to reach only the gateway. The gateway owns the approved egress path. Vanilla Kubernetes NetworkPolicy is L3/L4; hostname-based egress requires a CNI capability such as Cilium FQDN policy or an explicit egress proxy.

## Implemented vertical slice

The default local path runs without AWS, Kubernetes, an LLM provider, or network access:

1. Issue an HMAC-signed, short-lived agent identity with explicit scopes.
2. Verify issuer, audience, expiry, signature, revocation and requested scopes.
3. Authorize MCP tool calls using server-side role/scope policy.
4. Enforce per-agent request and token budgets.
5. Read files only from approved roots and write patches only under src/.
6. Reject traversal, absolute paths, symlinks escaping the workspace, and protected paths such as .env, .github/, infra/, k8s/, and policies/.
7. Record policy decisions in a hash-linked audit log.
8. Suspend an agent identity and deny subsequent calls.
9. Run adversarial tests for identity forgery, policy bypass, traversal, symlink escape, budget exhaustion, audit tampering and containment.

## Repository map

| Area | What it demonstrates |
|---|---|
| secure_agent/ | Identity, authorization, budgets, audit chain, workspace confinement, MCP gateway and containment |
| tests/ | Unit and adversarial regression tests |
| policies/ | Explicit tool authorization and budget policy |
| infra/terraform/ | GitHub Actions OIDC and EKS workload-identity trust examples |
| infra/policies/ | OPA/Conftest guardrails for Terraform plans |
| k8s/ | Namespace, restricted workloads, NetworkPolicies and Cilium egress policy example |
| supply-chain/ | Container build, SBOM, vulnerability gate and digest-signing contract |
| observability/ | Falco detection rules and event contract |
| docs/ | Architecture, threat model, ADRs and operational runbooks |

## Run locally

Requirements: Python 3.11+ and pytest (no cloud credentials needed).

~~~bash
cd secure-cloud-ai-agent-execution-platform
python -m pip install -e ".[dev]"
make verify
make demo
~~~

The demo creates an isolated temporary workspace, issues a short-lived identity, reads an approved file, and demonstrates denied actions. It does not execute a shell command or contact an external service.

## Security verification

~~~bash
make test
make lint
make terraform-check
make verify
~~~

Expected negative tests are successful tests: an unauthorized tool call, path escape, revoked token, exhausted budget, or tampered audit record must be rejected.

## Important design boundaries and limitations

- The local HMAC identity signer is for deterministic development tests. Production identity must use a managed asymmetric signing key (for example AWS KMS), key rotation, issuer separation, and a durable revocation store.
- The in-memory budget counter is a test implementation. Production budgets require atomic shared storage and tenant-level concurrency controls.
- The local hash chain detects modification but does not make local disk immutable. Production audit events must be exported to an independently administered append-only backend.
- A policy decision is not a sandbox. The Kubernetes manifests are defence-in-depth examples and require runtime validation, RBAC review, CNI enforcement and image policy.
- This project does not claim that prompt injection can be eliminated. It constrains what an injected agent can do and records denied attempts.
- The MCP stdio adapter is a local development transport. In production, place the gateway behind authenticated service-to-service transport; do not expose a reusable token to the untrusted agent process.
- Human approval and release authority are separate from patch creation. The agent cannot approve or deploy its own change.

## Reference

The design is informed by Microsoft's discussion of secure AI-agent infrastructure with kars: [From AI Infrastructure to Secure AI Agent Infrastructure with kars](https://techcommunity.microsoft.com/blog/AzureDevCommunityBlog/from-ai-infrastructure-to-secure-ai-agent-infrastructure-with-kars/4551519). This repository implements a small, independent teaching platform; it does not embed or claim compatibility with kars.

## Resume evidence policy

Only claim controls that have passed the corresponding test or sandbox validation. Do not claim production deployment, exploitable-risk reduction, attack prevention rates, or operational impact based only on local unit tests.
