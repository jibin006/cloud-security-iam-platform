# Kubernetes deployment template

This is a deployment template, not evidence of a live EKS deployment.

## Preconditions

1. Existing EKS cluster with OIDC provider and Pod Identity / IRSA support.
2. Apply Terraform and set the inference-router service-account annotation to the returned role ARN.
3. Replace the image tag in deployments.yaml with an immutable release tag or digest.
4. Provision a per-run or per-agent PVC named agent-workspace. Do not mount one shared writable repository volume into multiple mutually untrusted agents.
5. Provision the Kubernetes Secret agent-gateway-signing through an external secret manager. Never commit signing material to Git.
6. Restrict ingress to a trusted platform ingress controller and require TLS before requests reach the namespace.

The agent runtime has no Kubernetes service-account token, no cloud identity, no workspace mount and no internet egress. It forwards proposed tool calls to the MCP gateway. The gateway has no AWS API permissions in this template. A separately deployed inference router uses a role limited to the configured Bedrock model.

## Apply

~~~bash
kubectl apply -f namespace.yaml
kubectl apply -f service-accounts.yaml
kubectl apply -f deployments.yaml
kubectl apply -f network-policies.yaml
~~~

Apply the Cilium policy only when Cilium is installed and the inference-router deployment exists. Kubernetes NetworkPolicy does not provide hostname/FQDN filtering by itself.

## Runtime checks

- Confirm both deployments run as UID 10001, read-only root filesystem, RuntimeDefault seccomp, no privilege escalation and all Linux capabilities dropped.
- Confirm the agent-runtime service account does not mount a token and has no IAM role annotation.
- Confirm agent-runtime egress succeeds only to the MCP gateway and cluster DNS.
- Confirm gateway ingress accepts only agent-runtime pods.
- Confirm gateway cannot call AWS APIs using its own service account.
- Confirm the inference-router role cannot invoke an unapproved model ARN.
- Run an adversarial tool request that attempts to read /etc/passwd, write outside src/, call an unregistered tool, or use a revoked identity; all must be denied.
