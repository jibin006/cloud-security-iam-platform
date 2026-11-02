# Terraform deployment contract

This module targets an **existing** EKS cluster. It does not create a VPC or EKS control plane.

## Inputs that must be discovered, not guessed

- EKS OIDC provider ARN and issuer hostpath from the target cluster.
- GitHub OIDC provider ARN.
- Exact GitHub subject claim for the protected workflow. GitHub introduced immutable subject claims for some repositories in July 2026; do not assume a name-only subject. Inspect the actual token claim or follow current GitHub OIDC documentation.
- Exact Bedrock model or inference-profile ARN.

The GitHub role trust policy uses exact audience and subject conditions. The EKS gateway role receives no AWS permissions. The separate inference-router role can invoke only the explicitly supplied Bedrock model ARN.

## Commands

~~~bash
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -out=tfplan
~~~

Review the plan and IAM trust documents before applying. No terraform apply is performed by this project. Configure the agent-gateway service account with the gateway role ARN and the inference-router service account with the router role ARN through the Kubernetes annotations shown in k8s/service-accounts.yaml.

The GitHub publisher role is a sample for a separately protected release workflow. It is not automatically assumed by the PR workflow.

## Residual controls

- EKS access entries / Kubernetes RBAC are managed separately and must bind only the intended service accounts.
- The model router must not accept arbitrary model ARNs from the agent.
- ECR uses immutable tags and scan-on-push. Deployment admission must still verify the image digest and signature.
