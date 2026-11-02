variable "aws_region" {
  description = "AWS region for the workload platform."
  type        = string
  default     = "us-east-1"
}
variable "cluster_name" { type = string }
variable "eks_oidc_provider_arn" { type = string }
variable "eks_oidc_issuer_hostpath" { type = string }
variable "github_oidc_provider_arn" { type = string }
variable "github_oidc_subject" {
  description = "Exact GitHub token subject claim observed for the protected workflow. No wildcards."
  type        = string
  validation {
    condition     = length(var.github_oidc_subject) > 10 && !strcontains(var.github_oidc_subject, "*")
    error_message = "github_oidc_subject must be an exact, non-wildcard subject claim."
  }
}
variable "bedrock_model_arn" { type = string }
variable "ecr_repository_name" {
  type    = string
  default = "secure-agent-execution-platform"
}
variable "kubernetes_namespace" {
  type    = string
  default = "agent-platform"
}
