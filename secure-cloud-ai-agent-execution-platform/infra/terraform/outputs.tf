output "ecr_repository_url" {
  description = "Immutable-tag ECR repository for platform images."
  value       = aws_ecr_repository.platform.repository_url
}
output "agent_gateway_role_arn" {
  description = "IRSA role for MCP gateway; intentionally no AWS permissions."
  value       = aws_iam_role.agent_gateway.arn
}
output "inference_router_role_arn" {
  description = "IRSA role restricted to configured Bedrock model."
  value       = aws_iam_role.inference_router.arn
}
output "github_publisher_role_arn" {
  description = "OIDC role that can publish only to the platform ECR repository."
  value       = aws_iam_role.github_publisher.arn
}
