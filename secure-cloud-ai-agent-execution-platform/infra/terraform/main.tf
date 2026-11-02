locals {
  gateway_service_account = "agent-gateway"
  router_service_account  = "inference-router"
  github_subject          = var.github_oidc_subject
}

resource "aws_ecr_repository" "platform" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = {
    project    = "secure-agent-execution-platform"
    managed-by = "terraform"
  }
}

data "aws_iam_policy_document" "gateway_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer_hostpath}:sub"
      values   = ["system:serviceaccount:${var.kubernetes_namespace}:${local.gateway_service_account}"]
    }
  }
}

resource "aws_iam_role" "agent_gateway" {
  name                 = "secure-agent-gateway-${var.cluster_name}"
  assume_role_policy   = data.aws_iam_policy_document.gateway_trust.json
  description          = "MCP gateway identity; no AWS API permissions attached by default."
  max_session_duration = 3600
}

data "aws_iam_policy_document" "router_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.eks_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.eks_oidc_issuer_hostpath}:sub"
      values   = ["system:serviceaccount:${var.kubernetes_namespace}:${local.router_service_account}"]
    }
  }
}

resource "aws_iam_role" "inference_router" {
  name                 = "secure-agent-inference-router-${var.cluster_name}"
  assume_role_policy   = data.aws_iam_policy_document.router_trust.json
  description          = "Inference router can invoke only the configured Bedrock model."
  max_session_duration = 3600
}

data "aws_iam_policy_document" "router_bedrock" {
  statement {
    sid       = "InvokeOnlyApprovedFoundationModel"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
    resources = [var.bedrock_model_arn]
  }
}

resource "aws_iam_role_policy" "router_bedrock" {
  name   = "invoke-approved-model-only"
  role   = aws_iam_role.inference_router.id
  policy = data.aws_iam_policy_document.router_bedrock.json
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.github_subject]
    }
  }
}

resource "aws_iam_role" "github_publisher" {
  name                 = "secure-agent-github-publisher"
  assume_role_policy   = data.aws_iam_policy_document.github_trust.json
  description          = "Protected GitHub workflow can publish to one ECR repository."
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_ecr" {
  statement {
    sid       = "GetRegistryAuthorization"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "PublishOnlyPlatformRepository"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:CompleteLayerUpload",
      "ecr:InitiateLayerUpload",
      "ecr:PutImage",
      "ecr:UploadLayerPart",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer"
    ]
    resources = [aws_ecr_repository.platform.arn]
  }
}

resource "aws_iam_role_policy" "github_ecr" {
  name   = "publish-one-ecr-repository"
  role   = aws_iam_role.github_publisher.id
  policy = data.aws_iam_policy_document.github_ecr.json
}
