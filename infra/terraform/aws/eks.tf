resource "aws_iam_role" "cluster" {
  name = "samiir-fatma-eks"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "eks.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "main" {
  name     = "samiir-fatma-${var.environment}"
  version  = var.eks_version
  role_arn = aws_iam_role.cluster.arn
  vpc_config {
    subnet_ids              = aws_subnet.app[*].id
    endpoint_private_access = true
    endpoint_public_access  = length(var.admin_cidrs) > 0
    public_access_cidrs     = var.admin_cidrs
  }
  encryption_config {
    provider { key_arn = aws_kms_key.platform.arn }
    resources = ["secrets"]
  }
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  access_config { authentication_mode = "API" }
}

resource "aws_iam_role" "nodes" {
  name = "samiir-fatma-nodes"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "nodes" {
  for_each   = toset(["AmazonEKSWorkerNodePolicy", "AmazonEKS_CNI_Policy", "AmazonEC2ContainerRegistryReadOnly"])
  role       = aws_iam_role.nodes.name
  policy_arn = "arn:aws:iam::aws:policy/${each.value}"
}

locals {
  node_groups = {
    apps     = { instance = "m7g.large", min = 3, max = 12, taint = null }
    scanners = { instance = "c7g.large", min = 1, max = 4, taint = "scanners" }
    sandbox  = { instance = "c7g.large", min = 1, max = 4, taint = "sandbox" }
  }
}

resource "aws_eks_node_group" "groups" {
  for_each        = local.node_groups
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = aws_subnet.app[*].id
  instance_types  = [each.value.instance]
  ami_type        = "BOTTLEROCKET_ARM_64"
  scaling_config {
    desired_size = each.value.min
    min_size     = each.value.min
    max_size     = each.value.max
  }
  labels = { workload = each.key }
  dynamic "taint" {
    for_each = each.value.taint == null ? [] : [each.value.taint]
    content {
      key    = "workload"
      value  = taint.value
      effect = "NO_SCHEDULE"
    }
  }
}
