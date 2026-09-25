variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "backup_region" {
  type    = string
  default = "eu-central-1"
}

variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "azs" {
  type    = list(string)
  default = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

variable "db_instance_class" {
  type    = string
  default = "db.r7g.large"
}

variable "redis_node_type" {
  type    = string
  default = "cache.r7g.large"
}

variable "eks_version" {
  type    = string
  default = "1.33"
}

variable "admin_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to reach the EKS API endpoint (CI runners, bastion/VPN)."
}
