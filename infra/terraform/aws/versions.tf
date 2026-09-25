terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  # Remote state with locking and encryption (bucket/table created out of band).
  backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags { tags = { project = "samiir-fatma", environment = var.environment } }
}
