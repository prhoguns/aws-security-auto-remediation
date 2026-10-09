terraform {
  required_version = ">= 1.9"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 6.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { project = "aws-security-auto-remediation", managed_by = "terraform" }
  }
}
