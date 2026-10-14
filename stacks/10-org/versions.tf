terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }

  # Partial backend configuration: the bucket name contains the account ID,
  # so it is supplied at init time rather than committed.
  #   terraform init -backend-config=../../backend.hcl
  backend "s3" {
    key          = "10-org/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}
