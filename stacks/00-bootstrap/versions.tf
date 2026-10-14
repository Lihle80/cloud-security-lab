terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }

  # Bootstrap intentionally uses local state: it creates the very bucket that
  # every other stack uses as a backend. Commit the resulting state file only
  # if you accept that it contains no secrets (it does not), otherwise keep it
  # out of git and re-import on demand.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}
