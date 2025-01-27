terraform {
  required_providers {
    prismacloud = {
      source  = "paloaltonetworks/prismacloud"
      version = "1.6.0"
    }
  }
  required_version = ">= 1.1.0"
}