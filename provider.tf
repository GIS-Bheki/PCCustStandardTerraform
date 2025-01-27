terraform {
  backend "azurerm" {
    resource_group_name  = "SAN-AzureSecurityTestTools-DEV"
    storage_account_name = "sansasbgcloudsecurity"
    container_name       = "tfstate"
    key                  = "YDCXnTI1GXwB5gioO8fcqdDRjlF6r4EbDW9jpky6Cty6LFqIPRAO15+ZjIUyxUHq/41eRCDFX3Dy+ASt3iC7hA=="
  }

  required_providers {
    prismacloud = {
      source  = "paloaltonetworks/prismacloud"
      version = "1.6.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
  }
  required_version = ">= 1.1.0"
}

provider "prismacloud" {
  url                       = "api2.eu.prismacloud.io"
  username                  = var.prismacloud_username
  password                  = var.prismacloud_password
  customer_name             = "Standard Bank Group Limited"
  skip_ssl_cert_verification = true
  logging = {
    action  = true
    send    = true
    receive = true
  }
}