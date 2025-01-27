# STANDARD - SBSA PLATFORM COMPLIANCE
module "cs_platform" {
  source         = "./modules/standard"
  cs_name        = "Standard Bank Compliance - Platform"
  cs_description = "Standard Bank Group standard to verify the compliance of the cloud resources that are managed by Platform Team"
}

# STANDARD - SBSA FOUNDATIONAL COMPLIANCE
module "cs_foundational" {
  source         = "./modules/standard"
  cs_name        = "Standard Bank Compliance - Foundational"
  cs_description = "Standard Bank Group standard to verify the compliance of the cloud resources that are managed by the Foundation Team"
}

# STANDARD - SBSA APPLICATION COMPLIANCE
module "cs_application" {
  source         = "./modules/standard"
  cs_name        = "Standard Bank Compliance - Application"
  cs_description = "Standard Bank Group standard to verify the compliance of the cloud resources that are managed by the Application team"
}

# STANDARD - SB ENCRYPTION (World Map Dashboard)
module "cs_encryption_wmd" {
  source         = "./modules/standard"
  cs_name        = "SBG Encryption"
  cs_description = "Standard Bank Group standard created to report the encryption compliance of cloud resources into the World Map Dashboard"
}