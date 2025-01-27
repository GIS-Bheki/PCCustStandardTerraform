###############################################
# STANDARD
###############################################

resource "prismacloud_compliance_standard" "cs" {
  name        = var.cs_name
  description = var.cs_description
}

###############################################
# STANDARD REQUIREMENTS
###############################################

# IDENTITY AND ACCESS MANAGEMENT
resource "prismacloud_compliance_standard_requirement" "csr_iam" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Identity and Access Management"
  description    = ""
  requirement_id = "1"
}
# STORAGE
resource "prismacloud_compliance_standard_requirement" "csr_storage" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Storage"
  description    = ""
  requirement_id = "2"
}
# COMPUTE
resource "prismacloud_compliance_standard_requirement" "csr_compute" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Compute"
  description    = ""
  requirement_id = "3"
}
# NETWORKING
resource "prismacloud_compliance_standard_requirement" "csr_networking" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Networking"
  description    = ""
  requirement_id = "4"
}
# DATA SERVICES
resource "prismacloud_compliance_standard_requirement" "csr_data_services" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Data Services"
  description    = ""
  requirement_id = "5"
}
# LOGGING AND MONITORING
resource "prismacloud_compliance_standard_requirement" "csr_logging_monitoring" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Logging and Monitoring"
  description    = ""
  requirement_id = "6"
}
# SECURITY SERVICES
resource "prismacloud_compliance_standard_requirement" "csr_sec_services" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Security Services"
  description    = ""
  requirement_id = "7"
}

###############################################
# STANDARD REQUIREMENT SECTIONS 
###############################################

# IDENTITY AND ACCESS MANAGEMENT
resource "prismacloud_compliance_standard_requirement_section" "csrs_iam_account" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "Account"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_iam_policy" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "Policy"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_iam_service" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "Service"
  description = ""
}
# STORAGE
resource "prismacloud_compliance_standard_requirement_section" "csrs_storage_block" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Block Storage"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_storage_file" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "File Storage"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_storage_object" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Object Storage"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_storage_database" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Databases"
  description = ""
}
# COMPUTE
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_config_services" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Configuration Services"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_containers" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Containers"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_messaging" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Messaging"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_serverless" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Serverless"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_virtual_machines" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Virtual Machines"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_compute_web_app_services" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Web/App Services"
  description = ""
}
# NETWORKING
resource "prismacloud_compliance_standard_requirement_section" "csrs_networking_dns" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "DNS"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_networking_firewall" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Firewall"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_networking_routing" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Routing"
  description = ""
}
# DATA SERVICES
resource "prismacloud_compliance_standard_requirement_section" "csrs_data_services_analytics" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_data_services.csr_id
  section_id  = "Analytics"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_data_services_cognitive" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_data_services.csr_id
  section_id  = "Cognitive"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_data_services_database" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_data_services.csr_id
  section_id  = "Database"
  description = ""
}
# LOGGING AND MONITORING
resource "prismacloud_compliance_standard_requirement_section" "csrs_logging_monitoring_mgmnt_plane" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_logging_monitoring.csr_id
  section_id  = "Management Plane"
  description = ""
}
# SECURITY SERVICES
resource "prismacloud_compliance_standard_requirement_section" "csrs_sec_services_cyrptography" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_sec_services.csr_id
  section_id  = "Cryptography"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_sec_services_platform_security" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_sec_services.csr_id
  section_id  = "Platform Security"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_sec_services_resource_security" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_sec_services.csr_id
  section_id  = "Resource Security"
  description = ""
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_sec_services_secrets" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_sec_services.csr_id
  section_id  = "Secrets"
  description = ""
}