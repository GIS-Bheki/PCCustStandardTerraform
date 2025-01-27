# IDENTITY AND ACCESS MANAGEMENT
output "iam_account_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_iam_account.csrs_id
}
output "iam_policy_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_iam_policy.csrs_id
}
output "iam_service_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_iam_service.csrs_id
}
# STORAGE
output "storage_object_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_storage_object.csrs_id
}
output "storage_file_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_storage_file.csrs_id
}
output "storage_block_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_storage_block.csrs_id
}
# COMPUTE
output "compute_config_services_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_config_services.csrs_id
}
output "compute_containers_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_containers.csrs_id
}
output "compute_messaging_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_messaging.csrs_id
}
output "compute_serverless_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_serverless.csrs_id
}
output "compute_virtual_machines_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_virtual_machines.csrs_id
}
output "compute_web_app_svcs_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_compute_web_app_services.csrs_id
}
# NETWORKING
output "networking_dns_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_networking_dns.csrs_id
}
output "networking_firewall_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_networking_firewall.csrs_id
}
output "networking_routing_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_networking_routing.csrs_id
}
# DATA SERVICES
output "data_svcs_analytics_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_data_services_analytics.csrs_id
}
output "data_svcs_cognitive_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_data_services_cognitive.csrs_id
}
output "data_svcs_database_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_data_services_database.csrs_id
}
# LOGGING AND MONITORING
output "logging_monitoring_mgmnt_plane_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_logging_monitoring_mgmnt_plane.csrs_id
}
# SECURITY SERVICES
output "sec_services_cryptography_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_sec_services_cyrptography.csrs_id
}
output "sec_services_platform_security_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_sec_services_platform_security.csrs_id
}
output "sec_services_resource_security_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_sec_services_resource_security.csrs_id
}
output "sec_services_secrets_csrs_id" {
  value = prismacloud_compliance_standard_requirement_section.csrs_sec_services_secrets.csrs_id
}