###############################################
# AZURE DEFAULT POLICIES
###############################################

# Azure subscriptions with custom roles are overly permissive
module "policy_azure_subs_custom_roles_overly_permissive" {
  source                  = "./modules/policy_default"
  default_policy_id       = "40c06b29-589e-4f1f-8c02-8dafdc80cce6"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_account_csrs_id,module.cs_foundational.iam_account_csrs_id]
}

# Azure AD Users can consent to apps accessing company data on their behalf is enabled
module "policy_azure_ad_user_app_company_data_access_consent_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "84bbc52e-b321-44b7-9c0a-13b34c875f1e"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_account_csrs_id,module.cs_foundational.iam_account_csrs_id]
}

# Azure AKS enable role-based access control (RBAC) not enforced
module "policy_azure_aks_rbac_not_enforced" {
  source                  = "./modules/policy_default"
  default_policy_id       = "3b6626af-9601-4e99-ace5-7197cba0d37d"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# Azure SQL server not configured with Active Directory admin authentication
module "policy_azure_sql_server_no_ad_admin_config" {
  source                  = "./modules/policy_default"
  default_policy_id       = "4d2615bb-091e-48fd-87b7-77a277d7d2fd"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Key Vault secret has no expiration date (RBAC Key vault)
module "policy_azure_kv_secret_no_expiration_date" {
  source                  = "./modules/policy_default"
  default_policy_id       = "1da48a52-fc22-414f-a1bb-f864d7fdfc77"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_secrets_csrs_id,module.cs_foundational.sec_services_secrets_csrs_id]
}

# Azure Custom Role Administering Resource Locks not assigned
module "policy_azure_custom_role_administering_rsrce_locks_unassigned" {
  source                  = "./modules/policy_default"
  default_policy_id       = "bc47859c-edf2-4485-808b-2b60b3893e4f"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_account_csrs_id, module.cs_foundational.iam_account_csrs_id]
}


# Azure Storage Account using insecure TLS version
module "policy_azure_storage_acct_insecure_tls_version" {
  source                  = "./modules/policy_default"
  default_policy_id       = "91389569-c060-44e0-9aef-f13dba594f3c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure Storage accounts soft delete is disabled
module "policy_azure_storage_acct_soft_delete_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "f5a29936-659e-48a8-8110-783411bf6a9c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure AKS cluster HTTP application routing enabled
module "policy_azure_aks_cluster_http_app_routing_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0429670c-5d2d-4d0f-ab33-59eb5e000305"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# Azure Virtual Machines are not utilising Managed Disks
module "policy_azure_vms_not_utilising_managed_disks" {
  source                  = "./modules/policy_default"
  default_policy_id       = "5bb0ad91-f321-452d-9f9c-3efa2752a8be"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_application.compute_virtual_machines_csrs_id]
}

# Azure VM data disk is encrypted with the default encryption key instead of ADE/CMK
module "policy_azure_vm_disk_default_encryption_instead_of_ade_cmk" {
  source                  = "./modules/policy_default"
  default_policy_id       = "9ff0cb83-da37-40fb-8ba5-011d104393b4"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.compute_virtual_machines_csrs_id,module.cs_foundational.compute_virtual_machines_csrs_id]
}

# Azure disk is unattached and is encrypted with the default encryption key instead of ADE/CMK
module "policy_azure_disk_unattached_default_encryption_instead_of_ade_cmk" {
  source                  = "./modules/policy_default"
  default_policy_id       = "a1f899e5-0ff9-4883-a121-75c68cab532a"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.storage_block_csrs_id, module.cs_foundational.storage_block_csrs_id]
}

# Azure VM OS disk is encrypted with the default encryption key instead of ADE/CMK
module "policy_azure_vm_os_disk_default_encryption_instead_of_ade_cmk" {
  source                  = "./modules/policy_default"
  default_policy_id       = "bfb072a7-f602-47ad-89ac-a3eb61d3427e"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.compute_virtual_machines_csrs_id, module.cs_foundational.compute_virtual_machines_csrs_id]
}

# Azure Application Gateway is configured with SSL policy having TLS version 1.1 or lower

module "policy_azure_app_gw_allows_tlsv1_1_or_lower" {
  source                  = "./modules/policy_default"
  default_policy_id       = "8bf20934-38d6-419e-9e0e-b0c7b0c1d238"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Application Gateway does not have the Web application firewall (WAF) enabled
module "policy_azure_app_gw_no_web_app_fw_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "927d2db7-ae6f-4122-bc61-cdbc14c71d7d"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure App Service Web app doesn't use latest .Net Core version
module "policy_azure_web_app_not_using_latest_dot_net_core_version" {
  source                  = "./modules/policy_default"
  default_policy_id       = "629133a3-6e81-4288-bd38-e81cb5b708de"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure App Service Web app doesn't use latest PHP version
module "policy_azure_web_app_not_using_latest_php_version" {
  source                  = "./modules/policy_default"
  default_policy_id       = "15ce114a-1f16-4d0a-9ad3-1e674dcd9525"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure App Service Web app doesn't use latest Python version
module "policy_azure_not_using_latest_python_version" {
  source                  = "./modules/policy_default"
  default_policy_id       = "2ca02092-5798-4cee-81cd-add4456253d3"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure App Service Web app doesn't use latest Java version 
module "policy_azure_web_app_not_using_latest_java_version" {
  source                  = "./modules/policy_default"
  default_policy_id       = "1accd873-5ac3-4ff6-9729-b0464cb5cf12"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure App Services FTP deployment is All allowed
module "policy_azure_ftp_deployment_is_all_allowed" {
  source                  = "./modules/policy_default"
  default_policy_id       = "7fa164f0-fb0d-40a1-8293-8192f64eed81"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Network Security Group allows all traffic on CIFS (UDP Port 445)
module "policy_azure_nsg_allows_all_traffic_on_cifs_port_445" {
  source                  = "./modules/policy_default"
  default_policy_id       = "bc7929f8-fe70-48ec-8690-4288aa0b98ae"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on FTP (TCP Port 21)
module "policy_azure_nsg_allows_all_traffic_on_ftp_port_21" {
  source                  = "./modules/policy_default"
  default_policy_id       = "472e08a2-c741-43eb-a3ca-e2f5cd275cf7"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on FTP-Data (TCP Port 20)
module "policy_azure_nsg_allows_all_traffic_on_ftp_data_port_20" {
  source                  = "./modules/policy_default"
  default_policy_id       = "f48eda6b-5d66-4d73-a62e-671de3844555"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_firewall_csrs_id, module.cs_foundational.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on ICMP (Ping)
module "policy_azure_nsg_allows_all_traffic_on_icmp_ping" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0a3f1d49-4c05-47c4-98e2-3a42b822d05b"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on MSQL (TCP Port 4333)
module "policy_azure_allows_all_traffic_on_msql_port_4333" {
  source                  = "./modules/policy_default"
  default_policy_id       = "5826e50f-2f29-4444-9cad-3bb4e66ee3ca"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on MySQL (TCP Port 3306)
module "policy_azure_nsg_allows_all_traffic_on_mysql_port_3306" {
  source                  = "./modules/policy_default"
  default_policy_id       = "5dbd0da1-cfa4-4bce-a753-56dade428bd4"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on NetBIOS (UDP Port 137)
module "policy_azure_nsg_allows_all_traffic_on_netbios_port_137" {
  source                  = "./modules/policy_default"
  default_policy_id       = "18e1dd76-9d0f-4cdb-96d4-9d01b5cd68dc"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# # Azure Network Security Group allows all traffic on NetBIOS (UDP Port 138)  Bheki1
# module "policy_azure_nsg_allows_all_traffic_on_netbios_port_138" {
#   source                  = "./modules/policy_default"
#   default_policy_id       = "3784cdfd-dd25-4cf3-b506-ad77033ccc35"
#   naming_prefix           = var.naming_prefix
#   policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
#   policy_enabled          = true
#   compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
# }

# Azure Network Security Group allows all traffic on NetBIOS DNS (TCP Port 53)
module "policy_azure_nsg_allows_all_traffic_on_netbios_dns_port_53_tcp" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0c620876-4549-46c4-a5b3-16e86e3cefe7"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on NetBIOS DNS (UDP Port 53)
module "policy_azure_nsg_allows_all_traffic_on_netbios_dns_port_53_udp" {
  source                  = "./modules/policy_default"
  default_policy_id       = "709b47cd-6b7a-4500-b99e-a58529a6c79e"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on PostgreSQL (TCP Port 5432)
module "policy_azure_nsg_allows_all_traffic_on_posgresql_port_5432" {
  source                  = "./modules/policy_default"
  default_policy_id       = "a0791206-a669-4948-a845-cc735212013c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on SMTP (TCP Port 25)
module "policy_azure_nsg_allows_all_traffic_on_smtp_port_25" {
  source                  = "./modules/policy_default"
  default_policy_id       = "ac851899-1007-48c8-842f-dddb9a38c4ba"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on SQL Server (TCP Port 1433)
module "policy_azure_nsg_allows_all_traffic_on_sql_server_port_1433_tcp" {
  source                  = "./modules/policy_default"
  default_policy_id       = "3aa12e75-d78b-4157-9eca-6049187a30d7"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# # Azure Network Security Group allows all traffic on SQL Server (UDP Port 1434) Bheki2
# module "policy_azure_nsg_allows_all_traffic_on_sql_server_port_1434_udp" {
#   source                  = "./modules/policy_default"
#   default_policy_id       = "0546188d-6f21-449d-948e-677c285a5fcf"
#   naming_prefix           = var.naming_prefix
#   policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
#   policy_enabled          = true
#   compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
# }



# Azure Network Security Group allows all traffic on Telnet (TCP Port 23)
module "policy_azure_nsg_allows_all_traffic_on_telnet_port_23" {
  source                  = "./modules/policy_default"
  default_policy_id       = "936dd3cb-a9cc-4a13-9a2c-ea5d40856072"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on VNC Listener (TCP Port 5500)
module "policy_azure_nsg_allows_all_traffic_on_vnc_listener_port_5500" {
  source                  = "./modules/policy_default"
  default_policy_id       = "91a53c5d-d629-45bb-9610-fbd2cb4c6f3c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on VNC Server (TCP Port 5900)
module "policy_azure_nsg_allows_all_traffic_on_vnc_server_port_5900" {
  source                  = "./modules/policy_default"
  default_policy_id       = "4cddc286-94b0-427a-8747-7f06b51d4689"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on Windows RPC (TCP Port 135)
module "policy_azure_nsg_allows_all_traffic_on_windows_rpc_port_135" {
  source                  = "./modules/policy_default"
  default_policy_id       = "4afdc071-53ca-4516-8a3c-d5c91345c409"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Network Security Group allows all traffic on Windows SMB (TCP Port 445)
module "policy_azure_nsg_allows_all_traffic_on_windows_smb_port_445" {
  source                  = "./modules/policy_default"
  default_policy_id       = "500e9f2a-1063-4066-8eea-780efa90a0d7"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure Virtual Network subnet is not configured with a Network Security Group
module "policy_azure_vntwrk_subnet_nsg_not_configured" {
  source                  = "./modules/policy_default"
  default_policy_id       = "d3ed9388-fa76-44b7-ac6f-72503b6340e0"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_firewall_csrs_id, module.cs_foundational.networking_firewall_csrs_id]
}

# Azure SQL Server allow access to any Azure internal resources
module "policy_azure_sql_server_fw_rules_open_to_any_az_internal_resrources" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0faffeb6-dbcd-4715-be6e-f9cadc64cfeb"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure PostgreSQL Database Server 'Allow access to Azure services' enabled
module "policy_azure_postgresql_db_server_allow_access_azure_svcs_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "492e32db-49f1-495d-90f8-d1f84662d210"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for SQL servers on machines
module "policy_azure_mde_for_cloud_off_for_sql_server_machines" {
  source                  = "./modules/policy_default"
  default_policy_id       = "1f3ae628-17bf-4d0b-b2d1-a0fbb61bf19c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for Azure SQL Databases
module "policy_azure_mde_for_cloud_off_for_az_sql_dbs" {
  source                  = "./modules/policy_default"
  default_policy_id       = "c3f78c20-8967-47a0-a02b-1efc3810c666"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure MySQL Database Server SSL connection is disabled
module "policy_azure_mysql_db_server_ssl_connection_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "cc96a6d0-3251-4bf9-aaa4-349c34810721"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure PostgreSQL database server Infrastructure double encryption is disabled
module "policy_azure_postgresql_db_server_infra_double_encryption_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "c4546c5c-11b3-4252-a1bd-b9ae64bb903d"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Key Vault audit logging is disabled
module "policy_azure_kv_audit_logging_is_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "56bfe7bb-ef47-4252-a335-9751a4826609"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_cryptography_csrs_id, module.cs_foundational.sec_services_cryptography_csrs_id]
}

# Azure Key vaults diagnostics logs are disabled
module "policy_azure_kv_diagnostics_logs_are_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "922d0974-a29b-42f5-91ea-99da087a1718"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_cryptography_csrs_id, module.cs_foundational.sec_services_cryptography_csrs_id]
}

# Azure Load Balancer diagnostics logs are disabled
module "policy_azure_lb_diagnostics_logs_are_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0280e32d-9366-4700-9763-a03be7196614"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.compute_web_app_svcs_csrs_id, module.cs_foundational.compute_web_app_svcs_csrs_id]
}

# Azure Monitor Diagnostic Setting does not captures appropriate categories
module "policy_azure_monitor_diagnostic_settings_not_capturing_appropriate_categories" {
  source                  = "./modules/policy_default"
  default_policy_id       = "86d9615f-9e09-4ae5-a9fa-edb6927a8eec"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id, module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
}

# Azure Monitor log profile does not capture all activities
module "policy_azure_monitor_log_profile_not_capturing_all_activities" {
  source                  = "./modules/policy_default"
  default_policy_id       = "64f0ec41-cdcb-42e4-b556-eb66946a62ff"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id, module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
}

# Azure Monitoring log profile is not configured to export activity logs
module "policy_azure_monitoring_log_profile_not_configured_to_export_activity_logs" {
  source                  = "./modules/policy_default"
  default_policy_id       = "ebdba5a4-af9e-4015-a024-e8eb650e3be3"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
}

# Azure SQL Server audit log retention is less than 91 days
module "policy_azure_sql_server_audit_log_retention_less_than_91_days" {
  source                  = "./modules/policy_default"
  default_policy_id       = "0ca00469-8223-4753-a9df-4add7c37725f"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure SQL Server auditing is disabled
module "policy_azure_sql_server_auditing_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "86eb5c4f-d384-4cb0-b5d8-7dc007bb4804"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure storage account logging for blobs is disabled
module "policy_azure_storage_acct_logging_for_blobs_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "85a4a77f-0d46-4c3d-ae8c-37d945a0b44e"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.storage_object_csrs_id, module.cs_foundational.storage_object_csrs_id]
}

# Azure storage account logging for queues is disabled
module "policy_azure_storage_acct_logging_for_queues_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "fde9482f-3ac2-43f6-bda2-bf2013074acd"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.storage_block_csrs_id, module.cs_foundational.storage_block_csrs_id]
}

# Azure storage account logging for tables is disabled
module "policy_azure_storage_acct_logging_for_tagles_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "f4784022-48f3-4f3b-bc16-2b7fef56aea3"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.storage_block_csrs_id, module.cs_foundational.storage_block_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for App Service
module "policy_azure_microsoft_defender_for_cloud_is_set_to_off_for_app_service" {
  source                  = "./modules/policy_default"
  default_policy_id       = "8953512c-4b2f-4622-a3c8-fff004bfec66"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure SQL Server ADS Vulnerability Assessment is disabled
module "policy_azure_sql_server_ads_vulnerability_assessment_is_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "b805e5f2-8479-4197-82ce-9d8fcdf38a44"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure Microsoft Defender for Cloud email notification for subscription owner is not set
module "policy_azure_microsoft_defender_for_cloud_email_notification_for_subscription_owner_is_not_set" {
  source                  = "./modules/policy_default"
  default_policy_id       = "fc914428-2c9a-4240-a3a7-769b85187278"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Key Vault secret has no expiration date (Non-RBAC Key vault)
module "policy_azure_key_vault_secret_has_no_expiration_date_non-rbac_key_vault" {
  source                  = "./modules/policy_default"
  default_policy_id       = "35761038-989f-4a9c-9000-7962ba38e643"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_secrets_csrs_id, module.cs_foundational.sec_services_secrets_csrs_id]
}

# Azure SQL Server ADS Vulnerability Assessment 'Also send email notifications to admins and subscription owners' is disabled
module "policy_azure_sql_server_ads_vulnerability_assessment_also_send_email_notifications_to_admins_and_subscription_owners_is_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "2d9ff413-f69f-484e-ba55-22ab6333c249"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure Microsoft Defender for Cloud security contact additional email is not set
module "policy_azure_microsoft_defender_for_cloud_security_contact_additional_email_is_not_set" {
  source                  = "./modules/policy_default"
  default_policy_id       = "46e24e8c-945c-4048-91f2-800cccf54613"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Resource Group does not have a resource lock
module "policy_azure_resource_group_does_not_have_a_resource_lock" {
  source                  = "./modules/policy_default"
  default_policy_id       = "375c75a8-b503-48d1-90a0-79ae6b3cf6a5"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_resource_security_csrs_id, module.cs_platform.sec_services_resource_security_csrs_id]
}

# Azure Microsoft Defender for Cloud WDATP integration Disabled
module "policy_azure_microsoft_defender_for_cloud_wdatp_integration_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "b7a63b07-551a-4813-82f5-f47b8428e0b3"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Key Vault Key has no expiration date (RBAC Key vault)
module "policy_azure_key_vault_key_has_no_expiration_date_rbac_key_vault" {
  source                  = "./modules/policy_default"
  default_policy_id       = "63505d05-b9b7-4bf3-b028-f95f8a29bc58"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_secrets_csrs_id, module.cs_foundational.sec_services_secrets_csrs_id]
}

# Azure Microsoft Defender for Cloud security alert email notifications is not set
module "policy_azure_microsoft_defender_for_cloud_security_alert_email_notifications_is_not_set" {
  source                  = "./modules/policy_default"
  default_policy_id       = "8d78bf42-4e80-4e25-89fa-5f8a7fe8ddb1"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for Servers
module "policy_azure_microsoft_defender_for_cloud_is_set_to_off_for_servers" {
  source                  = "./modules/policy_default"
  default_policy_id       = "eb5f5af1-754d-4f6b-9c08-610a6974db16"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure SQL Server ADS Vulnerability Assessment 'Send scan reports to' is not configured
module "policy_azure_sql_server_ads_vulnerability_assessment_send_scan_reports_to_is_not_configured" {
  source                  = "./modules/policy_default"
  default_policy_id       = "bfff252d-3f21-4115-978d-e1a48d8ae19c"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for Key Vault
module "policy_azure_microsoft_defender_for_cloud_is_set_to_off_for_key_vault" {
  source                  = "./modules/policy_default"
  default_policy_id       = "9706338d-291b-4937-be1e-752e251ac5a7"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure SQL Server ADS Vulnerability Assessment Periodic recurring scans is disabled
module "policy_azure_sql_server_ads_vulnerability_assessment_periodic_recurring_scans_is_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "aa62cb1d-2bcb-478b-af5c-62462f8a6cba"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure Key Vault Key has no expiration date (Non-RBAC Key vault)
module "policy_azure_key_vault_key_has_no_expiration_date_non-rbac_key_vault" {
  source                  = "./modules/policy_default"
  default_policy_id       = "5eaf1168-8476-4fad-9331-d76e41d4c80d"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_secrets_csrs_id, module.cs_foundational.sec_services_secrets_csrs_id]
}

# Azure Microsoft Defender for Cloud MCAS integration Disabled
module "policy_azure_microsoft_defender_for_cloud_mcas_integration_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "470796d2-3ed6-40a3-b26a-e882afce4090"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure Microsoft Defender for Cloud is set to Off for Storage
module "policy_azure_microsoft_defender_for_cloud_is_set_to_off_for_storage" {
  source                  = "./modules/policy_default"
  default_policy_id       = "5436f3cc-3815-44f4-ac09-b8418e1f8e1d"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure SQL server Defender setting is set to Off
module "policy_azure_sql_server_defender_setting_is_set_to_off" {
  source                  = "./modules/policy_default"
  default_policy_id       = "4169132e-ead6-4c01-b147-d2b47b443678"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.data_svcs_database_csrs_id, module.cs_foundational.data_svcs_database_csrs_id]
}

# Azure PostgreSQL database server log retention days is less than or equals to 3 days
module "policy_azure_postgresql_database_server_log_retention_days_is_less_than_or_equals_to_3_days" {
  source                  = "./modules/policy_default"
  default_policy_id       = "e7bf8164-149e-4e05-aca7-ee2e95e188d0"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure PostgreSQL database server with log duration parameter disabled
module "policy_azure_postgresql_database_server_with_log_duration_parameter_disabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "f6e50db0-4774-480f-b6c6-1126fa21a22a"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Virtual machine scale sets are not utilising Managed Disks
module "policy_azure_virtual_machine_scale_sets_are_not_utilising_managed_disks" {
  source                  = "./modules/policy_default"
  default_policy_id       = "3596e236-1c20-4f3f-be6d-a513f0da63e1"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_application.compute_virtual_machines_csrs_id]
}

# Azure AKS cluster monitoring not enabled
module "policy_azure_aks_cluster_monitoring_not_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "be55c11a-981a-4f34-a2e7-81ce40d71aa5"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# Azure AKS cluster Azure CNI networking not enabled
module "policy_azure_aks_cluster_azure_cni_networking_not_enabled" {
  source                  = "./modules/policy_default"
  default_policy_id       = "ac313c08-1f79-4e55-96e4-49c20064bff0"
  naming_prefix           = var.naming_prefix
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# Azure storage account has a blob container with public access
module "policy_azure_storage_account_has_a_blob_container_with_public_access" {
  source            = "./modules/policy_default"
  default_policy_id = "7a506ab4-d0a2-48ee-a6f5-75a97f11397d"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Storage/storageAccounts/write' permission. Successful execution disables public access in Azure storage account, this disables anonymous/public read access to a container and the blobs within Azure storage account"
    cli_script_template = "az resource update --ids $${resourceId} --set properties.allowBlobPublicAccess=false"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# Azure PostgreSQL database server with SSL connection disabled
module "policy_azure_postgresql_database_server_with_ssl_connection_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "bf4ad407-076c-40b9-a8fa-a0c80352a744"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.DBforPostgreSQL servers/configuration/*' permission. Successful execution will enable SSL enforce which helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL)."
    cli_script_template = "az postgres server update --resource-group $${resourceGroup} --name $${resourceName} --ssl-enforcement Enabled"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Network Security Group having Inbound rule overly permissive to all traffic on TCP protocol
module "policy_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_tcp_protocol" {
  source            = "./modules/policy_default"
  default_policy_id = "543c6a0a-a50c-11e8-98d0-529269fb1459"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the inbound rule records allowing all traffic from Internet on TCP protocol."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_platform.networking_firewall_csrs_id, module.cs_foundational.networking_firewall_csrs_id]
}

# Azure Storage Account default network access is set to 'Allow'
module "policy_azure_storage_account_default_network_access_is_set_to_allow" {
  source            = "./modules/policy_default"
  default_policy_id = "991aca47-286f-45be-8737-ff9c069beab6"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Storage/storageAccounts/*' permission. Successful execution will disable default network access rule for Storage Accounts.'."
    cli_script_template = "az storage account update --name $${resourceName} --resource-group $${resourceGroup} --default-action Deny"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure App Service Web app doesn't have a Managed Service Identity
module "policy_azure_app_service_web_app_doesnt_have_a_managed_service_identity" {
  source            = "./modules/policy_default"
  default_policy_id = "329e3b79-b374-4434-b7c8-4d292aa4f991"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/*' permission. Successful execution sets managed service identity in App Service, that makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings."
    cli_script_template = "az webapp identity assign --resource-group $${resourceGroup} --name $${resourceName}"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Network Security Group allows all traffic on SSH port 22
module "policy_azure_network_security_group_allows_all_traffic_on_ssh_port_22" {
  source            = "./modules/policy_default"
  default_policy_id = "3beed53c-3f2d-47b6-bb6f-95da39ff0f26"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the inbound rule records allowing SSH traffic from Internet on port 22."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure PostgreSQL database server with log connections parameter disabled
module "policy_azure_postgresql_database_server_with_log_connections_parameter_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "8673dba3-9bf5-4691-826e-b5fc7be70dad"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.DBforPostgreSQL servers/configuration/*' permission. Successful execution will enable log_connections which helps the PostgreSQL database to log attempted connection to the server, as well as successful completion of client authentication."
    cli_script_template = "az postgres server configuration set --resource-group $${resourceGroup} --server-name $${resourceName} --name log_connections --value on"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure App Service Web app doesn't use latest TLS version
module "policy_azure_app_service_web_app_doesnt_use_latest_tls_version" {
  source            = "./modules/policy_default"
  default_policy_id = "74e43b65-16bf-42a5-8d10-a0f245716cde"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/*' permission. Successful execution sets web app TLS encryption version to latest TLS version(i.e. TLS 1.2)."
    cli_script_template = "az webapp config set --resource-group $${resourceGroup} --name $${resourceName} --min-tls-version 1.2"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Storage Account without Secure transfer enabled
module "policy_storage_accounts_without_secure_transfer_enabled" {
  source            = "./modules/policy_default"
  default_policy_id = "bc4e467f-10fa-471e-aa9b-28981dc73e93"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Storage/storageAccounts/*' permission. Successful execution will enable secure transfer for this storage account."
    cli_script_template = "az storage account update --ids $${resourceId} --https-only true"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure Key Vault is not recoverable
module "policy_azure_key_vault_is_not_recoverable" {
  source            = "./modules/policy_default"
  default_policy_id = "6c9c2a98-811f-4a04-8202-51285308bad9"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.KeyVault/*' permission. Successful execution will enable Purge Protection and Soft Delete rule for Key Vault. Note: Once purge-protection and soft-delete is enabled for a key vault, the action is irreversible."
    cli_script_template = "az keyvault update --name $${resourceName} --set properties.enablePurgeProtection=true properties.enableSoftDelete=true"
  }]
  compliance_metadata_ids = [module.cs_platform.sec_services_cryptography_csrs_id, module.cs_foundational.sec_services_cryptography_csrs_id]
}

# Azure Network Security Group allows all traffic on RDP Port 3389
module "policy_azure_network_security_group_allows_all_traffic_on_rdp_port_3389" {
  source            = "./modules/policy_default"
  default_policy_id = "a36a7170-d628-47fe-aab2-0e734702373d"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the inbound rule records allowing traffic from Internet on port 3389."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure App Service Web app doesn't use HTTP 2.0
module "policy_azure_app_service_web_app_doesnt_use_http_2_0" {
  source            = "./modules/policy_default"
  default_policy_id = "4f5c4a28-c3df-4bee-a980-621c794548ed"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/*' permission. Successful execution sets HTTP version to 2.0, which has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests."
    cli_script_template = "az webapp config set --resource-group $${resourceGroup} --name $${resourceName} --http20-enabled true"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Microsoft Defender for Cloud automatic provisioning of log Analytics agent for Azure VMs is set to Off
module "policy_azure_microsoft_defender_for_cloud_automatic_provisioning_of_log_analytics_agent_for_azure_vms_is_set_to_off" {
  source            = "./modules/policy_default"
  default_policy_id = "6c5091cc-2da3-42b3-877e-42fd7d9e85d6"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Security/autoProvisioningSettings/*' permission. Successful execution will enable automatic provisioning of monitoring agent."
    cli_script_template = "az security auto-provisioning-setting update --name \"$${resourceName}\" --auto-provision \"on\""
  }]
  compliance_metadata_ids = [module.cs_platform.sec_services_platform_security_csrs_id, module.cs_foundational.sec_services_platform_security_csrs_id]
}

# Azure PostgreSQL database server with connection throttling parameter is disabled
module "policy_azure_postgresql_database_server_with_connection_throttling_parameter_is_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "43d57e9b-6080-4608-bbe3-e31611b5d240"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.DBforPostgreSQL servers/configuration/*' permission. Successful execution will enable connection_throttling which helps the PostgreSQL database to set the verbosity of logged messages, which in turn generates query and error logs with respect to concurrent connections"
    cli_script_template = "az postgres server configuration set --resource-group $${resourceGroup} --server-name $${resourceName} --name connection_throttling --value on"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Network Security Group having Inbound rule overly permissive to all traffic on UDP protocol
module "policy_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_udp_protocol" {
  source            = "./modules/policy_default"
  default_policy_id = "d979e854-a50d-11e8-98d0-529269fb1459"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the inbound rule records allowing all traffic from Internet on UDP protocol."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_platform.networking_firewall_csrs_id, module.cs_foundational.networking_firewall_csrs_id]
}

# Azure App Service Web app doesn't redirect HTTP to HTTPS
module "policy_azure_app_service_web_app_doesnt_redirect_http_to_https" {
  source            = "./modules/policy_default"
  default_policy_id = "7cc2b77b-ad71-4a84-8cab-66b2b04eea5f"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/*' permission. Successful execution set on HTTPS-only feature, by which non-secure HTTP requests can be restricted and all HTTP requests will be redirected to the secure HTTPS port."
    cli_script_template = "az webapp update --resource-group $${resourceGroup} --name $${resourceName} --set httpsOnly=true"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure SQL database Transparent Data Encryption (TDE) encryption disabled
module "policy_azure_sql_database_transparent_data_encryption_tde_encryption_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "5a772daf-17c0-4a20-a689-2b3ab3f33779"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Sql/servers/databases/transparentDataEncryption/*' permission. Successful execution will enable SQL database encryption."
    cli_script_template = "az sql db tde set --ids $${resourceId} --status Enabled"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure PostgreSQL database server with log disconnections parameter disabled
module "policy_azure_postgresql_database_server_with_log_disconnections_parameter_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "80c4ade7-44a2-4f01-9997-43c18bc4d7e1"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.DBforPostgreSQL servers/configuration/*' permission. Successful execution will enable log_disconnections which helps the PostgreSQL database to log end of a sessions, including duration, which in turn generates query and error logs."
    cli_script_template = "az postgres server configuration set --resource-group $${resourceGroup} --server-name $${resourceName} --name log_disconnections --value on"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Azure Storage Account 'Trusted Microsoft Services' access not enabled
module "policy_azure_storage_account_trusted_microsoft_services_access_not_enabled" {
  source            = "./modules/policy_default"
  default_policy_id = "3d8d4e24-1336-4bc1-a1f3-15e680edca07"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Storage/storageAccounts/*' permission. Successful execution will enable Azure accounts to bypass 'Trusted Microsoft Services'."
    cli_script_template = "az storage account update --name $${resourceName} --resource-group  $${resourceGroup} --bypass AzureServices"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure App Service Web app authentication is off
module "policy_azure_app_service_web_app_authentication_is_off" {
  source            = "./modules/policy_default"
  default_policy_id = "5e94790e-0d8b-4001-b97f-b5f7670a9236"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/authsettings/*' permission. Successful execution will enable app service authentication, that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app."
    cli_script_template = "az webapp auth update --resource-group $${resourceGroup} --name $${resourceName} --enabled true"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Storage account container storing activity logs is publicly accessible
module "policy_azure_storage_account_container_storing_activity_logs_is_publicly_accessible" {
  source            = "./modules/policy_default"
  default_policy_id = "8a2315b0-70b9-477b-bd5c-41cb92a7b726"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Storage/storageAccounts/write' permission. Successful execution disables public access in Azure storage account, this disables anonymous/public read access to a container storing activity logs within Azure storage account"
    cli_script_template = "az resource update --ids $${resourceId} --set properties.allowBlobPublicAccess=false"
  }]
  compliance_metadata_ids = [module.cs_platform.storage_object_csrs_id, module.cs_foundational.storage_object_csrs_id]
}

# Azure App Service Web app client certificate is disabled
module "policy_azure_app_service_web_app_client_certificate_is_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "b1eec428-ad10-4206-a40e-916dbb0a76bd"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Web/sites/{app_name}/config/*' permission. Successful execution enables Client certificates, only clients that have a valid certificate will be able to reach the app."
    cli_script_template = "az webapp update --resource-group $${resourceGroup} --name $${resourceName} --set clientCertEnabled=true"
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# Azure Network Security Group having Inbound rule overly permissive to all traffic on any protocol
module "policy_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_any_protocol" {
  source            = "./modules/policy_default"
  default_policy_id = "840b4b1c-a50b-11e8-98d0-529269fb1459"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the inbound rule records allowing all traffic from Internet on any protocol."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_platform.networking_firewall_csrs_id, module.cs_foundational.networking_firewall_csrs_id]
}

# Azure Network Security Group with overly permissive outbound rule
module "policy_azure_network_security_group_with_overly_permissive_outbound_rule" {
  source            = "./modules/policy_default"
  default_policy_id = "22979dcf-b4d4-4a74-bf7f-2fae67adc3a9"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  #   policy_remediation = [{
  #     description         = "This CLI command requires 'Microsoft.Network/networkSecurityGroups/securityRules/*' permission. Successful execution will update the network security group to revoke the outbound rule records allowing all traffic to any source."
  #     cli_script_template = "az network nsg rule update --name $${ruleName} --resource-group $${resourceGroup} --nsg-name $${resourceName} --access Deny"
  #   }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# Azure PostgreSQL database server with log checkpoints parameter disabled
module "policy_azure_postgresql_database_server_with_log_checkpoints_parameter_disabled" {
  source            = "./modules/policy_default"
  default_policy_id = "703f7b61-be54-4b6f-be1d-bab81899ec87"
  naming_prefix     = var.naming_prefix
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.DBforPostgreSQL servers/configuration/*' permission. Successful execution will enable log_checkpoints which helps the PostgreSQL Database server to log each checkpoint in turn generates query and error logs."
    cli_script_template = "az postgres server configuration set --resource-group $${resourceGroup} --server-name $${resourceName} --name log_checkpoints --value on"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# Activity Log Retention should not be set to less than 365 days
module "policy_azure_activity_log_retention_should_not_be_set_to_less_than_365_days" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "a9937384-1ee3-430c-acda-fb97e357bfcd"
  policy_labels     = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'Microsoft.Insights/LogProfiles/[Read, Write, Delete]' permission. Successful execution will update the Azure monitor log profile retention policy days to 365 days."
    cli_script_template = "az monitor log-profiles update --name $${resourceName} --set retentionPolicy.days=365 retentionPolicy.enabled=true location=global"
  }]
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id, module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
}

# Azure ACR HTTPS not enabled for webhook
module "policy_azure_acr_https_not_enabled_for_webhook" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "9a28b0fb-67cd-4de9-80b0-702bc0ca6177"
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# Azure Storage account is not configured with private endpoint connection
module "policy_azure_azure_storage_account_is_not_configured_with_private_endpoint_connection" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "f32919fb-62a7-498a-83dd-e31e60ceda29"
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# Azure MySQL database flexible server using insecure TLS version
module "policy_azure_azure_mySQL_database_flexible_server_using_insecure_tls_version" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "9f9f8908-470d-4999-aed4-a4dbec53633c"
  policy_labels           = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}
# Audit usage of custom RBAC rules