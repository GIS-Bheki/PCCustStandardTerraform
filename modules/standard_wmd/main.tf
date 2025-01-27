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
# MESSAGING
resource "prismacloud_compliance_standard_requirement" "csr_messaging" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Messaging"
  description    = ""
  requirement_id = "7"
}
# SUPPORTING SERVICES
resource "prismacloud_compliance_standard_requirement" "csr_supporting_svcs" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Supporting Services"
  description    = ""
  requirement_id = "8"
}
# OTHER SECURITY CONSIDERATIONS
resource "prismacloud_compliance_standard_requirement" "csr_other_sec_considerations" {
  cs_id          = prismacloud_compliance_standard.cs.cs_id
  name           = "Other Security Considerations"
  description    = ""
  requirement_id = "9"
}

###############################################
# STANDARD REQUIREMENT SECTIONS 
###############################################

# IDENTITY AND ACCESS MANAGEMENT
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_mfa_is_not_enabled_on_root_account" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS MFA is not enabled on Root account"
  description = "AWS MFA is not enabled on Root account"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_access_key_enabled_on_root_account" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS Access key enabled on root account"
  description = "AWS Access key enabled on root account"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_access_keys_are_not_rotated_for_90_days" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS access keys are not rotated for 90 days"
  description = "AWS access keys are not rotated for 90 days"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_sql_server_not_configured_with_active_directory_admin_authentication" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "Azure SQL server not configured with Active Directory admin authentication"
  description = "Azure SQL server not configured with Active Directory admin authentication"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_mfa_not_enabled_for_iam_users" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS MFA not enabled for IAM users"
  description = "AWS MFA not enabled for IAM users"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_iam_password_policy_is_unsecure" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS IAM Password policy is unsecure"
  description = "AWS IAM Password policy is unsecure"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_iam_password_policy_does_not_have_password_expiration_period" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_iam.csr_id
  section_id  = "AWS IAM password policy does not have password expiration period"
  description = "AWS IAM password policy does not have password expiration period"
}
# STORAGE
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_microsoft_defender_for_cloud_is_set_to_off_for_azure_sql_databases" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure Microsoft Defender for Cloud is set to Off for Azure SQL Databases"
  description = "Azure Microsoft Defender for Cloud is set to Off for Azure SQL Databases"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_rds_snapshots_are_accessible_to_public" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "AWS RDS snapshots are accessible to public"
  description = "AWS RDS snapshots are accessible to public"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_storage_account_using_insecure_tls_version" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure Storage Account using insecure TLS version"
  description = "Azure Storage Account using insecure TLS version"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_mysql_database_flexible_server_using_insecure_tls_version" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure MySQL database flexible server using insecure TLS version"
  description = "Azure MySQL database flexible server using insecure TLS version"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_rds_database_instance_is_publicly_accessible" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "AWS RDS database instance is publicly accessible"
  description = "AWS RDS database instance is publicly accessible"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_mysql_database_server_ssl_connection_is_disabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure MySQL Database Server SSL connection is disabled"
  description = "Azure MySQL Database Server SSL connection is disabled"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_s3_buckets_are_accessible_to_public" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "AWS S3 buckets are accessible to public"
  description = "AWS S3 buckets are accessible to public"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_ebs_snapshots_are_accessible_to_public" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "AWS EBS snapshots are accessible to public"
  description = "AWS EBS snapshots are accessible to public"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_storage_account_container_storing_activity_logs_is_publicly_accessible" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure Storage account container storing activity logs is publicly accessible"
  description = "Azure Storage account container storing activity logs is publicly accessible"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_storage_account_has_a_blob_container_with_public_access" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure storage account has a blob container with public access"
  description = "Azure storage account has a blob container with public access"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_s3_buckets_are_accessible_to_any_authenticated_user" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "AWS S3 buckets are accessible to any authenticated user"
  description = "AWS S3 buckets are accessible to any authenticated user"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_microsoft_defender_for_cloud_is_set_to_off_for_sql_servers_on_machines" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_storage.csr_id
  section_id  = "Azure Microsoft Defender for Cloud is set to Off for SQL servers on machines"
  description = "Azure Microsoft Defender for Cloud is set to Off for SQL servers on machines"
}
# COMPUTE
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_acr_https_not_enabled_for_webhook" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Azure ACR HTTPS not enabled for webhook"
  description = "Azure ACR HTTPS not enabled for webhook"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_microsoft_defender_for_cloud_is_set_to_off_for_app_service" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Azure Microsoft Defender for Cloud is set to Off for App Service"
  description = "Azure Microsoft Defender for Cloud is set to Off for App Service"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_ec2_instance_not_configured_with_instance_metadata_service_v2_imdsv2" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)"
  description = "AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_amazon_machine_image_ami_is_publicly_accessible" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "AWS Amazon Machine Image (AMI) is publicly accessible"
  description = "AWS Amazon Machine Image (AMI) is publicly accessible"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_application_gateway_does_not_have_the_web_application_firewall_waf_enabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Azure Application Gateway does not have the Web application firewall (WAF) enabled"
  description = "Azure Application Gateway does not have the Web application firewall (WAF) enabled"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_app_service_web_app_doesnt_use_latest_tls_version" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "Azure App Service Web app doesn't use latest TLS version"
  description = "Azure App Service Web app doesn't use latest TLS version"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_eks_cluster_endpoint_access_publicly_enabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_compute.csr_id
  section_id  = "AWS EKS cluster endpoint access publicly enabled"
  description = "AWS EKS cluster endpoint access publicly enabled"
}
# NETWORKING
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_web_application_firewall_aws_waf_classic_logging_is_disabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Web Application Firewall (AWS WAF) Classic logging is disabled"
  description = "AWS Web Application Firewall (AWS WAF) Classic logging is disabled"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_sql_server_udp_port_1434" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on SQL Server (UDP Port 1434)"
  description = "Azure Network Security Group allows all traffic on SQL Server (UDP Port 1434)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_netbios_dns_tcp_port_53" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on NetBIOS DNS (TCP Port 53)"
  description = "Azure Network Security Group allows all traffic on NetBIOS DNS (TCP Port 53)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_rdp_port_3389" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on RDP Port 3389"
  description = "Azure Network Security Group allows all traffic on RDP Port 3389"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_security_group_allows_all_ipv6_traffic_on_rdp_port_3389" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Security Group allows all IPv6 traffic on RDP port (3389)"
  description = "AWS Security Group allows all IPv6 traffic on RDP port (3389)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_api_gateway_with_public_endpoints" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS API Gateway with Public Endpoints"
  description = "AWS API Gateway with Public Endpoints"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_postgresql_tcp_port_5432" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on PostgreSQL (TCP Port 5432)"
  description = "Azure Network Security Group allows all traffic on PostgreSQL (TCP Port 5432)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_mysql_tcp_port_3306" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on MySQL (TCP Port 3306)"
  description = "Azure Network Security Group allows all traffic on MySQL (TCP Port 3306)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_netbios_udp_port_137" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on NetBIOS (UDP Port 137)"
  description = "Azure Network Security Group allows all traffic on NetBIOS (UDP Port 137)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_icmp_ping" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on ICMP (Ping)"
  description = "Azure Network Security Group allows all traffic on ICMP (Ping)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_ftp-data_tcp_port_20" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on FTP-Data (TCP Port 20)"
  description = "Azure Network Security Group allows all traffic on FTP-Data (TCP Port 20)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_cloudfront_web_distribution_using_insecure_tls_version" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS CloudFront web distribution using insecure TLS version"
  description = "AWS CloudFront web distribution using insecure TLS version"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_netbios_dns_udp_port_53" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on NetBIOS DNS (UDP Port 53)"
  description = "Azure Network Security Group allows all traffic on NetBIOS DNS (UDP Port 53)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_vnc_server_tcp_port_5900" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on VNC Server (TCP Port 5900)"
  description = "Azure Network Security Group allows all traffic on VNC Server (TCP Port 5900)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_telnet_tcp_port_23" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on Telnet (TCP Port 23)"
  description = "Azure Network Security Group allows all traffic on Telnet (TCP Port 23)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_smtp_tcp_port_25" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on SMTP (TCP Port 25)"
  description = "Azure Network Security Group allows all traffic on SMTP (TCP Port 25)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_security_group_allows_all_ipv6_traffic_on_ssh_port_22" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Security Group allows all IPv6 traffic on SSH port (22)"
  description = "AWS Security Group allows all IPv6 traffic on SSH port (22)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_elastic_load_balancer_classic_ssl_negotiation_policy_configured_with_vulnerable_ssl_protocol" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol"
  description = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_vnc_listener_tcp_port_5500" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on VNC Listener (TCP Port 5500)"
  description = "Azure Network Security Group allows all traffic on VNC Listener (TCP Port 5500)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_windows_smb_tcp_port_445" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on Windows SMB (TCP Port 445)"
  description = "Azure Network Security Group allows all traffic on Windows SMB (TCP Port 445)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_cifs_udp_port_445" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on CIFS (UDP Port 445)"
  description = "Azure Network Security Group allows all traffic on CIFS (UDP Port 445)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_ssh_port_22" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on SSH port 22"
  description = "Azure Network Security Group allows all traffic on SSH port 22"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_security_group_allows_all_ipv4_traffic_on_ssh_port_22" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Security Group allows all IPv4 traffic on SSH port (22)"
  description = "AWS Security Group allows all IPv4 traffic on SSH port (22)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_msql_tcp_port_4333" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on MSQL (TCP Port 4333)"
  description = "Azure Network Security Group allows all traffic on MSQL (TCP Port 4333)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_windows_rpc_tcp_port_135" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on Windows RPC (TCP Port 135)"
  description = "Azure Network Security Group allows all traffic on Windows RPC (TCP Port 135)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_any_protocol" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group having Inbound rule overly permissive to all traffic on any protocol"
  description = "Azure Network Security Group having Inbound rule overly permissive to all traffic on any protocol"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_elastic_load_balancer_classic_ssl_negotiation_policy_configured_with_insecure_ciphers" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers"
  description = "AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_security_group_allows_all_ipv4_traffic_on_rdp_port_3389" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Security Group allows all IPv4 traffic on RDP port (3389)"
  description = "AWS Security Group allows all IPv4 traffic on RDP port (3389)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_ftp_tcp_port_21" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on FTP (TCP Port 21)"
  description = "Azure Network Security Group allows all traffic on FTP (TCP Port 21)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_netbios_udp_port_138" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on NetBIOS (UDP Port 138)"
  description = "Azure Network Security Group allows all traffic on NetBIOS (UDP Port 138)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_udp_protocol" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group having Inbound rule overly permissive to all traffic on UDP protocol"
  description = "Azure Network Security Group having Inbound rule overly permissive to all traffic on UDP protocol"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_having_inbound_rule_overly_permissive_to_all_traffic_on_tcp_protocol" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group having Inbound rule overly permissive to all traffic on TCP protocol"
  description = "Azure Network Security Group having Inbound rule overly permissive to all traffic on TCP protocol"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_virtual_network_subnet_is_not_configured_with_a_network_security_group" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Virtual Network subnet is not configured with a Network Security Group"
  description = "Azure Virtual Network subnet is not configured with a Network Security Group"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_network_security_group_allows_all_traffic_on_sql_server_tcp_port_1433" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "Azure Network Security Group allows all traffic on SQL Server (TCP Port 1433)"
  description = "Azure Network Security Group allows all traffic on SQL Server (TCP Port 1433)"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_elastic_load_balancer_elb_with_acm_certificate_expired_or_expiring_in_90_days" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_networking.csr_id
  section_id  = "AWS Elastic Load Balancer (ELB) with ACM certificate expired or expiring in 90 days"
  description = "AWS Elastic Load Balancer (ELB) with ACM certificate expired or expiring in 90 days"
}
# DATA SERVICES

# LOGGING AND MONITORING
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_vpc_flow_logs_not_enabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_logging_monitoring.csr_id
  section_id  = "AWS VPC Flow Logs not enabled"
  description = "AWS VPC Flow Logs not enabled"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_cloudtrail_is_not_enabled_on_the_account" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_logging_monitoring.csr_id
  section_id  = "AWS CloudTrail is not enabled on the account"
  description = "AWS CloudTrail is not enabled on the account"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_cloudtrail_logging_is_disabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_logging_monitoring.csr_id
  section_id  = "AWS CloudTrail logging is disabled"
  description = "AWS CloudTrail logging is disabled"
}
resource "prismacloud_compliance_standard_requirement_section" "csrs_azure_key_vault_audit_logging_is_disabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_logging_monitoring.csr_id
  section_id  = "Azure Key Vault audit logging is disabled"
  description = "Azure Key Vault audit logging is disabled"
}
# MESSAGING

# SUPPORTING SERVICES
resource "prismacloud_compliance_standard_requirement_section" "csrs_aws_secrets_manager_secret_rotation_is_not_enabled" {
  csr_id      = prismacloud_compliance_standard_requirement.csr_supporting_svcs.csr_id
  section_id  = "AWS Secrets Manager secret rotation is not enabled"
  description = "AWS Secrets Manager secret rotation is not enabled"
}
# OTHER SECURITY CONSIDERATIONS
