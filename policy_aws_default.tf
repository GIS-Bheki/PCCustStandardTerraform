###############################################
# AWS DEFAULT POLICIES
###############################################

# AWS Elastic File System (EFS) with encryption for data at rest is disabled
module "policy_aws_efs_data_at_rest_encryption_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "a7451ade-75eb-4e3e-b996-c2b0d5fdd329"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_file_csrs_id, module.cs_application.storage_file_csrs_id, module.cs_encryption_wmd.storage_file_csrs_id]
}

# AWS ElastiCache Redis cluster with encryption for data at rest disabled
module "policy_aws_ecache_redis_cluster_data_at_rest_encryption_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "884954a8-d886-4d58-a814-7fda27936166"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS Elasticsearch domain Encryption for data at rest is disabled
module "policy_aws_esearch_domain_data_at_rest_encryption_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "0a54c279-d08a-4443-a93b-6d109addd964"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id, module.cs_encryption_wmd.data_svcs_analytics_csrs_id]
}

# AWS RDS DB cluster encryption is disabled
module "policy_aws_rds_db_cluster_encryption_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "dae26f3c-d05a-4499-bdcd-fc5c32e3891f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS RDS instance is not encrypted
module "policy_aws_rds_instance_not_encrypted" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "34fa9efb-d18f-41e4-b93f-2f7e5378752c"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS Redshift instances are not encrypted
module "policy_aws_redshift_instances_not_encrypted" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "0132bbb2-c733-4c36-9c5d-c58967c7d1a6"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS Access key enabled on root account
module "policy_aws_access_key_enabled_on_root_account" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "88db4b66-4dec-48c0-9013-c7871d61b1c8"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_account_csrs_id,module.cs_foundational.iam_account_csrs_id]
}

# AWS CloudTrail bucket is publicly accessible
module "policy_aws_cloudtrail_bucket_is_publicly_accessible" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "b76ad441-e715-4fd0-bbc3-cd3b2bee34bf"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id, module.cs_application.logging_monitoring_mgmnt_plane_csrs_id]
}

# AWS VPC Flow Logs not enabled
module "policy_aws_vpc_flow_logs_not_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "49f4760d-c951-40e4-bfe1-08acaa17672a"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_routing_csrs_id,module.cs_foundational.networking_routing_csrs_id]
}

# AWS IAM policy allows full administrative privileges
module "policy_aws_iam_policy_allows_full_administrative_privileges" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "d9b86448-11a2-f9d4-74a5-f6fc590caeef"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_policy_csrs_id, module.cs_application.iam_policy_csrs_id]
}

# AWS route table with VPC peering overly permissive to all traffic q4Review
module "policy_aws_route_table_with_vpc_peering_overly_permissive_to_all_traffic" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "8d403b9b-794b-4516-84fa-e9415155fb27"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_routing_csrs_id]
}

# AWS IAM user has both Console access and Access Keys
module "policy_aws_iam_user_has_both_console_access_and_access_keys" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "6a34af3f-21ae-8008-0850-229761d01081"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_account_csrs_id]
}

# AWS Default Security Group does not restrict all traffic q4review
module "policy_aws_default_security_group_does_not_restrict_all_traffic" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "2378dbf4-b104-4bda-9b05-7417affbba3f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id]
}

# AWS Private ECR repository policy is overly permissive
module "policy_aws_private_ecr_repository_policy_is_overly_permissive" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "9f40d30b-97fd-4ec5-827b-f74b50a312b9"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id]
}

# AWS S3 bucket has global view ACL permissions enabled
module "policy_aws_s3_bucket_has_global_view_acl_permissions_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "43c42760-5283-4bc4-ac43-a80e58c4139f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# AWS CloudFront web distribution using insecure TLS version
module "policy_aws_cloudfront_web_distribution_that_allow_tls_versions_1_0_or_lower" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "45e37556-3d26-4cdb-8780-5b7fc5f60e01"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS ElastiCache cluster not associated with VPC
module "policy_aws_elasticache_cluster_not_associated_with_vpc" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "f5b4b962-e053-4e73-94d2-c21bd2520a0d"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS EKS cluster security group overly permissive to all traffic
module "policy_aws_eks_cluster_security_group_overly_permissive_to_all_traffic" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "5cc78081-1006-4874-8b13-bd01583888c4"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id]
}

# AWS CloudFront origin protocol policy does not enforce HTTPS-only
module "policy_aws_cloudfront_origin_protocol_policy_does_not_enforce_https-only" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "366ac171-3066-46d3-a32f-df80b0a9fe56"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS IAM policy allows assume role permission across all services
module "policy_aws_iam_policy_allows_assume_role_permission_across_all_services" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "625b4ce5-b8f1-4bdb-8959-7de645095e2b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
}

# AWS EMR cluster is not enabled with data encryption at rest
module "policy_aws_emr_cluster_is_not_enabled_with_data_encryption_at_rest" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "353d0997-a8e7-4b57-8b2c-0772b21ca53f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS IAM SSH keys for AWS CodeCommit have aged more than 90 days without being rotated
module "policy_aws_iam_ssh_keys_for_aws_codecommit_have_aged_more_than_90_days_without_being_rotated" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "3fb665cb-d0af-42e7-ba0f-1ddccd82356b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_account_csrs_id, module.cs_application.iam_account_csrs_id]
}

# AWS Elasticsearch domain publicly accessible
module "policy_aws_elasticsearch_domain_publicly_accessible" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4b411b41-7f4d-4626-884e-5ba8abd2a739"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id]
}

# AWS Elastic Load Balancer (ELB) with IAM certificate expiring in 90 days
module "policy_aws_elastic_load_balancer_elb_with_iam_certificate_expiring_in_90_days" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "2066c4ed-70ad-420e-acd6-a7d6df0797eb"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS KMS Key scheduled for deletion
module "policy_aws_kms_key_scheduled_for_deletion" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4779ab55-2f4b-48cf-b4a9-828165a73f77"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id]
}

# AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with vulnerable SSL protocol
module "policy_aws_elastic_load_balancer_classic_ssl_negotiation_policy_configured_with_vulnerable_ssl_protocol" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "2bfc9a1e-bbad-4778-8116-99d07f1d2ba5"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS S3 Bucket Policy allows public access to CloudTrail logs
module "policy_aws_s3_bucket_policy_allows_public_access_to_cloudtrail_logs" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "a5fe47e1-54f3-47e1-a2a3-deedfb2f70b2"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_platform.storage_object_csrs_id]
}

# AWS Kinesis streams are not encrypted using Server Side Encryption
module "policy_aws_kinesis_streams_are_not_encrypted_using_server_side_encryption" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "8fd3611b-3298-483c-a1ec-0df3fc1ded8d"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id, module.cs_encryption_wmd.data_svcs_analytics_csrs_id]
}

# AWS RDS DB snapshot is not encrypted
module "policy_aws_rds_db_snapshot_is_not_encrypted" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "74a52c45-75ae-404f-abf5-84b5cbd3d22f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
}

# AWS S3 bucket not configured with secure data transport policy
module "policy_aws_s3_bucket_not_configured_with_secure_data_transport_policy" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "7b0df373-006a-40d6-9f3d-68e6ea0bdd5d"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# AWS KMS customer managed external key expiring in 30 days or less
module "policy_aws_kms_customer_managed_external_key_expiring_in_30_days_or_less" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "0ee9e44a-bc0f-4eaa-9c1d-7fc4dedc7b39"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS Elastic Load Balancer (ELB) with ACM certificate expired or expiring in 90 days
module "policy_aws_elastic_load_balancer_elb_with_acm_certificate_expired_or_expiring_in_90_days" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "e2a025f5-d9d1-49ae-9eca-320f8da01b60"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS Elastic Load Balancer v2 (ELBv2) with listener TLS/SSL is not configured
module "policy_aws_elastic_load_balancer_v2_elbv2_with_listener_tlsssl_is_not_configured" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "dd7588a1-79f0-4b2b-8139-891eb50f570e"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS Elastic Load Balancer with listener TLS/SSL is not configured
module "policy_aws_elastic_load_balancer_with_listener_tlsssl_is_not_configured" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "836a7c8c-34c2-4861-be1e-df2f8cd27aab"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS ECS Fargate task definition root user found
module "policy_aws_ecs_fargate_task_definition_root_user_found" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "0ad8c26b-f3b5-4917-b9a4-057f6c2ddebc"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Platform 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_foundational.compute_containers_csrs_id]
}

# AWS CloudFront distribution is using insecure SSL protocols for HTTPS communication
module "policy_aws_cloudfront_distribution_is_using_insecure_ssl_protocols_for_https_communication" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "39df6f76-fc34-4660-97a1-fc967e3abe33"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS ECS task definition elevated privileges enabled
module "policy_aws_ecs_task_definition_elevated_privileges_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "869a1262-99f3-4d40-8207-3a80e4ba1dbd"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# AWS S3 buckets are accessible to any authenticated user
module "policy_aws_s3_buckets_are_accessible_to_any_authenticated_user" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "e8af29c5-eec9-433d-a46b-690c1a286e9b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# AWS Elastic Load Balancer v2 (ELBv2) listener that allow connection requests over HTTP
module "policy_aws_elastic_load_balancer_v2_elbv2_listener_that_allow_connection_requests_over_http" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "81c50f65-faa1-4d66-b8e2-d26eaeb08447"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS Elastic Load Balancer (Classic) with access log disabled
module "policy_aws_elastic_load_balancer_classic_with_access_log_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "b675c604-e886-43aa-a60f-a9ad1f3742d3"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS Elasticsearch IAM policy overly permissive to all traffic
module "policy_aws_elasticsearch_iam_policy_overly_permissive_to_all_traffic" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "d4524070-4c2d-4316-bf67-3716d5667102"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id]
}

# AWS Route53 Public Zone with Private Records
module "policy_aws_route53_public_zone_with_private_records" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "9a2dfca7-7d32-4007-b249-c1efd6dee74b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_dns_csrs_id,module.cs_foundational.networking_dns_csrs_id]
}

# AWS CloudFront distribution with access logging disabled
module "policy_aws_cloudfront_distribution_with_access_logging_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4a719209-0c06-4f42-a33e-9f0107a76fa9"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS Cloudfront Distribution with S3 have Origin Access set to disabled
module "policy_aws_cloudfront_distribution_with_s3_have_origin_access_set_to_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "b0aac456-7422-47fc-9144-9b150bd18a9d"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS VPC allows unauthorized peering
module "policy_aws_vpc_allows_unauthorized_peering" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "2e5e5b6e-584c-43e7-a8e1-2b66abb74da9"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.networking_routing_csrs_id,module.cs_foundational.networking_routing_csrs_id]
}

# AWS EMR cluster is not enabled with data encryption in transit
module "policy_aws_emr_cluster_is_not_enabled_with_data_encryption_in_transit" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4a22f0e7-c3ea-46cc-a255-c155921e7b1f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id]
}

# AWS Config must record all possible resources q4review
module "policy_aws_config_must_record_all_possible_resources" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4c64a4d6-1b96-4004-8a11-f215aa8ee3ce"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
}

# AWS EKS cluster using the default VPC
module "policy_aws_eks_cluster_using_the_default_vpc" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "531d82cd-5d3f-4d2f-ba89-bf3f8f35dab6"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# AWS Elastic Load Balancer (Classic) SSL negotiation policy configured with insecure ciphers
module "policy_aws_elastic_load_balancer_classic_ssl_negotiation_policy_configured_with_insecure_ciphers" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "fed45316-6cae-4dac-aa57-fb451bacb149"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
}

# AWS IAM has expired SSL/TLS certificates
module "policy_aws_iam_has_expired_ssltls_certificates" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "5a63ca23-75be-4fb7-9b52-c5392dce1553"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS IAM Access analyzer is not configured
module "policy_aws_iam_access_analyzer_is_not_configured" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "e50fe75a-d320-483a-88b9-240caf584236"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_platform.iam_service_csrs_id,module.cs_foundational.iam_service_csrs_id]
}

# AWS EC2 instance not configured with Instance Metadata Service v2 (IMDSv2)
module "policy_aws_ec2_instance_not_configured_with_instance_metadata_service_v2_imdsv2" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "32f75d19-c34d-4ec5-aa8c-675959db3aad"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_application.compute_virtual_machines_csrs_id]
}

# AWS Elasticsearch domain is not configured with HTTPS
module "policy_aws_elasticsearch_domain_is_not_configured_with_https" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "0dfd7218-7605-4323-a143-8204ca83faea"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id]
}

# AWS EBS snapshots are accessible to public
module "policy_aws_ebs_snapshots_are_accessible_to_public" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "7c714cb4-3d47-4c32-98d4-c13f92ce4ec5"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:ModifySnapshotAttribute' permission. Successful execution will make this EBS snapshot's access to private. This will ensure that only Owner has full privileges."
    cli_script_template = "aws ec2 --region $${region} modify-snapshot-attribute --snapshot-id $${resourceId} --attribute createVolumePermission --operation-type remove --group-names all"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# AWS VPC subnets should not allow automatic public IP assignment
module "policy_aws_vpc_subnets_should_not_allow_automatic_public_ip_assignment" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "11743cd3-35e4-4639-91e1-bc87b52d4cf5"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:ModifySubnetAttribute' permission. Successful execution will disable automatic public IP assignment for the respective Subnet."
    cli_script_template = "aws ec2 modify-subnet-attribute --subnet-id $${resourceId} --region $${region}  --no-map-public-ip-on-launch"
  }]
  compliance_metadata_ids = [module.cs_platform.networking_routing_csrs_id,module.cs_foundational.networking_routing_csrs_id]
}

# AWS RDS snapshots are accessible to public
module "policy_aws_rds_snapshots_are_accessible_to_public" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "a707de6a-11b7-478a-b636-5e21ee1f6162"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'rds:ModifyDBSnapshotAttribute' permission. Successful execution will reset this RDS snapshot's ACL (Access Control List) to private. This will ensure that only Owner has full privileges."
    cli_script_template = "aws rds --region $${region} modify-db-snapshot-attribute --db-snapshot-identifier $${resourceId} --attribute-name restore --values-to-remove \"all\""
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS Customer Master Key (CMK) rotation is not enabled
module "policy_aws_customer_master_key_cmk_rotation_is_not_enabled" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "497f7e2c-b702-47c7-9a07-f0f6404ac896"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'kms:EnableKeyRotation' permission. Successful execution will enable the key rotation for the respective Customer Master Key (CMK)."
    cli_script_template = "aws kms enable-key-rotation --key-id $${resourceId} --region $${region}"
  }]
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id]
}

# AWS IAM Password policy is unsecure
module "policy_aws_iam_password_policy_is_unsecure" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "b1acdeff-4959-4c14-8a5e-2adc1016a3d5"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
}

# AWS RDS database instance is publicly accessible
module "policy_aws_rds_database_instance_is_publicly_accessible" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "1bb6005a-dca6-40e2-b0a6-24da968c0808"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will disable the publicly accessible configuration of AWS RDS database instances"
    cli_script_template = "aws rds modify-db-instance --region $${region} --db-instance-identifier $${resourceName} --no-publicly-accessible --apply-immediately"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS IAM password policy does not have password expiration period
module "policy_aws_iam_password_policy_does_not_have_password_expiration_period" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "a8dcc272-0b02-4534-8627-cf70ddd264c5"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
}

# AWS Amazon Machine Image (AMI) is publicly accessible
module "policy_aws_amazon_machine_image_ami_is_publicly_accessible" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "81a2200a-c63e-4860-85a0-b54eaa581135"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Platform Compliance 2024Q3"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:ModifyImageAttribute' permission. Successful execution will make this AMI's access to private. This will ensure that only Owner has full privileges."
    cli_script_template = "aws ec2 --region $${region} modify-image-attribute --image-id $${resourceId} --launch-permission \"{\"Remove\": [{\"Group\":\"all\"}]}\""
  }]
  compliance_metadata_ids = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_platform.compute_virtual_machines_csrs_id]
}

# AWS RDS instance with copy tags to snapshots disabled
module "policy_aws_rds_instance_with_copy_tags_to_snapshots_disabled" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "1f524c07-3254-45a0-8ad7-03e29242c499"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable 'copy tags to snapshots' for the respective RDS."
    cli_script_template = "aws rds modify-db-instance --region $${region} --db-instance-identifier $${resourceName} --copy-tags-to-snapshot --apply-immediately"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS RDS instance delete protection is disabled
module "policy_aws_rds_instance_delete_protection_is_disabled" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "77b203a1-1d4b-442c-92c0-0c391ae4955f"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable deletion protection for the reported AWS RDS instance."
    cli_script_template = "aws rds modify-db-instance --db-instance-identifier $${resourceName} --region $${region} --deletion-protection"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS RDS cluster delete protection is disabled
module "policy_aws_rds_cluster_delete_protection_is_disabled" {
  source            = "./modules/policy_default"
  naming_prefix     = var.naming_prefix
  default_policy_id = "e058fabb-cc5c-4c19-88ed-b5d599044a92"
  policy_labels     = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled    = true
  policy_remediation = [{
    description         = "This CLI command requires 'rds:ModifyDBCluster' permission. Successful execution will enable deletion protection for the reported AWS RDS cluster."
    cli_script_template = "aws rds modify-db-cluster --db-cluster-identifier $${resourceName} --region $${region} --deletion-protection"
  }]
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS S3 bucket access control lists (ACLs) in use   q4Review
module "policy_aws_s3_bucket_access_control_lists_in_use" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "cab6f1a5-f6c5-4caf-bf10-b0f3a29e90ea"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id]
}

# AWS OpenSearch Fine-grained access control is disabled
module "policy_aws_opensearch_fine_grained_access_control_is_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "45987be9-259e-4940-ae03-351c68b8d3d8"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id]
}

# AWS Web Application Firewall (AWS WAF) Classic logging is disabled
module "policy_aws_web_application_firewall_classic_logging_is_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4aef2d8d-d2ca-42e8-a0c9-930827a7cadf"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
}

# AWS ECR Repository not configured with a lifecycle policy
module "policy_aws_ecr_repository_not_configured_with_a_lifecycle_policy" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "8377061b-355d-4fec-ad91-47f98f6f7912"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_containers_csrs_id, module.cs_application.compute_containers_csrs_id]
}

# AWS S3 bucket publicly readable
module "policy_aws_s3_bucket_publicly_readable" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "e0b4379d-6692-41ab-bd33-10cbac836b1e"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# AWS S3 bucket publicly writable
module "policy_aws_s3_bucket_publicly_writable" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "55b4de5f-2b59-4545-ac0c-f4ebad2e3add"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
}

# AWS RDS instance without Automatic Backup setting
module "policy_aws_rds_instance_without_automatic_backup_setting" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "3a6797a0-2420-4b27-b06b-9eec275c233f"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS Elastic IP not in use
module "policy_aws_elastic_ip_not_in_use" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "fae6c539-55ef-4cfd-a021-d939e8235116"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.networking_routing_csrs_id, module.cs_application.networking_routing_csrs_id]
}

# AWS EMR cluster is not configured with Kerberos Authentication
module "policy_aws_emr_cluster_is_not_configured_with_kerberos_authentication" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "5e2afd31-8a97-489b-a3ea-0378a29ce76a"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id]
}

# AWS Redshift database does not have audit logging enabled
module "policy_aws_redshift_database_does_not_have_audit_logging_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "91c941aa-d110-4b33-9934-aadd86b1a4d9"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS Redshift does not have require_ssl configured
module "policy_aws_redshift_does_not_have_require_ssl_configured" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "7446ad28-8502-4d71-b334-18cef8d85a2b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS SageMaker notebook instance not configured with data encryption at rest using KMS key
module "policy_aws_sagemaker_notebook_instance_not_configured_with_data_encryption_at_rest_using_kms_key" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "f2c2c424-6fc9-4f99-8efb-4cb09810be97"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_cognitive_csrs_id, module.cs_application.data_svcs_cognitive_csrs_id]
}

# AWS SageMaker notebook instance configured with direct internet access feature
module "policy_aws_sageMaker_notebook_instance_configured_with_direct_internet_access_feature" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "5c0ba8b1-9b88-486f-9fe1-a0eb9071a42b"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_cognitive_csrs_id, module.cs_application.data_svcs_cognitive_csrs_id]
}

# AWS SageMaker notebook instance is not placed in VPC
module "policy_aws_sageMaker_notebook_instance_is_not_placed_in_vpc" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "4af86954-7e52-46d6-bf4a-efa0c4ccee41"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_cognitive_csrs_id, module.cs_application.data_svcs_cognitive_csrs_id]
}

# AWS Certificate Manager (ACM) has certificates expiring in 30 days or less
module "policy_aws_certificate_manager_acm_has_certificates_expiring_in_30_days_or_less" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "369dcce6-f088-445d-95a7-777af0347821"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS IAM Groups with administrator access permissions
module "policy_aws_iam_groups_with_administrator_access" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "3b165f8d-1a65-41db-848d-d3783c4490ce"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_service_csrs_id, module.cs_application.iam_service_csrs_id]
}

# AWS Certificate Manager (ACM) has invalid or failed certificate
module "policy_aws_certificate_manager_has_invalid_or_failed_certificate" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "77450a1c-97c2-4d75-847d-1f9c48320a9d"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS Certificate Manager (ACM) has expired certificates
module "policy_aws_certificate_manager_has_expired_certificate" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "d1fae43a-5bb6-429a-945e-fec5e8d9c662"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS Certificate Manager (ACM) has certificates with Certificate Transparency Logging disabled
module "policy_aws_certificate_manager_has_certificates_with_certificate_transparency_logging_disabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "546a493a-3979-42d1-a018-e07dbfc15ae6"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS Certificate Manager (ACM) contains certificate pending validation
module "policy_aws_certificate_manager_contains_certificate_pending_valdation" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "01740791-ebd5-417a-bbfe-e1fdfc322dcc"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
}

# AWS EMR cluster is not enabled with local disk encryption
module "policy_aws_emr_cluster_is_not_enabled_with_local_disk_encryption" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "271423dc-295f-40fb-8743-ec07f58e8761"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_analytics_csrs_id, module.cs_application.data_svcs_analytics_csrs_id,module.cs_encryption_wmd.data_svcs_analytics_csrs_id]
}

# AWS ElastiCache Redis cluster with in-transit encryption disabled (Replication group)
module "policy_aws_elasticache_redis_cluster_with_in_transit_encryption_disabled_replication_group" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "fd782eca-2dba-47b2-b0f4-f949a7916215"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id,module.cs_encryption_wmd.data_svcs_analytics_csrs_id]
}

# AWS RDS minor upgrades not enabled
module "policy_aws_rds_minor_upgrades_not_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "9dd6cc35-1855-48c8-86ba-0e1818ce11e2"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
}

# AWS IAM user has two active Access Keys
module "policy_aws_iam_user_has_two_active_access_keys" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "e809c246-2ef5-4319-bba9-2c5735d88aa8"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_service_csrs_id, module.cs_application.iam_service_csrs_id]
}

# AWS IAM policy attached to users
module "policy_aws_iam_policy_attahed_to_users" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "2b7e07ba-56c8-42db-8db4-a4b65f5066c4"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.iam_policy_csrs_id, module.cs_application.iam_policy_csrs_id]
}

# AWS EC2 Instance IAM Role not enabled
module "policy_aws_ec2_instance_iam_role_not_enabled" {
  source                  = "./modules/policy_default"
  naming_prefix           = var.naming_prefix
  default_policy_id       = "8f2a2ff7-b484-463d-95df-aecd038f62b0"
  policy_labels           = ["Standard Bank Foundational Compliance 2025Q1.1","Standard Bank Application Compliance 2025Q1.1"]
  policy_enabled          = true
  compliance_metadata_ids = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_application.compute_virtual_machines_csrs_id]
}