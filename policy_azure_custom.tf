##############################################
# AZURE CUSTOM POLICIES
###############################################

# Managed identity should be used in your API App
module "policy_azure_managed_identity_should_be_used_in_your_api_app" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Managed identity should be used in your API App"
  policy_description        = <<EOF
A system assigned managed identity is restricted to one per resource and is tied to the lifecycle of this resource. You can grant permissions to the managed identity by using Azure role-based access control (Azure RBAC). The managed identity is authenticated with Azure AD, so you don’t have to store any credentials in code
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
On the Azure Portal 
1. Go to the App Service for your API app
2. Scroll to the Settings group in the left navigation
3. Select Identity
4. Use System assigned or User assigned identity following the steps described in this doc: https://aka.ms/managed-identity
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.compute_web_app_svcs_csrs_id,module.cs_foundational.compute_web_app_svcs_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-app-service' AND json.rule = identity.type does not contain \"SystemAssigned\" and kind starts with \"api\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Managed identity should be used in your Function App
module "policy_azure_managed_identity_should_be_used_in_your_function_app" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Managed identity should be used in your Function App"
  policy_description        = <<EOF
A system assigned managed identity is restricted to one per resource and is tied to the lifecycle of this resource. You can grant permissions to the managed identity by using Azure role-based access control (Azure RBAC). The managed identity is authenticated with Azure AD, so you don’t have to store any credentials in code
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
On the Azure Portal 

1. Create an app in the portal as you normally would. Navigate to it in the portal.
2. If using a function app, navigate to Platform features. For other app types, scroll down to the Settings group in the left navigation.
3. Select Identity.
4. Within the System assigned tab, switch Status to On. Click Save.

For more information follow the following link : https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=dotnet
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.compute_serverless_csrs_id,module.cs_foundational.compute_serverless_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-app-service' AND json.rule = identity.type does not contain \"SystemAssigned\" and kind contains \"function\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Azure VM Disk is not configured with any encryption
module "policy_azure_vm_disk_is_not_configured_with_any_encryption" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Azure VM Disk is not configured with any encryption"
  policy_description        = "Azure VM Disk is not configured with any encryption"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-disk-list' AND json.rule = (encryptionSettings does not exist or encryptionSettings.enabled is false) and encryption.type is not member of (\"EncryptionAtRestWithCustomerKey\", \"EncryptionAtRestWithPlatformAndCustomerKeys\",\"EncryptionAtRestWithPlatformKey\")"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Azure SQL Database Server is not configured with any encryption
module "policy_azure_sql_database_server_is_not_configured_with_any_encryption" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Azure SQL Database Server  is not configured with any encryption"
  policy_description        = "Azure SQL Database Server  is not configured with any encryption"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-sql-server-list' AND json.rule = ['sqlServer'].['properties.state'] equal ignore case Ready and sqlEncryptionProtectors[*].kind does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Azure SQL Database is not configured with any encryption 
module "policy_azure_sql_database_is_not_configured_with_any_encryption" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Azure SQL Database is not configured with any encryption"
  policy_description        = "Azure SQL Database is not configured with any encryption"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-sql-db-list' AND json.rule = transparentDataEncryption is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Database for MySQL
module "policy_azure_count_azure_database_for_mysql" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Database for MySQL"
  policy_description        = "Count Azure Database for MySQL"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-mysql-server' AND json.rule = type does not equal ignore case \"Microsoft.DBforMySQL/servers\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Database for MySQL Flexible Server 
module "policy_azure_count_azure_database_for_msql_flexible_server" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Database for MySQL Flexible Server"
  policy_description        = "Count Azure Database for MySQL Flexible Server"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-mysql-flexible-server' AND json.rule = type does not equal ignore case \"Microsoft.DBforMySQL/flexibleServers\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Database for PostgreSQL
module "policy_azure_count_azure_database_for_postgreSQL" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Database for PostgreSQL"
  policy_description        = "Count Azure Database for PostgreSQL"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-postgresql-server' AND json.rule = type does not equal ignore case \"Microsoft.DBforPostgreSQL/servers\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Database for PostgreSQL Flexible Server
module "policy_azure_count_azure_database_for_postgreSQL_flexible_server" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Database for PostgreSQL Flexible Server"
  policy_description        = "Count Azure Database for PostgreSQL Flexible Server"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-postgresql-flexible-server' AND json.rule = type does not equal ignore case \"Microsoft.DBforPostgreSQL/flexibleServers\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Cosmos DB
module "policy_azure_count_azure_cosmos_db" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Cosmos DB"
  policy_description        = "Count Azure Cosmos DB"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' AND api.name = 'azure-cosmos-db' AND json.rule = type does not equal ignore case \"Microsoft.DocumentDB/databaseAccounts\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# Count Azure Data Lake
module "policy_azure_count_azure_data_lake" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "Count Azure Data Lake"
  policy_description        = "Count Azure Data Lake"
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "azure"
  policy_labels             = ["Standard Bank Encryption Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_encryption_wmd.data_svcs_analytics_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'azure' and api.name = 'azure-data-lake-analytics-account' AND json.rule = type does not equal ignore case \"Microsoft.DataLakeAnalytics/accounts\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}