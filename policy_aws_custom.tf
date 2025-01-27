###############################################
# AWS CUSTOM POLICIES
###############################################

# AWS S3 buckets do not have server side encryption
module "policy_aws_s3_buckets_sse_not_enabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS S3 buckets do not have server side encryption"
  policy_description        = <<EOF
Customers can protect the data in S3 buckets using the AWS server-side encryption. If the server-side encryption is not turned on for S3 buckets with sensitive data, in the event of a data breach, malicious users can gain access to the data.

NOTE: Do NOT enable this policy if you are using 'Server-Side Encryption with Customer-Provided Encryption Keys (SSE-C).'
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS Console and navigate to the 'S3' service
2. Click on the reported S3 bucket
3. Click on the 'Properties' tab
4. Under the 'Default encryption' section, choose encryption option either AES-256 or AWS-KMS based on your requirement.

For more information about Server-side encryption,
Default encryption:
https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI Command will enable default AWS S3 bucket encryption that uses the S3 provided default AES256 key."
    cli_script_template = "aws s3api put-bucket-encryption --region $${region} --bucket $${resourceName} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id, module.cs_encryption_wmd.storage_object_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-s3api-get-bucket-acl' AND json.rule = 'policyAvailable is true and denyUnencryptedUploadsPolicies[*] is empty and sseAlgorithm equals None and (not tagSets.SseDisabled contains True)'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS access keys are not rotated for 60 days
module "policy_aws_access_keys_are_not_rotated_for_60_days" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS access keys are not rotated for 60 days"
  policy_description        = <<EOF
This policy identifies IAM users for which access keys are not rotated for 60 days. Access keys are used to sign API requests to AWS. As a security best practice, it is recommended that all access keys are regularly rotated to make sure that in the event of key compromise, unauthorized users are not able to gain access to your AWS services.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS console and navigate to the 'IAM' service.
2. Click on the user that was reported in the alert.
3. Click on 'Security Credentials' and for each 'Access Key'.
4. Follow the instructions below to rotate the Access Keys that are older than 60 days.
https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.iam_account_csrs_id, module.cs_application.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-iam-get-credential-report' AND json.rule = '(user does not equal \"AzureADRoleManager\") and ((access_key_1_active is true and access_key_1_last_rotated != N/A and _DateTime.ageInDays(access_key_1_last_rotated) > 60) or (access_key_2_active is true and access_key_2_last_rotated != N/A and _DateTime.ageInDays(access_key_2_last_rotated) > 60))'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS access keys are not rotated for 365 days
module "policy_aws_access_keys_are_not_rotated_for_365_days" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS access keys are not rotated for 365 days"
  policy_description        = <<EOF
This policy identifies IAM users for which access keys are not rotated for 365 days. Access keys are used to sign API requests to AWS. As a security best practice, it is recommended that all access keys are regularly rotated to make sure that in the event of key compromise, unauthorized users are not able to gain access to your AWS services.
SBG Custom - Exclude AzureADRoleManager.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS console and navigate to the 'IAM' service.
2. Click on the user that was reported in the alert.
3. Click on 'Security Credentials' and for each 'Access Key'.
4. Follow the instructions below to rotate the Access Keys that are older than 365 days.
https://aws.amazon.com/blogs/security/how-to-rotate-access-keys-for-iam-users/
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.iam_account_csrs_id, module.cs_application.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-iam-get-credential-report' AND json.rule = '(user does not equal \"AzureADRoleManager\") and ((access_key_1_active is true and access_key_1_last_rotated != N/A and _DateTime.ageInDays(access_key_1_last_rotated) > 365) or (access_key_2_active is true and access_key_2_last_rotated != N/A and _DateTime.ageInDays(access_key_2_last_rotated) > 365))'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS CloudTrail is not enabled on the account
module "policy_aws_cloudtrail_is_not_enabled_on_the_account" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail is not enabled on the account"
  policy_description        = <<EOF
Checks to ensure that a foundational (LZ) CloudTrail is enabled on the account. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail to get a complete audit trail of activities across various services. 
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS Console and navigate to the 'CloudTrail' service.
2. Follow the instructions below to enable CloudTrail on the account.
http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-cloudtrail-describe-trails' and json.rule = name equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\" as X; count(X) less than 1"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS CloudTrail is not enabled with multi trail and not capturing all management events
module "policy_aws_cloudtrail_is_not_enabled_with_multi_trail_and_not_capturing_all_management_events" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail is not enabled with multi trail and not capturing all management events"
  policy_description        = <<EOF
This policy identifies the AWS accounts which do not have a foundational (LZ) CloudTrail with multi-region trail enabled and capturing all management events. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on CloudTrail across different regions to get a complete audit trail of activities across various services.

NOTE: If you have Organization Trail enabled in your account, this policy can be disabled, or alerts generated for this policy on such an account can be ignored; as Organization Trail by default enables trail log for all accounts under that organization.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Refer to the following link to create/update the trail:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name= 'aws-cloudtrail-describe-trails' AND json.rule = 'isMultiRegionTrail is true and includeGlobalServiceEvents is true' as X; config from cloud.resource where api.name= 'aws-cloudtrail-get-trail-status' AND json.rule = 'status.isLogging equals true' as Y; config from cloud.resource where api.name= 'aws-cloudtrail-get-event-selectors' AND json.rule = 'eventSelectors[*].readWriteType contains All' as Z; filter '($.X.trailARN equals $.Z.trailARN) and ($.X.name equals $.Y.trail) and ($.X.name equal ignore case AWS-Landing-Zone-BaselineCloudTrail or $.X.name equal ignore case aws-controltower-BaselineCloudTrail)'; show X; count(X) less than 1"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS CloudTrail log validation is not enabled in all regions
module "policy_aws_cloudtrail_log_validation_is_not_enabled_in_all_regions" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail log validation is not enabled in all regions"
  policy_description        = <<EOF
This policy identifies AWS CloudTrails in which log validation is not enabled in all regions. CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was modified after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS console
2. In the console, select the specific region from region drop down on the top right corner, for which the alert is generated
3. Access the 'CloudTrail' service.
4. For each trail reported, under Configuration > Storage Location, make sure 'Enable log file validation' is set to 'Yes'.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "low"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'cloudtrail:UpdateTrail' permission. Successful execution will enable the log file validation for this CloudTrail."
    cli_script_template = "aws cloudtrail update-trail --name $${resourceName} --region $${region} --enable-log-file-validation"
  }]
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-cloudtrail-describe-trails' AND json.rule='logFileValidationEnabled is false and (name equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\")'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS CloudTrail logging is disabled
module "policy_aws_cloudtrail_logging_is_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail logging is disabled"
  policy_description        = <<EOF
This policy identifies the foundational (LZ) CloudTrails in which logging is disabled. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to turn on logging for CloudTrail across different regions to get a complete audit trail of activities across various services.

NOTE: This policy will be triggered only when you have CloudTrail configured in your AWS account and logging is disabled.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to AWS Console
2. Navigate to CloudTrail dashboard
3. Click on 'Trails' (Left panel)
4. Click on reported CloudTrail
5. Enable 'Logging' by hovering logging button to 'ON'
OR
If CLoudTrail is not required you can delete by clicking on the delete icon below the logging hover button.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'cloudtrail:StartLogging' permission. Successful execution will enable logging for the respective CloudTrail."
    cli_script_template = "aws cloudtrail start-logging --name $${resourceName} --region $${region}"
  }]
  compliance_metadata_ids = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where api.name = 'aws-cloudtrail-describe-trails' and json.rule = name equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\" as X; config from cloud.resource where api.name = 'aws-cloudtrail-get-trail-status' as Y; filter '$.X.name equals $.Y.trail and $.Y.status.isLogging is false'; show X;"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

 # AWS CloudTrail logs Not Encrypted
module "policy_aws_cloudtrail_logs_are_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail logs are not encrypted"
  policy_description        = <<EOF
Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information. 
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to AWS Console and navigate to the 'CloudTrail' service.
2. For each trail, under Configuration > Storage Location, select 'Yes' to 'Encrypt log files' setting
3.Choose and existing KMS key or create a new one to encrypt the logs with.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id, module.cs_application.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name='aws-cloudtrail-describe-trails' AND cloud.type = 'aws' AND json.rule = kmsKeyId does not exist and (name does not equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\")"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS CloudTrail logs should integrate with CloudWatch for all regions
module "policy_aws_cloudtrail_logs_should_integrate_with_cloudwatch_for_all_regions" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS CloudTrail logs should integrate with CloudWatch for all regions"
  policy_description        = <<EOF
This policy identifies the foundational (LZ) Cloudtrails which is not integrated with cloudwatch for all regions. CloudTrail uses Amazon S3 for log file storage and delivery, so log files are stored durably. In addition to capturing CloudTrail logs within a specified S3 bucket for long term analysis, realtime analysis can be performed by configuring CloudTrail to send logs to CloudWatch Logs. For a trail that is enabled in all regions in an account, CloudTrail sends log files from all those regions to a CloudWatch Logs log group. It is recommended that CloudTrail logs be sent to CloudWatch Logs.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign into AWS and navigate to CloudTrail service.
2. Click on Trail in the left menu navigation and choose the reported cloudtrail.
3. Go to CloudWatch Logs section and click Configure.
4. Define a new or select an existing log group and click Continue to complete the process.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-cloudtrail-describe-trails' as X; config from cloud.resource where api.name = 'aws-cloudtrail-get-trail-status' as Y; filter '(($.X.name == $.Y.trail) and ($.X.cloudWatchLogsLogGroupArn is not empty and $.X.cloudWatchLogsLogGroupArn exists) and $.X.isMultiRegionTrail is false and ($.Y.status.latestCloudWatchLogsDeliveryTime exists) and ($.X.name equal ignore case AWS-Landing-Zone-BaselineCloudTrail or $.X.name equal ignore case aws-controltower-BaselineCloudTrail))'; show X;"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS S3 CloudTrail bucket for which access logging is disabled
module "policy_aws_s3_cloudtrail_bucket_for_which_access_logging_is_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS S3 CloudTrail bucket for which access logging is disabled"
  policy_description        = <<EOF
This policy identifies S3 CloudTrail buckets for which access is disabled. S3 Bucket access logging generates access records for each request made to your S3 bucket. An access log record contains information such as the request type, the resources specified in the request worked, and the time and date the request was processed. It is recommended that bucket access logging be enabled on the CloudTrail S3 bucket.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS Console and navigate to the 'S3' service.
2. Click on the the S3 bucket that was reported.
3. Click on the 'Properties' tab.
4. Under the 'Server access logging' section, select 'Enable' option and provide s3 bucket of your choice in the 'Target bucket'
5. Click on 'Save Changes'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "low"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id,module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name = 'aws-cloudtrail-describe-trails' and json.rule = name equal ignore case AWS-Landing-Zone-BaselineCloudTrail or name equal ignore case aws-controltower-BaselineCloudTrail as X; config from cloud.resource where api.name = 'aws-s3api-get-bucket-acl' AND json.rule = loggingConfiguration.targetBucket does not exist as Y; filter '$.X.s3BucketName equals $.Y.bucketName'; show Y;"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS IAM password policy allows password reuse
module "policy_aws_iam_password_policy_allows_password_reuse" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy allows password reuse"
  policy_description        = <<EOF
This policy identifies IAM policies which allow password reuse . AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS console and navigate to the 'IAM' service.
2. Click on 'Account Settings', check  'Prevent password reuse'.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or passwordReusePrevention equals null or passwordReusePrevention !isType Integer or passwordReusePrevention < 1'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not expire in 90 days
module "policy_aws_iam_password_policy_does_not_expire_in_90_days" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not expire in 90 days"
  policy_description        = <<EOF
This policy identifies the IAM policies which does not have password expiration set to 90 days. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. check 'Enable password expiration' and enter a password expiration period.
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or maxPasswordAge !isType Integer or $.maxPasswordAge > 90 or maxPasswordAge equals 0'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not have a lowercase character
module "policy_aws_iam_password_policy_does_not_have_a_lowercase_character" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not have a lowercase character"
  policy_description        = <<EOF
Checks to ensure that IAM password policy requires a lowercase character. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. check 'Require at least one lowercase letter'.
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or requireLowercaseCharacters is false or requireLowercaseCharacters does not exist'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not have a minimum of 14 characters
module "policy_aws_iam_password_policy_does_not_have_a_minimum_of_14_characters" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not have a minimum of 14 characters"
  policy_description        = <<EOF
Checks to ensure that IAM password policy requires minimum of 14 characters. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. In the 'Minimum password length' field, put 14 or more (As per preference).
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or minimumPasswordLength < 14 or minimumPasswordLength does not exist'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not have a number
module "policy_aws_iam_password_policy_does_not_have_a_number" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not have a number"
  policy_description        = <<EOF
Checks to ensure that IAM password policy requires a number. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. check 'Require at least one number'.
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or requireNumbers is false or requireNumbers does not exist'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not have a symbol
module "policy_aws_iam_password_policy_does_not_have_a_symbol" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not have a symbol"
  policy_description        = <<EOF
Checks to ensure that IAM password policy requires a symbol. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. check 'Require at least one non-alphanumeric character'.
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or requireSymbols equals null or requireSymbols is false or requireSymbols does not exist'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS IAM password policy does not have an uppercase character
module "policy_aws_iam_password_policy_does_not_have_an_uppercase_character" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM password policy does not have an uppercase character"
  policy_description        = <<EOF
This policy identifies AWS accounts in which IAM password policy does not have an uppercase character. AWS IAM (Identity & Access Management) allows customers to secure AWS console access. As a security best practice, customers must have strong password policies in place.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS console and navigate to the 'IAM' service.
2. On the left navigation panel, Click on 'Account Settings'
3. check 'Require at least one uppercase letter'.
4. Click on 'Apply password policy'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'iam:UpdateAccountPasswordPolicy' permission. Successful execution will update the password policy to set the minimum password length to 14, require lowercase, uppercase, symbol, allow users to reset password, cannot reuse the last 24 passwords and password expiration to 90 days."
    cli_script_template = "aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --allow-users-to-change-password --password-reuse-prevention 24 --max-password-age 90"
  }]
  compliance_metadata_ids = [module.cs_platform.iam_policy_csrs_id,module.cs_foundational.iam_policy_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-iam-get-account-password-policy' AND json.rule='isDefaultPolicy is true or requireUppercaseCharacters is false or requireUppercaseCharacters does not exist'"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS S3 buckets are accessible to public
module "policy_aws_s3_buckets_are_accessible_to_public" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS S3 buckets are accessible to public"
  policy_description        = <<EOF
This policy identifies S3 buckets which are publicly accessible. Amazon S3 allows customers to store or retrieve any type of content from anywhere in the web. Often, customers have legitimate reasons to expose the S3 bucket to public, for example, to host website content. However, these buckets often contain highly sensitive enterprise data which if left open to public may result in sensitive data leaks.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS Console
2. Navigate to the 'S3' service
3. Click on the 'S3' resource reported in the alert
4. Click on the 'Permissions'
5. If Access Control List' is set to 'Public' follow below steps
a. Under 'Access Control List', Click on 'Everyone' and uncheck all items
b. Click on Save
6. If 'Bucket Policy' is set to public follow below steps
a. Under 'Bucket Policy', modify the policy to remove public access
b. Click on Save
c. If 'Bucket Policy' is not required delete the existing 'Bucket Policy'.

Note: Make sure updating 'Access Control List' or 'Bucket Policy' does not affect S3 bucket data access.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 's3:PutBucketPublicAccessBlock' permission. Successful execution enables 'Block public access' setting which blocks the public access for the S3 bucket."
    cli_script_template = "aws s3api put-public-access-block --bucket $${resourceName} --public-access-block-configuration \"IgnorePublicAcls=true,RestrictPublicBuckets=true\" --region $${region}"
  }]
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-s3api-get-bucket-acl' AND json.rule = \"((((acl.grants[?(@.grantee=='AllUsers')] size > 0) or policyStatus.isPublic is true) and publicAccessBlockConfiguration does not exist and accountLevelPublicAccessBlockConfiguration does not exist) or ((acl.grants[?(@.grantee=='AllUsers')] size > 0) and ((publicAccessBlockConfiguration.ignorePublicAcls is false and accountLevelPublicAccessBlockConfiguration does not exist) or (publicAccessBlockConfiguration does not exist and accountLevelPublicAccessBlockConfiguration.ignorePublicAcls is false) or (publicAccessBlockConfiguration.ignorePublicAcls is false and accountLevelPublicAccessBlockConfiguration.ignorePublicAcls is false))) or (policyStatus.isPublic is true and ((publicAccessBlockConfiguration.restrictPublicBuckets is false and accountLevelPublicAccessBlockConfiguration does not exist) or (publicAccessBlockConfiguration does not exist and accountLevelPublicAccessBlockConfiguration.restrictPublicBuckets is false) or (publicAccessBlockConfiguration.restrictPublicBuckets is false and accountLevelPublicAccessBlockConfiguration.restrictPublicBuckets is false)))) and websiteConfiguration does not exist and (not tagSets.PublicAccess contains True)\""
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS Redshift cluster logging not enabled
module "policy_aws_redshift_cluster_logging_not_enabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Redshift cluster logging not enabled"
  policy_description        = <<EOF
This policy identifies Redshift clusters that do not have cluster logging enabled.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To enable audit logging for a cluster:

1. Sign in to the AWS Management Console and open the Amazon Redshift console at https://console.aws.amazon.com/redshift/

2. On the navigation menu, choose Clusters, then choose the cluster that you want to update.

3. Choose the Properties tab. On the Database configurations panel, choose Edit, then Edit audit logging.

4. On the Edit audit logging page, choose Turn on and select S3 bucket or CloudWatch. We recommend using CloudWatch because administration is easy and it has helpful features for data visualization.

5. Choose which logs to export.

6. To save your choices, choose Save changes.

EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name = 'aws-redshift-describe-clusters' and json.rule = loggingStatus.loggingEnabled is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Security Group allows all IPv4 traffic on SSH port (22)
module "policy_aws_security_group_allows_all_ipv4_traffic_on_ssh_port_22" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Security Group allows all IPv4 traffic on SSH port (22)"
  policy_description        = <<EOF
This policy identifies Security groups that allow all traffic on SSH port 22. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network. Review your list of security group rules to ensure that your resources are not exposed. As a best practice, restrict SSH solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Before making any changes,cccccbhlfkvkedebnngubcnl please check the impact to your applications/services. If the Security Group reported indeed need to restrict all traffic, follow the instructions below:
1. Log in to the AWS Console
2. Navigate to the 'VPC' service
3. Select the 'Security Group' reported in the alert
4. Click on the 'Inbound Rule'
5. Remove the rule which has 'Source' value as 0.0.0.0/0 or ::/0 and 'Port Range' value as 22 (or range containing 22)
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:RevokeSecurityGroupIngress' permission. Successful execution will update the security group to revoke the ingress rule records with port 22 open to all traffic either on IPv4 or on IPv6 protocol."
    cli_script_template = "aws --region $${region} ec2 revoke-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'; aws --region $${region} ec2 authorize-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"10.0.0.0/8\"}]},{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"172.16.0.0/12\"}]}]';"
  }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-ec2-describe-security-groups' AND json.rule = isShared is false and (not tags[?(@.key=='SshAllowAllTraffic')].value contains True) and (ipPermissions[?any((ipRanges[*] contains 0.0.0.0/0) and (toPort == 22 or fromPort == 22))] exists)"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# # AWS Security Group allows all IPv6 traffic on SSH port (22)
# module "policy_aws_security_group_allows_all_ipv6_traffic_on_ssh_port_22" {  
#   source                    = "./modules/policy_custom"
#   naming_prefix             = var.naming_prefix
#   policy_name               = "AWS Security Group allows all IPv6 traffic on SSH port (22)"
#   policy_description        = <<EOF
# This policy identifies Security groups that allow all traffic on SSH port 22. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network. Review your list of security group rules to ensure that your resources are not exposed. As a best practice, restrict SSH solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.
# EOF
#   policy_type               = "config"
#   policy_recommendation     = <<EOF
# Before making any changes, please check the impact to your applications/services. If the Security Group reported indeed need to restrict all traffic, follow the instructions below:
# 1. Log in to the AWS Console
# 2. Navigate to the 'VPC' service
# 3. Select the 'Security Group' reported in the alert
# 4. Click on the 'Inbound Rule'
# 5. Remove the rule which has 'Source' value as 0.0.0.0/0 or ::/0 and 'Port Range' value as 22 (or range containing 22)
# EOF
#   policy_restrict_dismissal = "false"
#   policy_enabled            = "true"
#   policy_severity           = "high"
#   policy_cloud              = "aws"
#   policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
#   policy_rule_type          = "Config"
#   policy_remediation = [{
#     description         = "This CLI command requires 'ec2:RevokeSecurityGroupIngress' permission. Successful execution will update the security group to revoke the ingress rule records with port 22 open to all traffic either on IPv4 or on IPv6 protocol."
#     cli_script_template = "aws --region $${region} ec2 revoke-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\"}]}]'; aws --region $${region} ec2 authorize-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"10.0.0.0/8\"}]},{\"IpProtocol\":\"tcp\",\"FromPort\":22,\"ToPort\":22,\"IpRanges\":[{\"CidrIp\":\"172.16.0.0/12\"}]}]';"
#   }]
#   compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id, module.cs_application.networking_firewall_csrs_id]
#   rql_search_type         = "config"
#   rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-ec2-describe-security-groups' AND json.rule = isShared is false and (not tags[?(@.key=='SshAllowAllTraffic')].value contains True) and (ipPermissions[?any((ipv6Ranges[*].cidrIpv6 contains ::/0) and (toPort == 22 or fromPort == 22))] exists)"
#   rql_search_time_unit    = "day"
#   rql_search_time_amount  = 7
# }

# AWS Security Group allows all IPv4 traffic on RDP port (3389)
module "policy_aws_security_group_allows_all_ipv4_traffic_on_rdp_port_3389" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Security Group allows all IPv4 traffic on RDP port (3389)"
  policy_description        = <<EOF
This policy identifies Security groups that allow all traffic on RDP port 3389. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network. Review your list of security group rules to ensure that your resources are not exposed. As a best practice, restrict RDP solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Before making any changes, please check the impact to your applications/services. If the Security Group reported indeed need to restrict all traffic, follow the instructions below:
1. Log in to the AWS Console
2. Navigate to the 'VPC' service
3. Select the 'Security Group' reported in the alert
4. Click on the 'Inbound Rule'
5. Remove the rule which has 'Source' value as 0.0.0.0/0 or ::/0 and 'Port Range' value as 3389 (or range containing 3389)
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:RevokeSecurityGroupIngress' permission. Successful execution will update the security group to revoke the ingress rule records with port 3389 open to all traffic either on IPv4 or on IPv6 protocol."
    cli_script_template = "aws --region $${region} ec2 revoke-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"IpRanges\":[{\"CidrIp\":\"0.0.0.0/0\"}]}]'; aws --region $${region} ec2 authorize-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"IpRanges\":[{\"CidrIp\":\"10.0.0.0/8\"}]},{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"IpRanges\":[{\"CidrIp\":\"172.16.0.0/12\"}]}]';"
  }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-ec2-describe-security-groups' AND json.rule = isShared is false and (not tags[?(@.key=='RdpAllowAllTraffic')].value contains True) and (ipPermissions[?any((ipRanges[*] contains 0.0.0.0/0) and (toPort == 3389 or fromPort == 3389))] exists)"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS Security Group allows all IPv6 traffic on RDP port (3389)
module "policy_aws_security_group_allows_all_ipv6_traffic_on_rdp_port_3389" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Security Group allows all IPv6 traffic on RDP port (3389)"
  policy_description        = <<EOF
This policy identifies Security groups that allow all traffic on RDP port 3389. Doing so, may allow a bad actor to brute force their way into the system and potentially get access to the entire network. Review your list of security group rules to ensure that your resources are not exposed. As a best practice, restrict RDP solely to known static IP addresses. Limit the access list to include known hosts, services, or specific employees only.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Before making any changes, please check the impact to your applications/services. If the Security Group reported indeed need to restrict all traffic, follow the instructions below:
1. Log in to the AWS Console
2. Navigate to the 'VPC' service
3. Select the 'Security Group' reported in the alert
4. Click on the 'Inbound Rule'
5. Remove the rule which has 'Source' value as  ::/0 and 'Port Range' value as 3389 (or range containing 3389)
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3"]
  policy_rule_type          = "Config"
  policy_remediation = [{
    description         = "This CLI command requires 'ec2:RevokeSecurityGroupIngress' permission. Successful execution will update the security group to revoke the ingress rule records with port 3389 open to all traffic either on IPv6 protocol."
    cli_script_template = "aws --region $${region} ec2 revoke-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"Ipv6Ranges\":[{\"CidrIpv6\":\"::/0\"}]}]'; aws --region $${region} ec2 authorize-security-group-ingress --group-id $${resourceId} --ip-permissions '[{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"IpRanges\":[{\"CidrIp\":\"10.0.0.0/8\"}]},{\"IpProtocol\":\"tcp\",\"FromPort\":3389,\"ToPort\":3389,\"IpRanges\":[{\"CidrIp\":\"172.16.0.0/12\"}]}]';"
  }]
  compliance_metadata_ids = [module.cs_foundational.networking_firewall_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-ec2-describe-security-groups' AND json.rule = isShared is false and (not tags[?(@.key=='RdpAllowAllTraffic')].value contains True) and (ipPermissions[?any((ipv6Ranges[*].cidrIpv6 contains ::/0) and (toPort == 3389 or fromPort == 3389))] exists)"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS Secrets Manager Not Encrypted
module "policy_aws_secrets_manager_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = " AWS Secrets Manager Not Encrypted"
  policy_description        = <<EOF
AWS secrets manager should be encrypted.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF

EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_secrets_csrs_id, module.cs_application.sec_services_secrets_csrs_id, module.cs_encryption_wmd.storage_object_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name= 'aws-secretsmanager-describe-secret' AND json.rule = kmsKeyId does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS SNS Topic Not Encrypted 
module "policy_aws_sns_topic_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS SNS Topic Not Encrypted"
  policy_description        = <<EOF
AWS SNS Topics need to be encrypted
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Follow this guide (https://docs.aws.amazon.com/sns/latest/dg/sns-enable-encryption-for-topic.html) to configure encryption for your SNS Topic.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_messaging_csrs_id, module.cs_application.compute_messaging_csrs_id, module.cs_encryption_wmd.storage_object_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-sns-get-topic-attributes' AND json.rule = KmsMasterKeyId contains \"alias/aws\" and TopicArn does not contain \"AWS-Landing-Zone-Security-Notification\" and Tags[?(@.key=='DataClassification')].value does not contain \"InternalUseOnly\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS SSM Not Encrypted 
module "policy_aws_ssm_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS SSM Not Encrypted"
  policy_description        = <<EOF
AWS SSM parameter store needs to be encrypted.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Open the AWS Systems Manager console at 1.
2. In the navigation pane, choose Session Manager.
3. Go to the Preferences tab and click Edit.
4. Select the checkbox next to Enable KMS encryption.
5. Choose one of the following options:
6. Select a KMS key from your current account.
7. Enter a KMS key alias or KMS key ARN (manually).
8. Ensure that both users starting sessions and managed nodes have the necessary permissions to use the KMS key through AWS Identity and Access Management (IAM) policies.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_platform.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_object_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name= 'aws-ssm-parameter' AND json.rule = keyId does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EBS volume is not encrypted
module "policy_aws_ebs_volume_is_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EBS volume is not encrypted"
  policy_description        = <<EOF
Customers can protect the data in EBS Volumes using the AWS server-side encryption. If the server-side encryption is not turned on for an EBS Volume with sensitive data, in the event of a data breach, malicious users can gain access to the data.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To enable encryption at region level by default, follow below URL:
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default

Additional Information:

To detect existing EBS volumes that are not encrypted


EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.storage_block_csrs_id, module.cs_application.storage_block_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-ec2-describe-volumes' AND json.rule = 'encrypted is false'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

 # AWS SSM Parameter is not encrypted  
module "policy_aws_ssm_parameter_is_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS SSM Parameter is not encrypted"
  policy_description        = <<EOF
This policy identifies the AWS SSM Parameters which are not encrypted. AWS Systems Manager (SSM) parameters that store sensitive data, for example, passwords, database strings, and permit codes are encrypted so as to meet security and compliance prerequisites. An encrypted SSM parameter is any sensitive information that should be kept and referenced in a protected way.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS Console
2. Go to System Manager
3. In the navigation panel, Click on 'Parameter Store'
4. Choose the reported parameter and port it to a new parameter with Type 'SecureString'
5. Delete the reported parameter by clicking on 'Delete'
6. Click on 'Delete parameters'
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_application.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-ssm-parameter' AND json.rule = tags[?(@.key=='DataClassification')].value does not contain \"InternalUseOnly\" and tags[?(@.key=='Accelerator')].value does not contain \"AWSAccelerator\" and type does not contain SecureString and name does not equal ignore case \"/org/member/local_sns_arn\" and name does not start with \"/accelerator/\" and name does not start with \"/sbsa_images/\" and name does not start with \"/cdk-bootstrap/accel/\" and name does not contain \"ams\" and name does not contain \"NextInstanceNumber\" and name does not equal ignore case \"/sbg_org_level_framework/BackupFrameworkArn\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}
 
# AWS Access logging not enabled on S3 buckets
module "policy_aws_access_logging_not_enabled_on_s3_buckets" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Access logging not enabled on S3 buckets"
  policy_description        = <<EOF
Checks for S3 buckets without access logging turned on. Access logging allows customers to view complete audit trail on sensitive workloads such as S3 buckets. It is recommended that Access logging is turned on for all S3 buckets to meet audit & compliance requirement
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Login to the AWS Console and navigate to the 'S3' service.
2. Click on the the S3 bucket that was reported.
3. Click on the 'Properties' tab.
4. Under the 'Server access logging' section, select 'Enable logging' option.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name='aws-s3api-get-bucket-acl' AND json.rule='(loggingConfiguration.targetBucket equals null or loggingConfiguration.targetPrefix equals null) and (not tagSets.DataClassification contains \"InternalUseOnly\") and (not tagSets.DataClassification contains \"Public\")'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Elastic Load Balancer v2 (ELBv2) with access log disabled
module "policy_aws_elastic_load_balancer_v2_elbv2_with_access_log_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Elastic Load Balancer v2 (ELBv2) with access log disabled"
  policy_description        = <<EOF
This policy identifies Elastic Load Balancers v2 (ELBv2) which have access log disabled. Access logs capture detailed information about requests sent to your load balancer and each log contains information such as the time the request was received, the client's IP address, latencies, request paths, and server responses. You can use these access logs to analyze traffic patterns and troubleshoot issues.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Create the S3 bucket log file destination 
	1. Create a file on your computer that should have the contents of the CloudFormation Configuration Template shared at the bottom of this page (https://aws-tools.standardbank.co.za/confluence/display/CSER/AWS+Elastic+Load+Balancer+Logging).
	2. Open the AWS CloudFormation console.
	3. In the console, select the specific region from region drop down on the top right corner, for which the alert is generated (The bucket must be located in the same Region as the load balancer.). 
	4. Click Create stack, choose With new resources (standard).
	5. In the Specify template section, select Upload a template file and do the following:
		a. Click Choose file, locate and select the file created in step 1 above.
		b. Click Next.
	6. Provide a Stack name, choose Next.
	7. Provide the required template parameters.
		a. Parameters such as the ELBLogsReplicationS3BucketName and ELBLogsReplicationS3BucketOwnerAccountID should be obtained from the Template Parameters table at the bottom of this page.
		b. Choose Next.
	8. Choose Next.
	9. Click to acknowledge the creation of AWS IAM resources.
  10. Choose Submit.

Enable access logs
	1. Open the Amazon EC2 console
	2. In the navigation pane, choose Load Balancers.
	3. Select your load balancer.
	4. Click to view the Attributes tab.
	5. Click Edit, do the following:
		a. For Access logs, select Enable.
		b. For S3 URI, choose Browse S3.
		c. Choose the S3 bucket that was created using the configuration template in the previous task (Create the S3 bucket log file destination).  
		d. Choose Save changes.
EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-elbv2-describe-load-balancers' AND json.rule = \"state.code contains active and ['attributes'].['access_logs.s3.enabled'] contains false\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS API Gateway with Public Endpoints
module "policy_aws_api_gateway_with_public_endpoints" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS API Gateway with Public Endpoints"
  policy_description        = <<EOF
List all AWS API Gateways configured with Public Endpoints
EOF
  policy_type               = "config"
  policy_recommendation     = ""
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-apigateway-get-rest-apis' AND json.rule = endpointConfiguration.types does not contain \"PRIVATE\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EBS Snapshot is not encrypted" 
module "policy_aws_ebs_snapshot_is_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EBS Snapshot is not encrypted"
  policy_description        = <<EOF
  AWS EBS Snapshots need to be encrypted https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
   https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_application.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-ec2-describe-snapshots' AND json.rule = snapshot.encrypted is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS RDS DB cluster Snapshot is not encrypted
module "policy_aws_rds_cluster_snapshot_is_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS RDS DB cluster Snapshot is not encrypted"
  policy_description        = <<EOF
  RDS Cluster snapshots need to be encrypted
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
   1.    Open the Amazon RDS console, and then choose Snapshots from the navigation pane.
2.    Select the snapshot that you want to encrypt.
3.    Under Snapshot Actions, choose Copy Snapshot.
4.    Choose your Destination Region, and then enter your New DB Snapshot Identifier.
5.    Change Enable Encryption to Yes.
6.    Select your AWS KMS Key from the list.
7.    Choose Copy Snapshot.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_application.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name= 'aws-rds-db-cluster-snapshots' AND json.rule = storageEncrypted is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Classic Load Balancer not configured to span multiple Availability Zones
module "policy_aws_classic_load_balancer_not_configured_to_span_multiple_availability_zones" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Classic Load Balancer not configured to span multiple Availability Zones"
  policy_description        = <<EOF
This policy identifies AWS Classic Load Balancers that are not configured to span multiple Availability Zones. Classic Load Balancer would not be able to redirect traffic to targets in another Availability Zone if the sole configured Availability Zone becomes unavailable. As best practice, it is recommended to configure Classic Load Balancer to span multiple Availability Zones.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To configure AWS Classic Load Balancer to span multiple Availability Zones follow the steps mentioned in below URL:

https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-disable-az.html#add-availability-zone
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "low"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_web_app_svcs_csrs_id, module.cs_application.compute_web_app_svcs_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-elb-describe-load-balancers' AND json.rule = description.availabilityZones[*] size less than 2"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS IAM policy allows decryption actions on all KMS keys
module "policy_aws_iam_policy_allows_decryption_actions_on_all_kms_keys" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS IAM policy allows decryption actions on all KMS keys"
  policy_description        = <<EOF
This policy identifies IAM policies that allow decryption actions on all KMS keys. Instead of granting permissions for all keys, determine the minimum set of keys that users need to access encrypted data. You should grant to identities only the kms:Decrypt or kms:ReEncryptFrom permissions and only for the keys that are required to perform a task. By adopting the principle of least privilege, you can reduce the risk of unintended disclosure of your data.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
  To allow a user to encrypt and decrypt with any CMK in a specific AWS account; refer following example:
https://docs.aws.amazon.com/kms/latest/developerguide/customer-managed-policies.html#iam-policy-example-encrypt-decrypt-one-account

To allow a user to encrypt and decrypt with any CMK in a specific AWS account and Region; refer following example:
https://docs.aws.amazon.com/kms/latest/developerguide/customer-managed-policies.html#iam-policy-example-encrypt-decrypt-one-account-one-region

To allow a user to encrypt and decrypt with specific CMKs; refer following example:
https://docs.aws.amazon.com/kms/latest/developerguide/customer-managed-policies.html#iam-policy-example-encrypt-decrypt-specific-cmks
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "informational"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.iam_policy_csrs_id, module.cs_application.iam_policy_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name= 'aws-iam-get-policy-version' AND json.rule = document.Statement[?any(Effect equals Allow and Resource equals * and (Action contains kms:* or Action contains kms:Decrypt or Action contains kms:ReEncryptFrom) and Condition does not exist)] exists"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Secrets Manager secret rotation is not enabled
module "policy_aws_secrets_manager_secret_rotation_is_not_enabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Secrets Manager secret rotation is not enabled"
  policy_description        = <<EOF
This policy identifies AWS Secrets Manager secrets that do not have rotation enabled.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To configure automatic rotation for an AWS Secrets Manager secret follow the steps mentioned in URL below:

https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_turn-on-for-other.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "low"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_cryptography_csrs_id, module.cs_application.sec_services_cryptography_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-secretsmanager-describe-secret' AND json.rule = rotationEnabled is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Accounts Missing Mandatory Security Tags
module "policy_aws_accounts_missing_mandatory_security_tags" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Accounts Missing Mandatory Security Tags"
  policy_description        = <<EOF
The policy detects resoucres that do not have the mandatory tags.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
    Add/update the required tags on the account
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.sec_services_resource_security_csrs_id, module.cs_foundational.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-organizations-account' AND json.rule = tags[?(@.key=='CalloutGroup')] does not exist OR tags[?(@.key=='UTRKey')] does not exist OR (tags[?(@.key=='TechnicalOwner')] does not exist OR tags[?(@.key=='BSL_SystemOwner')] does not exist) OR tags[?(@.key=='CalloutGroup')].value is empty OR tags[?(@.key=='UTRKey')].value is empty OR (tags[?(@.key=='TechnicalOwner')].value is empty OR tags[?(@.key=='BSL_SystemOwner')].value is empty)"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}
 
module "policy_aws_fsx_windows_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS FSx Windows Not Encrypted"
  policy_description        = <<EOF
 No Preventative Control for AWS FSx For Windows this policy works to highlight non-compliance as a Detective Control - Encrypt Data Stores
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
  https://docs.aws.amazon.com/fsx/latest/WindowsGuide/encryption-at-rest.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.storage_file_csrs_id, module.cs_application.storage_file_csrs_id, module.cs_encryption_wmd.storage_file_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name = 'aws-fsx-file-system' AND json.rule = FileSystemType does not equal ignore case \"WINDOWS\" AND KmsKeyId does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Bounded IAM Roles Without Permissions Boundary
module "policy_aws_iam_roles_without_permissions_boundary" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Bounded IAM Roles Without Permissions Boundary"
  policy_description        = <<EOF
This policy identifies IAM Roles with no permission boundary.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.iam_account_csrs_id, module.cs_foundational.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-iam-list-roles' AND json.rule = (role.roleName starts with \"Bounded\" or role.roleName starts with \"bounded\" or role.path contains \"bounded\") AND role.permissionsBoundary does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EC2 Missing Backup Tags
module "policy_aws_ec2_missing_backup_tags" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EC2 Missing Backup Tags"
  policy_description        = <<EOF
Backups are effective againist Ransome ware attacks. This policy ensured all EC2 have backup tags
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Add nessesary tag
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_resource_security_csrs_id, module.cs_application.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND cloud.accountgroup = 'AWS South Africa Default Group' AND api.name = 'aws-ec2-describe-instances' AND resource.status = Active AND json.rule = tags[*].key none start with \"kubernetes.io\" AND tags[?(@.key=='aws:eks:cluster-name')] does not exist AND tags[*].key none start with \"aws:autoscaling\" AND (tags[?(@.key=='ams:rt:backup')] does not exist OR tags[?(@.key=='ams:rt:backup')].value is empty)"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS S3 Bucket Without Backup Tags
module "policy_aws_s3_missing_backup_tags" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS S3 Bucket Missing Backup Tags"
  policy_description        = <<EOF
Backups are effective againist Ransome ware attacks. This policy ensurs all S3 buckets have backup tags
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Add nessesary tag
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_resource_security_csrs_id, module.cs_application.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3api-get-bucket-acl' AND json.rule = tagSets.Backup does not exist"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS MSSQL Servers Without Active Directory Authentication Enabled
module "policy_aws_mssql_server_without_active_directory_enabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS MSSQL Servers Without Active Directory Authentication Enabled"
  policy_description        = <<EOF
Best practice for database authentication is authoritive Identity, the policy detects MS SQL Servers not using Active Directory Authentication.
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
    https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/User.SQLServer.ActiveDirectoryWindowsAuth.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_resource_security_csrs_id, module.cs_application.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.accountgroup = 'AWS South Africa Default Group' AND resource.status = Active AND api.name = 'aws-rds-describe-db-instances' AND json.rule = engine starts with \"sqlserver\" AND domainMemberships is empty"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EBS volume region with encryption is disabled
module "policy_aws_ebs_volume_region_with_encryption_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EBS volume region with encryption is disabled"
  policy_description        = <<EOF
This policy identifies AWS regions in which new EBS volumes are getting created without any encryption. Encrypting data at rest reduces unintentional exposure of data stored in EBS volumes. It is recommended to configure EBS volume at the regional level so that every new EBS volume created in that region will be enabled with encryption by using a provided encryption key.
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Log in to the AWS Management Console.
2. Navigate to the EC2 dashboard.
3. Under “Elastic Block Store,” select “Volumes.”
4. Click “Create Volume.”
5. Configure the volume settings.
6. Check the box for “Encrypt this volume.”
7. Choose the Key Management Service (KMS) Customer Master Key (CMK) under “Master Key.”
8. Click “Create Volume” 1.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name = 'aws-ec2-ebs-encryption' AND json.rule = ebsEncryptionByDefault is false and region is member of ('AWS Cape Town','AWS Ireland','AWS Frankfurt','AWS North Virginia')"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

#  AWS Config Recording is disabled  q4review
module "policy_aws_config_recording_is_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Config Recording is disabled"
  policy_description        = <<EOF
AWS Config is a web service that performs configuration management of supported AWS resources within your account and delivers log files to you. AWS config uses configuration recorder to detect changes in your resource configurations and capture these changes as configuration items. It continuously monitors and records your AWS resource configurations and allows you to automate the evaluation of recorded configurations against desired configurations. This policy generates alerts when AWS Config recorder is not enabled.
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS Management Console
2. Select the specific region from the top down, for which the alert is generated
3. Navigate to service 'Config' from the 'Services' dropdown.
If AWS Config set up exists,
a. Go to Settings
b. Click on 'Turn On' button under 'Recording is Off' section,
c. provide required information for bucket and role with proper permission
If AWS Config set up doesn't exist
a. Click on 'Get Started'
b. For Step 1, Tick the check box for 'Record all resources supported in this region' under section 'Resource types to record'
c. Under section 'Amazon S3 bucket', select bucket with permission to Config services
d. Under section 'AWS Config role', select a role with permission to Config services
e. Click on 'Next'
f. For Step 2, Select required rule and click on 'Next' otherwise click on 'Skip'
g. For Step 3, Review the created 'Settings' and click on 'Confirm'
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id, module.cs_platform.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND cloud.region IN ( 'AWS Virginia' , 'AWS Frankfurt' ,'AWS Cape Town' ,'AWS Ireland') AND api.name = 'aws-configservice-describe-configuration-recorders' AND json.rule = 'status.recording is true and status.lastStatus equals \"SUCCESS\" and recordingGroup.allSupported is true' as X; count(X) less than 1"  
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS MFA is not enabled on Root account
module "policy_aws_mfa_is_not_enabled_on_root_account" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS MFA is not enabled on Root account"
  policy_description        = <<EOF
Policy checks that MFA is enabled on Root Accounts
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Enable MFA on root account 
log Remedy with Active Directory Team
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.iam_account_csrs_id, module.cs_foundational.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND cloud.account = 'Production Landing Zone' and api.name = 'aws-iam-get-credential-report' AND json.rule = 'user equals \"<root_account>\" and mfa_active is false and arn does not contain gov:'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS access keys not used for more than 60 days
module "policy_aws_access_keys_not_used_for_more_than_60_days" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS access keys not used for more than 60 days"
  policy_description        = <<EOF
This policy identifies IAM users for which access keys are not used for more than 60 days. Access keys allow users programmatic access to resources. However, if any access key has not been used in the past 60 days, then that access key needs to be deleted (even though the access key is inactive)
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To delete the reported AWS User access key follow below mentioned URL:
https://aws.amazon.com/premiumsupport/knowledge-center/delete-access-key/
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.iam_account_csrs_id, module.cs_application.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type ='aws' and api.name = 'aws-iam-get-credential-report' AND json.rule = '(access_key_1_active is true and ((access_key_1_last_used_date != N/A and _DateTime.ageInDays(access_key_1_last_used_date) > 60) or (access_key_1_last_used_date == N/A and access_key_1_last_rotated != N/A and _DateTime.ageInDays(access_key_1_last_rotated) > 60))) or (access_key_2_active is true and ((access_key_2_last_used_date != N/A and _DateTime.ageInDays(access_key_2_last_used_date) > 60) or (access_key_2_last_used_date == N/A and access_key_2_last_rotated != N/A and _DateTime.ageInDays(access_key_2_last_rotated) > 60)))'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}
# AWS access keys not used for more than 365 days
module "policy_aws_access_keys_not_used_for_more_than_365_days" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS access keys not used for more than 365 days"
  policy_description        = <<EOF
This policy identifies IAM users for which access keys are not used for more than 365 days. Access keys allow users programmatic access to resources. However, if any access key has not been used in the past 365 days, then that access key needs to be deleted (even though the access key is inactive) module.policy_aws_access_keys_not_used_for_more_than_365_days.prismacloud_rql_search.this
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To delete the reported AWS User access key follow below mentioned URL:
https://aws.amazon.com/premiumsupport/knowledge-center/delete-access-key/
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.iam_account_csrs_id, module.cs_application.iam_account_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type ='aws' and api.name = 'aws-iam-get-credential-report' AND json.rule = '(access_key_1_active is true and ((access_key_1_last_used_date != N/A and _DateTime.ageInDays(access_key_1_last_used_date) > 365) or (access_key_1_last_used_date == N/A and access_key_1_last_rotated != N/A and _DateTime.ageInDays(access_key_1_last_rotated) > 365))) or (access_key_2_active is true and ((access_key_2_last_used_date != N/A and _DateTime.ageInDays(access_key_2_last_used_date) > 365) or (access_key_2_last_used_date == N/A and access_key_2_last_rotated != N/A and _DateTime.ageInDays(access_key_2_last_rotated) > 365)))'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EC2 Missing patching Tags
module "policy_aws_ec2_missing_patching_tags" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EC2 Missing Patching Tags"
  policy_description        = <<EOF
Pathes remediate vulnerabilities and are vital to security of resoucres. This policy ensures all EC2 have patching tags
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
Add nessesary tag
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_resource_security_csrs_id, module.cs_application.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-ec2-describe-instances' AND resource.status = Active AND json.rule = tags[*].key none start with \"kubernetes.io\" AND tags[?(@.key=='aws:eks:cluster-name')] does not exist AND tags[*].key none start with \"aws:autoscaling\" AND (tags[?(@.key=='PatchGroup')] does not exist OR tags[?(@.key=='PatchGroup')].value is empty)"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AMS Backup Vaults without Vault Lock enabled
module "policy_aws_backup_vaults_without_vault_lock" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AMS Backup Vaults without Vault Lock enabled"
  policy_description        = <<EOF
Policy Detects backup Vaults without vault lock enabled
  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To add a vault lock to your backup vault:
1. Sign in to the AWS Management Console, and open the AWS Backup console at https://console.aws.amazon.com/backup.
2. In the navigation pane, find Backup vaults. Click the link nested under Backup vaults called Vault locks.
3. Under How vault locks work or Vault locks, click + Create vault lock.
4. In the pane Vault lock details, choose which vault to which you want your lock applied.
5. Under Vault lock mode choose in which mode you want your vault locked. For more information on choosing your modes, see Vault lock modes earlier on this page.
6. For the Retention period, choose the minimum and maximum retention periods (retention periods are optional). New backup and copy jobs created in the vault will fail if they do not conform to the retention periods you set; these periods will not apply to recovery points that already in the vault.
7. If you chose compliance mode, a section called Vault lock start date is shown. If you chose Governance mode, this will not be displayed, and this step can be skipped.

In compliance mode, a vault lock has a cooling-off period from the creation of the vault lock until the vault and its lock becomes immutable and unchangeable. You choose the duration of this period (called grace time), though it must be at least 3 days (72 hours).

Important
Once the grace time is expired, the vault and its lock are immutable. It cannot be changed or deleted by any user or by AWS.

When you are satisfied with the configuration choices, click Create vault lock.

To confirm you wish to create this lock in the chosen mode, type confirm in the text box, then check the box acknowledging the configuration is as intended.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Platform Compliance 2024Q3"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_platform.sec_services_resource_security_csrs_id, module.cs_foundational.sec_services_resource_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND resource.status = Active AND api.name = 'aws-backup-vault-access-policy' AND json.rule = Locked equals \"false\" AND BackupVaultName starts with \"LZA\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

#  AWS CloudTrail logs Not Encrypted
module "policy_aws_cloudtrail_logs_not_encryped" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = " AWS CloudTrail logs Not Encrypted"
  policy_description        = <<EOF
 Checks to ensure that CloudTrail logs are encrypted. AWS CloudTrail is a service that enables governance, compliance, operational & risk auditing of the AWS account. It is a compliance and security best practice to encrypt the CloudTrail data since it may contain sensitive information. 
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
  1. Login to AWS Console and navigate to the 'CloudTrail' service.
2. For each trail, under Configuration > Storage Location, select 'Yes' to 'Encrypt log files' setting
3.Choose and existing KMS key or create a new one to encrypt the logs with.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.sec_services_platform_security_csrs_id, module.cs_application.sec_services_platform_security_csrs_id, module.cs_encryption_wmd.sec_services_platform_security_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name='aws-cloudtrail-describe-trails' AND cloud.type = 'aws' AND json.rule = kmsKeyId does not exist and (name does not equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\")"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

#   AWS DynamoDB Not Encrypted
module "policy_aws_DynamoDb_not_encryped" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS DynamoDB Not Encrypted"
  policy_description        = <<EOF
 Checks to ensure that AWS DynamoDb is encrypted.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
  Sign in to the AWS Management Console and open the DynamoDB console at https://console.aws.amazon.com/dynamodb/.
1. In the navigation pane on the left side of the console, choose Tables.
2. Choose Create Table. For the Table name, enter Music. For the primary key, enter Artist, and for the sort key, enter SongTitle, both as strings.
3. In Settings, make sure that Customize settings is selected.
4. Under Encryption at rest, choose an encryption type - AWS owned key, AWS managed key, or customer managed key.
5.Owned by Amazon DynamoDB. AWS owned key, specifically owned and managed by DynamoDB. You are not charged an additional fee for using this key.
6.AWS managed key. Key alias: aws/dynamodb. The key is stored in your account and is managed by AWS Key Management Service (AWS KMS). AWS KMS charges apply.
7.Stored in your account, and owned and managed by you. Customer managed key. The key is stored in your account and is managed by AWS Key Management Service (AWS KMS). AWS KMS charges apply.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where api.name='aws-cloudtrail-describe-trails' AND cloud.type = 'aws' AND json.rule = kmsKeyId does not exist and (name does not equal ignore case \"AWS-Landing-Zone-BaselineCloudTrail\" or name equal ignore case \"aws-controltower-BaselineCloudTrail\")"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EKS cluster endpoint access publicly enabled
module "policy_aws_eks_cluster_endpoint_publicly_enabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EKS cluster endpoint access publicly enabled"
  policy_description        = <<EOF
 When you create a new cluster, Amazon EKS creates an endpoint for the managed Kubernetes API server that you use to communicate with your cluster (using Kubernetes management tools such as kubectl). By default, this API server endpoint is public to the internet, and access to the API server is secured using a combination of AWS Identity and Access Management (IAM) and native Kubernetes Role Based Access Control (RBAC).
This policy checks your Kubernetes cluster endpoint access and triggers an alert if publicly enabled.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
  1. Go to the AWS Management Console.
2. Click on the EKS service.
3. Click on the Clusters tab.
4. Select the cluster that you want to update.
5. Click on the Networking tab.
6. For Private endpoint, select Enabled.
7. For Public access, select Disabled.
8. Click on the Save button
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_virtual_machines_csrs_id, module.cs_application.compute_virtual_machines_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-eks-describe-cluster' AND json.rule =  resourcesVpcConfig.endpointPublicAccess is true or resourcesVpcConfig.endpointPrivateAccess is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS EKS control plane logging disabled
module "policy_aws_eks_control_plane_logging_disabled" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EKS control plane logging disabled"
  policy_description        = <<EOF
 Amazon EKS control plane logging provides audit and diagnostic logs directly from the Amazon EKS control plane to CloudWatch Logs in your account. These logs make it easy for you to secure and run your clusters. You can select the exact log types you need, and logs are sent as log streams to a group for each Amazon EKS cluster in CloudWatch.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
To enable control plane logs:

1. Login to AWS Console
2. Navigate to the Amazon EKS dashboard
3. Choose the name of the cluster to display your cluster information
4. Under Logging, choose 'Manage logging'
5. For each individual log type, choose Enabled
6. Click on 'Save changes'
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.logging_monitoring_mgmnt_plane_csrs_id, module.cs_application.logging_monitoring_mgmnt_plane_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-eks-describe-cluster' AND json.rule =  logging.clusterLogging[*].types[*] all empty or logging.clusterLogging[*].enabled is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# AWS Redshift Cluster Not Encrypted
module "policy_aws_redshift_cluster_not_encrypted" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Redshift Cluster Not Encrypted"
  policy_description        = <<EOF
 Checks to ensure that AWS Redshift Cluster Not Encrypted.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
  https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-db-encryption.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "medium"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id, module.cs_encryption_wmd.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-redshift-describe-clusters' AND json.rule = encrypted is false"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# # AWS SQS queue Not Encrypted
# module "policy_aws_sqs_queue_not_encrypted" {
#   source                    = "./modules/policy_custom"
#   naming_prefix             = var.naming_prefix
#   policy_name               = "AWS SQS queue Not Encrypted"
#   policy_description        = <<EOF
#  This policy identifies SQS queues which are encrypted.
#   EOF  
#   policy_type               = "config"
#   policy_recommendation     = <<EOF
#   1. Sign in to the AWS console
# 2. Select the region, from the region drop-down, in which the alert is generated
# 3. Navigate to Simple Queue Service (SQS) dashboard
# 4. Choose the reported Simple Queue Service (SQS)
# 5. Click on 'Queue Actions' and Choose 'Configure Queue' from the dropdown 
# 6. On 'Configure' popup, Under 'Server-Side Encryption (SSE) Settings' section; Choose an 'AWS KMS Customer Master Key (CMK)' from the drop-down list or copy existing key ARN instead of (Default) alias/aws/sqs key.
# 7. Click on 'Save Changes'
#   EOF
#   policy_restrict_dismissal = "false"
#   policy_enabled            = "true"
#   policy_severity           = "medium"
#   policy_cloud              = "aws"
#   policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
#   policy_rule_type          = "Config"
#   compliance_metadata_ids   = [module.cs_foundational.compute_messaging_csrs_id, module.cs_application.compute_messaging_csrs_id, module.cs_encryption_wmd.compute_messaging_csrs_id]
#   rql_search_type           = "config"
#   rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-sqs-get-queue-attributes' AND json.rule = attributes.KmsMasterKeyId does not exist"
#   rql_search_time_unit      = "day"
#   rql_search_time_amount    = 7
# }

# AWS EBS snapshots are accessible to public " 
module "policy_aws_ebs_snapshots_are_accesible_to_public_tr" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS EBS snapshots are accessible to public (TR)"
  policy_description        = <<EOF
  This policy identifies EC2 EBS snapshots which are accessible to public. Amazon Elastic Block Store (Amazon EBS) provides persistent block storage volumes for use with Amazon EC2 instances in the AWS Cloud. If EBS snapshots are inadvertently shared to public, any unauthorized user with AWS console access can gain access to the snapshots and gain access to sensitive data.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
   1. Log in to the AWS console
2. In the console, select the specific region from region drop down on the top right corner, for which the alert is generated
3. Navigate to 'EC2' service.
4. Under the 'Elastic Block Storage', click on the 'Snapshots'.
5. For the specific Snapshots, change the value of field 'Property' to 'Private'.
6. Under the section 'Encryption Details', set the value of 'Encryption Enabled' to 'Yes'.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_application.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-ec2-describe-snapshots' AND json.rule='createVolumePermissions[*].group contains all'"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}


# AWS Redshift cluster instance with public access setting enabled Trusted Remediator
module "policy_aws_redshift_cluster_instance_with_public_access_setting_enabled_tr" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS Redshift cluster instance with public access setting enabled (TR)"
  policy_description        = <<EOF
This policy identifies AWS Redshift clusters with public access setting enabled.

AWS Redshift, a managed data warehousing service typically stores sensitive and critical data. Allowing public access increases the risk of unauthorized access, data breaches, and potential malicious activities.

As a recommended security measure, it is advised to disable public access for the Redshift cluster.
EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
To modify the publicly accessible setting of the Redshift cluster,
1. Sign in to the AWS console
2. In the console, select the specific region from the region drop-down on the top right corner, for which the alert is generated
3. Navigate to the 'Redshift' service.
4. Click on the checkbox for the identified Redshift cluster name.
5. In the top menu options, click on 'Actions' and select 'Modify publicly accessible setting' as the option.
6. Uncheck the checkbox 'Turn on Publicly accessible' in the 'Publicly accessible' section and click on 'Save Changes' button.

EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.data_svcs_database_csrs_id, module.cs_application.data_svcs_database_csrs_id]
  rql_search_type           = "config"
  rql_search_query          = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-redshift-describe-clusters' AND json.rule = publiclyAccessible is true"
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}

# SBG - AWS s3-bucket-level-public-access-prohibited
module "policy_aws_s3_bucket_level_public_access_prohibited" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS S3 buckets do not have server side encryption"
  policy_description        = <<EOF
This Policy checks whether an Amazon S3 general purpose bucket blocks public access at the bucket level. 
The control fails if any of the following settings are set to false:

ignorePublicAcls
blockPublicPolicy
blockPublicAcls
restrictPublicBuckets

  EOF
  policy_type               = "config"
  policy_recommendation     = <<EOF
https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-level-public-access-prohibited.html
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids = [module.cs_foundational.storage_object_csrs_id, module.cs_application.storage_object_csrs_id, module.cs_encryption_wmd.storage_object_csrs_id]
  rql_search_type         = "config"
  rql_search_query        = "config from cloud.resource where cloud.type = 'aws' AND api.name = 'aws-s3-access-point' AND json.rule = networkOrigin equal ignore case internet and (publicAccessBlockConfiguration does not exist or (publicAccessBlockConfiguration.blockPublicAcls is false or publicAccessBlockConfiguration.ignorePublicAcls is false or publicAccessBlockConfiguration.blockPublicPolicy is false or publicAccessBlockConfiguration.restrictPublicBuckets is false))"
  rql_search_time_unit    = "day"
  rql_search_time_amount  = 7
}

# AWS RDS snapshots are accessible to public (TR)
module "policy_ams_rds_snapshots_are_accessible_to_public_tr" {
  source                    = "./modules/policy_custom"
  naming_prefix             = var.naming_prefix
  policy_name               = "AWS RDS snapshots are accessible to public (TR)"
  policy_description        = <<EOF
 This policy identifies AWS RDS snapshots which are accessible to public. Amazon Relational Database Service (Amazon RDS) is a web service that makes it easier to setup and manage databases. If RDS snapshots are inadvertently shared to public, any unauthorized user with AWS console access can gain access to the snapshots and gain access to sensitive data.
  EOF  
  policy_type               = "config"
  policy_recommendation     = <<EOF
1. Sign in to the AWS console
2. In the console, select the specific region from region drop down on the top right corner, for which the alert is generated
3. Navigate to the 'RDS' service.
4. For the RDS instance reported in the alert, change 'Publicly Accessible' setting to 'No'.
  EOF
  policy_restrict_dismissal = "false"
  policy_enabled            = "true"
  policy_severity           = "high"
  policy_cloud              = "aws"
  policy_labels             = ["Standard Bank Foundational Compliance 2024Q3","Standard Bank Application Compliance 2025Q1.1"]
  policy_rule_type          = "Config"
  compliance_metadata_ids   = [module.cs_foundational.compute_config_services_csrs_id, module.cs_application.compute_config_services_csrs_id, module.cs_encryption_wmd.storage_block_csrs_id]
  rql_search_type           = "config"
  rql_search_query = "config from cloud.resource where cloud.type = 'aws' and api.name='aws-rds-describe-db-snapshots' AND json.rule=\"attributes[?(@.attributeName=='restore')].attributeValues[*] contains all\""
  rql_search_time_unit      = "day"
  rql_search_time_amount    = 7
}
