# Palo Alto Prisma Cloud - Terraform IAC

This repository contains the infrastructure as code templates needed for the SBSA Prisma cloud platform.

## Prerequisites 
1. Access to WEU-AzureSecurity RG in SB-SBG-SecurityShared-NonProd
2. Personal Prisma Cloud access key credentials.
3. [Terraform](https://developer.hashicorp.com/terraform/downloads) Installation

## Getting Started

1. az login                                                 (using EA Account with nessesary Entra PIM)
2. az account set --name SB-SBG-SecurityShared-NonProd      (set working scope)
3. Optional: Run `terraform init`, if this is your first time running terraform or if using a new module.

4. Run terraform `plan / apply / destroy` to manage your Prisma configuration.

NOTE: Take extra care when executing the `terraform destroy` command as this will delete all your configuration/infrastructure. Use the `--target` flag to pick specific resources that need to be destroyed/replaced.


*IMPORTANT TO NOTE:*

1. When configuring remediation on a policy, take care to update the *cli_script_template* attribute in the correct format.

    a) Variables in the cli script will need to be escaped to work with terraform. E.g. a variable named *\${resourceName}* will need to be replaced with *\$${resourceName}*. If this is not done, you will see an error like the following:
    ```
    Error: Invalid reference 
    on policy_aws_custom.tf line 151, in module policy_aws_cloudtrail_log_validation_is_not_enabled_in_all_regions": 
    151:     cli_script_template = "aws cloudtrail update-trail --name ${resourceName} --region ${region} --enable-log-file-validation"
    
    A reference to a resource type must be followed by at least one attribute access, specifying the resource name.
    ```

    b) JSON strings appearing in the the cli script will also need to be escaped. E.g. A cli script 
        
    ```
    "aws s3api put-bucket-encryption --bucket ${resourceName} --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'"
    ```
    will have to be declared as shown below
    ```
    cli_script_template = "aws s3api put-bucket-encryption --bucket $${resourceName} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"