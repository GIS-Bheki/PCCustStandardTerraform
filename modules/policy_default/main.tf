data "prismacloud_policy" "default_policy" {
  policy_id = var.default_policy_id
}

resource "prismacloud_policy" "this" {
  name           = join(" - ", [var.naming_prefix, data.prismacloud_policy.default_policy.name])
  policy_type    = data.prismacloud_policy.default_policy.policy_type
  description    = data.prismacloud_policy.default_policy.description
  severity       = data.prismacloud_policy.default_policy.severity
  recommendation = data.prismacloud_policy.default_policy.recommendation
  cloud_type     = data.prismacloud_policy.default_policy.cloud_type
  labels         = var.policy_labels
  enabled        = var.policy_enabled
  rule {
    name     = data.prismacloud_policy.default_policy.rule[0].name
    criteria = data.prismacloud_policy.default_policy.rule[0].criteria
    parameters = {
      "savedSearch" : "true",
      "withIac" : "false"
    }
    rule_type = data.prismacloud_policy.default_policy.rule[0].rule_type
  }
  dynamic "remediation" {
    for_each = var.policy_remediation
    content {
      description         = remediation.value.description
      cli_script_template = remediation.value.cli_script_template
    }
  }
  dynamic "compliance_metadata" {
    for_each = var.compliance_metadata_ids
    content {
      compliance_id = compliance_metadata.value
    }
    # The only mandatory parameter is compliance_id which corresponds to the section ID (not requirement and not compliance. section ID will identify those 2 automatically).
  }
}