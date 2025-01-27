resource "prismacloud_rql_search" "this" {
  search_type = var.rql_search_type
  query       = var.rql_search_query
  skip_result = true
  time_range {
    relative {
      unit   = var.rql_search_time_unit
      amount = var.rql_search_time_amount
    }
  }
}

resource "prismacloud_saved_search" "this" {
  name        = join(" - ", [var.naming_prefix, var.policy_name])
  description = var.policy_description
  search_id   = prismacloud_rql_search.this.search_id
  query       = prismacloud_rql_search.this.query
  time_range {
    relative {
      unit   = prismacloud_rql_search.this.time_range.0.relative.0.unit
      amount = prismacloud_rql_search.this.time_range.0.relative.0.amount
    }
  }
}

resource "prismacloud_policy" "this" {
  name                     = join(" - ", [var.naming_prefix, var.policy_name])
  policy_type              = var.policy_type
  description              = var.policy_description
  recommendation           = var.policy_recommendation
  restrict_alert_dismissal = var.policy_restrict_dismissal
  enabled                  = var.policy_enabled
  severity                 = var.policy_severity
  cloud_type               = var.policy_cloud
  labels                   = var.policy_labels
  rule {
    name      = join(" - ", [var.naming_prefix, var.policy_name])
    criteria  = prismacloud_saved_search.this.search_id
    rule_type = var.policy_rule_type
    parameters = {
      "savedSearch" : true,
      "withIac" : false,
    }
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