variable "rql_search_type" {
  description = "The type of rule - config or event"
  type        = string
}
variable "rql_search_query" {
  description = "The RQL query for this policy"
  type        = string
}
variable "rql_search_time_unit" {
  description = "Time range unit of the RQL query"
  type        = string
}
variable "rql_search_time_amount" {
  description = "Time range amount of the RQL query"
  type        = number
}
variable "policy_name" {
  description = "The name of the policy"
  type        = string
}
variable "policy_description" {
  description = "Description for the policy"
  type        = string
}
variable "policy_type" {
  description = "The type of policy - config audit_event network"
  type        = string
}
variable "policy_recommendation" {
  description = "Guide to how the rule can be remediated"
  type        = string
}
variable "policy_restrict_dismissal" {
  description = "Restrict alert dismissal"
  type        = string
}
variable "policy_enabled" {
  description = "Enable the policy or not"
  type        = string
}
variable "policy_severity" {
  description = "The severity of the policy - low, medium or high"
  type        = string
}
variable "policy_cloud" {
  description = "The name of the cloud platform this policy applies to"
  type        = string
}
variable "policy_labels" {
  description = "Custom defined policy labels"
  type        = list(string)
  default     = []
}
variable "policy_rule_type" {
  description = "The type of rule - Config, AuditEvent or Network"
  type        = string
}
variable "policy_remediation" {
  description = "The remediation cli script declared as a list with exactly one single string element"
  type        = list(map(string))
  default     = []
}
variable "compliance_metadata_ids" {
  description = "Compliance Standard requirement section Ids that link the policy to the applicable Compliance Standards"
  type        = list(string)
  default     = []
}

variable "naming_prefix" {
  description = "Naming prefix to be used for specific policies."
  type        = string
}