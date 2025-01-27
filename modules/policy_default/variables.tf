variable "default_policy_id" {
  description = "The ID (guid) of the default Prisma Cloud policy that is to be cloned"
  type        = string
}
variable "policy_labels" {
  description = "Custom defined policy labels"
  type        = list(string)
  default     = []
}
variable "policy_enabled" {
  description = "Enable the policy or not"
  type        = bool
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