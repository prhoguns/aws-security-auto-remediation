variable "region" {
  type    = string
  default = "ca-central-1"
}

variable "alert_email" {
  type        = string
  description = "Address subscribed to the alert topic. Confirm the subscription email after apply."
}

variable "dry_run" {
  type        = bool
  default     = true
  description = "Start in dry-run: the Lambda logs and alerts what it *would* change. Flip to false once you trust it."
}
