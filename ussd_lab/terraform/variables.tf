variable "region" {
  description = "eu-west-1 is cheap and well supplied. af-south-1 is closer to Lagos but costs more and must be enabled first."
  default     = "eu-west-1"
}
variable "team_count" { default = 5 }
variable "participants_per_team" { default = 10 }
variable "team_instance_type" {
  description = "8 vCPU / 32 GB: 10 Burp Community instances + XFCE desktops + 10 small range containers"
  default     = "m6i.2xlarge"
}
variable "instructor_instance_type" { default = "t3.xlarge" }
variable "root_volume_gb" { default = 60 }
variable "budget_usd" {
  description = "Monthly cost threshold that triggers email alerts"
  default     = 120
}
variable "budget_email" { type = string }
variable "auto_shutdown_hours" {
  description = "Hard stop N hours after each boot (cost safety net)"
  default     = 10
}
variable "burp_installer_url" {
  description = "Burp Suite Community Linux installer. If this URL changes, download it manually and set a new URL."
  default     = "https://portswigger.net/burp/releases/startdownload?product=community&type=Linux"
}
variable "rdp_cidrs" {
  description = "Leave empty: access is via SSM port-forwarding and the hosts have no inbound rules."
  type        = list(string)
  default     = []
}
