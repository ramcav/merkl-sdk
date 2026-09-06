variable "treasury_label" {
  description = "Short label for the treasury this signer serves. One signer per treasury (plan D18)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{1,32}$", var.treasury_label))
    error_message = "treasury_label must be 1-32 lowercase letters, digits or hyphens."
  }
}

variable "region" {
  description = "AWS region. The KMS endpoint the parent proxies to is derived from it."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  description = "Private subnet. The instance needs egress to KMS and nothing inbound."
  type        = string
}

variable "ami_id" {
  description = "Amazon Linux 2023 AMI with nitro-cli. Pin it: a moving AMI is a moving parent."
  type        = string
}

variable "instance_type" {
  description = "Must support Nitro Enclaves: at least 4 vCPU, and not a .metal-only family."
  type        = string
  default     = "m6i.xlarge"
}

variable "enclave_cpu_count" {
  description = "vCPUs handed to the enclave. They leave the parent's pool entirely."
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory handed to the enclave. 1024 is enough for the signer; below 512 it will not boot."
  type        = number
  default     = 1024
}

variable "enclave_pcrs" {
  description = <<-EOT
    Platform Configuration Registers the enclave must report, index to lowercase
    hex, as printed by `nitro-cli build-enclave`. This is the allowlist, and it is
    the only thing standing between the sealed key and any enclave at all.

      PCR0 — the whole image. Changes with every build.
      PCR1 — the kernel and bootstrap. Changes with the nitro-cli version.
      PCR2 — the application. Changes when the code changes but the base does not.
      PCR8 — the certificate a signed image was signed with. Only for signed
             images, and the one PCR that survives a rebuild, which is what makes
             it the right thing to pin if you sign your images.

    Leave an index empty to not pin it. An empty map pins nothing and is refused.
  EOT
  type        = map(string)

  validation {
    condition     = length([for value in values(var.enclave_pcrs) : value if value != ""]) > 0
    error_message = "Pin at least one PCR. A key policy with no measurement condition seals to nothing."
  }

  validation {
    condition = alltrue([
      for value in values(var.enclave_pcrs) : value == "" || can(regex("^[0-9a-f]{96}$", value))
    ])
    error_message = "Each PCR must be 96 lowercase hex characters (a 48-byte SHA-384 digest)."
  }

  validation {
    condition = alltrue([
      for value in values(var.enclave_pcrs) : value != join("", [for _ in range(96) : "0"])
    ])
    error_message = "An all-zero PCR is what a debug-mode enclave reports. Never pin one."
  }
}

variable "kms_proxy_port" {
  description = "Local port the parent's vsock-proxy listens on, forwarding to the KMS endpoint."
  type        = number
  default     = 8000
}

variable "key_deletion_window_days" {
  description = "Deleting the key destroys every sealed blob under it. Leave room to notice."
  type        = number
  default     = 30
}

variable "root_volume_gb" {
  type    = number
  default = 30
}

variable "enable_ssm" {
  description = "Session Manager instead of SSH: no inbound port, no key pair to lose."
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
