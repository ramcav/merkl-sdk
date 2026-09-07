output "kms_key_arn" {
  description = "Goes into the enclave image as MERKL_KMS_KEY_ID, at build time."
  value       = aws_kms_key.policy_key.arn
}

output "kms_key_alias" {
  value = aws_kms_alias.policy_key.name
}

output "instance_id" {
  description = "`aws ssm start-session --target <this>` to reach the parent."
  value       = aws_instance.signer.id
}

output "parent_role_arn" {
  value = aws_iam_role.parent.arn
}

output "pinned_pcrs" {
  description = "Echoed back so a plan diff shows an allowlist change as an allowlist change."
  value       = local.pcr_conditions
}

output "signer_endpoint" {
  description = <<-EOT
    Where the agent reaches the signer, from the instance itself or through SSM
    port forwarding. Never a public address: the security group has no ingress
    rule and the proxy refuses to bind anything but loopback.
  EOT
  value       = "http://127.0.0.1:8787"
}
