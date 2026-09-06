# One enclave-enabled instance, one KMS key that only that enclave can open.
#
# Deployed by the customer, in the customer's own account. Merkl never holds a
# fund-moving key and never holds this one either — the policy key is generated
# inside the enclave and sealed under a key whose policy names measurements the
# customer pinned. Nothing here grants Merkl access to anything.
#
# The whole security argument is in one place: `aws_kms_key.policy_key.policy`.
# Read that first.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  name = "merkl-signer-${var.treasury_label}"

  tags = merge(var.tags, {
    "merkl:component" = "nitro-signer"
    "merkl:treasury"  = var.treasury_label
  })

  # The measurements the enclave must report before KMS will decrypt for it.
  # Empty values are dropped so a partial allowlist is still a real condition
  # rather than a condition that matches everything.
  pcr_conditions = {
    for index, value in var.enclave_pcrs :
    "kms:RecipientAttestation:PCR${index}" => value
    if value != ""
  }
}

# --------------------------------------------------------------------------- #
# The key the policy key is sealed under
# --------------------------------------------------------------------------- #

resource "aws_kms_key" "policy_key" {
  description             = "Seals the Merkl policy signing key to enclave measurements"
  deletion_window_in_days = var.key_deletion_window_days
  enable_key_rotation     = false # a rotated key cannot open blobs sealed under the old one
  tags                    = local.tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Without this, the key is unmanageable the moment the console session
        # ends. It is the standard root statement and it is not a back door into
        # the enclave: an administrator can delete the key, which destroys the
        # sealed blob, and cannot decrypt it, which would require an attestation.
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action = [
          "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*",
          "kms:Update*", "kms:Revoke*", "kms:Disable*", "kms:Get*", "kms:Delete*",
          "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion",
        ]
        Resource = "*"
      },
      {
        # Sealing. Deliberately unconditioned, and this is the subtle part:
        # kms:RecipientAttestation:PCRx is only evaluated for Decrypt,
        # GenerateDataKey, GenerateDataKeyPair and GenerateRandom. Encrypt carries
        # no Recipient, so a statement conditioned on an attestation denies
        # Encrypt outright — and a first boot could not seal the key it just
        # generated. Nothing is given away: a ciphertext is not a secret, and
        # being able to seal a value is not being able to open one.
        Sid       = "AllowEnclaveToSeal"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["kms:Encrypt", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        # Unsealing. This is the statement that matters. KMS validates the
        # attestation document against the AWS Nitro PKI itself and then checks
        # these PCRs. A parent with the role and the credentials still gets
        # AccessDenied, because it has no NSM and cannot produce a document.
        Sid       = "AllowEnclaveToUnseal"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.parent.arn }
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = local.pcr_conditions
        }
      },
    ]
  })
}

resource "aws_kms_alias" "policy_key" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.policy_key.key_id
}

# --------------------------------------------------------------------------- #
# The instance
# --------------------------------------------------------------------------- #

resource "aws_iam_role" "parent" {
  name = "${local.name}-parent"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "parent" {
  name = "${local.name}-parent"
  role = aws_iam_role.parent.id

  # Encrypt and Decrypt only, on one key. The role is a courier: the KMS key
  # policy is what actually decides, and it decides on measurements.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      Resource = aws_kms_key.policy_key.arn
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  # Session Manager instead of SSH: no inbound port, no key pair to lose.
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.parent.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "parent" {
  name = "${local.name}-parent"
  role = aws_iam_role.parent.name
  tags = local.tags
}

resource "aws_security_group" "signer" {
  name        = local.name
  description = "Merkl Nitro signer: no inbound, egress to KMS only"
  vpc_id      = var.vpc_id
  tags        = local.tags

  # No ingress rule at all. The RPC listener is on loopback inside the instance
  # and the agent reaches it over SSM port forwarding or from the same host. A
  # signer reachable from a network is a signer whose only protection is a key.

  egress {
    description = "HTTPS to KMS and SSM"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "signer" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.signer.id]
  iam_instance_profile   = aws_iam_instance_profile.parent.name
  tags                   = merge(local.tags, { Name = local.name })

  # The point of the whole file.
  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 2          # the parent proxy runs in a container
  }

  root_block_device {
    encrypted   = true
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    enclave_cpu_count = var.enclave_cpu_count
    enclave_memory_mb = var.enclave_memory_mib
    kms_endpoint      = "kms.${var.region}.amazonaws.com"
    kms_proxy_port    = var.kms_proxy_port
  })

  lifecycle {
    # A replaced instance is a signer that stops signing until someone starts the
    # enclave again. Deliberate, and worth being deliberate about.
    create_before_destroy = false
  }
}
