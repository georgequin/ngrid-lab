terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = "ccisonfi-ussd-lab"
      ManagedBy = "terraform"
    }
  }
}

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ---------- network: one public subnet, no NAT gateway, no inbound rules ----------
resource "aws_vpc" "lab" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "ussd-lab" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_subnet" "pub" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.50.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.pub.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_security_group" "lab" {
  name   = "ussd-lab-hosts"
  vpc_id = aws_vpc.lab.id

  dynamic "ingress" {
    for_each = length(var.rdp_cidrs) > 0 ? [1] : []
    content {
      from_port   = 3389
      to_port     = 3389
      protocol    = "tcp"
      cidr_blocks = var.rdp_cidrs
    }
  }
  egress {
    description = "HTTPS: packages, Burp, S3, SSM"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "HTTP: apt mirrors"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------- bundles (students never receive the instructor bundle) ----------
resource "random_id" "sfx" {
  byte_length = 4
}

resource "aws_s3_bucket" "b" {
  bucket        = "ussd-lab-${random_id.sfx.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "student" {
  bucket = aws_s3_bucket.b.id
  key    = "student/student.tar.gz"
  source = "${path.module}/../dist/student.tar.gz"
  etag   = filemd5("${path.module}/../dist/student.tar.gz")
}

resource "aws_s3_object" "instructor" {
  bucket = aws_s3_bucket.b.id
  key    = "instructor/instructor.tar.gz"
  source = "${path.module}/../dist/instructor.tar.gz"
  etag   = filemd5("${path.module}/../dist/instructor.tar.gz")
}

# ---------- IAM for the hosts ----------
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "student" {
  name               = "ussd-lab-student-host"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role" "instructor" {
  name               = "ussd-lab-instructor-host"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_student" {
  role       = aws_iam_role.student.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ssm_instructor" {
  role       = aws_iam_role.instructor.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "s3_student" {
  role = aws_iam_role.student.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.b.arn}/student/*" }]
  })
}

resource "aws_iam_role_policy" "s3_instructor" {
  role = aws_iam_role.instructor.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.b.arn}/*" }]
  })
}

resource "aws_iam_instance_profile" "student" {
  name = "ussd-lab-student"
  role = aws_iam_role.student.name
}

resource "aws_iam_instance_profile" "instructor" {
  name = "ussd-lab-instructor"
  role = aws_iam_role.instructor.name
}

# ---------- per-team secrets (index 0 = instructor lab) ----------
resource "random_password" "team_pw" {
  count   = var.team_count + 1
  length  = 14
  special = false
}

resource "random_password" "lab_secret" {
  count   = var.team_count + 1
  length  = 24
  special = false
}

resource "random_password" "admin_token" {
  count   = var.team_count + 1
  length  = 24
  special = false
}

locals {
  user_data = {
    for i in range(var.team_count + 1) : i => templatefile("${path.module}/userdata.sh.tpl", {
      team         = i
      role         = i == 0 ? "instructor" : "student"
      bucket       = aws_s3_bucket.b.id
      participants = i == 0 ? 3 : var.participants_per_team
      team_pw      = random_password.team_pw[i].result
      lab_secret   = random_password.lab_secret[i].result
      admin_token  = random_password.admin_token[i].result
      burp_url     = var.burp_installer_url
      shutdown_min = var.auto_shutdown_hours * 60
    })
  }
}

# index 0 = instructor lab; 1..N = one workspace per team
resource "aws_instance" "host" {
  count                                = var.team_count + 1
  ami                                  = data.aws_ssm_parameter.ubuntu.value
  instance_type                        = count.index == 0 ? var.instructor_instance_type : var.team_instance_type
  subnet_id                            = aws_subnet.pub.id
  vpc_security_group_ids               = [aws_security_group.lab.id]
  iam_instance_profile                 = count.index == 0 ? aws_iam_instance_profile.instructor.name : aws_iam_instance_profile.student.name
  instance_initiated_shutdown_behavior = "stop"
  user_data                            = local.user_data[count.index]

  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }
  tags = {
    Name = count.index == 0 ? "ussd-lab-instructor" : "ussd-lab-team${count.index}"
    Team = tostring(count.index)
  }
  depends_on = [aws_s3_object.student, aws_s3_object.instructor]
}

# ---------- one IAM user per team: SSM sessions only to that team's instance ----------
resource "aws_iam_user" "team" {
  count = var.team_count
  name  = "ussd-lab-team${count.index + 1}"
}

resource "aws_iam_access_key" "team" {
  count = var.team_count
  user  = aws_iam_user.team[count.index].name
}

resource "aws_iam_user_policy" "team" {
  count = var.team_count
  user  = aws_iam_user.team[count.index].name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "ssm:StartSession"
        Resource  = "arn:aws:ec2:*:*:instance/*"
        Condition = { StringEquals = { "ssm:resourceTag/Team" = tostring(count.index + 1) } }
      },
      {
        Effect   = "Allow"
        Action   = "ssm:StartSession"
        Resource = "arn:aws:ssm:*::document/AWS-StartPortForwardingSession"
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:TerminateSession", "ssm:ResumeSession"]
        Resource = "arn:aws:ssm:*:*:session/$${aws:username}-*"
      },
      {
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances"
        Resource = "*"
      }
    ]
  })
}

# ---------- cost guard ----------
resource "aws_budgets_budget" "lab" {
  name         = "ussd-lab"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$ccisonfi-ussd-lab"]
  }
  dynamic "notification" {
    for_each = [50, 80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.budget_email]
    }
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}
