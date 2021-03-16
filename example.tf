########### Provider and Credentials config

provider "aws" {
  region     = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::XXXXXXXXXXX:role/roleName"
  }
}

provider "aws" {
  alias = "services"
  region     = "us-east-1"
}

########### Variables config

variable "zoneID" {
  default = "ZBM5I4N1F1F4G"
}

########### VPC Creation

# Terraform dev VPC
resource "aws_vpc" "dev" {
    cidr_block = "10.221.0.0/16"
    instance_tenancy = "default"
    enable_dns_support = "true"
    enable_dns_hostnames = "true"
    enable_classiclink = "false"
    tags = {
        Name = "dev",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
}

#########################################################################

### DNS SETTINGS

# Private Route53 dns Zone

resource "aws_route53_zone" "private" {
  name = "dev.internal.empresa.com.br"

  vpc {
    vpc_id = "${aws_vpc.dev.id}"
  }
  tags = {
        Name = "dev-private-dns-zone",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
  }
}

#### PUBLIC CERTIFICATES Creation

# Domain Certificate

resource "aws_acm_certificate" "dev-certificate" {
  domain_name       = "*.dev.empresa.com.br"
  validation_method = "DNS"

  tags = {
    Name = "dev-certificate",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  provider = "aws.services"
  name    = "${aws_acm_certificate.dev-certificate.domain_validation_options.0.resource_record_name}"
  type    = "${aws_acm_certificate.dev-certificate.domain_validation_options.0.resource_record_type}"
  zone_id = var.zoneID
  records = ["${aws_acm_certificate.dev-certificate.domain_validation_options.0.resource_record_value}"]
  ttl     = 60
  depends_on = [aws_acm_certificate.dev-certificate]
}

resource "aws_acm_certificate_validation" "dev-validation" {
  certificate_arn         = "${aws_acm_certificate.dev-certificate.arn}"
  validation_record_fqdns = ["${aws_route53_record.cert_validation.fqdn}"]
  depends_on = [aws_acm_certificate.dev-certificate]
}

####################################################################

### SES Configuration

resource "aws_ses_domain_identity" "ses-dev" {
  domain = "dev.empresa.com.br"
}

resource "aws_ses_domain_mail_from" "mailfrom-dev" {
  domain           = "${aws_ses_domain_identity.ses-dev.domain}"
  mail_from_domain = "mail.${aws_ses_domain_identity.ses-dev.domain}"
  depends_on = ["aws_ses_domain_identity.ses-dev"]
}

resource "aws_route53_record" "ses-dev-verification-record" {
  provider = "aws.services"
  zone_id = var.zoneID
  name    = "_amazonses.dev.empresa.com.br"
  type    = "TXT"
  ttl     = "600"
  records = ["${aws_ses_domain_identity.ses-dev.verification_token}"]
}

resource "aws_ses_domain_identity_verification" "ses-dev-verification" {
  domain = "${aws_ses_domain_identity.ses-dev.id}"
  depends_on = ["aws_route53_record.ses-dev-verification-record"]
}

resource "aws_ses_domain_dkim" "ses-dev-dkim" {
  domain = "${aws_ses_domain_identity.ses-dev.domain}"
}

resource "aws_route53_record" "example_amazonses_dkim_record" {
  provider = "aws.services"
  zone_id = var.zoneID
  count   = 3
  name    = "${element(aws_ses_domain_dkim.ses-dev-dkim.dkim_tokens, count.index)}._domainkey.dev.empresa.com.br"
  type    = "CNAME"
  ttl     = "600"
  records = ["${element(aws_ses_domain_dkim.ses-dev-dkim.dkim_tokens, count.index)}.dkim.amazonses.com"]
}

resource "aws_ses_receipt_rule" "emails-to-s3" {
  provider = "aws.services"
  name          = "dev-emails-to-s3"
  rule_set_name = "default-rule-set"
  recipients    = ["dev.empresa.com.br"]
  enabled       = true
  scan_enabled  = true
  s3_action {
    bucket_name = "artifactory-liberty"
    object_key_prefix = "emails/dev"
    position    = 4
  }
  depends_on = ["aws_ses_domain_identity_verification.ses-dev-verification","aws_ses_email_identity.ses-mail1","aws_ses_email_identity.ses-mail2","aws_ses_email_identity.ses-mail3","aws_ses_email_identity.ses-mail4"]
}

resource "aws_route53_record" "ses-record-dev1" {
  provider = "aws.services"
  ttl     = "300"
  name    = "mail.dev.empresa.com.br"
  type    = "MX"
  zone_id = var.zoneID
  records = ["10 feedback-smtp.us-east-1.amazonses.com"]
}

resource "aws_route53_record" "ses-record-dev2" {
  provider = "aws.services"
  ttl     = "300"
  name    = "dev.empresa.com.br"
  type    = "MX"
  zone_id = var.zoneID
  records = ["10 inbound-smtp.us-east-1.amazonaws.com"]
}

resource "aws_route53_record" "ses-record-dev3" {
  provider = "aws.services"
  ttl     = "300"
  name    = "mail.dev.empresa.com.br"
  type    = "TXT"
  zone_id = var.zoneID
  records = ["v=spf1 include:amazonses.com ~all"]
}

# Email Configurations Change or Add if needed

resource "aws_ses_email_identity" "ses-mail1" {
  email = "atendimento@dev.empresa.com.br"
}

resource "aws_ses_email_identity" "ses-mail2" {
  email = "mkt@dev.empresa.com.br"
}

resource "aws_ses_email_identity" "ses-mail3" {
  email = "desenvolvedores@dev.empresa.com.br"
}

resource "aws_ses_email_identity" "ses-mail4" {
  email = "nao-responda@dev.empresa.com.br"
}

##############################################################

### API Gateway Common Name

resource "aws_api_gateway_domain_name" "api-common-name" {
  certificate_arn = "${aws_acm_certificate_validation.dev-validation.certificate_arn}"
  domain_name     = "api.dev.empresa.com.br"
  depends_on = ["aws_acm_certificate_validation.dev-validation"]
}

# Route53 record
resource "aws_route53_record" "api-dns-record" {
  provider = "aws.services"
  name    = "${aws_api_gateway_domain_name.api-common-name.domain_name}"
  type    = "A"
  zone_id = var.zoneID
  alias {
    evaluate_target_health = true
    name                   = "${aws_api_gateway_domain_name.api-common-name.cloudfront_domain_name}"
    zone_id                = "${aws_api_gateway_domain_name.api-common-name.cloudfront_zone_id}"
  }
  depends_on = ["aws_api_gateway_domain_name.api-common-name"]
}

### API Gateway Role

resource "aws_iam_role" "ApiGW-Role" {
  name = "Role-ApiGW-dev"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
    EOF
  tags = {
    Name        = "Role-ApiGW-dev",
    Environment = "dev",
    Dominio = "Aplicacao",
    Modulo = "Permissionamento"
  }
}

resource "aws_iam_policy_attachment" "pol-attach10" {
  name = "pol-attach10"
  roles      = ["${aws_iam_role.ApiGW-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
  depends_on = [aws_iam_role.ApiGW-Role]
}

resource "aws_iam_policy_attachment" "pol-attach20" {
  name = "pol-attach20"
  roles      = ["${aws_iam_role.ApiGW-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaRole"
  depends_on = [aws_iam_role.ApiGW-Role]
}

##############################################################

### VPC Default Security Group

resource "aws_default_security_group" "SG-dev-default" {
  vpc_id = "${aws_vpc.dev.id}"

  ingress {
    protocol  = -1
    self      = true
    from_port = 0
    to_port   = 0
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
        Name = "SG-dev-default",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
  depends_on = ["aws_vpc.dev"]
}

# Terraform dev Subnets

#Subnet Pub 1
resource "aws_subnet" "dev-public-1" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.0.0/20"
    map_public_ip_on_launch = "true"
    availability_zone = "us-east-1a"

    tags ={
        Name = "dev-public-1",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}

#Subnet Pub 2
resource "aws_subnet" "dev-public-2" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.16.0/20"
    map_public_ip_on_launch = "true"
    availability_zone = "us-east-1b"

    tags ={
        Name = "dev-public-2",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}

#Subnet Private 1
resource "aws_subnet" "dev-private-1" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.32.0/20"
    map_public_ip_on_launch = "false"
    availability_zone = "us-east-1c"

    tags ={
        Name = "dev-private-1",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}

#Subnet Private 2
resource "aws_subnet" "dev-private-2" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.48.0/20"
    map_public_ip_on_launch = "false"
    availability_zone = "us-east-1d"

    tags ={
        Name = "dev-private-2",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}

#Subnet Database 1
resource "aws_subnet" "dev-database-1" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.64.0/20"
    map_public_ip_on_launch = "false"
    availability_zone = "us-east-1e"

    tags ={
        Name = "dev-database-1",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}

#Subnet Database 2
resource "aws_subnet" "dev-database-2" {
    vpc_id = "${aws_vpc.dev.id}"
    cidr_block = "10.221.80.0/20"
    map_public_ip_on_launch = "false"
    availability_zone = "us-east-1f"

    tags ={
        Name = "dev-database-2",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
	depends_on = ["aws_vpc.dev"]
}


# Terraform dev IGW
resource "aws_internet_gateway" "dev-igw" {
    
	vpc_id = "${aws_vpc.dev.id}"

    tags ={
        Name = "dev-igw",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
}

########### VPC Routing

# Terraform dev RT public
resource "aws_route_table" "RT-dev-public" {
    
	vpc_id = "${aws_vpc.dev.id}"
    
	route {
        cidr_block = "0.0.0.0/0"
        gateway_id = "${aws_internet_gateway.dev-igw.id}"
    }

    tags ={
        Name = "RT-dev-public",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
}

# Terraform dev Route Association

resource "aws_route_table_association" "dev-public-1-a" {
    subnet_id = "${aws_subnet.dev-public-1.id}"
    route_table_id = "${aws_route_table.RT-dev-public.id}"
}

resource "aws_route_table_association" "dev-public-2-a" {
    subnet_id = "${aws_subnet.dev-public-2.id}"
    route_table_id = "${aws_route_table.RT-dev-public.id}"
}

########### VPC Access List

#Network ACL

resource "aws_network_acl" "NACL-dev-private" {
  vpc_id = "${aws_vpc.dev.id}"
  subnet_ids = ["${aws_subnet.dev-private-1.id}", "${aws_subnet.dev-private-2.id}", "${aws_subnet.dev-database-1.id}", "${aws_subnet.dev-database-2.id}"]

  ingress {
    protocol   = "tcp"
    rule_no    = 99
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = {
    Name = "NACL-dev-main",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
  depends_on = ["aws_subnet.dev-private-1","aws_subnet.dev-private-2"]
}

########### NAT Gateway Configuration for private subnets

#NAT Gateway configuration.

# Terraform dev NG
resource "aws_eip" "dev-nat" {
	vpc = true
}

resource "aws_nat_gateway" "dev-nat-gw" {
	allocation_id = "${aws_eip.dev-nat.id}"
	subnet_id = "${aws_subnet.dev-public-1.id}"
  tags ={
    Name = "dev-nat-gw",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }          
	depends_on = ["aws_internet_gateway.dev-igw"]
}

# Terraform dev VPC for NAT

resource "aws_route_table" "RT-dev-private" {
    vpc_id = "${aws_vpc.dev.id}"
    route {
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = "${aws_nat_gateway.dev-nat-gw.id}"
    }
    tags ={
        Name = "RT-dev-private",
        Environment = "dev",
        Dominio = "Arquitetura",
        Modulo = "Comunicacao"
    }
}

# Terraform dev private routes association

resource "aws_route_table_association" "dev-private-1-a" {
    subnet_id = "${aws_subnet.dev-private-1.id}"
    route_table_id = "${aws_route_table.RT-dev-private.id}"
	depends_on = ["aws_route_table.RT-dev-private"]
}

resource "aws_route_table_association" "dev-private-2-a" {
    subnet_id = "${aws_subnet.dev-private-2.id}"
    route_table_id = "${aws_route_table.RT-dev-private.id}"
	depends_on = ["aws_route_table.RT-dev-private"]
}

resource "aws_route_table_association" "dev-database-1-a" {
    subnet_id = "${aws_subnet.dev-database-1.id}"
    route_table_id = "${aws_route_table.RT-dev-private.id}"
	depends_on = ["aws_route_table.RT-dev-private"]
}

resource "aws_route_table_association" "dev-database-2-a" {
    subnet_id = "${aws_subnet.dev-database-2.id}"
    route_table_id = "${aws_route_table.RT-dev-private.id}"
	depends_on = ["aws_route_table.RT-dev-private"]
}

#############################################################################

#Create the VPC initial Security Groups

# SG-ALB-dev

resource "aws_security_group" "SG-ALB-dev" {
  name        = "SG-ALB-dev"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.dev.id}"
  depends_on = [aws_default_security_group.SG-dev-default]

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["172.16.40.0/24"]
    description = "OpenVPN private Range"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.220.0.0/16"]
    description = "$ervices VPC"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.32.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.48.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.64.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.80.0/20"]
    description = "Private VPC Range"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG-ALB-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
}

# SG-RDS-dev

resource "aws_security_group" "SG-RDS-dev" {
  name        = "SG-RDS-dev"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.dev.id}"
  depends_on = [aws_default_security_group.SG-dev-default]

  ingress {
    
    from_port   = 3306
    to_port     = 3306
    protocol    = "TCP"
    cidr_blocks = ["172.16.40.0/24"]
    description = "OpenVPN private Range"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.220.0.0/16"]
    description = "$ervices VPC"
  }

    ingress {
    
    from_port   = 3306
    to_port     = 3306
    protocol    = "TCP"
    cidr_blocks = ["10.221.32.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 3306
    to_port     = 3306
    protocol    = "TCP"
    cidr_blocks = ["10.221.48.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 3306
    to_port     = 3306
    protocol    = "TCP"
    cidr_blocks = ["10.221.64.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 3306
    to_port     = 3306
    protocol    = "TCP"
    cidr_blocks = ["10.221.80.0/20"]
    description = "Private VPC Range"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG-RDS-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
}

# SG-EC2-dev

  resource "aws_security_group" "SG-ec2-dev" {
  name        = "SG-ec2-dev"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.dev.id}"
  depends_on = [aws_default_security_group.SG-dev-default]

  ingress {

    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["172.16.40.0/24"]
    description = "OpenVPN private Range"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.220.0.0/16"]
    description = "$ervices VPC"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.32.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.48.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.64.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.80.0/20"]
    description = "Private VPC Range"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG-ec2-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
}

# SG-ECS-dev

resource "aws_security_group" "SG-ecs-dev" {
  name        = "SG-ecs-dev"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${aws_vpc.dev.id}"
  depends_on = [aws_default_security_group.SG-dev-default]

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["172.16.40.0/24"]
    description = "OpenVPN private Range"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.220.0.0/16"]
    description = "$ervices VPC"
  }

  ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.32.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.48.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.64.0/20"]
    description = "Private VPC Range"
  }

    ingress {
    
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.221.80.0/20"]
    description = "Private VPC Range"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "SG-ecs-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
}

################################################################################

# Security Groups rule update to allow traffic from within the default vpc SG

resource "aws_security_group_rule" "sgr1" {
  type            = "ingress"
  from_port       = 0
  to_port         = 0
  protocol        = -1
  description = "default dev SG"
  source_security_group_id = "${aws_default_security_group.SG-dev-default.id}"
  security_group_id = "${aws_security_group.SG-ALB-dev.id}"
}

  resource "aws_security_group_rule" "sgr2" {
  type            = "ingress"
  from_port       = 0
  to_port         = 0
  protocol        = -1
  description = "default dev SG"
  source_security_group_id = "${aws_default_security_group.SG-dev-default.id}"
  security_group_id = "${aws_security_group.SG-ec2-dev.id}"
  }

  resource "aws_security_group_rule" "sgr3" {
  type            = "ingress"
  from_port       = 0
  to_port         = 0
  protocol        = -1
  description = "default dev SG"
  source_security_group_id = "${aws_default_security_group.SG-dev-default.id}"
  security_group_id = "${aws_security_group.SG-ecs-dev.id}"
  }

  resource "aws_security_group_rule" "sgr4" {
  type            = "ingress"
  from_port       = 0
  to_port         = 0
  protocol        = -1
  description = "default dev SG"
  source_security_group_id = "${aws_default_security_group.SG-dev-default.id}"
  security_group_id = "${aws_security_group.SG-RDS-dev.id}"
  }

############################################################################
# Creates Application Load Balancer

#resource "aws_lb" "ALB-dev" {
#  name               = "ALB-dev"
#  internal           = false
#  load_balancer_type = "application"
#  security_groups    = ["${aws_security_group.SG-ALB-dev.id}",
#                        "${aws_default_security_group.SG-dev-default.id}"]
#  subnets            = ["${aws_subnet.dev-public-1.id}",
#                        "${aws_subnet.dev-public-2.id}"]
#
#  enable_deletion_protection = true

  #Enable if you want to send access logs to s3.
  #access_logs {
  #  bucket  = "${aws_s3_bucket.lb_logs.bucket}"
  #  prefix  = "test-lb"
  #  enabled = true
  #}

#  tags = {
#    Name = "ALB-dev",
#    Environment = "dev",
#    Dominio = "Arquitetura",
#    Modulo = "Comunicacao"
#  }
#  depends_on = [aws_security_group.SG-ALB-dev]
#}

#resource "aws_lb_listener" "HTTP" {
#  load_balancer_arn = "${aws_lb.ALB-dev.arn}"
#  port              = "80"
#  protocol          = "HTTP"
#  default_action {
#  type = "fixed-response"
#    fixed_response {
#      content_type = "text/plain"
#      message_body = "The requested path could not be found. Check your URL."
#      status_code  = "400"
#    }
#  }
#}

# Secure Listener, uncomment after getting domain
#resource "aws_lb_listener" "HTTPS" {
#  load_balancer_arn = "${aws_lb.ALB-dev.arn}"
#  port              = "443"
#  protocol          = "HTTPS"
#  ssl_policy        = "ELBSecurityPolicy-2016-08"
#  certificate_arn   = "${aws_acm_certificate_validation.dev-validation.certificate_arn}"
#  default_action {
#  type = "fixed-response"
#    fixed_response {
#      content_type = "text/plain"
#      message_body = "The requested path could not be found. Check your URL."
#      status_code  = "400"
#    }
#  }
#}

##############################################################################

# Network Load Balancers:

resource "aws_lb" "NLB-dev" {
  name               = "NLB-dev"
  internal           = true
  load_balancer_type = "network"
  subnets            = ["${aws_subnet.dev-private-1.id}","${aws_subnet.dev-private-2.id}","${aws_subnet.dev-database-1.id}","${aws_subnet.dev-database-2.id}"]

  enable_deletion_protection = true

  tags = {
    Name        = "NLB-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Comunicacao"
  }
}  

##############################################################################

# S3 Buckets

resource "aws_s3_bucket" "empresa-artifactory-dev" {
  bucket = "empresa-artifactory-dev"
  acl    = "private"
   versioning {
    enabled = true
  }
  lifecycle_rule {
    enabled = true
    noncurrent_version_transition {
        days          = 30
        storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
        days          = 60
        storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
          days = 90
    }
    abort_incomplete_multipart_upload_days = 7
  }
   tags = {
    Name        = "empresa-artifactory-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Armazenamento"
  }
}

resource "aws_s3_bucket" "empresa-emails-messages-dev" {
  bucket = "empresa-emails-messages-dev"
  acl    = "private"
   versioning {
    enabled = true
  }
  lifecycle_rule {
    enabled = true
    noncurrent_version_transition {
        days          = 30
        storage_class = "STANDARD_IA"
    }

    noncurrent_version_transition {
        days          = 60
        storage_class = "GLACIER"
    }

    noncurrent_version_expiration {
          days = 90
    }
    abort_incomplete_multipart_upload_days = 7
  }
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSESPuts",
            "Effect": "Allow",
            "Principal": {
                "Service": "ses.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::empresa-emails-messages-dev/*"
            }
    ]
}
POLICY
   tags = {
    Name        = "empresa-emails-messages-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Armazenamento"
  }
}

#########################################################################

# WAF Rule Sets

# IP sets

resource "aws_waf_ipset" "whitelist-dev" {
  name = "whitelist-dev"

  ip_set_descriptors {
    type  = "IPV4"
    value = "177.92.77.82/32"
  }
  ip_set_descriptors {
    type  = "IPV4"
    value = "189.125.82.2/32"
  }
}

# Rules

resource "aws_waf_rule" "Ruleset-dev" {
  depends_on  = ["aws_waf_ipset.whitelist-dev"]
  name        = "WAF"
  metric_name = "dev"

  predicates {
    data_id = "${aws_waf_ipset.whitelist-dev.id}"
    negated = false
    type    = "IPMatch"
  }
}

#########################################################################

# API Gateway

resource "aws_api_gateway_domain_name" "example" {
  certificate_arn = "${aws_acm_certificate_validation.dev-validation.certificate_arn}"
  domain_name     = "api.dev.empresa.com.br"
  depends_on  = [aws_acm_certificate_validation.dev-validation]
}

resource "aws_api_gateway_vpc_link" "nlb-dev-link" {
  name        = "nlb-dev-link"
  description = "vpc link with internal nlb"
  target_arns = ["${aws_lb.NLB-dev.arn}"]
  depends_on  = [aws_lb.NLB-dev]
}

resource "aws_api_gateway_rest_api" "MyDemoAPI" {
  name        = "MyDemoAPI"
  description = "This is my API for demonstration purposes"
}

resource "aws_api_gateway_resource" "MyDemoResource" {
  rest_api_id = "${aws_api_gateway_rest_api.MyDemoAPI.id}"
  parent_id   = "${aws_api_gateway_rest_api.MyDemoAPI.root_resource_id}"
  path_part   = "mydemoresource"
}

########### VPC Peering Configs

# Peer Provider Config

provider "aws" {
  alias  = "peer"
  region = "us-east-1"
  # Accepter's credentials.
}

# Peering Connection dev x services (Current)

data "aws_caller_identity" "peerIdServices" {
  provider = "aws.peer"
}

# Requester's side of the connection.

resource "aws_vpc_peering_connection" "peering-dev-services" {
  vpc_id        = "${aws_vpc.dev.id}"
# Fixed Value, look in services account
  peer_vpc_id   = "vpc-02078ccd1249010a8"
# Fixed Value, look in services account
  peer_owner_id = "587897644671"
#peer_owner_id = "${data.aws_caller_identity.peer.account_id}"
  peer_region   = "us-east-1"
  auto_accept   = false
  tags = {
    Side = "Requester"
  	Name = "PC-dev-services"
  }
}

# Accepter's side of the connection.

resource "aws_vpc_peering_connection_accepter" "peering-services-dev" {
  provider                  = "aws.peer"
  vpc_peering_connection_id = "${aws_vpc_peering_connection.peering-dev-services.id}"
  auto_accept               = true

  tags = {
    Side = "Accepter"
	Name = "PC-services-dev"
  }
}

########### Add Peering Connection route to route tables in the requester side

# Route for dev-services (Current)

resource "aws_route" "RT-PC-dev-services" {
  route_table_id            = "${aws_route_table.RT-dev-private.id}"
  destination_cidr_block    = "10.220.0.0/16"
  vpc_peering_connection_id = "${aws_vpc_peering_connection.peering-dev-services.id}"
  depends_on                = [aws_vpc_peering_connection.peering-dev-services]
}

########### Add Peering Connection route to route tables in the peer side

# Route for services-dev

resource "aws_route" "RT-PC-services-dev" {
  provider = "aws.peer"
  # Fixed Value, look in services account
  route_table_id            = "rtb-02cc1385862f81cb6"
  destination_cidr_block    = "10.221.0.0/16"
  vpc_peering_connection_id = "${aws_vpc_peering_connection.peering-dev-services.id}"
  depends_on                = [aws_vpc_peering_connection.peering-dev-services]
}


###############################################################################
## RDS Subnet Groups

resource "aws_db_subnet_group" "rdsg-dev" {
  name       = "rdsg-dev"
  subnet_ids = ["${aws_subnet.dev-database-1.id}", "${aws_subnet.dev-database-2.id}"]
  tags = {
    Name        = "RDSG-dev",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Armazenamento"
  }
}

###############################################################################
## ECS IAM Role

resource "aws_iam_role" "ecs-Role" {
  name = "Role-ECS-dev"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "ecs.amazonaws.com",
          "ecs-tasks.amazonaws.com"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
    EOF
  tags = {
    Name        = "Role-ECS-dev",
    Environment = "dev",
    Dominio = "Aplicacao",
    Modulo = "Permissionamento"
  }
}

resource "aws_iam_policy_attachment" "pol-attach1" {
  name = "pol-attach1"
  roles      = ["${aws_iam_role.ecs-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
  depends_on = [aws_iam_role.ecs-Role]
}

resource "aws_iam_policy_attachment" "pol-attach2" {
  name = "pol-attach2"
  roles      = ["${aws_iam_role.ecs-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
  depends_on = [aws_iam_role.ecs-Role]
}

resource "aws_iam_policy_attachment" "pol-attach3" {
  name = "pol-attach3"
  roles      = ["${aws_iam_role.ecs-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
  depends_on = [aws_iam_role.ecs-Role]
}

resource "aws_iam_policy_attachment" "pol-attach4" {
  name = "pol-attach4"
  roles      = ["${aws_iam_role.ecs-Role.name}"]
  policy_arn = "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
  depends_on = [aws_iam_role.ecs-Role]
}

##################################################################

### Cloudfront Distributions

### Site da Plataforma

# S3 Origin Bucket

resource "aws_s3_bucket" "dev-site-bucket" {
  depends_on = ["aws_cloudfront_origin_access_identity.origin_access_identity"]
  bucket = "dev.empresa.com.br"
  acl    = "private"
   versioning {
    enabled = true
  }
  policy = <<POLICY
{
    "Version": "2008-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::dev.empresa.com.br/*"
        }
    ]
}
POLICY
   tags = {
    Name        = "dev.empresa.com.br",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Armazenamento"
  }
}

# Cloudfront Origin Access Identity

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "CDN OAI padrao dev"
}

locals {
  s3_origin_id = "myS3Origin"
}

# Cloudfront Distribution

resource "aws_cloudfront_distribution" "site-dev-distribution" {
  depends_on = ["aws_acm_certificate.dev-certificate2","aws_s3_bucket.dev-site-bucket","aws_cloudfront_origin_access_identity.origin_access_identity"]
  origin {
    domain_name = "${aws_s3_bucket.dev-site-bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "dev site CDN"
  default_root_object = "index.html"
  logging_config {
    include_cookies = false
    bucket          = "empresa-logs-dev.s3.amazonaws.com"
    prefix          = "CDN/dev.empresa.com.br"
  }
  aliases = ["dev.empresa.com.br"]
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }
  price_class = "PriceClass_All"
  viewer_certificate {
    acm_certificate_arn = "${aws_acm_certificate.dev-certificate2.arn}"
    ssl_support_method = "sni-only"
    minimum_protocol_version = "TLSv1.1_2016"
  }
  restrictions {
    geo_restriction {
    restriction_type = "none"
    }
  }
  custom_error_response {
        error_caching_min_ttl = 0
        error_code = 403
        response_code = 200
        response_page_path = "/index.html"
  }
  custom_error_response {
        error_caching_min_ttl = 0
        error_code = 404
        response_code = 200
        response_page_path = "/index.html"
  }
  tags = {
    Name        = "CDN site dev",
    Environment = "dev",
    Dominio = "Distribuicao",
    Modulo = "Arquitetura"
  }
}

# CDN Route53 record
resource "aws_route53_record" "cdn-dns-record" {
  provider = "aws.services"
  name    = "dev.empresa.com.br"
  type    = "A"
  zone_id = var.zoneID
  alias {
    evaluate_target_health = false
    name                   = "${aws_cloudfront_distribution.site-dev-distribution.domain_name}"
    zone_id                = "${aws_cloudfront_distribution.site-dev-distribution.hosted_zone_id}"
  }
  depends_on = ["aws_cloudfront_distribution.site-dev-distribution"]
}

### Site de Pesquisa

# S3 Origin Bucket

resource "aws_s3_bucket" "pesquisa-dev-site-bucket" {
  depends_on = ["aws_cloudfront_origin_access_identity.origin_access_identity"]
  bucket = "pesquisa.dev.empresa.com.br"
  acl    = "private"
   versioning {
    enabled = true
  }
  policy = <<POLICY
{
    "Version": "2008-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::pesquisa.dev.empresa.com.br/*"
        }
    ]
}
POLICY
   tags = {
    Name        = "pesquisa.dev.empresa.com.br",
    Environment = "dev",
    Dominio = "Arquitetura",
    Modulo = "Armazenamento"
  }
}

# Cloudfront Distribution

resource "aws_cloudfront_distribution" "pesquisa-site-dev-distribution" {
  depends_on = ["aws_acm_certificate.dev-certificate","aws_s3_bucket.pesquisa-dev-site-bucket","aws_cloudfront_origin_access_identity.origin_access_identity"]
  origin {
    domain_name = "${aws_s3_bucket.pesquisa-dev-site-bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
  }
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Pesquisa dev site CDN"
  default_root_object = "index.html"
  logging_config {
    include_cookies = false
    bucket          = "empresa-logs-dev.s3.amazonaws.com"
    prefix          = "CDN/pesquisa-dev.empresa.com.br"
  }
  aliases = ["pesquisa.dev.empresa.com.br"]
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }
  price_class = "PriceClass_All"
  viewer_certificate {
    acm_certificate_arn = "${aws_acm_certificate.dev-certificate.arn}"
    ssl_support_method = "sni-only"
    minimum_protocol_version = "TLSv1.1_2016"
  }
  restrictions {
    geo_restriction {
    restriction_type = "none"
    }
  }
  custom_error_response {
        error_caching_min_ttl = 0
        error_code = 403
        response_code = 200
        response_page_path = "/index.html"
  }
  custom_error_response {
        error_caching_min_ttl = 0
        error_code = 404
        response_code = 200
        response_page_path = "/index.html"
  }
  tags = {
    Name        = "CDN Pesquisa dev",
    Environment = "dev",
    Dominio = "Distribuicao",
    Modulo = "Arquitetura"
  }
}

# CDN Route53 record
resource "aws_route53_record" "cdn-pesquisa-dns-record" {
  provider = "aws.services"
  name    = "pesquisa.dev.empresa.com.br"
  type    = "A"
  zone_id = var.zoneID
  alias {
    evaluate_target_health = false
    name                   = "${aws_cloudfront_distribution.pesquisa-site-dev-distribution.domain_name}"
    zone_id                = "${aws_cloudfront_distribution.pesquisa-site-dev-distribution.hosted_zone_id}"
  }
  depends_on = ["aws_cloudfront_distribution.pesquisa-site-dev-distribution"]
}

##