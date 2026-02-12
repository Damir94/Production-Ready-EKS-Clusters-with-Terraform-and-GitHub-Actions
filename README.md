## Configuring Production-Ready EKS Clusters with Terraform and GitHub Actions

![eks-terraform](https://github.com/user-attachments/assets/baf4f47d-5e92-4351-ad6c-0aba66affa07)

Today, we will configure the Production Ready EKS Cluster using Terraform, an IaC(Infrastructure as Code) tool and Automate using GitHub Actions.

### Why are we using GitHub Actions?
We use GitHub Actions to automate work around our code so things happen automatically, consistently, and safely instead of manually.
Automation (No Manual Work)

Instead of doing this manually:
  - Build the app
  - Run tests
  - Build Docker images
  - Push images to Docker Hub
  - Deploy to Kubernetes / AWS
  - GitHub Actions does it automatically.

Let’s now explore GitHub Actions and configure a production-ready Amazon EKS cluster.

Amazon EKS is a key AWS service that enables us to deploy and manage Kubernetes applications in the cloud in a scalable and secure way.

Instead of focusing on basic “Hello World” examples, we’ll follow real industry best practices and understand how a production-grade EKS cluster should be designed and configured.

### Before getting started with this blog, make sure you have the following prerequisites:
  - An active AWS account
  - AWS credentials (access key and secret key).
  - ⚠️ While Administrator access may be used for learning purposes, it is strongly recommended to follow the principle of least privilege in real-world environments.
  - A solid understanding of Terraform
  - Basic knowledge of YAML, especially for defining GitHub Actions workflows

To configure the EKS Cluster, we are going to use a modular approach. You can feel free to jump on the Terraform code by clicking on the repo link
```bash
repo link
```
But if you want to understand what configurations we are doing, then you can continue in this blog and read the detailed information of each configuration.

### Directory Structure Overview

![structr](https://github.com/user-attachments/assets/653f45a5-c325-4e0a-9535-8a8a49bc2f8f)

### modules directory
This directory contains all the Terraform resource definitions related to the EKS cluster and its supporting services, such as IAM, VPC, and other required components.

### eks directory
In this directory, we define the resources based on our specific requirements. We also invoke (call) the reusable modules created inside the modules directory.

### Module Directory Breakdown
We’ll begin by exploring the files inside the modules directory.

### The gather.tf file is used to fetch the TLS certificate for the EKS cluster.
This certificate is required to configure an OIDC identity provider, which allows us to create IAM roles and policies that can be securely assumed by Kubernetes service accounts.
This setup is a critical best practice for enabling secure IAM integration with EKS.
### gather.tf
```hcl
data "tls_certificate" "eks-certificate" {
  url = aws_eks_cluster.eks[0].identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "eks_oidc_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks-oidc.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:default:aws-test"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks-oidc.arn]
      type        = "Federated"
    }
  }
}
```
### The vpc.tf file is responsible for provisioning all VPC-related AWS resources required for the EKS cluster, including:
  - A Virtual Private Cloud (VPC)
  - An Internet Gateway to enable internet access for public subnets
  - Public and private subnets, created based on the desired number of subnets
  - Public and private route tables, each associated with their respective subnet types
  - A NAT Gateway to allow outbound internet access from private subnets
  - An Elastic IP, which is required for the NAT Gateway
  - A security group for the EKS cluster, configured to restrict access to only authorized users or networks

This setup follows AWS and Kubernetes best practices by isolating workloads in private subnets while maintaining controlled and secure connectivity.
### vpc.tf
```hcl
locals {
  cluster-name = var.cluster-name
}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr-block
  instance_tenancy     = "default"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = var.vpc-name
    Env  = var.env

  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name                                          = var.igw-name
    env                                           = var.env
    "kubernetes.io/cluster/${local.cluster-name}" = "owned"
  }

  depends_on = [aws_vpc.vpc]
}

resource "aws_subnet" "public-subnet" {
  count                   = var.pub-subnet-count
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = element(var.pub-cidr-block, count.index)
  availability_zone       = element(var.pub-availability-zone, count.index)
  map_public_ip_on_launch = true

  tags = {
    Name                                          = "${var.pub-sub-name}-${count.index + 1}"
    Env                                           = var.env
    "kubernetes.io/cluster/${local.cluster-name}" = "owned"
    "kubernetes.io/role/elb"                      = "1"
  }

  depends_on = [aws_vpc.vpc,
  ]
}

resource "aws_subnet" "private-subnet" {
  count                   = var.pri-subnet-count
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = element(var.pri-cidr-block, count.index)
  availability_zone       = element(var.pri-availability-zone, count.index)
  map_public_ip_on_launch = false

  tags = {
    Name                                          = "${var.pri-sub-name}-${count.index + 1}"
    Env                                           = var.env
    "kubernetes.io/cluster/${local.cluster-name}" = "owned"
    "kubernetes.io/role/internal-elb"             = "1"
  }

  depends_on = [aws_vpc.vpc,
  ]
}


resource "aws_route_table" "public-rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = var.public-rt-name
    env  = var.env
  }

  depends_on = [aws_vpc.vpc
  ]
}

resource "aws_route_table_association" "name" {
  count          = 3
  route_table_id = aws_route_table.public-rt.id
  subnet_id      = aws_subnet.public-subnet[count.index].id

  depends_on = [aws_vpc.vpc,
    aws_subnet.public-subnet
  ]
}

resource "aws_eip" "ngw-eip" {
  domain = "vpc"

  tags = {
    Name = var.eip-name
  }

  depends_on = [aws_vpc.vpc
  ]

}

resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.ngw-eip.id
  subnet_id     = aws_subnet.public-subnet[0].id

  tags = {
    Name = var.ngw-name
  }

  depends_on = [aws_vpc.vpc,
    aws_eip.ngw-eip
  ]
}

resource "aws_route_table" "private-rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.ngw.id
  }

  tags = {
    Name = var.private-rt-name
    env  = var.env
  }

  depends_on = [aws_vpc.vpc,
  ]
}

resource "aws_route_table_association" "private-rt-association" {
  count          = 3
  route_table_id = aws_route_table.private-rt.id
  subnet_id      = aws_subnet.private-subnet[count.index].id

  depends_on = [aws_vpc.vpc,
    aws_subnet.private-subnet
  ]
}

resource "aws_security_group" "eks-cluster-sg" {
  name        = var.eks-sg
  description = "Allow 443 from Jump Server only"

  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] // It should be specific IP range
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = var.eks-sg
  }
}
```

### The iam.tf file is used to create all IAM roles required for the EKS cluster:

EKS Cluster Role – allows the cluster to manage AWS resources securely

Node Group Role – used by the worker nodes in the cluster

OIDC Role – enables Kubernetes service accounts to assume IAM roles via OIDC, which is essential for fine-grained permissions inside the cluster

Note:
The EKS cluster role typically uses the AmazonEKSClusterPolicy, which is standard for cluster operations.
For node group roles, you may need to attach additional policies depending on your application requirements, as the nodes often require different permissions (e.g., S3 access, DynamoDB access, or CloudWatch logging).

This approach follows best practices by separating cluster and node permissions and using OIDC for secure role assumption inside Kubernetes.
### iam.tf
```hcl
locals {
  cluster_name = var.cluster-name
}

resource "random_integer" "random_suffix" {
  min = 1000
  max = 9999
}

resource "aws_iam_role" "eks-cluster-role" {
  count = var.is_eks_role_enabled ? 1 : 0
  name  = "${local.cluster_name}-role-${random_integer.random_suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  count      = var.is_eks_role_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks-cluster-role[count.index].name
}

resource "aws_iam_role" "eks-nodegroup-role" {
  count = var.is_eks_nodegroup_role_enabled ? 1 : 0
  name  = "${local.cluster_name}-nodegroup-role-${random_integer.random_suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks-AmazonWorkerNodePolicy" {
  count      = var.is_eks_nodegroup_role_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks-nodegroup-role[count.index].name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKS_CNI_Policy" {
  count      = var.is_eks_nodegroup_role_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks-nodegroup-role[count.index].name
}
resource "aws_iam_role_policy_attachment" "eks-AmazonEC2ContainerRegistryReadOnly" {
  count      = var.is_eks_nodegroup_role_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks-nodegroup-role[count.index].name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEBSCSIDriverPolicy" {
  count      = var.is_eks_nodegroup_role_enabled ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.eks-nodegroup-role[count.index].name
}

# OIDC
resource "aws_iam_role" "eks_oidc" {
  assume_role_policy = data.aws_iam_policy_document.eks_oidc_assume_role_policy.json
  name               = "eks-oidc"
}

resource "aws_iam_policy" "eks-oidc-policy" {
  name = "test-policy"

  policy = jsonencode({
    Statement = [{
      Action = [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "*"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks-oidc-policy-attach" {
  role       = aws_iam_role.eks_oidc.name
  policy_arn = aws_iam_policy.eks-oidc-policy.arn
}
```

### The eks.tf file is responsible for configuring the EKS cluster and its node groups:
  - We are creating a private EKS cluster, ensuring that the control plane is not exposed to the public internet.
  - Private node groups are also configured, so the worker nodes operate within private subnets for better security.
Node Groups Configuration:
  - On-Demand Node Group – provides stable, always-available compute capacity
  - Spot Node Group – uses spare EC2 capacity at a lower cost, optimizing cloud spend
This setup follows industry best practices, balancing security, availability, and cost optimization.

### eks.tf
```hcl
resource "aws_eks_cluster" "eks" {

  count    = var.is-eks-cluster-enabled == true ? 1 : 0
  name     = var.cluster-name
  role_arn = aws_iam_role.eks-cluster-role[count.index].arn
  version  = var.cluster-version

  vpc_config {
    subnet_ids              = [aws_subnet.private-subnet[0].id, aws_subnet.private-subnet[1].id, aws_subnet.private-subnet[2].id]
    endpoint_private_access = var.endpoint-private-access
    endpoint_public_access  = var.endpoint-public-access
    security_group_ids      = [aws_security_group.eks-cluster-sg.id]
  }


  access_config {
    authentication_mode                         = "CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  tags = {
    Name = var.cluster-name
    Env  = var.env
  }
}

# OIDC Provider
resource "aws_iam_openid_connect_provider" "eks-oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks-certificate.certificates[0].sha1_fingerprint]
  url             = data.tls_certificate.eks-certificate.url
}


# AddOns for EKS Cluster
resource "aws_eks_addon" "eks-addons" {
  for_each      = { for idx, addon in var.addons : idx => addon }
  cluster_name  = aws_eks_cluster.eks[0].name
  addon_name    = each.value.name
  addon_version = each.value.version

  depends_on = [
    aws_eks_node_group.ondemand-node,
    aws_eks_node_group.spot-node
  ]
}

# NodeGroups
resource "aws_eks_node_group" "ondemand-node" {
  cluster_name    = aws_eks_cluster.eks[0].name
  node_group_name = "${var.cluster-name}-on-demand-nodes"

  node_role_arn = aws_iam_role.eks-nodegroup-role[0].arn

  scaling_config {
    desired_size = var.desired_capacity_on_demand
    min_size     = var.min_capacity_on_demand
    max_size     = var.max_capacity_on_demand
  }

  subnet_ids = [aws_subnet.private-subnet[0].id, aws_subnet.private-subnet[1].id, aws_subnet.private-subnet[2].id]

  instance_types = var.ondemand_instance_types
  capacity_type  = "ON_DEMAND"
  labels = {
    type = "ondemand"
  }

  update_config {
    max_unavailable = 1
  }
  tags = {
    "Name" = "${var.cluster-name}-ondemand-nodes"
  }
  tags_all = {
    "kubernetes.io/cluster/${var.cluster-name}" = "owned"
    "Name" = "${var.cluster-name}-ondemand-nodes"
  }

  depends_on = [aws_eks_cluster.eks]
}

resource "aws_eks_node_group" "spot-node" {
  cluster_name    = aws_eks_cluster.eks[0].name
  node_group_name = "${var.cluster-name}-spot-nodes"

  node_role_arn = aws_iam_role.eks-nodegroup-role[0].arn

  scaling_config {
    desired_size = var.desired_capacity_spot
    min_size     = var.min_capacity_spot
    max_size     = var.max_capacity_spot
  }

  subnet_ids = [aws_subnet.private-subnet[0].id, aws_subnet.private-subnet[1].id, aws_subnet.private-subnet[2].id]

  instance_types = var.spot_instance_types
  capacity_type  = "SPOT"

  update_config {
    max_unavailable = 1
  }
  tags = {
    "Name" = "${var.cluster-name}-spot-nodes"
  }
  tags_all = {
    "kubernetes.io/cluster/${var.cluster-name}" = "owned"
    "Name" = "${var.cluster-name}-ondemand-nodes"
  }
  labels = {
    type      = "spot"
    lifecycle = "spot"
  }
  disk_size = 50

  depends_on = [aws_eks_cluster.eks]
}
```
### The variables.tf file defines all the input variables used across the module files, such as iam.tf, vpc.tf, eks.tf, and others.

These variables make the Terraform code flexible and reusable, allowing you to configure values like:
  - VPC CIDR blocks
  - Subnet counts
  - Node group sizes
  - IAM role names
  - EKS cluster settings
By using variables, we can easily customize the infrastructure without changing the resource definitions themselves, following Terraform best practices.
### variables.tf
```hcl
variable "cluster-name" {}
variable "cidr-block" {}
variable "vpc-name" {}
variable "env" {}
variable "igw-name" {}
variable "pub-subnet-count" {}
variable "pub-cidr-block" {
  type = list(string)
}
variable "pub-availability-zone" {
  type = list(string)
}
variable "pub-sub-name" {}
variable "pri-subnet-count" {}
variable "pri-cidr-block" {
  type = list(string)
}
variable "pri-availability-zone" {
  type = list(string)
}
variable "pri-sub-name" {}
variable "public-rt-name" {}
variable "private-rt-name" {}
variable "eip-name" {}
variable "ngw-name" {}
variable "eks-sg" {}

#IAM
variable "is_eks_role_enabled" {
  type = bool
}
variable "is_eks_nodegroup_role_enabled" {
  type = bool
}

# EKS
variable "is-eks-cluster-enabled" {}
variable "cluster-version" {}
variable "endpoint-private-access" {}
variable "endpoint-public-access" {}
variable "addons" {
  type = list(object({
    name    = string
    version = string
  }))
}
variable "ondemand_instance_types" {}
variable "spot_instance_types" {}
variable "desired_capacity_on_demand" {}
variable "min_capacity_on_demand" {}
variable "max_capacity_on_demand" {}
variable "desired_capacity_spot" {}
variable "min_capacity_spot" {}
variable "max_capacity_spot" {}
```
### Creating the Module and Configuring the Backend
Now that all the resources have been defined, we need to create a module to deploy them.

### The backend.tf file configures remote state management for Terraform:
  - The Terraform state file (tfstate) is stored in an S3 bucket, ensuring the state is centralized and persistent.
  - State locking is enabled using a DynamoDB table to prevent multiple users or processes from making concurrent changes, avoiding deployment conflicts.

Important Notes:
  - You must manually create the S3 bucket and DynamoDB table in your AWS account before applying Terraform.
  - Update the bucket name and table name in the backend.tf configuration to match your resources.
  - When creating the DynamoDB table, set the Partition Key as LockID with type String (default).
Using S3 + DynamoDB for remote state storage is an industry best practice for collaboration and reliable Terraform deployments.
### backend.tf
```hcl
terraform {
  required_version = "~> 1.9.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.49.0"
    }
  }
  backend "s3" {
    bucket         = "dev-damir-tf-bucket"
    region         = "us-east-1"
    key            = "eks/terraform.tfstate"
    dynamodb_table = "Lock-Files"
    encrypt        = true
  }
}

provider "aws" {
  region = var.aws-region
}
```

### The main.tf file is used to instantiate the modules defined in the ../modules directory:
  - It calls the reusable modules for resources such as VPC, IAM, and EKS.
  - The configuration uses variables so that values can be provided via a .tfvars file, making it easy to manage different environments (e.g., dev, staging, production).
By following this approach, you can reuse the same infrastructure code across multiple environments while keeping configurations consistent and maintainable.

### main.tf
```hcl
locals {
  org = "ap-medium"
  env = var.env
}

module "eks" {
  source = "../module"

  env                   = var.env
  cluster-name          = "${local.env}-${local.org}-${var.cluster-name}"
  cidr-block            = var.vpc-cidr-block
  vpc-name              = "${local.env}-${local.org}-${var.vpc-name}"
  igw-name              = "${local.env}-${local.org}-${var.igw-name}"
  pub-subnet-count      = var.pub-subnet-count
  pub-cidr-block        = var.pub-cidr-block
  pub-availability-zone = var.pub-availability-zone
  pub-sub-name          = "${local.env}-${local.org}-${var.pub-sub-name}"
  pri-subnet-count      = var.pri-subnet-count
  pri-cidr-block        = var.pri-cidr-block
  pri-availability-zone = var.pri-availability-zone
  pri-sub-name          = "${local.env}-${local.org}-${var.pri-sub-name}"
  public-rt-name        = "${local.env}-${local.org}-${var.public-rt-name}"
  private-rt-name       = "${local.env}-${local.org}-${var.private-rt-name}"
  eip-name              = "${local.env}-${local.org}-${var.eip-name}"
  ngw-name              = "${local.env}-${local.org}-${var.ngw-name}"
  eks-sg                = var.eks-sg

  is_eks_role_enabled           = true
  is_eks_nodegroup_role_enabled = true
  ondemand_instance_types       = var.ondemand_instance_types
  spot_instance_types           = var.spot_instance_types
  desired_capacity_on_demand    = var.desired_capacity_on_demand
  min_capacity_on_demand        = var.min_capacity_on_demand
  max_capacity_on_demand        = var.max_capacity_on_demand
  desired_capacity_spot         = var.desired_capacity_spot
  min_capacity_spot             = var.min_capacity_spot
  max_capacity_spot             = var.max_capacity_spot
  is-eks-cluster-enabled        = var.is-eks-cluster-enabled
  cluster-version               = var.cluster-version
  endpoint-private-access       = var.endpoint-private-access
  endpoint-public-access        = var.endpoint-public-access

  addons = var.addons
}
```

### The variables.tf file defines all the input variables required across the service modules, such as iam.tf, vpc.tf, and eks.tf.
  - These variables are initialized in the corresponding .tfvars file, allowing you to provide environment-specific values.
  - Examples of configurable variables include:
      - VPC CIDR blocks
      - Subnet counts and types
      - Node group sizes
      - IAM role names
      - EKS cluster settings
Using variables in combination with a .tfvars file makes the infrastructure flexible, reusable, and easy to manage across multiple environments.
### variables.tf
```hcl
variable "aws-region" {}
variable "env" {}
variable "cluster-name" {}
variable "vpc-cidr-block" {}
variable "vpc-name" {}
variable "igw-name" {}
variable "pub-subnet-count" {}
variable "pub-cidr-block" {
  type = list(string)
}
variable "pub-availability-zone" {
  type = list(string)
}
variable "pub-sub-name" {}
variable "pri-subnet-count" {}
variable "pri-cidr-block" {
  type = list(string)
}
variable "pri-availability-zone" {
  type = list(string)
}
variable "pri-sub-name" {}
variable "public-rt-name" {}
variable "private-rt-name" {}
variable "eip-name" {}
variable "ngw-name" {}
variable "eks-sg" {}


# EKS
variable "is-eks-cluster-enabled" {}
variable "cluster-version" {}
variable "endpoint-private-access" {}
variable "endpoint-public-access" {}
variable "ondemand_instance_types" {
  default = ["t3a.medium"]
}

variable "spot_instance_types" {}
variable "desired_capacity_on_demand" {}
variable "min_capacity_on_demand" {}
variable "max_capacity_on_demand" {}
variable "desired_capacity_spot" {}
variable "min_capacity_spot" {}
variable "max_capacity_spot" {}
variable "addons" {
  type = list(object({
    name    = string
    version = string
  }))
}
```

### The dev.tfvars file is used to initialize the values for all the variables defined in variables.tf.
  - This allows you to customize configurations such as the number of subnets, node group sizes, or IAM role names.
  - To deploy the same infrastructure in multiple environments (e.g., dev, staging, production):
       - Create a new .tfvars file, like dev.tfvars, with environment-specific values.
       - Optionally, create a separate backend.tf file for that environment.
       - Apply Terraform using the corresponding .tfvars file.
Note: If you’re new to multiple environments, don’t worry—this is just a way to reuse the same Terraform code with different configurations.

### dev.tfvars
```hcl
env                   = "dev"
aws-region            = "us-east-1"
vpc-cidr-block        = "10.16.0.0/16"
vpc-name              = "vpc"
igw-name              = "igw"
pub-subnet-count      = 3
pub-cidr-block        = ["10.16.0.0/20", "10.16.16.0/20", "10.16.32.0/20"]
pub-availability-zone = ["us-east-1a", "us-east-1b", "us-east-1c"]
pub-sub-name          = "subnet-public"
pri-subnet-count      = 3
pri-cidr-block        = ["10.16.128.0/20", "10.16.144.0/20", "10.16.160.0/20"]
pri-availability-zone = ["us-east-1a", "us-east-1b", "us-east-1c"]
pri-sub-name          = "subnet-private"
public-rt-name        = "public-route-table"
private-rt-name       = "private-route-table"
eip-name              = "elasticip-ngw"
ngw-name              = "ngw"
eks-sg                = "eks-sg"

# EKS
is-eks-cluster-enabled     = true
cluster-version            = "1.33"
cluster-name               = "eks-cluster"
endpoint-private-access    = true
endpoint-public-access     = false
ondemand_instance_types    = ["t3a.medium"]
spot_instance_types        = ["c5a.large", "c5a.xlarge", "m5a.large", "m5a.xlarge", "c5.large", "m5.large", "t3a.large", "t3a.xlarge", "t3a.medium"]
desired_capacity_on_demand = "1"
min_capacity_on_demand     = "1"
max_capacity_on_demand     = "5"
desired_capacity_spot      = "1"
min_capacity_spot          = "1"
max_capacity_spot          = "10"
addons = [
  {
    name    = "vpc-cni",
    version = "v1.20.0-eksbuild.1"
  },
  {
    name    = "coredns"
    version = "v1.12.2-eksbuild.4"
  },
  {
    name    = "kube-proxy"
    version = "v1.33.0-eksbuild.2"
  },
  {
    name    = "aws-ebs-csi-driver"
    version = "v1.46.0-eksbuild.1"
  }
  # Add more addons as needed
]
```
### Automating EKS Deployment with GitHub Actions
Now that our Terraform configurations for the EKS cluster are ready, the next step is to automate the deployment using GitHub Actions.

The first step is to securely add your AWS credentials to the GitHub repository:

1. Navigate to your repository Settings.
2. Click on Secrets and variables → Actions.
3. Add the following secrets:
  - AWS_ACCESS_KEY_ID – your AWS access key
  - AWS_SECRET_ACCESS_KEY – your AWS secret key
Storing credentials as secrets ensures that sensitive information is not exposed in your code, following industry best practices for security.

<img width="1461" height="874" alt="Screenshot 2026-01-21 at 12 38 03 PM" src="https://github.com/user-attachments/assets/1df7154b-357b-4084-915c-53dccfd93cc8" />

### Creating a GitHub Actions Workflow for Terraform
After adding your AWS credentials as secrets, the next step is to create a workflow to deploy the infrastructure on AWS using GitHub Actions.

1. In your repository, create a directory:
```bash
.github/workflows
```
2. Inside the workflows directory, you can create one or more workflow files.
For this guide, we will create a file named:
```bash
Terraform.yaml
```
Note: All GitHub Actions workflows are written in YAML format, which defines the steps and triggers for automation.

### Below is the Workflow YAML script
The Workflow will trigger manually and add two parameters (tfvars file name and apply or destroy action)
```yaml
name: 'EKS-Creation-Using-Terraform'

on:
  workflow_dispatch:
    inputs:
      tfvars_file:
        description: 'Path to the .tfvars file'
        required: true
        default: 'dev.tfvars'
      action:
        type: choice
        description: 'Terraform Action'
        options:
          - plan
          - apply
          - destroy
        required: true
        default: 'apply'

env:
  AWS_REGION: us-east-1
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

permissions:
  contents: read

jobs:
  terraform:
    name: Terraform ${{ github.event.inputs.action }}
    runs-on: ubuntu-latest
    environment: production

    defaults:
      run:
        shell: bash
        working-directory: eks

    steps:
      - name: Checkout repository
        uses: actions/checkout@v5

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.9.3
          terraform_wrapper: true

      # Optional: Enable caching to speed up init
      - name: Cache Terraform
        uses: actions/cache@v4
        with:
          path: |
            ~/.terraform.d/plugin-cache
            .terraform
          key: ${{ runner.os }}-terraform-${{ hashFiles('**/*.tf') }}
          restore-keys: |
            ${{ runner.os }}-terraform-

      - name: Terraform Init
        run: terraform init

      - name: Terraform Format Check
        run: terraform fmt -check -diff

      - name: Terraform Validate
        run: terraform validate

      - name: Terraform Plan
        if: ${{ github.event.inputs.action == 'plan' }}
        run: |
          terraform plan -var-file=${{ github.event.inputs.tfvars_file }} -input=false

      - name: Terraform Apply
        if: ${{ github.event.inputs.action == 'apply' }}
        run: |
          terraform apply -auto-approve -var-file=${{ github.event.inputs.tfvars_file }} -input=false

      - name: Terraform Destroy
        if: ${{ github.event.inputs.action == 'destroy' }}
        run: |
          terraform destroy -auto-approve -var-file=${{ github.event.inputs.tfvars_file }} -input=false
```

### To do that, click on Actions

<img width="1918" height="308" alt="Screenshot 2026-01-23 at 12 16 51 PM" src="https://github.com/user-attachments/assets/d4a40adc-5f32-4989-ab99-7cd90ac9a0a7" />

To run the workflow, you need to provide a parameter.

Click on Run workflow after providing the arguments(Initially, we will run the plan only).

<img width="1906" height="620" alt="Screenshot 2026-01-23 at 12 38 26 PM" src="https://github.com/user-attachments/assets/de463f36-6e5c-47a5-b416-a0dfc11de060" />

The Plan is Successful.

<img width="1869" height="668" alt="Screenshot 2026-01-23 at 12 39 43 PM" src="https://github.com/user-attachments/assets/5edc1556-345a-402e-a0b8-829d6645d3b4" />

You can click on Terraform-Action to check the plan

<img width="1657" height="853" alt="Screenshot 2026-01-24 at 6 59 11 PM" src="https://github.com/user-attachments/assets/3456407e-73ca-4232-a8ad-4d9457057a4d" />

Now, we are ready to run the application. Workflow completed, and it has created our EKS Cluster with node groups.

Let’s validate them by viewing them on the Console
### VPC

<img width="688" height="97" alt="Screenshot 2026-02-05 at 12 45 55 PM" src="https://github.com/user-attachments/assets/e50f4bbd-e46a-4b92-a939-57a91028fa06" />

### Public & Private Subnets
![1_vdCErt2UEG80O2NS-1sk0g](https://github.com/user-attachments/assets/7579050e-b7db-40a3-9a9a-1b6d91441418)

### Internet Gateway

![1_TqKRdJZAh0ksZkdwH4jMyA](https://github.com/user-attachments/assets/34767663-934f-4624-ae78-ff43293031eb)

### Elastic IP

![1_TqKRdJZAh0ksZkdwH4jMyA](https://github.com/user-attachments/assets/de8211bd-e221-4e4d-b2b0-d72aea3a8379)

### Security Group

![1_jTUJa9kexm4SGg7i2_30Ug](https://github.com/user-attachments/assets/fdf30504-fbfc-4ce3-b41e-b7026e048f6e)

### EKS Cluster
![1_dCk9vHH4Z4GgXQUXiNSZrw](https://github.com/user-attachments/assets/9ee6c9e5-6f6a-460e-b614-ab59f211dbd4)

### NodeGroups
![1_MQhUxuq4rjrSfmzPtLFFWA](https://github.com/user-attachments/assets/9d0d8cde-d171-407b-91ef-cbca53fb0e51)

### OIDC Connector
![1_inACFoMjD6HRGBrbRdz_-A](https://github.com/user-attachments/assets/b5ee8471-0a47-4004-95b7-5800c29df96c)

If you want to destroy the infrastructure, you can simply go to the Actions Section then click on Terraform workflow
Note: To destroy, select the destroy option from the parameters

Here, our workflow succeeded, and services have been deleted.
