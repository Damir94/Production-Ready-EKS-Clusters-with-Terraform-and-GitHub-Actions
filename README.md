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

### gather.tf
The gather.tf file is used to fetch the TLS certificate for the EKS cluster.
This certificate is required to configure an OIDC identity provider, which allows us to create IAM roles and policies that can be securely assumed by Kubernetes service accounts.
This setup is a critical best practice for enabling secure IAM integration with EKS.
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
