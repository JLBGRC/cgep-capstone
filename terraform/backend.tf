terraform {
  backend "s3" {
    bucket         = "acme-health-capstone-tfstate"
    key            = "intake/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "acme-health-capstone-tflock"
    encrypt        = true
  }
}
