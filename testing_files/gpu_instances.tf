resource "aws_instance" "gpu_training" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "p4d.24xlarge"

  tags = {
    Name        = "ai-training-node"
    Environment = "production"
  }
}

resource "aws_instance" "inference" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "g5.xlarge"

  tags = {
    Name = "ml-inference"
  }
}
