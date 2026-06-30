# AWS Secure Configuration Auditor

A Python-based security auditing tool for assessing AWS environments against common cloud security best practices.

The goal of this project is to provide a lightweight, modular framework for identifying AWS security misconfigurations and producing structured security findings through both console and JSON reporting.

> **Project Status:** 🚧 Early Development  
> This repository is currently focused on development of the project architecture, AWS security research, and foundational development. The planned features and associated documentation will expand as implementation of the project progresses.

---

# Objectives

- Learn AWS security and architecture through project implementation
- Audit common AWS services for security misconfigurations
- Produce standardized security and audit findings
- Generate structured JSON reports
- Maintain a modular architecture that allows additional AWS services and security checks to be added over time

---

# Planned Architecture

```
AWS Account
      │
      ▼
AWS Client (boto3)
      │
      ▼
Resource Collectors
      │
      ▼
Security Checks
      │
      ▼
Findings
      │
      ▼
Reporting Engine
      ├── Console Output
      └── JSON Report
```

An architecture diagram will be added as implementation progresses.

---

# Planned Features

## Identity & Access Management (IAM)

- Administrator privilege detection
- MFA enforcement checks
- Access key age analysis
- Inactive access key detection
- Wildcard policy detection
- Root account security review

---

## Amazon S3

- Public bucket detection
- Bucket policy review
- Encryption verification
- Versioning verification
- Logging configuration review

---

## Amazon EC2

- Security Group analysis
- Publicly exposed management ports
- EBS encryption verification
- Instance metadata configuration

---

## Logging & Monitoring

- CloudTrail configuration
- AWS Config status
- GuardDuty status

---

# Planned Repository Structure

```
aws-security-configuration-auditor/
│
├── README.md
├── requirements.txt
├── LICENSE
│
├── docs/
├── examples/
├── reports/
│
└── src/
    ├── main.py
    ├── models.py
    ├── reporting.py
    ├── aws_client.py
    │
    ├── collectors/
    └── checks/
```

---

# Current Development Roadmap

- [x] Project planning
- [x] Initial repository structure
- [ ] AWS IAM research
- [ ] boto3 integration
- [ ] IAM resource collection
- [ ] IAM security checks
- [ ] Findings model
- [ ] JSON reporting
- [ ] Architecture diagram
- [ ] Documentation
- [ ] Screenshots

---

# Technologies

- Python 3
- boto3
- AWS IAM
- Amazon S3
- Amazon EC2
- AWS CloudTrail
- AWS Config
- JSON

---

# Planned Documentation

As development progresses, this repository will include:

- Architecture diagrams
- Detection matrix
- Example reports
- Example AWS configurations
- Screenshots
- Usage documentation

---

# License

MIT
