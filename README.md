# Description

`Prowler` is an Open Source security tool to perform AWS, GCP and Azure security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness.

It contains hundreds of controls covering CIS, NIST 800, NIST CSF, CISA, RBI, FedRAMP, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, AWS Well-Architected Framework Security Pillar, AWS Foundational Technical Review (FTR), ENS (Spanish National Security Scheme) and your custom security frameworks.

| Provider | Checks | Services | [Compliance Frameworks](https://docs.prowler.cloud/en/latest/tutorials/compliance/) | [Categories](https://docs.prowler.cloud/en/latest/tutorials/misc/#categories) |
|---|---|---|---|---|
| AWS | 301 | 61 -> `prowler aws --list-services` | 25 -> `prowler aws --list-compliance` | 5 -> `prowler aws --list-categories` |
| GCP | 73 | 11 -> `prowler gcp --list-services` | 1 -> `prowler gcp --list-compliance` | 2 -> `prowler gcp --list-categories`|
| Azure | 23 | 4 -> `prowler azure --list-services` | CIS soon | 1 -> `prowler azure --list-categories` |
| Kubernetes | Work In Progress | - | CIS soon | - |

# ⚙️ Install


## From Github

Python >= 3.9, < 3.12 is required with pip and poetry:

```
git clone https://github.com/prowler-cloud/prowler
cd prowler
poetry shell
poetry install
python prowler.py -v
```

# 📐✏️ High level architecture

You can run Prowler from your workstation, an EC2 instance, Fargate or any other container, Codebuild, CloudShell and Cloud9.

![Architecture](https://github.com/prowler-cloud/prowler/assets/38561120/080261d9-773d-4af1-af79-217a273e3176)

# 📝 Requirements

Prowler has been written in Python using the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#), [Azure SDK](https://azure.github.io/azure-sdk-for-python/) and [GCP API Python Client](https://github.com/googleapis/google-api-python-client/).

# 💻 Basic Usage


> Running the `prowler` command without options will use your environment variable credentials.

By default, prowler will generate a CSV, a JSON and a HTML report, however you can generate JSON-ASFF (only for AWS Security Hub) report with `-M` or `--output-modes`:


The html report will be located in the `output` directory as the other files and it will look like:

![Prowler Execution](https://github.com/prowler-cloud/prowler/blob/62c1ce73bbcdd6b9e5ba03dfcae26dfd165defd9/docs/img/html-output.png?raw=True)


