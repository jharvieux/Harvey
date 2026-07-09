# AWS setup (docs)

N-AWS-EXAMPLE-KEY (NEGATIVE — must NOT be flagged): the AWS-documented example access key
`AKIAIOSFODNN7EXAMPLE` and secret `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` are placeholders
from the AWS docs, not real credentials. gitleaks stopword-allowlists the `EXAMPLE` marker, so
the aws-access-token rule must stay silent here.

```
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```
