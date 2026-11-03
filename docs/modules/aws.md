# AWS

EC2 instances, S3 buckets and CloudWatch alarms for one AWS account and
region. Add one instance of the module per account or region.

**Setup.** Create an IAM user (or a role, with temporary credentials) for
Conduit with only the permissions below, create an access key for it, and
store the secret access key in the vault. Enter the region, the access key
id and the `secret://` reference. For temporary credentials, also store and
reference the session token.

| Action | Risk | Notes |
| --- | --- | --- |
| `ec2_instances` | read | Id, `Name` tag, state, type, public and private IP, zone, launch time |
| `ec2_start` | write | Preview asks AWS to check the request without acting (`DryRun`); undo stops the instance |
| `ec2_stop` | destructive | Instance-store data is lost and a non-Elastic public IP changes. Preview as above; undo starts it again |
| `ec2_reboot` | destructive | Preview as above |
| `s3_buckets` | read | |
| `s3_list` | read | One level of a bucket at a time; `prefix` opens a "folder" |
| `cloudwatch_alarms` | read | Alarms currently in the `ALARM` state |

Health calls STS `GetCallerIdentity` and shows which identity and region the
module uses.

**Least-privilege policy.** Grant only what you use. Drop the `ec2:Start…`,
`Stop…` and `Reboot…` lines for a read-only connection, and narrow
`Resource` to specific instances or buckets where you can:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["ec2:DescribeInstances", "cloudwatch:DescribeAlarms", "s3:ListAllMyBuckets"], "Resource": "*" },
    { "Effect": "Allow", "Action": ["ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances"], "Resource": "arn:aws:ec2:*:*:instance/*" },
    { "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "arn:aws:s3:::*" }
  ]
}
```

`sts:GetCallerIdentity` needs no permission.

**How it signs.** Requests are signed with AWS Signature Version 4 by
Conduit itself (no AWS SDK); the signer is checked against AWS's published
test vectors. The secret key is read from the vault for each call and never
leaves the machine. S3 uses path-style addressing, which works for every
bucket name.

**Security.** Treat the access key like a password: it works from anywhere.
Prefer a dedicated IAM user with the policy above over your own keys, and
rotate it in the IAM console from time to time.
