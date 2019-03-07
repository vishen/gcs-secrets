# GCS Secrets 

`gcs-secrets` provides a simple approach to store encryped secrets
in Google Cloud Storage (GCS) buckets. Secrets are encrypted using
Googke Key Management System (KMS).

## Prerequisites

```
- GCP Project
- KMS Keyring and Key already created
- GCS Bucket created.
```

## Intalling

```
$ go get -u github.com/vishen/gcs-secrets
```

## Create a new encrypted secret

This will use Google KMS to encrypt a secret with the given `keyring` and `key`.
The secret is then stored in GCS.

```
$ gcs-secrets -kms-project-id=<gcp-project-id> -kms-keyring=<kms-keyring> -kms-key=<kms-key> -gcs-bucket=<gcs-bucket> -gcs-prefix=<gcs-prefix> create vault-token=asdasd
Wrote secret in test-bucket at some-prefix/vault-token
```

## Get an encrypted secret

This will retieve the encrypted secret from GCS and then use Google KMS
to decrypt the secret.

```
$ gcs-secrets -kms-project-id=<gcp-project-id> -kms-keyring=<kms-keyring> -kms-key=<kms-key> -gcs-bucket=<gcs-bucket> -gcs-prefix=<gcs-prefix> get vault-token
Decrypted message is: asdasd
``` 

## Listing stored secrets

This will retrieve all of the stored secrets in the bucket.

```
$ gcs-secrets -kms-project-id=<gcp-project-id> -kms-keyring=<kms-keyring> -kms-key=<kms-key> -gcs-bucket=<gcs-bucket> -gcs-prefix=<gcs-prefix> get vault-token
some-prefix/vault-other-token (2019-03-07 23:25:17.867 +0000 UTC)
some-prefix/vault-token (2019-03-07 23:22:17.867 +0000 UTC)
```
