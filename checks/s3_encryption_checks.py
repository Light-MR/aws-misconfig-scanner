import boto3
from botocore.exceptions import ClientError


def check_bucket_encryption():
    """
    Detecta buckets S3 sin encriptación por default habilitada (SSE-S3 o SSE-KMS).
    Referencia: CIS AWS Foundations Benchmark 2.1.1
    """
    s3 = boto3.client('s3')
    findings = []

    response = s3.list_buckets()
    buckets = response['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    'resource': bucket_name,
                    'issue': 'Bucket S3 sin encriptación por default habilitada',
                    'severity': 'MEDIA'
                })
            else:
                continue

    return findings
