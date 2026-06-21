import boto3
from botocore.exceptions import ClientError

def check_public_buckets():
    """
    Detecta buckets S3 con acceso público habilitado.
    Referencia: CIS AWS Foundations Benchmark 2.1.5
    """
    s3 = boto3.client('s3')
    findings = []

    response = s3.list_buckets()
    buckets = response['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            is_public = policy_status['PolicyStatus']['IsPublic']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                is_public = False
            else:
                continue

        if is_public:
            findings.append({
                'resource': bucket_name,
                'issue': 'Bucket S3 con acceso público habilitado',
                'severity': 'ALTA'
            })

    return findings
