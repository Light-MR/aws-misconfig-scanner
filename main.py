#!/usr/bin/env python3
"""
AWS Misconfiguration Scanner
Detecta configuraciones de seguridad riesgosas en una cuenta AWS,
mapeadas a CIS AWS Foundations Benchmark.
"""

from checks.s3_checks import check_public_buckets
from checks.s3_encryption_checks import check_bucket_encryption
from checks.iam_checks import check_iam_users
from checks.ec2_checks import check_open_security_groups
from checks.cloudtrail_checks import check_cloudtrail_enabled
from checks.rds_checks import check_public_rds
from checks.root_account_checks import check_root_account
from report import print_report, export_json, export_html


def run_all_checks():
    """Corre todos los checks y regresa una lista unificada con todos los findings."""
    all_findings = []

    checks = [
        ('S3', check_public_buckets),
        ('S3', check_bucket_encryption),
        ('IAM', check_iam_users),
        ('EC2', check_open_security_groups),
        ('CloudTrail', check_cloudtrail_enabled),
        ('RDS', check_public_rds),
        ('IAM', check_root_account),
    ]

    for service_name, check_fn in checks:
        try:
            results = check_fn()
            for finding in results:
                finding['service'] = service_name
            all_findings.extend(results)
        except Exception as e:
            print(f"[ERROR] Falló el check {check_fn.__name__}: {e}")

    return all_findings


if __name__ == '__main__':
    print("Ejecutando checks de seguridad...\n")
    findings = run_all_checks()
    print_report(findings)
    export_json(findings)
    export_html(findings)
