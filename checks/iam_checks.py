import boto3
import csv
import io
import time
from datetime import datetime, timezone

def check_iam_users():
    """
    Detecta usuarios IAM sin MFA y con access keys viejas (>90 días).
    Referencia: CIS AWS Foundations Benchmark 1.10 (MFA) y 1.14 (rotación de keys)
    """
    iam = boto3.client('iam')
    findings = []

    # Generar el reporte de credenciales 
    status = iam.generate_credential_report()
    while status['State'] != 'COMPLETE':
        time.sleep(2)
        status = iam.generate_credential_report()

    response = iam.get_credential_report()
    report_csv = response['Content'].decode('utf-8')
    reader = csv.DictReader(io.StringIO(report_csv))

    for row in reader:
        username = row['user']

        if username == '<root_account>':
            continue

        # Check 1: ¿tiene MFA activado?
        if row['mfa_active'] == 'false':
            findings.append({
                'resource': username,
                'issue': 'Usuario IAM sin MFA activado',
                'severity': 'ALTA'
            })

        # Check 2: ¿access key 1 tiene más de 90 días?
        if row['access_key_1_active'] == 'true' and row['access_key_1_last_rotated'] != 'N/A':
            last_rotated = datetime.fromisoformat(row['access_key_1_last_rotated'].replace('Z', '+00:00'))
            days_old = (datetime.now(timezone.utc) - last_rotated).days
            if days_old > 90:
                findings.append({
                    'resource': username,
                    'issue': f'Access key con {days_old} días sin rotar',
                    'severity': 'MEDIA'
                })

    return findings
