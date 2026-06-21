import boto3


def check_root_account():
    """
    Detecta si la cuenta root tiene MFA deshabilitado o access keys activas.
    Referencia: CIS AWS Foundations Benchmark 1.5 (MFA en root) y 1.6 (sin access keys en root)
    """
    iam = boto3.client('iam')
    findings = []

    response = iam.get_account_summary()
    summary = response['SummaryMap']

    if summary.get('AccountMFAEnabled') == 0:
        findings.append({
            'resource': 'Root account',
            'issue': 'La cuenta root no tiene MFA habilitado',
            'severity': 'ALTA'
        })

    if summary.get('AccountAccessKeysPresent', 0) > 0:
        findings.append({
            'resource': 'Root account',
            'issue': 'La cuenta root tiene access keys activas (nunca deberían existir)',
            'severity': 'ALTA'
        })

    return findings
