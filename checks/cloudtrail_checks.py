import boto3


def check_cloudtrail_enabled():
    """
    Detecta si CloudTrail está deshabilitado o no está configurado correctamente
    (logging activo, multi-región, validación de integridad de logs).
    Referencia: CIS AWS Foundations Benchmark 3.1
    """
    cloudtrail = boto3.client('cloudtrail')
    findings = []

    response = cloudtrail.describe_trails()
    trails = response['trailList']

    if not trails:
        findings.append({
            'resource': 'Cuenta AWS',
            'issue': 'No existe ningún CloudTrail configurado en la cuenta',
            'severity': 'ALTA'
        })
        return findings

    for trail in trails:
        trail_name = trail['Name']

        if not trail.get('IsMultiRegionTrail'):
            findings.append({
                'resource': trail_name,
                'issue': 'CloudTrail no está configurado como multi-región',
                'severity': 'MEDIA'
            })

        if not trail.get('LogFileValidationEnabled'):
            findings.append({
                'resource': trail_name,
                'issue': 'CloudTrail no tiene validación de integridad de logs habilitada',
                'severity': 'MEDIA'
            })

    is_any_logging = any(
        cloudtrail.get_trail_status(Name=t['Name']).get('IsLogging')
        for t in trails
    )

    if not is_any_logging:
        findings.append({
            'resource': 'Cuenta AWS',
            'issue': 'Existen trails configurados pero ninguno está activamente loggeando',
            'severity': 'ALTA'
        })

    return findings
