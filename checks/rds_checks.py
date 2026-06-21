import boto3


def check_public_rds():
    """
    Detecta instancias RDS con acceso público habilitado.
    Referencia: buena práctica estándar de seguridad en bases de datos (no tiene número CIS específico)
    """
    rds = boto3.client('rds')
    findings = []

    response = rds.describe_db_instances()
    instances = response['DBInstances']

    for instance in instances:
        db_id = instance['DBInstanceIdentifier']

        if instance.get('PubliclyAccessible'):
            findings.append({
                'resource': db_id,
                'issue': 'Instancia RDS con acceso público habilitado (PubliclyAccessible=True)',
                'severity': 'ALTA'
            })

    return findings
