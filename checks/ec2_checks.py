import boto3
RISKY_PORTS = {
    # Acceso remoto / administración — ALTA
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    111: 'RPCbind',
    135: 'MS RPC',
    139: 'NetBIOS',
    445: 'SMB',
    514: 'rsh/syslog',
    593: 'HTTP RPC Epmap',
    992: 'Telnet (SSL)',
    2049: 'NFS',
    3389: 'RDP',
    5900: 'VNC',
    5901: 'VNC',
    5902: 'VNC',
    5903: 'VNC',
    47001: 'WinRM',

    # Bases de datos — ALTA
    1433: 'MS SQL Server',
    1434: 'MS SQL Browser',
    1521: 'Oracle DB',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    6379: 'Redis',
    6446: 'MySQL Proxy',
    9152: 'MS SQL 2000',
    11211: 'Memcached',
    21201: 'Memcached DB',
    27017: 'MongoDB',
    27018: 'MongoDB Shard',
    27019: 'MongoDB Config',
    28017: 'MongoDB (HTTP)',
    37601: 'eFTP',

    # Directorio / autenticación — ALTA
    389: 'LDAP',
    636: 'LDAPS',
    3268: 'Global Catalog LDAP',
    3269: 'Global Catalog LDAPS',

    # Contenedores / orquestación — ALTA
    2375: 'Docker API (sin TLS)',
    2376: 'Docker API (TLS)',
    6443: 'Kubernetes API',

    # Monitoreo / gestión — MEDIA
    161: 'SNMP',
    162: 'SNMP Trap',
    3260: 'iSCSI',
    8182: 'VMware FDM',

    # Paneles web administrativos — MEDIA
    8000: 'HTTP alterno',
    8008: 'HTTP alterno',
    8080: 'HTTP Proxy / admin',
    8443: 'HTTPS alterno',
    8888: 'Sun Answerbook / admin',
    10000: 'Webmin / panel admin',

    # Correo — MEDIA
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    465: 'SMTPS',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
}
RISKY_PORTS_ALTA = {21, 22, 23, 111, 135, 139, 445, 514, 593, 992, 2049, 3389,
                     5900, 5901, 5902, 5903, 47001,
                     1433, 1434, 1521, 3306, 5432, 6379, 6446, 9152,
                     11211, 21201, 27017, 27018, 27019, 28017, 37601,
                     389, 636, 3268, 3269,
                     2375, 2376, 6443}

def check_open_security_groups():
    """
    Detecta security groups con puertos sensibles abiertos a 0.0.0.0/0 (todo internet).
    Referencia: CIS AWS Foundations Benchmark 5.2 / 5.3
    """
    ec2 = boto3.client('ec2')
    findings = []

    response = ec2.describe_security_groups()
    security_groups = response['SecurityGroups']

    for sg in security_groups:
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', sg_id)

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')

            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')

                if cidr == '0.0.0.0/0' and from_port is not None:
                    if from_port in RISKY_PORTS:
                        severity = 'ALTA' if from_port in RISKY_PORTS_ALTA else 'MEDIA'
                        findings.append({
                            'resource': f'{sg_name} ({sg_id})',
                            'issue': f'Puerto {from_port} ({RISKY_PORTS[from_port]}) abierto a internet (0.0.0.0/0)',
                            'severity': severity
                        })
                    elif from_port == 0 and to_port == 65535:
                        findings.append({
                            'resource': f'{sg_name} ({sg_id})',
                            'issue': 'Todos los puertos abiertos a internet (0.0.0.0/0)',
                            'severity': 'ALTA'
                        })

    return findings
