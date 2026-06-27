"""
Entry point para AWS Lambda.
Corre los checks, sube los reportes a S3 y envía alerta si hay hallazgos ALTA.
"""
from main import run_all_checks
from report import export_json, export_html, send_alert, upload_to_s3


def lambda_handler(event, context):
    print("Ejecutando checks de seguridad...\n")
    findings = run_all_checks()

    json_path = '/tmp/scan_results.json'
    html_path = '/tmp/scan_report.html'

    export_json(findings, json_path)
    export_html(findings, html_path, profile='aws-scanner-lambda-role')


    upload_to_s3(json_path, 'scan_results.json')
    upload_to_s3(html_path, 'scan_report.html')

    send_alert(findings)

    return {
        'statusCode': 200,
        'total_findings': len(findings),
    }
