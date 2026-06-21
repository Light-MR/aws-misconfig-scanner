"""
Generacion de reportes: consola, JSON y HTML.
"""

import json
from datetime import datetime, timezone

RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'
BOLD = '\033[1m'

SEVERITY_COLOR = {
    'ALTA': RED,
    'MEDIA': YELLOW,
}


def print_report(findings):
    """Imprime el reporte en consola con colores por severidad."""

    print("  AWS MISCONFIGURATION SCANNER - REPORTE")
    print(f"  Fecha: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    if not findings:
        print(f"{GREEN}No se encontraron misconfigurations.{RESET}\n")
        return

    severity_order = {'ALTA': 0, 'MEDIA': 1, 'BAJA': 2}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f['severity'], 99))

    high = sum(1 for f in findings if f['severity'] == 'ALTA')
    medium = sum(1 for f in findings if f['severity'] == 'MEDIA')

    print(f"{BOLD}Resumen:{RESET} {RED}{high} ALTA{RESET} | {YELLOW}{medium} MEDIA{RESET} | Total: {len(findings)}\n")

    for f in findings_sorted:
        color = SEVERITY_COLOR.get(f['severity'], RESET)
        print(f"{color}[{f['severity']}]{RESET} {BOLD}{f['service']}{RESET} - {f['resource']}")
        print(f"        {f['issue']}\n")


def export_json(findings, filename='scan_results.json'):
    """Exporta los findings a un archivo JSON."""
    output = {
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'total_findings': len(findings),
        'findings': findings,
    }
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"Resultados exportados a {filename}")


def export_html(findings, filename='scan_report.html', region='us-east-1', profile='read-scanner'):
    """Genera un reporte HTML standalone con los findings."""
    severity_order = {'ALTA': 0, 'MEDIA': 1, 'BAJA': 2}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f['severity'], 99))

    high = sum(1 for f in findings if f['severity'] == 'ALTA')
    medium = sum(1 for f in findings if f['severity'] == 'MEDIA')

    rows = ""
    for f in findings_sorted:
        badge_class = 'badge-alta' if f['severity'] == 'ALTA' else 'badge-media'
        rows += f"""
            <tr>
                <td><span class="badge {badge_class}">{f['severity']}</span></td>
                <td class="service">{f['service']}</td>
                <td class="resource">{f['resource']}</td>
                <td>{f['issue']}</td>
            </tr>"""

    if not findings:
        rows = '<tr><td colspan="4" class="empty">No se encontraron misconfigurations.</td></tr>'

    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>scan_report - aws-misconfig-scanner</title>
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

    :root {{
        --bg: #0b0d10;
        --panel: #12161b;
        --border: #232a32;
        --text: #c7ccd1;
        --text-dim: #6b7280;
        --accent: #4fd1a5;
        --alta: #e0594f;
        --media: #d9a440;
    }}

    * {{ box-sizing: border-box; }}

    body {{
        font-family: 'IBM Plex Sans', sans-serif;
        background: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 48px 40px;
        font-size: 14px;
    }}

    .container {{ max-width: 880px; margin: 0 auto; }}

    .header {{
        border-bottom: 1px solid var(--border);
        padding-bottom: 20px;
        margin-bottom: 28px;
    }}

    .label {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        letter-spacing: 0.12em;
        color: var(--text-dim);
        text-transform: uppercase;
    }}

    h1 {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 22px;
        font-weight: 500;
        color: var(--text);
        margin: 6px 0 4px;
        letter-spacing: -0.01em;
    }}

    h1 .prompt {{ color: var(--accent); margin-right: 10px; }}

    .meta {{
        font-family: 'JetBrains Mono', monospace;
        color: var(--text-dim);
        font-size: 12px;
        margin-top: 8px;
    }}

    .summary {{
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1px;
        background: var(--border);
        border: 1px solid var(--border);
        margin-bottom: 32px;
    }}

    .stat {{ background: var(--panel); padding: 18px 20px; }}

    .stat-num {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 26px;
        font-weight: 500;
    }}

    .stat-label {{
        font-size: 11px;
        color: var(--text-dim);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-top: 4px;
    }}

    .stat-alta .stat-num {{ color: var(--alta); }}
    .stat-media .stat-num {{ color: var(--media); }}

    .findings-label {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: var(--text-dim);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 8px;
    }}

    table {{ width: 100%; border-collapse: collapse; border: 1px solid var(--border); }}

    th, td {{
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid var(--border);
        font-size: 13px;
    }}

    th {{
        font-family: 'JetBrains Mono', monospace;
        background: var(--panel);
        color: var(--text-dim);
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 500;
    }}

    tr:last-child td {{ border-bottom: none; }}

    td.resource, td.service {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
    }}

    .badge {{
        font-family: 'JetBrains Mono', monospace;
        display: inline-block;
        padding: 2px 8px;
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.05em;
        border-left: 2px solid;
    }}

    .badge-alta {{ color: var(--alta); border-color: var(--alta); }}
    .badge-media {{ color: var(--media); border-color: var(--media); }}

    .empty {{
        text-align: center;
        color: var(--accent);
        font-family: 'JetBrains Mono', monospace;
        padding: 32px;
        font-size: 13px;
    }}

    footer {{
        margin-top: 28px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        color: var(--text-dim);
        border-top: 1px solid var(--border);
        padding-top: 14px;
    }}

    footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="label">security audit report</div>
        <h1><span class="prompt">$</span>aws-misconfig-scanner</h1>
        <div class="meta">run: {timestamp} - region: {region} - profile: {profile}</div>
    </div>

    <div class="summary">
        <div class="stat stat-alta">
            <div class="stat-num">{high}</div>
            <div class="stat-label">Severidad alta</div>
        </div>
        <div class="stat stat-media">
            <div class="stat-num">{medium}</div>
            <div class="stat-label">Severidad media</div>
        </div>
        <div class="stat">
            <div class="stat-num">{len(findings)}</div>
            <div class="stat-label">Total findings</div>
        </div>
    </div>

    <div class="findings-label">findings</div>
    <table>
        <thead>
            <tr><th>Severidad</th><th>Servicio</th><th>Recurso</th><th>Issue</th></tr>
        </thead>
        <tbody>{rows}
        </tbody>
    </table>

    <footer>ref: CIS AWS Foundations Benchmark</footer>
</div>
</body>
</html>"""

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"Reporte HTML generado: {filename}")
