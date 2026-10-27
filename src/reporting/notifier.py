"""ALERTA (funcionalidad deseable de Wolf: "auditorias programadas y alertas").
Arma un mensaje resumen con lo mas grave y, si hay correo configurado, lo envia.

IMPORTANTE: esto NO es monitoreo en tiempo real. La alerta se emite cuando se EJECUTA
la auditoria. Para que corra sola cada cierto tiempo se usa el Programador de tareas
de Windows (o cron en Linux) llamando a: python -m src.main

Variables de entorno para el envio (en .env, nunca en el codigo):
    ALERT_SMTP_HOST, ALERT_SMTP_PORT (587), ALERT_SMTP_USER, ALERT_SMTP_PASS, ALERT_TO"""
import os
import smtplib
from email.message import EmailMessage

from src.analysis.rules_engine import SEVERITY_ORDER
from src.reporting.report_generator import coverage_metrics
from src.security import redact


def build_alert(run, findings, changes, min_severity="alta"):
    """Devuelve (asunto, cuerpo, cantidad_de_hallazgos_relevantes)."""
    limit = SEVERITY_ORDER[min_severity]
    important = [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= limit]
    cov = coverage_metrics(run)

    subject = (f"[Auditoría de red] {len(important)} hallazgo(s) {min_severity.upper()} o superior "
               f"- corrida {run.run_id}") if important else f"[Auditoría de red] Sin hallazgos graves - corrida {run.run_id}"
    lines = [f"Corrida {run.run_id} ({run.started_at})",
             f"Cobertura: {cov['ok']}/{cov['total']} equipos auditados, {cov['failed']} con error.",
             f"Cambios detectados contra la línea base: {len(changes)}.", ""]
    if important:
        lines.append("HALLAZGOS QUE REQUIEREN ATENCIÓN:")
        for f in important:
            lines.append(f"- [{f.severity.upper()}] {f.device}: {f.title}")
            lines.append(f"    Evidencia: {f.evidence}")
            lines.append(f"    Recomendación: {f.recommendation}")
    else:
        lines.append("No hay hallazgos de severidad alta o superior.")
    lines += ["", "Detalle completo en output/<corrida>/report.md"]
    return subject, redact("\n".join(lines)), len(important)


def send_email(subject: str, body: str) -> bool:
    """Envia el correo si ALERT_* esta configurado. Si no, queda en modo simulacion."""
    host, to = os.environ.get("ALERT_SMTP_HOST"), os.environ.get("ALERT_TO")
    user, password = os.environ.get("ALERT_SMTP_USER"), os.environ.get("ALERT_SMTP_PASS")
    if not (host and to and user and password):
        print("[ALERTA - SIMULACION] Correo no configurado (ALERT_SMTP_* en .env); no se envio.")
        return False
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, user, to
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("ALERT_SMTP_PORT", "587")), timeout=15) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(msg)
    return True
