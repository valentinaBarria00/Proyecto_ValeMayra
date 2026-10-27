"""R10 - VLAN esperada ausente. Responde al caso: "una VLAN esta mala o falta".
Se define en config.yaml con expected_vlans: [10, 20, 30] para cada equipo."""
from src.models import Finding


def rule_expected_vlans(ctx):
    findings = []
    for dev in ctx.ok_devices():
        expected = ctx.expect(dev.hostname).get("expected_vlans", [])
        if not expected:
            continue
        # Sin datos de VLAN NO se asume cumplimiento: se declara limitacion.
        if not dev.vlans:
            findings.append(Finding(
                "R10", "limitacion", dev.hostname, "VLAN no verificables",
                "El equipo no entrego informacion de VLAN.",
                f"Se esperaban las VLAN {expected}.",
                "Revisar privilegios o el parser de VLAN.", "Ninguno.", "Repetir la auditoria."))
            continue
        present = {v.id for v in dev.vlans}
        for vid in expected:
            if vid not in present:
                findings.append(Finding(
                    "R10", "alta", dev.hostname, f"VLAN esperada ausente: {vid}",
                    f"VLAN presentes: {sorted(present)}. Falta la VLAN {vid}.",
                    "Toda VLAN de expected_vlans debe existir en el equipo.",
                    f"Verificar si la VLAN {vid} fue eliminada por error y recrearla segun el diseno "
                    "(propuesta, NO se aplica automaticamente).",
                    "Medio: recrear una VLAN no corta trafico, pero asignarla a puertos si.",
                    f"La VLAN {vid} debe aparecer en la tabla de VLAN de {dev.hostname}."))
    return findings
