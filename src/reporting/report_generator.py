"""REPORTE (Wolf: "Exporta inventario, evidencia y mejoras -> informe y dataset").
Genera 4 archivos por ejecucion dentro de output/<run_id>/ :
    report.md     informe legible (inventario, hallazgos, cambios, limitaciones)
    findings.csv  hallazgos (abre directo en Excel)
    changes.csv   diferencias contra la linea base
    run.json      dataset completo normalizado (evidencia)
SEGURIDAD: todo el texto pasa por redact() antes de escribirse (ultima barrera)."""
import csv
import json
from dataclasses import asdict
from pathlib import Path

from src.security import redact

SEV_LABEL = {"critica": "Crítica", "alta": "Alta", "media": "Media",
             "baja": "Baja", "limitacion": "Limitación"}


def _fmt_uptime(sec):
    if sec is None:
        return "n/d"
    days, rest = divmod(int(sec), 86400)
    return f"{days}d {rest // 3600}h"


def coverage_metrics(run) -> dict:
    """Metricas de COBERTURA (Wolf): dispositivos exitosos/fallidos y campos completos."""
    ok = [d for d in run.devices if d.status == "ok"]
    total = len(run.devices)
    filled = checks_total = 0
    for d in ok:
        checks = [d.version is not None, d.uptime_seconds is not None,
                  bool(d.interfaces), bool(d.routes), bool(d.neighbors)]
        filled += sum(checks)
        checks_total += len(checks)
    return {"total": total, "ok": len(ok), "failed": total - len(ok),
            "coverage_pct": round(100 * len(ok) / total, 1) if total else 0.0,
            "fields_pct": round(100 * filled / checks_total, 1) if checks_total else 0.0}


def build_markdown(run, findings, changes, baseline=None) -> str:
    cov = coverage_metrics(run)
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    L = []
    L.append(f"# Informe de auditoría de red — corrida {run.run_id}\n")

    # ---- 1. Resumen ----
    L.append("## 1. Resumen de la ejecución\n")
    L.append(f"- **Fecha de recolección:** {run.started_at}")
    L.append(f"- **Línea base:** {baseline.run_id if baseline else 'sin línea base (no se evalúan tasas ni cambios)'}")
    L.append(f"- **Cobertura:** {cov['ok']}/{cov['total']} dispositivos auditados ({cov['coverage_pct']}%), "
             f"{cov['failed']} con error")
    L.append(f"- **Campos completos (dispositivos exitosos):** {cov['fields_pct']}%")
    L.append("- **Hallazgos:** " + (", ".join(f"{SEV_LABEL.get(k, k)}: {v}" for k, v in sorted(by_sev.items()))
                                    or "ninguno"))
    L.append(f"- **Cambios detectados:** {len(changes)}\n")

    # ---- 2. Inventario ----
    L.append("## 2. Inventario auditado\n")
    L.append("| Equipo | Plataforma | Rol | Estado | Versión | Uptime | Interfaces up/total | Intentos |")
    L.append("|---|---|---|---|---|---|---|---|")
    for d in run.devices:
        up = sum(1 for i in d.interfaces if i.oper_status == "up")
        L.append(f"| {d.hostname} | {d.platform} | {d.role} | {d.status} | {d.version or 'n/d'} | "
                 f"{_fmt_uptime(d.uptime_seconds)} | {up}/{len(d.interfaces)} | {d.attempts} |")
    L.append("")

    # ---- 3. Hallazgos ----
    L.append("## 3. Hallazgos\n")
    real = [f for f in findings if f.severity != "limitacion"]
    if not real:
        L.append("No se detectaron hallazgos.\n")
    for f in real:
        L.append(f"### [{SEV_LABEL.get(f.severity, f.severity).upper()}] {f.rule_id} — {f.device}: {f.title}\n")
        L.append(f"- **Evidencia:** {f.evidence}")
        L.append(f"- **Criterio:** {f.criterion}")
        L.append(f"- **Recomendación:** {f.recommendation}")
        L.append(f"- **Riesgo del cambio:** {f.risk}")
        L.append(f"- **Verificación posterior:** {f.verification}\n")

    # ---- 4. Cambios ----
    L.append("## 4. Cambios respecto a la línea base\n")
    if baseline is None:
        L.append("No hay línea base: no es posible detectar cambios.\n")
    elif not changes:
        L.append("Sin diferencias.\n")
    else:
        L.append("| Equipo | Categoría | Tipo | Detalle |")
        L.append("|---|---|---|---|")
        for c in changes:
            L.append(f"| {c.device} | {c.category} | {c.kind} | {c.detail} |")
        L.append("")

    # ---- 5. Limitaciones (Wolf: la ausencia de datos NO es cumplimiento) ----
    L.append("## 5. Limitaciones y supuestos\n")
    lim = [f"{f.device}: {f.title} — {f.evidence}" for f in findings if f.severity == "limitacion"]
    for d in run.devices:
        lim += [f"{d.hostname}: {x}" for x in d.limitations]
    for x in lim or ["Sin limitaciones registradas."]:
        L.append(f"- {x}")
    L.append("- La herramienta opera en modo de solo lectura; las recomendaciones son propuestas y no se aplican.")
    L.append("- La ausencia de un dato se informa como limitación, nunca como cumplimiento.\n")
    return redact("\n".join(L))


def write_reports(run, findings, changes, baseline, out_dir) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {k: out / name for k, name in (("markdown", "report.md"), ("findings", "findings.csv"),
                                           ("changes", "changes.csv"), ("json", "run.json"))}
    paths["markdown"].write_text(build_markdown(run, findings, changes, baseline), encoding="utf-8")

    # CSV con BOM (utf-8-sig) para que Excel muestre bien las tildes
    for key, rows, cols in (
        ("findings", findings, ["rule_id", "severity", "device", "title", "evidence",
                                "criterion", "recommendation", "risk", "verification"]),
        ("changes", changes, ["device", "category", "kind", "detail"]),
    ):
        with open(paths[key], "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols)
            writer.writeheader()
            for r in rows:
                writer.writerow({c: redact(str(asdict(r)[c])) for c in cols})

    # Dataset completo. Se sanitiza el texto serializado como ultima barrera.
    paths["json"].write_text(redact(json.dumps(asdict(run), indent=2, ensure_ascii=False)), encoding="utf-8")
    return {k: str(v) for k, v in paths.items()}
