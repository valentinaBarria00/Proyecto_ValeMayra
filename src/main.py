"""Punto de entrada. Modos:
    python -m src.main                                  -> demostracion (datos de ejemplo)
    python -m src.main --new A.json                     -> analiza una corrida guardada
    python -m src.main --base A.json --new B.json       -> analiza B y la compara con A
    python -m src.main --inventario                     -> lista el inventario (IP ocultas)
    python -m src.main --probar-seguridad               -> demo de accesos, bloqueo y sesiones
    (agrega --config config.secure.yaml para usar el inventario con IP cifradas)
En el PASO 2 se suma el modo 'live' (collectors reales) usando secure_session()."""
import argparse
from datetime import datetime
from pathlib import Path

from src.access_control import (AccessBlocked, AccessMonitor, SessionRegistry,
                                secure_session, security_section_md)
from src.analysis import RuleContext, compare_runs, evaluate
from src.demo_data import build_demo_runs
from src.errors import AuditError, AuthenticationError, ConnectionTimeoutError
from src.inventory import load_inventory
from src.models import Run
from src.reporting import build_alert, send_email, write_reports
from src.security import load_dotenv_simple, redact


def analizar(inv, nueva: Run, base: Run | None, etiqueta: str):
    """Nucleo comun: reglas + comparador + reportes + alerta para UNA corrida."""
    out_dir = inv.audit.get("output_dir", "output")
    findings = evaluate(RuleContext(nueva, base, inv))
    changes = compare_runs(base, nueva) if base else []
    paths = write_reports(nueva, findings, changes, base, f"{out_dir}/{nueva.run_id}")

    print(f"\n=== {etiqueta}: {nueva.run_id} | base: {base.run_id if base else 'ninguna'} ===")
    for f in findings:
        print(f"  [{f.severity.upper():10}] {f.rule_id} | {f.device:8} | {f.title}")
    for c in changes:
        print(f"  (cambio) {c.device:4} | {c.category:11} | {c.kind:10} | {c.detail}")
    print(f"  -> {len(findings)} hallazgos, {len(changes)} cambios. Informe: {paths['markdown']}")

    subject, body, n = build_alert(nueva, findings, changes, min_severity="alta")
    print(f"  ALERTA: {subject}")
    if n:
        send_email(subject, body)          # solo envia si hay SMTP configurado en .env


# ---------------------------- DEMO DE SEGURIDAD DE ACCESOS ----------------------------
# Que pasa en cada equipo (cada sublista = una ejecucion de la auditoria):
ESCENARIO = {
    "SW1": [["ok"]],                         # conecta a la primera
    "SW2": [["auth_fail"]] * 4,              # clave mala en 4 ejecuciones seguidas -> BLOQUEO
    "R1":  [["timeout", "ok"]],              # un timeout y el reintento funciona
    "R2":  [["timeout", "timeout"]],         # nunca responde
}


class _SesionFalsa:
    """Sesion simulada (en el paso 2 sera la sesion SSH/NETCONF real)."""
    def __init__(self, name): self.name = name
    def close(self): pass


def _opener_simulado(dev, resultados):
    pasos = iter(resultados)
    def opener():
        r = next(pasos, "ok")
        if r == "timeout":
            raise ConnectionTimeoutError(f"Timeout conectando a {dev['host']}")
        if r == "auth_fail":
            raise AuthenticationError("Credenciales rechazadas por el equipo")
        return _SesionFalsa(dev["hostname"])
    return opener


def probar_seguridad(inv):
    sec = inv.security
    monitor = AccessMonitor(str(Path(sec.get("logs_dir", "logs")) / "demo"),
                            max_failures=sec.get("max_auth_failures", 3),
                            lockout_minutes=sec.get("lockout_minutes", 15),
                            run_id=datetime.now().strftime("%Y%m%d_%H%M%S"))
    monitor.reset()                                   # la demo siempre parte limpia
    registry = SessionRegistry()
    retries = inv.audit.get("retries", 1)

    print(f"Politica: bloqueo tras {monitor.max_failures} fallos de clave seguidos, "
          f"{int(monitor.lockout.total_seconds() // 60)} min. Reintentos de timeout: {retries}\n")
    for dev in inv.devices:
        for n, resultados in enumerate(ESCENARIO.get(dev["hostname"], [["ok"]]), 1):
            try:
                with secure_session(monitor, registry, dev, _opener_simulado(dev, resultados), retries):
                    pass                              # PASO 2: aqui va la recoleccion real
                estado = "conectado y sesion cerrada"
            except AccessBlocked as exc:
                estado = f"BLOQUEADO -> {redact(str(exc))}"
            except AuditError as exc:
                estado = f"FALLO -> {redact(str(exc))}"
            print(f"  {dev['hostname']:4} ejecucion {n}: {estado}")

    summary = monitor.summary()
    print("\nIntentos de acceso por equipo (esta ejecucion):")
    print(f"  {'Equipo':6} {'IP oculta':16} {'Intentos':>8} {'Ok':>3} {'Clave':>5} {'Timeout':>7} {'Bloq.':>5}  Estado")
    for host, r in sorted(summary.items()):
        print(f"  {host:6} {r['ip']:16} {r['intentos']:>8} {r['exitosos']:>3} {r['fallos_clave']:>5} "
              f"{r['timeouts']:>7} {r['bloqueados']:>5}  {r['estado']}")
    print(f"\nSesiones abiertas al finalizar: {len(registry.open_sessions())}")

    out = Path(inv.audit.get("output_dir", "output")) / "seguridad_accesos.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(security_section_md(summary, registry.open_sessions()), encoding="utf-8")
    print(f"Registro detallado: {monitor.log_path}   |   Resumen: {out}")


def main():
    parser = argparse.ArgumentParser(description="Auditoria de redes Wolf-Industries")
    parser.add_argument("--base", help="JSON de la corrida anterior (linea base)")
    parser.add_argument("--new", help="JSON de la corrida a analizar")
    parser.add_argument("--config", default="config.yaml", help="inventario (config.yaml o config.secure.yaml)")
    parser.add_argument("--inventario", action="store_true", help="solo muestra el inventario")
    parser.add_argument("--probar-seguridad", action="store_true",
                        help="demo de control de accesos, bloqueo y cierre de sesiones")
    args = parser.parse_args()

    load_dotenv_simple(".env")                        # WOLF_KEY y credenciales desde .env
    try:
        inv = load_inventory(args.config)             # descifra las IP si estan cifradas
    except (AuditError, FileNotFoundError, ValueError) as exc:
        raise SystemExit(f"ERROR: {exc}")             # mensaje claro, sin traceback
    print(f"Inventario cargado: {len(inv.devices)} dispositivos autorizados")

    if args.inventario:                               # IP SIEMPRE ocultas al mostrar
        for d in inv.devices:
            print(f"  - {d['hostname']:4} | {d['platform']:14} | via {d['transport']:8} | {d['host_safe']}")
        return

    if args.probar_seguridad:
        probar_seguridad(inv)
        return

    if args.new:                                      # MODO ARCHIVOS (escenarios editables)
        base = Run.load(args.base) if args.base else None
        analizar(inv, Run.load(args.new), base, "ESCENARIO")
        return

    base, cambio = build_demo_runs()                  # MODO DEMOSTRACION
    runs_dir = inv.audit.get("runs_dir", "runs")
    analizar(inv, base, None, "BASE")
    base.save(runs_dir)
    analizar(inv, cambio, base, "NUEVA")
    cambio.save(runs_dir)


if __name__ == "__main__":
    main()
