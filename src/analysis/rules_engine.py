"""MOTOR DE REGLAS (Wolf: "Compara linea base y detecta condiciones -> hallazgos explicables").

Cada regla es una funcion pequena e independiente:
    regla(ctx) -> lista de Finding
Si una regla falla por un dato raro, NO tumba a las demas (ver evaluate()).
Para agregar una regla nueva: escribir la funcion y sumarla a la lista RULES.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from src.inventory import Inventory
from src.models import DeviceState, Finding, Run
from src.analysis.rules_vlan import rule_expected_vlans

# Orden para presentar los hallazgos (lo mas grave primero)
SEVERITY_ORDER = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "limitacion": 4}


@dataclass
class RuleContext:
    """Todo lo que una regla necesita saber."""
    run: Run                       # ejecucion actual
    baseline: Optional[Run]        # ejecucion anterior (puede no existir)
    inventory: Inventory           # umbrales (policy) y expectativas por equipo

    def ok_devices(self) -> List[DeviceState]:
        """Solo los equipos que SI se pudieron auditar."""
        return [d for d in self.run.devices if d.status == "ok"]

    def baseline_device(self, hostname: str) -> Optional[DeviceState]:
        if self.baseline is None:
            return None
        return next((d for d in self.baseline.devices if d.hostname == hostname), None)

    def expect(self, hostname: str) -> dict:
        """Expectativas del inventario (expected_up, expected_neighbors, role...)."""
        return self.inventory.get(hostname)


def _hours_between(t1: str, t2: str) -> float:
    return (datetime.fromisoformat(t2) - datetime.fromisoformat(t1)).total_seconds() / 3600


# ------------------------------------------------------------------------------
# R01 - Tasa de errores en interfaces (requiere 2 mediciones = ventana de tiempo)
# ------------------------------------------------------------------------------
def rule_error_rate(ctx: RuleContext) -> List[Finding]:
    limit = ctx.inventory.policy.get("errors_per_hour", 50)

    # Sin linea base NO se puede calcular una tasa: se declara como LIMITACION.
    if ctx.baseline is None:
        return [Finding(
            "R01", "limitacion", "(todos)", "Tasa de errores no evaluable",
            "No existe una ejecucion anterior para comparar los contadores.",
            "Los contadores de error son acumulados: se necesitan 2 mediciones y una ventana de tiempo.",
            "Ejecutar nuevamente la auditoria usando una ejecucion previa como linea base.",
            "Ninguno (solo lectura).", "Repetir la auditoria con --baseline y revisar R01.")]

    findings = []
    for dev in ctx.ok_devices():
        base = ctx.baseline_device(dev.hostname)
        if base is None or base.status != "ok":
            continue
        hours = _hours_between(base.collected_at, dev.collected_at)
        if hours <= 0:
            continue
        before = {i.name: i for i in base.interfaces}
        for itf in dev.interfaces:
            old = before.get(itf.name)
            if old is None:
                continue
            for attr, label in (("in_errors", "entrada"), ("out_errors", "salida")):
                now_v, old_v = getattr(itf, attr), getattr(old, attr)
                # Si falta el dato o el contador bajo (reinicio de contadores), se omite
                if now_v is None or old_v is None or now_v < old_v:
                    continue
                rate = (now_v - old_v) / hours
                if rate > limit:
                    findings.append(Finding(
                        "R01", "alta" if rate > limit * 10 else "media", dev.hostname,
                        f"Errores de {label} crecientes en {itf.name}",
                        f"{itf.name}: {old_v} -> {now_v} errores en {hours:.1f} h = {rate:.0f} errores/hora.",
                        f"Tasa permitida: {limit} errores/hora (policy.errors_per_hour).",
                        "Revisar cable/SFP/puerto remoto y la coincidencia de duplex/velocidad.",
                        "Bajo: cambiar un cable o SFP puede cortar el enlace unos segundos.",
                        "Tras la correccion, la tasa debe bajar de " + str(limit) + " errores/hora en la siguiente auditoria."))
    return findings


# ------------------------------------------------------------------------------
# R02 - Interfaz que se esperaba UP pero esta DOWN
# (Wolf: "una interfaz down no es hallazgo por si sola; se compara con el inventario")
# ------------------------------------------------------------------------------
def rule_expected_up(ctx: RuleContext) -> List[Finding]:
    findings = []
    for dev in ctx.ok_devices():
        by_name = {i.name: i for i in dev.interfaces}
        for name in ctx.expect(dev.hostname).get("expected_up", []):
            itf = by_name.get(name)
            if itf is None:
                findings.append(Finding(
                    "R02", "media", dev.hostname, f"Interfaz esperada no reportada: {name}",
                    f"{name} figura en expected_up pero el equipo no la informo.",
                    "Toda interfaz de expected_up debe existir en el equipo.",
                    "Verificar el nombre en el inventario o la salida del equipo.",
                    "Ninguno.", "Corregir el inventario y repetir la auditoria."))
            elif itf.oper_status != "up":
                findings.append(Finding(
                    "R02", "alta", dev.hostname, f"Interfaz esperada UP esta caida: {name}",
                    f"{name}: admin={itf.admin_status}, oper={itf.oper_status}.",
                    "Las interfaces de expected_up deben estar en estado operativo 'up'.",
                    "Revisar enlace fisico y estado del equipo remoto; si esta en admin down, "
                    "evaluar habilitarla (propuesta, NO se aplica automaticamente).",
                    "Medio: habilitar un puerto puede crear bucles si la topologia cambio.",
                    f"El estado oper de {name} debe pasar a 'up' en la siguiente auditoria."))
    return findings


# ------------------------------------------------------------------------------
# R03 - Utilizacion alta de enlace
# ------------------------------------------------------------------------------
def rule_utilization(ctx: RuleContext) -> List[Finding]:
    warn = ctx.inventory.policy.get("util_warn_pct", 70)
    crit = ctx.inventory.policy.get("util_crit_pct", 90)
    findings = []
    for dev in ctx.ok_devices():
        for itf in dev.interfaces:
            util = itf.utilization_pct          # None si faltan datos (no se asume nada)
            if util is None or util < warn:
                continue
            findings.append(Finding(
                "R03", "alta" if util >= crit else "media", dev.hostname,
                f"Utilizacion alta en {itf.name} ({util}%)",
                f"{itf.name}: in={itf.in_bps} bps, out={itf.out_bps} bps sobre {itf.speed_mbps} Mbps.",
                f"Umbral medio {warn}% / alto {crit}% (policy).",
                "Evaluar agregar enlaces (LACP), subir velocidad o aplicar QoS.",
                "Medio: modificar enlaces troncales puede interrumpir trafico.",
                "La utilizacion debe quedar bajo el umbral medio en el mismo horario de medicion."))
    return findings


# ------------------------------------------------------------------------------
# R04 - Equipo de capa 3 sin ruta por defecto
# ------------------------------------------------------------------------------
def rule_default_route(ctx: RuleContext) -> List[Finding]:
    findings = []
    for dev in ctx.ok_devices():
        if ctx.expect(dev.hostname).get("role") not in ("core", "router"):
            continue
        if not dev.routes:                      # sin datos de rutas = limitacion, no cumplimiento
            findings.append(Finding(
                "R04", "limitacion", dev.hostname, "Rutas no disponibles",
                "No se obtuvo la tabla de rutas.", "Un equipo core/router debe tener ruta por defecto.",
                "Revisar privilegios o el parser de rutas.", "Ninguno.", "Repetir la auditoria."))
        elif not any(r.prefix == "0.0.0.0/0" for r in dev.routes):
            findings.append(Finding(
                "R04", "alta", dev.hostname, "Sin ruta por defecto",
                f"Se encontraron {len(dev.routes)} rutas y ninguna es 0.0.0.0/0.",
                "Equipos con rol core/router deben tener ruta por defecto.",
                "Verificar si fue eliminada intencionalmente; de no ser asi, restaurarla.",
                "Alto: un cambio de rutas puede cortar la conectividad hacia el exterior.",
                "Debe existir 0.0.0.0/0 en la tabla de rutas de " + dev.hostname + "."))
    return findings


# ------------------------------------------------------------------------------
# R05 - Vecino esperado ausente (LLDP/CDP)
# ------------------------------------------------------------------------------
def rule_expected_neighbors(ctx: RuleContext) -> List[Finding]:
    findings = []
    for dev in ctx.ok_devices():
        seen = {n.remote_device.lower() for n in dev.neighbors}
        for expected in ctx.expect(dev.hostname).get("expected_neighbors", []):
            if expected.lower() not in seen:
                findings.append(Finding(
                    "R05", "alta", dev.hostname, f"Vecino esperado ausente: {expected}",
                    f"Vecinos vistos: {sorted(seen) or 'ninguno'}.",
                    "Los vecinos de expected_neighbors deben aparecer en LLDP/CDP.",
                    "Revisar enlace, LLDP habilitado y estado del equipo vecino.",
                    "Bajo: solo diagnostico.",
                    f"{expected} debe aparecer en la tabla de vecinos de {dev.hostname}."))
    return findings


# ------------------------------------------------------------------------------
# R06 - Misma VLAN con nombres distintos entre equipos
# ------------------------------------------------------------------------------
def rule_vlan_consistency(ctx: RuleContext) -> List[Finding]:
    names = {}                                  # id -> {hostname: nombre}
    for dev in ctx.ok_devices():
        for v in dev.vlans:
            if v.name:                          # algunas plataformas no informan nombre
                names.setdefault(v.id, {})[dev.hostname] = v.name
    findings = []
    for vid, per_dev in sorted(names.items()):
        if len({n.lower() for n in per_dev.values()}) > 1:
            findings.append(Finding(
                "R06", "media", "(varios)", f"VLAN {vid} con nombres inconsistentes",
                f"VLAN {vid}: " + ", ".join(f"{h}='{n}'" for h, n in per_dev.items()),
                "Una misma VLAN debe llamarse igual en todos los equipos.",
                "Unificar el nombre segun el estandar de la organizacion.",
                "Bajo: renombrar una VLAN no afecta el trafico.",
                f"La VLAN {vid} debe tener el mismo nombre en todos los equipos."))
    return findings


# ------------------------------------------------------------------------------
# R07 - Version de software fuera de la lista aprobada
# ------------------------------------------------------------------------------
def rule_version(ctx: RuleContext) -> List[Finding]:
    approved = ctx.inventory.policy.get("approved_versions", {})
    findings = []
    for dev in ctx.ok_devices():
        allowed = approved.get(dev.platform)
        if not allowed or not dev.version:
            continue
        if not any(a in dev.version for a in allowed):
            findings.append(Finding(
                "R07", "media", dev.hostname, "Version de software no aprobada",
                f"Version instalada: {dev.version}.",
                f"Versiones aprobadas para {dev.platform}: {allowed}.",
                "Planificar actualizacion en ventana de mantenimiento.",
                "Alto: actualizar requiere reinicio y respaldo previo (plan con rollback).",
                f"'show version' debe mostrar una version aprobada: {allowed}."))
    return findings


# ------------------------------------------------------------------------------
# R08 - Reinicio reciente (uptime bajo)
# ------------------------------------------------------------------------------
def rule_uptime(ctx: RuleContext) -> List[Finding]:
    min_h = ctx.inventory.policy.get("min_uptime_hours", 24)
    findings = []
    for dev in ctx.ok_devices():
        if dev.uptime_seconds is None:
            continue
        hours = dev.uptime_seconds / 3600
        if hours < min_h:
            findings.append(Finding(
                "R08", "baja", dev.hostname, "Reinicio reciente del equipo",
                f"Uptime: {hours:.1f} horas.", f"Se espera al menos {min_h} horas (policy.min_uptime_hours).",
                "Revisar logs del reinicio (energia, falla o cambio planificado).",
                "Ninguno.", "El uptime debe seguir creciendo en auditorias posteriores."))
    return findings


# ------------------------------------------------------------------------------
# R09 - Dispositivo que no se pudo auditar (COBERTURA)
# ------------------------------------------------------------------------------
def rule_coverage(ctx: RuleContext) -> List[Finding]:
    return [Finding(
        "R09", "alta", dev.hostname, "Dispositivo no auditable",
        f"Estado: error. Motivo: {dev.error}. Intentos: {dev.attempts}.",
        "Todo equipo del inventario autorizado debe poder auditarse.",
        "Revisar conectividad, servicio SSH/NETCONF y credenciales de solo lectura.",
        "Ninguno.", "La auditoria debe terminar con status 'ok' para este equipo.")
        for dev in ctx.run.devices if dev.status == "error"]


# Lista de reglas activas. Para sumar una regla nueva, agregala aqui.
RULES = [rule_error_rate, rule_expected_up, rule_utilization, rule_default_route,
         rule_expected_neighbors, rule_vlan_consistency, rule_expected_vlans, rule_version,
         rule_uptime, rule_coverage]


def evaluate(ctx: RuleContext) -> List[Finding]:
    """Ejecuta TODAS las reglas y devuelve los hallazgos ordenados por severidad."""
    findings: List[Finding] = []
    for rule in RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:                # una regla defectuosa no detiene el analisis
            findings.append(Finding(
                rule.__name__, "limitacion", "(motor)", "Regla no pudo ejecutarse",
                f"{type(exc).__name__}: {exc}", "El motor debe poder evaluar todas las reglas.",
                "Revisar los datos de entrada de la regla.", "Ninguno.", "Repetir la auditoria."))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.device, f.rule_id))
