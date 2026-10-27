"""COMPARADOR (Wolf: "Comparar al menos dos ejecuciones" / metrica "Cambios: altas, bajas y diferencias").

Recibe dos ejecuciones (anterior y actual) y devuelve la lista de cambios:
que aparecio (alta), que desaparecio (baja) y que cambio (modificado).
"""
from typing import List

from src.models import Change, DeviceState, Run


def _diff_sets(device, category, old: dict, new: dict, describe) -> List[Change]:
    """Compara dos diccionarios {clave: objeto} y genera altas/bajas."""
    changes = []
    for key in sorted(set(new) - set(old)):
        changes.append(Change(device, category, "alta", describe(new[key], "aparece")))
    for key in sorted(set(old) - set(new)):
        changes.append(Change(device, category, "baja", describe(old[key], "desaparece")))
    return changes


def compare_devices(old: DeviceState, new: DeviceState) -> List[Change]:
    h = new.hostname
    changes: List[Change] = []

    # --- Version de software ---
    if old.version != new.version:
        changes.append(Change(h, "version", "modificado", f"{old.version} -> {new.version}"))

    # --- Reinicio: el uptime actual es MENOR que el anterior ---
    if old.uptime_seconds and new.uptime_seconds and new.uptime_seconds < old.uptime_seconds:
        changes.append(Change(h, "dispositivo", "modificado", "Reinicio detectado (uptime menor al anterior)"))

    # --- Interfaces: altas, bajas y cambios de estado / direccion / contadores ---
    old_if = {i.name: i for i in old.interfaces}
    new_if = {i.name: i for i in new.interfaces}
    changes += _diff_sets(h, "interfaz", old_if, new_if, lambda i, v: f"Interfaz {i.name} {v}")
    for name in sorted(set(old_if) & set(new_if)):
        a, b = old_if[name], new_if[name]
        if a.oper_status != b.oper_status:
            changes.append(Change(h, "interfaz", "modificado", f"{name}: oper {a.oper_status} -> {b.oper_status}"))
        if a.admin_status != b.admin_status:
            changes.append(Change(h, "interfaz", "modificado", f"{name}: admin {a.admin_status} -> {b.admin_status}"))
        if a.ipv4 != b.ipv4:
            changes.append(Change(h, "interfaz", "modificado", f"{name}: IP {a.ipv4} -> {b.ipv4}"))
        for attr in ("in_errors", "out_errors"):
            x, y = getattr(a, attr), getattr(b, attr)
            if x is not None and y is not None and y > x:
                changes.append(Change(h, "contador", "modificado", f"{name}: {attr} {x} -> {y} (+{y - x})"))

    # --- VLAN ---
    old_v = {v.id: v for v in old.vlans}
    new_v = {v.id: v for v in new.vlans}
    changes += _diff_sets(h, "vlan", old_v, new_v, lambda v, t: f"VLAN {v.id} ({v.name}) {t}")
    for vid in sorted(set(old_v) & set(new_v)):
        if old_v[vid].name != new_v[vid].name:
            changes.append(Change(h, "vlan", "modificado", f"VLAN {vid}: nombre {old_v[vid].name} -> {new_v[vid].name}"))

    # --- Rutas (clave = prefijo + next hop + interfaz) ---
    key_r = lambda r: (r.prefix, r.next_hop, r.interface)
    changes += _diff_sets(h, "ruta", {key_r(r): r for r in old.routes}, {key_r(r): r for r in new.routes},
                          lambda r, t: f"Ruta {r.prefix} via {r.next_hop or r.interface} {t}")

    # --- Vecinos (clave = interfaz local + vecino remoto) ---
    key_n = lambda n: (n.local_interface, n.remote_device)
    changes += _diff_sets(h, "vecino", {key_n(n): n for n in old.neighbors}, {key_n(n): n for n in new.neighbors},
                          lambda n, t: f"Vecino {n.remote_device} en {n.local_interface} {t}")
    return changes


def compare_runs(old: Run, new: Run) -> List[Change]:
    """Compara dos ejecuciones completas."""
    old_d = {d.hostname: d for d in old.devices}
    new_d = {d.hostname: d for d in new.devices}
    changes: List[Change] = []

    for host in sorted(set(old_d) | set(new_d)):
        if host not in old_d:
            changes.append(Change(host, "dispositivo", "alta", "Nuevo en el inventario"))
        elif host not in new_d:
            changes.append(Change(host, "dispositivo", "baja", "Ya no esta en el inventario"))
        elif old_d[host].status != new_d[host].status:
            changes.append(Change(host, "dispositivo", "modificado",
                                  f"Estado de auditoria: {old_d[host].status} -> {new_d[host].status}"))
        elif new_d[host].status == "ok":          # solo se compara el detalle si ambos son validos
            changes += compare_devices(old_d[host], new_d[host])
    return changes
