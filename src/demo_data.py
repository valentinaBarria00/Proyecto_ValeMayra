"""DATOS DE DEMOSTRACION para probar reglas y comparador SIN equipos reales.
Simula dos auditorias: BASE (10:00) y CAMBIO (12:00, dos horas despues).
En el PASO 2 estos datos los producen los collectors + parsers reales,
y este archivo se puede conservar solo para las pruebas automaticas."""
from src.models import DeviceState, Interface, Neighbor, Route, Run, Vlan

DAY = 86400


def _cisco(host, version, uptime, ifaces, vlans, neighbors, routes, when, role):
    return DeviceState(hostname=host, platform="cisco_ios", role=role, collected_at=when,
                       version=version, uptime_seconds=uptime, interfaces=ifaces,
                       vlans=vlans, neighbors=neighbors, routes=routes)


def _junos(host, version, uptime, ifaces, neighbors, routes, when, role):
    # Junos no informa nombre de VLAN en este ejemplo -> la lista queda vacia
    return DeviceState(hostname=host, platform="juniper_junos", role=role, collected_at=when,
                       version=version, uptime_seconds=uptime, interfaces=ifaces,
                       neighbors=neighbors, routes=routes)


def _itf(name, oper="up", in_bps=0, out_bps=0, in_err=0, out_err=0, speed=1000):
    return Interface(name=name, admin_status="up", oper_status=oper, speed_mbps=speed,
                     in_bps=in_bps, out_bps=out_bps, in_errors=in_err, out_errors=out_err)


DEFAULT = Route("0.0.0.0/0", next_hop="10.0.10.1", protocol="static")
CONNECTED = Route("10.0.10.0/24", interface="Vlan10", protocol="connected")


def build_demo_runs():
    """Devuelve (corrida_base, corrida_con_cambios)."""
    t0, t1 = "2026-10-10T10:00:00", "2026-10-10T12:00:00"

    # ---------------- CORRIDA BASE ----------------
    base = Run(run_id="20261010_100000", started_at=t0, devices=[
        _cisco("SW1", "15.2(4)E10", 45 * DAY,
               [_itf("GigabitEthernet0/1", in_bps=940_000_000, out_bps=310_000_000, in_err=120),
                _itf("GigabitEthernet0/2", in_bps=120_000_000, out_bps=80_000_000)],
               [Vlan(10, "DATOS"), Vlan(20, "SERVIDORES"), Vlan(30, "VOZ")],
               [Neighbor("GigabitEthernet0/1", "SW2", "GigabitEthernet0/24"),
                Neighbor("GigabitEthernet0/2", "R1", "ge-0/0/0")],
               [DEFAULT, CONNECTED], t0, "core"),
        _cisco("SW2", "12.2(55)SE", 30 * DAY,                      # version NO aprobada (R07)
               [_itf("GigabitEthernet0/1", in_bps=200_000_000, out_bps=150_000_000)],
               [Vlan(10, "DATOS"), Vlan(20, "SERVERS"), Vlan(30, "VOZ")],   # VLAN 20 distinta (R06)
               [Neighbor("GigabitEthernet0/1", "SW1", "GigabitEthernet0/1")],
               [CONNECTED], t0, "access"),
        _junos("R1", "21.4R3", 10 * DAY,
               [_itf("ge-0/0/0", in_bps=80_000_000, out_bps=60_000_000)],
               [Neighbor("ge-0/0/0", "SW1", "GigabitEthernet0/2")],
               [DEFAULT], t0, "router"),
        _junos("R2", "20.2R1", 3 * 3600,                           # version no aprobada + uptime 3 h
               [_itf("ge-0/0/0", in_bps=10_000_000, out_bps=10_000_000)],
               [Neighbor("ge-0/0/0", "R1", "ge-0/0/1")],
               [DEFAULT], t0, "router"),
    ])

    # ---------------- CORRIDA CON CAMBIOS (+2 horas) ----------------
    cambio = Run(run_id="20261010_120000", started_at=t1, devices=[
        _cisco("SW1", "15.2(4)E10", 45 * DAY + 7200,
               [_itf("GigabitEthernet0/1", in_bps=940_000_000, out_bps=310_000_000, in_err=5120),  # errores suben
                _itf("GigabitEthernet0/2", oper="down")],                                          # se cae el enlace a R1
               [Vlan(10, "DATOS"), Vlan(20, "SERVIDORES"), Vlan(30, "VOZ"), Vlan(40, "CAMARAS")], # VLAN nueva
               [Neighbor("GigabitEthernet0/1", "SW2", "GigabitEthernet0/24")],                    # pierde vecino R1
               [CONNECTED], t1, "core"),                                                          # pierde ruta por defecto
        _cisco("SW2", "12.2(55)SE", 30 * DAY + 7200,
               [_itf("GigabitEthernet0/1", in_bps=200_000_000, out_bps=150_000_000)],
               [Vlan(10, "DATOS"), Vlan(20, "SERVERS")],          # VLAN 30 eliminada
               [Neighbor("GigabitEthernet0/1", "SW1", "GigabitEthernet0/1")],
               [CONNECTED], t1, "access"),
        _junos("R1", "21.4R3", 10 * DAY + 7200,
               [_itf("ge-0/0/0", oper="down")],
               [], [DEFAULT], t1, "router"),
        # R2 deja de responder: se registra el error SIN romper la auditoria completa
        DeviceState(hostname="R2", platform="juniper_junos", role="router", collected_at=t1,
                    status="error", error="ConnectionTimeoutError: Timeout conectando a 192.0.2.22",
                    attempts=2),
    ])
    return base, cambio
