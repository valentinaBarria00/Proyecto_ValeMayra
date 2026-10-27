"""MODELO COMUN (Wolf: "Modelo comun - normaliza interfaces, VLAN, rutas y vecinos").

Idea clave: Cisco y Juniper entregan los datos en formatos totalmente distintos.
Cada parser (adaptador) los convierte a ESTAS clases. Asi el motor de reglas,
el comparador y el reporte trabajan con un solo formato, sin importar la marca.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Interface:
    """Una interfaz de red, ya normalizada."""
    name: str                              # nombre completo, ej. GigabitEthernet0/1
    admin_status: str = "unknown"          # up | down | unknown (estado administrativo)
    oper_status: str = "unknown"           # up | down | unknown (estado operativo real)
    speed_mbps: Optional[int] = None       # velocidad del enlace en Mbps
    ipv4: Optional[str] = None             # direccion con mascara, ej. 10.0.0.1/24
    description: str = ""
    in_errors: Optional[int] = None        # errores de entrada (contador ACUMULADO)
    out_errors: Optional[int] = None       # errores de salida (contador ACUMULADO)
    in_discards: Optional[int] = None      # descartes de entrada
    out_discards: Optional[int] = None     # descartes de salida
    in_bps: Optional[int] = None           # trafico de entrada (bits por segundo)
    out_bps: Optional[int] = None          # trafico de salida (bits por segundo)

    @property
    def utilization_pct(self) -> Optional[float]:
        """Utilizacion = (trafico maximo entre in/out) / velocidad * 100.
        Devuelve None si falta algun dato (Wolf: la ausencia de datos es una
        LIMITACION, no un cumplimiento)."""
        if self.speed_mbps and (self.in_bps is not None or self.out_bps is not None):
            peak = max(self.in_bps or 0, self.out_bps or 0)
            return round(peak / (self.speed_mbps * 1_000_000) * 100, 1)
        return None


@dataclass
class Vlan:
    id: int                                # numero de VLAN (1-4094)
    name: Optional[str] = None
    ports: List[str] = field(default_factory=list)


@dataclass
class Route:
    prefix: str                            # red destino, ej. 0.0.0.0/0
    next_hop: Optional[str] = None         # gateway
    interface: Optional[str] = None        # interfaz de salida
    protocol: str = "unknown"              # connected | static | ospf | bgp ...


@dataclass
class Neighbor:
    local_interface: str                   # mi interfaz
    remote_device: str                     # nombre del vecino (LLDP/CDP)
    remote_port: Optional[str] = None      # puerto del vecino


@dataclass
class DeviceState:
    """Estado completo de UN dispositivo en UNA ejecucion."""
    hostname: str
    platform: str
    role: str = ""
    status: str = "ok"                     # ok | error (si no se pudo auditar)
    error: Optional[str] = None            # motivo del error (SIEMPRE sin secretos)
    collected_at: str = ""                 # fecha/hora ISO 8601 (evidencia)
    duration_s: float = 0.0                # cuanto tardo la auditoria del equipo
    attempts: int = 1                      # intentos realizados
    version: Optional[str] = None
    uptime_seconds: Optional[int] = None
    interfaces: List[Interface] = field(default_factory=list)
    vlans: List[Vlan] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    neighbors: List[Neighbor] = field(default_factory=list)
    config: Optional[str] = None           # configuracion YA sin secretos
    limitations: List[str] = field(default_factory=list)  # datos que NO se pudieron obtener
    raw: dict = field(default_factory=dict)  # salida original = EVIDENCIA

    @classmethod
    def from_dict(cls, d: dict) -> "DeviceState":
        """Reconstruye un DeviceState desde un JSON guardado (para comparar corridas)."""
        d = dict(d)
        d["interfaces"] = [Interface(**i) for i in d.get("interfaces", [])]
        d["vlans"] = [Vlan(**v) for v in d.get("vlans", [])]
        d["routes"] = [Route(**r) for r in d.get("routes", [])]
        d["neighbors"] = [Neighbor(**n) for n in d.get("neighbors", [])]
        return cls(**d)


@dataclass
class Run:
    """Una ejecucion completa de auditoria (todos los dispositivos)."""
    run_id: str                            # ej. 20261010_100000
    started_at: str
    devices: List[DeviceState] = field(default_factory=list)

    def save(self, directory: str) -> Path:
        """Guarda la ejecucion en JSON. Estos archivos son la 'linea base' futura."""
        path = Path(directory) / f"{self.run_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False),
                        encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str) -> "Run":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        d["devices"] = [DeviceState.from_dict(x) for x in d["devices"]]
        return cls(**d)


@dataclass
class Finding:
    """Hallazgo explicable (Wolf: cita dispositivo, evidencia, criterio y riesgo)."""
    rule_id: str                           # ej. R03
    severity: str                          # critica | alta | media | baja | limitacion
    device: str
    title: str
    evidence: str                          # el dato concreto que lo demuestra
    criterion: str                         # la regla/umbral que se incumple
    recommendation: str                    # que hacer (solo propuesta, no se aplica)
    risk: str                              # riesgo de aplicar el cambio
    verification: str                      # como comprobar que quedo corregido


@dataclass
class Change:
    """Diferencia detectada entre dos ejecuciones (deriva de configuracion)."""
    device: str
    category: str                          # interfaz | vlan | ruta | vecino | version | dispositivo
    kind: str                              # alta | baja | modificado
    detail: str


def validate_state(state: DeviceState) -> List[str]:
    """Valida el esquema normalizado. Devuelve la lista de problemas (vacia = OK)."""
    problems = []
    if not state.hostname or not state.platform:
        problems.append("hostname o platform vacio")
    names = [i.name for i in state.interfaces]
    if len(names) != len(set(names)):
        problems.append("hay nombres de interfaz duplicados")
    for v in state.vlans:
        if not 1 <= v.id <= 4094:
            problems.append(f"VLAN fuera de rango: {v.id}")
    for i in state.interfaces:
        for attr in ("in_errors", "out_errors", "in_discards", "out_discards"):
            value = getattr(i, attr)
            if value is not None and value < 0:
                problems.append(f"{i.name}.{attr} es negativo")
    return problems
