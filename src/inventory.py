"""Carga y VALIDA el archivo de inventario (config.yaml o config.secure.yaml)."""
from pathlib import Path

import yaml  # pip install pyyaml

from src.crypto_utils import decrypt_value, safe_ip
from src.security import register_sensitive_ips

# Campos que todo dispositivo debe traer
REQUIRED_FIELDS = ("hostname", "host", "platform", "transport")
# Si el inventario trae alguna de estas claves, se RECHAZA (seguridad: sin secretos en archivos)
FORBIDDEN_KEYS = {"password", "passwd", "secret", "community", "token"}
# Plataformas que la herramienta sabra auditar (se amplia al agregar parsers)
SUPPORTED_PLATFORMS = {"cisco_ios", "juniper_junos"}


class Inventory:
    """Contenedor: parametros (audit), umbrales (policy), seguridad y lista de equipos."""
    def __init__(self, audit: dict, policy: dict, devices: list, security: dict = None):
        self.audit = audit
        self.policy = policy
        self.devices = devices      # lista de diccionarios, uno por equipo
        self.security = security or {}

    def get(self, hostname: str) -> dict:
        """Busca un equipo por nombre (lo usaran las reglas para leer expected_up, etc.)."""
        return next((d for d in self.devices if d["hostname"] == hostname), {})


def load_inventory(path: str = "config.yaml") -> Inventory:
    file = Path(path)
    if not file.exists():
        raise FileNotFoundError(f"No existe {path}. Ejecuta desde la carpeta raiz del proyecto.")

    data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    devices = data.get("devices", [])
    if not devices:
        raise ValueError("El inventario no tiene dispositivos")

    seen = set()
    for dev in devices:
        name = dev.get("hostname", "?")
        # 1) campos obligatorios
        missing = [k for k in REQUIRED_FIELDS if k not in dev]
        if missing:
            raise ValueError(f"{name}: faltan campos obligatorios {missing}")
        # 2) sin secretos dentro del archivo
        bad = FORBIDDEN_KEYS & {k.lower() for k in dev}
        if bad:
            raise ValueError(f"{name}: no se permiten secretos en el inventario {bad}")
        # 3) plataforma soportada
        if dev["platform"] not in SUPPORTED_PLATFORMS:
            raise ValueError(f"{name}: plataforma no soportada '{dev['platform']}'")
        # 4) hostnames unicos
        if name in seen:
            raise ValueError(f"Hostname duplicado: {name}")
        seen.add(name)

    # 5) IP cifradas: se descifran SOLO en memoria y se registran para ocultarlas en logs/reportes
    for dev in devices:
        dev["host"] = decrypt_value(dev["host"])       # si no empieza con 'enc:' queda igual
        dev["host_safe"] = safe_ip(dev["host"])        # forma oculta para mostrar
    register_sensitive_ips([d["host"] for d in devices])

    return Inventory(audit=data.get("audit", {}),
                     policy=data.get("policy", {}),
                     devices=devices,
                     security=data.get("security", {}))
