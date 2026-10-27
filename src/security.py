"""SEGURIDAD: solo lectura, credenciales fuera del codigo, sanitizacion y ocultamiento de IP.
Cubre los requerimientos R01 y R05 del informe."""
import logging
import os
import re
from pathlib import Path

from src.errors import AuthenticationError, ReadOnlyViolation

# ---------------- 1. SOLO LECTURA (requerimiento R01) ----------------
# Lista blanca: un comando CLI solo se ejecuta si empieza con alguno de estos prefijos.
ALLOWED_PREFIXES = ("show ", "uname", "cat /proc/", "ip -j", "lldpcli show")
# Lista negra: verbos que modifican y caracteres para encadenar comandos.
FORBIDDEN_WORDS = re.compile(
    r"\b(set|add|del|delete|flush|replace|change|configure|conf|write|erase|"
    r"reload|reboot|shutdown|copy|rm|mv|tee|dd)\b", re.IGNORECASE)
FORBIDDEN_CHARS = re.compile(r"[;&|><`$]")


def ensure_read_only(command: str) -> None:
    """Lanza ReadOnlyViolation si el comando CLI podria modificar el equipo.
    Los conectores deben llamar a esta funcion ANTES de enviar cualquier comando."""
    cmd = command.strip()
    if not cmd.startswith(ALLOWED_PREFIXES):
        raise ReadOnlyViolation(f"Comando fuera de la lista blanca: '{cmd}'")
    if FORBIDDEN_CHARS.search(cmd) or FORBIDDEN_WORDS.search(cmd):
        raise ReadOnlyViolation(f"Comando potencialmente modificador: '{cmd}'")


def ensure_read_only_rpc(rpc_name: str) -> None:
    """Equivalente para NETCONF: solo se permiten operaciones 'get-*' / 'get'.
    Se bloquean edit-config, commit, lock, load-configuration, etc."""
    name = rpc_name.strip().lower()
    if not (name == "get" or name == "get-config" or name.startswith("get-")):
        raise ReadOnlyViolation(f"Operacion NETCONF no permitida: '{rpc_name}'")


# ---------------- 2. CREDENCIALES (requerimiento R05) ----------------
def load_dotenv_simple(path: str = ".env") -> None:
    """Carga variables desde .env (archivo que NO se sube a Git)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def get_credentials(cred_ref: str):
    """Devuelve (usuario, clave) desde <REF>_USER y <REF>_PASS. El inventario solo
    guarda la REFERENCIA (cred_ref), nunca el valor."""
    user = os.environ.get(f"{cred_ref}_USER")
    password = os.environ.get(f"{cred_ref}_PASS")
    if not user or not password:
        raise AuthenticationError(f"Credencial '{cred_ref}' no definida en variables de entorno")
    return user, password


# ---------------- 3. SANITIZACION + OCULTAMIENTO DE IP ----------------
# Detecta "enable secret 5 $1$xx", "password abc", "snmp-server community X", etc.
SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|community|token)\b(\s+\d+)?(\s*[:=]\s*|\s+)(\S+)")

# IP de GESTION registradas (las del inventario) -> su version oculta.
# Solo estas se ocultan: las IP de interfaces/rutas son datos de la auditoria y se conservan.
_SENSITIVE_IPS = {}


def register_sensitive_ips(ips) -> None:
    """El inventario llama a esto al cargar: desde ahi toda IP de gestion sale oculta."""
    from src.crypto_utils import safe_ip            # import tardio (evita ciclos)
    _SENSITIVE_IPS.clear()
    for ip in ips:
        _SENSITIVE_IPS[ip] = safe_ip(ip)


def redact(text: str, secrets=()) -> str:
    """Oculta secretos conocidos, patrones tipicos de secretos e IP de gestion."""
    if not text:
        return text
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    text = SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2) or ''}{m.group(3)}***", text)
    # IP mas largas primero y con limites, para no cortar 192.0.2.221 al buscar 192.0.2.22
    for ip in sorted(_SENSITIVE_IPS, key=len, reverse=True):
        text = re.sub(rf"(?<![\d.]){re.escape(ip)}(?!\d)", _SENSITIVE_IPS[ip], text)
    return text


class RedactFilter(logging.Filter):
    """Filtro de logging: ningun mensaje de log sale sin sanitizar."""
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.getMessage()))
        record.args = ()
        return True
