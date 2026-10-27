"""CIFRADO Y OCULTAMIENTO DE IP.

- encrypt_value / decrypt_value : cifrado simetrico Fernet (AES-128 + firma HMAC).
  Un valor cifrado se guarda como  "enc:<texto cifrado>"  y se detecta por ese prefijo.
- mask_ip / safe_ip             : version OCULTA de una IP para logs y reportes.
- La clave se lee de la variable de entorno WOLF_KEY (archivo .env), nunca del codigo.

Uso desde la terminal (raiz del proyecto):
    python -m src.crypto_utils genkey
    python -m src.crypto_utils encrypt-config config.yaml config.secure.yaml
"""
import hashlib
import hmac
import os
import re
import sys

from src.errors import AuditError

PREFIX = "enc:"


class CryptoError(AuditError):
    """Problema de clave o de cifrado (mensaje claro, sin revelar datos)."""


def _fernet():
    """Crea el objeto de cifrado con la clave WOLF_KEY. Falla con mensajes claros."""
    try:
        from cryptography.fernet import Fernet      # import tardio: solo se exige si se usa
    except ImportError:
        raise CryptoError("Falta la libreria 'cryptography'. Instala con: pip install cryptography")
    key = os.environ.get("WOLF_KEY", "").strip()
    if not key:
        raise CryptoError("Falta WOLF_KEY en el .env (genera una con: python -m src.crypto_utils genkey)")
    try:
        return Fernet(key.encode())
    except Exception:
        raise CryptoError("WOLF_KEY invalida: debe generarse con 'python -m src.crypto_utils genkey'")


def generate_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


def encrypt_value(plain: str) -> str:
    """Cifra un texto (ej. una IP). Si ya esta cifrado, lo deja igual."""
    if plain.startswith(PREFIX):
        return plain
    return PREFIX + _fernet().encrypt(plain.encode()).decode()


def decrypt_value(value):
    """Si el valor empieza con 'enc:' lo descifra; si no, lo devuelve tal cual
    (asi el inventario con IP en texto plano sigue funcionando)."""
    if not isinstance(value, str) or not value.startswith(PREFIX):
        return value
    fernet = _fernet()
    from cryptography.fernet import InvalidToken
    try:
        return fernet.decrypt(value[len(PREFIX):].encode()).decode()
    except InvalidToken:
        raise CryptoError("No se pudo descifrar: clave WOLF_KEY incorrecta o dato alterado")


# ------------------------- ocultar IP en logs y reportes -------------------------
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$")


def mask_ip(ip: str) -> str:
    """192.0.2.11 -> 192.0.x.x"""
    m = _IPV4.match(ip)
    return f"{m.group(1)}.{m.group(2)}.x.x" if m else "[host-oculto]"


def pseudonym(ip: str) -> str:
    """Codigo corto (4 hex) derivado de la IP con HMAC: distingue equipos entre si
    sin revelar la IP. Con la misma clave, la misma IP da siempre el mismo codigo."""
    key = (os.environ.get("WOLF_KEY") or "wolf-sin-clave").encode()
    return hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:4]


def safe_ip(ip: str) -> str:
    """Forma segura para mostrar: 192.0.x.x#a3f1"""
    return f"{mask_ip(ip)}#{pseudonym(ip)}"


# ------------------------- cifrar el archivo de inventario -------------------------
_HOST_LINE = re.compile(r"(?m)^(\s*host:\s*)([^\s#]+)")


def encrypt_config_text(text: str) -> str:
    """Cifra el valor de cada linea 'host:' del YAML, conservando comentarios y formato."""
    def repl(m):
        value = m.group(2).strip("\"'")
        if not value.startswith(PREFIX):
            value = encrypt_value(value)
        return f'{m.group(1)}"{value}"'
    return _HOST_LINE.sub(repl, text)


def _cli(argv) -> int:
    from src.security import load_dotenv_simple
    load_dotenv_simple(".env")                       # para leer WOLF_KEY si ya esta en .env
    try:
        if argv[:1] == ["genkey"]:
            print("Copia esta linea dentro de tu archivo .env (y respaldala en un lugar seguro):\n")
            print(f"WOLF_KEY={generate_key()}")
            return 0
        if argv[:1] == ["encrypt-config"] and len(argv) == 3:
            with open(argv[1], encoding="utf-8") as fh:
                original = fh.read()
            secure = encrypt_config_text(original)
            with open(argv[2], "w", encoding="utf-8") as fh:
                fh.write(secure)
            print(f"Listo: {argv[2]} generado con las IP cifradas ({secure.count(PREFIX)} valores).")
            return 0
    except CryptoError as exc:
        print(f"ERROR: {exc}")
        return 1
    print("Uso:\n  python -m src.crypto_utils genkey\n"
          "  python -m src.crypto_utils encrypt-config <entrada.yaml> <salida.yaml>")
    return 1


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
