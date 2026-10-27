"""Excepciones propias. Separarlas permite decidir que hacer segun el tipo de fallo:
reintentar un timeout, pero NO reintentar una clave incorrecta (evita bloquear la cuenta)."""


class AuditError(Exception):
    """Base de todos los errores de la herramienta."""


class ConnectionTimeoutError(AuditError):
    """El equipo no respondio a tiempo (se puede reintentar)."""


class AuthenticationError(AuditError):
    """Credenciales ausentes o rechazadas (NO se reintenta)."""


class PrivilegeError(AuditError):
    """Sin privilegio para ese comando (se anota como limitacion)."""


class CommandError(AuditError):
    """El comando fallo o no existe en la plataforma."""


class ReadOnlyViolation(AuditError):
    """Se intento ejecutar algo que NO es de solo lectura."""
