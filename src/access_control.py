"""CONTROL DE ACCESOS Y SESIONES.

AccessMonitor   : registra cada intento de conexion, cuenta cuantas veces se intento
                  entrar a cada equipo y BLOQUEA tras N fallos de clave seguidos.
SessionRegistry : lleva la cuenta de sesiones abiertas y las cierra siempre.
connect_secure / secure_session : forma obligatoria de conectarse a un equipo; une
                  las dos cosas anteriores (reintenta timeouts, nunca reintenta claves).

Como se usara en el PASO 2 (collectors reales):
    with secure_session(monitor, registry, device, lambda: abrir_ssh(device), retries=1) as conn:
        ... ejecutar comandos de solo lectura ...
    # al salir del bloque la sesion queda CERRADA, haya o no errores
"""
import atexit
import json
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from src.crypto_utils import safe_ip
from src.errors import AuditError, AuthenticationError, ConnectionTimeoutError
from src.security import redact


class AccessBlocked(AuditError):
    """El equipo esta bloqueado temporalmente por demasiados fallos de autenticacion."""


class AccessMonitor:
    def __init__(self, log_dir="logs", max_failures=3, lockout_minutes=15, run_id="", clock=None):
        self.log_path = Path(log_dir) / "access_log.jsonl"     # historial de intentos
        self.state_path = Path(log_dir) / "lockout_state.json"  # fallos seguidos y bloqueos
        self.max_failures = max_failures
        self.lockout = timedelta(minutes=lockout_minutes)
        self.run_id = run_id
        self.clock = clock or datetime.now                      # inyectable para pruebas
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._state = self._load_state()

    # ----------------------------- estado persistente -----------------------------
    def _load_state(self) -> dict:
        if self.state_path.exists():
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        return {}

    def _save_state(self) -> None:
        self.state_path.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def reset(self) -> None:
        """Borra registro y bloqueos (solo para la demostracion)."""
        for p in (self.log_path, self.state_path):
            if p.exists():
                p.unlink()
        self._state = {}

    # ----------------------------- registro de eventos -----------------------------
    def record(self, device: dict, outcome: str, detail: str = "") -> None:
        """outcome: success | timeout | auth_fail | error | blocked | closed | locked.
        Se guarda la IP OCULTA y el detalle sanitizado: el log nunca tiene IP ni claves reales."""
        event = {"ts": self.clock().isoformat(timespec="seconds"), "run_id": self.run_id,
                 "device": device["hostname"], "ip": safe_ip(device["host"]),
                 "cred_ref": device.get("cred_ref", ""), "outcome": outcome,
                 "detail": redact(detail)}
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

        # Contador de fallos de clave SEGUIDOS por equipo
        st = self._state.setdefault(device["hostname"], {"auth_failures": 0, "locked_until": None})
        if outcome == "auth_fail":
            st["auth_failures"] += 1
            if st["auth_failures"] >= self.max_failures:
                st["locked_until"] = (self.clock() + self.lockout).isoformat(timespec="seconds")
                self._save_state()
                self.record(device, "locked",
                            f"{st['auth_failures']} fallos seguidos; bloqueado {int(self.lockout.total_seconds() // 60)} min")
                return
        elif outcome == "success":
            st["auth_failures"], st["locked_until"] = 0, None
        self._save_state()

    def check_allowed(self, device: dict) -> None:
        """Llamar ANTES de conectar. Lanza AccessBlocked si el equipo esta bloqueado."""
        st = self._state.get(device["hostname"], {})
        until = st.get("locked_until")
        if not until:
            return
        if self.clock() < datetime.fromisoformat(until):
            self.record(device, "blocked", "intento denegado por bloqueo activo")
            raise AccessBlocked(f"{device['hostname']} bloqueado hasta {until[11:16]} "
                                f"por {st['auth_failures']} fallos de autenticacion seguidos")
        st["auth_failures"], st["locked_until"] = 0, None       # el bloqueo ya vencio
        self._save_state()

    # ----------------------------- resumen -----------------------------
    def summary(self, run_only=True) -> dict:
        """Cuantas veces se intento entrar a cada equipo.
        run_only=True cuenta solo esta ejecucion; False cuenta todo el historial."""
        rows = {}
        if not self.log_path.exists():
            return rows
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            e = json.loads(line)
            if run_only and e["run_id"] != self.run_id:
                continue
            r = rows.setdefault(e["device"], {"ip": e["ip"], "intentos": 0, "exitosos": 0,
                                              "fallos_clave": 0, "timeouts": 0, "errores": 0,
                                              "bloqueados": 0, "cerradas": 0, "ultimo": ""})
            key = {"success": "exitosos", "auth_fail": "fallos_clave", "timeout": "timeouts",
                   "error": "errores", "blocked": "bloqueados", "closed": "cerradas"}.get(e["outcome"])
            if key:
                r[key] += 1
            if e["outcome"] in ("success", "auth_fail", "timeout", "error"):
                r["intentos"] += 1
            r["ultimo"] = e["ts"]
        for host, r in rows.items():
            until = self._state.get(host, {}).get("locked_until")
            r["estado"] = (f"BLOQUEADO hasta {until[11:16]}"
                           if until and self.clock() < datetime.fromisoformat(until) else "libre")
        return rows


class SessionRegistry:
    """Registro de sesiones abiertas. Garantiza que ninguna quede abierta al terminar."""
    def __init__(self):
        self._open = {}
        atexit.register(self.close_all)          # red de seguridad al salir del programa

    def add(self, name: str, conn) -> None:
        self._open[name] = conn

    def close(self, name: str) -> None:
        conn = self._open.pop(name, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:                    # cerrar nunca debe romper la auditoria
                pass

    def close_all(self) -> None:
        for name in list(self._open):
            self.close(name)

    def open_sessions(self) -> list:
        return sorted(self._open)


def connect_secure(monitor, registry, device, opener, retries=1):
    """Conecta aplicando la politica de seguridad:
       - revisa bloqueo antes de cada intento
       - TIMEOUT  -> se reintenta hasta 'retries' veces
       - CLAVE MALA -> NUNCA se reintenta (evita bloquear la cuenta del equipo)
       - cada intento queda registrado"""
    last = None
    for attempt in range(1, retries + 2):
        monitor.check_allowed(device)
        try:
            conn = opener()
        except ConnectionTimeoutError as exc:
            monitor.record(device, "timeout", f"intento {attempt}: {exc}")
            last = exc
            continue
        except AuthenticationError as exc:
            monitor.record(device, "auth_fail", str(exc))
            raise
        except Exception as exc:
            monitor.record(device, "error", type(exc).__name__)
            raise
        monitor.record(device, "success", f"conectado en el intento {attempt}")
        registry.add(device["hostname"], conn)
        return conn
    raise last


@contextmanager
def secure_session(monitor, registry, device, opener, retries=1):
    """Abre la sesion y GARANTIZA su cierre al salir del bloque 'with'."""
    conn = connect_secure(monitor, registry, device, opener, retries)
    try:
        yield conn
    finally:
        registry.close(device["hostname"])
        monitor.record(device, "closed", "sesion cerrada")


def security_section_md(summary: dict, open_sessions: list) -> str:
    """Seccion de Markdown con los accesos (para agregar al informe)."""
    lines = ["## Seguridad de accesos y sesiones\n",
             "| Equipo | IP (oculta) | Intentos | Exitosos | Clave rechazada | Timeouts | Bloqueados | Estado |",
             "|---|---|---|---|---|---|---|---|"]
    for host, r in sorted(summary.items()):
        lines.append(f"| {host} | {r['ip']} | {r['intentos']} | {r['exitosos']} | {r['fallos_clave']} | "
                     f"{r['timeouts']} | {r['bloqueados']} | {r['estado']} |")
    lines.append(f"\n- **Sesiones abiertas al finalizar:** {len(open_sessions)}"
                 + (f" ({', '.join(open_sessions)})" if open_sessions else ""))
    lines.append("- Las IP de gestión se almacenan cifradas y se muestran ocultas; "
                 "la herramienta no abre puertos en escucha.")
    return redact("\n".join(lines))
