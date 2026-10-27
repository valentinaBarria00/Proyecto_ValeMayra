"""PRUEBAS del PASO 5: cifrado de IP, control de accesos y cierre de sesiones.
Ejecutar:  python -m unittest discover -s tests -t . -v"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.fernet import Fernet

from src import crypto_utils as cu
from src.access_control import (AccessBlocked, AccessMonitor, SessionRegistry,
                                connect_secure, secure_session)
from src.errors import AuthenticationError, ConnectionTimeoutError
from src.inventory import load_inventory
from src.security import redact, register_sensitive_ips


class RelojFalso:
    """Reloj controlable para probar bloqueos sin esperar minutos reales."""
    def __init__(self): self.t = datetime(2026, 10, 14, 10, 0, 0)
    def __call__(self): return self.t
    def avanzar(self, minutos): self.t += timedelta(minutes=minutos)


class ConexionFalsa:
    def __init__(self): self.cerrada = False
    def close(self): self.cerrada = True


DEV = {"hostname": "SW9", "host": "192.0.2.99", "cred_ref": "LAB"}


class TestCifradoIP(unittest.TestCase):
    def setUp(self):
        self.old = os.environ.get("WOLF_KEY")
        os.environ["WOLF_KEY"] = Fernet.generate_key().decode()

    def tearDown(self):
        os.environ.pop("WOLF_KEY", None)
        if self.old:
            os.environ["WOLF_KEY"] = self.old

    def test_cifra_y_descifra(self):
        enc = cu.encrypt_value("192.0.2.11")
        self.assertTrue(enc.startswith("enc:"))
        self.assertNotIn("192.0.2.11", enc)                      # la IP no aparece en claro
        self.assertEqual(cu.decrypt_value(enc), "192.0.2.11")
        self.assertEqual(cu.decrypt_value("192.0.2.11"), "192.0.2.11")   # texto plano pasa igual

    def test_clave_incorrecta_o_ausente(self):
        enc = cu.encrypt_value("192.0.2.11")
        os.environ["WOLF_KEY"] = Fernet.generate_key().decode()  # otra clave
        with self.assertRaises(cu.CryptoError):
            cu.decrypt_value(enc)
        del os.environ["WOLF_KEY"]
        with self.assertRaises(cu.CryptoError):
            cu.encrypt_value("192.0.2.11")

    def test_mascara_distingue_equipos(self):
        self.assertEqual(cu.mask_ip("192.0.2.11"), "192.0.x.x")
        self.assertNotEqual(cu.safe_ip("192.0.2.11"), cu.safe_ip("192.0.2.12"))

    def test_redact_oculta_ip_de_gestion_sin_cortar_otras(self):
        register_sensitive_ips(["192.0.2.22"])
        out = redact("Timeout conectando a 192.0.2.22.")
        self.assertNotIn("192.0.2.22", out)
        self.assertIn("192.0.x.x#", out)
        self.assertIn("192.0.2.221", redact("otro equipo 192.0.2.221"))   # no corta IP distintas

    def test_inventario_cifrado_se_descifra_en_memoria(self):
        original = load_inventory("config.yaml")
        cifrado = cu.encrypt_config_text(Path("config.yaml").read_text(encoding="utf-8"))
        for d in original.devices:
            self.assertNotIn(d["host"], cifrado)                 # ninguna IP queda en el archivo
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "secure.yaml"
            ruta.write_text(cifrado, encoding="utf-8")
            inv = load_inventory(str(ruta))
        self.assertEqual([d["host"] for d in inv.devices], [d["host"] for d in original.devices])
        self.assertTrue(all("x.x#" in d["host_safe"] for d in inv.devices))


class TestControlDeAccesos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reloj = RelojFalso()
        self.mon = AccessMonitor(self.tmp.name, max_failures=3, lockout_minutes=15,
                                 run_id="t", clock=self.reloj)
        register_sensitive_ips([DEV["host"]])

    def tearDown(self):
        self.tmp.cleanup()

    def test_bloquea_tras_fallos_y_se_libera_con_el_tiempo(self):
        for _ in range(3):
            self.mon.record(DEV, "auth_fail", "rechazada")
        with self.assertRaises(AccessBlocked):
            self.mon.check_allowed(DEV)
        resumen = self.mon.summary()["SW9"]
        self.assertEqual((resumen["fallos_clave"], resumen["bloqueados"]), (3, 1))
        self.assertTrue(resumen["estado"].startswith("BLOQUEADO"))
        self.reloj.avanzar(16)                                   # pasa el tiempo de bloqueo
        self.mon.check_allowed(DEV)                              # ya no lanza error

    def test_un_exito_reinicia_el_contador(self):
        for r in ("auth_fail", "auth_fail", "success", "auth_fail", "auth_fail"):
            self.mon.record(DEV, r)
        self.mon.check_allowed(DEV)                              # nunca llego a 3 seguidos

    def test_el_log_no_guarda_ip_ni_claves(self):
        self.mon.record(DEV, "error", "falla con password Sup3r en 192.0.2.99")
        texto = self.mon.log_path.read_text(encoding="utf-8")
        self.assertNotIn("192.0.2.99", texto)
        self.assertNotIn("Sup3r", texto)

    def test_timeout_se_reintenta_pero_clave_mala_no(self):
        llamadas = {"n": 0}
        def timeout():
            llamadas["n"] += 1
            raise ConnectionTimeoutError("sin respuesta")
        with self.assertRaises(ConnectionTimeoutError):
            connect_secure(self.mon, SessionRegistry(), DEV, timeout, retries=2)
        self.assertEqual(llamadas["n"], 3)                       # 1 intento + 2 reintentos

        llamadas["n"] = 0
        def clave_mala():
            llamadas["n"] += 1
            raise AuthenticationError("rechazada")
        with self.assertRaises(AuthenticationError):
            connect_secure(self.mon, SessionRegistry(), DEV, clave_mala, retries=2)
        self.assertEqual(llamadas["n"], 1)                       # NUNCA se reintenta

    def test_equipo_bloqueado_no_abre_conexion(self):
        for _ in range(3):
            self.mon.record(DEV, "auth_fail")
        abierto = {"n": 0}
        def opener():
            abierto["n"] += 1
            return ConexionFalsa()
        with self.assertRaises(AccessBlocked):
            connect_secure(self.mon, SessionRegistry(), DEV, opener)
        self.assertEqual(abierto["n"], 0)                        # ni siquiera intento conectar


class TestSesionesCerradas(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.mon = AccessMonitor(self.tmp.name, run_id="t")
        self.reg = SessionRegistry()

    def tearDown(self):
        self.tmp.cleanup()

    def test_se_cierra_en_exito_y_en_error(self):
        c1, c2 = ConexionFalsa(), ConexionFalsa()
        with secure_session(self.mon, self.reg, DEV, lambda: c1):
            self.assertEqual(self.reg.open_sessions(), ["SW9"])   # abierta dentro del bloque
        self.assertTrue(c1.cerrada)
        with self.assertRaises(RuntimeError):
            with secure_session(self.mon, self.reg, DEV, lambda: c2):
                raise RuntimeError("falla a mitad de la auditoria")
        self.assertTrue(c2.cerrada)                               # se cerro igual
        self.assertEqual(self.reg.open_sessions(), [])

    def test_close_all_cierra_lo_que_quede(self):
        c = ConexionFalsa()
        self.reg.add("X", c)
        self.reg.close_all()
        self.assertTrue(c.cerrada)
        self.assertEqual(self.reg.open_sessions(), [])


if __name__ == "__main__":
    unittest.main()
