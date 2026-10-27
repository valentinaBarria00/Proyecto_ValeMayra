"""PRUEBAS AUTOMATICAS (Wolf: casos T1-T4 + pruebas 01-03 del plan de pruebas del informe).
Ejecutar desde la raiz:  python -m unittest discover -s tests -t . -v"""
import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from src.analysis import RuleContext, compare_runs, evaluate
from src.demo_data import build_demo_runs
from src.errors import ReadOnlyViolation
from src.inventory import load_inventory
from src.models import DeviceState, Run, validate_state
from src.reporting import build_alert, build_markdown, write_reports
from src.security import ensure_read_only, ensure_read_only_rpc, redact

INV = load_inventory("config.yaml")
BASE, CAMBIO = build_demo_runs()
FINDINGS = evaluate(RuleContext(CAMBIO, BASE, INV))
CHANGES = compare_runs(BASE, CAMBIO)


class TestCasosWolf(unittest.TestCase):

    def test_t1_normalizacion_multiplataforma(self):
        """T1: dos plataformas distintas producen el MISMO esquema normalizado."""
        ok = [d for d in BASE.devices if d.status == "ok"]
        self.assertEqual({d.platform for d in ok}, {"cisco_ios", "juniper_junos"})
        for d in ok:
            self.assertEqual(validate_state(d), [], d.hostname)
        keys = [set(asdict(d)) for d in ok]
        self.assertTrue(all(k == keys[0] for k in keys))          # mismas claves
        with tempfile.TemporaryDirectory() as tmp:                # ida y vuelta a JSON
            path = BASE.save(tmp)
            self.assertEqual(asdict(Run.load(str(path))), asdict(BASE))

    def test_t2_error_controlado_sin_fuga_de_secretos(self):
        """T2: un equipo con timeout se registra como error; la auditoria continua."""
        r2 = next(d for d in CAMBIO.devices if d.hostname == "R2")
        self.assertEqual(r2.status, "error")
        self.assertTrue(any(f.rule_id == "R09" and f.device == "R2" for f in FINDINGS))
        self.assertGreater(len([d for d in CAMBIO.devices if d.status == "ok"]), 0)
        # Si el mensaje de error trajera una clave, el reporte debe ocultarla
        leaky = Run("x", "2026-10-10T12:00:00", [DeviceState(
            "R9", "juniper_junos", status="error", error="auth fallida password Sup3rSecret")])
        text = build_markdown(leaky, [], [], None)
        self.assertNotIn("Sup3rSecret", text)

    def test_t3_deteccion_de_cambios(self):
        """T3: la comparacion detecta altas, bajas y modificaciones entre corridas."""
        det = {(c.device, c.category, c.kind) for c in CHANGES}
        self.assertIn(("SW1", "vlan", "alta"), det)               # VLAN 40 nueva
        self.assertIn(("SW1", "ruta", "baja"), det)               # ruta por defecto perdida
        self.assertIn(("SW1", "contador", "modificado"), det)     # errores crecen
        self.assertIn(("SW2", "vlan", "baja"), det)               # VLAN 30 eliminada
        self.assertIn(("R2", "dispositivo", "modificado"), det)   # ok -> error

    def test_t4_hallazgos_conocidos_con_evidencia(self):
        """T4: reglas conocidas disparan con evidencia, criterio y recomendacion."""
        def get(rule, dev):
            return next(f for f in FINDINGS if f.rule_id == rule and f.device == dev)
        self.assertIn("2500", get("R01", "SW1").evidence)         # 5000 errores / 2 h
        self.assertIn("94.0", get("R03", "SW1").title)            # utilizacion 94%
        self.assertIn("30", get("R10", "SW2").title)              # VLAN 30 ausente
        for f in FINDINGS:                                        # nada queda vacio
            for campo in ("evidence", "criterion", "recommendation", "risk", "verification"):
                self.assertTrue(getattr(f, campo), f"{f.rule_id}.{campo} vacio")
        self.assertGreaterEqual(len({f.rule_id for f in FINDINGS}), 5)   # >= 5 hallazgos distintos

    def test_sin_linea_base_es_limitacion(self):
        """Wolf: la ausencia de datos es limitacion, no cumplimiento."""
        f = evaluate(RuleContext(BASE, None, INV))
        r01 = [x for x in f if x.rule_id == "R01"]
        self.assertTrue(r01 and all(x.severity == "limitacion" for x in r01))


class TestPlanDePruebasInforme(unittest.TestCase):

    def test_01_lectura_segura(self):
        """Prueba 01: cero comandos de configuracion pueden enviarse."""
        for ok in ("show version", "show ip interface brief", "show vlan brief",
                   "show cdp neighbors", "show lldp neighbors", "show ip route"):
            ensure_read_only(ok)                                  # no debe lanzar error
        for bad in ("configure terminal", "conf t", "write memory", "copy run start",
                    "show version; reload", "show running-config | include password",
                    "ip link set eth0 down", "reload"):
            with self.assertRaises(ReadOnlyViolation, msg=bad):
                ensure_read_only(bad)
        ensure_read_only_rpc("get-software-information")          # NETCONF lectura
        with self.assertRaises(ReadOnlyViolation):
            ensure_read_only_rpc("edit-config")

    def test_02_json_valido_y_completo(self):
        """Prueba 02: run.json valido, con los campos obligatorios completos."""
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_reports(CAMBIO, FINDINGS, CHANGES, BASE, tmp)
            data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        for d in data["devices"]:
            for campo in ("hostname", "platform", "status", "collected_at"):
                self.assertTrue(d[campo], f"{d['hostname']}.{campo} vacio")
            if d["status"] == "ok":
                self.assertTrue(d["version"] and d["uptime_seconds"] is not None and d["interfaces"])

    def test_03_sanidad_de_secretos(self):
        """Prueba 03: ninguna clave en texto claro dentro de los reportes."""
        self.assertNotIn("$1$mERr$hx5rVt7", redact("enable secret 5 $1$mERr$hx5rVt7"))
        self.assertNotIn("PUBLIC-LAB", redact("snmp-server community PUBLIC-LAB RO"))
        self.assertNotIn("MiClave123", redact("login con MiClave123 fallido", secrets=["MiClave123"]))
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_reports(CAMBIO, FINDINGS, CHANGES, BASE, tmp)
            for p in paths.values():
                contenido = Path(p).read_text(encoding="utf-8-sig")
                self.assertNotIn("Sup3rSecret", contenido)

    def test_alerta_resume_lo_grave(self):
        subject, body, n = build_alert(CAMBIO, FINDINGS, CHANGES, "alta")
        self.assertGreater(n, 0)
        self.assertIn("VLAN esperada ausente", body)


if __name__ == "__main__":
    unittest.main()
