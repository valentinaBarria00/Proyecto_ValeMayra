"""COMPROBACION DEL PASO 1 (antes era main.py). En el PASO 1 solo comprobamos que el inventario y el
modelo comun funcionan. En los pasos siguientes aqui se orquesta todo el flujo:
inventario -> collectors -> parsers -> modelo -> analisis -> reporte."""
import json
from dataclasses import asdict

from src.inventory import load_inventory
from src.models import DeviceState, Interface, validate_state


def main():
    # 1) Cargar y validar el inventario
    inv = load_inventory("config.yaml")
    print(f"Dispositivos autorizados: {len(inv.devices)}")
    for d in inv.devices:
        print(f"  - {d['hostname']:4} | {d['platform']:14} | via {d['transport']}")

    # 2) Probar el modelo comun creando un estado de ejemplo "a mano".
    #    (Mas adelante lo creara un parser a partir de la salida real del equipo.)
    demo = DeviceState(
        hostname="SW1",
        platform="cisco_ios",
        interfaces=[Interface(name="GigabitEthernet0/1", admin_status="up",
                              oper_status="up", speed_mbps=1000,
                              in_bps=940_000_000, out_bps=310_000_000)],
    )
    print("\nUtilizacion de ejemplo:", demo.interfaces[0].utilization_pct, "%")
    print("Problemas de validacion:", validate_state(demo) or "ninguno")

    # 3) Mostrar el estado como JSON (asi se guardara cada corrida)
    print("\nJSON del estado:")
    print(json.dumps(asdict(demo), indent=2, ensure_ascii=False)[:400], "...")


if __name__ == "__main__":
    main()
