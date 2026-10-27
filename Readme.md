# Wolf-Industries | Desafío 03 – Auditoría programable de redes con Python

## Preparar
    python -m venv .venv
    .venv\Scripts\activate
    pip install pyyaml

## Ejecutar (siempre desde la carpeta raíz)
    python -m src.main                                  # auditoría demo + reportes + alerta
    python -m src.main --base escenarios/01_base.json --new escenarios/02_puertos_variados.json   # probar escenarios editables
    python -m src.main --probar-seguridad              # control de accesos y bloqueo
    python -m unittest discover -s tests -t . -v        # pruebas T1-T4 y 01-03

## Estado
- Paso 1: inventario + modelo común        (listo)
- Paso 2: collectors + parsers reales      (pendiente)
- Paso 3: reglas + comparador              (listo)
- Paso 4: reportes + alerta + pruebas      (listo)
- Paso 5: seguridad (accesos, sesiones, IP cifradas) (listo)
