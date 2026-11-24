# Cambios respecto a la versión revisada

## Corregido
- **Demo HTML:** enlaces MITRE de subtécnicas (`T1110/001`, antes `T1110%2F001`); gráfico con eje temporal real, ejes y tooltips; filas de alertas accesibles con teclado; `aria-current`; estilos Media/Baja; filtros solo con valores existentes; reglas y versión leídas de `catalog.py`/`__version__`; favicon y metadatos; sin redirección (`index.html` es la demo).
- **Fechas:** `dd/mm/aaaa` ya no se confunde con `mm/dd`; soporte de epoch; selector `dayfirst` (app y CLI); aviso en fechas ambiguas.
- **Rendimiento:** detección de ~58 s a ~1 s con 100.000 eventos; análisis cacheado en Streamlit.
- **Seguridad:** descripciones de alertas con datos del log ya no se interpretan como Markdown (`st.text`).
- **Streamlit:** `use_container_width` → `width="stretch"`; mínimo `streamlit>=1.67` (requiere Python ≥ 3.11); sin `headless`.
- **Detección:** AUTH-004 es Crítica solo si los fallos alcanzan el umbral por cuenta (si no, Media); AUTH-003 con máximo configurable de intentos por cuenta; alertas multi-cuenta con `username` vacío y columna `accounts`.
- **SSH:** `Accepted keyboard-interactive/pam`, `Failed publickey`, timestamps ISO, salto dic→ene, año por defecto = actual; las líneas ajenas a sshd se cuentan aparte y con su motivo.
- **Informes:** JSON con `config`, hash/formato/descartes del input y versión real; HTML con color por severidad y configuración; CSV protegido también frente a tabuladores.
- **Repo:** CI con ruff y comprobación de que `index.html` está actualizado; autoría y licencia; `pyproject` con versión única y script `sentinelai`; capturas nuevas; documentación actualizada; 42 tests (antes 21).
