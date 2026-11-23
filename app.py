"""SentinelAI SOC workbench · Streamlit UI (no external services)."""

from __future__ import annotations

from html import escape
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from sentinelai import __version__
from sentinelai.catalog import RULES, technique_url
from sentinelai.detection import DetectionConfig, detect
from sentinelai.ml import detect_anomalies
from sentinelai.parsers import ParseError, parse_bytes
from sentinelai.reporting import to_csv, to_html, to_json

ROOT = Path(__file__).resolve().parent
COLORS = {"Crítica": "#ff6482", "Alta": "#ffae68", "Media": "#ffd777", "Baja": "#56b7ec"}
GREEN, MUTED, PANEL = "#48e6b9", "#94a8bf", "#142138"

st.set_page_config(page_title="SentinelAI | Security Analytics", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>

html, body, [class*="css"], [data-testid="stAppViewContainer"] {font-family:ui-sans-serif, system-ui, sans-serif;}
.block-container {padding-top:2rem;padding-bottom:4rem;max-width:1540px;}
[data-testid="stSidebar"] {background: #0d1728;border-right:1px solid #24364d;}
[data-testid="stSidebar"] .block-container {padding-top:1.4rem;}
[data-testid="stMetric"] {background:linear-gradient(145deg,#142239,#0e1b2c);border:1px solid #243751;border-radius:15px;padding:17px 19px;min-height:108px;}
[data-testid="stMetricLabel"] {color:#94a8bf;}
[data-testid="stMetricValue"] {color:#eaf4ff;font-family:ui-sans-serif, system-ui, sans-serif;}
section[data-testid="stFileUploader"] {border:1px dashed #30465c;border-radius:12px;padding:4px;}
div[data-testid="stAlert"] {border-radius:12px;}
hr {border-color:#22334c;}
a {color:#4ee4be !important;}
h1,h2,h3 {font-family:ui-sans-serif, system-ui, sans-serif;letter-spacing:-.03em;}
[data-testid="stDataFrame"] {border:1px solid #24344a;border-radius:12px;overflow:hidden;}
.stButton button[kind="primary"], [data-testid="stDownloadButton"] button[kind="primary"] {border-radius:11px;font-weight:700;}
.section-head {font-size:11px;letter-spacing:.18em;color:#4de5ba;font-weight:800;text-transform:uppercase;margin:18px 0 8px;}
.hero {border:1px solid #263e56;background:radial-gradient(ellipse at 100% -10%,rgba(62,231,182,.17),transparent 47%),linear-gradient(120deg,#13263b,#101a2d 75%);border-radius:22px;padding:27px 32px 24px;margin-bottom:22px;}
.hero h1 {font-size:45px;line-height:1.07;margin:3px 0 13px;color:#edf8ff;}
.hero p {max-width:850px;color:#a5b8cb;font-size:15px;margin:0 0 14px;line-height:1.6;}
.eyebrow {font-size:11px;font-weight:800;letter-spacing:.2em;color:#4be7bd;}
.chip {display:inline-block;background:#183b43;color:#8bf7d8;border:1px solid #2f685d;border-radius:40px;padding:4px 11px;margin:4px 6px 0 0;font-size:11px;font-weight:700;}
.chip.alt {background:#1b2940;color:#adc3e3;border-color:#344960;}
.note {font-size:13px;color:#94a9c1;margin:4px 0 14px;}
.finding {background:#131f32;border:1px solid #2b3d54;border-radius:12px;padding:14px 18px;margin:10px 0;}
.finding .sub {color:#90a6c2;font-size:12px;margin-top:5px;}
.brand {font-family:ui-sans-serif, system-ui, sans-serif;font-size:25px;font-weight:800;letter-spacing:-.04em;color:#e5f8f4;margin:5px 0 3px;}
.brand span {color:#45e6b8;}
.brand-sub {font-size:11px;color:#7c94b4;letter-spacing:.13em;text-transform:uppercase;padding-bottom:15px;}
.footer {font-size:12px;color:#849cb8;border-top:1px solid #263951;margin-top:35px;padding-top:16px;}
</style>""", unsafe_allow_html=True)


def hero() -> None:
    st.markdown(f"""
    <div class="hero"><div class="eyebrow">SECURITY OPERATIONS · EXPLAINABLE DETECTION · v{__version__}</div>
    <h1>See the signal.<br><span style="color:#48e6b9">Investigate the threat.</span></h1>
    <p>Laboratorio de detección de amenazas de autenticación. Correlaciona evidencias, investiga alertas y exporta informes SOC reproducibles. Sin cuentas, sin APIs externas y sin enviar logs a servicios remotos.</p>
    <span class="chip">◆ REGLAS EXPLICABLES</span><span class="chip alt">MITRE ATT&amp;CK</span><span class="chip alt">ML EXPERIMENTAL</span><span class="chip alt">100% LOCAL</span></div>
    """, unsafe_allow_html=True)


def heading(label: str, title: str, caption: str = "") -> None:
    st.markdown(f'<div class="section-head">{escape(label)}</div>', unsafe_allow_html=True)
    st.subheader(title)
    if caption:
        st.markdown(f'<p class="note">{escape(caption)}</p>', unsafe_allow_html=True)


def chart_layout(fig: go.Figure, height: int = 320) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=12, r=14, t=16, b=15),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#abc0d7", family="DM Sans, sans-serif", size=12),
        hoverlabel=dict(bgcolor="#15243b", font_color="white"),
        legend=dict(orientation="h", y=1.14, x=0),
    )
    fig.update_xaxes(gridcolor="#233750", linecolor="#233750", zeroline=False)
    fig.update_yaxes(gridcolor="#233750", linecolor="#233750", zeroline=False)
    return fig


with st.sidebar:
    st.markdown('<div class="brand">⬡ Sentinel<span>AI</span></div><div class="brand-sub">SOC ANALYST WORKSPACE</div>', unsafe_allow_html=True)
    page = st.radio("ESPACIO DE TRABAJO", ["Visión general", "Centro de alertas", "Explorador de eventos", "Detección con ML", "Reglas y metodología"], label_visibility="collapsed")
    st.divider()
    st.markdown("**FUENTE DE DATOS**")
    source_choice = st.radio("Datos de entrada", ["Demo sintética", "Subir mis logs"], horizontal=True, label_visibility="collapsed")
    fmt = "csv"
    upload = None
    ssh_year = 2026
    if source_choice == "Demo sintética":
        raw = (ROOT / "data" / "demo_auth.csv").read_bytes()
        st.caption("732 eventos reproducibles · escenarios benignos y sospechosos · 20–22 nov 2026")
    else:
        upload = st.file_uploader("CSV, JSONL o auth.log", type=["csv", "jsonl", "log", "txt"], help="Máximo 10 MB; procesa en la sesión local del servidor Streamlit")
        fmt = st.selectbox("Formato del archivo", ["csv", "jsonl", "ssh"], format_func=lambda v: {"csv":"CSV · Tabla", "jsonl":"JSONL · Una línea por evento", "ssh":"SSH · auth.log"}[v])
        if fmt == "ssh":
            ssh_year = st.number_input("Año para syslog sin año", min_value=2000, max_value=2100, value=2026)
        raw = upload.getvalue() if upload else None
        st.caption("No subas registros privados a una instancia pública de la app. Usa ejecución local para datos sensibles.")
    st.divider()
    with st.expander("⚙️ Parámetros del detector", expanded=False):
        window = st.slider("Ventana de correlación (min)", 3, 60, 10)
        failure_ip = st.slider("Fallos por IP", 3, 30, 8)
        failure_account = st.slider("Fallos por cuenta", 3, 20, 5)
        spray = st.slider("Cuentas objetivo (spray)", 3, 15, 6)
        after_failures = st.slider("Fallos antes de éxito", 2, 10, 3)
        offhours = st.checkbox("Analizar accesos nocturnos", value=False, help="Indicador contextual de baja confianza, desactivado por defecto")
        tz = st.selectbox("Zona horaria de la regla nocturna", ["Europe/Madrid", "UTC", "America/New_York", "America/Mexico_City"])
    st.divider()
    st.caption("SentinelAI v1.0 · Laboratorio defensivo · No sustituye a un SIEM ni prueba compromisos")

if raw is None:
    hero()
    st.info("Carga un archivo de autenticación para empezar, o activa **Demo sintética** en el menú lateral.")
    st.code("timestamp,source_ip,username,outcome,service,country\n2026-11-20T09:30:00Z,203.0.113.21,admin,failure,ssh,Unknown", language="csv")
    st.stop()

try:
    parsed = parse_bytes(raw, fmt, ssh_year=int(ssh_year))
    cfg = DetectionConfig(
        window_minutes=window, failed_ip_threshold=failure_ip,
        failed_account_threshold=failure_account, spraying_users_threshold=spray,
        success_after_failures=after_failures, detect_offhours=offhours, timezone=tz,
    )
    events = parsed.events
    alerts = detect(events, cfg)
except (ParseError, ValueError, UnicodeError) as exc:
    st.error(f"No se pudo procesar el archivo: {exc}")
    st.stop()

if parsed.dropped_rows:
    st.warning(f"Se han descartado {parsed.dropped_rows} de {parsed.total_rows} líneas o eventos no compatibles o inválidos. Comprueba el formato y los campos.")

if page == "Visión general":
    hero()
    total = len(events)
    failed = int(events["outcome"].eq("failure").sum())
    critical = int(alerts["severity"].eq("Crítica").sum()) if len(alerts) else 0
    cols = st.columns(4, gap="medium")
    for col, label, value, help_text in [
        (cols[0], "Eventos analizados", f"{total:,}", "Número de autenticaciones válidas"),
        (cols[1], "Fallos de acceso", f"{failed:,}", f"{failed/total:.1%} de los eventos"),
        (cols[2], "Alertas correlacionadas", str(len(alerts)), "Las reglas pueden solaparse"),
        (cols[3], "Alertas críticas", str(critical), "Alta prioridad de investigación, no compromiso confirmado"),
    ]:
        col.metric(label, value, help=help_text)
    st.write("")
    left, right = st.columns([1.75, 1], gap="large")
    with left:
        heading("ACTIVIDAD", "Autenticaciones a lo largo del tiempo")
        freq = "1h" if (events["timestamp"].max() - events["timestamp"].min()).total_seconds() > 86400 else "15min"
        timeline = events.assign(bucket=events["timestamp"].dt.floor(freq)).groupby(["bucket", "outcome"]).size().unstack(fill_value=0)
        fig = go.Figure()
        for outcome, color, name in [("success", GREEN, "Acceso correcto"), ("failure", "#ff829c", "Acceso fallido")]:
            if outcome in timeline:
                fig.add_trace(go.Scatter(x=timeline.index, y=timeline[outcome], mode="lines", name=name, line=dict(color=color, width=2.3), fill="tozeroy" if outcome == "success" else None, fillcolor="rgba(72,230,185,.07)"))
        fig.update_yaxes(title_text="Eventos")
        st.plotly_chart(chart_layout(fig), use_container_width=True, config={"displayModeBar": False})
    with right:
        heading("PRIORIZACIÓN", "Alertas por severidad")
        counts = alerts["severity"].value_counts() if len(alerts) else pd.Series(dtype=int)
        labels = [x for x in ["Crítica", "Alta", "Media", "Baja"] if counts.get(x, 0)]
        if labels:
            fig = go.Figure(go.Pie(labels=labels, values=[counts[x] for x in labels], hole=.67, marker_colors=[COLORS[x] for x in labels], textinfo="label+value", sort=False))
            fig.update_layout(showlegend=False, annotations=[dict(text=f"<b>{len(alerts)}</b><br>ALERTAS", x=.5, y=.5, showarrow=False, font=dict(size=14, color="#d5edf3"))])
            st.plotly_chart(chart_layout(fig), use_container_width=True, config={"displayModeBar": False})
        else:
            st.success("Ninguna regla ha disparado alertas con los datos actuales.")
    left, right = st.columns([1.15, 1.6], gap="large")
    with left:
        heading("PUNTOS DE ORIGEN", "IPs con más fallos")
        ip_stats = events[events["outcome"] == "failure"]["source_ip"].value_counts().head(7).sort_values()
        if len(ip_stats):
            fig = go.Figure(go.Bar(x=ip_stats.values, y=ip_stats.index.tolist(), orientation="h", marker_color="#50dcb8", text=ip_stats.values, textposition="outside"))
            fig.update_xaxes(title="Intentos fallidos")
            st.plotly_chart(chart_layout(fig, 285), use_container_width=True, config={"displayModeBar": False})
    with right:
        heading("TRIAJE PRIORITARIO", "Hallazgos recientes")
        if alerts.empty:
            st.info("No hay hallazgos pendientes en este conjunto de datos.")
        else:
            for a in alerts.head(5).to_dict("records"):
                st.markdown(f"""<div class="finding"><div><span style="color:{COLORS[a['severity']]};font-weight:800">● {escape(a['severity'].upper())}</span> &nbsp; <b>{escape(a['title'])}</b></div>
                <div class="sub">{escape(a['source_ip'])} · {escape(a['username'])} · {escape(a['rule_id'])} · {escape(a['timestamp'][:16].replace('T',' '))} UTC</div></div>""", unsafe_allow_html=True)
    st.info("**Cómo interpretar los resultados:** una alerta indica un patrón que merece revisión, no una intrusión confirmada. La demo contiene eventos sintéticos, incluidas anomalías introducidas deliberadamente.")

elif page == "Centro de alertas":
    heading("INVESTIGACIÓN", "Centro de alertas", "Filtra hallazgos, inspecciona la evidencia y exporta un informe reproducible.")
    c1, c2, c3 = st.columns([1.1, 1.2, 1.4])
    sev = c1.multiselect("Severidad", ["Crítica", "Alta", "Media", "Baja"], default=["Crítica", "Alta", "Media", "Baja"])
    rule_filter = c2.selectbox("Regla", ["Todas", *RULES.keys()])
    ip_filter = c3.text_input("IP o usuario", placeholder="Buscar origen o cuenta...").strip().lower()
    selected = alerts[alerts["severity"].isin(sev)].copy()
    if rule_filter != "Todas":
        selected = selected[selected["rule_id"] == rule_filter]
    if ip_filter:
        selected = selected[selected["source_ip"].str.lower().str.contains(ip_filter, regex=False) | selected["username"].str.lower().str.contains(ip_filter, regex=False)]
    st.caption(f"{len(selected)} de {len(alerts)} alertas visibles")
    show_cols = ["severity", "timestamp", "title", "source_ip", "username", "rule_id", "mitre_id", "evidence_count"]
    st.dataframe(selected[show_cols].rename(columns={"severity":"Prioridad", "timestamp":"Fecha (UTC)", "title":"Hallazgo", "source_ip":"IP de origen", "username":"Cuenta", "rule_id":"Regla", "mitre_id":"MITRE", "evidence_count":"Evidencias"}), use_container_width=True, hide_index=True, height=270)
    if not selected.empty:
        options = selected["alert_id"].tolist()
        lookup = {a["alert_id"]: a for a in selected.to_dict("records")}
        active = st.selectbox("Abrir expediente de investigación", options, format_func=lambda x: f"{lookup[x]['severity']} · {lookup[x]['title']} · {lookup[x]['source_ip']} · {x}")
        a = lookup[active]
        st.markdown(f"### {a['title']}")
        a1, a2, a3 = st.columns(3)
        a1.metric("Prioridad", a["severity"])
        a2.metric("Score heurístico", f"{a['score']}/100", help="Puntuación orientativa fija por regla, no probabilidad de compromiso")
        a3.metric("Evidencias correlacionadas", a["evidence_count"])
        st.write(a["description"])
        st.markdown(f"**Clasificación:** [{a['mitre_id']} · {a['mitre_name']}]({technique_url(a['mitre_id'])})")
        st.markdown(f"**Siguiente paso recomendado:** {a['recommendation']}")
        st.markdown("**Eventos que sustentan la alerta**")
        supporting = events[events["event_id"].isin(a["evidence_ids"])][["timestamp", "source_ip", "username", "outcome", "service", "event_id"]].copy()
        supporting["timestamp"] = supporting["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        st.dataframe(supporting, use_container_width=True, hide_index=True)
        if a["evidence_count"] > 30:
            st.caption("Se muestra una muestra de hasta 30 IDs de evento asociados a esta alerta.")
    st.divider()
    heading("EXPORTACIÓN", "Informes descargables")
    e1, e2, e3 = st.columns(3)
    e1.download_button("⬇ Informe HTML", to_html(selected, events), file_name="sentinelai-informe.html", mime="text/html", use_container_width=True)
    e2.download_button("⬇ Alertas CSV", to_csv(selected), file_name="sentinelai-alertas.csv", mime="text/csv", use_container_width=True)
    e3.download_button("⬇ Informe JSON", to_json(selected, events), file_name="sentinelai-informe.json", mime="application/json", use_container_width=True)
    st.caption("Los informes exportados aplican los filtros visibles. Los informes no sustituyen un análisis forense ni el contraste con otras fuentes.")

elif page == "Explorador de eventos":
    heading("TELEMETRÍA", "Explorador de eventos", "Consulta los eventos normalizados y las cuentas, servicios y orígenes representados en el lote.")
    c1, c2, c3 = st.columns([1, 1, 1.4])
    outcome_filter = c1.multiselect("Resultado", ["success", "failure"], default=["success", "failure"])
    services = c2.multiselect("Servicio", sorted(events["service"].unique().tolist()), default=sorted(events["service"].unique().tolist()))
    search = c3.text_input("Filtrar por IP o cuenta", placeholder="Ej.: admin o 203.0.113...").strip().lower()
    filtered = events[events["outcome"].isin(outcome_filter) & events["service"].isin(services)].copy()
    if search:
        filtered = filtered[filtered["source_ip"].str.lower().str.contains(search, regex=False) | filtered["username"].str.lower().str.contains(search, regex=False)]
    st.caption(f"Mostrando {min(len(filtered), 5000):,} de {len(filtered):,} eventos filtrados. La tabla está limitada a 5.000 filas para facilitar la exploración.")
    present = filtered.head(5000)[["timestamp", "source_ip", "username", "outcome", "service", "country", "event_id"]].copy()
    present["timestamp"] = present["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    st.dataframe(present, use_container_width=True, hide_index=True, height=480)
    st.divider()
    heading("DICCIONARIO", "Esquema de autenticación")
    st.markdown("Las columnas mínimas son `timestamp`, `source_ip`, `username` y `outcome` (`success` o `failure`). Se admiten alias como `time`, `src_ip`, `user` y `status`. Las fechas sin zona horaria se interpretan como **UTC**.")
    st.code("timestamp,source_ip,username,outcome,service,country\n2026-11-20T09:30:00Z,203.0.113.21,admin,failure,ssh,Unknown", language="csv")

elif page == "Detección con ML":
    heading("EXPERIMENTAL · MACHINE LEARNING", "Anomalías con Isolation Forest", "Modelo no supervisado aplicado a agregados IP + ventanas de 15 minutos. Entrenado exclusivamente en el lote analizado.")
    st.warning("**Interpretación responsable:** anomalía estadística ≠ ataque. No hay etiquetas de verdad ni evaluación de precisión en producción. El modelo no emite alertas SOC y no utiliza datos externos.")
    ratio = st.slider("Porcentaje esperado de muestras atípicas", 1, 20, 5, help="Parámetro contamination de Isolation Forest", key="ml_ratio")
    with st.spinner("Calculando características y puntuaciones de anomalía..."):
        ml_results = detect_anomalies(events, contamination=ratio / 100)
    if ml_results.empty:
        st.info("Se necesitan al menos 20 combinaciones distintas de IP y ventanas de 15 minutos para entrenar el detector.")
    else:
        suspicious = ml_results[ml_results["is_anomaly"]]
        a, b, c = st.columns(3)
        a.metric("Ventanas analizadas", len(ml_results))
        b.metric("Ventanas atípicas", len(suspicious))
        c.metric("Modelo", "Isolation Forest")
        fig = go.Figure()
        for flag, color, label in [(False, "#4de2ba", "Comportamiento frecuente"), (True, "#ff8092", "Atípico")]:
            sample = ml_results[ml_results["is_anomaly"] == flag]
            fig.add_trace(go.Scatter(x=sample["events"], y=sample["unique_accounts"], mode="markers", name=label, marker=dict(color=color, size=9, opacity=.75), customdata=sample[["source_ip", "failures"]].to_numpy(), hovertemplate="Eventos: %{x}<br>Cuentas: %{y}<br>IP: %{customdata[0]}<br>Fallos: %{customdata[1]}<extra></extra>"))
        fig.update_xaxes(title="Eventos por IP / 15 min")
        fig.update_yaxes(title="Cuentas diferentes")
        st.plotly_chart(chart_layout(fig, 375), use_container_width=True, config={"displayModeBar": False})
        heading("PUNTUACIONES", "Ventanas que merecen una mirada")
        if suspicious.empty:
            st.info("No se han clasificado muestras atípicas.")
        else:
            table = suspicious.head(50).rename(columns={"source_ip":"IP", "bucket":"Hora (UTC)", "events":"Eventos", "failures":"Fallos", "unique_accounts":"Cuentas", "failure_ratio":"Tasa de fallos", "after_hours":"Eventos de madrugada (UTC)", "anomaly_score":"Score estadístico"})
            st.dataframe(table, use_container_width=True, hide_index=True)
        st.caption("El score procede de -decision_function() y no es un porcentaje de riesgo. Puede cambiar con otro lote de entrada o con la contaminación configurada.")

else:
    heading("CONOCIMIENTO", "Reglas y metodología", "Detecciones correlacionadas por ventana móvil y referencias públicas de MITRE ATT&CK.")
    for key, rule in RULES.items():
        with st.expander(f"{key} · {rule['title']} · {rule['severity']}", expanded=(key == "AUTH-001")):
            st.write(rule["description"])
            st.markdown(f"**ATT&CK (clasificación orientativa):** [{rule['technique']} · {rule['technique_name']}]({technique_url(rule['technique'])})")
            st.markdown("**Respuesta sugerida:** " + rule["recommendation"])
    st.divider()
    heading("ARQUITECTURA", "Cómo funciona SentinelAI")
    st.code("CSV / JSONL / SSH auth.log\n          │\n          ▼\n Parser + validación → Eventos UTC normalizados\n          │\n          ├─▶ Reglas correlacionadas → Alertas + MITRE → HTML / CSV / JSON\n          │\n          └─▶ Features IP/15m → Isolation Forest → Anomalías (experimento)", language="text")
    st.markdown("""**Limitaciones importantes:**
- Detección por lotes, no en tiempo real, sin persistencia, agentes ni respuesta automática.
- Los umbrales son heurísticos y deben calibrarse; fallos de autenticación pueden ser legítimos.
- Los registros SSH clásicos no contienen año ni zona horaria: se solicita el año y se asume UTC.
- La correlación no atribuye identidades ni confirma compromiso. La geolocalización no se consulta externamente.
- El entrenamiento ML se hace con el mismo lote de análisis; es una señal exploratoria, no un clasificador validado.""")

st.markdown('<div class="footer">SENTINELAI · EXPLAINABLE SECURITY LAB · Datos locales/sintéticos · Software educativo, no SIEM de producción.</div>', unsafe_allow_html=True)
