"""Dashboard live (B16) - SOC Honeypot, Plotly Dash.

Interface professionnelle temps reel :
  - bandeau d'etat avec horodatage
  - cartes par service surveille (SSH / HTTP / FTP) : nom, port, volume, statut
  - KPIs (volume, IPs uniques, pays, integrite des logs)
  - carte geographique des sources d'attaque
  - repartition des profils attaquants (donut)
  - top credentials testes
  - flux des derniers evenements
Rafraichissement automatique -> projetable et lisible a 3 metres.
"""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, Input, Output, dcc, html

API = os.environ.get("HP_API_URL", "http://analyzer:8000")
REFRESH_MS = int(os.environ.get("HP_DASH_REFRESH_MS", "3000"))

# --- charte graphique -------------------------------------------------------
BG = "#0b0f17"
PANEL = "#121826"
PANEL_2 = "#161d2e"
BORDER = "#1f2937"
TEXT = "#e6edf3"
MUTED = "#8b96a8"
ACCENT = "#38bdf8"
FONT = "'Inter','Segoe UI',system-ui,sans-serif"

SERVICES = [
    {"key": "ssh", "name": "SSH", "port": 2222, "icon": "\U0001F510", "color": "#3b82f6"},
    {"key": "http", "name": "HTTP", "port": 8080, "icon": "\U0001F310", "color": "#22c55e"},
    {"key": "ftp", "name": "FTP", "port": 2121, "icon": "\U0001F4C1", "color": "#f59e0b"},
]

PROFILE_COLORS = {
    "bruteforcer": "#ef4444",
    "bot": "#f59e0b",
    "human": "#a855f7",
    "scanner_legitimate": "#22c55e",
    "unknown": "#64748b",
}

app = Dash(__name__, title="Honeypot - Live SOC Dashboard",
           external_stylesheets=[
               "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"])
server = app.server


def _get(path: str, default):
    try:
        return httpx.get(f"{API}{path}", timeout=4.0).json()
    except Exception:  # noqa: BLE001
        return default


def _panel(children, flex="1"):
    return html.Div(children=children, style={
        "background": PANEL, "border": f"1px solid {BORDER}", "borderRadius": "14px",
        "padding": "10px", "flex": flex, "margin": "8px",
        "boxShadow": "0 1px 3px rgba(0,0,0,.4)"})


def _fig_layout(fig, title):
    fig.update_layout(
        title={"text": title, "font": {"size": 16, "color": TEXT}},
        template="plotly_dark", paper_bgcolor=PANEL, plot_bgcolor=PANEL,
        font={"family": FONT, "color": TEXT},
        margin={"l": 30, "r": 20, "t": 50, "b": 30}, legend={"font": {"size": 11}})
    return fig


def _kpi(label, value, accent=ACCENT):
    return html.Div(style={"background": PANEL, "border": f"1px solid {BORDER}",
                           "borderRadius": "14px", "padding": "18px 20px", "flex": "1",
                           "margin": "8px", "minWidth": "180px"}, children=[
        html.Div(str(value), style={"fontSize": "32px", "fontWeight": "800", "color": accent}),
        html.Div(label, style={"fontSize": "12px", "color": MUTED, "marginTop": "4px",
                               "textTransform": "uppercase", "letterSpacing": ".5px"}),
    ])


def _service_card(svc, count):
    online = count > 0
    vol = f"{count:,}".replace(",", " ")
    return html.Div(style={"background": PANEL, "border": f"1px solid {BORDER}",
                           "borderLeft": f"4px solid {svc['color']}", "borderRadius": "12px",
                           "padding": "16px 18px", "flex": "1", "margin": "8px",
                           "minWidth": "200px", "display": "flex", "alignItems": "center",
                           "gap": "14px"}, children=[
        html.Div(svc["icon"], style={"fontSize": "26px"}),
        html.Div([
            html.Div([
                html.Span(svc["name"], style={"fontSize": "18px", "fontWeight": "700"}),
                html.Span(f":{svc['port']}", style={"fontSize": "12px", "color": MUTED,
                          "marginLeft": "6px"}),
            ]),
            html.Div(f"{vol} evenements", style={"fontSize": "13px", "color": MUTED}),
        ], style={"flex": "1"}),
        html.Span("\u25CF UP" if online else "\u25CB --",
                  style={"color": "#22c55e" if online else MUTED, "fontWeight": "700",
                         "fontSize": "12px"}),
    ])


def _events_table(events):
    cols = ["Heure", "Service", "Source IP", "Action", "Identifiants / Chemin", "Profil"]
    header = html.Tr([html.Th(h, style={"textAlign": "left", "padding": "8px 10px",
                      "color": MUTED, "fontSize": "12px", "borderBottom": f"1px solid {BORDER}",
                      "textTransform": "uppercase", "letterSpacing": ".5px"}) for h in cols])
    rows = []
    for e in events[:12]:
        ts = (e.get("ts") or "")[11:19]
        svc = (e.get("service") or "").upper()
        if e.get("username"):
            ident = f"{e.get('username')}:{e.get('password') or ''}"
        else:
            ident = e.get("http_path") or "-"
        prof = e.get("profile") or "-"
        pc = PROFILE_COLORS.get(prof, MUTED)
        rows.append(html.Tr([
            html.Td(ts, style={"padding": "7px 10px", "fontFamily": "monospace", "fontSize": "12px"}),
            html.Td(svc, style={"padding": "7px 10px", "fontWeight": "600"}),
            html.Td(e.get("src_ip") or "-", style={"padding": "7px 10px", "fontFamily": "monospace"}),
            html.Td(e.get("action") or "-", style={"padding": "7px 10px", "color": MUTED}),
            html.Td(str(ident)[:42], style={"padding": "7px 10px", "fontFamily": "monospace", "fontSize": "12px"}),
            html.Td(prof, style={"padding": "7px 10px", "color": pc, "fontWeight": "600"}),
        ], style={"borderBottom": f"1px solid {PANEL_2}"}))
    if not rows:
        rows = [html.Tr([html.Td("En attente d'evenements...", colSpan=6,
                style={"padding": "14px", "color": MUTED, "textAlign": "center"})])]
    return html.Table([html.Thead(header), html.Tbody(rows)],
                      style={"width": "100%", "borderCollapse": "collapse"})


app.layout = html.Div(style={"background": BG, "minHeight": "100vh", "fontFamily": FONT,
                             "padding": "20px 26px", "color": TEXT}, children=[
    html.Div(style={"display": "flex", "alignItems": "center",
                    "justifyContent": "space-between"}, children=[
        html.Div([
            html.Span("\U0001F36F", style={"fontSize": "30px", "marginRight": "12px"}),
            html.Span("Honeypot \u2014 Live SOC Dashboard",
                      style={"fontSize": "26px", "fontWeight": "800", "letterSpacing": "-.5px"}),
        ], style={"display": "flex", "alignItems": "center"}),
        html.Div([
            html.Span("\u25CF LIVE", style={"color": "#22c55e", "fontWeight": "700",
                                            "fontSize": "13px", "marginRight": "14px"}),
            html.Span(id="last-update", style={"color": MUTED, "fontSize": "13px"}),
        ]),
    ]),
    html.Div("Detection & analyse comportementale des attaques \u2014 M1SPRO",
             style={"color": MUTED, "fontSize": "13px", "margin": "4px 0 10px 2px"}),

    html.Div(id="kpi-row", style={"display": "flex", "flexWrap": "wrap"}),

    html.Div("Services surveilles", style={"color": MUTED, "fontSize": "12px",
             "textTransform": "uppercase", "letterSpacing": "1px", "margin": "14px 10px 2px"}),
    html.Div(id="services-row", style={"display": "flex", "flexWrap": "wrap"}),

    html.Div(style={"display": "flex", "flexWrap": "wrap"}, children=[
        _panel(dcc.Graph(id="map", style={"height": "330px"}, config={"displayModeBar": False}), flex="2"),
        _panel(dcc.Graph(id="profiles", style={"height": "330px"}, config={"displayModeBar": False}), flex="1"),
    ]),
    html.Div(style={"display": "flex", "flexWrap": "wrap"}, children=[
        _panel(dcc.Graph(id="services", style={"height": "330px"}, config={"displayModeBar": False}), flex="1"),
        _panel(dcc.Graph(id="creds", style={"height": "330px"}, config={"displayModeBar": False}), flex="1"),
    ]),
    html.Div(style={"display": "flex"}, children=[
        _panel([
            html.Div("Derniers evenements", style={"fontSize": "16px", "fontWeight": "600",
                     "margin": "6px 4px 10px"}),
            html.Div(id="events-table"),
        ]),
    ]),

    dcc.Interval(id="tick", interval=REFRESH_MS, n_intervals=0),
])


@app.callback(
    [Output("kpi-row", "children"), Output("services-row", "children"),
     Output("map", "figure"), Output("profiles", "figure"),
     Output("services", "figure"), Output("creds", "figure"),
     Output("events-table", "children"), Output("last-update", "children")],
    Input("tick", "n_intervals"),
)
def refresh(_n):
    stats = _get("/stats", {})
    attackers = _get("/attackers", [])
    events = _get("/events", [])

    integ = stats.get("integrity_failures", 0)
    total = f"{stats.get('total_events', 0):,}".replace(",", " ")
    kpis = [
        _kpi("Evenements captures", total),
        _kpi("IPs uniques", stats.get("unique_ips", 0)),
        _kpi("Pays sources", len(stats.get("by_country", {}))),
        _kpi("Logs corrompus", integ, accent="#22c55e" if integ == 0 else "#ef4444"),
    ]

    by_service = stats.get("by_service", {})
    service_cards = [_service_card(s, by_service.get(s["key"], 0)) for s in SERVICES]

    pts = [a for a in attackers if a.get("lat") is not None and a.get("lon") is not None]
    if pts:
        geomap = px.scatter_geo(
            lat=[a["lat"] for a in pts], lon=[a["lon"] for a in pts],
            size=[max(a.get("events", 1), 1) for a in pts],
            color=[a.get("profile") or "unknown" for a in pts],
            color_discrete_map=PROFILE_COLORS,
            hover_name=[a["src_ip"] for a in pts], projection="natural earth")
    else:
        geomap = go.Figure()
        geomap.add_annotation(text="Aucune source geolocalisee (trafic LAN / prive)",
                              showarrow=False, font={"color": MUTED})
    geomap.update_geos(bgcolor=PANEL, landcolor="#1e2636", showocean=True,
                       oceancolor="#0d1320", lakecolor="#0d1320", showcountries=True,
                       countrycolor="#2b3650")
    _fig_layout(geomap, "\U0001F30D Sources d'attaques")

    prof = stats.get("by_profile", {})
    if prof:
        pie = px.pie(names=list(prof.keys()), values=list(prof.values()), hole=0.55,
                     color=list(prof.keys()), color_discrete_map=PROFILE_COLORS)
        pie.update_traces(textinfo="percent+label", textfont_size=12)
    else:
        pie = go.Figure()
    _fig_layout(pie, "\U0001F3AF Profils attaquants")

    if by_service:
        order = sorted(by_service.items(), key=lambda x: x[1], reverse=True)
        names = [k.upper() for k, _ in order]
        vals = [v for _, v in order]
        colors = [next((s["color"] for s in SERVICES if s["key"] == k), ACCENT) for k, _ in order]
        bars = go.Figure(go.Bar(x=names, y=vals, marker_color=colors,
                                text=vals, textposition="outside"))
    else:
        bars = go.Figure()
    _fig_layout(bars, "\U0001F4CA Evenements par service")

    creds = stats.get("top_credentials", [])
    if creds:
        creds = creds[::-1]
        cbar = go.Figure(go.Bar(x=[c[1] for c in creds], y=[c[0] for c in creds],
                                orientation="h", marker_color="#ef4444"))
    else:
        cbar = go.Figure()
    _fig_layout(cbar, "\U0001F511 Top credentials testes")
    cbar.update_layout(yaxis={"tickfont": {"family": "monospace", "size": 11}})

    table = _events_table(events)
    stamp = "Mise a jour : " + datetime.now().strftime("%H:%M:%S")
    return kpis, service_cards, geomap, pie, bars, cbar, table, stamp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("HP_DASH_PORT", "8050")), debug=False)
