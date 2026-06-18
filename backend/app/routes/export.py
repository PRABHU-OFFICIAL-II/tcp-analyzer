import csv
import io
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse

router = APIRouter()


def _get_report(body: dict) -> dict:
    """Validate the posted report body."""
    if not body or "filename" not in body:
        raise HTTPException(status_code=400, detail="Invalid report payload.")
    return body


@router.post("/export/json")
def export_json(body: dict):
    report = _get_report(body)
    aid = report.get("analysis_id", "report")[:8]
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="report_{aid}.json"'},
    )


@router.post("/export/csv")
def export_csv(body: dict):
    report = _get_report(body)
    aid = report.get("analysis_id", "report")[:8]

    buf = io.StringIO()
    w = csv.writer(buf)

    def write_section(title, rows, headers):
        w.writerow([])
        w.writerow([f"=== {title} ==="])
        w.writerow(headers)
        for row in rows:
            w.writerow(row)

    w.writerow(["TCP Analyzer Report"])
    w.writerow(["File", report.get("filename")])
    w.writerow(["Total Packets", report.get("total_packets")])
    w.writerow(["Duration (s)", report.get("capture_duration_sec")])

    write_section("Diagnoses", [
        [d["severity"].upper(), d["headline"], "; ".join(d.get("details", []))]
        for d in report.get("diagnoses", [])
    ], ["Severity", "Headline", "Details"])

    write_section("Retransmissions",
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"),
          e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("retransmission_events", [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Packet #", "Detail"])

    write_section("Zero Window Events",
        [[e["src_ip"], e["dst_ip"], e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("zero_window_events", [])],
        ["Src IP", "Dst IP", "Packet #", "Detail"])

    write_section("Security Findings",
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"),
          e["severity"], e["detail"]]
         for section in ["port_scan_sources", "cleartext_credentials",
                          "protocol_port_mismatches", "exfiltration_indicators",
                          "scanner_signatures"]
         for e in report.get("security", {}).get(section, [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Severity", "Detail"])

    write_section("Top Flows",
        [[f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"],
          f["packets"], f["bytes"], f["duration_sec"]]
         for f in (report.get("flow") or {}).get("flows", [])[:50]],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Packets", "Bytes", "Duration (s)"])

    write_section("Beaconing Flows",
        [[b["src_ip"], b["dst_ip"], b["dst_port"], b["connection_count"],
          b["avg_interval_sec"], b["cv"]]
         for b in (report.get("beacons") or {}).get("beacons", [])],
        ["Src IP", "Dst IP", "Dst Port", "Connections", "Avg Interval (s)", "CV"])

    write_section("HTTP Objects",
        [[o["method"], o["host"], o["path"], o.get("status_code", ""),
          o.get("content_type", ""), o.get("request_size", 0), o.get("response_size", 0)]
         for o in (report.get("http_objects") or {}).get("objects", [])[:200]],
        ["Method", "Host", "Path", "Status", "Content-Type", "Req Bytes", "Resp Bytes"])

    write_section("DNS Records",
        [[r["query"], r["query_type"], "; ".join(r.get("responses", [])),
          r.get("latency_ms", ""), r.get("rcode", 0)]
         for r in (report.get("dns_map") or {}).get("records", [])[:500]],
        ["Domain", "Type", "Responses", "Latency (ms)", "RCode"])

    write_section("MAC Map",
        [[e["mac"], e.get("manufacturer", ""), e.get("hostname", ""),
          e.get("hostname_source", ""), ", ".join(e.get("ips", [])), e.get("packet_count", 0)]
         for e in (report.get("mac_map") or {}).get("entries", [])],
        ["MAC", "Manufacturer", "Hostname", "Source", "IPs", "Packets"])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report_{aid}.csv"'},
    )


@router.post("/export/html")
def export_html(body: dict):
    report = _get_report(body)
    aid = report.get("analysis_id", "report")[:8]

    SEVERITY_COLOR = {
        "critical": "#ef4444", "warning": "#f59e0b",
        "info": "#3b82f6",     "clean": "#22c55e",
    }

    def badge(sev):
        color = SEVERITY_COLOR.get(sev, "#94a3b8")
        return (f'<span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-size:0.75rem;font-weight:700;'
                f'text-transform:uppercase">{sev}</span>')

    def fmt_bytes(b):
        b = int(b or 0)
        if b >= 1_000_000: return f"{b/1_000_000:.2f} MB"
        if b >= 1_000:     return f"{b/1_000:.1f} KB"
        return f"{b} B"

    diag_rows = "".join(
        f"<tr><td>{badge(d['severity'])}</td>"
        f"<td><strong>{d['headline']}</strong><br>"
        f"<small style='color:#64748b'>{' | '.join(d.get('details', []))}</small></td></tr>\n"
        for d in report.get("diagnoses", [])
    )

    sec_rows = "".join(
        f"<tr><td style='font-family:monospace'>{e['src_ip']}</td>"
        f"<td style='font-family:monospace'>{e['dst_ip']}</td>"
        f"<td>{badge(e['severity'])}</td><td>{e['detail']}</td></tr>\n"
        for section in ["port_scan_sources", "cleartext_credentials",
                         "protocol_port_mismatches", "exfiltration_indicators",
                         "scanner_signatures"]
        for e in report.get("security", {}).get(section, [])
    )

    flow_rows = "".join(
        f"<tr><td style='font-family:monospace'>{f['src_ip']}:{f['src_port']}</td>"
        f"<td style='font-family:monospace'>{f['dst_ip']}:{f['dst_port']}</td>"
        f"<td>{f['protocol']}</td><td>{f['packets']}</td>"
        f"<td>{fmt_bytes(f['bytes'])}</td><td>{f['duration_sec']}s</td></tr>\n"
        for f in (report.get("flow") or {}).get("flows", [])[:50]
    )

    http_rows = "".join(
        f"<tr><td><strong>{o['method']}</strong></td>"
        f"<td style='font-family:monospace'>{o['host']}</td>"
        f"<td style='font-family:monospace'>{o['path']}</td>"
        f"<td style='color:{'#ef4444' if (o.get('status_code','') or '').startswith(('4','5')) else '#22c55e' if (o.get('status_code','') or '').startswith('2') else '#94a3b8'};font-weight:700'>"
        f"{o.get('status_code','—')}</td>"
        f"<td>{fmt_bytes(o.get('response_size',0))}</td></tr>\n"
        for o in (report.get("http_objects") or {}).get("objects", [])[:100]
    )

    dns_rows = "".join(
        f"<tr><td style='font-family:monospace'>{r['query']}</td>"
        f"<td>{r['query_type']}</td>"
        f"<td style='font-family:monospace'>{', '.join(r.get('responses',[])[:3])}</td>"
        f"<td style='color:{'#ef4444' if r.get('rcode',0) in (2,3) else '#22c55e'}'>{r.get('rcode',0)}</td>"
        f"<td>{r.get('latency_ms','—')} ms</td></tr>\n"
        for r in (report.get("dns_map") or {}).get("records", [])[:100]
    )

    mac_rows = "".join(
        f"<tr><td style='font-family:monospace'>{e['mac']}</td>"
        f"<td>{e.get('manufacturer','Unknown')}</td>"
        f"<td><strong>{e.get('hostname') or '—'}</strong>"
        f"{'<small style=color:#64748b> (' + e.get('hostname_source','') + ')</small>' if e.get('hostname_source') else ''}</td>"
        f"<td style='font-family:monospace'>{', '.join(e.get('ips',[]))}</td></tr>\n"
        for e in (report.get("mac_map") or {}).get("entries", [])
    )

    proxy = report.get("proxy") or {}
    proxy_verdict = proxy.get("verdict", "No proxy indicators detected")
    proxy_sev = proxy.get("verdict_severity", "clean")
    proxy_color = "#ef4444" if proxy_sev == "warning" else "#f59e0b" if proxy_sev == "info" else "#22c55e"

    perf  = report.get("performance", {})
    proto = report.get("protocol", {})

    no_rows = lambda n: f"<tr><td colspan='{n}' style='color:#94a3b8;font-style:italic'>None detected</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCP Analyzer Report — {report.get('filename','')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        background:#f0f4f8;color:#1e293b;line-height:1.6;padding:2rem}}
  h1{{font-size:2rem;font-weight:900;color:#0f172a;margin-bottom:0.25rem}}
  h2{{font-size:0.85rem;font-weight:700;color:#475569;margin:2rem 0 0.75rem;
      text-transform:uppercase;letter-spacing:0.07em}}
  .meta{{color:#64748b;font-size:0.875rem;margin-bottom:2rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
          gap:0.75rem;margin-bottom:2rem}}
  .stat{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:0.9rem 1rem;
         box-shadow:0 1px 3px rgba(0,0,0,0.05)}}
  .stat .val{{font-size:1.6rem;font-weight:700}}
  .stat .lbl{{font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.06em}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem;margin-bottom:1.5rem}}
  th{{text-align:left;padding:0.5rem 0.75rem;color:#64748b;font-weight:600;
      background:#f8fafc;border-bottom:2px solid #e2e8f0}}
  td{{padding:0.45rem 0.75rem;border-bottom:1px solid #f1f5f9;color:#475569}}
  td:first-child{{color:#1e293b}}
  .card{{background:#fff;border:1px solid #e2e8f0;border-radius:12px;
          padding:1.25rem;margin-bottom:1.5rem;box-shadow:0 1px 4px rgba(0,0,0,0.05)}}
  .verdict{{display:inline-block;padding:0.5rem 1rem;border-radius:8px;
             font-weight:700;font-size:0.9rem;margin-bottom:1rem}}
  footer{{text-align:center;color:#94a3b8;font-size:0.8rem;margin-top:3rem;
          padding-top:1rem;border-top:1px solid #e2e8f0}}
</style>
</head>
<body>
<h1>TCP Analyzer Report</h1>
<p class="meta">
  {report.get('filename','')} &nbsp;·&nbsp;
  {report.get('total_packets',0):,} packets &nbsp;·&nbsp;
  {report.get('capture_duration_sec',0):.2f}s capture &nbsp;·&nbsp;
  {len(report.get('unique_ips',[]))} unique IPs &nbsp;·&nbsp;
  ID: {report.get('analysis_id','')[:8]}
</p>

<div class="stats">
  <div class="stat">
    <div class="lbl">Retransmit Rate</div>
    <div class="val" style="color:{'#ef4444' if (perf.get('retransmission_rate_pct',0) or 0)>2 else '#22c55e'}">
      {perf.get('retransmission_rate_pct',0):.2f}%</div></div>
  <div class="stat">
    <div class="lbl">Avg Handshake</div>
    <div class="val" style="color:#2563eb">{perf.get('avg_handshake_ms') or '—'} ms</div></div>
  <div class="stat">
    <div class="lbl">Reset Rate</div>
    <div class="val" style="color:{'#ef4444' if (proto.get('reset_rate_pct',0) or 0)>5 else '#22c55e'}">
      {proto.get('reset_rate_pct',0):.2f}%</div></div>
  <div class="stat">
    <div class="lbl">HTTP Error Rate</div>
    <div class="val" style="color:{'#d97706' if (proto.get('http_error_rate_pct',0) or 0)>10 else '#22c55e'}">
      {proto.get('http_error_rate_pct',0):.2f}%</div></div>
</div>

<h2>Diagnoses</h2>
<div class="card">
<table><thead><tr><th>Severity</th><th>Finding</th></tr></thead>
<tbody>{diag_rows or no_rows(2)}</tbody></table>
</div>

<h2>Security Findings</h2>
<div class="card">
<table><thead><tr><th>Src IP</th><th>Dst IP</th><th>Severity</th><th>Detail</th></tr></thead>
<tbody>{sec_rows or no_rows(4)}</tbody></table>
</div>

<h2>Proxy Detection</h2>
<div class="card">
<div class="verdict" style="background:{'#fef2f2' if proxy_sev=='warning' else '#f0fdf4'};color:{proxy_color};border:1px solid {'#fecaca' if proxy_sev=='warning' else '#bbf7d0'}">
  {proxy_verdict}</div>
</div>

<h2>Top Flows</h2>
<div class="card">
<table><thead><tr><th>Source</th><th>Destination</th><th>Proto</th>
<th>Packets</th><th>Bytes</th><th>Duration</th></tr></thead>
<tbody>{flow_rows or no_rows(6)}</tbody></table>
</div>

<h2>HTTP Objects</h2>
<div class="card">
<table><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Size</th></tr></thead>
<tbody>{http_rows or no_rows(5)}</tbody></table>
</div>

<h2>DNS Records</h2>
<div class="card">
<table><thead><tr><th>Domain</th><th>Type</th><th>Answers</th><th>RCode</th><th>Latency</th></tr></thead>
<tbody>{dns_rows or no_rows(5)}</tbody></table>
</div>

<h2>MAC Address Map</h2>
<div class="card">
<table><thead><tr><th>MAC</th><th>Manufacturer</th><th>Hostname</th><th>IPs</th></tr></thead>
<tbody>{mac_rows or no_rows(4)}</tbody></table>
</div>

<footer>Generated by TCP Analyzer v3.0 &nbsp;·&nbsp; {report.get('filename','')}</footer>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="report_{aid}.html"'},
    )


@router.post("/export/pdf")
def export_pdf(body: dict):
    report = _get_report(body)
    aid = report.get("analysis_id", "report")[:8]

    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed. Run: pip install fpdf2")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    SEVERITY_COLOR = {
        "critical": (239, 68, 68), "warning": (245, 158, 11),
        "info": (59, 130, 246),    "clean": (34, 197, 94),
    }

    def _safe(text):
        if not isinstance(text, str):
            text = str(text)
        return (text
            .replace("—", "-").replace("–", "-")
            .replace("‘", "'").replace("’", "'")
            .replace("“", '"').replace("”", '"')
            .replace("•", "*").replace("…", "...")
            .encode("latin-1", errors="replace").decode("latin-1"))

    def heading(text, size=14):
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, _safe(text), ln=True)
        pdf.ln(1)

    def section_line():
        pdf.set_draw_color(220, 220, 220)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

    # Cover
    pdf.add_page()
    pdf.set_fill_color(37, 99, 235)
    pdf.rect(0, 0, 210, 70, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_y(20)
    pdf.cell(0, 12, "TCP Analyzer Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, report.get("filename", ""), align="C", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(200, 220, 255)
    pdf.cell(0, 6, f"Analysis ID: {report.get('analysis_id', '')}", align="C", ln=True)
    pdf.ln(22)

    pdf.set_text_color(30, 30, 30)
    heading("Summary", 12)
    section_line()
    perf  = report.get("performance", {})
    proto = report.get("protocol", {})
    for label, value in [
        ("Total Packets",         f"{report.get('total_packets', 0):,}"),
        ("Capture Duration",      f"{report.get('capture_duration_sec', 0):.2f} s"),
        ("Unique IPs",            str(len(report.get("unique_ips", [])))),
        ("Retransmission Rate",   f"{perf.get('retransmission_rate_pct', 0):.2f}%"),
        ("Avg Handshake",         f"{perf.get('avg_handshake_ms') or '—'} ms"),
        ("P95 Handshake",         f"{perf.get('p95_handshake_ms') or '—'} ms"),
        ("HTTP Error Rate",       f"{proto.get('http_error_rate_pct', 0):.2f}%"),
        ("Connection Reset Rate", f"{proto.get('reset_rate_pct', 0):.2f}%"),
        ("Proxy Detection",       (report.get("proxy") or {}).get("verdict", "—")),
    ]:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(80, 7, label + ":")
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, _safe(value), ln=True)

    # Diagnoses
    pdf.add_page()
    heading("Diagnoses", 14)
    section_line()
    for d in report.get("diagnoses", []):
        sev   = d.get("severity", "info")
        color = SEVERITY_COLOR.get(sev, (100, 100, 100))
        pdf.set_fill_color(*color)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(22, 6, f"  {sev.upper()}", fill=True)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, _safe(f"  {d.get('headline', '')}"), ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        for detail in d.get("details", []):
            pdf.cell(22)
            pdf.multi_cell(0, 5, _safe(f"* {detail}"))
        pdf.ln(2)

    # Security
    all_sec = [
        e for section in ["port_scan_sources", "cleartext_credentials",
                           "protocol_port_mismatches", "exfiltration_indicators",
                           "scanner_signatures"]
        for e in report.get("security", {}).get(section, [])
    ]
    if all_sec:
        pdf.add_page()
        heading("Security Findings", 14)
        section_line()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(230, 230, 230)
        for col, w in [("Src IP", 35), ("Dst IP", 35), ("Severity", 20), ("Detail", 0)]:
            pdf.cell(w if w else 200 - 90, 6, col, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for e in all_sec[:100]:
            sev = e.get("severity", "info")
            c   = SEVERITY_COLOR.get(sev, (100, 100, 100))
            pdf.set_text_color(50, 50, 50)
            pdf.cell(35, 5, e.get("src_ip", ""))
            pdf.cell(35, 5, e.get("dst_ip", ""))
            pdf.set_text_color(*c)
            pdf.cell(20, 5, sev.upper())
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 5, _safe(e.get("detail", ""))[:120])

    # Top flows
    flows = (report.get("flow") or {}).get("flows", [])[:30]
    if flows:
        pdf.add_page()
        heading("Top Flows", 14)
        section_line()
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(230, 230, 230)
        for col, w in [("Src IP:Port", 40), ("Dst IP:Port", 40), ("Proto", 16),
                       ("Pkts", 16), ("Bytes", 24), ("Dur(s)", 20)]:
            pdf.cell(w, 6, col, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        def _fmt(b):
            b = int(b or 0)
            if b >= 1e6: return f"{b/1e6:.1f}MB"
            if b >= 1e3: return f"{b/1e3:.0f}KB"
            return str(b)
        for f in flows:
            pdf.set_text_color(50, 50, 50)
            for val, w in [
                (f"{f['src_ip']}:{f['src_port']}", 40),
                (f"{f['dst_ip']}:{f['dst_port']}", 40),
                (f["protocol"], 16), (str(f["packets"]), 16),
                (_fmt(f["bytes"]), 24), (str(f["duration_sec"]), 20),
            ]:
                pdf.cell(w, 5, val)
            pdf.ln()

    buf = io.BytesIO(pdf.output())
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{aid}.pdf"'},
    )
