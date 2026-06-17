import csv
import io
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from .. import db

router = APIRouter()


@router.get("/export/{analysis_id}/json")
def export_json(analysis_id: str):
    report = db.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.json"'},
    )


@router.get("/export/{analysis_id}/csv")
def export_csv(analysis_id: str):
    report = db.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

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
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"), e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("retransmission_events", [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Packet #", "Detail"])

    write_section("Zero Window Events",
        [[e["src_ip"], e["dst_ip"], e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("zero_window_events", [])],
        ["Src IP", "Dst IP", "Packet #", "Detail"])

    write_section("Security Findings",
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"), e["severity"], e["detail"]]
         for section in ["port_scan_sources", "cleartext_credentials", "protocol_port_mismatches",
                         "exfiltration_indicators", "scanner_signatures"]
         for e in report.get("security", {}).get(section, [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Severity", "Detail"])

    write_section("Top Flows",
        [[f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"],
          f["packets"], f["bytes"], f["duration_sec"]]
         for f in (report.get("flow") or {}).get("flows", [])[:50]],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Packets", "Bytes", "Duration (s)"])

    write_section("Beaconing Flows",
        [[b["src_ip"], b["dst_ip"], b["dst_port"], b["connection_count"], b["avg_interval_sec"], b["cv"]]
         for b in (report.get("beacons") or {}).get("beacons", [])],
        ["Src IP", "Dst IP", "Dst Port", "Connections", "Avg Interval (s)", "CV"])

    write_section("HTTP Objects",
        [[o["method"], o["host"], o["path"], o.get("status_code", ""), o.get("content_type", ""),
          o.get("request_size", 0), o.get("response_size", 0)]
         for o in (report.get("http_objects") or {}).get("objects", [])[:200]],
        ["Method", "Host", "Path", "Status", "Content-Type", "Req Bytes", "Resp Bytes"])

    write_section("DNS Records",
        [[r["query"], r["query_type"], "; ".join(r.get("responses", [])),
          r.get("latency_ms", ""), r.get("rcode", 0)]
         for r in (report.get("dns_map") or {}).get("records", [])[:500]],
        ["Domain", "Type", "Responses", "Latency (ms)", "RCode"])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.csv"'},
    )


@router.get("/export/{analysis_id}/html")
def export_html(analysis_id: str):
    report = db.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

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
        if b >= 1_000_000:
            return f"{b/1_000_000:.2f} MB"
        if b >= 1_000:
            return f"{b/1_000:.1f} KB"
        return f"{b} B"

    diag_rows = ""
    for d in report.get("diagnoses", []):
        diag_rows += (
            f"<tr><td>{badge(d['severity'])}</td>"
            f"<td><strong>{d['headline']}</strong><br>"
            f"<small style='color:#94a3b8'>{' | '.join(d.get('details', []))}</small></td></tr>\n"
        )

    sec_rows = ""
    for section in ["port_scan_sources", "cleartext_credentials",
                    "protocol_port_mismatches", "exfiltration_indicators", "scanner_signatures"]:
        for e in report.get("security", {}).get(section, []):
            sec_rows += (
                f"<tr><td style='font-family:monospace'>{e['src_ip']}</td>"
                f"<td style='font-family:monospace'>{e['dst_ip']}</td>"
                f"<td>{badge(e['severity'])}</td>"
                f"<td>{e['detail']}</td></tr>\n"
            )

    flow_rows = ""
    for f in (report.get("flow") or {}).get("flows", [])[:50]:
        flow_rows += (
            f"<tr><td style='font-family:monospace'>{f['src_ip']}:{f['src_port']}</td>"
            f"<td style='font-family:monospace'>{f['dst_ip']}:{f['dst_port']}</td>"
            f"<td>{f['protocol']}</td><td>{f['packets']}</td>"
            f"<td>{fmt_bytes(f['bytes'])}</td><td>{f['duration_sec']}s</td></tr>\n"
        )

    http_rows = ""
    for o in (report.get("http_objects") or {}).get("objects", [])[:100]:
        status = o.get("status_code", "—")
        status_color = "#ef4444" if status and status.startswith(("4", "5")) else "#22c55e" if status and status.startswith("2") else "#94a3b8"
        http_rows += (
            f"<tr><td><strong>{o['method']}</strong></td>"
            f"<td style='font-family:monospace'>{o['host']}</td>"
            f"<td style='font-family:monospace;max-width:300px;overflow:hidden'>{o['path']}</td>"
            f"<td style='color:{status_color};font-weight:700'>{status}</td>"
            f"<td>{fmt_bytes(o.get('response_size',0))}</td></tr>\n"
        )

    dns_rows = ""
    for r in (report.get("dns_map") or {}).get("records", [])[:100]:
        rcode_color = "#ef4444" if r.get("rcode", 0) in (2, 3) else "#22c55e"
        dns_rows += (
            f"<tr><td style='font-family:monospace'>{r['query']}</td>"
            f"<td>{r['query_type']}</td>"
            f"<td style='font-family:monospace'>{', '.join(r.get('responses', [])[:3])}</td>"
            f"<td style='color:{rcode_color}'>{r.get('rcode', 0)}</td>"
            f"<td>{r.get('latency_ms', '—')} ms</td></tr>\n"
        )

    perf = report.get("performance", {})
    proto = report.get("protocol", {})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TCP Analyzer Report — {report.get('filename', '')}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        background:#0f1117;color:#e2e8f0;line-height:1.6;padding:2rem}}
  h1{{font-size:2rem;color:#f1f5f9;margin-bottom:0.25rem}}
  h2{{font-size:1.1rem;color:#94a3b8;margin:2rem 0 1rem;
      border-bottom:1px solid #2d3148;padding-bottom:0.5rem}}
  .meta{{color:#64748b;font-size:0.875rem;margin-bottom:2rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));
          gap:1rem;margin-bottom:2rem}}
  .stat{{background:#1e2130;border:1px solid #2d3148;border-radius:10px;
         padding:1rem}}
  .stat .val{{font-size:1.75rem;font-weight:700}}
  .stat .lbl{{font-size:0.72rem;color:#64748b;text-transform:uppercase;
              letter-spacing:0.06em}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem;margin-bottom:2rem}}
  th{{text-align:left;padding:0.5rem 0.75rem;color:#64748b;font-weight:600;
      border-bottom:1px solid #2d3148}}
  td{{padding:0.45rem 0.75rem;border-bottom:1px solid #1a1d27;color:#94a3b8}}
  td:first-child{{color:#cbd5e1}}
  .section{{background:#1e2130;border:1px solid #2d3148;border-radius:12px;
             padding:1.5rem;margin-bottom:1.5rem}}
  footer{{text-align:center;color:#475569;font-size:0.8rem;margin-top:3rem}}
</style>
</head>
<body>
<h1>TCP Analyzer Report</h1>
<p class="meta">
  {report.get('filename','')} &nbsp;·&nbsp;
  {report.get('total_packets',0):,} packets &nbsp;·&nbsp;
  {report.get('capture_duration_sec',0):.2f}s capture &nbsp;·&nbsp;
  {len(report.get('unique_ips',[]))} unique IPs &nbsp;·&nbsp;
  Analysis ID: {report.get('analysis_id','')[:8]}
</p>

<div class="stats">
  <div class="stat"><div class="lbl">Retransmit Rate</div>
    <div class="val" style="color:{'#ef4444' if (perf.get('retransmission_rate_pct',0) or 0) > 2 else '#22c55e'}">
      {perf.get('retransmission_rate_pct',0):.2f}%</div></div>
  <div class="stat"><div class="lbl">Avg Handshake</div>
    <div class="val" style="color:#60a5fa">{perf.get('avg_handshake_ms','—')} ms</div></div>
  <div class="stat"><div class="lbl">Reset Rate</div>
    <div class="val" style="color:{'#ef4444' if (proto.get('reset_rate_pct',0) or 0) > 5 else '#22c55e'}">
      {proto.get('reset_rate_pct',0):.2f}%</div></div>
  <div class="stat"><div class="lbl">HTTP Error Rate</div>
    <div class="val" style="color:{'#f59e0b' if (proto.get('http_error_rate_pct',0) or 0) > 10 else '#22c55e'}">
      {proto.get('http_error_rate_pct',0):.2f}%</div></div>
</div>

<h2>Diagnoses</h2>
<div class="section">
<table><thead><tr><th>Severity</th><th>Finding</th></tr></thead>
<tbody>{diag_rows}</tbody></table>
</div>

<h2>Security Findings</h2>
<div class="section">
<table><thead><tr><th>Src IP</th><th>Dst IP</th><th>Severity</th><th>Detail</th></tr></thead>
<tbody>{"<tr><td colspan='4' style='color:#4b5563;font-style:italic'>None detected</td></tr>" if not sec_rows else sec_rows}</tbody></table>
</div>

<h2>Top Flows (by bytes)</h2>
<div class="section">
<table><thead><tr><th>Source</th><th>Destination</th><th>Proto</th>
<th>Packets</th><th>Bytes</th><th>Duration</th></tr></thead>
<tbody>{"<tr><td colspan='6' style='color:#4b5563;font-style:italic'>No flow data</td></tr>" if not flow_rows else flow_rows}</tbody></table>
</div>

<h2>HTTP Objects</h2>
<div class="section">
<table><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Size</th></tr></thead>
<tbody>{"<tr><td colspan='5' style='color:#4b5563;font-style:italic'>No HTTP traffic detected</td></tr>" if not http_rows else http_rows}</tbody></table>
</div>

<h2>DNS Records</h2>
<div class="section">
<table><thead><tr><th>Domain</th><th>Type</th><th>Answers</th><th>RCode</th><th>Latency</th></tr></thead>
<tbody>{"<tr><td colspan='5' style='color:#4b5563;font-style:italic'>No DNS traffic detected</td></tr>" if not dns_rows else dns_rows}</tbody></table>
</div>

<footer>Generated by TCP Analyzer v3.0 — {report.get('filename','')}</footer>
</body></html>"""

    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.html"'},
    )


@router.get("/export/{analysis_id}/pdf")
def export_pdf(analysis_id: str):
    report = db.get_report(analysis_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed.")

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

    def body(text, size=10):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 6, _safe(text))

    def section_line():
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

    # Cover page
    pdf.add_page()
    pdf.set_fill_color(15, 17, 23)
    pdf.rect(0, 0, 210, 80, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_y(25)
    pdf.cell(0, 12, "TCP Analyzer Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 8, report.get("filename", ""), align="C", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(180, 180, 180)
    pdf.cell(0, 6, f"Analysis ID: {report.get('analysis_id', '')}", align="C", ln=True)
    pdf.ln(20)

    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    section_line()

    perf = report.get("performance", {})
    proto = report.get("protocol", {})
    stats = [
        ("Total Packets",       f"{report.get('total_packets', 0):,}"),
        ("Capture Duration",    f"{report.get('capture_duration_sec', 0):.2f} s"),
        ("Unique IPs",          str(len(report.get("unique_ips", [])))),
        ("Retransmission Rate", f"{perf.get('retransmission_rate_pct', 0):.2f}%"),
        ("Avg Handshake",       f"{perf.get('avg_handshake_ms') or '—'} ms"),
        ("P95 Handshake",       f"{perf.get('p95_handshake_ms') or '—'} ms"),
        ("HTTP Error Rate",     f"{proto.get('http_error_rate_pct', 0):.2f}%"),
        ("Connection Reset Rate", f"{proto.get('reset_rate_pct', 0):.2f}%"),
    ]
    pdf.set_font("Helvetica", "", 10)
    for label, value in stats:
        pdf.set_text_color(80, 80, 80)
        pdf.cell(80, 7, label + ":")
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, value, ln=True)

    # Diagnoses
    pdf.add_page()
    heading("Diagnoses", 14)
    section_line()
    for d in report.get("diagnoses", []):
        sev = d.get("severity", "info")
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

    # Security findings
    sec = report.get("security", {})
    all_sec = []
    for section in ["port_scan_sources", "cleartext_credentials",
                    "protocol_port_mismatches", "exfiltration_indicators", "scanner_signatures"]:
        all_sec.extend(sec.get(section, []))
    if all_sec:
        pdf.add_page()
        heading("Security Findings", 14)
        section_line()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(35, 6, "Src IP", fill=True)
        pdf.cell(35, 6, "Dst IP", fill=True)
        pdf.cell(20, 6, "Severity", fill=True)
        pdf.cell(0, 6, "Detail", fill=True, ln=True)
        pdf.set_font("Helvetica", "", 8)
        for e in all_sec[:100]:
            pdf.set_text_color(50, 50, 50)
            pdf.cell(35, 5, e.get("src_ip", ""))
            pdf.cell(35, 5, e.get("dst_ip", ""))
            sev = e.get("severity", "info")
            c = SEVERITY_COLOR.get(sev, (100, 100, 100))
            pdf.set_text_color(*c)
            pdf.cell(20, 5, sev.upper())
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 5, _safe(e.get("detail", ""))[:120])

    # Top flows
    flows = (report.get("flow") or {}).get("flows", [])[:30]
    if flows:
        pdf.add_page()
        heading("Top Flows (by bytes)", 14)
        section_line()
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(230, 230, 230)
        for col, w in [("Src IP", 32), ("Dst IP", 32), ("S.Port", 16), ("D.Port", 16),
                       ("Proto", 16), ("Pkts", 16), ("Bytes", 22), ("Dur(s)", 18)]:
            pdf.cell(w, 6, col, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for f in flows:
            pdf.set_text_color(50, 50, 50)
            def _fmt(b):
                b = int(b or 0)
                if b >= 1e6: return f"{b/1e6:.2f}MB"
                if b >= 1e3: return f"{b/1e3:.1f}KB"
                return str(b)
            for val, w in [(f["src_ip"], 32), (f["dst_ip"], 32),
                           (str(f["src_port"]), 16), (str(f["dst_port"]), 16),
                           (f["protocol"], 16), (str(f["packets"]), 16),
                           (_fmt(f["bytes"]), 22), (str(f["duration_sec"]), 18)]:
                pdf.cell(w, 5, val)
            pdf.ln()

    buf = io.BytesIO(pdf.output())
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.pdf"'},
    )
