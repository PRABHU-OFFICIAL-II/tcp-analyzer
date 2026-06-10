import csv
import io
import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
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

    # Diagnoses
    write_section("Diagnoses", [
        [d["severity"].upper(), d["headline"], "; ".join(d.get("details", []))]
        for d in report.get("diagnoses", [])
    ], ["Severity", "Headline", "Details"])

    # Performance anomalies
    write_section("Retransmissions",
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"), e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("retransmission_events", [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Packet #", "Detail"])

    write_section("Zero Window Events",
        [[e["src_ip"], e["dst_ip"], e.get("packet_number"), e["detail"]]
         for e in report.get("performance", {}).get("zero_window_events", [])],
        ["Src IP", "Dst IP", "Packet #", "Detail"])

    # Security
    write_section("Security Findings",
        [[e["src_ip"], e["dst_ip"], e.get("src_port"), e.get("dst_port"), e["severity"], e["detail"]]
         for section in ["port_scan_sources", "cleartext_credentials", "protocol_port_mismatches", "exfiltration_indicators"]
         for e in report.get("security", {}).get(section, [])],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Severity", "Detail"])

    # Flows
    write_section("Top Flows",
        [[f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"], f["packets"], f["bytes"], f["duration_sec"]]
         for f in (report.get("flow") or {}).get("flows", [])[:50]],
        ["Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Packets", "Bytes", "Duration (s)"])

    # Beacons
    write_section("Beaconing Flows",
        [[b["src_ip"], b["dst_ip"], b["dst_port"], b["connection_count"], b["avg_interval_sec"], b["cv"]]
         for b in (report.get("beacons") or {}).get("beacons", [])],
        ["Src IP", "Dst IP", "Dst Port", "Connections", "Avg Interval (s)", "CV"])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.csv"'},
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
        "critical": (239, 68, 68),
        "warning": (245, 158, 11),
        "info": (59, 130, 246),
        "clean": (34, 197, 94),
    }

    def heading(text, size=14):
        pdf.set_font("Helvetica", "B", size)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, text, ln=True)
        pdf.ln(1)

    def body(text, size=10):
        pdf.set_font("Helvetica", "", size)
        pdf.set_text_color(60, 60, 60)
        pdf.multi_cell(0, 6, text)

    def section_line():
        pdf.set_draw_color(200, 200, 200)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

    # ── Cover page ────────────────────────────────────────────────────────────
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

    # Summary stats
    pdf.set_text_color(30, 30, 30)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    section_line()

    stats = [
        ("Total Packets", f"{report.get('total_packets', 0):,}"),
        ("Capture Duration", f"{report.get('capture_duration_sec', 0):.2f} s"),
        ("Unique IPs", str(len(report.get("unique_ips", [])))),
        ("Retransmission Rate", f"{report.get('performance', {}).get('retransmission_rate_pct', 0):.2f}%"),
        ("HTTP Error Rate", f"{report.get('protocol', {}).get('http_error_rate_pct', 0):.2f}%"),
        ("Connection Reset Rate", f"{report.get('protocol', {}).get('reset_rate_pct', 0):.2f}%"),
    ]
    pdf.set_font("Helvetica", "", 10)
    for label, value in stats:
        pdf.set_text_color(80, 80, 80)
        pdf.cell(70, 7, label + ":")
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 7, value, ln=True)

    # ── Diagnoses ─────────────────────────────────────────────────────────────
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
        pdf.cell(0, 6, f"  {d.get('headline', '')}", ln=True)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(80, 80, 80)
        for detail in d.get("details", []):
            pdf.cell(22)
            pdf.multi_cell(0, 5, f"• {detail}")
        pdf.ln(2)

    # ── Security findings ─────────────────────────────────────────────────────
    sec = report.get("security", {})
    all_sec = (
        sec.get("port_scan_sources", []) +
        sec.get("cleartext_credentials", []) +
        sec.get("protocol_port_mismatches", []) +
        sec.get("exfiltration_indicators", [])
    )
    if all_sec:
        pdf.add_page()
        heading("Security Findings", 14)
        section_line()
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(30, 6, "Src IP", fill=True)
        pdf.cell(30, 6, "Dst IP", fill=True)
        pdf.cell(20, 6, "Severity", fill=True)
        pdf.cell(0, 6, "Detail", fill=True, ln=True)
        pdf.set_font("Helvetica", "", 8)
        for e in all_sec[:100]:
            pdf.set_text_color(50, 50, 50)
            pdf.cell(30, 5, e.get("src_ip", ""))
            pdf.cell(30, 5, e.get("dst_ip", ""))
            sev = e.get("severity", "info")
            c = SEVERITY_COLOR.get(sev, (100, 100, 100))
            pdf.set_text_color(*c)
            pdf.cell(20, 5, sev.upper())
            pdf.set_text_color(50, 50, 50)
            pdf.multi_cell(0, 5, e.get("detail", "")[:100])

    # ── Top flows ──────────────────────────────────────────────────────────────
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
            for val, w in [(f["src_ip"], 32), (f["dst_ip"], 32),
                           (str(f["src_port"]), 16), (str(f["dst_port"]), 16),
                           (f["protocol"], 16), (str(f["packets"]), 16),
                           (str(f["bytes"]), 22), (str(f["duration_sec"]), 18)]:
                pdf.cell(w, 5, val)
            pdf.ln()

    buf = io.BytesIO(pdf.output())
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="report_{analysis_id[:8]}.pdf"'},
    )
