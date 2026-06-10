import { useState } from "react";
import {
  ArrowLeft, FileText, Shield, Zap, Globe, Network,
  Fingerprint, Lock, MapPin, Radio, AlertTriangle,
  Clock, Globe2, Server,
} from "lucide-react";
import DiagnosisCard from "../components/DiagnosisCard.jsx";
import AnomalyTable from "../components/AnomalyTable.jsx";
import StatCard from "../components/StatCard.jsx";
import ThroughputChart from "../components/ThroughputChart.jsx";
import ExportBar from "../components/ExportBar.jsx";
import FlowTable from "../components/FlowTable.jsx";
import FingerprintPanel from "../components/FingerprintPanel.jsx";
import TLSDeepPanel from "../components/TLSDeepPanel.jsx";
import GeoBarChart from "../components/GeoBarChart.jsx";
import BeaconTable from "../components/BeaconTable.jsx";
import RSTForensicsPanel from "../components/RSTForensicsPanel.jsx";
import TimelinePanel from "../components/TimelinePanel.jsx";
import HTTPObjectsPanel from "../components/HTTPObjectsPanel.jsx";
import DNSMapPanel from "../components/DNSMapPanel.jsx";

const TABS = [
  { id: "overview",     label: "Overview",     icon: <FileText size={14} /> },
  { id: "timeline",     label: "Timeline",     icon: <Clock size={14} /> },
  { id: "performance",  label: "Performance",  icon: <Zap size={14} /> },
  { id: "security",     label: "Security",     icon: <Shield size={14} /> },
  { id: "protocol",     label: "Protocol",     icon: <Globe size={14} /> },
  { id: "flows",        label: "Flows",        icon: <Network size={14} /> },
  { id: "http",         label: "HTTP",         icon: <Globe2 size={14} /> },
  { id: "dns",          label: "DNS",          icon: <Server size={14} /> },
  { id: "fingerprint",  label: "Fingerprint",  icon: <Fingerprint size={14} /> },
  { id: "tls",          label: "TLS Deep",     icon: <Lock size={14} /> },
  { id: "geo",          label: "Geo / IOC",    icon: <MapPin size={14} /> },
  { id: "beacons",      label: "Beacons",      icon: <Radio size={14} /> },
  { id: "rst",          label: "RST Forensics", icon: <AlertTriangle size={14} /> },
];

const layout = {
  page: { minHeight: "100vh", background: "#0f1117", padding: "2rem" },
  header: { display: "flex", alignItems: "center", gap: "1rem", marginBottom: "1.5rem", flexWrap: "wrap" },
  backBtn: { background: "none", border: "1px solid #3b4268", color: "#94a3b8", borderRadius: "8px",
    padding: "0.5rem 1rem", cursor: "pointer", display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.875rem" },
  filename: { fontSize: "1.4rem", fontWeight: 700, color: "#f1f5f9" },
  meta: { color: "#64748b", fontSize: "0.875rem", marginLeft: "auto" },
  tabBar: { display: "flex", gap: "0.15rem", borderBottom: "1px solid #2d3148", marginBottom: "2rem", overflowX: "auto" },
  tab: (active) => ({
    padding: "0.6rem 1rem", cursor: "pointer", background: "none", border: "none", whiteSpace: "nowrap",
    color: active ? "#60a5fa" : "#64748b",
    borderBottom: active ? "2px solid #60a5fa" : "2px solid transparent",
    fontWeight: active ? 600 : 400, fontSize: "0.82rem",
    display: "flex", alignItems: "center", gap: "0.35rem",
  }),
  statsGrid: { display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fill, minmax(155px, 1fr))", marginBottom: "2rem" },
  sectionTitle: { fontSize: "1rem", fontWeight: 700, color: "#e2e8f0", marginBottom: "1rem",
    paddingBottom: "0.5rem", borderBottom: "1px solid #2d3148" },
  card: { background: "#1e2130", border: "1px solid #2d3148", borderRadius: "12px", padding: "1.5rem", marginBottom: "1.5rem" },
};

export default function ReportPage({ report, onReset }) {
  const [tab, setTab] = useState("overview");
  const { performance: perf, security: sec, protocol: proto } = report;

  return (
    <div style={layout.page}>
      <div style={layout.header}>
        <button style={layout.backBtn} onClick={onReset}><ArrowLeft size={15} /> New Analysis</button>
        <span style={layout.filename}>{report.filename}</span>
        <span style={layout.meta}>
          {report.total_packets.toLocaleString()} packets &nbsp;·&nbsp;
          {Number(report.capture_duration_sec).toFixed(1)}s &nbsp;·&nbsp;
          {report.unique_ips.length} IPs
        </span>
      </div>

      <ExportBar analysisId={report.analysis_id} />

      <div style={layout.tabBar}>
        {TABS.map(t => (
          <button key={t.id} style={layout.tab(tab === t.id)} onClick={() => setTab(t.id)}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {tab === "overview"    && <OverviewTab report={report} perf={perf} />}
      {tab === "timeline"    && <TimelineTab timeline={report.timeline} />}
      {tab === "performance" && <PerformanceTab perf={perf} />}
      {tab === "security"    && <SecurityTab sec={sec} arp={report.arp} ioc={report.ioc} />}
      {tab === "protocol"    && <ProtocolTab proto={proto} />}
      {tab === "flows"       && <FlowsTab flow={report.flow} />}
      {tab === "http"        && <HTTPTab httpObjects={report.http_objects} />}
      {tab === "dns"         && <DNSTab dnsMap={report.dns_map} />}
      {tab === "fingerprint" && <FingerprintTab fp={report.fingerprint} />}
      {tab === "tls"         && <TLSTab tls={report.tls_deep} />}
      {tab === "geo"         && <GeoTab geo={report.geo} />}
      {tab === "beacons"     && <BeaconsTab beacons={report.beacons} />}
      {tab === "rst"         && <RSTForensicsTab metrics={report.rst_forensics} />}
    </div>
  );
}

function OverviewTab({ report, perf }) {
  const criticals = report.diagnoses.filter(d => d.severity === "critical").length;
  const warnings  = report.diagnoses.filter(d => d.severity === "warning").length;
  const timelineCount = report.timeline?.events?.length ?? 0;
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Total Packets"     value={report.total_packets.toLocaleString()} color="#60a5fa" />
        <StatCard label="Duration"          value={Number(report.capture_duration_sec).toFixed(1)} unit="s" color="#818cf8" />
        <StatCard label="Unique IPs"        value={report.unique_ips.length} color="#a78bfa" />
        <StatCard label="Critical Findings" value={criticals} color={criticals > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Warnings"          value={warnings}  color={warnings  > 0 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="Retransmit Rate"   value={perf.retransmission_rate_pct} unit="%" color={perf.retransmission_rate_pct > 2 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Timeline Events"   value={timelineCount} color={timelineCount > 0 ? "#f97316" : "#22c55e"} />
      </div>
      <h2 style={layout.sectionTitle}>Diagnoses</h2>
      {report.diagnoses.map((d, i) => <DiagnosisCard key={i} diagnosis={d} />)}
      <h2 style={{ ...layout.sectionTitle, marginTop: "2rem" }}>Throughput Over Time</h2>
      <div style={layout.card}><ThroughputChart data={perf.throughput_series} /></div>
    </div>
  );
}

function TimelineTab({ timeline }) {
  return (
    <div>
      <h2 style={layout.sectionTitle}>Unified Event Timeline</h2>
      <p style={{ color: "#64748b", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
        Chronological view of all notable events across every analysis module.
        Filter by category or search by IP / keyword.
      </p>
      <TimelinePanel timeline={timeline} />
    </div>
  );
}

function PerformanceTab({ perf }) {
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Avg Handshake"   value={perf.avg_handshake_ms != null ? Number(perf.avg_handshake_ms).toFixed(1) : null} unit="ms" color="#60a5fa" />
        <StatCard label="P95 Handshake"   value={perf.p95_handshake_ms != null ? Number(perf.p95_handshake_ms).toFixed(1) : null} unit="ms" color="#818cf8" />
        <StatCard label="Max Handshake"   value={perf.max_handshake_ms != null ? Number(perf.max_handshake_ms).toFixed(1) : null} unit="ms" color={perf.max_handshake_ms > 200 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="Retransmissions" value={perf.retransmission_count} color={perf.retransmission_count > 0 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="Retransmit Rate" value={perf.retransmission_rate_pct} unit="%" color={perf.retransmission_rate_pct > 2 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Zero Windows"    value={perf.zero_window_count} color={perf.zero_window_count > 0 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="Avg App Delta"   value={perf.avg_delta_ms != null ? Number(perf.avg_delta_ms).toFixed(1) : null} unit="ms" color="#818cf8" />
        <StatCard label="P95 App Delta"   value={perf.p95_delta_ms != null ? Number(perf.p95_delta_ms).toFixed(1) : null} unit="ms" color="#a78bfa" />
      </div>
      <h2 style={layout.sectionTitle}>Throughput Over Time</h2>
      <div style={layout.card}><ThroughputChart data={perf.throughput_series} /></div>
      <AnomalyTable title="Slow Handshakes"       entries={perf.handshake_anomalies} />
      <AnomalyTable title="Zero Window Events"    entries={perf.zero_window_events} />
      <AnomalyTable title="Slow Server Responses" entries={perf.slow_response_events || []} />
      <AnomalyTable title="Retransmission Events" entries={perf.retransmission_events} />
    </div>
  );
}

function SecurityTab({ sec, arp, ioc }) {
  const arpConflicts = arp?.conflicts ?? [];
  const iocMatches   = ioc?.matches ?? [];
  const scannerSigs  = sec.scanner_signatures ?? [];
  const total = sec.port_scan_sources.length + sec.cleartext_credentials.length +
    sec.protocol_port_mismatches.length + sec.exfiltration_indicators.length +
    arpConflicts.length + iocMatches.length + scannerSigs.length;

  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Port Scans"       value={sec.port_scan_sources.length}      color={sec.port_scan_sources.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Cleartext Creds"  value={sec.cleartext_credentials.length}  color={sec.cleartext_credentials.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Proto Mismatches" value={sec.protocol_port_mismatches.length} color={sec.protocol_port_mismatches.length > 0 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="Exfil Indicators" value={sec.exfiltration_indicators.length} color={sec.exfiltration_indicators.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="ARP Conflicts"    value={arpConflicts.length}               color={arpConflicts.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="IOC Matches"      value={iocMatches.length}                 color={iocMatches.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Scanner Sigs"     value={scannerSigs.length}                color={scannerSigs.length > 0 ? "#ef4444" : "#22c55e"} />
      </div>
      {total === 0 && <div style={{ ...layout.card, textAlign: "center", color: "#22c55e" }}>No security anomalies detected</div>}
      <AnomalyTable title="Port Scan Activity"          entries={sec.port_scan_sources} />
      <AnomalyTable title="Cleartext Credentials"       entries={sec.cleartext_credentials} />
      <AnomalyTable title="Protocol / Port Mismatches"  entries={sec.protocol_port_mismatches} />
      <AnomalyTable title="Exfiltration Indicators"     entries={sec.exfiltration_indicators} />
      <AnomalyTable title="Scanner Tool Signatures"     entries={scannerSigs} />
      {arpConflicts.length > 0 && (
        <div style={{ marginBottom: "2rem" }}>
          <h3 style={{ color: "#94a3b8", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase",
            letterSpacing: "0.07em", marginBottom: "0.75rem" }}>ARP Spoofing Conflicts</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #2d3148" }}>
                  {["IP Address", "MACs Observed", "Packet #", "Timestamp"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {arpConflicts.map((c, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#ef4444", fontFamily: "monospace", fontWeight: 600 }}>{c.ip}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#fca5a5", fontFamily: "monospace" }}>{c.macs_seen.join(", ")}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{c.packet_number}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#64748b" }}>{new Date(c.timestamp * 1000).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {iocMatches.length > 0 && (
        <div style={{ marginBottom: "2rem" }}>
          <h3 style={{ color: "#94a3b8", fontSize: "0.85rem", fontWeight: 600, textTransform: "uppercase",
            letterSpacing: "0.07em", marginBottom: "0.75rem" }}>IOC Matches</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #2d3148" }}>
                  {["IP", "Source", "Severity", "Detail"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocMatches.map((m, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#ef4444", fontFamily: "monospace" }}>{m.ip}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{m.source}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: m.severity === "critical" ? "#ef4444" : "#f59e0b",
                      fontWeight: 700, fontSize: "0.75rem", textTransform: "uppercase" }}>{m.severity}</td>
                    <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{m.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function ProtocolTab({ proto }) {
  const statusEntries = Object.entries(proto.http_status_counts).sort((a, b) => b[1] - a[1]);
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Total Connections" value={proto.total_connections} color="#60a5fa" />
        <StatCard label="RST Rate"          value={proto.reset_rate_pct} unit="%" color={proto.reset_rate_pct > 5 ? "#ef4444" : "#22c55e"} />
        <StatCard label="HTTP Error Rate"   value={proto.http_error_rate_pct} unit="%" color={proto.http_error_rate_pct > 10 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="TLS Failures"      value={proto.tls_failures.length} color={proto.tls_failures.length > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="DNS Errors"        value={proto.dns_errors.length} color={proto.dns_errors.length > 0 ? "#f59e0b" : "#22c55e"} />
        <StatCard label="ICMP Errors"       value={(proto.icmp_errors || []).length} color={(proto.icmp_errors || []).length > 0 ? "#f59e0b" : "#22c55e"} />
      </div>
      {statusEntries.length > 0 && (
        <>
          <h2 style={layout.sectionTitle}>HTTP Status Codes</h2>
          <div style={{ ...layout.card, display: "flex", gap: "1rem", flexWrap: "wrap" }}>
            {statusEntries.map(([code, count]) => (
              <div key={code} style={{ background: "#0f1117", borderRadius: "8px", padding: "0.75rem 1.25rem",
                textAlign: "center", border: `1px solid ${code.startsWith("2") ? "#22c55e" : code.startsWith("4") || code.startsWith("5") ? "#ef4444" : "#3b4268"}` }}>
                <div style={{ fontSize: "1.5rem", fontWeight: 700,
                  color: code.startsWith("2") ? "#22c55e" : code.startsWith("4") || code.startsWith("5") ? "#ef4444" : "#94a3b8" }}>{count}</div>
                <div style={{ fontSize: "0.8rem", color: "#64748b" }}>HTTP {code}</div>
              </div>
            ))}
          </div>
        </>
      )}
      <AnomalyTable title="TLS Handshake Failures"  entries={proto.tls_failures} />
      <AnomalyTable title="DNS Errors"               entries={proto.dns_errors} />
      <AnomalyTable title="ICMP Errors"              entries={proto.icmp_errors || []} />
      <AnomalyTable title="Connection Resets (RST)"  entries={proto.connection_resets} />
    </div>
  );
}

function FlowsTab({ flow }) {
  if (!flow) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No flow data available.</p>;
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Total Flows"   value={flow.total_flows} color="#60a5fa" />
        <StatCard label="Top Talkers"   value={flow.top_talkers.length} color="#a78bfa" />
        <StatCard label="Conversations" value={flow.conversation_matrix.length} color="#818cf8" />
      </div>
      <div style={layout.card}>
        <FlowTable flows={flow.flows} topTalkers={flow.top_talkers} matrix={flow.conversation_matrix} />
      </div>
    </div>
  );
}

function HTTPTab({ httpObjects }) {
  if (!httpObjects) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No HTTP data available.</p>;
  return (
    <div>
      <h2 style={layout.sectionTitle}>HTTP Object Extraction</h2>
      <p style={{ color: "#64748b", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
        All HTTP request/response pairs reconstructed from the capture.
        Filter by status code, search by host or path.
      </p>
      <div style={layout.card}>
        <HTTPObjectsPanel httpObjects={httpObjects} />
      </div>
    </div>
  );
}

function DNSTab({ dnsMap }) {
  if (!dnsMap) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No DNS data available.</p>;
  return (
    <div>
      <h2 style={layout.sectionTitle}>DNS Map</h2>
      <p style={{ color: "#64748b", fontSize: "0.875rem", marginBottom: "1.5rem" }}>
        Domain resolution map, NXDOMAIN / SERVFAIL tracking, and top-queried domains.
      </p>
      <div style={layout.card}>
        <DNSMapPanel dnsMap={dnsMap} />
      </div>
    </div>
  );
}

function FingerprintTab({ fp }) {
  if (!fp) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No fingerprint data available.</p>;
  const osCounts = fp.hosts.reduce((acc, h) => { acc[h.os_guess] = (acc[h.os_guess] || 0) + 1; return acc; }, {});
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Hosts Identified" value={fp.hosts.length} color="#60a5fa" />
        {Object.entries(osCounts).map(([os, count]) => (
          <StatCard key={os} label={os} value={count} color="#a78bfa" />
        ))}
      </div>
      <h2 style={layout.sectionTitle}>Host Fingerprints</h2>
      <div style={layout.card}><FingerprintPanel hosts={fp.hosts} /></div>
    </div>
  );
}

function TLSTab({ tls }) {
  if (!tls) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No TLS data available.</p>;
  return (
    <div>
      <h2 style={layout.sectionTitle}>TLS Deep Inspection</h2>
      <div style={layout.card}>
        <TLSDeepPanel
          connections={tls.connections}
          weakCipherCount={tls.weak_cipher_count}
          deprecatedCount={tls.deprecated_version_count}
          uniqueJa3={tls.unique_ja3}
        />
      </div>
    </div>
  );
}

function GeoTab({ geo }) {
  if (!geo) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No geo data available.</p>;
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="External IPs" value={geo.entries.length}    color="#60a5fa" />
        <StatCard label="Countries"    value={geo.by_country.length} color="#a78bfa" />
      </div>
      <h2 style={layout.sectionTitle}>Traffic by Country</h2>
      <div style={layout.card}><GeoBarChart data={geo.by_country} /></div>
      <h2 style={layout.sectionTitle}>External IP Details</h2>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #2d3148" }}>
              {["IP Address", "Country", "City", "ISP", "Bytes"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "#64748b", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {geo.entries.map((e, i) => (
              <tr key={i} style={{ borderBottom: "1px solid #1e2130" }}>
                <td style={{ padding: "0.5rem 0.75rem", color: "#cbd5e1", fontFamily: "monospace" }}>{e.ip}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#e2e8f0" }}>{e.country_code} {e.country}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{e.city || "—"}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#94a3b8" }}>{e.isp || "—"}</td>
                <td style={{ padding: "0.5rem 0.75rem", color: "#60a5fa", fontWeight: 600 }}>
                  {e.bytes >= 1e6 ? (e.bytes / 1e6).toFixed(2) + " MB" : e.bytes >= 1e3 ? (e.bytes / 1e3).toFixed(1) + " KB" : e.bytes + " B"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RSTForensicsTab({ metrics }) {
  if (!metrics) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No RST forensics data available.</p>;
  const criticalCount = metrics.classified?.filter(r => r.severity === "critical").length ?? 0;
  const causeCount    = Object.keys(metrics.by_cause ?? {}).length;
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Total RSTs"      value={metrics.total_resets}  color={metrics.total_resets > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Critical Causes" value={criticalCount}         color={criticalCount > 0 ? "#ef4444" : "#22c55e"} />
        <StatCard label="Distinct Causes" value={causeCount}            color="#a78bfa" />
      </div>
      {metrics.total_resets > 0 && (
        <div style={{ background: "#2d1515", border: "1px solid #7f1d1d22", borderRadius: "8px",
          padding: "0.75rem 1rem", marginBottom: "1.5rem", color: "#fca5a5", fontSize: "0.85rem" }}>
          <strong>Click any card below</strong> to expand the full evidence chain and root cause explanation.
        </div>
      )}
      <RSTForensicsPanel metrics={metrics} />
    </div>
  );
}

function BeaconsTab({ beacons }) {
  if (!beacons) return <p style={{ color: "#4b5563", fontStyle: "italic" }}>No beacon data available.</p>;
  return (
    <div>
      <div style={layout.statsGrid}>
        <StatCard label="Beaconing Flows" value={beacons.beacons.length} color={beacons.beacons.length > 0 ? "#ef4444" : "#22c55e"} />
      </div>
      {beacons.beacons.length > 0 && (
        <div style={{ background: "#2d1515", border: "1px solid #7f1d1d", borderRadius: "8px",
          padding: "0.75rem 1rem", marginBottom: "1.5rem", color: "#fca5a5", fontSize: "0.85rem" }}>
          <strong>Beaconing detected.</strong> Flows connecting at regular intervals may indicate C2 callbacks.
          Lower CV = more regular timing = more suspicious.
        </div>
      )}
      <h2 style={layout.sectionTitle}>Beaconing Flows</h2>
      <div style={layout.card}><BeaconTable beacons={beacons.beacons} /></div>
    </div>
  );
}
