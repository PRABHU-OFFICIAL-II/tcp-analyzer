import { useState, useRef, useEffect } from "react";

function MarkdownMessage({ content }) {
  const lines = content.split("\n");
  const elements = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // H3
    if (line.startsWith("### ")) {
      elements.push(
        <div key={i} style={{ fontSize: "0.82rem", fontWeight: 700, color: "#a5b4fc",
          marginTop: "1rem", marginBottom: "0.35rem", borderBottom: "1px solid rgba(99,102,241,0.2)",
          paddingBottom: "0.25rem" }}>
          {renderInline(line.slice(4))}
        </div>
      );
      i++; continue;
    }
    // H2
    if (line.startsWith("## ")) {
      elements.push(
        <div key={i} style={{ fontSize: "0.875rem", fontWeight: 700, color: "#c4b5fd",
          marginTop: "1.1rem", marginBottom: "0.4rem", borderBottom: "1px solid rgba(139,92,246,0.3)",
          paddingBottom: "0.3rem" }}>
          {renderInline(line.slice(3))}
        </div>
      );
      i++; continue;
    }
    // H1
    if (line.startsWith("# ")) {
      elements.push(
        <div key={i} style={{ fontSize: "0.95rem", fontWeight: 700, color: "#e2e8f0",
          marginTop: "1.2rem", marginBottom: "0.5rem" }}>
          {renderInline(line.slice(2))}
        </div>
      );
      i++; continue;
    }
    // Bullet list item (- or *)
    if (/^[\*\-]\s/.test(line)) {
      const listItems = [];
      while (i < lines.length && /^[\*\-]\s/.test(lines[i])) {
        listItems.push(
          <li key={i} style={{ marginBottom: "0.3rem", lineHeight: 1.55 }}>
            {renderInline(lines[i].slice(2))}
          </li>
        );
        i++;
      }
      elements.push(
        <ul key={`ul-${i}`} style={{ paddingLeft: "1.25rem", margin: "0.35rem 0", listStyleType: "disc" }}>
          {listItems}
        </ul>
      );
      continue;
    }
    // Numbered list
    if (/^\d+\.\s/.test(line)) {
      const listItems = [];
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        const text = lines[i].replace(/^\d+\.\s/, "");
        listItems.push(
          <li key={i} style={{ marginBottom: "0.3rem", lineHeight: 1.55 }}>
            {renderInline(text)}
          </li>
        );
        i++;
      }
      elements.push(
        <ol key={`ol-${i}`} style={{ paddingLeft: "1.25rem", margin: "0.35rem 0" }}>
          {listItems}
        </ol>
      );
      continue;
    }
    // Horizontal rule
    if (/^---+$/.test(line.trim())) {
      elements.push(<hr key={i} style={{ border: "none", borderTop: "1px solid #2d3148", margin: "0.75rem 0" }} />);
      i++; continue;
    }
    // Empty line → spacer
    if (line.trim() === "") {
      elements.push(<div key={i} style={{ height: "0.4rem" }} />);
      i++; continue;
    }
    // Regular paragraph
    elements.push(
      <div key={i} style={{ lineHeight: 1.6, marginBottom: "0.1rem" }}>
        {renderInline(line)}
      </div>
    );
    i++;
  }

  return <div style={{ fontSize: "0.825rem", color: "#e2e8f0" }}>{elements}</div>;
}

function renderInline(text) {
  // Split on **bold**, *italic*, and `code` markers
  const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith("**") && part.endsWith("**"))
      return <strong key={idx} style={{ color: "#f1f5f9", fontWeight: 700 }}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("*") && part.endsWith("*"))
      return <em key={idx} style={{ color: "#cbd5e1" }}>{part.slice(1, -1)}</em>;
    if (part.startsWith("`") && part.endsWith("`"))
      return <code key={idx} style={{ background: "rgba(99,102,241,0.15)", color: "#a5b4fc",
        padding: "0.1rem 0.35rem", borderRadius: "4px", fontSize: "0.78rem", fontFamily: "monospace" }}>
        {part.slice(1, -1)}
      </code>;
    return part;
  });
}

const PPP_AVATAR = "https://ca.slack-edge.com/E7T5PNK3P-U0AGF1FVD1P-5424c1ea1a50-512";

const CAPTURE_REASONS = [
  "There was latency / slowness that I was investigating",
  "A connection was being dropped or reset unexpectedly",
  "I suspected a security incident or unauthorized access",
  "An application was failing or throwing errors",
  "I was checking for DNS or TLS issues",
  "I wanted to understand traffic patterns / bandwidth usage",
  "I was debugging a specific host or service",
];

const s = {
  toggle: {
    position: "fixed", bottom: "2rem", right: "2rem", zIndex: 1000,
    background: "linear-gradient(135deg, #3b82f6, #6366f1)",
    border: "none", borderRadius: "50px", color: "#fff",
    padding: "0.6rem 1rem 0.6rem 0.6rem", cursor: "pointer",
    display: "flex", alignItems: "center", gap: "0.5rem",
    fontSize: "0.875rem", fontWeight: 600,
    boxShadow: "0 4px 24px rgba(99,102,241,0.4)",
    transition: "transform 0.15s",
  },
  toggleAvatar: {
    width: "28px", height: "28px", borderRadius: "50%",
    objectFit: "cover", border: "2px solid rgba(255,255,255,0.3)",
    flexShrink: 0,
  },
  panel: (open) => ({
    position: "fixed", right: 0, top: 0, bottom: 0,
    width: open ? "420px" : 0,
    background: "#12151f",
    borderLeft: "1px solid #2d3148",
    display: "flex", flexDirection: "column",
    zIndex: 999,
    transition: "width 0.25s cubic-bezier(0.4,0,0.2,1)",
    overflow: "hidden",
  }),
  header: {
    padding: "1rem 1.25rem", borderBottom: "1px solid #2d3148",
    display: "flex", alignItems: "center", justifyContent: "space-between",
    background: "#0f1117",
  },
  headerTitle: {
    display: "flex", alignItems: "center", gap: "0.6rem",
    fontSize: "0.95rem", fontWeight: 700, color: "#e2e8f0",
  },
  headerAvatar: {
    width: "30px", height: "30px", borderRadius: "50%",
    objectFit: "cover", border: "2px solid #6366f1", flexShrink: 0,
  },
  badge: {
    background: "linear-gradient(135deg, #3b82f6, #6366f1)",
    borderRadius: "4px", padding: "0.15rem 0.5rem",
    fontSize: "0.65rem", fontWeight: 700, color: "#fff", letterSpacing: "0.05em",
  },
  closeBtn: {
    background: "none", border: "none", color: "#64748b",
    cursor: "pointer", fontSize: "1.2rem", lineHeight: 1,
    padding: "0.25rem",
  },
  body: {
    flex: 1, overflowY: "auto", padding: "1rem 1.25rem",
    display: "flex", flexDirection: "column", gap: "0.75rem",
  },
  setupCard: {
    background: "#1e2130", border: "1px solid #2d3148",
    borderRadius: "12px", padding: "1.25rem",
  },
  setupHeader: {
    display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.75rem",
  },
  setupAvatar: {
    width: "40px", height: "40px", borderRadius: "50%",
    objectFit: "cover", border: "2px solid #6366f1", flexShrink: 0,
  },
  setupLabel: {
    fontSize: "0.8rem", fontWeight: 600, color: "#94a3b8",
    textTransform: "uppercase", letterSpacing: "0.05em",
  },
  setupSubLabel: {
    fontSize: "0.75rem", color: "#64748b",
  },
  reasonBtn: (sel) => ({
    display: "block", width: "100%", textAlign: "left",
    background: sel ? "rgba(99,102,241,0.15)" : "transparent",
    border: `1px solid ${sel ? "#6366f1" : "#2d3148"}`,
    borderRadius: "8px", padding: "0.55rem 0.75rem",
    color: sel ? "#a5b4fc" : "#94a3b8", cursor: "pointer",
    fontSize: "0.8rem", marginBottom: "0.4rem",
    transition: "all 0.15s",
  }),
  customInput: {
    width: "100%", background: "#0f1117", border: "1px solid #2d3148",
    borderRadius: "8px", padding: "0.55rem 0.75rem",
    color: "#e2e8f0", fontSize: "0.8rem", outline: "none",
    marginTop: "0.5rem", boxSizing: "border-box",
  },
  startBtn: {
    width: "100%", marginTop: "1rem",
    background: "linear-gradient(135deg, #3b82f6, #6366f1)",
    border: "none", borderRadius: "8px", padding: "0.65rem",
    color: "#fff", fontWeight: 700, fontSize: "0.875rem", cursor: "pointer",
  },
  bubbleWrap: (role) => ({
    display: "flex", flexDirection: role === "user" ? "row-reverse" : "row",
    gap: "0.5rem", alignItems: "flex-start",
  }),
  agentAvatar: {
    flexShrink: 0, width: "30px", height: "30px", borderRadius: "50%",
    objectFit: "cover", border: "2px solid #6366f1",
  },
  userAvatar: {
    flexShrink: 0, width: "30px", height: "30px", borderRadius: "50%",
    background: "#334155",
    display: "flex", alignItems: "center", justifyContent: "center",
    fontSize: "0.7rem", fontWeight: 700, color: "#94a3b8",
  },
  bubble: (role) => ({
    maxWidth: "85%",
    background: role === "user" ? "#1e2540" : "#1a1d2e",
    border: `1px solid ${role === "user" ? "#3b4268" : "#2d3148"}`,
    borderRadius: role === "user" ? "12px 4px 12px 12px" : "4px 12px 12px 12px",
    padding: "0.65rem 0.875rem",
    color: "#e2e8f0", fontSize: "0.825rem", lineHeight: 1.6,
    whiteSpace: "pre-wrap", wordBreak: "break-word",
  }),
  thinkingBubble: {
    maxWidth: "85%",
    background: "rgba(99,102,241,0.05)",
    border: "1px solid rgba(99,102,241,0.2)",
    borderRadius: "4px 12px 12px 12px",
    padding: "0.5rem 0.875rem",
    color: "#6366f1", fontSize: "0.75rem", fontStyle: "italic",
  },
  footer: {
    padding: "0.75rem 1rem", borderTop: "1px solid #2d3148",
    background: "#0f1117",
    display: "flex", gap: "0.5rem", alignItems: "flex-end",
  },
  textarea: {
    flex: 1, background: "#1e2130", border: "1px solid #2d3148",
    borderRadius: "8px", padding: "0.65rem 0.875rem",
    color: "#e2e8f0", fontSize: "0.825rem", outline: "none",
    resize: "none", lineHeight: 1.5, minHeight: "42px", maxHeight: "120px",
    fontFamily: "inherit",
  },
  sendBtn: (disabled) => ({
    background: disabled ? "#1e2130" : "linear-gradient(135deg, #3b82f6, #6366f1)",
    border: "none", borderRadius: "8px", padding: "0.65rem 0.875rem",
    color: disabled ? "#4b5563" : "#fff", cursor: disabled ? "not-allowed" : "pointer",
    fontWeight: 700, fontSize: "0.875rem", flexShrink: 0,
  }),
  contextBar: {
    background: "rgba(99,102,241,0.08)", border: "1px solid rgba(99,102,241,0.2)",
    borderRadius: "8px", padding: "0.5rem 0.75rem",
    fontSize: "0.75rem", color: "#a5b4fc",
    display: "flex", gap: "0.4rem", alignItems: "flex-start",
  },
  dots: {
    display: "flex", gap: "4px", padding: "0.5rem 0",
  },
  dot: (i) => ({
    width: "6px", height: "6px", borderRadius: "50%",
    background: "#6366f1",
    animation: `ai-bounce 1s ease-in-out ${i * 0.15}s infinite`,
  }),
};

export default function AIChatPanel({ report }) {
  const [open, setOpen] = useState(false);
  const [started, setStarted] = useState(false);
  const [captureReason, setCaptureReason] = useState("");
  const [customReason, setCustomReason] = useState("");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const bodyRef = useRef(null);
  const taRef = useRef(null);

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const effectiveReason = captureReason === "__custom__" ? customReason : captureReason;

  async function handleStart() {
    if (!effectiveReason.trim()) return;
    setStarted(true);
    setMessages([{
      role: "assistant",
      content: `Got it. I've noted your capture context: "${effectiveReason.trim()}"\n\nI've reviewed the full analysis report for **${report.filename}**. Ask me anything about the findings — performance issues, security alerts, connection patterns, or specific IPs.`
    }]);
  }

  async function sendMessage(text) {
    if (!text.trim() || loading) return;
    const userMsg = { role: "user", content: text.trim() };
    const nextMessages = [...messages, userMsg];
    setMessages(nextMessages);
    setInput("");
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report,
          capture_reason: effectiveReason.trim(),
          messages: nextMessages.map(m => ({ role: m.role, content: m.content })),
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setMessages(prev => [...prev, { role: "assistant", content: data.response }]);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  }

  function handleReset() {
    setStarted(false);
    setCaptureReason("");
    setCustomReason("");
    setMessages([]);
    setError(null);
  }

  return (
    <>
      <style>{`
        @keyframes ai-bounce {
          0%, 100% { transform: translateY(0); opacity: 0.5; }
          50% { transform: translateY(-5px); opacity: 1; }
        }
      `}</style>

      <button
        style={s.toggle}
        onClick={() => setOpen(o => !o)}
        title="Ask PPP Agent about this capture"
      >
        <img src={PPP_AVATAR} alt="PPP" style={s.toggleAvatar} />
        {open ? "Close Agent" : "Ask PPP Agent"}
      </button>

      <div style={s.panel(open)}>
        {open && (
          <>
            <div style={s.header}>
              <div style={s.headerTitle}>
                <img src={PPP_AVATAR} alt="PPP Agent" style={s.headerAvatar} />
                PPP Agent
                <span style={s.badge}>AI</span>
              </div>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                {started && (
                  <button
                    style={{ ...s.closeBtn, fontSize: "0.75rem", color: "#64748b", padding: "0.2rem 0.5rem",
                      border: "1px solid #2d3148", borderRadius: "6px" }}
                    onClick={handleReset}
                    title="Start over"
                  >
                    Reset
                  </button>
                )}
                <button style={s.closeBtn} onClick={() => setOpen(false)}>✕</button>
              </div>
            </div>

            <div style={s.body} ref={bodyRef}>
              {!started ? (
                <div style={s.setupCard}>
                  <div style={s.setupHeader}>
                    <img src={PPP_AVATAR} alt="PPP Agent" style={s.setupAvatar} />
                    <div>
                      <div style={s.setupLabel}>Why did you capture this TCP dump?</div>
                      <div style={s.setupSubLabel}>PPP Agent will tailor the analysis to your exact use case.</div>
                    </div>
                  </div>
                  {CAPTURE_REASONS.map(r => (
                    <button
                      key={r}
                      style={s.reasonBtn(captureReason === r)}
                      onClick={() => setCaptureReason(r)}
                    >
                      {captureReason === r ? "● " : "○ "}{r}
                    </button>
                  ))}
                  <button
                    style={s.reasonBtn(captureReason === "__custom__")}
                    onClick={() => setCaptureReason("__custom__")}
                  >
                    {captureReason === "__custom__" ? "● " : "○ "}Other (describe below)
                  </button>
                  {captureReason === "__custom__" && (
                    <input
                      style={s.customInput}
                      placeholder="Describe why you captured this dump..."
                      value={customReason}
                      onChange={e => setCustomReason(e.target.value)}
                      autoFocus
                    />
                  )}
                  <button
                    style={{
                      ...s.startBtn,
                      opacity: effectiveReason.trim() ? 1 : 0.4,
                      cursor: effectiveReason.trim() ? "pointer" : "not-allowed",
                    }}
                    onClick={handleStart}
                    disabled={!effectiveReason.trim()}
                  >
                    Start PPP Agent Analysis →
                  </button>
                </div>
              ) : (
                <>
                  <div style={s.contextBar}>
                    <span>📌</span>
                    <span><strong>Context:</strong> {effectiveReason}</span>
                  </div>

                  {messages.map((m, i) => (
                    <div key={i} style={s.bubbleWrap(m.role)}>
                      {m.role === "assistant" ? (
                        <img src={PPP_AVATAR} alt="PPP Agent" style={s.agentAvatar} />
                      ) : (
                        <div style={s.userAvatar}>You</div>
                      )}
                      <div style={s.bubble(m.role)}>
                        {m.role === "assistant"
                          ? <MarkdownMessage content={m.content} />
                          : m.content}
                      </div>
                    </div>
                  ))}

                  {loading && (
                    <div style={s.bubbleWrap("assistant")}>
                      <img src={PPP_AVATAR} alt="PPP Agent" style={s.agentAvatar} />
                      <div style={s.thinkingBubble}>
                        <div style={s.dots}>
                          {[0, 1, 2].map(i => <div key={i} style={s.dot(i)} />)}
                        </div>
                      </div>
                    </div>
                  )}

                  {error && (
                    <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid #ef4444",
                      borderRadius: "8px", padding: "0.65rem 0.875rem", color: "#fca5a5", fontSize: "0.8rem" }}>
                      Error: {error}
                    </div>
                  )}
                </>
              )}
            </div>

            {started && (
              <div style={s.footer}>
                <textarea
                  ref={taRef}
                  style={s.textarea}
                  placeholder="Ask PPP Agent about the analysis..."
                  value={input}
                  onChange={e => {
                    setInput(e.target.value);
                    e.target.style.height = "auto";
                    e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
                  }}
                  onKeyDown={handleKeyDown}
                  rows={1}
                  disabled={loading}
                />
                <button
                  style={s.sendBtn(!input.trim() || loading)}
                  onClick={() => sendMessage(input)}
                  disabled={!input.trim() || loading}
                >
                  Send
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
