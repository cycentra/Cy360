/**
 * CyMindChatOverlay.jsx
 * Native streaming chat panel that calls CyMind's SSE streaming API.
 * Rendered by App.jsx for analyst/admin users only.
 *
 * Auth flow:
 *   1. Fetch /api/system/cymind → get chatApiKey (pak_...) and cymindUrl
 *   2. POST /cymind/api/v1/chat/stream via nginx proxy (same-origin, no mixed-content)
 *      with Authorization: Bearer <chatApiKey> and use_mcp: true
 *   3. Parse SSE chunks: data: {"token":"...", "done":false} ... data: [DONE]
 *
 * Agentic actions:
 *   When the Flask proxy detects an action intent it emits:
 *     data: {"action_pending": {type, params, label, risk, summary, reversible}}
 *   The overlay renders a confirm card.  On confirm, POST /api/cymind/action/execute.
 *
 * Props:
 *   onClose — callback to hide the overlay
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { API_BASE } from "../core/constants.js";

// ── Inline keyframe injection (runs once) ─────────────────────────────────────
const _STYLE_ID = "cymind-overlay-styles";
if (!document.getElementById(_STYLE_ID)) {
  const s = document.createElement("style");
  s.id = _STYLE_ID;
  s.textContent = `
    @keyframes cymindSlideIn  { from { transform: translateY(100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    @keyframes cymindSlideOut { from { transform: translateY(0);    opacity: 1; } to { transform: translateY(100%); opacity: 0; } }
    .cymind-overlay-enter { animation: cymindSlideIn  0.3s cubic-bezier(0.16,1,0.3,1) forwards; }
    .cymind-overlay-exit  { animation: cymindSlideOut 0.25s ease-in forwards; }
    .cymind-msg-blink::after { content: "▌"; animation: cymindBlink 0.7s step-end infinite; }
    @keyframes cymindBlink { 0%,100%{opacity:1} 50%{opacity:0} }
    .cymind-scroll::-webkit-scrollbar { width: 4px; }
    .cymind-scroll::-webkit-scrollbar-thumb { background: rgba(0,229,160,0.2); border-radius: 2px; }
  `;
  document.head.appendChild(s);
}

// ── Markdown-lite renderer (bold, inline code, line breaks only) ──────────────
function MsgText({ text }) {
  // Split on **bold**, `code`, and newlines
  const parts = [];
  let rest = text;
  while (rest.length) {
    const bold  = rest.indexOf("**");
    const code  = rest.indexOf("`");
    const nl    = rest.indexOf("\n");
    const first = [bold, code, nl].filter(i => i >= 0).sort((a, b) => a - b)[0];
    if (first === undefined) { parts.push({ t: "text", v: rest }); break; }
    if (first > 0) parts.push({ t: "text", v: rest.slice(0, first) });
    if (first === nl) {
      parts.push({ t: "br" });
      rest = rest.slice(nl + 1);
    } else if (first === code) {
      const end = rest.indexOf("`", code + 1);
      if (end === -1) { parts.push({ t: "text", v: rest }); break; }
      parts.push({ t: "code", v: rest.slice(code + 1, end) });
      rest = rest.slice(end + 1);
    } else {
      const end = rest.indexOf("**", bold + 2);
      if (end === -1) { parts.push({ t: "text", v: rest }); break; }
      parts.push({ t: "bold", v: rest.slice(bold + 2, end) });
      rest = rest.slice(end + 2);
    }
  }
  return (
    <span>
      {parts.map((p, i) =>
        p.t === "br"   ? <br key={i} /> :
        p.t === "bold" ? <strong key={i} style={{ color: "rgba(255,255,255,0.85)" }}>{p.v}</strong> :
        p.t === "code" ? <code key={i} style={{ background: "rgba(0,229,160,0.1)", borderRadius: 3, padding: "1px 4px", fontSize: "0.9em", color: "#00e5a0", fontFamily: "monospace" }}>{p.v}</code> :
                         <span key={i}>{p.v}</span>
      )}
    </span>
  );
}

// ── Action confirm card ───────────────────────────────────────────────────────
const _RISK_COLOR = { low: "#00e5a0", medium: "#f0c040", high: "#ff6b6b" };
const _RISK_BG    = { low: "rgba(0,229,160,0.1)", medium: "rgba(240,192,64,0.1)", high: "rgba(255,107,107,0.1)" };

function ActionConfirmCard({ action, status, result, onConfirm, onCancel }) {
  const { label, risk, summary, reversible } = action;
  const riskColor = _RISK_COLOR[risk] || "#aaa";
  const riskBg    = _RISK_BG[risk]    || "rgba(255,255,255,0.05)";
  const executing = status === "executing";
  const done      = status === "confirmed" || status === "cancelled";

  return (
    <div style={{
      border:        `1px solid ${riskColor}`,
      borderRadius:  8,
      background:    riskBg,
      padding:       "12px 14px",
      fontSize:      12,
      lineHeight:    1.65,
      fontFamily:    "system-ui, sans-serif",
    }}>
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <span style={{
          background: riskColor, color: "#000", fontWeight: 700,
          fontSize: 9, padding: "2px 7px", borderRadius: 20, letterSpacing: "0.8px",
          textTransform: "uppercase",
        }}>
          {risk} risk
        </span>
        {!reversible && (
          <span style={{
            background: "rgba(255,107,107,0.2)", color: "#ff6b6b", fontWeight: 600,
            fontSize: 9, padding: "2px 7px", borderRadius: 20, letterSpacing: "0.8px",
            textTransform: "uppercase", border: "1px solid rgba(255,107,107,0.3)",
          }}>
            irreversible
          </span>
        )}
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: 10 }}>
          Action pending confirmation
        </span>
      </div>

      {/* Label */}
      <div style={{ fontWeight: 700, color: "white", marginBottom: 6, fontSize: 13 }}>
        {label}
      </div>

      {/* Summary */}
      <div style={{ color: "rgba(255,255,255,0.6)", marginBottom: 12 }}>
        <MsgText text={summary} />
      </div>

      {/* Result (after execution) */}
      {result && (
        <div style={{
          background: result.success ? "rgba(0,229,160,0.08)" : "rgba(255,107,107,0.08)",
          border: `1px solid ${result.success ? "rgba(0,229,160,0.2)" : "rgba(255,107,107,0.2)"}`,
          borderRadius: 6, padding: "8px 10px", marginBottom: 10,
          color: result.success ? "#00e5a0" : "#ff6b6b", fontSize: 11,
        }}>
          {result.success ? "✓ " : "✗ "}<MsgText text={result.message || (result.success ? "Done" : "Failed")} />
        </div>
      )}

      {/* Buttons */}
      {!done && (
        <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
          <button
            onClick={onConfirm}
            disabled={executing}
            style={{
              flex: 1,
              background: executing ? "rgba(0,229,160,0.05)" : "rgba(0,229,160,0.15)",
              border: "1px solid rgba(0,229,160,0.4)",
              borderRadius: 6, padding: "6px 14px",
              color: executing ? "rgba(0,229,160,0.4)" : "#00e5a0",
              fontWeight: 700, fontSize: 11, cursor: executing ? "default" : "pointer",
              fontFamily: "monospace", letterSpacing: "0.8px",
              transition: "background 0.15s",
            }}
          >
            {executing ? "Executing…" : "⚡ EXECUTE"}
          </button>
          <button
            onClick={onCancel}
            disabled={executing}
            style={{
              flex: 1,
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 6, padding: "6px 14px",
              color: "rgba(255,255,255,0.65)",
              fontWeight: 600, fontSize: 11, cursor: executing ? "default" : "pointer",
              fontFamily: "monospace",
            }}
          >
            Cancel
          </button>
        </div>
      )}

      {status === "cancelled" && (
        <div style={{ color: "rgba(255,255,255,0.3)", fontSize: 11, marginTop: 4 }}>
          Action cancelled.
        </div>
      )}
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────
export function CyMindChatOverlay({ onClose }) {
  const [exiting,    setExiting]    = useState(false);
  const [configErr,  setConfigErr]  = useState(null);
  const [ready,      setReady]      = useState(false);
  const [messages,   setMessages]   = useState([
    { role: "assistant", content: "Hello! I'm CyMind, your AI security assistant. I have live access to your SIEM data. I can also execute response actions — just ask me to block an IP, close an incident, run a scan, or set up a schedule.", done: true },
  ]);
  const [input,      setInput]      = useState("");
  const [streaming,  setStreaming]  = useState(false);
  // actionCards: maps message index → {status, result}
  const [actionCards, setActionCards] = useState({});
  const bottomRef  = useRef(null);
  const abortRef   = useRef(null);
  const inputRef   = useRef(null);

  // Verify integration is configured — proxy handles auth server-side
  useEffect(() => {
    fetch(`${API_BASE}/api/system/cymind`, { credentials: "include" })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        if (!d?.cymindUrl) {
          setConfigErr("CyMind URL not configured. Ask your admin to enable it in System Settings → CyMind.");
        } else if (!d?.hasChatKey) {
          setConfigErr("CyMind integration not fully set up. Ask your admin to run Enable Integration in System Settings → CyMind.");
        } else {
          setReady(true);
        }
      })
      .catch(() => setConfigErr("Could not load CyMind configuration."));
  }, []);

  // Auto-scroll on new content
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, actionCards]);

  const handleClose = () => {
    abortRef.current?.abort();
    setExiting(true);
    setTimeout(onClose, 240);
  };

  // ── Action card handlers ────────────────────────────────────────────────────

  const handleActionConfirm = useCallback(async (msgIdx) => {
    const msg = messages[msgIdx];
    if (!msg?.actionPending) return;

    // Set card to executing
    setActionCards(prev => ({ ...prev, [msgIdx]: { status: "executing", result: null } }));

    try {
      const resp = await fetch(`${API_BASE}/api/cymind/action/execute`, {
        method:      "POST",
        credentials: "include",
        headers:     { "Content-Type": "application/json" },
        body:        JSON.stringify({
          type:   msg.actionPending.type,
          params: msg.actionPending.params,
        }),
      });
      const data = await resp.json();
      setActionCards(prev => ({
        ...prev,
        [msgIdx]: { status: "confirmed", result: data },
      }));
      // Append result as a separate assistant message
      setMessages(prev => [
        ...prev,
        {
          role:    "assistant",
          content: data.message || (data.success ? "Action completed successfully." : "Action failed."),
          done:    true,
          error:   !data.success,
        },
      ]);
    } catch (err) {
      setActionCards(prev => ({
        ...prev,
        [msgIdx]: { status: "confirmed", result: { success: false, message: err.message } },
      }));
    }
  }, [messages]);

  const handleActionCancel = useCallback((msgIdx) => {
    setActionCards(prev => ({ ...prev, [msgIdx]: { status: "cancelled", result: null } }));
  }, []);

  // ── Chat send ───────────────────────────────────────────────────────────────

  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || streaming || !ready) return;

    setInput("");
    const userMsg      = { role: "user", content: text, done: true };
    const assistantMsg = { role: "assistant", content: "", done: false };

    setMessages(prev => [...prev, userMsg, assistantMsg]);
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    // Build message history for the API (exclude the empty placeholder we just added)
    const history = [...messages, userMsg].map(m => ({
      role:    m.role === "action_card" ? "assistant" : m.role,
      content: m.content || "",
    }));

    try {
      // Route via CyCentra's Flask proxy so no nginx injection is needed and
      // the chat key stays server-side (never exposed in browser requests).
      const resp = await fetch(`${API_BASE}/api/cymind/chat/stream`, {
        method: "POST",
        signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          messages:     history,
          use_mcp:      true,
          use_rag:      true,
          use_external: false,
        }),
      });

      if (!resp.ok) {
        throw new Error(`CyMind returned HTTP ${resp.status}`);
      }

      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = "";
      let   actionPending = null;  // holds action_pending payload when detected

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop(); // incomplete line stays in buffer

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const raw = line.slice(6).trim();
          if (raw === "[DONE]") break;
          try {
            const chunk = JSON.parse(raw);
            if (chunk.error) throw new Error(chunk.error);

            // ── Agentic action event ────────────────────────────────────────
            if (chunk.action_pending) {
              actionPending = chunk.action_pending;
              // Replace the placeholder assistant message with an action card
              setMessages(prev => {
                const msgs = [...prev];
                msgs[msgs.length - 1] = {
                  ...msgs[msgs.length - 1],
                  role:          "action_card",
                  actionPending: chunk.action_pending,
                  done:          true,
                };
                return msgs;
              });
              continue;
            }

            // ── Regular text token ──────────────────────────────────────────
            if (chunk.token) {
              setMessages(prev => {
                const msgs = [...prev];
                msgs[msgs.length - 1] = {
                  ...msgs[msgs.length - 1],
                  content: msgs[msgs.length - 1].content + chunk.token,
                };
                return msgs;
              });
            }
          } catch (parseErr) {
            if (parseErr.message !== "Unexpected end of JSON input") {
              throw parseErr;
            }
          }
        }
      }

      // If an action card was received, set its initial state in actionCards
      if (actionPending) {
        setMessages(prev => {
          const idx = prev.length - 1;
          setActionCards(cards => ({
            ...cards,
            [idx]: { status: "pending", result: null },
          }));
          return prev;
        });
      }

    } catch (err) {
      if (err.name !== "AbortError") {
        setMessages(prev => {
          const msgs = [...prev];
          msgs[msgs.length - 1] = {
            ...msgs[msgs.length - 1],
            content: `Error: ${err.message}`,
            done: true,
            error: true,
          };
          return msgs;
        });
      }
    } finally {
      // Mark last message as done
      setMessages(prev => {
        const msgs = [...prev];
        msgs[msgs.length - 1] = { ...msgs[msgs.length - 1], done: true };
        return msgs;
      });
      setStreaming(false);
      abortRef.current = null;
      inputRef.current?.focus();
    }
  }, [input, streaming, ready, messages]);

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={handleClose}
        style={{
          position: "fixed", inset: 0, zIndex: 900,
          background: "rgba(0,0,0,0.45)", backdropFilter: "blur(3px)",
        }}
      />

      {/* Overlay panel */}
      <div
        className={exiting ? "cymind-overlay-exit" : "cymind-overlay-enter"}
        style={{
          position: "fixed", bottom: 0, right: 24,
          width: "min(500px, calc(100vw - 48px))",
          height: "min(700px, calc(100vh - 80px))",
          zIndex: 901,
          display: "flex", flexDirection: "column",
          background: "#0d1117",
          border: "1px solid rgba(0,229,160,0.25)",
          borderBottom: "none",
          borderRadius: "10px 10px 0 0",
          boxShadow: "0 -8px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,229,160,0.08)",
          overflow: "hidden",
        }}
      >
        {/* Title bar */}
        <div style={{
          height: 44, display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "0 14px 0 16px", flexShrink: 0,
          background: "rgba(0,229,160,0.06)",
          borderBottom: "1px solid rgba(0,229,160,0.15)",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="1.8">
              <path d="M12 2a7 7 0 0 1 7 7c0 3.5-2.5 6.4-5.8 7.7L12 22l-1.2-5.3C7.5 15.4 5 12.5 5 9a7 7 0 0 1 7-7z"/>
              <circle cx="12" cy="9" r="2.5" fill="rgba(0,229,160,0.3)" stroke="#00e5a0" strokeWidth="1.5"/>
            </svg>
            <span style={{ color: "#00e5a0", fontFamily: "monospace", fontSize: 12, fontWeight: 700, letterSpacing: "1.5px" }}>
              CYMIND
            </span>
            <span style={{ color: "rgba(255,255,255,0.55)", fontSize: 10, fontFamily: "monospace" }}>
              AI Security Assistant
            </span>
            {streaming && (
              <span style={{ color: "rgba(0,229,160,0.5)", fontSize: 9, fontFamily: "monospace", marginLeft: 4 }}>
                ● LIVE
              </span>
            )}
          </div>
          <button
            onClick={handleClose}
            title="Close"
            style={{
              background: "transparent", border: "none", cursor: "pointer",
              color: "rgba(255,255,255,0.65)", padding: 4, borderRadius: 4,
              display: "flex", alignItems: "center",
            }}
            onMouseEnter={e => e.currentTarget.style.color = "rgba(255,255,255,0.8)"}
            onMouseLeave={e => e.currentTarget.style.color = "rgba(255,255,255,0.4)"}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>

        {/* Content area */}
        {configErr ? (
          <div style={{
            flex: 1, display: "flex", flexDirection: "column",
            alignItems: "center", justifyContent: "center", gap: 12, padding: 24,
          }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <div style={{ color: "rgba(255,255,255,0.65)", fontSize: 12, fontFamily: "monospace", textAlign: "center", lineHeight: 1.7 }}>
              {configErr}
            </div>
          </div>
        ) : !ready ? (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ color: "rgba(0,229,160,0.6)", fontFamily: "monospace", fontSize: 11 }}>Loading…</div>
          </div>
        ) : (
          <>
            {/* Message list */}
            <div
              className="cymind-scroll"
              style={{
                flex: 1, overflowY: "auto", padding: "12px 14px",
                display: "flex", flexDirection: "column", gap: 10,
              }}
            >
              {messages.map((msg, i) => (
                <div
                  key={i}
                  style={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                  }}
                >
                  {/* ── Action confirm card ── */}
                  {msg.role === "action_card" && msg.actionPending ? (
                    <div style={{ maxWidth: "95%", width: "100%" }}>
                      {/* Show any text tokens that appeared before the action card */}
                      {msg.content && (
                        <div style={{
                          background: "rgba(255,255,255,0.04)",
                          border: "1px solid rgba(255,255,255,0.07)",
                          borderRadius: "10px 10px 0 2px",
                          padding: "8px 12px", fontSize: 12, lineHeight: 1.65,
                          color: "rgba(255,255,255,0.7)", marginBottom: 6,
                          fontFamily: "system-ui, sans-serif", whiteSpace: "pre-wrap",
                        }}>
                          <MsgText text={msg.content} />
                        </div>
                      )}
                      <ActionConfirmCard
                        action={msg.actionPending}
                        status={actionCards[i]?.status || "pending"}
                        result={actionCards[i]?.result || null}
                        onConfirm={() => handleActionConfirm(i)}
                        onCancel={() => handleActionCancel(i)}
                      />
                    </div>
                  ) : (
                    /* ── Regular message bubble ── */
                    <div style={{
                      maxWidth: "85%",
                      background: msg.role === "user"
                        ? "rgba(0,229,160,0.12)"
                        : msg.error
                          ? "rgba(255,59,59,0.08)"
                          : "rgba(255,255,255,0.04)",
                      border: `1px solid ${msg.role === "user" ? "rgba(0,229,160,0.2)" : msg.error ? "rgba(255,59,59,0.2)" : "rgba(255,255,255,0.07)"}`,
                      borderRadius: msg.role === "user" ? "10px 10px 2px 10px" : "10px 10px 10px 2px",
                      padding: "8px 12px",
                      fontSize: 12,
                      lineHeight: 1.65,
                      color: msg.role === "user"
                        ? "rgba(255,255,255,0.8)"
                        : msg.error
                          ? "#ff6b6b"
                          : "rgba(255,255,255,0.7)",
                      fontFamily: "system-ui, sans-serif",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                    }}>
                      <span className={(!msg.done && msg.role === "assistant") ? "cymind-msg-blink" : ""}>
                        <MsgText text={msg.content} />
                      </span>
                    </div>
                  )}
                </div>
              ))}
              <div ref={bottomRef} />
            </div>

            {/* Input bar */}
            <div style={{
              flexShrink: 0,
              borderTop: "1px solid rgba(0,229,160,0.12)",
              padding: "10px 12px",
              display: "flex", gap: 8, alignItems: "flex-end",
              background: "rgba(0,0,0,0.2)",
            }}>
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about incidents, alerts, agents, CVEs…"
                rows={1}
                disabled={streaming}
                style={{
                  flex: 1,
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(0,229,160,0.15)",
                  borderRadius: 6,
                  color: "rgba(255,255,255,0.8)",
                  fontSize: 12,
                  fontFamily: "system-ui, sans-serif",
                  padding: "8px 10px",
                  resize: "none",
                  outline: "none",
                  minHeight: 36,
                  maxHeight: 100,
                  overflowY: "auto",
                  lineHeight: 1.5,
                }}
                onInput={e => {
                  e.target.style.height = "auto";
                  e.target.style.height = Math.min(e.target.scrollHeight, 100) + "px";
                }}
                onFocus={e  => e.target.style.borderColor = "rgba(0,229,160,0.4)"}
                onBlur={e   => e.target.style.borderColor = "rgba(0,229,160,0.15)"}
              />
              <button
                onClick={streaming ? () => abortRef.current?.abort() : sendMessage}
                disabled={!streaming && !input.trim()}
                title={streaming ? "Stop" : "Send (Enter)"}
                style={{
                  flexShrink: 0,
                  width: 36, height: 36,
                  background: streaming ? "rgba(255,59,59,0.15)" : "rgba(0,229,160,0.15)",
                  border: `1px solid ${streaming ? "rgba(255,59,59,0.3)" : "rgba(0,229,160,0.3)"}`,
                  borderRadius: 6,
                  cursor: (!streaming && !input.trim()) ? "default" : "pointer",
                  opacity: (!streaming && !input.trim()) ? 0.3 : 1,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "opacity 0.15s",
                }}
              >
                {streaming ? (
                  // Stop icon
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="#ff6b6b">
                    <rect x="4" y="4" width="16" height="16" rx="2"/>
                  </svg>
                ) : (
                  // Send icon
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="2">
                    <line x1="22" y1="2" x2="11" y2="13"/>
                    <polygon points="22 2 15 22 11 13 2 9 22 2"/>
                  </svg>
                )}
              </button>
            </div>
          </>
        )}
      </div>
    </>
  );
}
