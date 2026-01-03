import { useEffect, useState } from "react";
import {
  register,
  login,
  listSessions,
  createSession,
  getSession,
  sendMessage,
  type Session,
  type Message,
} from "./api";

function App() {
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem("jwt")
  );
  const [email, setEmail] = useState("ian@example.com");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");

  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSession, setActiveSession] = useState<Session | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loadingReply, setLoadingReply] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // load sessions when logged in
  useEffect(() => {
    if (!token) return;
    (async () => {
      try {
        const s = await listSessions(token);
        setSessions(s);
        if (s.length > 0) {
          selectSession(s[0].id, token);
        }
      } catch (e) {
        console.error(e);
      }
    })();
  }, [token]);

  async function selectSession(id: number, t = token!) {
    const session = sessions.find((s) => s.id === id);
    if (!session) return;
    setActiveSession(session);
    const full = await getSession(t, id);
    setMessages(full.messages);
  }

  async function handleAuth() {
    try {
      setError(null);
      if (authMode === "register") {
        await register(email, password);
      }
      const { access_token } = await login(email, password);
      setToken(access_token);
      localStorage.setItem("jwt", access_token);
    } catch (e) {
      console.error(e);
      setError("Auth failed. Check email/password.");
    }
  }

  async function handleNewSession() {
    if (!token) return;
    const s = await createSession(token, "New Chat");
    const updated = [s, ...sessions];
    setSessions(updated);
    await selectSession(s.id, token);
  }

  async function handleSend() {
    if (!token || !activeSession || !input.trim()) return;
    setLoadingReply(true);
    try {
      const { user_message, bot_message } = await sendMessage(
        token,
        activeSession.id,
        input.trim()
      );
      setInput("");
      setMessages((prev) => [...prev, user_message, bot_message]);
    } finally {
      setLoadingReply(false);
    }
  }

  function handleLogout() {
    setToken(null);
    localStorage.removeItem("jwt");
    setSessions([]);
    setActiveSession(null);
    setMessages([]);
  }

  // ---------- Auth screen ----------
  if (!token) {
    return (
      <div style={{ maxWidth: 400, margin: "4rem auto", fontFamily: "sans-serif" }}>
        <h1>Project Chatbot</h1>
        <p>{authMode === "login" ? "Log in" : "Register"} with email + password.</p>
        <label>
          Email
          <input
            style={{ width: "100%", marginBottom: 8 }}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            type="password"
            style={{ width: "100%", marginBottom: 8 }}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <p style={{ color: "red" }}>{error}</p>}
        <button onClick={handleAuth}>
          {authMode === "login" ? "Log in" : "Register & Log in"}
        </button>
        <button
          style={{ marginLeft: 8 }}
          onClick={() =>
            setAuthMode((m) => (m === "login" ? "register" : "login"))
          }
        >
          Switch to {authMode === "login" ? "Register" : "Login"}
        </button>
      </div>
    );
  }

  // ---------- Chat screen ----------
  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: "sans-serif" }}>
      {/* sidebar */}
      <div
        style={{
          width: 260,
          borderRight: "1px solid #ddd",
          padding: 16,
          boxSizing: "border-box",
        }}
      >
        <h2>Sessions</h2>
        <button onClick={handleNewSession}>+ New Chat</button>
        <button style={{ marginLeft: 8 }} onClick={handleLogout}>
          Logout
        </button>
        <ul style={{ listStyle: "none", padding: 0, marginTop: 16 }}>
          {sessions.map((s) => (
            <li
              key={s.id}
              onClick={() => selectSession(s.id)}
              style={{
                padding: "8px 4px",
                cursor: "pointer",
                background:
                  activeSession?.id === s.id ? "rgba(0,0,0,0.06)" : "transparent",
              }}
            >
              {s.title} <br />
              <small>{new Date(s.updated_at).toLocaleString()}</small>
            </li>
          ))}
          {sessions.length === 0 && <li>No sessions yet.</li>}
        </ul>
      </div>

      {/* chat pane */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: 16, borderBottom: "1px solid #ddd" }}>
          <h2>{activeSession ? activeSession.title : "No session selected"}</h2>
        </div>
        <div
          style={{
            flex: 1,
            padding: 16,
            overflowY: "auto",
            background: "#f7f7f7",
          }}
        >
          {messages.map((m) => (
            <div
              key={m.id}
              style={{
                marginBottom: 8,
                textAlign: m.sender === "user" ? "right" : "left",
              }}
            >
              <div
                style={{
                  display: "inline-block",
                  padding: "8px 12px",
                  borderRadius: 12,
                  background:
                    m.sender === "user" ? "#007bff" : "white",
                  color: m.sender === "user" ? "white" : "black",
                }}
              >
                {m.content}
              </div>
            </div>
          ))}
          {loadingReply && <p>Bot is thinking…</p>}
        </div>
        <div style={{ padding: 16, borderTop: "1px solid #ddd" }}>
          <input
            style={{ width: "80%", marginRight: 8 }}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Type a message…"
          />
          <button onClick={handleSend} disabled={!activeSession || loadingReply}>
            Send
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
