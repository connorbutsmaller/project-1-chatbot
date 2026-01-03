const API_URL = "http://127.0.0.1:8000";

export interface Session {
  id: number;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface Message {
  id: number;
  sender: "user" | "bot";
  content: string;
  timestamp: string;
}

export async function register(email: string, password: string) {
  const res = await fetch(`${API_URL}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) throw new Error("Register failed");
  return res.json();
}

export async function login(email: string, password: string) {
  const res = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: email, password }),
  });
  if (!res.ok) throw new Error("Login failed");
  return res.json() as Promise<{ access_token: string; token_type: string }>;
}

function authHeaders(token: string) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

export async function listSessions(token: string) {
  const res = await fetch(`${API_URL}/sessions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to load sessions");
  return res.json() as Promise<Session[]>;
}

export async function createSession(token: string, title: string) {
  const res = await fetch(`${API_URL}/sessions`, {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({ title }),
  });
  if (!res.ok) throw new Error("Failed to create session");
  return res.json() as Promise<Session>;
}

export async function getSession(token: string, id: number) {
  const res = await fetch(`${API_URL}/sessions/${id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to load session");
  return res.json() as Promise<{ messages: Message[] } & Session>;
}

export async function sendMessage(token: string, id: number, content: string) {
  const res = await fetch(`${API_URL}/sessions/${id}/messages`, {
    method: "POST",
    headers: authHeaders(token),
    body: JSON.stringify({ content }),
  });
  if (!res.ok) throw new Error("Failed to send message");
  return res.json() as Promise<{ user_message: Message; bot_message: Message }>;
}
