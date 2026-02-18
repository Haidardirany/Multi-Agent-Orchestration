import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import multer from "multer";
import { z } from "zod";
import { Pool } from "pg";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);

const port = Number(process.env.BACKEND_PORT || 3000);
const databaseUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET || "dev_change_me";
const cookieName = process.env.COOKIE_NAME || "ft_auth";
const cookieSecure = String(process.env.COOKIE_SECURE || "false") === "true";
const uploadDir = process.env.UPLOAD_DIR || "/app/uploads";
const maxUploadMb = Number(process.env.MAX_UPLOAD_MB || 5);
const corsOrigin = process.env.CORS_ORIGIN || "http://localhost:8080";

if (!databaseUrl) {
  console.error("Missing DATABASE_URL");
  process.exit(1);
}

fs.mkdirSync(uploadDir, { recursive: true });

const pool = new Pool({ connectionString: databaseUrl });

app.use(helmet());
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(cors({ origin: corsOrigin, credentials: true }));

app.use("/uploads", express.static(uploadDir, { fallthrough: false }));

const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

async function dbQuery(text, params) {
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, jwtSecret, { expiresIn: "7d" });
}

function setAuthCookie(res, token) {
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: "lax",
    path: "/"
  });
}

function clearAuthCookie(res) {
  res.clearCookie(cookieName, { path: "/" });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.[cookieName];
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  try {
    const payload = jwt.verify(token, jwtSecret);
    req.user = { id: payload.sub, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid session" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });
    if (req.user.role !== role) return res.status(403).json({ error: "Forbidden" });
    return next();
  };
}

async function auditToolCall(userId, toolName, args) {
  await dbQuery(
    `INSERT INTO audit_logs (user_id, action, tool, request_json)
     VALUES ($1, 'tool_call', $2, $3::jsonb)`,
    [userId ?? null, toolName, JSON.stringify(args ?? {})]
  );
}

/* ---------------------------
   Schemas
---------------------------- */
const signupSchema = z.object({
  email: z.string().email().max(254),
  username: z.string().min(3).max(32).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(8).max(128)
});

const loginSchema = z.object({
  emailOrUsername: z.string().min(3).max(254),
  password: z.string().min(1).max(128)
});

const profileSchema = z.object({
  displayName: z.string().min(1).max(64).optional(),
  bio: z.string().max(240).optional()
});

const assistantSchema = z.object({
  message: z.string().min(1).max(4000)
});

/* ---------------------------
   Health
---------------------------- */
app.get("/health", (_req, res) => res.json({ ok: true }));

/* ---------------------------
   Auth
---------------------------- */
app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });

  const { email, username, password } = parsed.data;
  const passwordHash = await bcrypt.hash(password, 12);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const userResult = await client.query(
      `INSERT INTO users (email, username, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email, username, role, created_at`,
      [email.toLowerCase(), username, passwordHash]
    );

    const user = userResult.rows[0];

    await client.query(
      `INSERT INTO profiles (user_id, display_name, bio, avatar_path)
       VALUES ($1, $2, $3, $4)`,
      [user.id, username, "", null]
    );

    await client.query("COMMIT");

    const token = signToken(user);
    setAuthCookie(res, token);

    return res.status(201).json({ user });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err?.code === "23505") return res.status(409).json({ error: "Email or username already exists" });
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });

  const { emailOrUsername, password } = parsed.data;

  const result = await dbQuery(
    `SELECT id, email, username, password_hash, role, created_at
     FROM users
     WHERE lower(email) = lower($1) OR username = $1
     LIMIT 1`,
    [emailOrUsername]
  );

  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = signToken(user);
  setAuthCookie(res, token);

  const safeUser = { id: user.id, email: user.email, username: user.username, role: user.role, created_at: user.created_at };
  return res.json({ user: safeUser });
});

app.post("/api/auth/logout", (req, res) => {
  clearAuthCookie(res);
  return res.json({ ok: true });
});

/* ---------------------------
   Me / Profile
---------------------------- */
app.get("/api/me", requireAuth, async (req, res) => {
  const result = await dbQuery(
    `SELECT u.id, u.email, u.username, u.role, u.created_at,
            p.display_name, p.bio, p.avatar_path
     FROM users u
     JOIN profiles p ON p.user_id = u.id
     WHERE u.id = $1`,
    [req.user.id]
  );
  if (result.rowCount === 0) return res.status(404).json({ error: "User not found" });
  return res.json({ me: result.rows[0] });
});

app.patch("/api/me/profile", requireAuth, async (req, res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });

  const { displayName, bio } = parsed.data;

  const result = await dbQuery(
    `UPDATE profiles
     SET display_name = COALESCE($2, display_name),
         bio = COALESCE($3, bio)
     WHERE user_id = $1
     RETURNING user_id, display_name, bio, avatar_path, updated_at`,
    [req.user.id, displayName, bio]
  );

  return res.json({ profile: result.rows[0] });
});

/* ---------------------------
   Avatar upload (disk)
---------------------------- */
const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase() || ".bin";
    const safeExt = [".png", ".jpg", ".jpeg", ".webp", ".gif"].includes(ext) ? ext : ".bin";
    cb(null, `${crypto.randomUUID()}${safeExt}`);
  }
});

const avatarUpload = multer({
  storage: avatarStorage,
  limits: { fileSize: maxUploadMb * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ["image/png", "image/jpeg", "image/webp", "image/gif"].includes(file.mimetype);
    cb(ok ? null : new Error("Invalid file type"), ok);
  }
});

app.post("/api/me/avatar", requireAuth, avatarUpload.single("avatar"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const publicPath = `/uploads/${req.file.filename}`;

  const result = await dbQuery(
    `UPDATE profiles
     SET avatar_path = $2
     WHERE user_id = $1
     RETURNING user_id, avatar_path, updated_at`,
    [req.user.id, publicPath]
  );

  return res.json({ avatar: result.rows[0] });
});

/* ---------------------------
   RAG: KB ingest + search
---------------------------- */
function chunkText(text, maxChars = 800) {
  const blocks = String(text || "")
    .replace(/\r\n/g, "\n")
    .split(/\n\s*\n/g)
    .map(s => s.trim())
    .filter(Boolean);

  const chunks = [];
  for (const block of blocks) {
    if (block.length <= maxChars) {
      chunks.push(block);
    } else {
      for (let i = 0; i < block.length; i += maxChars) {
        chunks.push(block.slice(i, i + maxChars));
      }
    }
  }
  return chunks.slice(0, 2000);
}

// KB upload: accept text file (txt/md) OR JSON {title, content}
const kbUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const ok = ["text/plain", "text/markdown", "application/octet-stream"].includes(file.mimetype);
    cb(ok ? null : new Error("Invalid KB file type"), ok);
  }
});

app.post("/api/kb/documents", requireAuth, kbUpload.single("file"), async (req, res) => {
  let title = req.body?.title;
  let source = null;
  let content = null;

  if (req.file) {
    source = req.file.originalname || null;
    title = title || source || "Untitled";
    content = req.file.buffer.toString("utf8");
  } else {
    const json = z.object({
      title: z.string().min(1).max(120),
      content: z.string().min(1).max(200000)
    }).safeParse(req.body);

    if (!json.success) return res.status(400).json({ error: "Provide a file or JSON {title, content}" });
    title = json.data.title;
    content = json.data.content;
  }

  const chunks = chunkText(content);

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const docRes = await client.query(
      `INSERT INTO kb_documents (owner_user_id, title, source, content)
       VALUES ($1, $2, $3, $4)
       RETURNING id, title, source, created_at`,
      [req.user.id, title, source, content]
    );

    const doc = docRes.rows[0];

    for (let i = 0; i < chunks.length; i++) {
      await client.query(
        `INSERT INTO kb_chunks (doc_id, chunk_index, content)
         VALUES ($1, $2, $3)`,
        [doc.id, i, chunks[i]]
      );
    }

    await client.query("COMMIT");
    return res.status(201).json({ document: doc, chunks: chunks.length });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    return res.status(500).json({ error: "KB ingest failed" });
  } finally {
    client.release();
  }
});

app.get("/api/kb/search", requireAuth, async (req, res) => {
  const q = String(req.query?.q || "").trim();
  if (!q) return res.status(400).json({ error: "Missing q" });

  const k = Math.min(Number(req.query?.k || 5), 10);

  const result = await dbQuery(
    `SELECT c.id, c.doc_id, c.chunk_index, left(c.content, 400) AS snippet,
            d.title, d.source
     FROM kb_chunks c
     JOIN kb_documents d ON d.id = c.doc_id
     WHERE c.tsv @@ plainto_tsquery('simple', $1)
     ORDER BY ts_rank(c.tsv, plainto_tsquery('simple', $1)) DESC
     LIMIT $2`,
    [q, k]
  );

  return res.json({ query: q, results: result.rows });
});

/* ---------------------------
   Tool layer (MCP-style)
---------------------------- */
const toolDefs = [
  {
    name: "kb.search",
    description: "Search KB chunks using Postgres full-text search.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string" }, k: { type: "number" } },
      required: ["query"]
    }
  },
  {
    name: "user.getProfile",
    description: "Get the authenticated user's profile (least privilege).",
    inputSchema: { type: "object", properties: {}, required: [] }
  },
  {
    name: "tickets.create",
    description: "Create a simple ticket/task for the authenticated user.",
    inputSchema: {
      type: "object",
      properties: { title: { type: "string" }, description: { type: "string" } },
      required: ["title"]
    }
  }
];

async function toolCall(user, name, args) {
  await auditToolCall(user?.id ?? null, name, args);

  if (name === "kb.search") {
    const query = String(args?.query || "").trim();
    const k = Math.min(Number(args?.k || 5), 10);
    if (!query) return { results: [] };

    const result = await dbQuery(
      `SELECT c.id, c.doc_id, c.chunk_index, c.content,
              d.title, d.source
       FROM kb_chunks c
       JOIN kb_documents d ON d.id = c.doc_id
       WHERE c.tsv @@ plainto_tsquery('simple', $1)
       ORDER BY ts_rank(c.tsv, plainto_tsquery('simple', $1)) DESC
       LIMIT $2`,
      [query, k]
    );

    return { results: result.rows.map(r => ({
      chunkId: r.id,
      docId: r.doc_id,
      title: r.title,
      source: r.source,
      chunkIndex: r.chunk_index,
      content: r.content
    })) };
  }

  if (name === "user.getProfile") {
    const result = await dbQuery(
      `SELECT u.id, u.email, u.username, u.role,
              p.display_name, p.bio, p.avatar_path
       FROM users u
       JOIN profiles p ON p.user_id = u.id
       WHERE u.id = $1`,
      [user.id]
    );
    return { profile: result.rows[0] ?? null };
  }

  if (name === "tickets.create") {
    const title = String(args?.title || "").trim();
    const description = String(args?.description || "").trim();
    if (!title) throw new Error("Missing title");

    const result = await dbQuery(
      `INSERT INTO tickets (owner_user_id, title, description)
       VALUES ($1, $2, $3)
       RETURNING id, title, status, created_at`,
      [user.id, title, description || null]
    );
    return { ticket: result.rows[0] };
  }

  throw new Error("Unknown tool");
}

// MCP-like JSON-RPC endpoint
app.post("/api/mcp", requireAuth, async (req, res) => {
  const rpc = req.body || {};
  const id = rpc.id ?? null;

  try {
    if (rpc.jsonrpc !== "2.0") throw new Error("Invalid jsonrpc");

    if (rpc.method === "tools/list") {
      return res.json({ jsonrpc: "2.0", id, result: { tools: toolDefs } });
    }

    if (rpc.method === "tools/call") {
      const name = rpc.params?.name;
      const args = rpc.params?.arguments ?? {};
      const result = await toolCall(req.user, name, args);
      return res.json({ jsonrpc: "2.0", id, result });
    }

    throw new Error("Method not found");
  } catch (e) {
    return res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32602, message: e?.message || "RPC error" }
    });
  }
});

/* ---------------------------
   Orchestrator + “agents”
---------------------------- */
function pickRoute(message) {
  const m = message.toLowerCase();
  if (m.includes("create ticket") || m.includes("open ticket") || m.startsWith("ticket:")) return "ticket_agent";
  if (m.includes("my profile") || m.includes("my bio") || m.includes("my avatar")) return "profile_agent";
  return "rag_agent";
}

// Minimal “LLM” response generator (placeholder). Replace later with a real model.
function synthesizeAnswer({ message, route, profile, citations, ticket }) {
  let out = "";

  if (route === "profile_agent") {
    out += "Here is your current profile data (authorized):\n\n";
    out += JSON.stringify(profile, null, 2);
    return out;
  }

  if (route === "ticket_agent") {
    out += "Ticket created.\n\n";
    out += `ID: ${ticket.id}\nTitle: ${ticket.title}\nStatus: ${ticket.status}\nCreated: ${ticket.created_at}\n`;
    return out;
  }

  // rag_agent
  out += "Answer (grounded from the knowledge base):\n\n";
  out += `You asked: "${message}"\n\n`;

  if (!citations.length) {
    out += "I could not find relevant passages in the current knowledge base.\n";
    out += "Upload documents first, or rephrase the query.\n";
    return out;
  }

  out += "Relevant passages:\n\n";
  citations.slice(0, 3).forEach((c, i) => {
    out += `[#${i + 1}] ${c.title}${c.source ? ` (${c.source})` : ""} — chunk ${c.chunkIndex}\n`;
    out += c.content.slice(0, 600) + "\n\n";
  });

  out += "Citations:\n";
  citations.slice(0, 3).forEach((c, i) => {
    out += `  [#${i + 1}] doc="${c.title}", chunkId=${c.chunkId}\n`;
  });

  return out;
}

/* ---------------------------
   Assistant endpoints
---------------------------- */
app.post("/api/assistant", requireAuth, async (req, res) => {
  const parsed = assistantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const message = parsed.data.message;
  const route = pickRoute(message);

  if (route === "profile_agent") {
    const profileRes = await toolCall(req.user, "user.getProfile", {});
    return res.json({ route, answer: synthesizeAnswer({ message, route, profile: profileRes.profile, citations: [] }) });
  }

  if (route === "ticket_agent") {
    const title = message.replace(/^ticket:\s*/i, "").slice(0, 120) || "New ticket";
    const ticketRes = await toolCall(req.user, "tickets.create", { title, description: message });
    return res.json({ route, answer: synthesizeAnswer({ message, route, ticket: ticketRes.ticket, citations: [] }) });
  }

  const kb = await toolCall(req.user, "kb.search", { query: message, k: 5 });
  const answer = synthesizeAnswer({ message, route, citations: kb.results });
  return res.json({ route, answer, citations: kb.results.slice(0, 3) });
});

// Streaming (SSE)
app.post("/api/assistant/stream", requireAuth, async (req, res) => {
  const parsed = assistantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });

  const message = parsed.data.message;
  const route = pickRoute(message);

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const send = (event, data) => {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  send("meta", { route });

  try {
    let payload = { message, route, citations: [] };

    if (route === "profile_agent") {
      const profileRes = await toolCall(req.user, "user.getProfile", {});
      payload.profile = profileRes.profile;
    } else if (route === "ticket_agent") {
      const title = message.replace(/^ticket:\s*/i, "").slice(0, 120) || "New ticket";
      const ticketRes = await toolCall(req.user, "tickets.create", { title, description: message });
      payload.ticket = ticketRes.ticket;
    } else {
      const kb = await toolCall(req.user, "kb.search", { query: message, k: 5 });
      payload.citations = kb.results.slice(0, 3);
    }

    const full = synthesizeAnswer(payload);

    // Stream the answer in chunks (placeholder for token streaming)
    const chunkSize = 120;
    for (let i = 0; i < full.length; i += chunkSize) {
      send("delta", { text: full.slice(i, i + chunkSize) });
      await new Promise(r => setTimeout(r, 20));
    }

    send("done", { ok: true, citations: payload.citations || [] });
    res.end();
  } catch (e) {
    send("error", { message: e?.message || "Assistant error" });
    res.end();
  }
});

/* ---------------------------
   Permissions demo
---------------------------- */
app.get("/api/admin/ping", requireAuth, requireRole("admin"), (_req, res) => {
  return res.json({ ok: true, admin: true });
});

/* ---------------------------
   Upload error handler
---------------------------- */
app.use((err, _req, res, _next) => {
  if (err?.message === "Invalid file type" || err?.message === "Invalid KB file type") return res.status(400).json({ error: err.message });
  if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "File too large" });
  return res.status(500).json({ error: "Server error" });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Backend listening on :${port}`);
});
const ollamaBaseUrl = process.env.OLLAMA_BASE_URL || "http://host.docker.internal:11434";
const ollamaModel = process.env.OLLAMA_MODEL || "llama3.2:3b";
const ollamaTemperature = Number(process.env.OLLAMA_TEMPERATURE || 0.2);
const ollamaKeepAlive = process.env.OLLAMA_KEEP_ALIVE || "5m";
