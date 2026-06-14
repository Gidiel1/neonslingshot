import { pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const rootDir = resolve(".");
const dataDir = join(rootDir, "data");
const dbPath = join(dataDir, "db.json");
let db = null;
let pool = null;
let schemaReady = false;

const maxSaveFields = [
  "totalStars",
  "chaosBest",
  "itemsBest",
  "colorHuntBest",
  "flowBest",
  "stillBest",
  "classicBestScore",
  "bestRunStars",
  "classicBestCombo",
  "solarBestScore",
  "magentaBestScore",
  "itemsNoItemBestScore",
  "strengthMeteorBest",
  "planetDestroyCount"
];

const arraySaveFields = [
  "claimedChallenges",
  "completedChallenges",
  "unlockedColors",
  "unlockedShapes",
  "unlockedTrails"
];

const leaderboardToSaveFields = {
  classic: "classicBestScore",
  items: "itemsBest",
  flow: "flowBest",
  colorHunt: "colorHuntBest",
  chaos: "chaosBest"
};

function emptyDb() {
  return { users: [], sessions: {} };
}

function loadFileDb() {
  if (db) return db;
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  if (!existsSync(dbPath)) {
    writeFileSync(dbPath, JSON.stringify(emptyDb(), null, 2));
  }
  try {
    db = JSON.parse(readFileSync(dbPath, "utf8"));
  } catch {
    db = emptyDb();
  }
  return db;
}

function saveFileDb() {
  if (!db) return;
  writeFileSync(dbPath, JSON.stringify(db, null, 2));
}

async function getPool() {
  if (!process.env.DATABASE_URL) return null;
  if (pool) return pool;
  const { Pool } = await import("pg");
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }
  });
  return pool;
}

async function ensureSchema() {
  const activePool = await getPool();
  if (!activePool || schemaReady) return activePool;
  await activePool.query(`
    create table if not exists users (
      id text primary key,
      username text not null,
      username_lower text unique not null,
      password_hash text not null,
      save jsonb not null default '{}'::jsonb,
      leaderboard jsonb not null default '{}'::jsonb,
      created_at bigint not null,
      updated_at bigint not null
    );
    create table if not exists sessions (
      token text primary key,
      user_id text not null references users(id) on delete cascade,
      created_at bigint not null
    );
  `);
  schemaReady = true;
  return activePool;
}

export function normalizeUsername(username) {
  return String(username || "").trim().slice(0, 18);
}

export function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const candidate = hashPassword(password, salt).split(":")[1];
  const left = Buffer.from(candidate, "hex");
  const right = Buffer.from(hash, "hex");
  return left.length === right.length && timingSafeEqual(left, right);
}

function maxNumber(...values) {
  return Math.max(0, ...values.map((value) => Number(value || 0)).filter(Number.isFinite));
}

function mergeArrays(...arrays) {
  return [...new Set(arrays.flatMap((items) => (Array.isArray(items) ? items : [])))];
}

function normalizeSaveWithLeaderboard(save = {}, leaderboard = {}) {
  const merged = { ...save };
  for (const [leaderboardKey, saveKey] of Object.entries(leaderboardToSaveFields)) {
    merged[saveKey] = maxNumber(merged[saveKey], leaderboard[leaderboardKey]);
  }
  merged.classicBestCombo = Math.max(1, Number(merged.classicBestCombo || 1));
  merged.unlockedColors = mergeArrays(["standard"], merged.unlockedColors);
  merged.unlockedShapes = mergeArrays(["orb"], merged.unlockedShapes);
  merged.unlockedTrails = mergeArrays(["classic"], merged.unlockedTrails);
  return merged;
}

function mergeSaveProfiles(current = {}, incoming = {}) {
  const merged = { ...current, ...incoming };
  for (const field of maxSaveFields) {
    merged[field] = field === "classicBestCombo"
      ? Math.max(1, maxNumber(current[field], incoming[field]))
      : maxNumber(current[field], incoming[field]);
  }
  for (const field of arraySaveFields) {
    merged[field] = mergeArrays(current[field], incoming[field]);
  }
  merged.unlockedColors = mergeArrays(["standard"], merged.unlockedColors);
  merged.unlockedShapes = mergeArrays(["orb"], merged.unlockedShapes);
  merged.unlockedTrails = mergeArrays(["classic"], merged.unlockedTrails);
  if (!merged.unlockedColors.includes(merged.selectedColor)) merged.selectedColor = current.selectedColor || "standard";
  if (!merged.unlockedShapes.includes(merged.selectedShape)) merged.selectedShape = current.selectedShape || "orb";
  if (!merged.unlockedTrails.includes(merged.selectedTrail)) merged.selectedTrail = current.selectedTrail || "classic";
  merged.rainbowUnlocked = Boolean(current.rainbowUnlocked || incoming.rainbowUnlocked || merged.unlockedTrails.includes("rainbow"));
  return merged;
}

function mergeLeaderboards(current = {}, incoming = {}) {
  const merged = { ...current, ...incoming };
  for (const key of Object.keys(leaderboardToSaveFields)) {
    merged[key] = maxNumber(current[key], incoming[key]);
  }
  return merged;
}

export function publicUser(user) {
  const leaderboard = user.leaderboard || {};
  return {
    id: user.id,
    username: user.username,
    save: normalizeSaveWithLeaderboard(user.save || {}, leaderboard),
    leaderboard
  };
}

function fromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    save: row.save || {},
    leaderboard: row.leaderboard || {}
  };
}

export function tokenFromRequest(request) {
  const auth = request.headers.authorization || "";
  return auth.startsWith("Bearer ") ? auth.slice(7) : "";
}

export async function readJson(request) {
  if (request.body && typeof request.body === "object") return request.body;
  if (typeof request.body === "string") return request.body ? JSON.parse(request.body) : {};
  let body = "";
  for await (const chunk of request) body += chunk;
  return body ? JSON.parse(body) : {};
}

export async function createUser({ username, password, save }) {
  const cleanName = normalizeUsername(username);
  if (cleanName.length < 3) {
    const error = new Error("Der Name muss mindestens 3 Zeichen haben.");
    error.status = 400;
    throw error;
  }
  if (String(password || "").length < 4) {
    const error = new Error("Das Passwort muss mindestens 4 Zeichen haben.");
    error.status = 400;
    throw error;
  }

  const activePool = await ensureSchema();
  const id = randomBytes(12).toString("hex");
  const token = randomBytes(24).toString("hex");
  const now = Date.now();
  const passwordHash = hashPassword(password);
  const cleanSave = normalizeSaveWithLeaderboard(save && typeof save === "object" ? save : {}, {});

  if (activePool) {
    try {
      const result = await activePool.query(
        `insert into users (id, username, username_lower, password_hash, save, leaderboard, created_at, updated_at)
         values ($1, $2, $3, $4, $5, '{}'::jsonb, $6, $6)
         returning *`,
        [id, cleanName, cleanName.toLowerCase(), passwordHash, cleanSave, now]
      );
      await activePool.query("insert into sessions (token, user_id, created_at) values ($1, $2, $3)", [token, id, now]);
      return { token, user: publicUser(fromRow(result.rows[0])) };
    } catch (error) {
      if (error.code === "23505") {
        const conflict = new Error("Dieser Name ist schon vergeben.");
        conflict.status = 409;
        throw conflict;
      }
      throw error;
    }
  }

  const fileDb = loadFileDb();
  if (fileDb.users.some((user) => user.username.toLowerCase() === cleanName.toLowerCase())) {
    const error = new Error("Dieser Name ist schon vergeben.");
    error.status = 409;
    throw error;
  }
  const user = { id, username: cleanName, passwordHash, save: cleanSave, leaderboard: {}, createdAt: now, updatedAt: now };
  fileDb.users.push(user);
  fileDb.sessions[token] = user.id;
  saveFileDb();
  return { token, user: publicUser(user) };
}

export async function loginUser({ username, password }) {
  const cleanName = normalizeUsername(username);
  const activePool = await ensureSchema();
  const now = Date.now();
  const token = randomBytes(24).toString("hex");

  if (activePool) {
    const result = await activePool.query("select * from users where username_lower = $1 limit 1", [cleanName.toLowerCase()]);
    const user = fromRow(result.rows[0]);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      const error = new Error("Name oder Passwort stimmt nicht.");
      error.status = 401;
      throw error;
    }
    await activePool.query("insert into sessions (token, user_id, created_at) values ($1, $2, $3)", [token, user.id, now]);
    return { token, user: publicUser(user) };
  }

  const fileDb = loadFileDb();
  const user = fileDb.users.find((item) => item.username.toLowerCase() === cleanName.toLowerCase());
  if (!user || !verifyPassword(password, user.passwordHash)) {
    const error = new Error("Name oder Passwort stimmt nicht.");
    error.status = 401;
    throw error;
  }
  fileDb.sessions[token] = user.id;
  saveFileDb();
  return { token, user: publicUser(user) };
}

export async function userFromToken(token) {
  if (!token) return null;
  const activePool = await ensureSchema();
  if (activePool) {
    const result = await activePool.query(
      `select users.* from sessions join users on users.id = sessions.user_id where sessions.token = $1 limit 1`,
      [token]
    );
    return fromRow(result.rows[0]);
  }
  const fileDb = loadFileDb();
  const userId = fileDb.sessions[token];
  return userId ? fileDb.users.find((user) => user.id === userId) : null;
}

export async function saveUserData(token, { save, leaderboard }) {
  const user = await userFromToken(token);
  if (!user) {
    const error = new Error("Nicht eingeloggt.");
    error.status = 401;
    throw error;
  }
  const incomingSave = save && typeof save === "object" ? save : {};
  const incomingLeaderboard = leaderboard && typeof leaderboard === "object" ? leaderboard : {};
  const cleanLeaderboard = mergeLeaderboards(user.leaderboard || {}, incomingLeaderboard);
  const cleanSave = normalizeSaveWithLeaderboard(mergeSaveProfiles(user.save || {}, incomingSave), cleanLeaderboard);
  const activePool = await ensureSchema();
  if (activePool) {
    await activePool.query(
      "update users set save = $1, leaderboard = $2, updated_at = $3 where id = $4",
      [cleanSave, cleanLeaderboard, Date.now(), user.id]
    );
    return;
  }
  const fileDb = loadFileDb();
  const fileUser = fileDb.users.find((item) => item.id === user.id);
  fileUser.save = cleanSave;
  fileUser.leaderboard = cleanLeaderboard;
  fileUser.updatedAt = Date.now();
  saveFileDb();
}

function leaderboardScoreExpression(mode) {
  const saveField = leaderboardToSaveFields[mode];
  if (!saveField) return null;
  return {
    text: `greatest(
      case when (leaderboard ->> $1) ~ '^[0-9]+(\\.[0-9]+)?$' then (leaderboard ->> $1)::numeric else 0 end,
      case when (save ->> $2) ~ '^[0-9]+(\\.[0-9]+)?$' then (save ->> $2)::numeric else 0 end
    )`,
    saveField
  };
}

export async function leaderboardFor(mode, currentToken = "") {
  const activePool = await ensureSchema();
  if (activePool) {
    const expression = leaderboardScoreExpression(mode);
    if (!expression) return [];
    const result = await activePool.query(
      `with scored as (
         select
           users.id,
           users.username,
           ${expression.text} as score,
           rank() over (order by ${expression.text} desc) as rank
         from users
       ),
       active_user as (
         select users.id
         from sessions
         join users on users.id = sessions.user_id
         where sessions.token = $3
         limit 1
       )
       select username, score, rank, id = (select id from active_user) as is_current
       from scored
       where score > 0 and (rank <= 20 or id = (select id from active_user))
       order by score desc
       limit 21`,
      [mode, expression.saveField, currentToken]
    );
    return result.rows.map((row) => ({
      username: row.username,
      score: Number(row.score || 0),
      rank: Number(row.rank || 0),
      isCurrent: Boolean(row.is_current)
    }));
  }
  const saveField = leaderboardToSaveFields[mode];
  const fileDb = loadFileDb();
  const currentUserId = fileDb.sessions[currentToken];
  return fileDb.users
    .map((user) => ({
      id: user.id,
      username: user.username,
      score: maxNumber(user.leaderboard?.[mode], user.save?.[saveField])
    }))
    .filter((row) => row.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((row, index) => ({ ...row, rank: index + 1 }))
    .filter((row) => row.rank <= 20 || row.id === currentUserId)
    .slice(0, 21)
    .map(({ id, username, score, rank }) => ({ username, score, rank, isCurrent: id === currentUserId }));
}
