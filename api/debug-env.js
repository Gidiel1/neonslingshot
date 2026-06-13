import { sendJson } from "./_response.js";

export default function handler(request, response) {
  if (request.method !== "GET") return sendJson(response, 405, { error: "Methode nicht erlaubt." });
  const databaseUrl = process.env.DATABASE_URL || "";
  let host = "";
  let protocol = "";
  let database = "";
  let parseError = "";

  try {
    if (databaseUrl) {
      const parsed = new URL(databaseUrl);
      host = parsed.hostname;
      protocol = parsed.protocol;
      database = parsed.pathname.replace("/", "");
    }
  } catch (error) {
    parseError = error.message;
  }

  return sendJson(response, 200, {
    databaseUrlSet: Boolean(databaseUrl),
    protocol,
    host,
    database,
    parseError,
    hint: "Diese Route zeigt absichtlich kein Passwort und keine komplette DATABASE_URL."
  });
}
