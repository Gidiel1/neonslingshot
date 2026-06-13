import { saveUserData, tokenFromRequest } from "../lib/store.js";
import { sendError, sendJson } from "./_response.js";

export default async function handler(request, response) {
  if (request.method !== "POST") return sendJson(response, 405, { error: "Methode nicht erlaubt." });
  try {
    await saveUserData(tokenFromRequest(request), request.body || {});
    return sendJson(response, 200, { ok: true });
  } catch (error) {
    return sendError(response, error);
  }
}
