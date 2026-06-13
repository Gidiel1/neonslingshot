import { loginUser } from "../lib/store.js";
import { sendError, sendJson } from "./_response.js";

export default async function handler(request, response) {
  if (request.method !== "POST") return sendJson(response, 405, { error: "Methode nicht erlaubt." });
  try {
    return sendJson(response, 200, await loginUser(request.body || {}));
  } catch (error) {
    return sendError(response, error);
  }
}
