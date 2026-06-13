import { publicUser, tokenFromRequest, userFromToken } from "../lib/store.js";
import { sendError, sendJson } from "./_response.js";

export default async function handler(request, response) {
  if (request.method !== "GET") return sendJson(response, 405, { error: "Methode nicht erlaubt." });
  try {
    const user = await userFromToken(tokenFromRequest(request));
    if (!user) return sendJson(response, 401, { error: "Nicht eingeloggt." });
    return sendJson(response, 200, { user: publicUser(user) });
  } catch (error) {
    return sendError(response, error);
  }
}
