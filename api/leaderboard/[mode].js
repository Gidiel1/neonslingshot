import { leaderboardFor, tokenFromRequest } from "../../lib/store.js";
import { sendError, sendJson } from "../_response.js";

export default async function handler(request, response) {
  if (request.method !== "GET") return sendJson(response, 405, { error: "Methode nicht erlaubt." });
  try {
    return sendJson(response, 200, { rows: await leaderboardFor(request.query.mode, tokenFromRequest(request)) });
  } catch (error) {
    return sendError(response, error);
  }
}
