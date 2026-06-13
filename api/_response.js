export function sendJson(response, status, payload) {
  response.status(status).json(payload);
}

export function sendError(response, error) {
  response.status(error.status || 500).json({ error: error.message || "Serverfehler." });
}
