export class ApiError extends Error {
  constructor(message, status, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export async function api(path, options = {}) {
  const requestOptions = {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  };

  const response = await fetch(path, requestOptions);
  const contentType = response.headers.get("content-type") || "";

  let payload;
  if (contentType.includes("application/json")) {
    payload = await response.json().catch(() => ({}));
  } else {
    payload = await response.text();
  }

  if (!response.ok) {
    const message =
      typeof payload === "object"
        ? payload.detail || payload.message || `HTTP ${response.status}`
        : payload || `HTTP ${response.status}`;

    const error = new ApiError(message, response.status, payload);
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("exitlane:authenticationrequired"));
    }
    throw error;
  }

  return payload;
}

export function postJson(path, body = undefined) {
  return api(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
