export class ApiError extends Error {
  constructor(message, status, payload = null, code = "request_failed") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
    this.code = code;
  }
}

const inFlightGets = new Map();
const DEFAULT_TIMEOUT = 15000;

export function clearInFlightRequests() {
  inFlightGets.clear();
}

export async function api(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const deduplicate = method === "GET" && options.deduplicate !== false && !options.signal;
  const key = `${method}:${path}`;
  if (deduplicate && inFlightGets.has(key)) return inFlightGets.get(key);

  const request = performRequest(path, options);
  if (deduplicate) {
    inFlightGets.set(key, request);
    request.finally(() => inFlightGets.delete(key)).catch(() => {});
  }
  return request;
}

async function performRequest(path, options) {
  const controller = new AbortController();
  const timeoutMilliseconds = options.timeoutMilliseconds ?? DEFAULT_TIMEOUT;
  const timeout = setTimeout(() => controller.abort("timeout"), timeoutMilliseconds);
  const onAbort = () => controller.abort(options.signal?.reason || "aborted");
  options.signal?.addEventListener("abort", onAbort, { once: true });
  const requestOptions = {
    ...options,
    signal: controller.signal,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  };
  delete requestOptions.timeoutMilliseconds;
  delete requestOptions.deduplicate;

  let response;
  try {
    response = await fetch(path, requestOptions);
  } catch (error) {
    if (controller.signal.aborted) {
      const timedOut = controller.signal.reason === "timeout";
      throw new ApiError(timedOut ? "Request timed out." : "Request aborted.", 0, null, timedOut ? "timeout" : "aborted");
    }
    throw new ApiError("The service is unavailable.", 0, null, "network_error");
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", onAbort);
  }
  const contentType = response.headers.get("content-type") || "";

  let payload;
  if (contentType.includes("application/json")) {
    payload = await response.json().catch(() => ({}));
  } else {
    payload = await response.text();
  }

  if (!response.ok) {
    const message = response.status === 401 ? "Authentication required." : `Request failed (${response.status}).`;

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
