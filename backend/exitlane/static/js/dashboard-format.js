export function normaliseTimestamp(value) {
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? timestamp : null;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    return Math.abs(value) < 1e12 ? value * 1000 : value;
  }
  if (typeof value !== "string" || !value.trim()) return null;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return normaliseTimestamp(numeric);
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

export function formatRelativeTime(value, now = Date.now(), translate = (_key, _variables, fallback) => fallback) {
  const timestamp = normaliseTimestamp(value);
  const currentTimestamp = normaliseTimestamp(now);
  if (timestamp === null || currentTimestamp === null) {
    return translate("dashboard.time.no_handshake", {}, "No handshake");
  }
  const seconds = Math.max(0, Math.floor((currentTimestamp - timestamp) / 1000));
  if (seconds <= 1) return translate("dashboard.time.just_now", {}, "just now");
  const units = [[86400, "days"], [3600, "hours"], [60, "minutes"], [1, "seconds"]];
  const [size, key] = units.find(([unit]) => seconds >= unit) || units.at(-1);
  const count = Math.floor(seconds / size);
  const translationKey = count === 1 && key !== "seconds" ? key.slice(0, -1) : key;
  const fallbackUnit = count === 1 ? key.slice(0, -1) : key;
  return translate(`dashboard.time.${translationKey}_ago`, { count }, `${count} ${fallbackUnit} ago`);
}

export function formatBytes(bytes) {
  const value = Math.max(0, Number(bytes || 0));
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(Math.max(value, 1)) / Math.log(1024)), units.length - 1);
  const scaled = value / (1024 ** index);
  return `${index === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[index]}`;
}

export function formatDuration(seconds) {
  const value = Math.max(0, Math.floor(Number(seconds || 0)));
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  return days ? `${days}d ${hours}h` : hours ? `${hours}h ${minutes}m` : `${minutes}m`;
}
