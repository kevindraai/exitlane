export function formatRelativeTime(value, now = Date.now(), translate = (_key, _variables, fallback) => fallback) {
  if (!value) return translate("dashboard.time.no_handshake", {}, "No handshake");
  const seconds = Math.max(0, Math.floor((now - new Date(value).getTime()) / 1000));
  const units = [[86400, "days"], [3600, "hours"], [60, "minutes"], [1, "seconds"]];
  const [size, key] = units.find(([unit]) => seconds >= unit) || units.at(-1);
  const count = Math.floor(seconds / size);
  return translate(`dashboard.time.${key}_ago`, { count }, `${count} ${key} ago`);
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
