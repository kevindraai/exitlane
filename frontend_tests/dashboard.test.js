import assert from "node:assert/strict";
import test from "node:test";
import { formatBytes, formatDuration, formatRelativeTime } from "../backend/exitlane/static/js/dashboard-format.js";

const translate = (key, variables) => `${key}:${variables.count ?? ""}`;

test("formats handshake ages through explicit translation keys", () => {
  const now = Date.parse("2026-07-22T12:00:00Z");
  assert.equal(formatRelativeTime("2026-07-22T11:59:52Z", now, translate), "dashboard.time.seconds_ago:8");
  assert.equal(formatRelativeTime("2026-07-22T11:57:00Z", now, translate), "dashboard.time.minutes_ago:3");
  assert.equal(formatRelativeTime(null, now, translate), "dashboard.time.no_handshake:");
});

test("formats byte counts and uptime deterministically", () => {
  assert.equal(formatBytes(1536), "1.5 KiB");
  assert.equal(formatDuration(90061), "1d 1h");
});
