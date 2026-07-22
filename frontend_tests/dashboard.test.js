import assert from "node:assert/strict";
import test from "node:test";
import { formatBytes, formatDuration, formatRelativeTime, normaliseTimestamp } from "../backend/exitlane/static/js/dashboard-format.js";
import { getSlice, succeedRefresh } from "../backend/exitlane/static/js/state.js";

const translate = (key, variables) => `${key}:${variables.count ?? ""}`;

test("formats exact refresh boundaries through shared translation keys", () => {
  const now = Date.parse("2026-07-22T12:00:00Z");
  const ago = (seconds) => new Date(now - seconds * 1000).toISOString();
  assert.equal(formatRelativeTime(ago(0), now, translate), "dashboard.time.just_now:");
  assert.equal(formatRelativeTime(ago(1), now, translate), "dashboard.time.just_now:");
  assert.equal(formatRelativeTime(ago(2), now, translate), "dashboard.time.seconds_ago:2");
  assert.equal(formatRelativeTime(ago(59), now, translate), "dashboard.time.seconds_ago:59");
  assert.equal(formatRelativeTime(ago(60), now, translate), "dashboard.time.minute_ago:1");
  assert.equal(formatRelativeTime(ago(61), now, translate), "dashboard.time.minute_ago:1");
  assert.equal(formatRelativeTime(ago(120), now, translate), "dashboard.time.minutes_ago:2");
});

test("normalises ISO strings, Date objects, epoch seconds and milliseconds", () => {
  const iso = "2026-07-22T12:00:00Z";
  const milliseconds = Date.parse(iso);
  assert.equal(normaliseTimestamp(iso), milliseconds);
  assert.equal(normaliseTimestamp(new Date(iso)), milliseconds);
  assert.equal(normaliseTimestamp(milliseconds), milliseconds);
  assert.equal(normaliseTimestamp(milliseconds / 1000), milliseconds);
});

test("invalid and missing timestamps use the existing unknown label", () => {
  const now = Date.parse("2026-07-22T12:00:00Z");
  assert.equal(formatRelativeTime(null, now, translate), "dashboard.time.no_handshake:");
  assert.equal(formatRelativeTime(undefined, now, translate), "dashboard.time.no_handshake:");
  assert.equal(formatRelativeTime("not-a-date", now, translate), "dashboard.time.no_handshake:");
});

test("language rerender and ticker formatting never reset updatedAt", () => {
  const timestamp = Date.parse("2026-07-22T12:00:00Z");
  succeedRefresh("dashboard", { health: {} }, timestamp);
  const english = (key, variables) => key === "dashboard.time.seconds_ago" ? `${variables.count} seconds ago` : "just now";
  const dutch = (key, variables) => key === "dashboard.time.seconds_ago" ? `${variables.count} seconden geleden` : "zojuist";
  assert.equal(formatRelativeTime(timestamp, timestamp + 2000, english), "2 seconds ago");
  assert.equal(formatRelativeTime(timestamp, timestamp + 3000, dutch), "3 seconden geleden");
  assert.equal(getSlice("dashboard").updatedAt, timestamp);
});

test("formats byte counts and uptime deterministically", () => {
  assert.equal(formatBytes(1536), "1.5 KiB");
  assert.equal(formatDuration(90061), "1d 1h");
});
