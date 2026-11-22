import type { CheckResult } from "./types.ts";

export function pass(id: string, message: string): CheckResult {
  return { id, status: "pass", message };
}

export function warn(id: string, message: string): CheckResult {
  return { id, status: "warn", message };
}

export function fail(id: string, message: string): CheckResult {
  return { id, status: "fail", message };
}

export function skip(id: string, reason: string): CheckResult {
  return { id, status: "skip", message: `Skipped: ${reason}` };
}
