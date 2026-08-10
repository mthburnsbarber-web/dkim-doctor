import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const cli = fileURLToPath(new URL("../dkim-doctor.mjs", import.meta.url));

function run(...args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: "utf8" });
}

test("no domain is a usage error without making DNS requests", () => {
  const result = run();
  assert.equal(result.status, 2);
  assert.match(result.stderr, /usage: dkim-doctor/);
});

test("unknown flags fail closed", () => {
  const result = run("--not-a-real-option");
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown flag/);
});

test("an empty selector list is accepted syntactically and reports domain problems", () => {
  const result = run("invalid.", "--selectors", "");
  assert.equal(result.status, 1);
  assert.match(result.stdout, /SPF: no v=spf1 record/);
  assert.match(result.stdout, /DKIM: no key under 0 probed selectors/);
});
