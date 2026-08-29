import assert from "node:assert/strict";
import { test } from "node:test";

import { REDACTED, applyRedactions } from "../src/redact.js";

test("masks a top-level leaf", () => {
  const out = applyRedactions({ to: "a", body: "secret" }, ["parameters.body"]);
  assert.deepEqual(out, { to: "a", body: REDACTED });
});

test("masks a nested leaf and leaves siblings intact", () => {
  const out = applyRedactions(
    { user: { name: "Dana", email: "dana@x.com" } },
    ["parameters.user.email"],
  );
  assert.deepEqual(out, { user: { name: "Dana", email: REDACTED } });
});

test("masks an array element by index", () => {
  const out = applyRedactions(
    { contacts: [{ email: "a@x.com" }, { email: "b@x.com" }] },
    ["parameters.contacts[1].email"],
  );
  assert.equal((out.contacts as Array<{ email: string }>)[1]!.email, REDACTED);
  assert.equal((out.contacts as Array<{ email: string }>)[0]!.email, "a@x.com");
});

test("does not mutate the input", () => {
  const input = { body: "secret" };
  applyRedactions(input, ["parameters.body"]);
  assert.equal(input.body, "secret");
});

test("ignores paths that do not resolve", () => {
  const out = applyRedactions({ a: 1 }, ["parameters.b.c", "parameters.a.deep"]);
  assert.deepEqual(out, { a: 1 });
});

test("accepts paths without the parameters. prefix", () => {
  assert.deepEqual(applyRedactions({ x: "y" }, ["x"]), { x: REDACTED });
});
