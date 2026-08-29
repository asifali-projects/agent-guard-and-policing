/** Apply the runtime's redaction paths to a parameter object. */

export const REDACTED = "[REDACTED]";

type Key = string | number;

/** "parameters.user.contacts[0].email" -> ["user", "contacts", 0, "email"] */
function tokens(path: string): Key[] {
  const body = path.startsWith("parameters.") ? path.slice("parameters.".length) : path;
  const out: Key[] = [];
  for (const part of body.split(".")) {
    const match = /\[(\d+)\]/.exec(part);
    const name = part.replace(/\[\d+\]/g, "");
    if (name) out.push(name);
    if (match) out.push(Number(match[1]));
  }
  return out;
}

function clone<T>(value: T): T {
  return typeof structuredClone === "function"
    ? structuredClone(value)
    : (JSON.parse(JSON.stringify(value)) as T);
}

/** Return a deep copy of `parameters` with every `path` leaf masked. */
export function applyRedactions(
  parameters: Record<string, unknown>,
  paths: string[],
): Record<string, unknown> {
  const result = clone(parameters);
  for (const path of paths) {
    const parts = tokens(path);
    if (parts.length === 0) continue;
    let node: unknown = result;
    let ok = true;
    for (const key of parts.slice(0, -1)) {
      if (node != null && typeof node === "object") {
        node = (node as Record<Key, unknown>)[key];
      } else {
        ok = false;
        break;
      }
    }
    const last = parts[parts.length - 1]!;
    if (ok && node != null && typeof node === "object") {
      (node as Record<Key, unknown>)[last] = REDACTED;
    }
  }
  return result;
}
