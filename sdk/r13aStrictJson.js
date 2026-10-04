/**
 * Strict R13-A R4 JSON admission.
 *
 * The protocol boundary starts at raw bytes. This reader rejects malformed
 * UTF-8, a leading UTF-8 BOM, duplicate decoded member names, prototype
 * members, lone surrogates, non-finite binary64 values, trailing content, and
 * multiple top-level values before any protocol object is constructed.
 */
export class R13aStrictJsonError extends Error {
  constructor(kind) {
    super(kind);
    this.name = "R13aStrictJsonError";
    this.kind = kind;
  }
}

export function strictParseR13aJsonText(text) {
  if (typeof text !== "string") throw new TypeError("json_text_required");
  let index = 0;

  const whitespace = () => {
    while (index < text.length && " \t\n\r".includes(text[index])) index += 1;
  };
  const invalid = () => {
    throw new R13aStrictJsonError("json_parse_failed");
  };

  const parseString = () => {
    if (text[index] !== "\"") invalid();
    index += 1;
    let output = "";
    while (true) {
      if (index >= text.length) invalid();
      const character = text[index];
      if (character === "\"") {
        index += 1;
        return output;
      }
      if (character === "\\") {
        index += 1;
        const escape = text[index];
        index += 1;
        if (escape === "\"") output += "\"";
        else if (escape === "\\") output += "\\";
        else if (escape === "/") output += "/";
        else if (escape === "b") output += "\b";
        else if (escape === "f") output += "\f";
        else if (escape === "n") output += "\n";
        else if (escape === "r") output += "\r";
        else if (escape === "t") output += "\t";
        else if (escape === "u") {
          const hex = text.slice(index, index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) invalid();
          const code = Number.parseInt(hex, 16);
          index += 4;
          if (code >= 0xd800 && code <= 0xdbff) {
            const lowHex = text.slice(index + 2, index + 6);
            const low = /^[0-9a-fA-F]{4}$/.test(lowHex) ? Number.parseInt(lowHex, 16) : null;
            if (text.slice(index, index + 2) === "\\u" && low >= 0xdc00 && low <= 0xdfff) {
              output += String.fromCharCode(code, low);
              index += 6;
            } else {
              output += String.fromCharCode(code);
            }
          } else {
            output += String.fromCharCode(code);
          }
        } else {
          invalid();
        }
      } else if (character.charCodeAt(0) < 0x20) {
        invalid();
      } else {
        output += character;
        index += 1;
      }
    }
  };

  const parseValue = () => {
    whitespace();
    const character = text[index];
    if (character === "{") {
      index += 1;
      const pairs = [];
      whitespace();
      if (text[index] === "}") {
        index += 1;
        return { kind: "object", pairs };
      }
      while (true) {
        whitespace();
        const key = parseString();
        whitespace();
        if (text[index] !== ":") invalid();
        index += 1;
        pairs.push([key, parseValue()]);
        whitespace();
        if (text[index] === ",") {
          index += 1;
          continue;
        }
        if (text[index] === "}") {
          index += 1;
          return { kind: "object", pairs };
        }
        invalid();
      }
    }
    if (character === "[") {
      index += 1;
      const items = [];
      whitespace();
      if (text[index] === "]") {
        index += 1;
        return { kind: "array", items };
      }
      while (true) {
        items.push(parseValue());
        whitespace();
        if (text[index] === ",") {
          index += 1;
          continue;
        }
        if (text[index] === "]") {
          index += 1;
          return { kind: "array", items };
        }
        invalid();
      }
    }
    if (character === "\"") return { kind: "string", value: parseString() };
    if (text.startsWith("true", index)) {
      index += 4;
      return { kind: "scalar", value: true };
    }
    if (text.startsWith("false", index)) {
      index += 5;
      return { kind: "scalar", value: false };
    }
    if (text.startsWith("null", index)) {
      index += 4;
      return { kind: "scalar", value: null };
    }
    const match = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?/.exec(text.slice(index));
    if (!match) invalid();
    index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) invalid();
    return { kind: "scalar", value };
  };

  const root = parseValue();
  whitespace();
  if (index !== text.length) invalid();
  if (root.kind !== "object") invalid();

  const containsDuplicateMember = (node) => {
    if (node.kind === "array") return node.items.some(containsDuplicateMember);
    if (node.kind !== "object") return false;
    const seen = new Set();
    for (const [key, value] of node.pairs) {
      if (seen.has(key)) return true;
      seen.add(key);
      if (containsDuplicateMember(value)) return true;
    }
    return false;
  };
  const stringHasLoneSurrogate = (value) => {
    for (let offset = 0; offset < value.length; offset += 1) {
      const code = value.charCodeAt(offset);
      if (code >= 0xd800 && code <= 0xdbff) {
        const low = value.charCodeAt(offset + 1);
        if (!(low >= 0xdc00 && low <= 0xdfff)) return true;
        offset += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return true;
      }
    }
    return false;
  };
  const containsLoneSurrogate = (node) => {
    if (node.kind === "string") return stringHasLoneSurrogate(node.value);
    if (node.kind === "array") return node.items.some(containsLoneSurrogate);
    if (node.kind !== "object") return false;
    return node.pairs.some(([key, value]) => stringHasLoneSurrogate(key) || containsLoneSurrogate(value));
  };
  const containsPrototypeMember = (node) => {
    if (node.kind === "array") return node.items.some(containsPrototypeMember);
    if (node.kind !== "object") return false;
    return node.pairs.some(([key, value]) => key === "__proto__" || containsPrototypeMember(value));
  };
  const materialize = (node) => {
    if (node.kind === "string" || node.kind === "scalar") return node.value;
    if (node.kind === "array") return node.items.map(materialize);
    const object = Object.create(null);
    for (const [key, value] of node.pairs) object[key] = materialize(value);
    return object;
  };

  if (containsDuplicateMember(root)) throw new R13aStrictJsonError("duplicate_member");
  if (containsLoneSurrogate(root)) throw new R13aStrictJsonError("lone_surrogate");
  if (containsPrototypeMember(root)) throw new R13aStrictJsonError("prototype_member");
  return materialize(root);
}

export function strictParseR13aJsonBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("json_bytes_required");
  let text;
  try {
    // ignoreBOM:true preserves U+FEFF, causing the JSON grammar to reject it.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new R13aStrictJsonError("body_not_utf8");
  }
  return strictParseR13aJsonText(text);
}
