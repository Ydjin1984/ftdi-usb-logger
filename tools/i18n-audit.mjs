// Аудит i18n: какие ключи используются в t()/msg(), какие реально определены,
// и что из используемого не имеет английского перевода.
// Запуск: node tools/i18n-audit.mjs
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(process.argv[2] || "ui/src");

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

// Декодировать простой строковый литерал (одинарные/двойные кавычки, \n, \", \\, \uXXXX).
function decodeLit(raw, quote) {
  let s = raw.slice(1, -1);
  return s.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|n|r|t|"|'|\\|0)/g, (m, e) => {
    if (e === "n") return "\n";
    if (e === "r") return "\r";
    if (e === "t") return "\t";
    if (e === "0") return "\0";
    if (e[0] === "u") {
      const hex = e[1] === "{" ? e.slice(2, -1) : e.slice(1);
      return String.fromCodePoint(parseInt(hex, 16));
    }
    return e;
  });
}

// Строковый литерал на позиции i (пропуск пробелов). Возвращает {value,end} | null.
function litAt(src, i) {
  while (i < src.length && /\s/.test(src[i])) i++;
  const q = src[i];
  if (q !== '"' && q !== "'" && q !== "`") return null;
  let j = i + 1;
  while (j < src.length) {
    if (src[j] === "\\") { j += 2; continue; }
    if (src[j] === q) return { value: decodeLit(src.slice(i, j + 1), q), end: j + 1 };
    j++;
  }
  return null;
}

// Все строковые литералы внутри объектного литерала, начинающегося на позиции `{`.
function keysInObject(src, braceIdx) {
  let depth = 0, j = braceIdx;
  const keys = [];
  for (; j < src.length; j++) {
    const c = src[j];
    if (c === '"' || c === "'" || c === "`") {
      const lit = litAt(src, j);
      if (lit) { j = lit.end - 1; continue; }
    }
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) break; }
  }
  const body = src.slice(braceIdx, j + 1);
  // ключи объекта: "<key>": или '<key>':
  const re = /(["'])((?:\\.|(?!\1).)*)\1\s*:/gs;
  let m;
  while ((m = re.exec(body))) { const l = litAt(m[0], 0); if (l) keys.push(l.value); }
  // shorthand-ключи без значения не поддерживаются — в msg() их нет
  return { keys, end: j };
}

const defined = new Map();   // key -> [files]
const used = new Map();      // key -> [files]
const files = walk(ROOT);

for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  const rel = path.relative(process.cwd(), f);

  // msg({...})
  const msgRe = /\bmsg\(\s*\{/g;
  let m;
  while ((m = msgRe.exec(src))) {
    const brace = src.indexOf("{", m.index);
    const { keys } = keysInObject(src, brace);
    for (const k of keys) {
      if (!defined.has(k)) defined.set(k, []);
      defined.get(k).push(rel);
    }
  }

  // t("...") — первый аргумент-литерал
  const tRe = /\bt\(\s*(?=["'`])/g;
  while ((m = tRe.exec(src))) {
    const lit = litAt(src, m.index + m[0].length);
    if (!lit) continue;
    const k = lit.value;
    if (!used.has(k)) used.set(k, []);
    used.get(k).push(rel);
  }
}

// EN-словарь в i18n.ts: ключи верхнего объекта EN
const i18nSrc = fs.readFileSync(path.join(ROOT, "i18n.ts"), "utf8");
const enIdx = i18nSrc.indexOf("const EN");
const enBrace = i18nSrc.indexOf("{", enIdx);
const { keys: enKeys } = keysInObject(i18nSrc, enBrace);
const EN = new Set(enKeys);

const missing = [...used.keys()].filter((k) => !EN.has(k) && !defined.has(k));
const unusedDefined = [...EN].filter((k) => !used.has(k));

missing.sort();
console.log(`Файлов TS: ${files.length}`);
console.log(`Ключей в словаре EN: ${EN.size}`);
console.log(`Ключей в msg(): ${defined.size}`);
console.log(`Используется t(): ${used.size} уникальных`);
console.log(`\n=== НЕТ ПЕРЕВОДА (${missing.length}) ===`);
for (const k of missing) console.log(`  ${JSON.stringify(k)}   <- ${[...new Set(used.get(k))].join(", ")}`);
console.log(`\n=== В словаре, но не используется (${unusedDefined.length}) ===`);
for (const k of unusedDefined.slice(0, 40)) console.log(`  ${JSON.stringify(k)}`);

// Совпадение по нормализации: регистр/пробелы/ё — чтобы увидеть класс ошибки
const norm = (s) => s.toLowerCase().replace(/\s+/g, " ").replace(/ё/g, "е").replace(/[.…]/g, "").trim();
const normMap = new Map();
for (const k of [...EN, ...defined.keys()]) normMap.set(norm(k), k);
let near = 0;
for (const k of missing) {
  const n = normMap.get(norm(k));
  if (n !== undefined) { near++; if (near <= 15) console.log(`  ПОЧТИ: ${JSON.stringify(k)} ~ ${JSON.stringify(n)}`); }
}
console.log(`\nПочти-совпадений (регистр/ё/многоточие): ${near}`);

// Годится как проверка в CI: непереведённая строка — это ошибка.
if (missing.length > 0) process.exitCode = 1;
