// Copies the normative JSON Schemas and every validated example of docs/spec (zeus repository) into
// spec-fixtures/ so zeus-core's conformance tests need no access to the other repository.
//
// Usage: node scripts/sync-spec-fixtures.mjs [path-to-zeus-repo]   (default: ../zeus)
//        node scripts/sync-spec-fixtures.mjs --check [path]         (exit 1 when the copy is stale)
//
// Fence convention in the spec markdown (see docs/spec/tools/validate-spec.mjs):
//   ```json  validate=<schema-name>#/$defs/<Def>   one JSON document
//   ```jsonl validate=<schema-name>#/$defs/<Def>   one document per line (add "chain" for audit chains)
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const args = process.argv.slice(2);
const check = args.includes('--check');
const zeus = resolve(args.find((a) => !a.startsWith('--')) ?? join(root, '..', 'zeus'));
const specDir = join(zeus, 'docs', 'spec');
if (!existsSync(specDir)) {
  console.error(`spec directory not found: ${specDir}`);
  process.exit(2);
}

const outRoot = join(root, 'spec-fixtures');
const README = "# spec-fixtures\n\nA verbatim copy of the normative JSON Schemas and every validated example of the Zeus specification (the `zeus` repository, `docs/spec`), so the conformance tests of this repository need no access to the other one.\n\n* `schema/`: every `*.schema.json`, `job-state-machine.v1.json` and `redaction-vectors.v1.json`.\n* `examples/`: one file per `validate=` block of the markdown documents, named `<doc number>-L<line>.<json|jsonl>`, and `index.json` listing the schema, the definition and the source document of each.\n\nDo not edit these files by hand. Refresh them with:\n\n```sh\nnode scripts/sync-spec-fixtures.mjs ../zeus          # copy\nnode scripts/sync-spec-fixtures.mjs --check ../zeus  # fail if stale (CI)\n```\n\nTests read them through `zeus_types::spec_testing` (cargo feature `spec-testing`).\n";
const files = new Map(); // relative path -> content (string | Buffer)
files.set('README.md', README);

for (const f of readdirSync(join(specDir, 'schema')).sort()) {
  files.set(`schema/${f}`, readFileSync(join(specDir, 'schema', f)));
}

const index = [];
for (const doc of readdirSync(specDir).filter((f) => /^\d\d-.*\.md$/.test(f)).sort()) {
  const lines = readFileSync(join(specDir, doc), 'utf8').split(/\r?\n/);
  const docNo = doc.slice(0, 2);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^```(jsonl?)\s+validate=(\S+)(\s+chain)?\s*$/);
    if (!m) continue;
    const body = [];
    let j = i + 1;
    while (j < lines.length && !lines[j].startsWith('```')) body.push(lines[j++]);
    const [, kind, ref, chain] = m;
    const [schema, def = ''] = ref.split('#');
    const name = `examples/${docNo}-L${i + 1}.${kind}`;
    files.set(name, body.join('\n') + '\n');
    index.push({ file: name, doc, line: i + 1, schema, def: def.replace(/^\/\$defs\//, ''), kind, chain: Boolean(chain) });
    i = j;
  }
}
files.set('examples/index.json', JSON.stringify(index, null, 2) + '\n');

if (check) {
  let stale = 0;
  for (const [rel, content] of files) {
    const p = join(outRoot, rel);
    if (!existsSync(p) || !readFileSync(p).equals(Buffer.from(content))) {
      console.error(`stale: ${rel}`);
      stale++;
    }
  }
  process.exit(stale ? 1 : 0);
}

rmSync(outRoot, { recursive: true, force: true });
for (const [rel, content] of files) {
  const p = join(outRoot, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
}
console.log(`wrote ${files.size} files (${index.length} examples) to ${outRoot}`);
