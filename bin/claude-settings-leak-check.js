#!/usr/bin/env node
/**
 * claude-settings-leak-check: does any Claude Code settings file hold a secret, and is it
 * reachable from a git remote? Background: Apiiro (2026-11) found real secrets in 1,122 of 104,185
 * public copies of .claude/settings.local.json. "Yes, and don't ask again" stores the COMPLETE
 * approved shell command in permissions.allow, credentials included.
 *
 *   npx claude-settings-leak-check [--root <dir>] [--depth <n>] [--json]
 *
 * Local only: reads files under --root (default: cwd) and runs `git` read-only. No network call.
 * Secret values are NEVER printed: findings show the rule, entry index, file and a masked
 * prefix/length. Exit 2 = finding(s), 0 = none. "None" is not "clean": it means no known pattern
 * matched. Rotate before you delete; deleting a pushed file does not un-leak it.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const RULES = [
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['openai-style-key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['jwt-or-supabase-key', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ['slack-token', /\bxox[abprs]-[A-Za-z0-9-]{20,}/],
  ['stripe-key', /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/],
  ['private-key-block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['url-embedded-credentials', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"]+:[^\s@'"]{3,}@[^\s'"]+/i],
  ['bearer-header', /\bAuthorization:\s*(?:Bearer|Basic|token)\s+[A-Za-z0-9._~+/=-]{12,}/i],
  ['secret-assignment', /\b[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Za-z0-9_]*=(?!\$|["']?\$)["']?[^\s"']{8,}/i],
  ['cli-secret-flag', /(?:--(?:password|passwd|token|api-?key|secret|client-secret)(?:=|\s+)|\s-p)(?!\$)["']?[^\s"'-][^\s"']{7,}/i],
  ['mysql-style-password', /\s-p[^\s"'$-][^\s"']{5,}/],
];

// A reference to a secret store is not a secret.
const SAFE_HINTS = [/\$\{?[A-Z_][A-Z0-9_]*\}?/, /\bkeyvault\b.*\bshow\b/i];

function mask(s) {
  return `${s.slice(0, 4)}…(${s.length} chars)`;
}

// A placeholder is not a credential: __KEY__, <token>, ${TOKEN}, YOUR_KEY, REDACTED, xxxx.
function isPlaceholder(v) {
  return /^_{1,3}[A-Z0-9_]+_{1,3}$/.test(v) || /^<.*>$/.test(v) || /^\$/.test(v)
    || /^(?:x+|\*+|\.{3,})$/i.test(v) || /(?:REDACTED|PLACEHOLDER|YOUR[_-]|CHANGEME|EXAMPLE)/i.test(v);
}
function tokenOf(rule, matched) {
  if (rule === 'bearer-header') return matched.replace(/^.*?(?:Bearer|Basic|token)\s+/i, '');
  return null;
}

function scanEntry(entry) {
  const hits = [];
  if (typeof entry !== 'string') return hits;
  for (const [rule, re] of RULES) {
    const m = entry.match(re);
    if (!m) continue;
    // Skip when the only thing after the assignment is a variable reference.
    if (rule === 'secret-assignment' && SAFE_HINTS.some((h) => h.test(m[0]))) continue;
    const tok = tokenOf(rule, m[0]);
    if (tok && isPlaceholder(tok)) continue;
    hits.push({ rule, sample: mask(m[0]) });
  }
  return hits;
}

function scanSettings(json) {
  const findings = [];
  const perms = (json && json.permissions) || {};
  for (const list of ['allow', 'ask', 'deny']) {
    (Array.isArray(perms[list]) ? perms[list] : []).forEach((entry, index) => {
      for (const h of scanEntry(entry)) findings.push({ list, index, ...h });
    });
  }
  // env block in settings is stored in clear text too.
  const env = (json && json.env) || {};
  for (const [k, v] of Object.entries(env)) {
    for (const h of scanEntry(`${k}=${v}`)) findings.push({ list: 'env', index: k, ...h });
    if (k === 'ANTHROPIC_BASE_URL' && typeof v === 'string' && !/^https:\/\/([a-z0-9-]+\.)*anthropic\.com(\/|$)/i.test(v)) {
      findings.push({ list: 'env', index: k, rule: 'non-anthropic-base-url', sample: mask(v) });
    }
  }
  return findings;
}

function git(cwd, args) {
  try {
    // A scanned repo is untrusted: its .git/config can name commands (core.fsmonitor, hooks).
    // Neutralize those so inspecting a clone cannot execute anything from it.
    const hardened = ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.untrackedCache=false',
      '-c', 'protocol.allow=never', '-c', 'core.sshCommand=false', '-c', 'core.pager=cat'];
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_OPTIONAL_LOCKS: '0', GIT_TERMINAL_PROMPT: '0' };
    return execFileSync('git', [...hardened, ...args], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 }).trim();
  } catch (e) { return null; }
}

function exposure(file) {
  const dir = path.dirname(file);
  const top = git(dir, ['rev-parse', '--show-toplevel']);
  if (!top) return { git: false };
  const rel = path.relative(top, file);
  const tracked = git(top, ['ls-files', '--', rel]) === rel;
  const ignored = git(top, ['check-ignore', '-q', '--', rel]) !== null;
  const everCommitted = (git(top, ['log', '--all', '--oneline', '-1', '--', rel]) || '') !== '';
  const remotes = (git(top, ['remote', '-v']) || '').split('\n').filter(Boolean).length > 0;
  return { git: true, tracked, ignored, everCommitted, hasRemote: remotes };
}

const SKIP = new Set(['node_modules', '.git', 'Library', '.Trash', '.cache', 'dist', 'build']);
function findSettingsFiles(root, maxDepth) {
  const out = [];
  (function walk(dir, depth) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of ents) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === '.claude') {
          for (const f of ['settings.local.json', 'settings.json']) {
            const fp = path.join(p, f);
            if (fs.existsSync(fp)) out.push(fp);
          }
        } else if (!SKIP.has(e.name) && depth < maxDepth && !e.isSymbolicLink()) walk(p, depth + 1);
      }
    }
  })(root, 0);
  return out;
}

function scanFile(file) {
  let json;
  try { json = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    return { file, error: 'unparseable JSON', findings: [] };
  }
  const findings = scanSettings(json);
  const ex = findings.length ? exposure(file) : null;
  let severity = 'none';
  if (findings.length) {
    severity = 'LOCAL';
    if (ex && ex.git && (ex.tracked || ex.everCommitted)) severity = ex.hasRemote ? 'EXPOSED-REMOTE' : 'COMMITTED';
    else if (ex && ex.git && !ex.ignored) severity = 'AT-RISK';
  }
  return { file, findings, exposure: ex, severity };
}

function main() {
  const argv = process.argv.slice(2);
  const opt = (f, d) => { const i = argv.indexOf(`--${f}`); return i >= 0 ? argv[i + 1] : d; };
  const root = path.resolve(opt('root', process.cwd()));
  const depth = Number(opt('depth', 4));
  const files = findSettingsFiles(root, depth);
  const results = files.map(scanFile);
  const bad = results.filter((r) => r.findings.length);
  if (argv.includes('--json')) {
    console.log(JSON.stringify({ root, scanned: files.length, results: bad }, null, 2));
  } else {
    console.log(`Scanned ${files.length} Claude settings file(s) under ${root}`);
    for (const r of results.filter((x) => x.error)) console.log(`  ? ${r.file}: ${r.error}`);
    for (const r of bad) {
      console.log(`\n[${r.severity}] ${r.file}`);
      for (const f of r.findings) console.log(`   - ${f.list}[${f.index}] ${f.rule}  ${f.sample}`);
      if (r.severity === 'LOCAL') console.log('   Local only and git-ignored: rotate anyway if the machine is shared or backed up.');
      else console.log('   Rotate the credential FIRST, then remove the entry (and purge history if committed).');
    }
    if (!bad.length) console.log('No known secret pattern found. That is not proof of clean.');
  }
  process.exit(bad.length ? 2 : 0);
}

if (require.main === module) main();
module.exports = { scanEntry, scanSettings, scanFile, findSettingsFiles, RULES };
