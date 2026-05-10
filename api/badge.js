// Vercel Edge Function: GET /api/badge?eco=<eco>&pkg=<name>
// Returns an SVG badge with the package's OSV-derived grade.
//
// Embed in a README:
//   ![supplycheck](https://supplycheck.hijacksecurity.com/api/badge?eco=npm&pkg=lodash)
//
// Grading is OSV-only (current-version advisories). For the full heuristic
// grade (typosquat, age, maintainers, etc.), link to the main page:
//   https://supplycheck.hijacksecurity.com/#eco=<eco>&pkg=<name>

export const config = { runtime: 'edge' };

const ECO_COLORS = {
  npm: '#cb3837',
  pypi: '#5db14e',
  maven: '#ec7c1a',
  go: '#00add8',
  nuget: '#2683c6',
};

const GRADE_COLORS = {
  A: '#5af78e',
  B: '#9ece6a',
  C: '#e0af68',
  D: '#ff9e64',
  F: '#f7768e',
  '?': '#7d8590',
};

const OSV_ECO = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  go: 'Go',
  nuget: 'NuGet',
};

const DEPS_DEV_SYSTEM = {
  npm: 'NPM',
  pypi: 'PYPI',
  maven: 'MAVEN',
  go: 'GO',
  nuget: 'NUGET',
};

const MAL_KEYWORDS = /\b(malicious|malware|backdoor|crypto[- ]stealer|info[- ]stealer|protestware|embedded malware|cryptominer)\b/i;

async function latestVersion(eco, name) {
  // Try ecosystem-native registry first (more reliable / lower latency for npm + pypi).
  try {
    if (eco === 'npm') {
      const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace(/%2F/g, '/')}/latest`, { cf: { cacheTtl: 600 } });
      if (r.ok) return (await r.json()).version || null;
    }
    if (eco === 'pypi') {
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (r.ok) return (await r.json()).info?.version || null;
    }
  } catch (_) { /* fall through */ }

  // Fallback: deps.dev for any ecosystem we know.
  const sys = DEPS_DEV_SYSTEM[eco];
  if (!sys) return null;
  try {
    const r = await fetch(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(name)}`);
    if (!r.ok) return null;
    const j = await r.json();
    // Prefer the default version. deps.dev marks one with isDefault=true.
    const def = (j.versions || []).find(v => v.isDefault);
    return (def || j.versions?.[0])?.versionKey?.version || null;
  } catch (_) {
    return null;
  }
}

async function osvLookup(eco, name, version) {
  const ecosystem = OSV_ECO[eco];
  if (!ecosystem) return [];
  const body = { package: { ecosystem, name } };
  if (version) body.version = version;
  try {
    const r = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) return [];
    const j = await r.json();
    return j.vulns || [];
  } catch (_) {
    return [];
  }
}

function isMalicious(v) {
  if (!v) return false;
  if (typeof v.id === 'string' && v.id.startsWith('MAL-')) return true;
  const ds = v.database_specific || {};
  if (ds.malware === true) return true;
  if (typeof ds.severity === 'string' && /malic/i.test(ds.severity)) return true;
  const blob = `${v.summary || ''} ${v.details || ''}`;
  return MAL_KEYWORDS.test(blob);
}

function severityFromAdvisory(v) {
  // Prefer GHSA-style database_specific.severity, then OSV severity[].score (CVSS), then fallback to CRITICAL keywords.
  const ds = (v.database_specific?.severity || '').toUpperCase();
  if (ds === 'CRITICAL' || ds === 'HIGH' || ds === 'MEDIUM' || ds === 'LOW') return ds.toLowerCase();
  const sev = v.severity?.[0];
  if (sev && sev.type === 'CVSS_V3' && typeof sev.score === 'string') {
    const m = sev.score.match(/CVSS:[^\s]+\/AV:[^\/]+/i);
    // Score itself isn't the numeric — CVSS_V3 type carries the vector. Skip parsing; treat as medium baseline.
  }
  if (Array.isArray(v.severity)) {
    for (const s of v.severity) {
      if (typeof s.score === 'number') {
        if (s.score >= 9) return 'critical';
        if (s.score >= 7) return 'high';
        if (s.score >= 4) return 'medium';
        if (s.score > 0) return 'low';
      }
    }
  }
  return 'medium';
}

function gradeFromAdvisories(vulns) {
  if (!vulns.length) return 'A';
  let worst = 'low';
  for (const v of vulns) {
    if (isMalicious(v)) return 'F';
    const s = severityFromAdvisory(v);
    if (s === 'critical') worst = 'critical';
    else if (s === 'high' && worst !== 'critical') worst = 'high';
    else if (s === 'medium' && !['critical', 'high'].includes(worst)) worst = 'medium';
  }
  if (worst === 'critical') return 'F';
  if (worst === 'high') return 'D';
  if (worst === 'medium') return 'C';
  return 'B';
}

function escapeXml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[c]);
}

function approxTextWidth(s, charPx = 6.5) {
  return Math.ceil(s.length * charPx);
}

function makeSvg({ eco, grade, vulnCount }) {
  const ecoColor = ECO_COLORS[eco] || '#7d8590';
  const gradeColor = GRADE_COLORS[grade] || GRADE_COLORS['?'];
  const leftLabel = 'supplycheck';
  const rightLabel = grade === '?' ? '?' : `${grade}${vulnCount > 0 ? ` · ${vulnCount}` : ''}`;
  const padX = 8;
  const leftW = approxTextWidth(leftLabel) + padX * 2;
  const rightW = approxTextWidth(rightLabel) + padX * 2;
  const total = leftW + rightW;
  const h = 20;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${total}" height="${h}" role="img" aria-label="supplycheck: ${escapeXml(grade)}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="m"><rect width="${total}" height="${h}" rx="3" fill="#fff"/></mask>
  <g mask="url(#m)">
    <rect width="${leftW}" height="${h}" fill="#0d1011"/>
    <rect x="${leftW}" width="${rightW}" height="${h}" fill="${gradeColor}"/>
    <rect width="${total}" height="${h}" fill="url(#s)"/>
    <rect x="0" y="0" width="3" height="${h}" fill="${ecoColor}"/>
  </g>
  <g font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-rendering="geometricPrecision">
    <text x="${leftW / 2}" y="14" fill="#fff" text-anchor="middle">${escapeXml(leftLabel)}</text>
    <text x="${leftW + rightW / 2}" y="14" fill="#0a0a0a" text-anchor="middle" font-weight="bold">${escapeXml(rightLabel)}</text>
  </g>
</svg>`;
}

function svgResponse(svg, status = 200, cacheSeconds = 3600) {
  return new Response(svg, {
    status,
    headers: {
      'content-type': 'image/svg+xml; charset=utf-8',
      'cache-control': `public, max-age=${cacheSeconds}, s-maxage=${cacheSeconds}, stale-while-revalidate=86400`,
      'access-control-allow-origin': '*',
    },
  });
}

export default async function handler(request) {
  const url = new URL(request.url);
  const eco = (url.searchParams.get('eco') || '').toLowerCase();
  const pkg = url.searchParams.get('pkg') || '';

  if (!eco || !pkg || !ECO_COLORS[eco]) {
    return svgResponse(makeSvg({ eco: 'unknown', grade: '?', vulnCount: 0 }), 400, 60);
  }

  try {
    const version = await latestVersion(eco, pkg);
    const vulns = await osvLookup(eco, pkg, version);
    const grade = gradeFromAdvisories(vulns);
    return svgResponse(makeSvg({ eco, grade, vulnCount: vulns.length }));
  } catch (_) {
    return svgResponse(makeSvg({ eco, grade: '?', vulnCount: 0 }), 200, 60);
  }
}
