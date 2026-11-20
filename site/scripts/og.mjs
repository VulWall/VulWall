// Renders public/og.png (1200x630), the social preview image, with headless Chrome.
// Run after changing the design: `npm run og`. The PNG is committed, so the site build
// does not need a browser. Set CHROME to the browser binary if it is not found.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(import.meta.dirname, '..');
const chrome =
	process.env.CHROME ??
	['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/google-chrome', '/usr/bin/chromium'].find(
		existsSync,
	);
if (!chrome) throw new Error('Chrome not found; set CHROME to its path');

const font = (pkg, file) => pathToFileURL(join(root, 'node_modules/@fontsource', pkg, 'files', file)).href;
const logo = readFileSync(join(root, 'src/assets/logo-mark-dark.svg'), 'utf8');

const html = `<!doctype html><html><head><meta charset="utf-8"><style>
@font-face { font-family: 'Chakra Petch'; font-weight: 600; src: url(${font('chakra-petch', 'chakra-petch-latin-600-normal.woff2')}); }
@font-face { font-family: 'Inter'; font-weight: 400; src: url(${font('inter', 'inter-latin-400-normal.woff2')}); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 400; src: url(${font('jetbrains-mono', 'jetbrains-mono-latin-400-normal.woff2')}); }
html, body { margin: 0; width: 1200px; height: 630px; }
body { box-sizing: border-box; padding: 80px 88px; display: flex; flex-direction: column; justify-content: space-between;
  background: linear-gradient(135deg, #212C5E 0%, #0056A1 100%); color: #FBFBFD; font-family: 'Inter', sans-serif; }
.brand { display: flex; align-items: center; gap: 20px; font: 600 40px 'Chakra Petch'; letter-spacing: 0.02em; text-transform: uppercase; }
.brand svg { width: 64px; height: 66px; }
h1 { margin: 0; max-width: 960px; font: 600 68px/1.1 'Chakra Petch'; letter-spacing: -0.01em; }
.foot { display: flex; justify-content: space-between; align-items: center; font-size: 26px; color: rgba(251,251,253,0.85); }
code { font: 400 24px 'JetBrains Mono'; padding: 14px 22px; border-radius: 8px; background: #101827; color: #E5E7EB; }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #F47D17; margin-right: 12px; }
</style></head><body>
<div class="brand">${logo}<span>VulWall</span></div>
<h1>See your attack surface the way an attacker does</h1>
<div class="foot"><span><span class="dot"></span>Self-hosted &middot; Open source &middot; MIT</span><code>vulwall.com</code></div>
</body></html>`;

const dir = mkdtempSync(join(tmpdir(), 'vulwall-og-'));
const page = join(dir, 'og.html');
writeFileSync(page, html);
const out = join(root, 'public/og.png');
execFileSync(chrome, [
	'--headless',
	'--disable-gpu',
	'--hide-scrollbars',
	'--allow-file-access-from-files',
	'--force-device-scale-factor=1',
	'--window-size=1200,630',
	`--screenshot=${out}`,
	pathToFileURL(page).href,
]);
console.log(`wrote ${out}`);
