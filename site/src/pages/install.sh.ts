import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { APIRoute } from 'astro';

// Serves the repository's install.sh unchanged at https://vulwall.com/install.sh.
// Astro runs from site/, so the repository root is one level up.
export const GET: APIRoute = async () =>
	new Response(await readFile(resolve(process.cwd(), '../install.sh')), {
		headers: { 'Content-Type': 'text/x-shellscript; charset=utf-8' },
	});
