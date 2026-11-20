import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// Astro runs from site/, so the repository root is one level up.
const changelogPath = resolve(process.cwd(), '../CHANGELOG.md');

export const collections = {
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),

	// The root CHANGELOG.md, rendered at build time so the site never keeps its own copy.
	// Its "# Changelog" heading is dropped because the page supplies the title.
	changelog: defineCollection({
		loader: {
			name: 'changelog',
			load: async ({ store, renderMarkdown, watcher }) => {
				const body = (await readFile(changelogPath, 'utf8')).replace(/^# .*\n+/, '');
				store.clear();
				store.set({ id: 'changelog', data: {}, body, rendered: await renderMarkdown(body) });
				watcher?.add(changelogPath);
			},
		},
	}),
};
