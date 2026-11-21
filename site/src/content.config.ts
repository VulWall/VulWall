import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { fromHtml } from 'hast-util-from-html';
import { defaultSchema, sanitize, type Schema } from 'hast-util-sanitize';
import { toHtml } from 'hast-util-to-html';

// Astro runs from site/, so the repository root is one level up.
const changelogPath = resolve(process.cwd(), '../CHANGELOG.md');

// release-please writes PR titles and bodies into CHANGELOG.md, and the Markdown
// renderer passes raw HTML through, so the rendered changelog is sanitized with
// GitHub's allow-list, without images (they would load from any host). Heading ids
// stay unprefixed so the table of contents links work.
const changelogSchema: Schema = {
	...defaultSchema,
	tagNames: defaultSchema.tagNames?.filter((tag) => !['img', 'picture', 'source'].includes(tag)),
	clobber: [],
	attributes: {
		...defaultSchema.attributes,
		...Object.fromEntries(['h2', 'h3', 'h4', 'h5', 'h6'].map((h) => [h, ['id']])),
	},
};
const sanitizeHtml = (html: string) =>
	toHtml(sanitize(fromHtml(html, { fragment: true }), changelogSchema));

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
				const rendered = await renderMarkdown(body);
				store.set({
					id: 'changelog',
					data: {},
					body,
					rendered: { ...rendered, html: sanitizeHtml(rendered.html) },
				});
				watcher?.add(changelogPath);
			},
		},
	}),
};
