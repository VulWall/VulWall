// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = 'https://vulwall.com';
const description =
	'Self-hosted external attack surface scanner. Finds your subdomains, open ports and vulnerabilities, and explains what to fix. Free and open source (AGPL-3.0).';

export default defineConfig({
	site,
	output: 'static',
	trailingSlash: 'ignore',
	// The changelog and install.sh are read from the repository root at build time.
	vite: { server: { fs: { allow: ['..'] } } },
	integrations: [
		starlight({
			title: 'VulWall',
			description,
			logo: {
				light: './src/assets/logo-mark.svg',
				dark: './src/assets/logo-mark-dark.svg',
				alt: 'VulWall',
				replacesTitle: false,
			},
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'VulWall on GitHub', href: 'https://github.com/VulWall/VulWall' }],
			editLink: { baseUrl: 'https://github.com/VulWall/VulWall/edit/main/site/' },
			credits: false,
			components: { Hero: './src/components/Hero.astro' },
			// One frame style for every code block, and long commands wrap instead of scrolling.
			expressiveCode: { defaultProps: { frame: 'code', wrap: true, preserveIndent: true } },
			head: [
				{ tag: 'meta', attrs: { property: 'og:image', content: `${site}/og.png` } },
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
				{ tag: 'meta', attrs: { property: 'og:image:alt', content: 'VulWall: self-hosted external attack surface scanner' } },
				{ tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
			],
			customCss: [
				'@fontsource/inter/400.css',
				'@fontsource/inter/500.css',
				'@fontsource/inter/600.css',
				'@fontsource/inter/700.css',
				'@fontsource/jetbrains-mono/400.css',
				'@fontsource/jetbrains-mono/500.css',
				'@fontsource/chakra-petch/600.css',
				'@fortawesome/fontawesome-free/css/fontawesome.min.css',
				'@fortawesome/fontawesome-free/css/solid.min.css',
				'@fortawesome/fontawesome-free/css/brands.min.css',
				'./src/styles/tokens/colors.css',
				'./src/styles/tokens/severity.css',
				'./src/styles/brand.css',
			],
			sidebar: [
				{ label: 'Overview', link: '/docs/' },
				{
					label: 'Getting started',
					items: [
						'docs/getting-started/requirements',
						'docs/getting-started/install',
						'docs/getting-started/manual-install',
						'docs/getting-started/first-scan',
					],
				},
				{
					label: 'Configuration',
					items: [
						'docs/configuration',
						'docs/configuration/reverse-proxy',
						'docs/configuration/ai',
					],
				},
				{
					label: 'Operations',
					items: [
						'docs/operations/upgrade',
						'docs/operations/backup',
						'docs/operations/admin-password',
						'docs/operations/logs-and-tracing',
					],
				},
				{
					label: 'How it works',
					items: ['docs/how-it-works', 'docs/how-it-works/scanners'],
				},
				{
					label: 'Project',
					items: [
						'docs/contributing',
						'docs/contributing/adding-a-scanner',
						'docs/security',
						'docs/license',
						'docs/faq',
						{ label: 'Changelog', link: '/changelog/' },
					],
				},
			],
		}),
	],
});
