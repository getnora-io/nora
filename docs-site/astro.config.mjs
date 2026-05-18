// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	site: 'https://getnora.dev',
	integrations: [
		starlight({
			title: 'NORA',
			description: 'No-nonsense Open Registry for Artifacts',
			logo: {
				src: './src/assets/logo.svg',
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/getnora-io/nora' },
			],
			defaultLocale: 'root',
			locales: {
				root: {
					label: 'English',
					lang: 'en',
				},
				ru: {
					label: 'Русский',
					lang: 'ru',
				},
			},
			expressiveCode: {
				themes: ['github-dark'],
				styleOverrides: {
					borderColor: '#27272a',
					borderRadius: '0.5rem',
				},
			},
			sidebar: [
				{
					label: 'Getting Started',
					translations: { ru: 'Начало работы' },
					items: [
						{ label: 'Introduction', translations: { ru: 'Введение' }, slug: 'getting-started/introduction' },
						{ label: 'Quick Start', translations: { ru: 'Быстрый старт' }, slug: 'getting-started/quickstart' },
						{ label: 'Installation', translations: { ru: 'Установка' }, slug: 'getting-started/installation' },
					],
				},
				{
					label: 'Registries',
					translations: { ru: 'Реестры' },
					items: [
						{ label: 'Docker', slug: 'registries/docker' },
						{ label: 'Maven', slug: 'registries/maven' },
						{ label: 'npm', slug: 'registries/npm' },
						{ label: 'Cargo', slug: 'registries/cargo' },
						{ label: 'PyPI', slug: 'registries/pypi' },
						{ label: 'Go Modules', translations: { ru: 'Go-модули' }, slug: 'registries/go' },
						{ label: 'Raw', translations: { ru: 'Файлы (Raw)' }, slug: 'registries/raw' },
						{ label: 'RubyGems', slug: 'registries/rubygems' },
						{ label: 'Terraform', slug: 'registries/terraform' },
						{ label: 'Ansible Galaxy', slug: 'registries/ansible' },
						{ label: 'NuGet', slug: 'registries/nuget' },
						{ label: 'Pub (Dart)', slug: 'registries/pub' },
						{ label: 'Conan', slug: 'registries/conan' },
					],
				},
				{
					label: 'Configuration',
					translations: { ru: 'Конфигурация' },
					items: [
						{ label: 'Settings', translations: { ru: 'Настройки' }, slug: 'configuration/settings' },
						{ label: 'Authentication', translations: { ru: 'Аутентификация' }, slug: 'configuration/authentication' },
						{ label: 'Docker Proxy', translations: { ru: 'Docker-прокси' }, slug: 'configuration/docker-proxy' },
						{ label: 'S3 Storage', translations: { ru: 'S3-хранилище' }, slug: 'configuration/s3-storage' },
						{ label: 'TLS / HTTPS', slug: 'configuration/tls' },
						{ label: 'Outbound Proxy', translations: { ru: 'Исходящий прокси' }, slug: 'configuration/http-proxy' },
						{ label: 'Curation', translations: { ru: 'Курирование' }, slug: 'configuration/curation' },
						{ label: 'Circuit Breaker', translations: { ru: 'Автоматический выключатель' }, slug: 'configuration/circuit-breaker' },
						{ label: 'Rate Limits', translations: { ru: 'Ограничение запросов' }, slug: 'configuration/rate-limits' },
					],
				},
				{
					label: 'Deployment',
					translations: { ru: 'Развёртывание' },
					items: [
						{ label: 'Production Guide', translations: { ru: 'Руководство по продакшену' }, slug: 'deployment/production' },
						{ label: 'Helm Chart', slug: 'deployment/helm' },
						{ label: 'Upgrade Guide', translations: { ru: 'Руководство по обновлению' }, slug: 'deployment/upgrade-guide' },
					],
				},
				{
					label: 'Observability',
					translations: { ru: 'Наблюдаемость' },
					items: [
						{ label: 'Prometheus Metrics', translations: { ru: 'Метрики Prometheus' }, slug: 'observability/prometheus-metrics' },
						{ label: 'Audit Log', translations: { ru: 'Журнал аудита' }, slug: 'observability/audit-log' },
					],
				},
				{
					label: 'Integrations',
					translations: { ru: 'Интеграции' },
					items: [
						{ label: 'ArgoCD Image Updater', slug: 'integrations/argocd-image-updater' },
					],
				},
				{
					label: 'Examples',
					translations: { ru: 'Примеры' },
					items: [
						{ label: 'Kubernetes', translations: { ru: 'Kubernetes' }, slug: 'examples/kubernetes' },
					],
				},
			],
			customCss: ['./src/styles/custom.css'],
		}),
	],
});
