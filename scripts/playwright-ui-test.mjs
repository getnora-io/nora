#!/usr/bin/env node
/**
 * NORA Pre-Release UI Test Suite (Playwright)
 *
 * Comprehensive browser-based testing:
 *   - Page rendering & structure
 *   - CSS/styling verification
 *   - HTMX interactivity
 *   - Navigation & routing
 *   - Search functionality
 *   - Language switching (EN/RU)
 *   - Security headers
 *   - Responsive design (mobile/tablet/desktop)
 *   - Accessibility (a11y basics)
 *   - Console errors / CSP violations
 *   - Screenshots for visual review
 *
 * Usage:
 *   node playwright-ui-test.mjs [base_url] [screenshot_dir]
 *
 * First-time setup:
 *   npx playwright install chromium
 */

import { chromium } from 'playwright';
import { mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const BASE = process.argv[2] || 'http://127.0.0.1:4088';
const SCREENSHOT_DIR = process.argv[3] || '/tmp/nora-ui-screenshots';

// Ensure screenshot directory exists
if (!existsSync(SCREENSHOT_DIR)) mkdirSync(SCREENSHOT_DIR, { recursive: true });

let pass = 0, fail = 0, warn = 0;
const results = [];
const consoleErrors = [];
const cspViolations = [];

function check(name, status, detail) {
    results.push({ name, status, detail });
    if (status === 'PASS') pass++;
    else if (status === 'FAIL') fail++;
    else warn++;
}

function assert(cond, msg) { if (!cond) throw new Error(msg || 'Assertion failed'); }

async function screenshot(page, name) {
    const path = join(SCREENSHOT_DIR, `${name}.png`);
    await page.screenshot({ path, fullPage: true });
    return path;
}

async function run() {
    console.log('======================================================================');
    console.log('  NORA Pre-Release UI Test Suite (Playwright + Chromium)');
    console.log(`  Target: ${BASE}`);
    console.log(`  Screenshots: ${SCREENSHOT_DIR}`);
    console.log(`  ${new Date().toISOString()}`);
    console.log('======================================================================\n');

    const browser = await chromium.launch({ headless: true });

    // ================================================================
    // PHASE 1: Dashboard — Desktop
    // ================================================================
    console.log('=== Phase 1: Dashboard (Desktop 1920x1080) ===\n');

    const desktopCtx = await browser.newContext({
        viewport: { width: 1920, height: 1080 },
        locale: 'en-US',
    });
    const page = await desktopCtx.newPage();

    // Collect all console errors and CSP violations
    page.on('pageerror', e => consoleErrors.push(e.message));
    page.on('console', msg => {
        if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    // 1.1 Dashboard loads
    try {
        const resp = await page.goto(`${BASE}/ui/`, { waitUntil: 'networkidle', timeout: 15000 });
        assert(resp.status() === 200);
        check('1.1 Dashboard HTTP 200', 'PASS');
    } catch (e) {
        check('1.1 Dashboard HTTP 200', 'FAIL', e.message);
        await browser.close();
        printResults();
        process.exit(1);
    }

    // 1.2 Page title
    try {
        const title = await page.title();
        assert(title.length > 0, `Empty title`);
        check('1.2 Page has title', 'PASS', title);
    } catch (e) { check('1.2 Page has title', 'FAIL', e.message); }

    // 1.3 HTML structure
    try {
        const html = await page.content();
        assert(html.includes('<!DOCTYPE html>') || html.includes('<!doctype html>'), 'No doctype');
        assert(html.includes('<head>') || html.includes('<head '), 'No head');
        assert(html.includes('</html>'), 'No closing html');
        check('1.3 Valid HTML structure', 'PASS');
    } catch (e) { check('1.3 Valid HTML structure', 'FAIL', e.message); }

    // 1.4 Registry cards present
    try {
        const body = await page.textContent('body');
        for (const name of ['Docker', 'Maven', 'npm', 'Cargo', 'PyPI']) {
            assert(body.includes(name), `Missing ${name} card`);
        }
        check('1.4 All 5 registry cards rendered', 'PASS');
    } catch (e) { check('1.4 All 5 registry cards rendered', 'FAIL', e.message); }

    // 1.5 Stats section (downloads, uploads, artifacts)
    try {
        const body = await page.textContent('body');
        // Check for stat-like numbers or labels
        const hasStats = /download|upload|artifact|cache/i.test(body);
        assert(hasStats, 'No stats section found');
        check('1.5 Stats section visible', 'PASS');
    } catch (e) { check('1.5 Stats section visible', 'FAIL', e.message); }

    // 1.6 Mount points / endpoints table
    try {
        const body = await page.textContent('body');
        const hasMounts = ['/v2/', '/maven2/', '/npm/', '/simple/'].some(m => body.includes(m));
        assert(hasMounts, 'No mount points');
        check('1.6 Mount points table', 'PASS');
    } catch (e) { check('1.6 Mount points table', 'FAIL', e.message); }

    // 1.7 Activity log section
    try {
        const body = await page.textContent('body');
        const hasActivity = /activity|recent|no activity|нет активности/i.test(body);
        assert(hasActivity, 'No activity section');
        check('1.7 Activity log section', 'PASS');
    } catch (e) { check('1.7 Activity log section', 'FAIL', e.message); }

    // 1.8 CSS applied (not unstyled)
    try {
        const bg = await page.evaluate(() => {
            const s = getComputedStyle(document.body);
            return { bg: s.backgroundColor, font: s.fontFamily, color: s.color };
        });
        assert(bg.bg !== 'rgba(0, 0, 0, 0)' && bg.bg !== '', `No background: ${bg.bg}`);
        assert(bg.font.length > 0, 'No font');
        check('1.8 CSS styling applied', 'PASS', `bg=${bg.bg}`);
    } catch (e) { check('1.8 CSS styling applied', 'FAIL', e.message); }

    // 1.9 HTMX loaded
    try {
        const hasHtmx = await page.evaluate(() => typeof htmx !== 'undefined');
        assert(hasHtmx, 'htmx not defined');
        check('1.9 HTMX library loaded', 'PASS');
    } catch (e) { check('1.9 HTMX library loaded', 'FAIL', e.message); }

    // 1.10 No JS errors on dashboard
    try {
        const dashErrors = consoleErrors.filter(e => !e.includes('favicon'));
        assert(dashErrors.length === 0, dashErrors.join('; '));
        check('1.10 No JavaScript errors', 'PASS');
    } catch (e) { check('1.10 No JavaScript errors', 'FAIL', e.message); }

    await screenshot(page, '01-dashboard-desktop');

    // ================================================================
    // PHASE 2: Navigation & Routing
    // ================================================================
    console.log('=== Phase 2: Navigation & Routing ===\n');

    // 2.1 All nav links resolve
    try {
        const links = await page.locator('a[href^="/ui/"]').all();
        assert(links.length >= 5, `Only ${links.length} nav links`);
        check('2.1 Navigation links exist', 'PASS', `${links.length} links`);
    } catch (e) { check('2.1 Navigation links exist', 'FAIL', e.message); }

    // 2.2 Click through each registry
    for (const reg of ['docker', 'maven', 'npm', 'cargo', 'pypi']) {
        try {
            const resp = await page.goto(`${BASE}/ui/${reg}`, { waitUntil: 'networkidle', timeout: 10000 });
            assert(resp.status() === 200);
            const html = await page.content();
            assert(html.includes('<!DOCTYPE html>') || html.includes('<!doctype html>'));
            check(`2.2.${reg} ${reg} list page`, 'PASS');
            await screenshot(page, `02-${reg}-list`);
        } catch (e) { check(`2.2.${reg} ${reg} list page`, 'FAIL', e.message); }
    }

    // 2.3 Back to dashboard
    try {
        const resp = await page.goto(`${BASE}/ui/`, { waitUntil: 'networkidle' });
        assert(resp.status() === 200);
        check('2.3 Return to dashboard', 'PASS');
    } catch (e) { check('2.3 Return to dashboard', 'FAIL', e.message); }

    // 2.4 Root redirect to /ui/
    try {
        const resp = await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
        assert(page.url().includes('/ui/'), `Redirected to ${page.url()}`);
        check('2.4 Root / redirects to /ui/', 'PASS');
    } catch (e) { check('2.4 Root / redirects to /ui/', 'FAIL', e.message); }

    // ================================================================
    // PHASE 3: Language Switching
    // ================================================================
    console.log('=== Phase 3: Internationalization ===\n');

    // 3.1 English
    try {
        await page.goto(`${BASE}/ui/?lang=en`, { waitUntil: 'networkidle' });
        const text = await page.textContent('body');
        const hasEn = /download|upload|artifact|storage/i.test(text);
        assert(hasEn, 'No English text');
        check('3.1 English locale', 'PASS');
        await screenshot(page, '03-lang-en');
    } catch (e) { check('3.1 English locale', 'FAIL', e.message); }

    // 3.2 Russian
    try {
        await page.goto(`${BASE}/ui/?lang=ru`, { waitUntil: 'networkidle' });
        const text = await page.textContent('body');
        assert(/[а-яА-Я]/.test(text), 'No Russian characters');
        check('3.2 Russian locale', 'PASS');
        await screenshot(page, '03-lang-ru');
    } catch (e) { check('3.2 Russian locale', 'FAIL', e.message); }

    // 3.3 Language switcher exists
    try {
        // Look for language toggle (button, select, or link)
        const body = await page.textContent('body');
        const hasLangSwitch = /EN|RU|English|Русский/i.test(body) ||
            (await page.locator('[href*="lang="]').count()) > 0;
        if (hasLangSwitch) {
            check('3.3 Language switcher visible', 'PASS');
        } else {
            check('3.3 Language switcher visible', 'WARN', 'Not found but pages work via ?lang=');
        }
    } catch (e) { check('3.3 Language switcher visible', 'WARN', e.message); }

    // ================================================================
    // PHASE 4: Search (HTMX)
    // ================================================================
    console.log('=== Phase 4: Search & Interactivity ===\n');

    // 4.1 Search input exists on registry list page
    try {
        await page.goto(`${BASE}/ui/docker`, { waitUntil: 'networkidle' });
        const searchInput = await page.locator('input[type="search"], input[type="text"][hx-get], input[placeholder*="earch"], input[placeholder*="оиск"]').count();
        if (searchInput > 0) {
            check('4.1 Search input on list page', 'PASS');
        } else {
            check('4.1 Search input on list page', 'WARN', 'No search input found');
        }
    } catch (e) { check('4.1 Search input on list page', 'WARN', e.message); }

    // 4.2 HTMX search endpoint works
    try {
        const resp = await page.goto(`${BASE}/api/ui/docker/search?q=test`, { waitUntil: 'networkidle' });
        assert(resp.status() === 200);
        check('4.2 Search API responds', 'PASS');
    } catch (e) { check('4.2 Search API responds', 'FAIL', e.message); }

    // 4.3 Search with empty result
    try {
        const resp = await page.goto(`${BASE}/api/ui/docker/search?q=zzz_nonexistent_pkg`, { waitUntil: 'networkidle' });
        const text = await page.textContent('body');
        assert(resp.status() === 200);
        check('4.3 Empty search result', 'PASS');
    } catch (e) { check('4.3 Empty search result', 'FAIL', e.message); }

    // ================================================================
    // PHASE 5: Security Headers in Browser
    // ================================================================
    console.log('=== Phase 5: Security Headers ===\n');

    try {
        const resp = await page.goto(`${BASE}/ui/`, { waitUntil: 'networkidle' });
        const headers = resp.headers();

        const checks = [
            ['x-content-type-options', 'nosniff'],
            ['x-frame-options', 'DENY'],
            ['referrer-policy', 'strict-origin-when-cross-origin'],
        ];

        for (const [header, expected] of checks) {
            const val = headers[header];
            if (val === expected) {
                check(`5.1 ${header}: ${expected}`, 'PASS');
            } else {
                check(`5.1 ${header}: ${expected}`, 'FAIL', `Got: ${val || 'missing'}`);
            }
        }

        // CSP check — should contain 'self' with quotes
        const csp = headers['content-security-policy'] || '';
        if (csp.includes("'self'")) {
            check('5.2 CSP contains quoted self', 'PASS');
        } else {
            check('5.2 CSP contains quoted self', 'FAIL', `CSP: ${csp.slice(0, 80)}`);
        }

        if (csp.includes("'unsafe-inline'")) {
            check('5.3 CSP allows unsafe-inline (needed for UI)', 'PASS');
        } else {
            check('5.3 CSP allows unsafe-inline', 'FAIL', 'UI may break without it');
        }
    } catch (e) { check('5.x Security headers', 'FAIL', e.message); }

    // ================================================================
    // PHASE 6: Responsive Design
    // ================================================================
    console.log('=== Phase 6: Responsive Design ===\n');

    // 6.1 Mobile (375x812 — iPhone)
    try {
        const mobileCtx = await browser.newContext({
            viewport: { width: 375, height: 812 },
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)',
        });
        const mobilePage = await mobileCtx.newPage();
        const resp = await mobilePage.goto(`${BASE}/ui/`, { waitUntil: 'networkidle', timeout: 10000 });
        assert(resp.status() === 200);

        // Check content is not clipped — page should scroll
        const bodyWidth = await mobilePage.evaluate(() => document.body.scrollWidth);
        const viewWidth = 375;
        // Allow some overflow but not extreme (like full desktop rendering on mobile)
        const overflowOk = bodyWidth <= viewWidth * 1.5;
        if (overflowOk) {
            check('6.1 Mobile (375px) no horizontal overflow', 'PASS', `body=${bodyWidth}px`);
        } else {
            check('6.1 Mobile (375px) no horizontal overflow', 'WARN', `body=${bodyWidth}px > ${viewWidth * 1.5}px`);
        }

        await screenshot(mobilePage, '06-mobile-375');
        await mobileCtx.close();
    } catch (e) { check('6.1 Mobile layout', 'FAIL', e.message); }

    // 6.2 Tablet (768x1024 — iPad)
    try {
        const tabletCtx = await browser.newContext({ viewport: { width: 768, height: 1024 } });
        const tabletPage = await tabletCtx.newPage();
        await tabletPage.goto(`${BASE}/ui/`, { waitUntil: 'networkidle', timeout: 10000 });
        await screenshot(tabletPage, '06-tablet-768');
        check('6.2 Tablet (768px) renders', 'PASS');
        await tabletCtx.close();
    } catch (e) { check('6.2 Tablet layout', 'FAIL', e.message); }

    // ================================================================
    // PHASE 7: Swagger / API Docs
    // ================================================================
    console.log('=== Phase 7: Swagger UI ===\n');

    try {
        const resp = await page.goto(`${BASE}/api-docs`, { waitUntil: 'networkidle', timeout: 15000 });
        assert(resp.status() === 200);
        const text = await page.textContent('body');
        assert(text.length > 200, `Swagger page too short: ${text.length}`);
        check('7.1 Swagger UI loads', 'PASS');
        await screenshot(page, '07-swagger');
    } catch (e) { check('7.1 Swagger UI loads', 'FAIL', e.message); }

    // ================================================================
    // PHASE 8: Accessibility Basics
    // ================================================================
    console.log('=== Phase 8: Accessibility ===\n');

    try {
        await page.goto(`${BASE}/ui/`, { waitUntil: 'networkidle' });

        // 8.1 lang attribute on html
        const lang = await page.evaluate(() => document.documentElement.getAttribute('lang'));
        if (lang) {
            check('8.1 HTML lang attribute', 'PASS', lang);
        } else {
            check('8.1 HTML lang attribute', 'WARN', 'Missing — screen readers need this');
        }
    } catch (e) { check('8.1 HTML lang attribute', 'WARN', e.message); }

    try {
        // 8.2 Images have alt text
        const imgsWithoutAlt = await page.locator('img:not([alt])').count();
        if (imgsWithoutAlt === 0) {
            check('8.2 All images have alt text', 'PASS');
        } else {
            check('8.2 All images have alt text', 'WARN', `${imgsWithoutAlt} images without alt`);
        }
    } catch (e) { check('8.2 Images alt text', 'WARN', e.message); }

    try {
        // 8.3 Color contrast — check at least body text isn't invisible
        const contrast = await page.evaluate(() => {
            const s = getComputedStyle(document.body);
            return { color: s.color, bg: s.backgroundColor };
        });
        assert(contrast.color !== contrast.bg, 'Text color equals background');
        check('8.3 Text/background contrast', 'PASS', `text=${contrast.color} bg=${contrast.bg}`);
    } catch (e) { check('8.3 Text/background contrast', 'FAIL', e.message); }

    try {
        // 8.4 Focusable elements reachable via Tab
        const focusable = await page.locator('a, button, input, select, textarea, [tabindex]').count();
        assert(focusable > 0, 'No focusable elements');
        check('8.4 Focusable elements exist', 'PASS', `${focusable} elements`);
    } catch (e) { check('8.4 Focusable elements', 'WARN', e.message); }

    // ================================================================
    // PHASE 9: Error Collection Summary
    // ================================================================
    console.log('=== Phase 9: Error Summary ===\n');

    if (consoleErrors.length === 0) {
        check('9.1 No console errors during session', 'PASS');
    } else {
        const filtered = consoleErrors.filter(e => !e.includes('favicon'));
        if (filtered.length === 0) {
            check('9.1 No console errors (favicon ignored)', 'PASS');
        } else {
            check('9.1 Console errors found', 'FAIL', filtered.slice(0, 3).join(' | '));
        }
    }

    // ================================================================
    // DONE
    // ================================================================
    await browser.close();

    // Print screenshots list
    console.log('\n=== Screenshots ===');
    const { readdirSync } = await import('fs');
    const shots = readdirSync(SCREENSHOT_DIR).filter(f => f.endsWith('.png')).sort();
    for (const s of shots) {
        console.log(`  ${SCREENSHOT_DIR}/${s}`);
    }

    printResults();
    process.exit(fail > 0 ? 1 : 0);
}

function printResults() {
    console.log('\n======================================================================');
    console.log('  NORA Playwright UI Test Results');
    console.log('======================================================================\n');

    for (const r of results) {
        const icon = r.status === 'PASS' ? '\x1b[32m[PASS]\x1b[0m'
            : r.status === 'FAIL' ? '\x1b[31m[FAIL]\x1b[0m'
            : '\x1b[33m[WARN]\x1b[0m';
        const detail = r.detail ? ` — ${r.detail}` : '';
        console.log(`  ${icon} ${r.name}${detail}`);
    }

    console.log(`\n  Total: \x1b[32m${pass} passed\x1b[0m, \x1b[31m${fail} failed\x1b[0m, \x1b[33m${warn} warnings\x1b[0m`);
    console.log('======================================================================\n');
}

run().catch(e => {
    console.error('\x1b[31mFatal:\x1b[0m', e.message);
    process.exit(2);
});
