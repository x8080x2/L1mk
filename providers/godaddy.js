function createGoDaddyProvider(deps) {
    const { cfg, typeHuman, clickAndWait, clickSmart } = deps;

    const submitEmailIfPresent = async (page, email) => {
        const emailSelectors = ['input[type="email"]', 'input[name="username"]', '#username'];
        let found = null;
        for (const selector of emailSelectors) {
            const handle = await page.$(selector).catch(() => null);
            if (handle) {
                found = { selector, handle };
                break;
            }
        }
        if (!found) return true;
        await typeHuman(page, found.selector, email);
        await found.handle.dispose().catch(() => {});
        const submitSelectors = ['button[type="submit"]', 'input[type="submit"]'];
        for (const s of submitSelectors) {
            const ok = await clickSmart(page, s);
            if (ok) {
                await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: cfg.navTimeoutMs }).catch(() => {});
                break;
            }
        }
        return true;
    };

    const enterPasswordAndSubmit = async (page, password) => {
        let input = null;
        for (let i = 0; i < 8; i++) {
            input = await page.$('#password').catch(() => null);
            if (input) break;
            await new Promise(r => setTimeout(r, 750));
        }
        if (!input) return false;
        try {
            await input.click({ clickCount: 3 }).catch(() => {});
            await input.type(password, { delay: Math.floor(Math.random() * 20) + 10 });
        } catch (e) {
            return false;
        }
        const submitSelectors = ['button[type="submit"]', 'input[type="submit"]'];
        for (const s of submitSelectors) {
            const ok = await clickSmart(page, s);
            if (ok) {
                await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: cfg.navTimeoutMs }).catch(() => {});
                break;
            }
        }
        await input.dispose().catch(() => {});
        return true;
    };

    return {
        name: 'godaddy',
        detect: async (page) => {
            const url = String(page.url() || '');
            if (url.includes('sso.godaddy.com') || url.includes('login.secureserver.net') || url.includes('godaddy.com')) {
                return true;
            }
            const found = await page.$('#password').catch(() => null);
            if (found) {
                await found.dispose().catch(() => {});
                return true;
            }
            return false;
        },
        login: async ({ page, email, password, simulate }) => {
            if (simulate) {
                await submitEmailIfPresent(page, email);
                return { passwordAttempted: false, ok: true };
            }
            await submitEmailIfPresent(page, email);
            const ok = await enterPasswordAndSubmit(page, password);
            return { passwordAttempted: true, ok };
        }
    };
}

module.exports = { createGoDaddyProvider };
