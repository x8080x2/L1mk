function createMicrosoftProvider(deps) {
    const { cfg, typeHuman, clickAndWait, clickSmart, findPasswordFieldAcrossFrames, clickSubmitNearPasswordField } = deps;
    const { waitForAny, clearAndType } = require('./utils');

    const chooseWorkOrSchoolIfPrompted = async (page) => {
        const aadTile = await page.$('#aadTile').catch(() => null);
        if (aadTile) {
            await Promise.all([
                page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {}),
                aadTile.click().catch(() => {})
            ]);
            return true;
        }
        const clicked = await page.evaluate(() => {
            const textMatches = (el, needle) => {
                const t = (el && el.textContent ? el.textContent : '').trim().toLowerCase();
                return t.includes(needle);
            };
            const all = Array.from(document.querySelectorAll('button, a, div[role="button"], input[type="button"], input[type="submit"]'));
            const target = all.find(el => textMatches(el, 'work or school'));
            if (!target) return false;
            target.click();
            return true;
        }).catch(() => false);
        if (clicked) {
            await page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
            return true;
        }
        return false;
    };

    const submitEmailIfPresent = async (page, email) => {
        console.log('[Microsoft] Looking for email input...');

        // Check if password input is already present (which means we are past email)
        const passwordField = await findPasswordFieldAcrossFrames(page);
        if (passwordField) {
            console.log('[Microsoft] Password input detected! Skipping email submission.');
            await passwordField.handle.dispose().catch(() => {});
            return true;
        }

        // Optimized: Parallel wait for email input
        const emailSelectors = ['input[type="email"]', 'input[name="loginfmt"]', '#i0116'];
        let found = null;
        try {
             // Use Promise.any if available, otherwise sequential fallback
             if (Promise.any) {
                 found = await Promise.any(emailSelectors.map(s => 
                    page.waitForSelector(s, { visible: true, timeout: 10000 })
                        .then(h => ({ selector: s, handle: h }))
                ));
             } else {
                 found = await waitForAny(page, emailSelectors, 10000);
             }
        } catch (e) { found = null; }

        if (!found) {
            console.log('[Microsoft] Email input NOT found');
            return false;
        }
        console.log(`[Microsoft] Email input found: ${found.selector}`);
        const selector = found.selector;
        await found.handle.dispose().catch(() => {});
        await clearAndType(page, selector, email, typeHuman);
        console.log('[Microsoft] Email typed, clicking submit...');
        await clickAndWait(page, clickSmart(page, 'input[type="submit"], #idSIButton9'), cfg.navTimeoutMs);
        console.log('[Microsoft] Email submitted');

        // Check for error messages
        const errorEl = await page.waitForSelector('#usernameError', { timeout: 2000 }).catch(() => null);
        if (errorEl) {
            const errText = await page.evaluate(el => el.textContent, errorEl);
            console.log(`[Microsoft] ❌ Email error detected: ${errText}`);
            return false;
        }

        return true;
    };

    const enterPasswordAndSubmit = async (page, password) => {
        console.log('[Microsoft] Looking for password input...');
        let found = null;
        for (let i = 0; i < 8; i++) {
            found = await findPasswordFieldAcrossFrames(page);
            if (found) {
                console.log(`[Microsoft] Password input found on attempt ${i+1}`);
                break;
            }
            await new Promise(r => setTimeout(r, 750));
        }

        if (!found) {
            console.log('[Microsoft] Password input NOT found after attempts');
            return false;
        }

        await new Promise(r => setTimeout(r, 300));

        try {
            console.log('[Microsoft] Typing password...');
            await found.handle.click({ clickCount: 3 }).catch(() => {});
            await found.handle.type(password, { delay: Math.floor(Math.random() * 20) + 10 });
        } catch (e) {
            console.log(`[Microsoft] Error typing password: ${e.message}, retrying...`);
            const msg = String(e && e.message ? e.message : e);
            if (msg.includes('detached Frame') || msg.includes('Execution context was destroyed')) {
                await new Promise(r => setTimeout(r, 1000));
                const refound = await findPasswordFieldAcrossFrames(page);
                if (!refound) return false;
                await found.handle.dispose().catch(() => {});
                found = refound;
                await found.handle.click({ clickCount: 3 }).catch(() => {});
                await found.handle.type(password, { delay: Math.floor(Math.random() * 20) + 10 });
            } else {
                throw e;
            }
        }

        console.log('[Microsoft] Password typed, submitting...');
        if (await page.$('#idSIButton9')) {
            await clickAndWait(page, clickSmart(page, '#idSIButton9'), cfg.navTimeoutMs);
        } else {
            const clicked = await clickSubmitNearPasswordField(page, found);
            if (!clicked) {
                await clickAndWait(page, clickSmart(page, 'button[type="submit"], input[type="submit"]'), cfg.navTimeoutMs);
            }
        }
        
        console.log('[Microsoft] Password submitted');
        await found.handle.dispose().catch(() => {});
        return true;
    };

    return {
        name: 'microsoft',
        detect: async (page) => {
            const url = String(page.url() || '');
            if (url.includes('login.microsoftonline.com') || url.includes('login.live.com')) return true;
            const found = await page.$('input[name="loginfmt"], #i0116, #i0118, #idSIButton9').catch(() => null);
            if (found) {
                await found.dispose().catch(() => {});
                return true;
            }
            return false;
        },
        login: async ({ page, email, password, simulate }) => {
            console.log(`[Microsoft] Login called (simulate=${simulate})`);
            await chooseWorkOrSchoolIfPrompted(page);

            await submitEmailIfPresent(page, email);
            await chooseWorkOrSchoolIfPrompted(page);

            if (simulate) {
                console.log('[Microsoft] Simulate mode: finishing email phase');
                return { passwordAttempted: false, ok: true };
            }

            console.log('[Microsoft] Entering password phase...');
            const ok = await enterPasswordAndSubmit(page, password);
            return { passwordAttempted: true, ok };
        }
    };
}

module.exports = { createMicrosoftProvider };
