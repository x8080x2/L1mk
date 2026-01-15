async function waitForAny(page, selectors, timeoutMs) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        for (const selector of selectors) {
            const handle = await page.$(selector).catch(() => null);
            if (handle) return { selector, handle };
        }
        await new Promise(r => setTimeout(r, 150));
    }
    return null;
}

async function clearAndType(page, selector, text, typeFn) {
    await page.waitForSelector(selector, { timeout: 8000 }).catch(() => {});
    await page.focus(selector).catch(() => {});
    await page.evaluate((sel) => {
        const el = document.querySelector(sel);
        if (!el) return;
        if (typeof el.value !== 'undefined') el.value = '';
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
    }, selector).catch(() => {});
    await typeFn(page, selector, text);
}

async function clickSmart(page, selector) {
    try {
        await page.click(selector, { delay: Math.floor(Math.random() * 20) + 10 });
        return true;
    } catch {}
    try {
        const ok = await page.evaluate((sel) => {
            const el = document.querySelector(sel);
            if (!el) return false;
            el.scrollIntoView({ block: 'center', inline: 'center' });
            el.click();
            return true;
        }, selector);
        if (ok) return true;
    } catch {}
    const handle = await page.$(selector).catch(() => null);
    if (!handle) return false;
    try {
        await handle.click();
        return true;
    } catch {
        return false;
    } finally {
        await handle.dispose().catch(() => {});
    }
}

module.exports = { waitForAny, clearAndType, clickSmart };
