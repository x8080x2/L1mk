const { createMicrosoftProvider } = require('./microsoft');
const { createGoDaddyProvider } = require('./godaddy');

function createProviders(deps) {
    return [
        createMicrosoftProvider(deps),
        createGoDaddyProvider(deps)
    ];
}

module.exports = { createProviders };
