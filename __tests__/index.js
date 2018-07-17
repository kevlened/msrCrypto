const crypto = require('../dist/msrcrypto');

require('webcrypto-test-suite')({
  crypto,
  shouldSkip(spec) {
    if (spec.includes('RS256') && spec.includes('generateKey')) return true;
    if (spec.includes('RS384') && spec.includes('generateKey')) return true;
    if (spec.includes('RS512') && spec.includes('generateKey')) return true;
  }
});
