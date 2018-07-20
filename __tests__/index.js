const hasDocument = typeof document !== 'undefined';
const crypto = require('../');

require('webcrypto-test-suite')({
  crypto,
  shouldSkip(spec) {
    if (spec.includes('RS256') && spec.includes('generateKey')) return true;
    if (spec.includes('RS384') && spec.includes('generateKey')) return true;
    if (spec.includes('RS512') && spec.includes('generateKey')) return true;
  }
});

// Can't use jest in a browser
if (!hasDocument && typeof describe !== 'undefined') {
  describe('msrCryptoPermanentForceSync', () => {
    beforeEach(() => jest.resetModules());
  
    it('attempts to use Worker if available', async () => {
      global.Worker = jest.fn(() => {
        throw 'Will get caught';
      });
      const msrCrypto = require('../');
      await msrCrypto.subtle.digest(
        { name: 'SHA-256' },
        new Uint8Array([1,2,3]).buffer
      );
      expect(global.Worker).toHaveBeenCalled();
    });
  
    it('does not attempt to use Worker if msrCryptoPermanentForceSync enabled', async () => {
      global.msrCryptoPermanentForceSync = true;
      global.Worker = jest.fn(() => {
        throw 'Will get caught';
      });
      const msrCrypto = require('../');
      await msrCrypto.subtle.digest(
        { name: 'SHA-256' },
        new Uint8Array([1,2,3]).buffer
      );
      expect(global.Worker).not.toHaveBeenCalled();
    });
  });
}
