const os = require('os');

let browsers = ['ChromeHeadless', 'FirefoxHeadless'];
if (process.platform === 'darwin') {
  browsers.push('Safari');
} else if (process.platform === 'win32' && 
          os.release().slice(3) === '10.') {
  browsers.push('Edge');
}

module.exports = function(config) {
  config.set({
    frameworks: ['jasmine'],
    files: [
      '__tests__/index.js'
    ],
    preprocessors: {
      '__tests__/index.js': ['webpack']
    },
    webpack: {
      mode: 'none',
      node: false
    },
    browserDisconnectTimeout: 5000,
    reporters: ['progress'],
    port: 9876,
    colors: true,
    // config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers,
    customLaunchers: {
      FirefoxHeadless: {
        base: 'Firefox',
        flags: ['-headless']
      }
    }
  })
}
