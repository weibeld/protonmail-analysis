// List all exported functions of the pmcrypto package
//
// Usage:
//   $ npm install github:ProtonMail/pmcrypto
//   $ node exports-pmcrypto.js
Object.keys(require('pmcrypto')).forEach(o => console.log(o));
