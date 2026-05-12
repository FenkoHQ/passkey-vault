const fs = require('fs');
const path = require('path');

const manifest = {
  manifest_version: 3,
  name: 'Passkey Vault',
  version: process.env.npm_package_version || '0.1.0',
  description: 'Secure passkey storage and management',

  permissions: ['storage', 'activeTab', 'scripting', 'offscreen', 'background'],

  host_permissions: ['https://*/*', 'http://localhost:*/*'],

  background: {
    service_worker: 'background.js',
    type: 'module',
  },

  content_scripts: [
    {
      matches: ['https://*/*', 'http://localhost:*/*'],
      js: ['content.js'],
      run_at: 'document_start',
      all_frames: true,
    },
  ],

  web_accessible_resources: [
    {
      resources: ['webauthn-inject.js'],
      matches: ['https://*/*', 'http://localhost:*/*'],
    },
  ],

  action: {
    default_title: 'Passkey Vault',
  },

  icons: {
    16: 'icons/icon16.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png',
  },

  content_security_policy: {
    extension_pages: "script-src 'self'; object-src 'self'",
  },
};

const distPath = path.join(__dirname, '..', 'dist');
const manifestPath = path.join(distPath, 'manifest.json');

// Ensure dist directory exists
if (!fs.existsSync(distPath)) {
  fs.mkdirSync(distPath, { recursive: true });
}

// Write manifest.json
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

console.log('Manifest generated successfully:', manifestPath);
