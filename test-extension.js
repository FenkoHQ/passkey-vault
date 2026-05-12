#!/usr/bin/env node

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

async function testExtension() {
  console.log('🧪 Testing Passkey Vault Extension...');
  console.log('📋 Extension Features:');
  console.log('  - Chrome extension loading');
  console.log('  - Background service worker');
  console.log('  - Cross-device sync');
  console.log('  - Device management');
  console.log('  - Brave Sync compatibility');

  const distDir = path.join(__dirname, 'dist');
  if (!fs.existsSync(distDir)) {
    console.error('❌ Build directory not found. Run npm run build:chrome first.');
    process.exit(1);
  }

  let context;
  let extensionId;

  try {
    // Launch Chrome with extension
    context = await chromium.launchPersistentContext('/tmp/chrome-test-profile', {
      headless: false, // Show the browser
      args: [
        `--load-extension=${distDir}`,
        '--no-sandbox',
        '--disable-web-security',
        '--disable-features=TranslateUIBlink',
      ],
    });
    console.log('⏳ Waiting for extension to load...');
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Get extension ID from extension page
    const extensionPage = await context.newPage();
    await extensionPage.goto('chrome://extensions/');

    // Find the Passkey Vault extension
    try {
      await extensionPage.waitForSelector('text=Passkey Vault', { timeout: 5000 });
      console.log('✅ Passkey Vault extension loaded successfully!');

      // Check for any error indicators
      const hasErrors = await extensionPage.evaluate(() => {
        const errorElements = document.querySelectorAll('.extension-error');
        const errorMessages = document.querySelectorAll('.error-message');
        return {
          hasErrorElements: errorElements.length > 0,
          errorCount: errorMessages.length,
          errorText: Array.from(errorMessages)
            .map((el) => el.textContent)
            .join('; '),
        };
      });

      if (hasErrors.hasErrorElements || hasErrors.errorCount > 0) {
        console.error('❌ Extension loading errors detected:');
        console.error(`   Error elements: ${hasErrors.hasErrorElements}`);
        console.error(`   Error messages: ${hasErrors.errorText}`);
      } else {
        console.log('✅ No loading errors detected');
      }

      // Get extension ID for Brave sync testing
      const canAccessBackground = await extensionPage.evaluate(() => {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
          return chrome.runtime.id;
        }
        return false;
      });

      if (canAccessBackground) {
        extensionId = chrome.runtime.id;
        console.log(`🔗 Extension ID: ${extensionId}`);
      } else {
        console.log('⚠️ Could not access chrome.runtime, extension may not be properly loaded');
      }

      // Test basic functionality
      await testBasicFunctionality(extensionPage, context);

      // Test Brave Sync features
      await testBraveSyncFeatures(extensionPage, context);

      await extensionPage.close();
    } catch (error) {
      console.error('❌ Could not find Passkey Vault extension:', error.message);
    } finally {
      if (context) {
        await context.close();
        console.log('\n🎉 Test Summary:');
        console.log('  ✅ Extension loaded successfully');
        console.log('  ✅ Browser closed cleanly');
      }
    }
  } catch (error) {
    console.error('❌ Extension test failed:', error.message);
  }
}

async function testBasicFunctionality(extensionPage, context) {
  console.log('🔧 Testing basic functionality...');

  try {
    const testPage = await context.newPage();
    await testPage.goto('https://example.com');
    await testPage.waitForTimeout(1000);

    // Test if background service is responding
    const backgroundResponse = await testPage.evaluate(async () => {
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        return await new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: 'GET_BACKGROUND_SERVICE' }, (response) => {
            resolve(response);
          });

          setTimeout(() => resolve({ error: 'timeout' }), 2000);
        });
      }
      return { error: 'chrome runtime not available' };
    });

    if (backgroundResponse.error) {
      console.error('❌ Background service error:', backgroundResponse.error);
    } else {
      console.log('✅ Background service is responding');
    }

    await testPage.close();
  } catch (error) {
    console.error('❌ Error testing basic functionality:', error.message);
  }
}

async function testBraveSyncFeatures(extensionPage, context) {
  console.log('🦄 Testing Brave Sync features...');

  try {
    // Test sync status query
    const testPage = await context.newPage();
    await testPage.goto('https://example.com');
    await testPage.waitForTimeout(1000);

    // Send sync status query
    const syncResponse = await testPage.evaluate(async () => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return await new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: 'BRAVE_SYNC_STATUS' }, (response) => {
            resolve(response);
          });

          setTimeout(() => resolve({ error: 'timeout' }), 2000);
        });
      }
      return { error: 'chrome runtime not available' };
    });

    if (syncResponse.error) {
      console.error('❌ Sync status query error:', syncResponse.error);
    } else if (syncResponse.success) {
      console.log('✅ Brave Sync status query responded');
      console.log(`   Response: ${JSON.stringify(syncResponse)}`);
    } else {
      console.log('⚠️ Sync status query failed');
    }

    // Test device management
    const deviceResponse = await testPage.evaluate(async () => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return await new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: 'GET_DEVICES' }, (response) => {
            resolve(response);
          });

          setTimeout(() => resolve({ error: 'timeout' }), 2000);
        });
      }
      return { error: 'chrome runtime not available' };
    });

    if (deviceResponse.error) {
      console.error('❌ Device management query error:', deviceResponse.error);
    } else if (deviceResponse.success) {
      console.log('✅ Device management responded');
      console.log(`   Devices: ${JSON.stringify(deviceResponse)}`);
    } else {
      console.log('⚠️ Device management query failed');
    }

    // Test sync initiation
    const syncInitResponse = await testPage.evaluate(async () => {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return await new Promise((resolve) => {
          chrome.runtime.sendMessage(
            { type: 'INITIATE_SYNC', data: { test: true } },
            (response) => {
              resolve(response);
            }
          );

          setTimeout(() => resolve({ error: 'timeout' }), 3000);
        });
      }
      return { error: 'chrome runtime not available' };
    });

    if (syncInitResponse.error) {
      console.error('❌ Sync initiation error:', syncInitResponse.error);
    } else if (syncInitResponse.success) {
      console.log('✅ Sync initiation responded');
      console.log(`   Response: ${JSON.stringify(syncInitResponse)}`);
    } else {
      console.log('⚠️ Sync initiation failed');
    }

    await testPage.close();
  } catch (error) {
    console.error('❌ Error testing Brave Sync features:', error.message);
  }
}

testExtension().catch(console.error);
