package nz.fenko.passkeyvault;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.text.InputType;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.ConsoleMessage;
import android.webkit.JavascriptInterface;
import android.webkit.JsPromptResult;
import android.webkit.JsResult;
import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.Toast;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    private static final int CAMERA_REQUEST = 42;
    private static final int CREATE_FILE_REQUEST = 43;
    private static final String APP_ORIGIN = "app.passkey-vault.local";
    private WebView webView;
    private byte[] pendingFileBytes;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Only expose the WebView to remote debugging (chrome://inspect) in
        // debuggable builds. In a release build this would let anyone with ADB
        // read the decrypted vault out of the page's JS/DOM.
        boolean isDebuggable =
                (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        WebView.setWebContentsDebuggingEnabled(isDebuggable);

        webView = new WebView(this);
        webView.setLayoutParams(new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        webView.setBackgroundColor(0xFF0D1117);

        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(0xFF0D1117);
        root.addView(webView);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setDecorFitsSystemWindows(false);
            // WebView ignores its own padding, so insets go on the wrapper.
            // IME is included so the keyboard lifts the bottom bar instead of covering it.
            root.setOnApplyWindowInsetsListener((view, insets) -> {
                android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.systemBars()
                                | WindowInsets.Type.displayCutout()
                                | WindowInsets.Type.ime());
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom);
                return WindowInsets.CONSUMED;
            });
        }

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setMediaPlaybackRequiresUserGesture(false);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setBlockNetworkLoads(false);

        webView.addJavascriptInterface(new AndroidBridge(this), "AndroidBridge");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    return assetResponse(request.getUrl());
                }
                return super.shouldInterceptRequest(view, request);
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (APP_ORIGIN.equals(url.getHost())) {
                    return false;
                }
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, url));
                } catch (ActivityNotFoundException e) {
                    Toast.makeText(MainActivity.this, "No app can open this link", Toast.LENGTH_SHORT).show();
                }
                return true;
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onPermissionRequest(PermissionRequest request) {
                // Only grant the camera (needed for QR scanning); never blanket-grant
                // every requested resource (which would also hand over the microphone).
                java.util.List<String> allowed = new java.util.ArrayList<>();
                for (String resource : request.getResources()) {
                    if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource)) {
                        allowed.add(resource);
                    }
                }
                if (allowed.isEmpty()) {
                    request.deny();
                } else {
                    request.grant(allowed.toArray(new String[0]));
                }
            }

            @Override
            public boolean onConsoleMessage(ConsoleMessage message) {
                // Avoid mirroring web console output to logcat in release builds.
                if ((getApplicationInfo().flags
                        & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    android.util.Log.d("FenkoVaultWeb", message.message());
                }
                return true;
            }

            // A custom WebChromeClient suppresses the WebView's built-in JS
            // dialogs, so window.alert/confirm/prompt would silently return
            // null/false. The web vault uses prompt() for backup passwords and
            // confirm() for wipe, so without these the encrypted export/import
            // and wipe actions appear to do nothing. Wire them to native dialogs.
            @Override
            public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
                new AlertDialog.Builder(MainActivity.this, android.R.style.Theme_Material_Dialog_Alert)
                        .setMessage(message)
                        .setCancelable(false)
                        .setPositiveButton(android.R.string.ok, (dialog, which) -> result.confirm())
                        .show();
                return true;
            }

            @Override
            public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
                new AlertDialog.Builder(MainActivity.this, android.R.style.Theme_Material_Dialog_Alert)
                        .setMessage(message)
                        .setPositiveButton(android.R.string.ok, (dialog, which) -> result.confirm())
                        .setNegativeButton(android.R.string.cancel, (dialog, which) -> result.cancel())
                        .setOnCancelListener(dialog -> result.cancel())
                        .show();
                return true;
            }

            @Override
            public boolean onJsPrompt(WebView view, String url, String message, String defaultValue,
                    JsPromptResult result) {
                final EditText input = new EditText(MainActivity.this);
                if (defaultValue != null) {
                    input.setText(defaultValue);
                }
                // prompt() is only used for backup passwords here; mask the input.
                if (message != null && message.toLowerCase().contains("password")) {
                    input.setInputType(InputType.TYPE_CLASS_TEXT
                            | InputType.TYPE_TEXT_VARIATION_PASSWORD);
                }
                int pad = (int) (20 * getResources().getDisplayMetrics().density);
                input.setPadding(pad, input.getPaddingTop(), pad, input.getPaddingBottom());
                new AlertDialog.Builder(MainActivity.this, android.R.style.Theme_Material_Dialog_Alert)
                        .setMessage(message)
                        .setView(input)
                        .setPositiveButton(android.R.string.ok,
                                (dialog, which) -> result.confirm(input.getText().toString()))
                        .setNegativeButton(android.R.string.cancel, (dialog, which) -> result.cancel())
                        .setOnCancelListener(dialog -> result.cancel())
                        .show();
                return true;
            }
        });

        setContentView(root);
        ensureCameraPermission();
        webView.loadUrl("https://" + APP_ORIGIN + "/index.html");
    }

    private WebResourceResponse assetResponse(Uri uri) {
        if (!APP_ORIGIN.equals(uri.getHost())) {
            return null;
        }

        String path = uri.getPath();
        if (path == null || path.equals("/") || path.isEmpty()) {
            path = "/index.html";
        }
        String asset = path.startsWith("/") ? path.substring(1) : path;

        try {
            InputStream stream = getAssets().open(asset);
            return new WebResourceResponse(mimeType(asset), "UTF-8", stream);
        } catch (IOException e) {
            return new WebResourceResponse("text/plain", "UTF-8", null);
        }
    }

    private static String mimeType(String asset) {
        if (asset.endsWith(".html")) return "text/html";
        if (asset.endsWith(".css")) return "text/css";
        if (asset.endsWith(".js")) return "application/javascript";
        if (asset.endsWith(".png")) return "image/png";
        if (asset.endsWith(".svg")) return "image/svg+xml";
        if (asset.endsWith(".ttf")) return "font/ttf";
        if (asset.endsWith(".woff2")) return "font/woff2";
        return "application/octet-stream";
    }

    private void ensureCameraPermission() {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, CAMERA_REQUEST);
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
            return;
        }
        super.onBackPressed();
    }

    // Opens the system "Save to..." dialog (Storage Access Framework) so the
    // user can write a backup anywhere — Downloads, Drive, etc. The bytes are
    // held until the picker returns in onActivityResult.
    private void startSaveFile(String suggestedName, String mimeType, String content) {
        pendingFileBytes = content.getBytes(StandardCharsets.UTF_8);
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType(mimeType != null && !mimeType.isEmpty() ? mimeType : "application/json");
        intent.putExtra(Intent.EXTRA_TITLE, suggestedName);
        try {
            startActivityForResult(intent, CREATE_FILE_REQUEST);
        } catch (ActivityNotFoundException e) {
            pendingFileBytes = null;
            Toast.makeText(this, "No file manager available", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != CREATE_FILE_REQUEST) {
            return;
        }
        byte[] bytes = pendingFileBytes;
        pendingFileBytes = null;
        if (resultCode != Activity.RESULT_OK || data == null || data.getData() == null || bytes == null) {
            return;
        }
        try (OutputStream out = getContentResolver().openOutputStream(data.getData())) {
            if (out != null) {
                out.write(bytes);
                out.flush();
                Toast.makeText(this, "Backup saved", Toast.LENGTH_SHORT).show();
            }
        } catch (IOException e) {
            Toast.makeText(this, "Could not save file", Toast.LENGTH_SHORT).show();
        }
    }

    private void postBiometricResult(boolean ok) {
        runOnUiThread(() -> webView.evaluateJavascript(
                "window.__fenkoBiometricResult && window.__fenkoBiometricResult(" + ok + ")", null));
    }

    public static final class AndroidBridge {
        private final MainActivity context;

        AndroidBridge(MainActivity context) {
            this.context = context;
        }

        @JavascriptInterface
        public boolean canUseBiometrics() {
            BiometricManager manager = context.getSystemService(BiometricManager.class);
            if (manager == null) {
                return false;
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                return manager.canAuthenticate(
                        BiometricManager.Authenticators.BIOMETRIC_WEAK
                                | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                        == BiometricManager.BIOMETRIC_SUCCESS;
            }
            return manager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
        }

        @JavascriptInterface
        public void requestBiometricUnlock() {
            context.runOnUiThread(() -> {
                BiometricPrompt.Builder builder = new BiometricPrompt.Builder(context)
                        .setTitle("Unlock Fenko Vault")
                        .setSubtitle("Use your face, fingerprint, or screen lock");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    builder.setAllowedAuthenticators(
                            BiometricManager.Authenticators.BIOMETRIC_WEAK
                                    | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
                } else {
                    builder.setDeviceCredentialAllowed(true);
                }
                builder.build().authenticate(
                        new CancellationSignal(),
                        context.getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(
                                    BiometricPrompt.AuthenticationResult result) {
                                context.postBiometricResult(true);
                            }

                            @Override
                            public void onAuthenticationError(int errorCode, CharSequence errString) {
                                context.postBiometricResult(false);
                            }
                        });
            });
        }

        @JavascriptInterface
        public void copyText(String value) {
            ClipboardManager clipboard =
                    (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setPrimaryClip(ClipData.newPlainText("Fenko Vault", value));
            Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show();
        }

        @JavascriptInterface
        public void toast(String value) {
            Toast.makeText(context, value, Toast.LENGTH_SHORT).show();
        }

        @JavascriptInterface
        public void saveFile(String suggestedName, String mimeType, String content) {
            context.runOnUiThread(() -> context.startSaveFile(suggestedName, mimeType, content));
        }

        @JavascriptInterface
        public String loadVaultSnapshot() {
            return ProviderVaultStore.loadSnapshot(context).toString();
        }

        @JavascriptInterface
        public void saveVaultSnapshot(
                String passkeysJson,
                String totpJson,
                String syncConfigJson,
                String syncDevicesJson,
                String customRelaysJson) {
            ProviderVaultStore.saveSnapshot(
                    context,
                    passkeysJson,
                    totpJson,
                    syncConfigJson,
                    syncDevicesJson,
                    customRelaysJson);
        }
    }
}
