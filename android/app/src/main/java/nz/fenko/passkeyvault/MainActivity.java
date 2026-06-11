package nz.fenko.passkeyvault;

import android.Manifest;
import android.app.Activity;
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
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.webkit.ConsoleMessage;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;
import java.io.IOException;
import java.io.InputStream;

public final class MainActivity extends Activity {
    private static final int CAMERA_REQUEST = 42;
    private static final String APP_ORIGIN = "app.passkey-vault.local";
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView.setWebContentsDebuggingEnabled(true);

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
                request.grant(request.getResources());
            }

            @Override
            public boolean onConsoleMessage(ConsoleMessage message) {
                android.util.Log.d("FenkoVaultWeb", message.message());
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
