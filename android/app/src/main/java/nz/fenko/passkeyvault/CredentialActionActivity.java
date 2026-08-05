package nz.fenko.passkeyvault;

import android.app.Activity;
import android.app.KeyguardManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.content.Intent;
import java.util.function.Consumer;
import android.os.Bundle;
import android.service.credentials.CreateCredentialRequest;
import android.service.credentials.CredentialProviderService;
import android.service.credentials.GetCredentialRequest;
import android.credentials.CreateCredentialException;
import android.credentials.CreateCredentialResponse;
import android.credentials.Credential;
import android.credentials.CredentialOption;
import android.credentials.GetCredentialException;
import android.credentials.GetCredentialResponse;
import java.util.List;
import java.security.MessageDigest;
import android.util.Base64;

public final class CredentialActionActivity extends Activity {
    static final String EXTRA_ACTION = "nz.fenko.passkeyvault.extra.ACTION";
    static final String EXTRA_CREDENTIAL_ID = "nz.fenko.passkeyvault.extra.CREDENTIAL_ID";
    static final String EXTRA_OPTION_ID = "nz.fenko.passkeyvault.extra.OPTION_ID";
    static final String EXTRA_CREDENTIAL_TYPE = "nz.fenko.passkeyvault.extra.CREDENTIAL_TYPE";
    static final String ACTION_GET = "get";
    static final String ACTION_CREATE = "create";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String action = getIntent().getStringExtra(EXTRA_ACTION);
        if (ACTION_CREATE.equals(action)
                || getIntent().hasExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST)) {
            handleCreate();
        } else {
            handleGet();
        }
    }

    private void handleGet() {
        try {
            String credentialId = getIntent().getStringExtra(EXTRA_CREDENTIAL_ID);
            ProviderVaultStore.PasskeyRecord passkey =
                    ProviderVaultStore.findPasskey(this, credentialId);
            if (passkey == null) {
                finishGetError(GetCredentialException.TYPE_NO_CREDENTIAL, "Passkey not found");
                return;
            }

            GetCredentialRequest request = getIntent().getParcelableExtra(
                    CredentialProviderService.EXTRA_GET_CREDENTIAL_REQUEST);
            String requestJson = requestJsonFromGetRequest(request);
            if (!ProviderVaultStore.requestAllowsCredential(requestJson, passkey.credentialId)) {
                finishGetError(GetCredentialException.TYPE_NO_CREDENTIAL, "Passkey not allowed");
                return;
            }

            String privilegedOrigin = request == null || request.getCallingAppInfo() == null
                    ? null : request.getCallingAppInfo().getOrigin();
            String origin = callingAppOrigin(request == null ? null : request.getCallingAppInfo(), privilegedOrigin);
            byte[] clientDataHash = privilegedOrigin == null ? null : clientDataHashFromGetRequest(request);
            verifyUser(verified -> {
                try {
                    String authenticationJson = WebAuthnNative.authenticationResponseJson(
                            passkey, requestJson, origin, clientDataHash, verified);
                    ProviderVaultStore.upsertPasskey(this, passkey);
                    Bundle data = publicKeyBundle(WebAuthnNative.KEY_AUTH_RESPONSE_JSON, authenticationJson);
                    Credential credential = new Credential(WebAuthnNative.TYPE_PUBLIC_KEY_CREDENTIAL, data);
                    Intent result = new Intent();
                    result.putExtra(CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                            new GetCredentialResponse(credential));
                    setResult(RESULT_OK, result);
                    finish();
                } catch (Exception e) {
                    finishGetError(GetCredentialException.TYPE_UNKNOWN, e.getMessage());
                }
            }, () -> finishGetError(GetCredentialException.TYPE_USER_CANCELED, "User verification required"));
        } catch (Exception e) {
            finishGetError(GetCredentialException.TYPE_UNKNOWN, e.getMessage());
        }
    }

    private void handleCreate() {
        try {
            CreateCredentialRequest request = getIntent().getParcelableExtra(
                    CredentialProviderService.EXTRA_CREATE_CREDENTIAL_REQUEST);
            if (request == null || !WebAuthnNative.isPublicKeyType(request.getType())) {
                finishCreateError(CreateCredentialException.TYPE_NO_CREATE_OPTIONS, "Unsupported credential type");
                return;
            }

            String requestJson = ProviderVaultStore.requestJson(request.getData());
            String privilegedOrigin = request.getCallingAppInfo() == null ? null : request.getCallingAppInfo().getOrigin();
            String origin = callingAppOrigin(request.getCallingAppInfo(), privilegedOrigin);
            verifyUser(verified -> {
                try {
                    ProviderVaultStore.PasskeyRecord passkey = WebAuthnNative.createPasskey(requestJson, origin);
                    String registrationJson = WebAuthnNative.registrationResponseJson(passkey, requestJson, origin, verified);
                    ProviderVaultStore.upsertPasskey(this, passkey);
                    Bundle data = publicKeyBundle(WebAuthnNative.KEY_REG_RESPONSE_JSON, registrationJson);
                    Intent result = new Intent();
                    result.putExtra(CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                            new CreateCredentialResponse(data));
                    setResult(RESULT_OK, result);
                    finish();
                } catch (Exception e) {
                    finishCreateError(CreateCredentialException.TYPE_UNKNOWN, e.getMessage());
                }
            }, () -> finishCreateError(CreateCredentialException.TYPE_USER_CANCELED, "User verification required"));
        } catch (Exception e) {
            finishCreateError(CreateCredentialException.TYPE_UNKNOWN, e.getMessage());
        }
    }

    private String callingAppOrigin(android.service.credentials.CallingAppInfo info, String privilegedOrigin)
            throws Exception {
        if (privilegedOrigin != null && !privilegedOrigin.isEmpty()) return privilegedOrigin;
        if (info == null || info.getSigningInfo() == null) {
            throw new SecurityException("Credential request has no verified calling app");
        }
        byte[] certificate = info.getSigningInfo().getApkContentsSigners()[0].toByteArray();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate);
        return "android:apk-key-hash:" + Base64.encodeToString(
                digest, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    /**
     * Run the platform user-verification ceremony before signing.
     *
     * onVerified(true)  — the user actually authenticated.
     * onVerified(false) — the device has no secure lock screen, so there is
     *                     nothing to verify against. The ceremony still
     *                     proceeds, but with the UV flag clear so the relying
     *                     party is told the truth rather than a comfortable lie.
     * onCancel          — the user dismissed the prompt, or it errored.
     *
     * Gating on KeyguardManager.isDeviceSecure() rather than
     * BiometricManager.canAuthenticate() is deliberate: the latter reports
     * NONE_ENROLLED on a device that has a PIN or pattern but no enrolled
     * fingerprint, which would lock every such user out of their own passkeys
     * even though setDeviceCredentialAllowed lets the prompt accept that PIN.
     */
    private void verifyUser(Consumer<Boolean> onVerified, Runnable onCancel) {
        KeyguardManager keyguard = getSystemService(KeyguardManager.class);
        if (keyguard == null || !keyguard.isDeviceSecure()) {
            onVerified.accept(false);
            return;
        }
        new BiometricPrompt.Builder(this)
                .setTitle("Verify to use Fenko Vault")
                .setDeviceCredentialAllowed(true)
                .build()
                .authenticate(new CancellationSignal(), getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override public void onAuthenticationSucceeded(
                                    BiometricPrompt.AuthenticationResult result) {
                                onVerified.accept(true);
                            }
                            @Override public void onAuthenticationError(int code, CharSequence message) {
                                onCancel.run();
                            }
                        });
    }

    private byte[] clientDataHashFromGetRequest(GetCredentialRequest request) {
        if (request == null) return null;
        for (CredentialOption option : request.getCredentialOptions()) {
            if (!WebAuthnNative.isPublicKeyType(option.getType())) continue;
            byte[] hash = option.getCredentialRetrievalData()
                    .getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH");
            if (hash == null) {
                hash = option.getCandidateQueryData()
                        .getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH");
            }
            if (hash != null) return hash;
        }
        return null;
    }

    private String requestJsonFromGetRequest(GetCredentialRequest request) {
        if (request == null) return null;
        List<CredentialOption> options = request.getCredentialOptions();
        for (CredentialOption option : options) {
            if (!WebAuthnNative.isPublicKeyType(option.getType())) continue;
            String requestJson = ProviderVaultStore.requestJson(option.getCredentialRetrievalData());
            if (requestJson == null) {
                requestJson = ProviderVaultStore.requestJson(option.getCandidateQueryData());
            }
            if (requestJson != null) return requestJson;
        }
        return null;
    }

    private Bundle publicKeyBundle(String primaryKey, String responseJson) {
        Bundle data = new Bundle();
        data.putString(primaryKey, responseJson);
        data.putString("android.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson);
        data.putString("android.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson);
        data.putString("authenticationResponseJson", responseJson);
        data.putString("registrationResponseJson", responseJson);
        data.putString(WebAuthnNative.KEY_SUBTYPE, WebAuthnNative.TYPE_PUBLIC_KEY_CREDENTIAL);
        return data;
    }

    private void finishGetError(String type, String message) {
        Intent result = new Intent();
        result.putExtra(
                CredentialProviderService.EXTRA_GET_CREDENTIAL_EXCEPTION,
                new GetCredentialException(type, message == null ? "" : message));
        setResult(RESULT_OK, result);
        finish();
    }

    private void finishCreateError(String type, String message) {
        Intent result = new Intent();
        result.putExtra(
                CredentialProviderService.EXTRA_CREATE_CREDENTIAL_EXCEPTION,
                new CreateCredentialException(type, message == null ? "" : message));
        setResult(RESULT_OK, result);
        finish();
    }
}
