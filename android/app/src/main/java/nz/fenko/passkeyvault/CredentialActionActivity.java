package nz.fenko.passkeyvault;

import android.app.Activity;
import android.content.Intent;
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

            String origin = request == null || request.getCallingAppInfo() == null
                    ? passkey.origin
                    : request.getCallingAppInfo().getOrigin();
            byte[] clientDataHash = clientDataHashFromGetRequest(request);
            String authenticationJson =
                    WebAuthnNative.authenticationResponseJson(passkey, requestJson, origin, clientDataHash);
            ProviderVaultStore.upsertPasskey(this, passkey);

            Bundle data = publicKeyBundle(WebAuthnNative.KEY_AUTH_RESPONSE_JSON, authenticationJson);
            Credential credential = new Credential(WebAuthnNative.TYPE_PUBLIC_KEY_CREDENTIAL, data);
            Intent result = new Intent();
            result.putExtra(
                    CredentialProviderService.EXTRA_GET_CREDENTIAL_RESPONSE,
                    new GetCredentialResponse(credential));
            setResult(RESULT_OK, result);
            finish();
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
            String origin = request.getCallingAppInfo() == null
                    ? null
                    : request.getCallingAppInfo().getOrigin();
            ProviderVaultStore.PasskeyRecord passkey =
                    WebAuthnNative.createPasskey(requestJson, origin);
            String registrationJson =
                    WebAuthnNative.registrationResponseJson(passkey, requestJson, origin);
            ProviderVaultStore.upsertPasskey(this, passkey);

            Bundle data = publicKeyBundle(WebAuthnNative.KEY_REG_RESPONSE_JSON, registrationJson);
            Intent result = new Intent();
            result.putExtra(
                    CredentialProviderService.EXTRA_CREATE_CREDENTIAL_RESPONSE,
                    new CreateCredentialResponse(data));
            setResult(RESULT_OK, result);
            finish();
        } catch (Exception e) {
            finishCreateError(CreateCredentialException.TYPE_UNKNOWN, e.getMessage());
        }
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
