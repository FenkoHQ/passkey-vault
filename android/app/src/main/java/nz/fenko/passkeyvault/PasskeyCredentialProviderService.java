package nz.fenko.passkeyvault;

import android.app.PendingIntent;
import android.app.slice.Slice;
import android.app.slice.SliceSpec;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import android.util.Log;
import android.service.credentials.Action;
import android.service.credentials.BeginCreateCredentialRequest;
import android.service.credentials.BeginCreateCredentialResponse;
import android.service.credentials.BeginGetCredentialOption;
import android.service.credentials.BeginGetCredentialRequest;
import android.service.credentials.BeginGetCredentialResponse;
import android.service.credentials.ClearCredentialStateRequest;
import android.service.credentials.CreateEntry;
import android.service.credentials.CredentialEntry;
import android.service.credentials.CredentialProviderService;
import android.credentials.ClearCredentialStateException;
import android.credentials.CreateCredentialException;
import android.credentials.GetCredentialException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class PasskeyCredentialProviderService extends CredentialProviderService {
    private static final String TAG = "FenkoVaultProvider";

    // The system picker only renders entries encoded in the androidx.credentials
    // slice format, so every spec name, revision, and hint below must match
    // androidx.credentials.provider exactly.
    private static final String CREATE_SPEC_TYPE = "CreateEntry";
    private static final int CREATE_REVISION = 1;
    private static final String CREATE_HINT_ACCOUNT_NAME =
            "androidx.credentials.provider.createEntry.SLICE_HINT_USER_PROVIDER_ACCOUNT_NAME";
    private static final String CREATE_HINT_NOTE =
            "androidx.credentials.provider.createEntry.SLICE_HINT_NOTE";
    private static final String CREATE_HINT_ICON =
            "androidx.credentials.provider.createEntry.SLICE_HINT_PROFILE_ICON";
    private static final String CREATE_HINT_PENDING_INTENT =
            "androidx.credentials.provider.createEntry.SLICE_HINT_PENDING_INTENT";
    private static final String CREATE_HINT_AUTO_SELECT =
            "androidx.credentials.provider.createEntry.SLICE_HINT_AUTO_SELECT_ALLOWED";

    private static final int ENTRY_REVISION = 1;
    private static final String ENTRY_HINT_OPTION_ID =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_OPTION_ID";
    private static final String ENTRY_HINT_DEDUPLICATION_ID =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_DEDUPLICATION_ID";
    private static final String ENTRY_HINT_IS_DEFAULT_ICON_PREFERRED =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_IS_DEFAULT_ICON_PREFERRED";
    private static final String ENTRY_HINT_AFFILIATED_DOMAIN =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_AFFILIATED_DOMAIN";
    private static final String ENTRY_HINT_TYPE_DISPLAY_NAME =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_TYPE_DISPLAY_NAME";
    private static final String ENTRY_HINT_TITLE =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_USER_NAME";
    private static final String ENTRY_HINT_SUBTITLE =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_CREDENTIAL_TYPE_DISPLAY_NAME";
    private static final String ENTRY_HINT_AUTO_ALLOWED =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_AUTO_ALLOWED";
    private static final String ENTRY_HINT_ICON =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_PROFILE_ICON";
    private static final String ENTRY_HINT_PENDING_INTENT =
            "androidx.credentials.provider.credentialEntry.SLICE_HINT_PENDING_INTENT";

    private static final String ACTION_SPEC_TYPE = "Action";
    private static final int ACTION_REVISION = 0;
    private static final String ACTION_HINT_TITLE =
            "androidx.credentials.provider.action.HINT_ACTION_TITLE";
    private static final String ACTION_HINT_SUBTITLE =
            "androidx.credentials.provider.action.HINT_ACTION_SUBTEXT";
    private static final String ACTION_HINT_PENDING_INTENT =
            "androidx.credentials.provider.action.SLICE_HINT_PENDING_INTENT";

    @Override
    public void onBeginGetCredential(
            BeginGetCredentialRequest request,
            CancellationSignal cancellationSignal,
            OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> callback) {
        BeginGetCredentialResponse.Builder response = new BeginGetCredentialResponse.Builder();
        List<ProviderVaultStore.PasskeyRecord> passkeys = ProviderVaultStore.loadPasskeys(this);
        Log.i(TAG, "begin get options=" + request.getBeginGetCredentialOptions().size()
                + " stored=" + passkeys.size());
        int count = 0;

        for (BeginGetCredentialOption option : request.getBeginGetCredentialOptions()) {
            if (!WebAuthnNative.isPublicKeyType(option.getType())) continue;
            String requestJson = ProviderVaultStore.requestJson(option.getCandidateQueryData());
            String rpId = ProviderVaultStore.rpIdFromRequestJson(requestJson);

            for (ProviderVaultStore.PasskeyRecord passkey : passkeys) {
                if (rpId != null && rpId.length() > 0 && !rpId.equals(passkey.rpId)) continue;
                if (!ProviderVaultStore.requestAllowsCredential(requestJson, passkey.credentialId)) continue;
                response.addCredentialEntry(new CredentialEntry(option, credentialSlice(option, passkey)));
                count++;
            }
        }

        if (count == 0) {
            response.addAction(new Action(openAppSlice("Open Fenko Vault", "No matching passkeys found")));
        }
        Log.i(TAG, "begin get entries=" + count);
        callback.onResult(response.build());
    }

    @Override
    public void onBeginCreateCredential(
            BeginCreateCredentialRequest request,
            CancellationSignal cancellationSignal,
            OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException> callback) {
        BeginCreateCredentialResponse.Builder response = new BeginCreateCredentialResponse.Builder();
        Log.i(TAG, "begin create type=" + request.getType());
        if (WebAuthnNative.isPublicKeyType(request.getType())) {
            response.addCreateEntry(new CreateEntry(createSlice(request.getType())));
        }
        callback.onResult(response.build());
    }

    @Override
    public void onClearCredentialState(
            ClearCredentialStateRequest request,
            CancellationSignal cancellationSignal,
            OutcomeReceiver<Void, ClearCredentialStateException> callback) {
        callback.onResult(null);
    }

    private Slice credentialSlice(
            BeginGetCredentialOption option,
            ProviderVaultStore.PasskeyRecord passkey) {
        Intent intent = new Intent(this, CredentialActionActivity.class);
        intent.putExtra(CredentialActionActivity.EXTRA_ACTION, CredentialActionActivity.ACTION_GET);
        intent.putExtra(CredentialActionActivity.EXTRA_CREDENTIAL_ID, passkey.credentialId);
        intent.putExtra(CredentialActionActivity.EXTRA_OPTION_ID, option.getId());

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                passkey.credentialId.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);

        String username = passkey.userName == null || passkey.userName.length() == 0
                ? (passkey.displayName == null || passkey.displayName.length() == 0
                        ? passkey.rpId
                        : passkey.displayName)
                : passkey.userName;

        Slice.Builder slice = new Slice.Builder(
                Uri.EMPTY, new SliceSpec(option.getType(), ENTRY_REVISION));
        slice.addText(option.getId(), null, Arrays.asList(ENTRY_HINT_OPTION_ID));
        slice.addText(username, null, Arrays.asList(ENTRY_HINT_DEDUPLICATION_ID));
        slice.addText("false", null, Arrays.asList(ENTRY_HINT_IS_DEFAULT_ICON_PREFERRED));
        slice.addText(null, null, Arrays.asList(ENTRY_HINT_AFFILIATED_DOMAIN));
        slice.addText("Passkey", null, Arrays.asList(ENTRY_HINT_TYPE_DISPLAY_NAME));
        slice.addText(username, null, Arrays.asList(ENTRY_HINT_TITLE));
        slice.addText(passkey.displayName, null, Arrays.asList(ENTRY_HINT_SUBTITLE));
        slice.addText("false", null, Arrays.asList(ENTRY_HINT_AUTO_ALLOWED));
        slice.addIcon(
                Icon.createWithResource(this, R.mipmap.ic_launcher),
                null,
                Arrays.asList(ENTRY_HINT_ICON));
        slice.addAction(
                pendingIntent,
                new Slice.Builder(slice)
                        .addHints(Collections.singletonList(ENTRY_HINT_PENDING_INTENT))
                        .build(),
                null);
        return slice.build();
    }

    private Slice createSlice(String type) {
        Intent intent = new Intent(this, CredentialActionActivity.class);
        intent.putExtra(CredentialActionActivity.EXTRA_ACTION, CredentialActionActivity.ACTION_CREATE);
        intent.putExtra(CredentialActionActivity.EXTRA_CREDENTIAL_TYPE, type);

        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                type.hashCode(),
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);

        Slice.Builder slice = new Slice.Builder(
                Uri.EMPTY, new SliceSpec(CREATE_SPEC_TYPE, CREATE_REVISION));
        slice.addText("Fenko Vault", null, Arrays.asList(CREATE_HINT_ACCOUNT_NAME));
        slice.addText("Stored on this device", null, Arrays.asList(CREATE_HINT_NOTE));
        slice.addIcon(
                Icon.createWithResource(this, R.mipmap.ic_launcher),
                null,
                Arrays.asList(CREATE_HINT_ICON));
        slice.addAction(
                pendingIntent,
                new Slice.Builder(slice)
                        .addHints(Collections.singletonList(CREATE_HINT_PENDING_INTENT))
                        .build(),
                null);
        slice.addText("false", null, Arrays.asList(CREATE_HINT_AUTO_SELECT));
        return slice.build();
    }

    private Slice openAppSlice(String title, String subtitle) {
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                7,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Slice.Builder slice = new Slice.Builder(
                Uri.EMPTY, new SliceSpec(ACTION_SPEC_TYPE, ACTION_REVISION));
        slice.addText(title, null, Arrays.asList(ACTION_HINT_TITLE));
        slice.addText(subtitle, null, Arrays.asList(ACTION_HINT_SUBTITLE));
        slice.addAction(
                pendingIntent,
                new Slice.Builder(slice)
                        .addHints(Collections.singletonList(ACTION_HINT_PENDING_INTENT))
                        .build(),
                null);
        return slice.build();
    }
}
