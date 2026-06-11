package nz.fenko.passkeyvault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class ProviderVaultStore {
    private static final String PREFS = "passkey_vault_native";
    private static final String PASSKEYS = "passkeys";
    private static final String TOTP = "totp_entries";
    private static final String SYNC_CONFIG = "sync_config";
    private static final String SYNC_DEVICES = "sync_devices";
    private static final String CUSTOM_RELAYS = "custom_relays";

    private ProviderVaultStore() {}

    static JSONObject loadSnapshot(Context context) {
        SharedPreferences prefs = prefs(context);
        JSONObject out = new JSONObject();
        putJson(out, "passkeys", prefs.getString(PASSKEYS, "[]"), new JSONArray());
        putJson(out, "totpEntries", prefs.getString(TOTP, "[]"), new JSONArray());
        putJson(out, "syncConfig", prefs.getString(SYNC_CONFIG, "{}"), new JSONObject());
        putJson(out, "syncDevices", prefs.getString(SYNC_DEVICES, "null"), JSONObject.NULL);
        putJson(out, "customRelays", prefs.getString(CUSTOM_RELAYS, "[]"), new JSONArray());
        return out;
    }

    static void saveSnapshot(
            Context context,
            String passkeysJson,
            String totpJson,
            String syncConfigJson,
            String syncDevicesJson,
            String customRelaysJson) {
        prefs(context)
                .edit()
                .putString(PASSKEYS, normalizeArray(passkeysJson))
                .putString(TOTP, normalizeArray(totpJson))
                .putString(SYNC_CONFIG, normalizeObject(syncConfigJson))
                .putString(SYNC_DEVICES, normalizeJson(syncDevicesJson, "null"))
                .putString(CUSTOM_RELAYS, normalizeArray(customRelaysJson))
                .apply();
    }

    static List<PasskeyRecord> loadPasskeys(Context context) {
        String raw = prefs(context).getString(PASSKEYS, "[]");
        JSONArray array = parseArray(raw);
        List<PasskeyRecord> out = new ArrayList<PasskeyRecord>();
        for (int i = 0; i < array.length(); i++) {
            JSONObject item = array.optJSONObject(i);
            if (item == null) continue;
            PasskeyRecord record = PasskeyRecord.fromJson(item);
            if (record != null) out.add(record);
        }
        return out;
    }

    static void savePasskeys(Context context, List<PasskeyRecord> passkeys) {
        JSONArray array = new JSONArray();
        for (PasskeyRecord passkey : passkeys) {
            array.put(passkey.toJson());
        }
        prefs(context).edit().putString(PASSKEYS, array.toString()).apply();
    }

    static PasskeyRecord findPasskey(Context context, String id) {
        if (id == null || id.length() == 0) return null;
        for (PasskeyRecord passkey : loadPasskeys(context)) {
            if (id.equals(passkey.id) || id.equals(passkey.credentialId)) return passkey;
        }
        return null;
    }

    static void upsertPasskey(Context context, PasskeyRecord passkey) {
        List<PasskeyRecord> passkeys = loadPasskeys(context);
        boolean replaced = false;
        for (int i = 0; i < passkeys.size(); i++) {
            PasskeyRecord current = passkeys.get(i);
            if (current.id.equals(passkey.id) || current.credentialId.equals(passkey.credentialId)) {
                passkeys.set(i, passkey);
                replaced = true;
                break;
            }
        }
        if (!replaced) passkeys.add(passkey);
        savePasskeys(context, passkeys);
    }

    static String requestJson(Bundle data) {
        String direct = findString(data, "request_json");
        if (direct == null) direct = findString(data, "requestJson");
        if (direct == null) direct = findString(data, "BUNDLE_KEY_REQUEST_JSON");
        if (direct == null) direct = firstJsonLookingString(data);
        return direct;
    }

    static String rpIdFromRequestJson(String requestJson) {
        if (requestJson == null || requestJson.length() == 0) return null;
        try {
            JSONObject root = new JSONObject(requestJson);
            String rpId = root.optString("rpId", "");
            if (rpId.length() > 0) return rpId;
            JSONObject rp = root.optJSONObject("rp");
            if (rp != null) {
                rpId = rp.optString("id", "");
                if (rpId.length() > 0) return rpId;
            }
        } catch (JSONException ignored) {
        }
        return null;
    }

    static String challengeFromRequestJson(String requestJson) {
        if (requestJson == null || requestJson.length() == 0) return "";
        try {
            return new JSONObject(requestJson).optString("challenge", "");
        } catch (JSONException ignored) {
            return "";
        }
    }

    static boolean requestAllowsCredential(String requestJson, String credentialId) {
        if (requestJson == null || requestJson.length() == 0 || credentialId == null) return true;
        try {
            JSONArray allowCredentials = new JSONObject(requestJson).optJSONArray("allowCredentials");
            if (allowCredentials == null || allowCredentials.length() == 0) return true;
            for (int i = 0; i < allowCredentials.length(); i++) {
                JSONObject item = allowCredentials.optJSONObject(i);
                if (item != null && credentialId.equals(item.optString("id", ""))) return true;
            }
            return false;
        } catch (JSONException ignored) {
            return true;
        }
    }

    static String userIdFromCreateRequest(String requestJson) {
        try {
            JSONObject user = new JSONObject(requestJson).optJSONObject("user");
            return user == null ? null : user.optString("id", null);
        } catch (JSONException ignored) {
            return null;
        }
    }

    static String userNameFromCreateRequest(String requestJson) {
        try {
            JSONObject user = new JSONObject(requestJson).optJSONObject("user");
            return user == null ? "" : user.optString("name", "");
        } catch (JSONException ignored) {
            return "";
        }
    }

    static String displayNameFromCreateRequest(String requestJson) {
        try {
            JSONObject user = new JSONObject(requestJson).optJSONObject("user");
            return user == null ? "" : user.optString("displayName", "");
        } catch (JSONException ignored) {
            return "";
        }
    }

    static String rpNameFromCreateRequest(String requestJson) {
        try {
            JSONObject rp = new JSONObject(requestJson).optJSONObject("rp");
            return rp == null ? "" : rp.optString("name", "");
        } catch (JSONException ignored) {
            return "";
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static void putJson(JSONObject out, String key, String raw, Object fallback) {
        try {
            if (raw == null || "null".equals(raw)) out.put(key, JSONObject.NULL);
            else if (raw.trim().startsWith("[")) out.put(key, new JSONArray(raw));
            else out.put(key, new JSONObject(raw));
        } catch (JSONException e) {
            try {
                out.put(key, fallback);
            } catch (JSONException ignored) {
            }
        }
    }

    private static JSONArray parseArray(String raw) {
        try {
            return new JSONArray(raw == null ? "[]" : raw);
        } catch (JSONException e) {
            return new JSONArray();
        }
    }

    private static String normalizeArray(String raw) {
        try {
            return new JSONArray(raw == null ? "[]" : raw).toString();
        } catch (JSONException e) {
            return "[]";
        }
    }

    private static String normalizeObject(String raw) {
        try {
            return new JSONObject(raw == null ? "{}" : raw).toString();
        } catch (JSONException e) {
            return "{}";
        }
    }

    private static String normalizeJson(String raw, String fallback) {
        if (raw == null || raw.length() == 0 || "null".equals(raw)) return fallback;
        try {
            String trimmed = raw.trim();
            if (trimmed.startsWith("[")) return new JSONArray(trimmed).toString();
            return new JSONObject(trimmed).toString();
        } catch (JSONException e) {
            return fallback;
        }
    }

    private static String findString(Bundle data, String needle) {
        if (data == null) return null;
        Set<String> keys = data.keySet();
        for (String key : keys) {
            Object value = data.get(key);
            if (value instanceof String
                    && key.toLowerCase().contains(needle.toLowerCase())) {
                return (String) value;
            }
            if (value instanceof Bundle) {
                String nested = findString((Bundle) value, needle);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    private static String firstJsonLookingString(Bundle data) {
        if (data == null) return null;
        for (String key : data.keySet()) {
            Object value = data.get(key);
            if (value instanceof String) {
                String text = ((String) value).trim();
                if (text.startsWith("{") && text.contains("challenge")) return text;
            }
            if (value instanceof Bundle) {
                String nested = firstJsonLookingString((Bundle) value);
                if (nested != null) return nested;
            }
        }
        return null;
    }

    static final class PasskeyRecord {
        String id;
        String credentialId;
        String rpId;
        String origin;
        String userId;
        String userName;
        String displayName;
        String privateKey;
        String publicKey;
        long createdAt;
        long counter;
        JSONObject source;

        static PasskeyRecord fromJson(JSONObject json) {
            String credentialId = json.optString("credentialId", json.optString("id", ""));
            String privateKey = json.optString("privateKey", "");
            String rpId = json.optString("rpId", "");
            if (credentialId.length() == 0 || privateKey.length() == 0 || rpId.length() == 0) {
                return null;
            }

            JSONObject user = json.optJSONObject("user");
            PasskeyRecord record = new PasskeyRecord();
            record.id = json.optString("id", credentialId);
            record.credentialId = credentialId;
            record.rpId = rpId;
            record.origin = json.optString("origin", "https://" + rpId);
            record.userId = user == null ? null : user.optString("id", null);
            record.userName = user == null ? "" : user.optString("name", "");
            record.displayName = user == null ? "" : user.optString("displayName", "");
            record.privateKey = privateKey;
            record.publicKey = json.optString("publicKey", "");
            record.createdAt = json.optLong("createdAt", System.currentTimeMillis());
            record.counter = json.optLong("counter", 0);
            record.source = new JSONObject();
            try {
                record.source = new JSONObject(json.toString());
            } catch (JSONException ignored) {
            }
            return record;
        }

        JSONObject toJson() {
            JSONObject json = source == null ? new JSONObject() : source;
            try {
                json.put("id", id);
                json.put("credentialId", credentialId);
                json.put("type", "public-key");
                json.put("rpId", rpId);
                json.put("origin", origin == null || origin.length() == 0 ? "https://" + rpId : origin);
                JSONObject user = json.optJSONObject("user");
                if (user == null) user = new JSONObject();
                if (userId == null) user.put("id", JSONObject.NULL);
                else user.put("id", userId);
                user.put("name", userName == null ? "" : userName);
                user.put("displayName", displayName == null ? "" : displayName);
                json.put("user", user);
                json.put("privateKey", privateKey);
                json.put("publicKey", publicKey);
                json.put("createdAt", createdAt);
                json.put("counter", counter);
            } catch (JSONException ignored) {
            }
            return json;
        }
    }
}
