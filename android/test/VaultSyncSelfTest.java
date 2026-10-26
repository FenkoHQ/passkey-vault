package nz.fenko.passkeyvault;

import android.content.ContextWrapper;
import android.content.SharedPreferences;
import java.lang.reflect.Proxy;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import sun.misc.Unsafe;

// Runs the real store on the JVM with isolated in-memory preferences.
public final class VaultSyncSelfTest {
    private static final Map<String, String> values = new HashMap<>();
    private static SharedPreferences prefs;

    public static void main(String[] args) throws Exception {
        SharedPreferences.Editor editor = (SharedPreferences.Editor) Proxy.newProxyInstance(
                VaultSyncSelfTest.class.getClassLoader(), new Class[]{SharedPreferences.Editor.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("putString")) {
                        values.put((String) arguments[0], (String) arguments[1]);
                        return proxy;
                    }
                    if (method.getName().equals("clear")) { values.clear(); return proxy; }
                    if (method.getName().equals("commit")) { return true; }
                    return null;
                });
        prefs = (SharedPreferences) Proxy.newProxyInstance(VaultSyncSelfTest.class.getClassLoader(),
                new Class[]{SharedPreferences.class}, (proxy, method, arguments) -> {
                    if (method.getName().equals("edit")) { return editor; }
                    if (method.getName().equals("getString")) {
                        return values.getOrDefault((String) arguments[0], (String) arguments[1]);
                    }
                    return null;
                });
        Field field = Unsafe.class.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        FakeContext context = (FakeContext) ((Unsafe) field.get(null)).allocateInstance(FakeContext.class);
        String record = "{\"id\":\"p\",\"credentialId\":\"p\",\"rpId\":\"example.com\",\"privateKey\":\"keep\",\"createdAt\":1,\"counter\":9,\"prfKey\":\"keep-prf\"}";
        ProviderVaultStore.upsertPasskey(context, ProviderVaultStore.PasskeyRecord.fromJson(new JSONObject(record)));
        ProviderVaultStore.saveSnapshot(context, "[]", "[]", "{}", "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).size() == 1, "stale web save removed native credential");
        ProviderVaultStore.saveSnapshot(context, "[" + record.replace("\"counter\":9", "\"counter\":1") + "]", "[]", "{}", "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).get(0).counter == 9, "stale web save rolled back counter");
        String deleted = "{\"deletions\":[{\"kind\":\"passkey\",\"id\":\"p\",\"deletedAt\":2}]}";
        ProviderVaultStore.saveSnapshot(context, "[]", "[]", deleted, "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).isEmpty(), "explicit deletion was ignored");
        ProviderVaultStore.saveSnapshot(context, "[" + record + "]", "[]", "{}", "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).isEmpty(), "stale snapshot resurrected deletion");
        ProviderVaultStore.saveSnapshot(context, "[" + record.replace("\"createdAt\":1", "\"createdAt\":1,\"updatedAt\":3") + "]", "[]", "{}", "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).size() == 1, "explicit restore was ignored");
        require("keep-prf".equals(ProviderVaultStore.loadPasskeys(context).get(0).toJson().optString("prfKey")), "lost PRF material");
        String a = record.replace("\"createdAt\":1", "\"createdAt\":1,\"updatedAt\":4,\"label\":\"a\"");
        String z = a.replace("\"label\":\"a\"", "\"label\":\"z\"");
        ProviderVaultStore.saveSnapshot(context, "[" + a + "]", "[]", "{}", "null", "[]");
        ProviderVaultStore.saveSnapshot(context, "[" + z + "]", "[]", "{}", "null", "[]");
        require(ProviderVaultStore.loadSnapshot(context).getJSONArray("passkeys").getJSONObject(0).getString("label").equals("z"), "equal revision must choose canonical winner");
        ProviderVaultStore.saveSnapshot(context, "[]", "[]", "{\"resetVault\":true}", "null", "[]");
        require(ProviderVaultStore.loadPasskeys(context).size() == 1, "config must not reset vault");
        org.json.JSONArray fixtures = new org.json.JSONArray(new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(args[0])), java.nio.charset.StandardCharsets.UTF_8));
        for (int i = 0; i < fixtures.length(); i++) {
            JSONObject fixture = fixtures.getJSONObject(i);
            for (String first : new String[]{"local", "remote"}) {
                ProviderVaultStore.resetVault(context);
                String second = first.equals("local") ? "remote" : "local";
                ProviderVaultStore.saveSnapshot(context, "[" + fixture.getJSONObject(first) + "]", "[]", "{}", "null", "[]");
                ProviderVaultStore.saveSnapshot(context, "[" + fixture.getJSONObject(second) + "]", "[]", "{}", "null", "[]");
                JSONObject winner = ProviderVaultStore.loadSnapshot(context).getJSONArray("passkeys").getJSONObject(0);
                require(winner.getString("label").equals(fixture.getString("winner")), fixture.getString("name"));
                require(winner.getLong("counter") == fixture.getLong("counter"), "fixture counter floor");
            }
        }
        ProviderVaultStore.resetVault(context);
        require(ProviderVaultStore.loadPasskeys(context).isEmpty(), "explicit reset failed");
        java.nio.file.Path idFixturesPath = java.nio.file.Paths.get(args[0]).resolveSibling("credential-id-fixtures.json");
        org.json.JSONArray idFixtures = new org.json.JSONArray(new String(java.nio.file.Files.readAllBytes(idFixturesPath), java.nio.charset.StandardCharsets.UTF_8));
        for (int i = 0; i < idFixtures.length(); i++) {
            JSONObject fixture = idFixtures.getJSONObject(i);
            String stored = fixture.getString("stored");
            String expected = fixture.getString("credentialId");
            require(ProviderVaultStore.credentialIdFromStored(stored).equals(expected), fixture.getString("name"));
            JSONObject json = new JSONObject(record).put("id", stored).put("credentialId", stored);
            ProviderVaultStore.PasskeyRecord passkey = ProviderVaultStore.PasskeyRecord.fromJson(json);
            require(passkey.credentialId.equals(expected) && passkey.id.equals(stored), "load must decode " + fixture.getString("name"));
            String request = new JSONObject().put("allowCredentials",
                    new org.json.JSONArray().put(new JSONObject().put("type", "public-key").put("id", expected))).toString();
            require(ProviderVaultStore.requestAllowsCredential(request, passkey.credentialId), "allowCredentials must match " + fixture.getString("name"));
        }
        System.out.println("Native snapshot merge: PASS");
    }

    private static final class FakeContext extends ContextWrapper {
        private FakeContext() { super(null); }
        @Override public android.content.Context getApplicationContext() { return this; }
        @Override public SharedPreferences getSharedPreferences(String name, int mode) { return prefs; }
    }

    private static void require(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
    }
}
