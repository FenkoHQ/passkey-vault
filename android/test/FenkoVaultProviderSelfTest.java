package nz.fenko.passkeyvault;

import org.json.JSONObject;

public final class FenkoVaultProviderSelfTest {
    public static void main(String[] args) throws Exception {
        JSONObject rp = new JSONObject()
                .put("id", "example.com")
                .put("name", "Example");
        JSONObject user = new JSONObject()
                .put("id", "dXNlci0x")
                .put("name", "ali@example.com")
                .put("displayName", "Ali");
        JSONObject request = new JSONObject()
                .put("challenge", "Y2hhbGxlbmdlLTE")
                .put("rp", rp)
                .put("user", user);

        ProviderVaultStore.PasskeyRecord passkey =
                WebAuthnNative.createPasskey(request.toString(), "https://example.com");
        require("example.com".equals(passkey.rpId), "rpId mismatch");
        require("ali@example.com".equals(passkey.userName), "userName mismatch");
        require(passkey.credentialId != null && passkey.credentialId.length() > 20, "credentialId missing");
        require(passkey.privateKey != null && passkey.privateKey.length() > 100, "privateKey missing");
        require(passkey.publicKey != null && passkey.publicKey.length() > 80, "publicKey missing");

        String registration = WebAuthnNative.registrationResponseJson(
                passkey,
                request.toString(),
                "https://example.com");
        JSONObject registrationJson = new JSONObject(registration);
        require(passkey.credentialId.equals(registrationJson.getString("id")), "registration id mismatch");
        require("public-key".equals(registrationJson.getString("type")), "registration type mismatch");
        JSONObject regResponse = registrationJson.getJSONObject("response");
        require(regResponse.getString("clientDataJSON").length() > 20, "registration clientDataJSON missing");
        require(regResponse.getString("attestationObject").length() > 20, "attestationObject missing");
        require(regResponse.getString("publicKey").length() > 20, "publicKey response missing");

        String authentication = WebAuthnNative.authenticationResponseJson(
                passkey,
                request.toString(),
                "https://example.com");
        JSONObject authenticationJson = new JSONObject(authentication);
        require(passkey.credentialId.equals(authenticationJson.getString("id")), "authentication id mismatch");
        require(passkey.counter == 1, "counter did not increment");
        JSONObject authResponse = authenticationJson.getJSONObject("response");
        require(authResponse.getString("clientDataJSON").length() > 20, "auth clientDataJSON missing");
        require(authResponse.getString("authenticatorData").length() > 20, "authenticatorData missing");
        require(authResponse.getString("signature").length() > 20, "signature missing");

        ProviderVaultStore.PasskeyRecord roundTrip =
                ProviderVaultStore.PasskeyRecord.fromJson(passkey.toJson());
        require(roundTrip != null, "roundTrip parse failed");
        require(passkey.credentialId.equals(roundTrip.credentialId), "roundTrip credentialId mismatch");
        require(passkey.counter == roundTrip.counter, "roundTrip counter mismatch");

        System.out.println(new JSONObject()
                .put("ok", true)
                .put("rpId", passkey.rpId)
                .put("credentialIdLength", passkey.credentialId.length())
                .put("counter", passkey.counter)
                .put("registrationType", registrationJson.getString("type"))
                .put("authenticationType", authenticationJson.getString("type"))
                .toString());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
