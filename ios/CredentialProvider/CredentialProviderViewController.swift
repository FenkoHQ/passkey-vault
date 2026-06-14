import AuthenticationServices
import LocalAuthentication
import UIKit

/// AutoFill credential provider for passkeys (iOS 17+). Mirrors the Android
/// `PasskeyCredentialProviderService`: serves WebAuthn create/get from the shared
/// vault, signing with ES256 over `authenticatorData || clientDataHash`.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let vault = VaultStore.shared

    // MARK: Assertion (get)

    /// We always require user verification, so the silent path defers to UI.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        extensionContext.cancelRequest(
            withError: ASExtensionError(.userInteractionRequired))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        completeAssertion(request: request, credentialID: identity.credentialID)
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        // Pick the first stored passkey for the requested relying party. A fuller
        // UI would list candidates; this auto-selects, then verifies the user.
        let rpId = requestParameters.relyingPartyIdentifier
        let matches = vault.loadPasskeys().filter { $0.rpId == rpId }
        guard let chosen = matches.first,
              let credID = Base64URL.decode(chosen.credentialId) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }
        completeAssertion(parameters: requestParameters, credentialID: credID)
    }

    // MARK: Registration (create)

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        guard request.supportedAlgorithms.contains(.ES256) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }
        authenticateUser { [weak self] ok in
            guard let self else { return }
            guard ok else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled)); return
            }
            do {
                let credential = try self.register(request: request, identity: identity)
                self.extensionContext.completeRegistrationRequest(using: credential)
            } catch {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            }
        }
    }

    // MARK: - Helpers

    private func completeAssertion(request: ASPasskeyCredentialRequest? = nil,
                                   parameters: ASPasskeyCredentialRequestParameters? = nil,
                                   credentialID: Data) {
        let credIdB64 = Base64URL.encode(credentialID)
        guard let passkey = vault.findPasskey(credentialId: credIdB64) else {
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }
        let clientDataHash = request?.clientDataHash ?? parameters?.clientDataHash ?? Data()

        authenticateUser { [weak self] ok in
            guard let self else { return }
            guard ok else {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled)); return
            }
            do {
                var updated = passkey
                updated.counter += 1
                let authData = WebAuthn.authenticatorData(
                    rpId: updated.rpId, credentialId: nil, cosePublicKey: nil,
                    includeAttestedCredentialData: false, counter: updated.counter)
                let signature = try WebAuthn.assertionSignature(
                    privateKeyPKCS8B64: updated.privateKey,
                    authenticatorData: authData, clientDataHash: clientDataHash)
                self.vault.upsert(updated)   // persist the bumped counter

                let userHandle = updated.userId.flatMap(Base64URL.decode) ?? Data()
                let credential = ASPasskeyAssertionCredential(
                    userHandle: userHandle,
                    relyingParty: updated.rpId,
                    signature: signature,
                    clientDataHash: clientDataHash,
                    authenticatorData: authData,
                    credentialID: credentialID)
                self.extensionContext.completeAssertionRequest(using: credential)
            } catch {
                self.extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            }
        }
    }

    private func register(request: ASPasskeyCredentialRequest,
                          identity: ASPasskeyCredentialIdentity) throws -> ASPasskeyRegistrationCredential {
        let keys = WebAuthn.generateKeyPair()
        var credentialIDBytes = Data(count: 32)
        _ = credentialIDBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        guard let publicKeyRaw = Base64Std.decode(keys.publicKey) else {
            throw WebAuthnError.badPublicKey
        }
        let cose = try WebAuthn.cosePublicKey(rawPublicKey: publicKeyRaw)
        let authData = WebAuthn.authenticatorData(
            rpId: identity.relyingPartyIdentifier,
            credentialId: credentialIDBytes, cosePublicKey: cose,
            includeAttestedCredentialData: true, counter: 0)
        let attestationObject = WebAuthn.attestationObject(authData: authData)

        let record = PasskeyRecord(
            id: Base64URL.encode(credentialIDBytes),
            credentialId: Base64URL.encode(credentialIDBytes),
            rpId: identity.relyingPartyIdentifier,
            origin: "https://\(identity.relyingPartyIdentifier)",
            userId: identity.userHandle.isEmpty ? nil : Base64URL.encode(identity.userHandle),
            userName: identity.userName,
            displayName: identity.userName,
            privateKey: keys.privateKey,
            publicKey: keys.publicKey,
            createdAt: Date().timeIntervalSince1970 * 1000,
            counter: 0)
        vault.upsert(record)

        return ASPasskeyRegistrationCredential(
            relyingParty: identity.relyingPartyIdentifier,
            clientDataHash: request.clientDataHash,
            credentialID: credentialIDBytes,
            attestationObject: attestationObject)
    }

    private func authenticateUser(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        context.localizedReason = "Use a passkey from Fenko Vault"
        var error: NSError?
        let policy: LAPolicy = .deviceOwnerAuthentication
        guard context.canEvaluatePolicy(policy, error: &error) else {
            DispatchQueue.main.async { completion(false) }
            return
        }
        context.evaluatePolicy(policy, localizedReason: context.localizedReason) { ok, _ in
            DispatchQueue.main.async { completion(ok) }
        }
    }
}
