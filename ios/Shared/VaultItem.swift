import Foundation

enum VaultItemKind: String {
    case passkey
    case totp
}

// Views receive labels and codes, never passkey private keys or OTP seeds.
struct VaultItem: Identifiable {
    let id: String
    let kind: VaultItemKind
    let title: String
    let account: String
    let code: String?
}

struct VaultAssertion {
    let userHandle: Data
    let authenticatorData: Data
    let signature: Data
}

struct VaultRegistration {
    let credentialID: Data
    let attestation: Data
}

struct ProviderCredential: Identifiable {
    let id: Data
    let account: String
}
