import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum KeyCreation {
    case allowed
    case forbidden
}

enum DeviceKeyStore {
    private static let service = "nz.fenko.passkeyvault.encryption"
    private static let account = "vault-key-v1"

    static func load(context: LAContext, creation: KeyCreation) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: VaultStore.appGroup,
            kSecUseAuthenticationContext as String: context,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data { return data }
        guard status == errSecItemNotFound else { throw VaultError.keychain(status) }
        guard creation == .allowed else { throw VaultError.missingKey }

        // Device authentication protects the key in both the host and its AutoFill extension.
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .userPresence, &error
        ) else { throw VaultError.keychain(errSecParam) }
        let key = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        query.removeValue(forKey: kSecReturnData as String)
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = key
        let added = SecItemAdd(query as CFDictionary, nil)
        if added == errSecDuplicateItem {
            return try load(context: context, creation: .forbidden)
        }
        guard added == errSecSuccess else { throw VaultError.keychain(added) }
        return key
    }
}
