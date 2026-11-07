import Foundation
import LocalAuthentication

protocol ProviderVaultAccess {
    func unlock(context: LAContext) throws
    func lock()
}

extension VaultStore: ProviderVaultAccess {}

enum ProviderSessionError: Error {
    case denied
}

@MainActor
final class ProviderSession {
    private let vault: ProviderVaultAccess
    private let authenticate: (LAContext, String) async throws -> Bool
    private var context: LAContext?

    init(vault: ProviderVaultAccess = VaultStore.shared,
         authenticate: @escaping (LAContext, String) async throws -> Bool = { context, reason in
             try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
         }) {
        self.vault = vault
        self.authenticate = authenticate
    }

    func perform(reason: String, operation: () throws -> Void) async throws {
        let auth = LAContext()
        context = auth
        guard try await authenticate(auth, reason) else { throw ProviderSessionError.denied }
        try vault.unlock(context: auth)
        try operation()
    }

    func cancel() {
        context?.invalidate()
        context = nil
        vault.lock()
    }
}
