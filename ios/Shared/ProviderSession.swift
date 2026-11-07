import Foundation
import LocalAuthentication

protocol ProviderVaultAccess {
    func unlock(context: LAContext) throws
    func lock()
}

extension VaultStore: ProviderVaultAccess {}

enum ProviderSessionError: Error {
    case denied
    case stale
}

@MainActor
final class ProviderSession {
    private let vault: ProviderVaultAccess
    private let authenticate: (LAContext, String) async throws -> Bool
    private var context: LAContext?
    private var generation = 0

    init(vault: ProviderVaultAccess = VaultStore.shared,
         authenticate: @escaping (LAContext, String) async throws -> Bool = { context, reason in
             try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
         }) {
        self.vault = vault
        self.authenticate = authenticate
    }

    func perform(reason: String, operation: () throws -> Void) async throws {
        cancel()
        let attempt = generation
        let auth = LAContext()
        context = auth
        do {
            let verified = try await authenticate(auth, reason)
            guard generation == attempt, !Task.isCancelled else { throw ProviderSessionError.stale }
            guard verified else { throw ProviderSessionError.denied }
            try vault.unlock(context: auth)
            try operation()
        } catch {
            guard generation == attempt else { throw ProviderSessionError.stale }
            cancel()
            throw error
        }
    }

    func cancel() {
        generation += 1
        context?.invalidate()
        context = nil
        vault.lock()
    }
}
