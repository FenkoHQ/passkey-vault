import Foundation
import LocalAuthentication

final class ProviderTestVault: ProviderVaultAccess {
    var unlocks = 0
    var locks = 0
    func unlock(context: LAContext) throws { unlocks += 1 }
    func lock() { locks += 1 }
}

@MainActor
func verifyCancellation() async {
    let vault = ProviderTestVault()
    var pending: CheckedContinuation<Bool, Never>?
    var performed = false
    let session = ProviderSession(vault: vault, authenticate: { _, _ in
        await withCheckedContinuation { pending = $0 }
    })
    let attempt = Task {
        try? await session.perform(reason: "Test cancellation") { performed = true }
    }
    while pending == nil { await Task.yield() }
    session.cancel()
    pending?.resume(returning: true)
    await attempt.value
    precondition(vault.unlocks == 0 && !performed, "Late provider authentication reopened a canceled request")
    print("iOS provider lifecycle: PASS")
}

await verifyCancellation()
