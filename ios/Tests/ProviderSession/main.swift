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
    var prompts: [CheckedContinuation<Bool, Never>] = []
    let overlapping = ProviderSession(vault: vault, authenticate: { _, _ in
        await withCheckedContinuation { prompts.append($0) }
    })
    var completed: [String] = []
    let first = Task { try? await overlapping.perform(reason: "First") { completed.append("first") } }
    while prompts.count < 1 { await Task.yield() }
    let second = Task { try? await overlapping.perform(reason: "Second") { completed.append("second") } }
    while prompts.count < 2 { await Task.yield() }
    prompts[0].resume(returning: true)
    await first.value
    prompts[1].resume(returning: true)
    await second.value
    precondition(completed == ["second"] && vault.unlocks == 1, "A superseded provider request ran or canceled its replacement")
    overlapping.cancel()
    print("iOS provider lifecycle: PASS")
}

await verifyCancellation()
