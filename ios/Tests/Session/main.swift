import Foundation
import LocalAuthentication

final class TestVault: NativeVaultAccess {
    var unlocks = 0
    var readable = true
    func unlock(context: LAContext) throws { unlocks += 1 }
    func lock() {}
    func items(at date: Date) throws -> [VaultItem] {
        guard readable else { throw VaultError.invalidArchive }
        return [VaultItem(id: "fixture", kind: .totp, title: "Example", account: "alice", code: "123456")]
    }
    func exportBackup(password: String) throws -> Data { Data() }
    func importFile(_ url: URL, password: String) throws -> Int { 0 }
    func issueHOTP(_ id: String) throws -> String { "123456" }
}

@MainActor
final class TestSync: NativeSyncLifecycle {
    var resumes = 0
    var suspends = 0
    func resume() { resumes += 1 }
    func suspend() { suspends += 1 }
    func changed() {}
}

@MainActor
func verifySession() async {
    let deniedVault = TestVault()
    let denied = NativeVaultModel(vault: deniedVault, authenticate: { _ in false })
    await denied.unlock()
    precondition(denied.session == .locked, "Denied authentication left the session stuck unlocking")
    precondition(deniedVault.unlocks == 0, "Denied authentication opened storage")

    let vault = TestVault()
    let sync = TestSync()
    let model = NativeVaultModel(vault: vault, sync: sync, authenticate: { _ in true })
    await model.unlock()
    precondition(model.session == .unlocked && model.items.count == 1, "Successful unlock did not load entries")
    precondition(sync.resumes == 1, "Unlock did not resume sync")
    vault.readable = false
    model.refresh()
    precondition(model.session == .locked && model.items.isEmpty, "Failed refresh left stale secrets visible")
    precondition(sync.suspends == 1, "Lock did not suspend sync")

    // A delayed authentication response must not reopen a vault locked while it was pending.
    var pending: CheckedContinuation<Bool, Never>?
    let delayedVault = TestVault()
    let delayed = NativeVaultModel(vault: delayedVault, authenticate: { _ in
        await withCheckedContinuation { pending = $0 }
    })
    let unlock = Task { await delayed.unlock() }
    while pending == nil { await Task.yield() }
    delayed.lock()
    pending?.resume(returning: true)
    await unlock.value
    precondition(delayed.session == .locked && delayedVault.unlocks == 0, "Late authentication reopened storage")
    print("iOS session lifecycle: PASS")
}

await verifySession()
