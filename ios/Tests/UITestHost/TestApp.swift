import LocalAuthentication
import SwiftUI

// This executable is a separate test target and is never embedded in the shipping app.
@main
struct VaultUITestApp: App {
    private let access = FixtureVault()

    var body: some Scene {
        WindowGroup {
            VaultHomeView(model: NativeVaultModel(vault: access, authenticate: { _ in true }),
                          sync: NativeSyncModel(vault: access.vault))
        }
    }
}

private final class FixtureVault: NativeVaultAccess {
    let vault: VaultStore
    private let archive: VaultArchive
    private let key = Data(repeating: 51, count: 32)

    init() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        archive = VaultArchive(directory: directory)
        vault = VaultStore(archive: archive)
    }

    func unlock(context: LAContext) throws { try archive.unlock(key: key) }
    func lock() { vault.lock() }
    func items(at date: Date) throws -> [VaultItem] { try vault.items(at: date) }
    func exportBackup(password: String) throws -> Data { try vault.exportBackup(password: password) }
    func importFile(_ url: URL, password: String) throws -> Int { try vault.importFile(url, password: password) }
    func issueHOTP(_ id: String) throws -> String { try vault.issueHOTP(id) }
    func addOTP(_ setup: OTPSetup) throws { try vault.addOTP(setup) }
    func deleteItem(_ id: String, kind: VaultItemKind) throws { try vault.deleteItem(id, kind: kind) }
}
