import Foundation
import LocalAuthentication
import SwiftUI

@MainActor
final class NativeVaultModel: ObservableObject {
    enum Session {
        case locked
        case unlocking
        case unlocked
    }

    @Published private(set) var session: Session = .locked
    @Published private(set) var items: [VaultItem] = []
    @Published var message: String?
    private let vault: VaultStore
    private var context: LAContext?
    private var generation = 0
    private var lastActivity = Date()
    private static let idleTimeout: TimeInterval = 5 * 60

    init(vault: VaultStore = .shared) {
        self.vault = vault
    }

    func unlock() async {
        guard session == .locked else { return }
        session = .unlocking
        message = nil
        generation += 1
        let attempt = generation
        let auth = LAContext()
        context = auth
        do {
            let verified = try await auth.evaluatePolicy(.deviceOwnerAuthentication,
                                                        localizedReason: "Unlock your Fenko Vault")
            guard verified, generation == attempt else { return }
            try vault.unlock(context: auth)
            session = .unlocked
            touch()
            refresh()
        } catch {
            guard generation == attempt else { return }
            lock()
            message = error.localizedDescription
        }
    }

    func lock() {
        generation += 1
        context?.invalidate()
        context = nil
        vault.lock()
        items = []
        session = .locked
    }

    func touch() {
        lastActivity = Date()
    }

    func tick() {
        guard session == .unlocked else { return }
        if Date().timeIntervalSince(lastActivity) >= Self.idleTimeout {
            lock()
            return
        }
        refresh()
    }

    func refresh() {
        guard session == .unlocked else { return }
        do {
            items = try vault.items()
        } catch {
            message = error.localizedDescription
        }
    }

    func backup(password: String) throws -> Data {
        guard session == .unlocked else { throw VaultError.locked }
        touch()
        return try vault.exportBackup(password: password)
    }

    func restore(url: URL, password: String) {
        guard session == .unlocked else { return }
        do {
            let count = try vault.importFile(url, password: password)
            touch()
            refresh()
            message = "Imported \(count) entries."
        } catch {
            message = "Import failed. Check the backup and its password. Your existing entries are unchanged."
        }
    }
}
