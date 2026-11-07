import Foundation
import LocalAuthentication
import SwiftUI

protocol NativeVaultAccess {
    func unlock(context: LAContext) throws
    func lock()
    func items(at date: Date) throws -> [VaultItem]
    func exportBackup(password: String) throws -> Data
    func importFile(_ url: URL, password: String) throws -> Int
    func issueHOTP(_ id: String) throws -> String
}

extension VaultStore: NativeVaultAccess {}

@MainActor
protocol NativeSyncLifecycle: AnyObject {
    func resume()
    func suspend()
    func changed()
}

@MainActor
final class NativeVaultModel: ObservableObject {
    enum Session {
        case locked
        case unlocking
        case unlocked
    }

    @Published private(set) var session: Session = .locked
    @Published private(set) var items: [VaultItem] = []
    @Published private(set) var issuedCodes: [String: String] = [:]
    @Published var message: String?
    private let vault: NativeVaultAccess
    private let sync: (any NativeSyncLifecycle)?
    private let authenticate: (LAContext) async throws -> Bool
    private var context: LAContext?
    private var generation = 0
    private var lastActivity = Date()
    private static let idleTimeout: TimeInterval = 5 * 60

    init(vault: NativeVaultAccess = VaultStore.shared, sync: (any NativeSyncLifecycle)? = nil,
         authenticate: @escaping (LAContext) async throws -> Bool = { context in
             try await context.evaluatePolicy(.deviceOwnerAuthentication,
                                              localizedReason: "Unlock your Fenko Vault")
         }) {
        self.vault = vault
        self.sync = sync
        self.authenticate = authenticate
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
            let verified = try await authenticate(auth)
            guard generation == attempt else { return }
            guard verified else {
                lock()
                return
            }
            try vault.unlock(context: auth)
            session = .unlocked
            touch()
            refresh()
            if session == .unlocked { sync?.resume() }
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
        sync?.suspend()
        vault.lock()
        items = []
        issuedCodes = [:]
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
            items = try vault.items(at: Date())
            let ids = Set(items.filter { $0.kind == .hotp }.map(\.id))
            issuedCodes = issuedCodes.filter { ids.contains($0.key) }
        } catch {
            lock()
            message = error.localizedDescription
        }
    }

    func backup(password: String) throws -> Data {
        guard session == .unlocked else { throw VaultError.locked }
        touch()
        return try vault.exportBackup(password: password)
    }

    func issueHOTP(_ id: String) {
        guard session == .unlocked else { return }
        do {
            issuedCodes[id] = try vault.issueHOTP(id)
            touch()
            sync?.changed()
        } catch { message = "Could not generate the next code. Try again." }
    }

    func restore(url: URL, password: String) {
        guard session == .unlocked else { return }
        do {
            let count = try vault.importFile(url, password: password)
            touch()
            refresh()
            sync?.changed()
            message = "Imported \(count) entries."
        } catch {
            message = "Import failed. Check the backup and its password. Your existing entries are unchanged."
        }
    }
}
