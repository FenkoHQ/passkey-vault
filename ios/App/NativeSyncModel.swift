import Foundation
import SwiftUI
import VaultSync

@MainActor
final class NativeSyncModel: ObservableObject, NativeSyncLifecycle {
    @Published private(set) var enabled = false
    @Published private(set) var peers: [VaultPeer] = []
    @Published private(set) var status: SyncStatus = .stopped
    @Published var deviceName = "iPhone"
    @Published var recoveryPhrase: String?
    @Published var message: String?
    private let vault: VaultStore
    private var service: SyncService?
    private var active = false
    private var generation = 0

    init(vault: VaultStore = .shared) {
        self.vault = vault
    }

    var statusText: String {
        switch status {
        case .stopped: return enabled ? "Sync is paused." : "Sync is off."
        case .connecting: return "Connecting to relay…"
        case .connected: return "Connected to relay."
        case .sent: return "Update accepted by relay."
        case .received: return "Update received."
        case .retryNeeded: return "An update needs retrying."
        case .networkError: return "Connection interrupted. Retrying…"
        case .storageError: return "Could not read or save a sync update."
        }
    }

    func resume() {
        active = true
        restart()
    }

    func suspend() {
        active = false
        recoveryPhrase = nil
        peers = []
        message = nil
        stopCurrent()
    }

    func changed() {
        guard active, let service else { return }
        Task { await service.changed() }
    }

    func create() {
        guard active, !enabled else { return }
        do {
            let phrase = try SyncRecovery.generate()
            if join(phrase) { recoveryPhrase = phrase }
        } catch { message = "Could not create a sync chain. Try again." }
    }

    @discardableResult
    func join(_ phrase: String) -> Bool {
        guard active, !enabled else { return false }
        do {
            let hash = try SyncRecovery.seedHash(phrase)
            try vault.joinSync(seedHash: hash, deviceName: deviceName)
            restart()
            return true
        } catch {
            message = "Could not join. Check the recovery phrase and device name."
            return false
        }
    }

    func leave() {
        guard active else { return }
        stopCurrent()
        do {
            try vault.leaveSync()
            enabled = false
            peers = []
            recoveryPhrase = nil
        } catch {
            message = "Could not leave the sync chain. Try again."
            restart()
        }
    }

    func retry() {
        guard active, let service else { return }
        Task { await service.retry() }
    }

    private func stopCurrent() {
        generation += 1
        let previous = service
        service = nil
        status = .stopped
        Task { await previous?.stop() }
    }

    private func restart() {
        stopCurrent()
        guard active else { return }
        do {
            guard let settings = try vault.syncSettings() else {
                enabled = false
                return
            }
            enabled = true
            deviceName = settings.deviceName
            peers = try vault.syncPeers()
            let token = generation
            let config = try RelaySyncConfig(seedHash: settings.seedHash, deviceID: settings.deviceID,
                                             deviceName: settings.deviceName, relays: settings.relays)
            let next = SyncService(config: config, load: { [weak self] in
                try await MainActor.run {
                    guard let self, self.active, self.generation == token else { throw VaultError.locked }
                    return try self.vault.syncSnapshot()
                }
            }, apply: { [weak self] incoming in
                try await MainActor.run {
                    guard let self, self.active, self.generation == token else { throw VaultError.locked }
                    let peer = VaultPeer(id: incoming.peer.id, name: incoming.peer.name,
                                         type: incoming.peer.type, lastSeen: incoming.peer.lastSeen)
                    let changed = try self.vault.applySync(incoming.snapshot, peer: peer)
                    self.peers = try self.vault.syncPeers()
                    return changed ? .changed : .unchanged
                }
            }, report: { [weak self] status in
                await MainActor.run {
                    guard let self, self.active, self.generation == token else { return }
                    self.status = status
                }
            })
            service = next
            Task {
                guard active, generation == token else { return }
                await next.start()
                if !active || generation != token { await next.stop() }
            }
        } catch {
            status = .storageError
            message = "Could not load sync settings. Your vault entries are unchanged."
        }
    }
}
