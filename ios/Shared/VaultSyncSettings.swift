import Foundation

struct VaultSyncSettings {
    static let defaultRelays = [
        "wss://vaultsync.fenko.nz", "wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band",
    ]
    let seedHash: String
    let chainID: String
    let deviceID: String
    let deviceName: String
    let relays: [URL]
}

struct VaultPeer: Identifiable {
    let id: String
    let name: String
    let type: String
    let lastSeen: Double
}
