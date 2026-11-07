import SwiftUI

struct NativeSyncView: View {
    @ObservedObject var model: NativeSyncModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var phrase = ""
    @State private var leaving = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Status") {
                    Text(model.statusText)
                    Text("Sync runs while the vault is unlocked. Relay acceptance confirms upload; another device must connect to receive it.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if model.enabled {
                    Section("Devices") {
                        ForEach(model.peers) { peer in
                            VStack(alignment: .leading, spacing: 4) {
                                Text(peer.name)
                                Text(peer.type).font(.footnote).foregroundStyle(.secondary)
                            }
                        }
                        Button("Retry sync") { model.retry() }
                    }
                    Section {
                        Button("Leave sync chain", role: .destructive) { leaving = true }
                    } footer: {
                        Text("Leaving keeps this device's vault entries. It does not remove copies on other devices.")
                    }
                } else {
                    Section("This device") {
                        TextField("Device name", text: $model.deviceName)
                    }
                    Section("Start a chain") {
                        Button("Create sync chain") { model.create() }
                        Text("Save the recovery phrase, then enter it on your other devices.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    Section("Join an existing chain") {
                        SecureField("12- or 24-word recovery phrase", text: $phrase)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        Button("Join sync chain") {
                            if model.join(phrase) { phrase = "" }
                        }.disabled(phrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
            .navigationTitle("Sync")
            .confirmationDialog("Leave this sync chain?", isPresented: $leaving, titleVisibility: .visible) {
                Button("Leave chain", role: .destructive) { model.leave() }
            }
            .onDisappear { phrase = "" }
            .sheet(isPresented: Binding(get: { model.recoveryPhrase != nil },
                                         set: { if !$0 { model.recoveryPhrase = nil } })) {
                NavigationStack {
                    VStack(alignment: .leading, spacing: 24) {
                        Text("Save your recovery phrase").font(.title2)
                        Text("Anyone with this phrase can join your chain and read its vault entries. Keep it private.")
                        Text(model.recoveryPhrase ?? "")
                            .font(.title3.monospaced()).textSelection(.enabled).privacySensitive()
                        Text("This phrase is shown once. Keep an encrypted backup as well.")
                            .font(.footnote).foregroundStyle(.secondary)
                        Button("I've saved it") { model.recoveryPhrase = nil }
                            .buttonStyle(.borderedProminent)
                    }
                    .padding(24)
                    .overlay {
                        if scenePhase != .active { Rectangle().fill(.background) }
                    }
                }
            }
        }
    }
}
