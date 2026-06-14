import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    private let vault = VaultStore.shared
    @State private var passkeys: [PasskeyRecord] = []
    @State private var totp: [TOTPEntry] = []
    @State private var importing = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("Enable Fenko Vault under Settings → General → AutoFill & Passwords, then turn on \u{201C}Fenko Vault\u{201D} as a passkey provider.",
                          systemImage: "key.fill")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Passkeys (\(passkeys.count))") {
                    if passkeys.isEmpty {
                        Text("No passkeys yet. Import a backup or create one from a website.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(passkeys, id: \.credentialId) { pk in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(pk.rpId).font(.body)
                            Text(pk.userName.isEmpty ? "—" : pk.userName)
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }

                if !totp.isEmpty {
                    Section("2FA codes (\(totp.count))") {
                        ForEach(totp) { entry in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.issuer.isEmpty ? entry.account : entry.issuer)
                                    Text(entry.account).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                Text(TOTP.code(for: entry) ?? "------")
                                    .font(.system(.title3, design: .monospaced))
                            }
                        }
                    }
                }
            }
            .navigationTitle("Fenko Vault")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { importing = true } label: { Image(systemName: "square.and.arrow.down") }
                }
            }
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [.json],
                          allowsMultipleSelection: false) { result in
                handleImport(result)
            }
            .alert(message ?? "", isPresented: Binding(
                get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("OK", role: .cancel) {}
            }
            .onAppear(perform: reload)
        }
    }

    private func reload() {
        passkeys = vault.loadPasskeys()
        totp = vault.loadTOTP()
        vault.updateCredentialIdentities(passkeys)
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        guard case let .success(urls) = result, let url = urls.first else { return }
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            message = "Could not read file."; return
        }
        let count = vault.importBackup(data)
        reload()
        message = "Imported \(count) passkey\(count == 1 ? "" : "s")."
    }
}
