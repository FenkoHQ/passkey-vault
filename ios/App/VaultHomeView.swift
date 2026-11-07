import SwiftUI
import UniformTypeIdentifiers

private struct BackupDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    let data: Data

    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw VaultError.invalidData }
        self.data = data
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

struct VaultHomeView: View {
    @StateObject private var model: NativeVaultModel
    @StateObject private var sync: NativeSyncModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var search = ""
    @State private var password = ""
    @State private var confirmation = ""
    @State private var importing = false
    @State private var exporting = false
    @State private var document: BackupDocument?
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()
    private let amber = Color(red: 0.96, green: 0.65, blue: 0.14)

    init() {
        let sync = NativeSyncModel()
        _sync = StateObject(wrappedValue: sync)
        _model = StateObject(wrappedValue: NativeVaultModel(sync: sync))
    }

    var body: some View {
        Group {
            if model.session == .unlocked {
                TabView {
                    vault.tabItem { Label("Vault", systemImage: "key.fill") }
                    NativeSyncView(model: sync).tabItem { Label("Sync", systemImage: "arrow.triangle.2.circlepath") }
                    settings.tabItem { Label("Settings", systemImage: "gearshape") }
                }
            } else {
                lockScreen
            }
        }
        .tint(amber)
        .font(.custom("Saira", size: 17, relativeTo: .body))
        .simultaneousGesture(TapGesture().onEnded { model.touch() })
        .onReceive(timer) { _ in model.tick() }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { model.lock() }
            if phase == .active { model.refresh() }
        }
        .onChange(of: model.session) { _, session in
            if session == .locked {
                password = ""
                confirmation = ""
                search = ""
                document = nil
                exporting = false
                importing = false
            }
        }
        .overlay {
            if scenePhase != .active {
                Rectangle().fill(.background).overlay {
                    Label("Fenko Vault", systemImage: "lock.fill")
                        .font(.custom("Saira", size: 28, relativeTo: .title))
                }.ignoresSafeArea()
            }
        }
        .alert("Fenko Vault", isPresented: Binding(get: { model.message != nil || sync.message != nil },
                                                   set: { if !$0 { model.message = nil; sync.message = nil } })) {
            Button("OK") { model.message = nil; sync.message = nil }
        } message: { Text(model.message ?? sync.message ?? "") }
        .fileExporter(isPresented: $exporting, document: document,
                      contentType: .json, defaultFilename: "fenko-vault-backup") { result in
            document = nil
            if case .failure = result { model.message = "The backup could not be saved. Try again." }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            if case .success(let url) = result { model.restore(url: url, password: password) }
            password = ""
            confirmation = ""
        }
    }

    private var lockScreen: some View {
        VStack(spacing: 24) {
            Image(systemName: "lock.shield").font(.system(size: 64)).foregroundStyle(amber)
            Text("Fenko Vault").font(.custom("Saira", size: 36, relativeTo: .largeTitle))
            Text("Your passkeys and 2FA codes, on your device.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button {
                Task { await model.unlock() }
            } label: {
                if model.session == .unlocking { ProgressView() }
                else { Label("Unlock vault", systemImage: "faceid") }
            }
            .buttonStyle(.borderedProminent)
            .foregroundStyle(.black)
            .disabled(model.session == .unlocking)
            Text("Use Face ID, Touch ID, or your device passcode.")
                .font(.footnote).foregroundStyle(.secondary)
        }
        .padding(32)
    }

    private var vault: some View {
        NavigationStack {
            List {
                ForEach(model.items.filter { item in
                    search.isEmpty || (item.title + " " + item.account).localizedCaseInsensitiveContains(search)
                }) { item in
                    HStack(spacing: 14) {
                        Image(systemName: item.kind == .passkey ? "key.fill" : "number.square")
                            .foregroundStyle(amber).frame(width: 28)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.title).font(.custom("Saira", size: 19, relativeTo: .headline))
                            Text(item.account).font(.subheadline).foregroundStyle(.secondary)
                            if let code = item.code ?? model.issuedCodes[item.id] {
                                Text(code).font(.title2.monospacedDigit()).textSelection(.enabled)
                            }
                            if item.kind == .hotp {
                                Button(model.issuedCodes[item.id] == nil ? "Generate code" : "Next code") {
                                    model.issueHOTP(item.id)
                                }.buttonStyle(.borderless)
                            }
                        }
                        .padding(.vertical, 6)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .overlay {
                if model.items.isEmpty {
                    ContentUnavailableView("Your vault is empty", systemImage: "key",
                                           description: Text("Import a backup in Settings, or enable Fenko Vault as a passkey provider."))
                }
            }
            .navigationTitle("Vault")
            .searchable(text: $search, prompt: "Search sites and accounts")
            .onChange(of: search) { _, _ in model.touch() }
            .toolbar { Button("Lock", systemImage: "lock") { model.lock() } }
        }
    }

    private var settings: some View {
        NavigationStack {
            Form {
                Section("Passkeys") {
                    #if LOCAL_DEVICE_TEST
                    Text("This test app supports vault storage and backups. Passkey AutoFill requires the full Fenko Vault build.")
                    #else
                    Text("Enable Fenko Vault in your device's Password AutoFill settings to create and use passkeys in apps and Safari.")
                    #endif
                }
                Section("Backup and restore") {
                    SecureField("Backup password", text: $password)
                    SecureField("Confirm password for export", text: $confirmation)
                    Button("Export encrypted backup") {
                        do {
                            document = BackupDocument(data: try model.backup(password: password))
                            password = ""
                            confirmation = ""
                            exporting = true
                        } catch { model.message = error.localizedDescription }
                    }
                    .disabled(password.isEmpty || password != confirmation)
                    Button("Import backup") { importing = true }
                    Text("Keep the file and password safe. Nobody can recover them for you.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("Security") {
                    Text("The vault locks when you leave the app or after five minutes without activity.")
                    Button("Lock vault") { model.lock() }
                }
            }
            .onChange(of: password) { _, _ in model.touch() }
            .onChange(of: confirmation) { _, _ in model.touch() }
            .navigationTitle("Settings")
        }
    }
}
