import SwiftUI

struct OTPSetupView: View {
    @ObservedObject var model: NativeVaultModel
    @Environment(\.dismiss) private var dismiss
    @State private var issuer = ""
    @State private var account = ""
    @State private var secret = ""
    @State private var uri = ""
    @State private var kind = OTPKind.totp
    @State private var algorithm = OTPAlgorithm.sha1
    @State private var digits = 6
    @State private var period = "30"
    @State private var counter = "0"
    @State private var error: String?
    @State private var scanning = false
    @State private var requestingCamera = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Setup link") {
                    Button("Scan QR code", systemImage: "qrcode.viewfinder") {
                        requestingCamera = true
                    }.disabled(requestingCamera)
                    SecureField("otpauth:// link", text: $uri)
                    Button("Read setup link") { readLink() }.disabled(uri.isEmpty)
                }
                Section("Authenticator") {
                    TextField("Issuer or service", text: $issuer)
                    TextField("Account", text: $account)
                        .textInputAutocapitalization(.never)
                    SecureField("Setup key", text: $secret)
                        .textInputAutocapitalization(.characters)
                    Picker("Type", selection: $kind) {
                        Text("Time-based (TOTP)").tag(OTPKind.totp)
                        Text("Counter-based (HOTP)").tag(OTPKind.hotp)
                    }
                }
                Section("Advanced settings") {
                    Picker("Algorithm", selection: $algorithm) {
                        ForEach(OTPAlgorithm.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    Stepper("Digits: \(digits)", value: $digits, in: 6...10)
                    if kind == .totp {
                        TextField("Period in seconds", text: $period).keyboardType(.numberPad)
                    } else {
                        TextField("Starting counter", text: $counter).keyboardType(.numberPad)
                    }
                    Text("Use the settings supplied by the service.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .autocorrectionDisabled()
            .navigationTitle("Add 2FA code")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }.disabled(secret.isEmpty || (issuer.isEmpty && account.isEmpty))
                }
            }
            .onChange(of: model.session) { _, session in
                if session != .unlocked { clear(); dismiss() }
            }
            .task(id: requestingCamera) {
                guard requestingCamera else { return }
                let allowed = await VaultCamera.authorize()
                guard !Task.isCancelled, model.session == .unlocked else { return }
                requestingCamera = false
                if allowed { scanning = true; model.touch() }
                else { error = "Camera scanning is unavailable. Allow camera access in Settings, or enter the setup key." }
            }
            .onChange(of: [issuer, account, secret, uri, period, counter]) { _, _ in model.touch() }
            .sheet(isPresented: $scanning) {
                NavigationStack {
                    OTPScannerView { value in
                        guard model.session == .unlocked else { return }
                        scanning = false
                        uri = value
                        readLink()
                    } failed: {
                        scanning = false
                        error = "The camera could not scan the code. Try again or enter the setup key."
                    }
                    .navigationTitle("Scan authenticator QR")
                    .toolbar { Button("Cancel") { scanning = false } }
                }
            }
        }
    }

    private func readLink() {
        do {
            let setup = try OTPSetup.fromURI(uri)
            issuer = setup.issuer
            account = setup.account
            secret = setup.secret
            kind = setup.kind
            algorithm = setup.algorithm
            digits = setup.digits
            period = String(setup.period)
            counter = String(setup.counter)
            uri = ""
            error = nil
            model.touch()
        } catch { self.error = "The setup link is invalid or unsupported." }
    }

    private func save() {
        guard let period = Int(period), let counter = UInt64(counter) else {
            error = "Enter a valid period and counter."
            return
        }
        let setup = OTPSetup(kind: kind, issuer: issuer, account: account, secret: secret,
                             algorithm: algorithm, digits: digits, period: period, counter: counter)
        if model.addOTP(setup) { dismiss() }
        else {
            error = model.message ?? "Unlock the vault and try again."
            model.message = nil
        }
    }

    private func clear() {
        scanning = false
        secret = ""
        uri = ""
        account = ""
        issuer = ""
    }
}
