import SwiftUI

@main
struct FenkoVaultApp: App {
    var body: some Scene {
        WindowGroup {
            WebVaultView()
                .ignoresSafeArea(.keyboard)
        }
    }
}
