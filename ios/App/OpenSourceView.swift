import SwiftUI

struct OpenSourceView: View {
    private let notices = Bundle.main.url(forResource: "OpenSourceNotices", withExtension: "txt")
        .flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? "License notices could not be loaded."

    var body: some View {
        ScrollView {
            Text(notices)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .navigationTitle("Open source licenses")
    }
}
