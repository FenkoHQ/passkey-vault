import AVFoundation
import SwiftUI
import VisionKit

@MainActor
enum VaultCamera {
    static func authorize() async -> Bool {
        guard DataScannerViewController.isSupported else { return false }
        let allowed = await AVCaptureDevice.requestAccess(for: .video)
        return allowed && DataScannerViewController.isAvailable
    }
}

struct OTPScannerView: UIViewControllerRepresentable {
    let receive: (String) -> Void
    let failed: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(receive: receive, failed: failed) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
                                                qualityLevel: .balanced, recognizesMultipleItems: false,
                                                isPinchToZoomEnabled: true, isGuidanceEnabled: true,
                                                isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {
        guard !scanner.isScanning, !context.coordinator.finished else { return }
        do { try scanner.startScanning() }
        catch {
            context.coordinator.finished = true
            // SwiftUI must finish its current update before the sheet is dismissed.
            DispatchQueue.main.async { failed() }
        }
    }

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        coordinator.finished = true
        scanner.stopScanning()
        scanner.delegate = nil
    }

    @MainActor
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        var finished = false
        private let receive: (String) -> Void
        private let failed: () -> Void

        init(receive: @escaping (String) -> Void, failed: @escaping () -> Void) {
            self.receive = receive
            self.failed = failed
        }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem],
                         allItems: [RecognizedItem]) {
            guard !finished else { return }
            for item in items {
                guard case .barcode(let code) = item, let value = code.payloadStringValue else { continue }
                finished = true
                scanner.stopScanning()
                receive(value)
                return
            }
        }

        func dataScanner(_ scanner: DataScannerViewController,
                         becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            guard !finished else { return }
            finished = true
            scanner.stopScanning()
            failed()
        }
    }
}
