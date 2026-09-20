import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var model = RemovalModel()
    @State private var importing = false
    @State private var exporting = false

    var body: some View {
        NavigationStack {
            Form {
                fileSection
                stageSection
            }
            .navigationTitle("Password Remover")
            .fileImporter(
                isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: false
            ) { result in
                if case .success(let urls) = result, let url = urls.first { model.load(url) }
            }
        }
    }

    private var fileSection: some View {
        Section {
            Button {
                importing = true
            } label: {
                Label(model.fileName.isEmpty ? "Choose a file" : model.fileName,
                      systemImage: "doc.badge.plus")
            }
            .accessibilityIdentifier("choose-file")

            if !model.fileName.isEmpty {
                Button("Start over", role: .destructive) { model.reset() }
                    .accessibilityIdentifier("start-over")
            }
        } footer: {
            Text("The file never leaves this device. There is no upload and no network code.")
        }
    }

    @ViewBuilder
    private var stageSection: some View {
        switch model.stage {
        case .empty:
            EmptyView()

        case .inspected(let detection):
            Section("What this file is") {
                LabeledContent("Format", value: detection.format.rawValue.uppercased())
                LabeledContent("Protection", value: detection.protection.rawValue)
                if let algorithm = detection.algorithm {
                    LabeledContent("Algorithm", value: algorithm)
                }
                Text(detection.detail).font(.footnote).foregroundStyle(.secondary)
            }
            if detection.removability == .removable {
                Section("Password") {
                    SecureField("Password for this file", text: $model.password)
                        .textContentType(.password)
                        .accessibilityIdentifier("password-field")
                    Button("Remove protection") { model.removeProtection() }
                        .disabled(model.password.isEmpty)
                        .accessibilityIdentifier("remove-button")
                }
            }

        case .working:
            Section { ProgressView("Working…").accessibilityIdentifier("working") }

        case .done(let url, let detection):
            Section("Done") {
                Label("Protection removed and verified", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
                    .accessibilityIdentifier("success")
                Text(detection.detail).font(.footnote).foregroundStyle(.secondary)
                ShareLink(item: url) { Label("Save or share", systemImage: "square.and.arrow.up") }
                    .accessibilityIdentifier("share-button")
            }

        case .failed(let message):
            Section("Could not do that") {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("error")
            }
        }
    }
}

#Preview { ContentView() }
