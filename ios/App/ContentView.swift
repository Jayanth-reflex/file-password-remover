import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @StateObject private var model = DocumentModel()
    @State private var importing = false
    @State private var generatePassword = true

    var body: some View {
        ZStack {
            Theme.ink.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 28) {
                    masthead
                    source
                    stageContent
                    colophon
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .tint(Theme.brass)
        .fileImporter(
            isPresented: $importing, allowedContentTypes: [.item], allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first { model.load(url) }
        }
    }

    // MARK: - Masthead

    private var masthead: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Local only").caption(Theme.brass)
            Text("File Password Remover")
                .font(.system(.largeTitle, design: .default).weight(.bold))
                .foregroundStyle(Theme.platinum)
            Text("Lock a file, or open one you have the password for. Nothing leaves this device.")
                .font(.subheadline)
                .foregroundStyle(Theme.mist)
        }
    }

    // MARK: - Source

    private var source: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionMark(label: "Source")
            Button {
                importing = true
            } label: {
                HStack {
                    Image(systemName: "doc.badge.plus")
                    Text(model.fileName.isEmpty ? "Choose a file" : model.fileName)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                }
                .frame(minHeight: 44)
                .padding(.horizontal, 16)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
                .foregroundStyle(Theme.platinum)
            }
            .accessibilityIdentifier("choose-file")

            if !model.fileName.isEmpty {
                Button("Start over", role: .destructive) { model.reset() }
                    .font(.footnote)
                    .accessibilityIdentifier("start-over")
            }
        }
    }

    // MARK: - Stages

    @ViewBuilder
    private var stageContent: some View {
        switch model.stage {
        case .empty:
            EmptyView()

        case .inspected(let detection):
            detectionCard(detection)
            switch model.available {
            case .remove: removeControls
            case .protectIt: protectControls
            case .nothing: EmptyView()
            }

        case .working:
            HStack(spacing: 12) {
                ProgressView().tint(Theme.brass)
                Text("Working…").foregroundStyle(Theme.mist)
            }
            .accessibilityIdentifier("working")

        case .done(let url, let detection):
            outcome(
                title: "Protection removed",
                detail: detection.detail,
                url: url,
                verification: model.verification
            )

        case .protected(let url, let detection, let generated):
            outcome(
                title: "Protected and verified",
                detail: detection.detail,
                url: url,
                verification: model.verification
            )
            if let generated {
                generatedPassword(generated)
            }

        case .failed(let message):
            VStack(alignment: .leading, spacing: 8) {
                SectionMark(label: "Could not do that")
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(Theme.oxide)
                    .accessibilityIdentifier("error")
            }
        }
    }

    private func detectionCard(_ detection: Detection) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionMark(label: "What this file is")
            VStack(alignment: .leading, spacing: 10) {
                field("Format", detection.format.rawValue.uppercased())
                field("Protection", detection.protection.rawValue)
                if let algorithm = detection.algorithm {
                    field("Algorithm", algorithm)
                }
                Text(detection.detail)
                    .font(.footnote)
                    .foregroundStyle(Theme.mist)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
        }
    }

    private func field(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).caption()
            Spacer(minLength: 16)
            Text(value).mark().multilineTextAlignment(.trailing)
        }
        .accessibilityElement(children: .combine)
    }

    private var removeControls: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionMark(label: "Password")
            SecureField("Password for this file", text: $model.password)
                .textContentType(.password)
                .textFieldStyle(.plain)
                .padding(14)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
                .foregroundStyle(Theme.platinum)
                .accessibilityIdentifier("password-field")
            primaryButton("Remove protection", enabled: !model.password.isEmpty) {
                model.removeProtection()
            }
            .accessibilityIdentifier("remove-button")
        }
    }

    private var protectControls: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionMark(label: "Add a password")
            Picker("How to choose a password", selection: $generatePassword) {
                Text("Generate one").tag(true)
                Text("Use my own").tag(false)
            }
            .pickerStyle(.segmented)
            .accessibilityIdentifier("password-source")

            if generatePassword {
                Text("A strong password will be made for you and shown once. This app cannot recover it later.")
                    .font(.footnote)
                    .foregroundStyle(Theme.mist)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                SecureField("Password to set", text: $model.password)
                    .textContentType(.newPassword)
                    .textFieldStyle(.plain)
                    .padding(14)
                    .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
                    .foregroundStyle(Theme.platinum)
                    .accessibilityIdentifier("new-password-field")
                // Typed twice: behind a mask, one wrong key would lock the file
                // with a password nobody knows, and it cannot be recovered.
                SecureField("Type it again", text: $model.confirmation)
                    .textContentType(.newPassword)
                    .textFieldStyle(.plain)
                    .padding(14)
                    .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
                    .foregroundStyle(Theme.platinum)
                    .accessibilityIdentifier("confirm-password-field")
                if !model.confirmation.isEmpty && model.password != model.confirmation {
                    Text("The two passwords do not match.")
                        .font(.footnote)
                        .foregroundStyle(Theme.oxide)
                        .accessibilityIdentifier("password-mismatch")
                }
            }

            primaryButton(
                "Protect this file",
                enabled: model.canProtect(generatePassword: generatePassword)
            ) {
                model.protectFile(generatePassword: generatePassword)
            }
            .accessibilityIdentifier("protect-button")
        }
    }

    private func outcome(
        title: String, detail: String, url: URL, verification: [String: String]
    ) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionMark(label: "Done")
            Label(title, systemImage: "checkmark.seal.fill")
                .font(.headline)
                .foregroundStyle(Theme.patina)
                .accessibilityIdentifier("success")
            Text(detail).font(.footnote).foregroundStyle(Theme.mist)
            if !verification.isEmpty {
                HallmarkRow(verification)
            }
            ShareLink(item: url) {
                Label("Save or share", systemImage: "square.and.arrow.up")
                    .frame(minHeight: 44)
            }
            .accessibilityIdentifier("share-button")
        }
    }

    /// Shown once, and never stored. Losing it means losing the file, so it is
    /// the loudest thing on screen when it appears.
    private func generatedPassword(_ password: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionMark(label: "Password")
            Text(password)
                .font(.system(.title3, design: .monospaced))
                .foregroundStyle(Theme.platinum)
                .textSelection(.enabled)
                .accessibilityIdentifier("generated-password")
                .accessibilityLabel(
                    "Generated password: " + password.map { String($0) }.joined(separator: " ")
                )
            Button {
                UIPasteboard.general.string = password
            } label: {
                Label("Copy password", systemImage: "doc.on.doc").frame(minHeight: 44)
            }
            .accessibilityIdentifier("copy-password")
            Text("Save this now. It is shown once, and this app cannot recover it.")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(Theme.brass)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.brass, lineWidth: 1)
        )
    }

    private func primaryButton(
        _ title: String, enabled: Bool, action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            Text(title)
                .font(.headline)
                .frame(maxWidth: .infinity, minHeight: 48)
        }
        .buttonStyle(.borderedProminent)
        .tint(Theme.brass)
        .foregroundStyle(Theme.ink)
        .disabled(!enabled)
    }

    private var colophon: some View {
        // The version is here so a bug report can name the build it came from.
        // It reads from FprKit rather than the app bundle, so what is shown is
        // the version of the engine that produced the result above it.
        Text("Version \(FprKit.version). No network access, no telemetry. Apache-2.0.")
            .caption()
            .padding(.top, 8)
    }
}

#Preview { ContentView() }
