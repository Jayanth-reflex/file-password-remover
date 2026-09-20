import SwiftUI

/// The palette and type scale from docs/design/design-system.md.
///
/// Colours are declared through `UIColor`'s trait-aware initialiser rather than
/// as fixed values, so the whole interface follows the system appearance
/// without a single `if colorScheme ==` anywhere in the views.
enum Theme {

    static let ink = dynamic(dark: 0x121417, light: 0xF7F7F5)
    static let surface = dynamic(dark: 0x1A1D21, light: 0xFFFFFF)
    static let line = dynamic(dark: 0x2A2E34, light: 0xE4E4E0)
    static let mist = dynamic(dark: 0x8B9198, light: 0x6B6F76)
    static let platinum = dynamic(dark: 0xECEEF0, light: 0x15171A)
    /// The one accent. It marks what was verified and nothing else.
    static let brass = dynamic(dark: 0xC6A664, light: 0x9A7B3A)
    static let patina = dynamic(dark: 0x5E9C86, light: 0x3F7A63)
    static let oxide = dynamic(dark: 0xA8564B, light: 0x94433A)

    private static func dynamic(dark: UInt32, light: UInt32) -> Color {
        Color(UIColor { traits in
            UIColor(rgb: traits.userInterfaceStyle == .dark ? dark : light)
        })
    }

    /// Captions: small, upper case, wide tracked. The hallmark voice.
    struct Caption: ViewModifier {
        var color: Color = Theme.mist
        func body(content: Content) -> some View {
            content
                .font(.system(.caption2, design: .default).weight(.semibold))
                .textCase(.uppercase)
                .tracking(1.4)
                .foregroundStyle(color)
        }
    }

    /// Marks: monospaced, so columns of evidence line up and digits do not jitter.
    struct Mark: ViewModifier {
        func body(content: Content) -> some View {
            content
                .font(.system(.footnote, design: .monospaced))
                .foregroundStyle(Theme.platinum)
        }
    }
}

extension View {
    func caption(_ color: Color = Theme.mist) -> some View {
        modifier(Theme.Caption(color: color))
    }

    func mark() -> some View { modifier(Theme.Mark()) }
}

private extension UIColor {
    convenience init(rgb: UInt32) {
        self.init(
            red: CGFloat((rgb >> 16) & 0xFF) / 255,
            green: CGFloat((rgb >> 8) & 0xFF) / 255,
            blue: CGFloat(rgb & 0xFF) / 255,
            alpha: 1
        )
    }
}

/// The verification evidence, as a row of struck marks.
///
/// The signature element of the interface. It appears only after a verified
/// success, and every mark in it is data the engine returned from re-reading
/// the file it just wrote.
struct HallmarkRow: View {
    let marks: [(caption: String, value: String)]

    /// Shorter captions, matching the CLI renderer, so the two interfaces name
    /// the same evidence the same way. Only the caption is shortened.
    static let captions = [
        "content_digest": "digest",
        "content_scope": "scope",
        "docinfo_keys": "docinfo",
        "has_xmp": "xmp",
        "opens_with_password": "opens",
    ]

    init(_ verification: [String: String]) {
        marks = verification
            .sorted { $0.key < $1.key }
            .map { (Self.captions[$0.key] ?? $0.key, $0.value) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Rectangle().fill(Theme.line).frame(height: 1)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(alignment: .top, spacing: 20) {
                    ForEach(marks, id: \.caption) { mark in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(mark.caption).caption(Theme.brass)
                            Text(mark.value).mark()
                        }
                    }
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            "Verified. " + marks.map { "\($0.caption) \($0.value)" }.joined(separator: ", ")
        )
    }
}

/// A caption over a hairline: the section marker.
struct SectionMark: View {
    let label: String

    var body: some View {
        HStack(spacing: 12) {
            Text(label).caption()
            Rectangle().fill(Theme.line).frame(height: 1)
        }
        .accessibilityAddTraits(.isHeader)
    }
}
