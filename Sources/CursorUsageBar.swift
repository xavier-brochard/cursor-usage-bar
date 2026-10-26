// CursorUsageBar: shows your Cursor monthly usage ("$used/$limit") in the macOS menu bar.
//
// Auth: reuses Cursor.app's login. Cursor keeps its access token in state.vscdb,
// encrypted with Electron safeStorage (AES-128-CBC, key derived from the
// "Cursor Safe Storage" Keychain item). If that path fails, a session cookie
// pasted from cursor.com is used instead.
//
// Data: unofficial cursor.com dashboard endpoints, which may change without notice.

import AppKit
import CommonCrypto
import Security
import ServiceManagement
import SQLite3
import SwiftUI

// MARK: - Entry point

@main
enum Main {
    @MainActor
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--print") || args.contains("--probe") {
            Task {
                let code = await CLI.run(probe: args.contains("--probe"))
                exit(code)
            }
            dispatchMain()
        }
        CursorUsageBarApp.main()
    }
}

// MARK: - Model

struct Usage {
    var usedCents: Double
    var limitCents: Double?
    var resetsAt: Date?

    var fraction: Double? {
        guard let limitCents, limitCents > 0 else { return nil }
        return usedCents / limitCents
    }

    /// Menu bar text, e.g. "412.50/2000".
    var compact: String {
        let used = String(format: "%.2f", usedCents / 100)
        guard let limitCents else { return used }
        return "\(used)/\(Self.plainDollars(limitCents))"
    }

    /// e.g. "$412.50 of $2,000 (21%)".
    var summary: String {
        guard let limitCents, let fraction else { return "\(Self.currency(usedCents)) used" }
        return "\(Self.currency(usedCents)) of \(Self.currency(limitCents)) (\(Int((fraction * 100).rounded()))%)"
    }

    /// e.g. "$1,587.50 left · resets Nov 1".
    var remainingLine: String? {
        var parts: [String] = []
        if let limitCents { parts.append("\(Self.currency(max(limitCents - usedCents, 0))) left") }
        if let resetsAt { parts.append("resets \(Self.shortDate.string(from: resetsAt))") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private static func plainDollars(_ cents: Double) -> String {
        cents.truncatingRemainder(dividingBy: 100) == 0
            ? String(format: "%.0f", cents / 100)
            : String(format: "%.2f", cents / 100)
    }

    private static func currency(_ cents: Double) -> String {
        let f = NumberFormatter()
        f.numberStyle = .currency
        f.currencyCode = "USD"
        f.locale = Locale(identifier: "en_US")
        if cents.truncatingRemainder(dividingBy: 100) == 0 { f.maximumFractionDigits = 0 }
        return f.string(from: NSNumber(value: cents / 100)) ?? "$\(cents / 100)"
    }

    private static let shortDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US")
        f.setLocalizedDateFormatFromTemplate("MMM d")
        return f
    }()
}

enum UsageError: LocalizedError {
    case cursorDataMissing
    case notSignedIn
    case keychain(OSStatus)
    case decryptionFailed
    case notAuthenticated
    case http(Int)
    case unexpectedResponse
    case bothFailed(cursor: Error, pasted: Error)

    var errorDescription: String? {
        switch self {
        case .cursorDataMissing:
            "Cursor's local data wasn't found. Is Cursor installed?"
        case .notSignedIn:
            "Cursor isn't signed in. Open Cursor and log in."
        case .keychain(let status) where status == errSecUserCanceled || status == errSecAuthFailed:
            "Keychain access to “Cursor Safe Storage” was denied."
        case .keychain(let status):
            "Couldn't read “Cursor Safe Storage” from the Keychain (\(status))."
        case .decryptionFailed:
            "Couldn't decrypt Cursor's token. Its storage format may have changed."
        case .notAuthenticated:
            "Session expired. Open Cursor to sign in again."
        case .http(let code):
            "cursor.com returned HTTP \(code)."
        case .unexpectedResponse:
            "Unexpected response from cursor.com. The API may have changed."
        case .bothFailed(let cursor, let pasted):
            "\(cursor.localizedDescription) Pasted cookie: \(pasted.localizedDescription)"
        }
    }
}

// MARK: - Cursor.app login

enum CursorLogin {
    static let dbPath = ProcessInfo.processInfo.environment["CURSOR_DB_PATH"]
        ?? NSHomeDirectory() + "/Library/Application Support/Cursor/User/globalStorage/state.vscdb"

    static let tokenKey = "cursorAuth/accessToken"
    static let profileKey = "cursorAuth/cachedScopedProfile"
    private static let envelopePrefix = "cursor-safe-storage:v1:"

    /// Builds the `WorkosCursorSessionToken` cookie value from Cursor's stored login.
    /// Re-read on every call so it follows Cursor's own token refreshes.
    static func sessionCookie() async throws -> String {
        let items = try readItems([tokenKey, profileKey])
        guard let stored = items[tokenKey], !stored.isEmpty else { throw UsageError.notSignedIn }
        let token = try await decrypt(stored)
        guard let cookie = cookieValue(token: token, authId: authId(fromProfile: items[profileKey])) else {
            throw UsageError.notSignedIn
        }
        return cookie
    }

    /// Reads values from Cursor's VS Code-style key/value store, read-only.
    static func readItems(_ keys: [String]) throws -> [String: String] {
        var db: OpaquePointer?
        guard FileManager.default.fileExists(atPath: dbPath),
              sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            sqlite3_close(db)
            throw UsageError.cursorDataMissing
        }
        defer { sqlite3_close(db) }
        sqlite3_busy_timeout(db, 3000)

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT value FROM ItemTable WHERE key = ?", -1, &stmt, nil) == SQLITE_OK else {
            throw UsageError.cursorDataMissing
        }
        defer { sqlite3_finalize(stmt) }

        var result: [String: String] = [:]
        for key in keys {
            sqlite3_reset(stmt)
            sqlite3_bind_text(stmt, 1, key, -1, sqliteTransient)
            guard sqlite3_step(stmt) == SQLITE_ROW, let bytes = sqlite3_column_blob(stmt, 0) else { continue }
            let data = Data(bytes: bytes, count: Int(sqlite3_column_bytes(stmt, 0)))
            result[key] = String(decoding: data, as: UTF8.self)
        }
        return result
    }

    /// Decrypts "cursor-safe-storage:v1:<base64 of Electron safeStorage 'v10' blob>".
    static func decrypt(_ stored: String) async throws -> String {
        // Older Cursor versions stored the token in plain text.
        guard stored.hasPrefix(envelopePrefix) else { return stored }
        guard let blob = Data(base64Encoded: String(stored.dropFirst(envelopePrefix.count))),
              blob.starts(with: Array("v10".utf8)) else { throw UsageError.decryptionFailed }
        let key = try await SafeStorageKey.shared.get()
        guard let plain = aes128CBCDecrypt(Data(blob.dropFirst(3)), key: key),
              let token = String(data: plain, encoding: .utf8), !token.isEmpty else {
            await SafeStorageKey.shared.reset()
            throw UsageError.decryptionFailed
        }
        return token
    }

    static func cookieValue(token: String, authId: String?) -> String? {
        if token.contains("%3A%3A") { return token }
        if token.contains("::") { return token.replacingOccurrences(of: "::", with: "%3A%3A") }
        guard let subject = jwtSubject(token) ?? authId,
              let userId = subject.split(separator: "|").last else { return nil }
        return "\(userId)%3A%3A\(token)"
    }

    static func jwtSubject(_ token: String) -> String? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var b64 = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        guard let data = Data(base64Encoded: b64),
              let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return claims["sub"] as? String
    }

    private static func authId(fromProfile json: String?) -> String? {
        guard let data = json?.data(using: .utf8),
              let profile = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return profile["authId"] as? String
    }

    private static func aes128CBCDecrypt(_ data: Data, key: Data) -> Data? {
        let iv = [UInt8](repeating: 0x20, count: kCCBlockSizeAES128) // Chromium uses 16 spaces
        var out = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var moved = 0
        let status = key.withUnsafeBytes { k in
            data.withUnsafeBytes { d in
                CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                        k.baseAddress, key.count, iv, d.baseAddress, data.count, &out, out.count, &moved)
            }
        }
        return status == Int32(kCCSuccess) ? Data(out.prefix(moved)) : nil
    }

    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}

/// The AES key behind Electron safeStorage, cached in memory so the Keychain is read once per launch.
actor SafeStorageKey {
    static let shared = SafeStorageKey()
    private var cached: Data?

    func get() throws -> Data {
        if let cached { return cached }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Cursor Safe Storage",
            kSecAttrAccount as String: "Cursor",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let password = item as? Data else { throw UsageError.keychain(status) }

        let salt = Array("saltysalt".utf8)
        var key = [UInt8](repeating: 0, count: kCCKeySizeAES128)
        let result = password.withUnsafeBytes { pw in
            CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw.bindMemory(to: CChar.self).baseAddress, password.count,
                                 salt, salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1), 1003, &key, key.count)
        }
        guard result == Int32(kCCSuccess) else { throw UsageError.decryptionFailed }
        cached = Data(key)
        return Data(key)
    }

    func reset() { cached = nil }
}

// MARK: - Pasted cookie fallback

enum PastedCookie {
    private static let baseQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "io.github.xavier-brochard.CursorUsageBar",
        kSecAttrAccount as String: "WorkosCursorSessionToken",
    ]

    static func load() -> String? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func save(_ value: String) -> Bool {
        delete()
        var query = baseQuery
        query[kSecValueData as String] = Data(value.utf8)
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    static func delete() {
        SecItemDelete(baseQuery as CFDictionary)
    }

    /// Accepts the bare cookie value, "WorkosCursorSessionToken=…", or a whole Cookie header.
    static func normalize(_ raw: String) -> String? {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let range = value.range(of: "WorkosCursorSessionToken=") {
            value = String(value[range.upperBound...].prefix { $0 != ";" })
        }
        value = value.replacingOccurrences(of: "::", with: "%3A%3A")
        guard value.contains("%3A%3A"), !value.contains(where: \.isWhitespace) else { return nil }
        return value
    }
}

// MARK: - cursor.com API

struct CursorAPI {
    let cookie: String

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.timeoutIntervalForRequest = 20
        return URLSession(configuration: config)
    }()

    func get(_ path: String) async throws -> Any {
        try await json(path, method: "GET", body: nil)
    }

    func post(_ path: String, _ body: [String: Any] = [:]) async throws -> Any {
        try await json(path, method: "POST", body: body)
    }

    func raw(_ path: String, method: String, body: [String: Any]?) async throws -> (status: Int, data: Data) {
        var request = URLRequest(url: URL(string: "https://cursor.com" + path)!)
        request.httpMethod = method
        request.setValue("WorkosCursorSessionToken=\(cookie)", forHTTPHeaderField: "Cookie")
        // POSTs are rejected without a cursor.com Origin (CSRF check).
        request.setValue("https://cursor.com", forHTTPHeaderField: "Origin")
        request.setValue("https://cursor.com/dashboard/usage", forHTTPHeaderField: "Referer")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, response) = try await Self.session.data(for: request)
        return ((response as? HTTPURLResponse)?.statusCode ?? 0, data)
    }

    private func json(_ path: String, method: String, body: [String: Any]?) async throws -> Any {
        let (status, data) = try await raw(path, method: method, body: body)
        if status == 401 || status == 403 { throw UsageError.notAuthenticated }
        guard (200..<300).contains(status) else { throw UsageError.http(status) }
        guard let json = try? JSONSerialization.jsonObject(with: data) else { throw UsageError.unexpectedResponse }
        return json
    }
}

// MARK: - Fetching usage

enum UsageFetcher {
    /// Tries Cursor.app's login first, then the pasted cookie.
    static func fetch() async throws -> Usage {
        do {
            return try await fetch(cookie: CursorLogin.sessionCookie())
        } catch let cursorError {
            guard let pasted = PastedCookie.load() else { throw cursorError }
            do {
                return try await fetch(cookie: pasted)
            } catch {
                throw UsageError.bothFailed(cursor: cursorError, pasted: error)
            }
        }
    }

    static func fetch(cookie: String) async throws -> Usage {
        let api = CursorAPI(cookie: cookie)
        // "Your monthly usage $X / $Y" on cursor.com/dashboard/usage.
        if let usage = parseUsageSummary(try await api.get("/api/usage-summary")) {
            return usage
        }
        // Personal plans with unified billing.
        if let usage = parseUsageStatus(try await api.get("/api/dashboard/v2/usage-status?scope=user")) {
            return usage
        }
        throw UsageError.unexpectedResponse
    }

    static func parseUsageSummary(_ json: Any) -> Usage? {
        guard let root = json as? [String: Any],
              let individual = root["individualUsage"] as? [String: Any] else { return nil }
        // Team/enterprise plans report "overall"; other plans "onDemand" or "plan". Amounts are cents.
        for pool in ["overall", "onDemand", "plan"] {
            guard let bucket = individual[pool] as? [String: Any],
                  bucket["enabled"] as? Bool != false,
                  let used = number(bucket["used"]) else { continue }
            return Usage(usedCents: used, limitCents: number(bucket["limit"]), resetsAt: date(root["billingCycleEnd"]))
        }
        return nil
    }

    static func parseUsageStatus(_ json: Any) -> Usage? {
        guard let object = findObject(in: json, containing: "usedCents"),
              let used = number(object["usedCents"]) else { return nil }
        return Usage(usedCents: used, limitCents: number(object["limitCents"]), resetsAt: date(object["resetsAt"]))
    }

    /// Finds the first dictionary (depth-first) that has `key`.
    private static func findObject(in json: Any, containing key: String) -> [String: Any]? {
        if let dict = json as? [String: Any] {
            if dict[key] != nil { return dict }
            for value in dict.values { if let found = findObject(in: value, containing: key) { return found } }
        } else if let array = json as? [Any] {
            for value in array { if let found = findObject(in: value, containing: key) { return found } }
        }
        return nil
    }

    private static func number(_ any: Any?) -> Double? {
        switch any {
        case let n as NSNumber: n.doubleValue
        case let s as String: Double(s)
        default: nil
        }
    }

    private static func date(_ any: Any?) -> Date? {
        if let s = any as? String, Double(s) == nil {
            let iso = ISO8601DateFormatter()
            iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            return iso.date(from: s) ?? ISO8601DateFormatter().date(from: s)
        }
        guard let n = number(any) else { return nil }
        return Date(timeIntervalSince1970: n > 1e11 ? n / 1000 : n) // epoch ms or s
    }
}

// MARK: - Command line (--print, --probe)

enum CLI {
    static func run(probe: Bool) async -> Int32 {
        if probe {
            await Probe.run()
            return 0
        }
        do {
            let usage = try await UsageFetcher.fetch()
            print(usage.compact)
            print(usage.summary)
            if let line = usage.remainingLine { print(line) }
            return 0
        } catch {
            FileHandle.standardError.write(Data("error: \(error.localizedDescription)\n".utf8))
            return 1
        }
    }
}

/// Dumps raw responses from the known dashboard endpoints, to debug API changes.
/// Output can include account details: don't paste it publicly.
enum Probe {
    static func run() async {
        let cookie: String
        do {
            let stored = try CursorLogin.readItems([CursorLogin.tokenKey])[CursorLogin.tokenKey] ?? ""
            let token = try await CursorLogin.decrypt(stored)
            print("stored token: \(stored.prefix(while: { $0 != ":" })) envelope, \(stored.count) chars")
            print("decrypted token: \(token.count) chars, JWT: \(CursorLogin.jwtSubject(token) != nil), has '::': \(token.contains("::"))")
            cookie = try await CursorLogin.sessionCookie()
            print("auth: Cursor login")
        } catch {
            guard let pasted = PastedCookie.load() else {
                print("auth failed: \(error.localizedDescription)")
                return
            }
            cookie = pasted
            print("auth: pasted cookie (Cursor login failed: \(error.localizedDescription))")
        }

        let api = CursorAPI(cookie: cookie)
        let endpoints: [(String, String, [String: Any]?)] = [
            ("GET", "/api/usage-summary", nil),
            ("GET", "/api/dashboard/v2/usage-status?scope=user", nil),
            ("POST", "/api/dashboard/get-current-period-usage", [:]),
        ]
        for (method, path, body) in endpoints {
            do {
                let (status, data) = try await api.raw(path, method: method, body: body)
                print("\n### \(method) \(path) -> \(status)\n\(redact(String(decoding: data.prefix(3000), as: UTF8.self)))")
            } catch {
                print("\n### \(method) \(path) -> \(error.localizedDescription)")
            }
        }
    }

    private static func redact(_ text: String) -> String {
        text.replacingOccurrences(of: #"[\w.+-]+@[\w-]+\.[\w.]+"#, with: "<email>", options: .regularExpression)
    }
}

// MARK: - App state

@MainActor
final class UsageStore: ObservableObject {
    @Published private(set) var usage: Usage?
    @Published private(set) var errorMessage: String?
    @Published private(set) var updatedAt: Date?
    @Published private(set) var isRefreshing = false
    @Published private(set) var hasPastedCookie = PastedCookie.load() != nil
    @Published private(set) var launchAtLogin = SMAppService.mainApp.status == .enabled

    private var timer: Timer?
    private var wakeObserver: NSObjectProtocol?

    init() {
        timer = Timer.scheduledTimer(withTimeInterval: 5 * 60, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(10)) // give the network time to come back
                await self?.refresh()
            }
        }
        Task { await refresh() }
    }

    var label: String {
        guard let usage else { return errorMessage == nil ? "Cursor …" : "Cursor ⚠︎" }
        let warn = errorMessage != nil || (usage.fraction ?? 0) >= 0.9
        return warn ? "⚠︎ \(usage.compact)" : usage.compact
    }

    var statusLine: String {
        if let errorMessage { return errorMessage }
        if let updatedAt { return "Updated \(updatedAt.formatted(date: .omitted, time: .shortened))" }
        return "Loading…"
    }

    func refresh() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            usage = try await UsageFetcher.fetch()
            updatedAt = Date()
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func usePastedCookie() {
        guard let raw = NSPasteboard.general.string(forType: .string),
              let value = PastedCookie.normalize(raw) else {
            errorMessage = "The clipboard doesn't hold a WorkosCursorSessionToken cookie."
            return
        }
        guard PastedCookie.save(value) else {
            errorMessage = "Couldn't save the cookie to the Keychain."
            return
        }
        hasPastedCookie = true
        Task { await refresh() }
    }

    func forgetPastedCookie() {
        PastedCookie.delete()
        hasPastedCookie = false
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            errorMessage = "Launch at Login: \(error.localizedDescription)"
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }
}

// MARK: - UI

struct CursorUsageBarApp: App {
    @StateObject private var store = UsageStore()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(store: store)
        } label: {
            Text(store.label).monospacedDigit()
        }
        .menuBarExtraStyle(.menu)
    }
}

struct MenuContent: View {
    @ObservedObject var store: UsageStore

    var body: some View {
        if let usage = store.usage {
            Text(usage.summary)
            if let line = usage.remainingLine { Text(line) }
        }
        Text(store.statusLine)
        Divider()
        Button("Refresh Now") { Task { await store.refresh() } }
            .keyboardShortcut("r")
        Button("Open Usage Dashboard") {
            NSWorkspace.shared.open(URL(string: "https://cursor.com/dashboard/usage")!)
        }
        Divider()
        Button("Use Session Cookie from Clipboard") { store.usePastedCookie() }
        if store.hasPastedCookie {
            Button("Forget Session Cookie") { store.forgetPastedCookie() }
        }
        Toggle("Launch at Login", isOn: Binding(get: { store.launchAtLogin }, set: { store.setLaunchAtLogin($0) }))
        Divider()
        Button("Quit") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
