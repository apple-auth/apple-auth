import Foundation
import apple_auth

/// Optional session storage encryption. Key ownership and storage belong to the application.
public enum SessionCrypto {
    private static let maximumSize = 16 * 1024 * 1024
    public static func generateKey() throws -> Data {
        try clientData { aauth_client_generate_session_key($0) }
    }

    internal static func validate(_ key: Data) throws {
        guard key.count == 32 else { throw AppleAuthError("Session encryption requires a 32-byte key") }
    }

    public static func encrypt(_ data: Data, key: Data) throws -> Data {
        try validate(key)
        guard data.count <= maximumSize else { throw AppleAuthError("Session exceeds the 16 MiB storage limit") }
        return try data.withUnsafeBytes { bytes in
            try key.withUnsafeBytes { secret in
                try clientData { aauth_client_encrypt_session(bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count, secret.bindMemory(to: UInt8.self).baseAddress, secret.count, $0) }
            }
        }
    }

    public static func decrypt(_ data: Data, key: Data) throws -> Data {
        try validate(key)
        guard data.count <= maximumSize + 37 else { throw AppleAuthError("Session exceeds the 16 MiB storage limit") }
        return try data.withUnsafeBytes { bytes in
            try key.withUnsafeBytes { secret in
                try clientData { aauth_client_decrypt_session(bytes.bindMemory(to: UInt8.self).baseAddress,
                    bytes.count, secret.bindMemory(to: UInt8.self).baseAddress, secret.count, $0) }
            }
        }
    }

    internal static func encode(_ data: Data, key: Data?) throws -> Data {
        guard let key else { return data }
        return try encrypt(data, key: key)
    }

    internal static func decode(_ data: Data, key: Data?) throws -> Data {
        guard let key else {
            guard !data.starts(with: Data("AAUTHENC".utf8)) else {
                throw AppleAuthError("Encrypted session requires an encryption key")
            }
            return data
        }
        return try decrypt(data, key: key)
    }

    internal static func save(_ data: Data, to file: URL, key: Data?, overwrite: Bool = true) throws {
        let path = try localPath(file)
        if !overwrite && FileManager.default.fileExists(atPath: path) {
            throw AppleAuthError("Session output already exists")
        }
        let encoded = try encode(data, key: key)
        try encoded.withUnsafeBytes { bytes in
            try checkClient(aauth_client_save_session(path,
                bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count))
        }
    }

    internal static func read(from file: URL) throws -> Data {
        _ = try localPath(file)
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var data = Data()
        while let chunk = try handle.read(upToCount: min(65536, maximumSize + 38 - data.count)), !chunk.isEmpty {
            data.append(chunk)
            guard data.count <= maximumSize + 37 else {
                throw AppleAuthError("Session file exceeds the 16 MiB storage limit")
            }
        }
        return data
    }
}

public extension AccountSession {
    func serialize(encryptionKey: Data? = nil) throws -> Data {
        try SessionCrypto.encode(plist, key: encryptionKey)
    }

    static func deserialize(_ data: Data, encryptionKey: Data? = nil) throws -> AccountSession {
        try AccountSession(plist: SessionCrypto.decode(data, key: encryptionKey))
    }

    static func load(from file: URL, encryptionKey: Data? = nil) throws -> AccountSession {
        _ = try localPath(file)
        return try deserialize(SessionCrypto.read(from: file), encryptionKey: encryptionKey)
    }
}

public extension StoreSession {
    func serialize(encryptionKey: Data? = nil) throws -> Data {
        try SessionCrypto.encode(plist, key: encryptionKey)
    }

    static func deserialize(_ data: Data, encryptionKey: Data? = nil) throws -> StoreSession {
        try StoreSession(plist: SessionCrypto.decode(data, key: encryptionKey))
    }
}

public extension DeveloperSession {
    func serialize(encryptionKey: Data? = nil) throws -> Data {
        try SessionCrypto.encode(JSONEncoder().encode(self), key: encryptionKey)
    }

    static func deserialize(_ data: Data, encryptionKey: Data? = nil) throws -> DeveloperSession {
        let value = try JSONDecoder().decode(DeveloperSession.self,
            from: SessionCrypto.decode(data, key: encryptionKey))
        guard !value.accountID.isEmpty, !value.token.isEmpty, value.expiresAtMilliseconds >= 0 else {
            throw AppleAuthError("Invalid saved Developer Session")
        }
        return value
    }

    func save(to file: URL, encryptionKey: Data? = nil) throws {
        try SessionCrypto.save(JSONEncoder().encode(self), to: file, key: encryptionKey)
    }

    static func load(from file: URL, encryptionKey: Data? = nil) throws -> DeveloperSession {
        _ = try localPath(file)
        return try deserialize(SessionCrypto.read(from: file), encryptionKey: encryptionKey)
    }
}
