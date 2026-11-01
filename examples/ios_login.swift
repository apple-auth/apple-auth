import Foundation
import AppleAuth

func signInForDeveloperServices(directory: URL, email: String, password: String,
                                verification: Verification) async throws -> (Device, DeveloperSession) {
    let device = try Device(directory: directory, platform: .iphone)
    let account = try await device.login(email: email, password: password, verification: verification)
    let session = try await device.developerSession(account: account)
    return (device, session)
}
