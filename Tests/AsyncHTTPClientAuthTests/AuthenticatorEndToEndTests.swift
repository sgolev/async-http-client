//===----------------------------------------------------------------------===//
//
// This source file is part of the AsyncHTTPClient open source project
//
// Copyright (c) 2026 Apple Inc. and the AsyncHTTPClient project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of AsyncHTTPClient project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import AsyncHTTPClient
import Crypto
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import XCTest
import _CryptoExtras

@testable import AsyncHTTPClientAuth

#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
final class AuthenticatorEndToEndTests: XCTestCase {
    // MARK: Digest

    func testDigest() async throws {
        let nonceCounts = NIOLockedValueBox<[String]>([])
        let server = AuthTestServer { head, _ in
            guard let authorization = head.headers.first(name: "Authorization"),
                let fields = HTTPAuthenticationChallenge.parse(headerValues: [authorization]).first,
                fields.matches(scheme: "Digest"),
                let uri = fields[parameter: "uri"], let nc = fields[parameter: "nc"],
                let cnonce = fields[parameter: "cnonce"]
            else {
                var headers = HTTPHeaders()
                headers.add(name: "WWW-Authenticate", value: #"Digest realm="test", qop="auth", nonce="n1""#)
                headers.add(
                    name: "WWW-Authenticate",
                    value: #"Digest realm="test", qop="auth", algorithm=SHA-256, nonce="n2", opaque="o""#
                )
                return TestResponse(status: .unauthorized, headers: headers)
            }
            func sha256(_ string: String) -> String { SHA256.hash(data: Array(string.utf8)).hexString }
            let expected = sha256(
                "\(sha256("alice:test:secret")):n2:\(nc):\(cnonce):auth:\(sha256("\(head.method.rawValue):\(uri)"))"
            )
            guard fields[parameter: "response"] == expected, fields[parameter: "algorithm"] == "SHA-256",
                fields[parameter: "opaque"] == "o", uri == head.uri
            else {
                return TestResponse(status: .forbidden)
            }
            nonceCounts.withLockedValue { $0.append(nc) }
            return TestResponse(status: .ok)
        }
        defer { XCTAssertNoThrow(try server.shutdown()) }

        let authenticator = DigestAuthenticator(username: "alice", password: "secret")
        try await withClient { client in
            var request = HTTPClientRequest(url: server.baseURL + "/protected?x=1")
            request.authenticator = authenticator
            let first = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(first.status, .ok)
            XCTAssertEqual(first.history.count, 2)

            // The nonce is reused without another challenge.
            let second = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(second.status, .ok)
            XCTAssertEqual(second.history.count, 1)
        }
        XCTAssertEqual(nonceCounts.withLockedValue { $0 }, ["00000001", "00000002"])
    }

    func testDigestWithWrongPasswordGivesUp() async throws {
        let server = AuthTestServer { _, _ in
            TestResponse(
                status: .unauthorized,
                headers: ["WWW-Authenticate": #"Digest realm="test", qop="auth", nonce="n""#]
            )
        }
        defer { XCTAssertNoThrow(try server.shutdown()) }

        try await withClient { client in
            var request = HTTPClientRequest(url: server.baseURL + "/")
            request.authenticator = DigestAuthenticator(username: "alice", password: "wrong")
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .unauthorized)
            XCTAssertEqual(response.history.count, 2)
        }
    }

    // MARK: SCRAM

    func testSCRAM() async throws {
        let server = SCRAMTestServer(password: "pencil")
        defer { XCTAssertNoThrow(try server.server.shutdown()) }

        try await withClient { client in
            var request = HTTPClientRequest(url: server.server.baseURL + "/")
            request.authenticator = SCRAMAuthenticator(username: "user", password: "pencil")
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.history.count, 3)

            request.authenticator = SCRAMAuthenticator(username: "user", password: "wrong")
            let rejected = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(rejected.status, .unauthorized)
        }
    }

    func testSCRAMDetectsForgedServer() async throws {
        let server = SCRAMTestServer(password: "pencil", forgeServerSignature: true)
        defer { XCTAssertNoThrow(try server.server.shutdown()) }

        try await withClient { client in
            var request = HTTPClientRequest(url: server.server.baseURL + "/")
            request.authenticator = SCRAMAuthenticator(username: "user", password: "pencil")
            await XCTAssertThrowsErrorAsync(try await client.execute(request, deadline: .now() + .seconds(10))) {
                XCTAssertEqual($0 as? HTTPClientAuthenticationError, .serverSignatureMismatch)
            }
        }
    }

    // MARK: NTLM

    func testNTLM() async throws {
        let server = AuthTestServer { head, connection in
            if connection.values["authenticated"] as? Bool == true {
                return TestResponse(status: .ok, body: "connection:\(connection.id)")
            }
            guard let authorization = head.headers.first(name: "Authorization"), authorization.hasPrefix("NTLM "),
                let message = Base64.decode(String(authorization.dropFirst(5)))
            else {
                return TestResponse(status: .unauthorized, headers: ["WWW-Authenticate": "NTLM"])
            }
            switch message.count >= 12 ? message.readUInt32(at: 8) : 0 {
            case 1:
                let challenge = NTLMTestServer.challengeMessage(
                    serverChallenge: RandomBytes.generate(8),
                    timestamp: NTLM.fileTime(unixTimeInterval: 1_700_000_000)
                )
                connection.values["negotiate"] = message
                connection.values["challenge"] = challenge
                return TestResponse(
                    status: .unauthorized,
                    headers: ["WWW-Authenticate": "NTLM \(Base64.encode(challenge))"]
                )
            case 3:
                guard let negotiate = connection.values["negotiate"] as? [UInt8],
                    let challenge = connection.values["challenge"] as? [UInt8],
                    let verified = try? NTLMTestServer.verify(
                        authenticate: message,
                        negotiate: negotiate,
                        challenge: challenge,
                        password: "Password"
                    ),
                    verified.micIsValid, verified.user == "User", verified.domain == "Domain"
                else {
                    return TestResponse(status: .unauthorized, headers: ["WWW-Authenticate": "NTLM"])
                }
                connection.values["authenticated"] = true
                return TestResponse(status: .ok, body: "connection:\(connection.id)")
            default:
                return TestResponse(status: .badRequest)
            }
        }
        defer { XCTAssertNoThrow(try server.shutdown()) }

        try await withClient { client in
            var request = HTTPClientRequest(url: server.baseURL + "/")
            request.authenticator = NTLMAuthenticator(user: "User", domain: "Domain", password: "Password")

            let first = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(first.status, .ok)
            XCTAssertEqual(first.history.count, 2)
            let firstBody = String(buffer: try await first.body.collect(upTo: 1024))

            let second = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(second.status, .ok)
            XCTAssertEqual(second.history.count, 1)
            let secondBody = String(buffer: try await second.body.collect(upTo: 1024))
            XCTAssertEqual(secondBody, firstBody)

            request.authenticator = NTLMAuthenticator(user: "User", domain: "Domain", password: "wrong")
            let rejected = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(rejected.status, .unauthorized)
        }
    }

    // MARK: Negotiate

    func testNegotiateWithMutualAuthentication() async throws {
        let server = NegotiateTestServer(sendsFinalToken: true)
        defer { XCTAssertNoThrow(try server.server.shutdown()) }
        let provider = FakeNegotiateProvider()

        try await withClient { client in
            var request = HTTPClientRequest(url: server.server.baseURL + "/")
            request.authenticator = NegotiateAuthenticator(contextProvider: provider)
            let first = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(first.status, .ok)
            XCTAssertEqual(first.history.count, 3)

            // The authenticated connection is reused.
            let second = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(second.status, .ok)
            XCTAssertEqual(second.history.count, 1)
        }
        XCTAssertEqual(provider.servicePrincipalNames, ["HTTP@127.0.0.1"])
        XCTAssertEqual(server.server.connections, 1)
    }

    func testNegotiateFailsWithoutMutualAuthentication() async throws {
        let server = NegotiateTestServer(sendsFinalToken: false)
        defer { XCTAssertNoThrow(try server.server.shutdown()) }

        try await withClient { client in
            var request = HTTPClientRequest(url: server.server.baseURL + "/")
            request.authenticator = NegotiateAuthenticator(contextProvider: FakeNegotiateProvider())
            await XCTAssertThrowsErrorAsync(try await client.execute(request, deadline: .now() + .seconds(10))) {
                XCTAssertEqual($0 as? HTTPClientAuthenticationError, .mutualAuthenticationFailed)
            }

            request.authenticator = NegotiateAuthenticator(
                mutualAuthentication: .optional,
                contextProvider: FakeNegotiateProvider()
            )
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testSystemGSSAPIWithoutCredentials() async throws {
        // Make sure there is no ticket.
        setenv("KRB5CCNAME", "FILE:/nonexistent/ahc-test-ccache", 1)
        do {
            _ = try await GSSAPISecurityContextProvider().credentialIdentity()
            XCTFail("Expected an error")
        } catch let error as HTTPClientAuthenticationError {
            #if canImport(GSS) || GSSAPI
            XCTAssertTrue(error.isGSSFailure, "\(error)")
            #else
            XCTAssertEqual(error, .negotiateUnavailable)
            #endif
        }
    }
}

// MARK: - Helpers

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
func withClient<Result>(_ body: (HTTPClient) async throws -> Result) async throws -> Result {
    let client = HTTPClient(eventLoopGroupProvider: .singleton)
    do {
        let result = try await body(client)
        try await client.shutdown()
        return result
    } catch {
        try? await client.shutdown()
        throw error
    }
}

func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ verify: (Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expression did not throw", file: file, line: line)
    } catch {
        verify(error)
    }
}

/// Implements the server side of SCRAM-SHA-256 (RFC 7804).
final class SCRAMTestServer: Sendable {
    let server: AuthTestServer
    private static let salt: [UInt8] = Array("salt-for-tests".utf8)

    init(password: String, forgeServerSignature: Bool = false) {
        let saltedPassword = try! SCRAMClient.saltedPassword(
            mechanism: .sha256,
            password: password,
            salt: Self.salt,
            iterations: 4096
        )
        @Sendable func hmac(_ key: [UInt8], _ message: String) -> [UInt8] {
            Array(HMAC<SHA256>.authenticationCode(for: Array(message.utf8), using: SymmetricKey(data: key)))
        }
        let clientKey = hmac(saltedPassword, "Client Key")
        let storedKey = Array(SHA256.hash(data: clientKey))
        let serverKey = hmac(saltedPassword, "Server Key")
        // sid -> (client-first-message-bare, server-first-message)
        let sessions = NIOLockedValueBox<[String: (String, String)]>([:])

        self.server = AuthTestServer { head, _ in
            let challenge = TestResponse(
                status: .unauthorized,
                headers: ["WWW-Authenticate": #"SCRAM-SHA-256 realm="test""#]
            )
            guard let authorization = head.headers.first(name: "Authorization"),
                let fields = HTTPAuthenticationChallenge.parse(headerValues: [authorization]).first,
                fields.matches(scheme: "SCRAM-SHA-256"),
                let data = fields[parameter: "data"].flatMap(Base64.decode).map({ String(decoding: $0, as: UTF8.self) })
            else {
                return challenge
            }

            guard let sid = fields[parameter: "sid"] else {
                // client-first: "n,,n=user,r=<nonce>"
                guard data.hasPrefix("n,,"), let nonceStart = data.range(of: ",r=") else { return challenge }
                let bare = String(data.dropFirst(3))
                let nonce = String(data[nonceStart.upperBound...]) + "server"
                let serverFirst = "r=\(nonce),s=\(Base64.encode(Self.salt)),i=4096"
                let sid = "sid\(sessions.withLockedValue { $0.count })"
                sessions.withLockedValue { $0[sid] = (bare, serverFirst) }
                return TestResponse(
                    status: .unauthorized,
                    headers: ["WWW-Authenticate": "SCRAM-SHA-256 sid=\(sid), data=\(Base64.encode(serverFirst.utf8))"]
                )
            }

            // client-final: "c=biws,r=<nonce>,p=<proof>"
            guard let (bare, serverFirst) = sessions.withLockedValue({ $0[sid] }),
                let proofStart = data.range(of: ",p="),
                let proof = Base64.decode(String(data[proofStart.upperBound...]))
            else {
                return challenge
            }
            let authMessage = "\(bare),\(serverFirst),\(data[..<proofStart.lowerBound])"
            let clientSignature = hmac(storedKey, authMessage)
            let recoveredClientKey = zip(proof, clientSignature).map { $0 ^ $1 }
            guard Array(SHA256.hash(data: recoveredClientKey)) == storedKey else {
                return challenge
            }
            var serverSignature = hmac(serverKey, authMessage)
            if forgeServerSignature {
                serverSignature[0] ^= 0xFF
            }
            let serverFinal = "v=\(Base64.encode(serverSignature))"
            return TestResponse(
                status: .ok,
                headers: ["Authentication-Info": "sid=\(sid), data=\(Base64.encode(serverFinal.utf8))"]
            )
        }
    }
}

/// A server for a fake two leg `Negotiate` exchange, with tokens "c1", "s1", "c2", "s2".
final class NegotiateTestServer: Sendable {
    let server: AuthTestServer

    init(sendsFinalToken: Bool) {
        self.server = AuthTestServer { head, connection in
            if connection.values["authenticated"] as? Bool == true {
                return TestResponse(status: .ok)
            }
            let token = head.headers.first(name: "Authorization").flatMap { value -> String? in
                guard value.hasPrefix("Negotiate ") else { return nil }
                return Base64.decode(String(value.dropFirst(10))).map { String(decoding: $0, as: UTF8.self) }
            }
            switch token {
            case "c1":
                return TestResponse(
                    status: .unauthorized,
                    headers: ["WWW-Authenticate": "Negotiate \(Base64.encode("s1".utf8))"]
                )
            case "c2":
                connection.values["authenticated"] = true
                var headers = HTTPHeaders()
                if sendsFinalToken {
                    headers.add(name: "WWW-Authenticate", value: "Negotiate \(Base64.encode("s2".utf8))")
                }
                return TestResponse(status: .ok, headers: headers)
            default:
                return TestResponse(status: .unauthorized, headers: ["WWW-Authenticate": "Negotiate"])
            }
        }
    }
}

final class FakeNegotiateProvider: NegotiateSecurityContextProvider {
    private let _servicePrincipalNames = NIOLockedValueBox<[String]>([])
    var servicePrincipalNames: [String] { self._servicePrincipalNames.withLockedValue { $0 } }

    func credentialIdentity() async throws -> String {
        "alice@TEST"
    }

    func makeContext(
        servicePrincipalName: String,
        channelBinding: [UInt8]?
    ) async throws
        -> any NegotiateSecurityContext
    {
        self._servicePrincipalNames.withLockedValue { $0.append(servicePrincipalName) }
        return Context()
    }

    final class Context: NegotiateSecurityContext {
        func step(_ token: [UInt8]?) async throws -> (token: [UInt8]?, isComplete: Bool) {
            switch token.map({ String(decoding: $0, as: UTF8.self) }) {
            case .none:
                return (Array("c1".utf8), false)
            case "s1":
                return (Array("c2".utf8), false)
            case "s2":
                return (nil, true)
            default:
                throw HTTPClientAuthenticationError.malformedChallenge
            }
        }
    }
}
