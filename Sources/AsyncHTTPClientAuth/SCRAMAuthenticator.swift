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
import NIOHTTP1
import _CryptoExtras

/// Authenticates with the `SCRAM-SHA-256` or `SCRAM-SHA-1` scheme (RFC 7804).
///
/// SCRAM authenticates both sides: the server proves that it knows the (salted) password as well. A response whose
/// server signature does not match fails with ``HTTPClientAuthenticationError/serverSignatureMismatch``.
///
/// - Note: User names and passwords are not normalized with SASLprep. Use ASCII credentials, or credentials that are
///   already normalized.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public final class SCRAMAuthenticator: HTTPClientAuthenticator {
    public enum Mechanism: String, Sendable, CaseIterable {
        case sha256 = "SCRAM-SHA-256"
        case sha1 = "SCRAM-SHA-1"
    }

    public let username: String
    private let password: String
    /// The mechanisms to use, in the order of preference.
    public let mechanisms: [Mechanism]

    /// PBKDF2 is expensive by design. Cache the salted password per salt and iteration count.
    private let saltedPasswords = NIOLockedValueBox<[SaltedPasswordKey: [UInt8]]>([:])

    private struct SaltedPasswordKey: Hashable {
        var mechanism: Mechanism
        var salt: [UInt8]
        var iterations: Int
    }

    public init(username: String, password: String, mechanisms: [Mechanism] = [.sha256, .sha1]) {
        self.username = username
        self.password = password
        self.mechanisms = mechanisms
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        let response = try await exchange.send(request)
        let challenges = response.authenticationChallenges(for: peer)
        guard response.status == peer.challengeStatus,
            let (mechanism, challenge) = self.mechanisms.lazy.compactMap({ mechanism in
                challenges.first(where: { $0.matches(scheme: mechanism.rawValue) }).map { (mechanism, $0) }
            }).first
        else {
            return response
        }

        // client-first
        var client = SCRAMClient(
            mechanism: mechanism,
            username: self.username,
            nonce: Base64.encode(RandomBytes.generate(18))
        )
        var realm = ""
        if let value = challenge[parameter: "realm"] {
            realm = "realm=\"\(value.quotedStringEscaped)\", "
        }
        var authenticated = request
        authenticated.headers.replaceOrAdd(
            name: peer.credentialsHeaderName,
            value: "\(mechanism.rawValue) \(realm)data=\(Base64.encode(client.clientFirstMessage.utf8))"
        )
        let serverFirstResponse = try await exchange.send(authenticated)
        guard serverFirstResponse.status == peer.challengeStatus,
            let serverChallenge = serverFirstResponse.authenticationChallenges(for: peer)
                .first(where: { $0.matches(scheme: mechanism.rawValue) && $0[parameter: "data"] != nil }),
            let sid = serverChallenge[parameter: "sid"],
            let serverFirst = serverChallenge[parameter: "data"].flatMap(Base64.decode)
        else {
            return serverFirstResponse
        }

        // client-final
        let clientFinal = try client.clientFinalMessage(
            serverFirstMessage: String(decoding: serverFirst, as: UTF8.self),
            saltedPassword: { salt, iterations in
                try self.saltedPassword(mechanism: mechanism, salt: salt, iterations: iterations)
            }
        )
        authenticated.headers.replaceOrAdd(
            name: peer.credentialsHeaderName,
            value: "\(mechanism.rawValue) sid=\(sid), data=\(Base64.encode(clientFinal.utf8))"
        )
        let finalResponse = try await exchange.send(authenticated)
        guard finalResponse.status != peer.challengeStatus else {
            return finalResponse
        }

        // server-final
        guard
            let info = finalResponse.headers.first(name: peer.authenticationInfoHeaderName)
                .map(HTTPAuthenticationChallenge.parseParameters),
            let serverFinal = info["data"].flatMap(Base64.decode)
        else {
            throw HTTPClientAuthenticationError.mutualAuthenticationFailed
        }
        try client.verify(serverFinalMessage: String(decoding: serverFinal, as: UTF8.self))
        return finalResponse
    }

    private func saltedPassword(mechanism: Mechanism, salt: [UInt8], iterations: Int) throws -> [UInt8] {
        let key = SaltedPasswordKey(mechanism: mechanism, salt: salt, iterations: iterations)
        if let cached = self.saltedPasswords.withLockedValue({ $0[key] }) {
            return cached
        }
        let salted = try SCRAMClient.saltedPassword(
            mechanism: mechanism,
            password: self.password,
            salt: salt,
            iterations: iterations
        )
        self.saltedPasswords.withLockedValue { $0[key] = salted }
        return salted
    }
}

/// The client side of a SCRAM exchange (RFC 5802, section 3), without channel binding.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
struct SCRAMClient {
    let mechanism: SCRAMAuthenticator.Mechanism
    let clientFirstMessageBare: String
    let nonce: String
    private var expectedServerSignature: [UInt8]?

    /// The gs2-header for "no channel binding" and no authorization identity.
    static let gs2Header = "n,,"

    init(mechanism: SCRAMAuthenticator.Mechanism, username: String, nonce: String) {
        self.mechanism = mechanism
        self.nonce = nonce
        self.clientFirstMessageBare = "n=\(Self.saslName(username)),r=\(nonce)"
    }

    var clientFirstMessage: String {
        Self.gs2Header + self.clientFirstMessageBare
    }

    mutating func clientFinalMessage(
        serverFirstMessage: String,
        saltedPassword: (_ salt: [UInt8], _ iterations: Int) throws -> [UInt8]
    ) throws -> String {
        let attributes = Self.attributes(of: serverFirstMessage)
        guard let combinedNonce = attributes["r"], combinedNonce.hasPrefix(self.nonce),
            combinedNonce.count > self.nonce.count,
            let salt = attributes["s"].flatMap(Base64.decode),
            let iterations = attributes["i"].flatMap({ Int($0) }), iterations > 0
        else {
            throw HTTPClientAuthenticationError.malformedChallenge
        }

        let salted = try saltedPassword(salt, iterations)
        let clientFinalWithoutProof = "c=\(Base64.encode(Self.gs2Header.utf8)),r=\(combinedNonce)"
        let authMessage = Array("\(self.clientFirstMessageBare),\(serverFirstMessage),\(clientFinalWithoutProof)".utf8)

        let clientKey = self.hmac(key: salted, Array("Client Key".utf8))
        let storedKey = self.hash(clientKey)
        let clientSignature = self.hmac(key: storedKey, authMessage)
        let clientProof = zip(clientKey, clientSignature).map { $0 ^ $1 }
        let serverKey = self.hmac(key: salted, Array("Server Key".utf8))
        self.expectedServerSignature = self.hmac(key: serverKey, authMessage)

        return "\(clientFinalWithoutProof),p=\(Base64.encode(clientProof))"
    }

    func verify(serverFinalMessage: String) throws {
        let attributes = Self.attributes(of: serverFinalMessage)
        guard let expected = self.expectedServerSignature, attributes["e"] == nil,
            let signature = attributes["v"].flatMap(Base64.decode)
        else {
            throw HTTPClientAuthenticationError.mutualAuthenticationFailed
        }
        guard signature == expected else {
            throw HTTPClientAuthenticationError.serverSignatureMismatch
        }
    }

    static func saltedPassword(
        mechanism: SCRAMAuthenticator.Mechanism,
        password: String,
        salt: [UInt8],
        iterations: Int
    ) throws -> [UInt8] {
        let hashFunction: KDF.Insecure.PBKDF2.HashFunction
        let length: Int
        switch mechanism {
        case .sha256:
            hashFunction = .sha256
            length = SHA256.byteCount
        case .sha1:
            hashFunction = .insecureSHA1
            length = Insecure.SHA1.byteCount
        }
        let key = try KDF.Insecure.PBKDF2.deriveKey(
            from: Array(password.utf8),
            salt: salt,
            using: hashFunction,
            outputByteCount: length,
            unsafeUncheckedRounds: iterations
        )
        return key.withUnsafeBytes { Array($0) }
    }

    private func hmac(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        switch self.mechanism {
        case .sha256:
            return Array(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        case .sha1:
            return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        }
    }

    private func hash(_ message: [UInt8]) -> [UInt8] {
        switch self.mechanism {
        case .sha256:
            return Array(SHA256.hash(data: message))
        case .sha1:
            return Array(Insecure.SHA1.hash(data: message))
        }
    }

    /// RFC 5802, section 5.1: `=` and `,` are escaped in user names.
    private static func saslName(_ username: String) -> String {
        var result = ""
        for character in username {
            switch character {
            case "=": result += "=3D"
            case ",": result += "=2C"
            default: result.append(character)
            }
        }
        return result
    }

    private static func attributes(of message: String) -> [String: String] {
        var attributes: [String: String] = [:]
        for attribute in message.split(separator: ",") {
            guard let equals = attribute.firstIndex(of: "=") else { continue }
            attributes[String(attribute[..<equals])] = String(attribute[attribute.index(after: equals)...])
        }
        return attributes
    }
}
