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

/// Authenticates with the `Digest` scheme (RFC 7616).
///
/// Supports the `MD5`, `MD5-sess`, `SHA-256` and `SHA-256-sess` algorithms, the `auth` and `auth-int` qualities of
/// protection, and `userhash`. If the server offers several challenges, the strongest supported algorithm is used.
/// `SHA-512-256` is not supported.
///
/// The authenticator remembers the last challenge of each peer, so that following requests are authenticated
/// without another round trip. Share an authenticator between requests to benefit from that.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public final class DigestAuthenticator: HTTPClientAuthenticator {
    public let username: String
    private let password: String

    /// Whether `rspauth` in `Authentication-Info` must be present and correct. Defaults to `false`.
    public let requiresServerAuthentication: Bool

    /// The largest request body that is hashed for `auth-int`. Larger bodies are rejected.
    static let maximumIntegrityProtectedBodySize = 4 * 1024 * 1024

    private let sessions = NIOLockedValueBox<[HTTPClientExchange.Peer: Session]>([:])

    public init(username: String, password: String, requiresServerAuthentication: Bool = false) {
        self.username = username
        self.password = password
        self.requiresServerAuthentication = requiresServerAuthentication
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        var request = request

        // Reuse the last challenge of the peer, if there is one.
        var sent: Authorization?
        var response: HTTPClientResponse
        if let session = self.sessions.withLockedValue({ $0[peer]?.next() }) {
            self.sessions.withLockedValue { $0[peer] = session }
            sent = try await self.authorization(for: &request, session: session)
            response = try await exchange.send(sent!.applied(to: request, peer: peer))
        } else {
            response = try await exchange.send(request)
        }

        // At most one retry with a fresh challenge, unless the server says the nonce was stale.
        var answeredFreshChallenge = false
        while response.status == peer.challengeStatus {
            let challenges = response.authenticationChallenges(for: peer).compactMap(Challenge.init)
            guard let challenge = challenges.max(by: { $0.algorithm.strength < $1.algorithm.strength }) else {
                break
            }
            if answeredFreshChallenge && !challenge.stale {
                // The credentials are wrong.
                break
            }
            answeredFreshChallenge = true
            var session = Session(challenge: challenge)
            session.nonceCount = 1
            self.sessions.withLockedValue { $0[peer] = session }
            sent = try await self.authorization(for: &request, session: session)
            response = try await exchange.send(sent!.applied(to: request, peer: peer))
        }

        if let sent, response.status != peer.challengeStatus {
            try self.processAuthenticationInfo(of: response, for: sent, peer: peer)
        }
        return response
    }

    // MARK: Computation

    struct Challenge {
        var realm: String
        var nonce: String
        var opaque: String?
        var algorithm: Algorithm
        var qop: QualityOfProtection?
        var stale: Bool
        var userhash: Bool

        init?(_ challenge: HTTPAuthenticationChallenge) {
            guard challenge.matches(scheme: "Digest"),
                let realm = challenge[parameter: "realm"],
                let nonce = challenge[parameter: "nonce"],
                let algorithm = Algorithm(rawValue: challenge[parameter: "algorithm"] ?? "MD5")
            else {
                return nil
            }
            self.realm = realm
            self.nonce = nonce
            self.opaque = challenge[parameter: "opaque"]
            self.algorithm = algorithm
            let offered = (challenge[parameter: "qop"] ?? "").split(separator: ",").map {
                $0.trimmingCharacters(in: " \t").lowercased()
            }
            // RFC 7616 requires qop. `auth` is preferred, since it does not need the body.
            if offered.contains("auth") {
                self.qop = .auth
            } else if offered.contains("auth-int") {
                self.qop = .authInt
            } else if offered.isEmpty {
                // RFC 2069 compatibility
                self.qop = nil
            } else {
                return nil
            }
            self.stale = challenge[parameter: "stale"]?.lowercased() == "true"
            self.userhash = challenge[parameter: "userhash"]?.lowercased() == "true"
        }
    }

    enum Algorithm: String {
        case md5 = "MD5"
        case md5Session = "MD5-sess"
        case sha256 = "SHA-256"
        case sha256Session = "SHA-256-sess"

        init?(rawValue: String) {
            switch rawValue.uppercased() {
            case "MD5": self = .md5
            case "MD5-SESS": self = .md5Session
            case "SHA-256": self = .sha256
            case "SHA-256-SESS": self = .sha256Session
            default: return nil
            }
        }

        var strength: Int {
            switch self {
            case .md5, .md5Session: return 0
            case .sha256, .sha256Session: return 1
            }
        }

        var isSession: Bool {
            self == .md5Session || self == .sha256Session
        }

        func hash(_ string: String) -> String {
            self.hash(Array(string.utf8))
        }

        func hash(_ bytes: some Sequence<UInt8>) -> String {
            let bytes = Array(bytes)
            switch self {
            case .md5, .md5Session:
                return Insecure.MD5.hash(data: bytes).hexString
            case .sha256, .sha256Session:
                return SHA256.hash(data: bytes).hexString
            }
        }
    }

    enum QualityOfProtection: String {
        case auth
        case authInt = "auth-int"
    }

    struct Session {
        var challenge: Challenge
        var nonceCount: UInt32 = 0

        init(challenge: Challenge) {
            self.challenge = challenge
        }

        /// The session for the next request.
        func next() -> Session? {
            // Without qop, a nonce can't be reused safely.
            guard self.challenge.qop != nil else { return nil }
            var next = self
            next.nonceCount += 1
            return next
        }
    }

    struct Authorization {
        var headerValue: String
        var algorithm: Algorithm
        var ha1: String
        var nonce: String
        var nonceCount: String
        var cnonce: String
        var qop: QualityOfProtection?
        var uri: String

        func applied(to request: HTTPClientRequest, peer: HTTPClientExchange.Peer) -> HTTPClientRequest {
            var request = request
            request.headers.replaceOrAdd(name: peer.credentialsHeaderName, value: self.headerValue)
            return request
        }
    }

    private func authorization(for request: inout HTTPClientRequest, session: Session) async throws -> Authorization {
        var entityBody: ByteBuffer?
        if session.challenge.qop == .authInt {
            entityBody = try await request.collectBody(upTo: Self.maximumIntegrityProtectedBodySize)
        }
        return Self.authorization(
            username: self.username,
            password: self.password,
            method: request.method.rawValue,
            uri: request.requestTarget,
            entityBody: entityBody.map { Array($0.readableBytesView) } ?? [],
            session: session,
            cnonce: RandomBytes.generate(16).hexString
        )
    }

    /// Computes the `Authorization` header (RFC 7616, section 3.4).
    static func authorization(
        username: String,
        password: String,
        method: String,
        uri: String,
        entityBody: [UInt8],
        session: Session,
        cnonce: String
    ) -> Authorization {
        let challenge = session.challenge
        let algorithm = challenge.algorithm
        let nonceCount = String(session.nonceCount, radix: 16)
        let paddedNonceCount = String(repeating: "0", count: max(0, 8 - nonceCount.count)) + nonceCount

        var ha1 = algorithm.hash("\(username):\(challenge.realm):\(password)")
        if algorithm.isSession {
            ha1 = algorithm.hash("\(ha1):\(challenge.nonce):\(cnonce)")
        }
        let a2: String
        switch challenge.qop {
        case .authInt:
            a2 = "\(method):\(uri):\(algorithm.hash(entityBody))"
        case .auth, .none:
            a2 = "\(method):\(uri)"
        }
        let response: String
        if let qop = challenge.qop {
            response = algorithm.hash(
                "\(ha1):\(challenge.nonce):\(paddedNonceCount):\(cnonce):\(qop.rawValue):\(algorithm.hash(a2))"
            )
        } else {
            response = algorithm.hash("\(ha1):\(challenge.nonce):\(algorithm.hash(a2))")
        }

        var fields: [String] = []
        if challenge.userhash {
            fields.append("username=\"\(algorithm.hash("\(username):\(challenge.realm)"))\"")
        } else if username.utf8.allSatisfy({ $0 >= 0x20 && $0 < 0x7F }) {
            fields.append("username=\"\(username.quotedStringEscaped)\"")
        } else {
            // RFC 7616, section 3.4.4
            fields.append("username*=UTF-8''\(Self.percentEncoded(username))")
        }
        fields.append("realm=\"\(challenge.realm.quotedStringEscaped)\"")
        fields.append("uri=\"\(uri.quotedStringEscaped)\"")
        fields.append("algorithm=\(algorithm.rawValue)")
        fields.append("nonce=\"\(challenge.nonce.quotedStringEscaped)\"")
        if let qop = challenge.qop {
            fields.append("nc=\(paddedNonceCount)")
            fields.append("cnonce=\"\(cnonce)\"")
            fields.append("qop=\(qop.rawValue)")
        }
        fields.append("response=\"\(response)\"")
        if let opaque = challenge.opaque {
            fields.append("opaque=\"\(opaque.quotedStringEscaped)\"")
        }
        if challenge.userhash {
            fields.append("userhash=true")
        }

        return Authorization(
            headerValue: "Digest " + fields.joined(separator: ", "),
            algorithm: algorithm,
            ha1: ha1,
            nonce: challenge.nonce,
            nonceCount: paddedNonceCount,
            cnonce: cnonce,
            qop: challenge.qop,
            uri: uri
        )
    }

    private func processAuthenticationInfo(
        of response: HTTPClientResponse,
        for authorization: Authorization,
        peer: HTTPClientExchange.Peer
    ) throws {
        let info =
            response.headers.first(name: peer.authenticationInfoHeaderName)
            .map(HTTPAuthenticationChallenge.parseParameters) ?? [:]

        if let nextNonce = info["nextnonce"] {
            self.sessions.withLockedValue { sessions in
                guard var session = sessions[peer] else { return }
                session.challenge.nonce = nextNonce
                session.nonceCount = 0
                sessions[peer] = session
            }
        }

        guard self.requiresServerAuthentication else { return }
        // RFC 7616, section 3.5: like `response`, but A2 has no method.
        guard let rspauth = info["rspauth"], let qop = authorization.qop else {
            throw HTTPClientAuthenticationError.mutualAuthenticationFailed
        }
        let algorithm = authorization.algorithm
        let expected = algorithm.hash(
            "\(authorization.ha1):\(authorization.nonce):\(authorization.nonceCount):\(authorization.cnonce):"
                + "\(qop.rawValue):\(algorithm.hash(":\(authorization.uri)"))"
        )
        guard rspauth == expected else {
            throw HTTPClientAuthenticationError.serverSignatureMismatch
        }
    }

    private static func percentEncoded(_ string: String) -> String {
        var result = ""
        for byte in string.utf8 {
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
                UInt8(ascii: "~"):
                result.append(Character(Unicode.Scalar(byte)))
            default:
                result += "%" + [byte].hexString.uppercased()
            }
        }
        return result
    }
}

extension Substring {
    func trimmingCharacters(in characters: String) -> Substring {
        let set = Set(characters)
        var result = self
        while let first = result.first, set.contains(first) { result = result.dropFirst() }
        while let last = result.last, set.contains(last) { result = result.dropLast() }
        return result
    }
}
