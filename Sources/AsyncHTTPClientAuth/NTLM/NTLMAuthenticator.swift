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
import NIOHTTP1

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Date
#else
import struct Foundation.Date
#endif

/// Authenticates with the `NTLM` scheme ([MS-NLMP], NTLMv2 only).
///
/// NTLM authenticates connections, not requests. The authenticator pins a connection for the user, runs the
/// three message handshake on it, and marks it as authenticated. Later requests of the same user reuse
/// authenticated connections without another handshake.
///
/// If the connection uses TLS, the credentials are bound to the server certificate (Extended Protection for
/// Authentication), unless ``channelBinding`` is ``ChannelBindingPolicy/disabled``.
///
/// - Warning: NTLM is a legacy protocol. Prefer `Negotiate` (Kerberos) where possible.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct NTLMAuthenticator: HTTPClientAuthenticator {
    /// The identity a connection is pinned for. It covers the password, so that an authenticator with other (for
    /// example wrong) credentials for the same user never gets a connection that was authenticated by another one.
    struct Identity: Hashable, Sendable {
        var domain: String
        var user: String
        /// The NT hash of the password, never the password itself.
        var credentialHash: [UInt8]
    }

    public var user: String
    public var domain: String
    private var password: String
    public var workstation: String
    public var channelBinding: ChannelBindingPolicy

    /// - Parameters:
    ///   - user: The user name, without the domain.
    ///   - domain: The domain of the user, for example `"CORP"`.
    ///   - password: The password.
    ///   - workstation: The name of the client machine. Defaults to none.
    ///   - channelBinding: Whether credentials are bound to the TLS channel. Defaults to
    ///     ``ChannelBindingPolicy/automatic``.
    public init(
        user: String,
        domain: String,
        password: String,
        workstation: String = "",
        channelBinding: ChannelBindingPolicy = .automatic
    ) {
        self.user = user
        self.domain = domain
        self.password = password
        self.workstation = workstation
        self.channelBinding = channelBinding
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        let connection = try await exchange.pinConnection(
            with: Identity(
                domain: self.domain.uppercased(),
                user: self.user.lowercased(),
                credentialHash: NTLM.ntowfv2(password: self.password, user: self.user, domain: self.domain)
            )
        )
        if connection.isAuthenticated {
            let response = try await exchange.send(request)
            guard Self.challenge(in: response, peer: peer) != nil else {
                return response
            }
            // The server forgot the connection's authentication. Authenticate again.
        }

        let negotiate = NTLM.negotiateMessage()
        var authenticated = request
        authenticated.headers.replaceOrAdd(
            name: peer.credentialsHeaderName,
            value: "NTLM \(Base64.encode(negotiate))"
        )
        let challengeResponse = try await exchange.send(authenticated)
        guard let token = Self.challenge(in: challengeResponse, peer: peer), !token.isEmpty,
            let bytes = Base64.decode(token)
        else {
            return challengeResponse
        }
        let challenge = try NTLM.ChallengeMessage(bytes)

        let authenticate = NTLM.authenticateMessage(
            negotiate: negotiate,
            challenge: challenge,
            user: self.user,
            domain: self.domain,
            password: self.password,
            workstation: self.workstation,
            targetName: peer.isProxy ? nil : "HTTP/\(peer.host)",
            channelBinding: try TLSChannelBinding.binding(for: connection, peer: peer, policy: self.channelBinding),
            clientChallenge: RandomBytes.generate(8),
            currentTime: NTLM.fileTime(unixTimeInterval: Date().timeIntervalSince1970)
        )
        authenticated.headers.replaceOrAdd(
            name: peer.credentialsHeaderName,
            value: "NTLM \(Base64.encode(authenticate))"
        )
        let response = try await exchange.send(authenticated)
        if response.status != peer.challengeStatus {
            exchange.markConnectionAuthenticated()
        }
        return response
    }

    /// The token of an NTLM challenge, if the response is one.
    private static func challenge(in response: HTTPClientResponse, peer: HTTPClientExchange.Peer) -> String? {
        guard response.status == peer.challengeStatus else { return nil }
        let challenge = response.authenticationChallenges(for: peer).first(where: { $0.matches(scheme: "NTLM") })
        return challenge.map { $0.token68 ?? "" }
    }
}
