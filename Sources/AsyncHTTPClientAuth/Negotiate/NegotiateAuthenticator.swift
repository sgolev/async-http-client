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

/// A security context that produces the tokens of a `Negotiate` exchange, for example a GSS-API context with the
/// SPNEGO mechanism.
public protocol NegotiateSecurityContext: AnyObject, Sendable {
    /// Processes a token from the server and returns the next token for the server.
    ///
    /// - Parameter token: The server's token, `nil` for the first call.
    /// - Returns: The token to send, if any, and whether the context is established.
    func step(_ token: [UInt8]?) async throws -> (token: [UInt8]?, isComplete: Bool)
}

/// Creates the security contexts of a ``NegotiateAuthenticator``.
public protocol NegotiateSecurityContextProvider: Sendable {
    /// Identifies the credentials that contexts use, for example the Kerberos principal. Connections authenticated
    /// with the same credentials are shared.
    func credentialIdentity() async throws -> String

    /// Creates a context to authenticate with a service.
    ///
    /// - Parameters:
    ///   - servicePrincipalName: The host based service name, for example `"HTTP@www.example.com"`.
    ///   - channelBinding: The application data of the channel bindings, if any.
    func makeContext(
        servicePrincipalName: String,
        channelBinding: [UInt8]?
    ) async throws
        -> any NegotiateSecurityContext
}

/// Authenticates with the `Negotiate` scheme (RFC 4559), usually with Kerberos through SPNEGO.
///
/// ```swift
/// let negotiate = NegotiateAuthenticator(mutualAuthentication: .required, channelBinding: .automatic)
/// var configuration = HTTPClient.Configuration()
/// configuration.authenticator = negotiate
/// configuration.proxy = .server(host: "proxy.corp.example.com", port: 3128, authenticator: negotiate)
/// ```
///
/// The authenticator pins a connection for the credentials, so that the legs of a multi-leg exchange are sent on the
/// same connection, and marks it as authenticated. By default, the tokens are created with the system's GSS-API: on
/// Apple platforms with GSS.framework, on Linux with MIT Kerberos, if the `GSSAPI` package trait is enabled.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct NegotiateAuthenticator: HTTPClientAuthenticator {
    public enum MutualAuthentication: Sendable, Hashable {
        /// The server must authenticate itself with a final token.
        case required
        /// A final token from the server is verified, if there is one.
        case optional
        /// Final tokens from the server are ignored.
        case disabled
    }

    public var mutualAuthentication: MutualAuthentication
    public var channelBinding: ChannelBindingPolicy
    private let contextProvider: any NegotiateSecurityContextProvider

    /// The maximum number of legs before the authenticator gives up.
    static let maximumLegs = 3

    /// Uses the system's GSS-API with the default credentials, for example the Kerberos ticket cache.
    public init(
        mutualAuthentication: MutualAuthentication = .required,
        channelBinding: ChannelBindingPolicy = .automatic
    ) {
        self.init(
            mutualAuthentication: mutualAuthentication,
            channelBinding: channelBinding,
            contextProvider: GSSAPISecurityContextProvider()
        )
    }

    public init(
        mutualAuthentication: MutualAuthentication = .required,
        channelBinding: ChannelBindingPolicy = .automatic,
        contextProvider: some NegotiateSecurityContextProvider
    ) {
        self.mutualAuthentication = mutualAuthentication
        self.channelBinding = channelBinding
        self.contextProvider = contextProvider
    }

    private struct Identity: Hashable, Sendable {
        var principal: String
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        let principal = try await self.contextProvider.credentialIdentity()
        let connection = try await exchange.pinConnection(with: Identity(principal: principal))

        var response = try await exchange.send(request)
        if connection.isAuthenticated && response.status != peer.challengeStatus {
            return response
        }

        var context: (any NegotiateSecurityContext)?
        var isComplete = false
        for _ in 0..<Self.maximumLegs {
            guard response.status == peer.challengeStatus, let challenge = Self.challenge(in: response, peer: peer)
            else {
                break
            }
            if context == nil {
                context = try await self.contextProvider.makeContext(
                    servicePrincipalName: "HTTP@\(peer.host)",
                    channelBinding: try TLSChannelBinding.binding(
                        for: connection,
                        peer: peer,
                        policy: self.channelBinding
                    )
                )
            } else if challenge.isEmpty {
                // The server rejected the context.
                break
            }
            let step = try await context!.step(challenge.isEmpty ? nil : challenge)
            isComplete = step.isComplete
            guard let token = step.token else { break }

            var authenticated = request
            authenticated.headers.replaceOrAdd(
                name: peer.credentialsHeaderName,
                value: "Negotiate \(Base64.encode(token))"
            )
            response = try await exchange.send(authenticated)
        }

        guard let context, response.status != peer.challengeStatus else {
            return response
        }

        // The final response may carry the server's token for mutual authentication (RFC 4559, section 5).
        let finalToken = Self.challenge(in: response, peer: peer).flatMap { $0.isEmpty ? nil : $0 }
        switch self.mutualAuthentication {
        case .required, .optional:
            if let finalToken {
                isComplete = try await context.step(finalToken).isComplete
            }
            if self.mutualAuthentication == .required && !isComplete {
                throw HTTPClientAuthenticationError.mutualAuthenticationFailed
            }
        case .disabled:
            break
        }

        exchange.markConnectionAuthenticated()
        return response
    }

    /// The decoded token of a `Negotiate` challenge, empty for a challenge without a token.
    private static func challenge(in response: HTTPClientResponse, peer: HTTPClientExchange.Peer) -> [UInt8]? {
        guard
            let challenge = response.authenticationChallenges(for: peer).first(where: {
                $0.matches(scheme: "Negotiate")
            })
        else {
            return nil
        }
        guard let token68 = challenge.token68 else {
            return []
        }
        return Base64.decode(token68)
    }
}
