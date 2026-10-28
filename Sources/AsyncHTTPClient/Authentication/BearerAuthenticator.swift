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

import NIOHTTP1

/// Authenticates with the `Bearer` scheme (RFC 6750).
///
/// The authenticator can refresh tokens: if the peer rejects a token, the token provider is asked for a new one and
/// the request is sent once more.
///
/// ```swift
/// let authenticator = BearerAuthenticator { rejectedToken in
///     if let rejectedToken {
///         return try await tokenStore.refresh(replacing: rejectedToken)
///     }
///     return try await tokenStore.currentToken()
/// }
/// ```
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct BearerAuthenticator: HTTPClientAuthenticator {
    private let tokenProvider: @Sendable (_ rejectedToken: String?) async throws -> String?

    /// Uses a fixed token.
    public init(token: String) {
        self.tokenProvider = { rejectedToken in
            rejectedToken == nil ? token : nil
        }
    }

    /// Uses tokens from a provider.
    ///
    /// - Parameter tokenProvider: Called with `nil` to get the token for a request. If the peer rejects a token, it
    ///   is called with the rejected token to get a new one. Returning `nil` sends the request without a token, or
    ///   gives up and returns the rejecting response.
    public init(tokenProvider: @escaping @Sendable (_ rejectedToken: String?) async throws -> String?) {
        self.tokenProvider = tokenProvider
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        guard let token = try await self.tokenProvider(nil) else {
            return try await exchange.send(request)
        }

        var authenticated = request
        authenticated.headers.replaceOrAdd(name: peer.credentialsHeaderName, value: "Bearer \(token)")
        let response = try await exchange.send(authenticated)

        guard response.status == peer.challengeStatus,
            let challenge = response.authenticationChallenges(for: peer).first(where: { $0.matches(scheme: "Bearer") }),
            Self.isTokenRejection(challenge),
            let refreshedToken = try await self.tokenProvider(token)
        else {
            return response
        }

        authenticated.headers.replaceOrAdd(name: peer.credentialsHeaderName, value: "Bearer \(refreshedToken)")
        return try await exchange.send(authenticated)
    }

    /// RFC 6750, section 3.1: the token is expired, revoked or malformed. A missing error code is treated the same
    /// way, since many servers omit it. Other error codes (`invalid_request`, `insufficient_scope`) can't be fixed
    /// with a new token.
    private static func isTokenRejection(_ challenge: HTTPAuthenticationChallenge) -> Bool {
        switch challenge[parameter: "error"] {
        case .none, "invalid_token":
            return true
        default:
            return false
        }
    }
}
