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

/// Authenticates requests on behalf of the ``HTTPClient``.
///
/// An authenticator is handed every request before it is sent, together with an ``HTTPClientExchange``.
/// It may modify the request, send it any number of times with ``HTTPClientExchange/send(_:)``, and
/// returns the response that the ``HTTPClient`` should return to the user.
///
/// A scheme that answers a challenge looks like this:
///
/// ```swift
/// struct TokenAuthenticator: HTTPClientAuthenticator {
///     func authenticate(
///         _ request: HTTPClientRequest,
///         exchange: HTTPClientExchange
///     ) async throws -> HTTPClientResponse {
///         let response = try await exchange.send(request)
///         guard response.status == exchange.peer.challengeStatus,
///             let challenge = response.authenticationChallenges(for: exchange.peer)
///                 .first(where: { $0.scheme == "Token" })
///         else {
///             return response
///         }
///         var retry = request
///         retry.headers.replaceOrAdd(
///             name: exchange.peer.credentialsHeaderName,
///             value: "Token \(makeToken(for: challenge))"
///         )
///         return try await exchange.send(retry)
///     }
/// }
/// ```
///
/// Connection-based schemes, like NTLM or Negotiate, use ``HTTPClientExchange/pinConnection(with:)`` to
/// send all legs of a handshake on the same connection.
///
/// Authenticators are configured with ``HTTPClient/Configuration/authenticator`` for all requests of a client,
/// with ``HTTPClientRequest/authenticator`` for a single request, or with
/// ``HTTPClient/Configuration/Proxy/authenticator`` for an HTTP proxy.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public protocol HTTPClientAuthenticator: Sendable {
    /// Authenticates the request.
    ///
    /// - Parameters:
    ///   - request: The request that the user wants to send.
    ///   - exchange: Sends requests to the peer that needs to be authenticated. It is only valid until this method
    ///     returns.
    /// - Returns: The response to return to the user. This is usually the response to the last request that was
    ///   sent with the exchange.
    func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse
}
