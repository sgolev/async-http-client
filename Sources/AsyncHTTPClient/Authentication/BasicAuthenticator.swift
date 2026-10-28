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

/// Authenticates with the `Basic` scheme (RFC 7617).
///
/// ```swift
/// var request = HTTPClientRequest(url: "https://example.com/")
/// request.authenticator = BasicAuthenticator(username: "alice", password: "s3cret")
/// ```
///
/// The credentials are UTF-8 encoded.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct BasicAuthenticator: HTTPClientAuthenticator {
    /// The base64 encoded `user-id:password`.
    public var encodedCredentials: String

    /// Whether credentials are sent with the first request. If `false`, credentials are only sent after the peer
    /// challenged the client with the `Basic` scheme. Defaults to `true`.
    public var preemptive: Bool

    public init(username: String, password: String, preemptive: Bool = true) {
        self.init(
            encodedCredentials: encodeBasicAuthCredentials(username: username, password: password),
            preemptive: preemptive
        )
    }

    /// - Parameters:
    ///   - encodedCredentials: The base64 encoded `user-id:password`.
    ///   - preemptive: Whether credentials are sent with the first request.
    public init(encodedCredentials: String, preemptive: Bool = true) {
        self.encodedCredentials = encodedCredentials
        self.preemptive = preemptive
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        let peer = exchange.peer
        var authenticated = request
        authenticated.headers.replaceOrAdd(name: peer.credentialsHeaderName, value: "Basic \(self.encodedCredentials)")

        if self.preemptive {
            return try await exchange.send(authenticated)
        }

        let response = try await exchange.send(request)
        guard response.status == peer.challengeStatus,
            response.authenticationChallenges(for: peer).contains(where: { $0.matches(scheme: "Basic") })
        else {
            return response
        }
        return try await exchange.send(authenticated)
    }
}
