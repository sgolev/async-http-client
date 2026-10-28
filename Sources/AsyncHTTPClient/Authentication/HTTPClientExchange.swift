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

/// Sends requests to a single peer on behalf of an ``HTTPClientAuthenticator``.
///
/// The exchange is only valid during the call to ``HTTPClientAuthenticator/authenticate(_:exchange:)`` that it
/// was passed to. Calls on one exchange must not overlap.
///
/// Sending a new request, releasing the connection or returning from the authenticator discards whatever is left
/// of the bodies of earlier responses, except for the response that the authenticator returns. If the remainder of
/// a body is small, it is read and dropped, so that the connection can be reused. Otherwise the connection is
/// closed.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct HTTPClientExchange: Sendable {
    /// The peer that requests are sent to and that is authenticated.
    public struct Peer: Sendable, Hashable {
        public enum Kind: Sendable, Hashable {
            /// The origin server.
            case origin
            /// An HTTP proxy. Requests sent to a proxy are `CONNECT` requests.
            case proxy
        }

        public var kind: Kind
        /// The URL scheme used to talk to the peer, for example `"https"`.
        public var scheme: String
        public var host: String
        public var port: Int

        public init(kind: Kind, scheme: String, host: String, port: Int) {
            self.kind = kind
            self.scheme = scheme
            self.host = host
            self.port = port
        }

        public var isProxy: Bool {
            self.kind == .proxy
        }

        /// The status of a response that challenges the client to authenticate: 401 or 407.
        public var challengeStatus: HTTPResponseStatus {
            self.isProxy ? .proxyAuthenticationRequired : .unauthorized
        }

        /// The header that contains challenges: `WWW-Authenticate` or `Proxy-Authenticate`.
        public var challengeHeaderName: String {
            self.isProxy ? "Proxy-Authenticate" : "WWW-Authenticate"
        }

        /// The header that carries credentials: `Authorization` or `Proxy-Authorization`.
        public var credentialsHeaderName: String {
            self.isProxy ? "Proxy-Authorization" : "Authorization"
        }

        /// The header with information about a successful authentication: `Authentication-Info` or
        /// `Proxy-Authentication-Info`.
        public var authenticationInfoHeaderName: String {
            self.isProxy ? "Proxy-Authentication-Info" : "Authentication-Info"
        }
    }

    let backing: any HTTPClientExchangeBacking

    init(backing: any HTTPClientExchangeBacking) {
        self.backing = backing
    }

    /// The peer that requests are sent to.
    public var peer: Peer {
        self.backing.peer
    }

    /// Sends a request on the exchange's connection.
    ///
    /// If a connection is pinned, the request is sent on it. Otherwise the request is sent on any suitable
    /// connection, opening a new one if needed.
    ///
    /// - Throws: ``HTTPClientError/connectionChanged`` without sending anything, if the pinned connection was
    ///   closed. ``HTTPClientError/requestBodyNotReplayable``, if the request's body can only be sent once and
    ///   another such body was already sent on this exchange.
    public func send(_ request: HTTPClientRequest) async throws -> HTTPClientResponse {
        try await self.backing.send(request)
    }

    /// Reserves a connection for this exchange, opening one if needed.
    ///
    /// Subsequent calls return the same connection, unless it was closed or released. Use this, if the scheme
    /// authenticates connections rather than requests (like NTLM), or if you need to inspect the connection before
    /// you send a request (like for TLS channel binding).
    ///
    /// A pinned connection is never handed to another exchange while it is pinned. Pinned connections always use
    /// HTTP/1.1.
    ///
    /// Without an identity, a connection that was marked authenticated with ``markConnectionAuthenticated()`` is
    /// closed when it is released. Use ``pinConnection(with:)`` to keep authenticated connections around.
    public func pinConnection() async throws -> HTTPClientConnection {
        try await self.backing.pinConnection(identity: nil)
    }

    /// Reserves a connection for this exchange, that is only ever shared with exchanges that pin a connection with
    /// the same identity.
    ///
    /// Use an identity that identifies the credentials the connection is authenticated with, for example the user
    /// name. A connection that was marked authenticated with ``markConnectionAuthenticated()`` is returned to the
    /// pool when it is released. The next exchange that pins a connection with the same identity may get it, and
    /// sees ``HTTPClientConnection/isAuthenticated`` set.
    public func pinConnection(with identity: some Hashable & Sendable) async throws -> HTTPClientConnection {
        try await self.backing.pinConnection(identity: ConnectionPool.PinIdentity(identity))
    }

    /// Discards any pending response and hands the pinned connection back to the pool.
    ///
    /// Call this before you send a request that does not need the pinned connection, for example a long running one.
    public func releaseConnection() async {
        await self.backing.releaseConnection()
    }

    /// Records that the pinned connection has completed authentication.
    ///
    /// The next exchange that pins this connection sees ``HTTPClientConnection/isAuthenticated`` set and can skip
    /// sending credentials.
    public func markConnectionAuthenticated() {
        self.backing.markConnectionAuthenticated()
    }
}

/// A connection that was pinned by an ``HTTPClientExchange``.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct HTTPClientConnection: Sendable {
    /// The HTTP version of the connection.
    public var httpVersion: HTTPVersion
    /// Information about the TLS session, if the connection is secured by TLS.
    public var tlsInfo: HTTPClient.TLSInfo?
    /// Whether ``HTTPClientExchange/markConnectionAuthenticated()`` was called for this connection before.
    public var isAuthenticated: Bool

    public init(httpVersion: HTTPVersion, tlsInfo: HTTPClient.TLSInfo?, isAuthenticated: Bool) {
        self.httpVersion = httpVersion
        self.tlsInfo = tlsInfo
        self.isAuthenticated = isAuthenticated
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
protocol HTTPClientExchangeBacking: AnyObject, Sendable {
    var peer: HTTPClientExchange.Peer { get }
    func send(_ request: HTTPClientRequest) async throws -> HTTPClientResponse
    func pinConnection(identity: ConnectionPool.PinIdentity?) async throws -> HTTPClientConnection
    func releaseConnection() async
    func markConnectionAuthenticated()
}
