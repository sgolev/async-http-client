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

import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1

/// The exchange that a proxy authenticator uses to open a tunnel through an HTTP proxy.
///
/// Every request is a `CONNECT` request to the same authority. Each request is sent on a plain text connection to
/// the proxy, that is reused as long as the proxy keeps it open. Once the proxy accepts a request, the connection
/// is a tunnel and the exchange is done.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
final class ProxyConnectExchange: HTTPClientExchangeBacking {
    private struct ProxyConnection {
        var channel: Channel
        var handler: NIOLoopBound<HTTP1ProxyConnectRequestHandler>
        var isReusable = true
    }

    private struct State {
        var connection: ProxyConnection?
        var isPinned = false
        /// A pinned connection was closed. Requests fail with `connectionChanged`, until a connection is pinned
        /// again or released.
        var pinnedConnectionLost = false
        var tunnel: Channel?
        var openChannels: [Channel] = []
    }

    let peer: HTTPClientExchange.Peer

    /// The authority the tunnel is opened to.
    let authority: String
    private let targetHost: String
    private let targetPort: Int
    /// Opens a connection to the proxy, with the HTTP codec and an ``HTTP1ProxyConnectRequestHandler`` installed.
    private let openChannel: @Sendable () -> EventLoopFuture<(Channel, NIOLoopBound<HTTP1ProxyConnectRequestHandler>)>
    private let state = NIOLockedValueBox(State())

    init(
        proxyHost: String,
        proxyPort: Int,
        target: ConnectionTarget,
        openChannel: @escaping @Sendable () -> EventLoopFuture<(Channel, NIOLoopBound<HTTP1ProxyConnectRequestHandler>)>
    ) {
        self.peer = HTTPClientExchange.Peer(kind: .proxy, scheme: "http", host: proxyHost, port: proxyPort)
        (self.targetHost, self.targetPort) = target.proxyConnectTarget
        self.authority = "\(self.targetHost):\(self.targetPort)"
        self.openChannel = openChannel
    }

    /// The request that is passed to the proxy authenticator.
    func makeInitialRequest(connectHeaders: HTTPHeaders) -> HTTPClientRequest {
        var request = HTTPClientRequest(url: self.authority)
        request.method = .CONNECT
        request.headers = HTTP1ProxyConnectRequestHandler.removingReservedHeaders(from: connectHeaders)
        return request
    }

    func send(_ request: HTTPClientRequest) async throws -> HTTPClientResponse {
        guard request.method == .CONNECT, request.url == self.authority, request.body == nil else {
            throw HTTPClientError.invalidExchangeUse
        }
        let connection = try await self.connection()

        let head = HTTP1ProxyConnectRequestHandler.makeConnectHead(
            targetHost: self.targetHost,
            targetPort: self.targetPort,
            headers: request.headers
        )
        let response = try await connection.channel.eventLoop.flatSubmit {
            connection.handler.value.sendConnect(head)
        }.get()

        self.state.withLockedValue { state in
            if (200..<300).contains(response.head.status.code) {
                state.tunnel = connection.channel
            } else if !response.connectionReusable {
                state.connection?.isReusable = false
            }
        }

        return HTTPClientResponse(
            version: response.head.version,
            status: response.head.status,
            headers: response.head.headers,
            body: response.body.map { .bytes($0) } ?? HTTPClientResponse.Body()
        )
    }

    func pinConnection(identity: ConnectionPool.PinIdentity?) async throws -> HTTPClientConnection {
        // A tunnel is opened exactly once per connection. Identities are therefore irrelevant.
        self.state.withLockedValue { state in
            if state.pinnedConnectionLost {
                state.connection = nil
                state.pinnedConnectionLost = false
            }
            state.isPinned = false
        }
        _ = try await self.connection()
        self.state.withLockedValue { $0.isPinned = true }
        return HTTPClientConnection(httpVersion: .http1_1, tlsInfo: nil, isAuthenticated: false)
    }

    func releaseConnection() async {
        self.state.withLockedValue { state in
            state.isPinned = false
            state.pinnedConnectionLost = false
        }
    }

    func markConnectionAuthenticated() {
        // Every connection to the proxy is only used to open a single tunnel.
    }

    /// Returns the tunnel, if the proxy accepted a request, and closes all other connections to the proxy.
    func finish() -> Channel? {
        let (tunnel, channels) = self.state.withLockedValue { state in
            defer {
                state.openChannels.removeAll()
                state.connection = nil
            }
            return (state.tunnel, state.openChannels)
        }
        for channel in channels where channel !== tunnel {
            channel.close(promise: nil)
        }
        return tunnel
    }

    private func connection() async throws -> ProxyConnection {
        let existing = try self.state.withLockedValue { state -> ProxyConnection? in
            if state.tunnel != nil {
                // The tunnel is open. There is nothing left to authenticate.
                throw HTTPClientError.invalidExchangeUse
            }
            if let connection = state.connection, connection.isReusable, connection.channel.isActive {
                return connection
            }
            if state.isPinned {
                state.pinnedConnectionLost = true
            }
            if state.pinnedConnectionLost {
                throw HTTPClientError.connectionChanged
            }
            return nil
        }
        if let existing {
            return existing
        }

        let (channel, handler) = try await self.openChannel().get()
        let connection = ProxyConnection(channel: channel, handler: handler)
        self.state.withLockedValue { state in
            state.connection = connection
            state.openChannels.append(channel)
        }
        return connection
    }
}
