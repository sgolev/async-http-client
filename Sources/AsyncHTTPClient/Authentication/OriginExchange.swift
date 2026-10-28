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

import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOSSL

#if canImport(FoundationEssentials)
import struct FoundationEssentials.URL
#else
import struct Foundation.URL
#endif

/// The exchange that an authenticator uses to talk to the origin server of a request.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
final class OriginExchange: HTTPClientExchangeBacking {
    /// The remainder of a response body that is read and dropped to keep a connection alive. Larger bodies cause
    /// the connection to be closed instead.
    static let maximumDiscardedBodyBytes = 1024 * 1024

    private struct Pin {
        var handle: PinnedConnectionHandle
        var identity: ConnectionPool.PinIdentity?
    }

    private struct State {
        var pin: Pin?
        var legs: [HTTPClientRequestResponse] = []
        /// Responses whose bodies might still be streaming.
        var outstanding: [(transaction: Transaction, expectedContentLength: Int?)] = []
        var sentSingleUseBody = false
        var isFinished = false
    }

    let peer: HTTPClientExchange.Peer

    private let client: HTTPClient
    private let poolKey: ConnectionPool.Key
    private let tlsConfiguration: TLSConfiguration?
    private let deadline: NIODeadline
    private let logger: Logger
    private let state = NIOLockedValueBox(State())

    init(client: HTTPClient, prepared: HTTPClientRequest.Prepared, deadline: NIODeadline, logger: Logger) {
        self.client = client
        self.poolKey = prepared.poolKey
        self.tlsConfiguration = prepared.tlsConfiguration
        self.deadline = deadline
        self.logger = logger
        self.peer = HTTPClientExchange.Peer(
            kind: .origin,
            scheme: prepared.poolKey.scheme.rawValue,
            host: prepared.url.host ?? "",
            port: prepared.url.port ?? prepared.poolKey.scheme.defaultPort
        )
    }

    func send(_ request: HTTPClientRequest) async throws -> HTTPClientResponse {
        let prepared = try HTTPClientRequest.Prepared(
            request,
            dnsOverride: self.client.configuration.dnsOverride,
            localAddress: self.client.configuration.localAddress,
            tracing: self.client.configuration.tracing
        )
        guard prepared.poolKey == self.poolKey else {
            // An exchange only talks to a single peer.
            throw HTTPClientError.invalidExchangeUse
        }

        let (pin, outstanding) = try self.state.withLockedValue { state in
            guard !state.isFinished else {
                throw HTTPClientError.invalidExchangeUse
            }
            if !request.body.canBeConsumedMultipleTimes {
                guard !state.sentSingleUseBody else {
                    throw HTTPClientError.requestBodyNotReplayable
                }
                state.sentSingleUseBody = true
            }
            defer { state.outstanding.removeAll() }
            return (state.pin?.handle, state.outstanding)
        }
        Self.discard(outstanding)

        let submit: ((Transaction) -> Void)? = pin.map { handle in
            { transaction in
                handle.pool.executeOnPinnedConnection(transaction, connectionID: handle.connectionID)
            }
        }
        let response = try await self.client.executeCancellable(
            prepared,
            deadline: self.deadline,
            logger: self.logger,
            submit: submit
        )

        self.state.withLockedValue { state in
            state.legs.append(
                HTTPClientRequestResponse(
                    request: request,
                    responseHead: HTTPResponseHead(
                        version: response.version,
                        status: response.status,
                        headers: response.headers
                    )
                )
            )
            if let transaction = response.body.transaction {
                state.outstanding.append(transaction)
            }
        }
        return response
    }

    func pinConnection(identity: ConnectionPool.PinIdentity?) async throws -> HTTPClientConnection {
        let current = try self.state.withLockedValue { state in
            guard !state.isFinished else {
                throw HTTPClientError.invalidExchangeUse
            }
            return state.pin
        }

        if let current, current.identity == identity {
            let handle = current.handle
            let (isPinned, isAuthenticated) = handle.pool.pinnedConnectionState(handle.connectionID)
            if isPinned {
                return HTTPClientConnection(
                    httpVersion: .http1_1,
                    tlsInfo: handle.tlsInfo,
                    isAuthenticated: isAuthenticated
                )
            }
        }

        // Either nothing is pinned, the identity changed or the pinned connection is gone.
        await self.releaseConnection()
        let handle = try await self.lease(identity: identity)
        self.state.withLockedValue { state in
            state.pin = Pin(handle: handle, identity: identity)
        }
        return HTTPClientConnection(
            httpVersion: .http1_1,
            tlsInfo: handle.tlsInfo,
            isAuthenticated: handle.isAuthenticated
        )
    }

    func releaseConnection() async {
        let (pin, outstanding) = self.state.withLockedValue { state in
            defer {
                state.pin = nil
                state.outstanding.removeAll()
            }
            return (state.pin, state.outstanding)
        }
        Self.discard(outstanding)
        if let handle = pin?.handle {
            handle.pool.unpin(handle.connectionID)
        }
    }

    func markConnectionAuthenticated() {
        guard let handle = self.state.withLockedValue({ $0.pin?.handle }) else {
            assertionFailure("markConnectionAuthenticated() requires a pinned connection")
            return
        }
        handle.pool.markPinnedConnectionAuthenticated(handle.connectionID)
    }

    /// Ends the exchange once the authenticator returned.
    ///
    /// Discards the bodies of all responses, except the one that is returned to the user, and hands a pinned
    /// connection back to the pool. If the returned response is still streaming on it, the pool takes the connection
    /// back once the response is finished.
    ///
    /// - Returns: All requests that were sent on the exchange and their responses.
    @discardableResult
    func finish(returning response: HTTPClientResponse?) -> [HTTPClientRequestResponse] {
        let returnedTransaction = response?.body.transaction?.0
        let (pin, outstanding, legs) = self.state.withLockedValue { state in
            defer {
                state.isFinished = true
                state.pin = nil
                state.outstanding.removeAll()
            }
            return (state.pin, state.outstanding, state.legs)
        }
        Self.discard(outstanding.filter { $0.transaction !== returnedTransaction })
        if let handle = pin?.handle {
            handle.pool.unpin(handle.connectionID)
        }
        return legs
    }

    private static func discard(_ outstanding: [(transaction: Transaction, expectedContentLength: Int?)]) {
        for (transaction, expectedContentLength) in outstanding {
            transaction.discardResponseBody(
                maxBytes: Self.maximumDiscardedBodyBytes,
                expectedContentLength: expectedContentLength
            )
        }
    }

    private func lease(identity: ConnectionPool.PinIdentity?) async throws -> PinnedConnectionHandle {
        let eventLoop = self.client.eventLoopGroup.any()
        let lease = ConnectionLeaseRequest(
            poolKey: self.poolKey.with(pinning: identity.map { .identity($0) } ?? .anonymous),
            tlsConfiguration: self.tlsConfiguration,
            logger: self.logger,
            connectionDeadline: .now() + self.client.configuration.timeout.connectionCreationTimeout,
            preferredEventLoop: eventLoop
        )
        let deadlineTask = eventLoop.scheduleTask(deadline: self.deadline) {
            lease.cancel(with: HTTPClientError.deadlineExceeded)
        }
        defer { deadlineTask.cancel() }

        return try await withTaskCancellationHandler {
            self.client.poolManager.executeRequest(lease)
            return try await lease.futureResult.get()
        } onCancel: {
            lease.cancel(with: CancellationError())
        }
    }
}
