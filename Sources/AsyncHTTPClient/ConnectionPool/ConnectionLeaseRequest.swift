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

/// A connection that was leased from a connection pool by an `HTTPClientExchange`.
///
/// While a connection is pinned, the pool's state machine considers it leased. Requests are sent on it
/// with ``HTTPConnectionPool/executeOnPinnedConnection(_:connectionID:)`` and it is handed back to the pool
/// with ``HTTPConnectionPool/unpin(_:)``.
struct PinnedConnectionHandle: Sendable {
    let pool: HTTPConnectionPool
    let connectionID: HTTPConnectionPool.Connection.ID
    let tlsInfo: HTTPClient.TLSInfo?
    let isAuthenticated: Bool
}

/// A request for a whole connection instead of a request that is executed on a connection.
///
/// It is scheduled like any other request. Once the pool's state machine decides to execute it on a
/// connection, the pool pins the connection and succeeds the lease instead of executing anything.
final class ConnectionLeaseRequest: HTTPSchedulableRequest {
    private enum State {
        case pending(HTTPRequestScheduler?)
        case done
    }

    let poolKey: ConnectionPool.Key
    let tlsConfiguration: TLSConfiguration?
    let logger: Logger
    let connectionDeadline: NIODeadline
    let preferredEventLoop: EventLoop
    var requiredEventLoop: EventLoop? { nil }

    private let promise: EventLoopPromise<PinnedConnectionHandle>
    private let state = NIOLockedValueBox(State.pending(nil))

    init(
        poolKey: ConnectionPool.Key,
        tlsConfiguration: TLSConfiguration?,
        logger: Logger,
        connectionDeadline: NIODeadline,
        preferredEventLoop: EventLoop
    ) {
        self.poolKey = poolKey
        self.tlsConfiguration = tlsConfiguration
        self.logger = logger
        self.connectionDeadline = connectionDeadline
        self.preferredEventLoop = preferredEventLoop
        self.promise = preferredEventLoop.makePromise()
    }

    var connectionLease: ConnectionLeaseRequest? { self }

    var futureResult: EventLoopFuture<PinnedConnectionHandle> {
        self.promise.futureResult
    }

    func requestWasQueued(_ scheduler: HTTPRequestScheduler) {
        self.state.withLockedValue { state in
            if case .pending = state {
                state = .pending(scheduler)
            }
        }
    }

    func fail(_ error: Error) {
        let shouldFail = self.state.withLockedValue { state -> Bool in
            guard case .pending = state else { return false }
            state = .done
            return true
        }
        if shouldFail {
            self.promise.fail(error)
        }
    }

    /// Cancels the lease, if it has not been granted yet.
    func cancel(with error: Error) {
        let scheduler = self.state.withLockedValue { state -> HTTPRequestScheduler?? in
            guard case .pending(let scheduler) = state else { return .none }
            state = .done
            return .some(scheduler)
        }
        guard case .some(let scheduler) = scheduler else { return }
        self.promise.fail(error)
        scheduler?.cancelRequest(self)
    }

    /// Grants the lease. Returns `false` if the lease has already failed or was cancelled, in which case
    /// the caller must hand the connection back to the pool.
    func succeed(_ handle: PinnedConnectionHandle) -> Bool {
        let shouldSucceed = self.state.withLockedValue { state -> Bool in
            guard case .pending = state else { return false }
            state = .done
            return true
        }
        if shouldSucceed {
            self.promise.succeed(handle)
        }
        return shouldSucceed
    }

    // MARK: HTTPExecutableRequest

    // A lease is never written to a connection. The pool intercepts it before that can happen.
    private static func neverExecuted() -> Never { preconditionFailure("A connection lease is never executed") }
    var requestHead: HTTPRequestHead { Self.neverExecuted() }
    var requestFramingMetadata: RequestFramingMetadata { Self.neverExecuted() }
    var requestOptions: RequestOptions { Self.neverExecuted() }
    func willExecuteRequest(_: HTTPRequestExecutor) { Self.neverExecuted() }
    func requestHeadSent() { Self.neverExecuted() }
    func resumeRequestBodyStream() { Self.neverExecuted() }
    func pauseRequestBodyStream() { Self.neverExecuted() }
    func requestBodyStreamSent() { Self.neverExecuted() }
    func receiveResponseHead(_: HTTPResponseHead) { Self.neverExecuted() }
    func receiveResponseBodyParts(_: CircularBuffer<ByteBuffer>) { Self.neverExecuted() }
    func receiveResponseEnd(_: CircularBuffer<ByteBuffer>?, trailers: HTTPHeaders?) { Self.neverExecuted() }
}
