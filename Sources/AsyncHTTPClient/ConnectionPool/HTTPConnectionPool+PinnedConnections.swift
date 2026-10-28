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

import NIOCore

extension HTTPConnectionPool {
    /// Keeps track of the connections that are pinned by an `HTTPClientExchange`.
    ///
    /// A pinned connection is leased in the pool's ``StateMachine`` for the whole time it is pinned. Requests
    /// are sent on it without going through the state machine. The connection's release events are intercepted
    /// and only forwarded to the state machine, once the connection is unpinned and idle.
    struct PinnedConnections {
        private struct Entry {
            var connection: Connection
            var isBusy: Bool = false
            var queue: CircularBuffer<Request> = []
            var releaseRequested: Bool = false
            var requestsSent: Int = 0
        }

        enum ExecuteAction {
            case execute(Request, Connection)
            case queue(Request)
            case fail(Request, Error)
        }

        enum ReleaseAction: Equatable {
            /// The connection is not pinned. Forward the event to the state machine.
            case notPinned
            /// The connection is no longer pinned. Forward the release to the state machine.
            case forwardRelease(additionalUses: Int)
            /// Execute the next request that is waiting for the pinned connection.
            case execute(Request, Connection)
            /// The connection is no longer pinned and must not be reused. Close it.
            case close(Connection)
            case none

            static func == (lhs: Self, rhs: Self) -> Bool {
                switch (lhs, rhs) {
                case (.notPinned, .notPinned), (.none, .none):
                    return true
                case (.forwardRelease(let lhs), .forwardRelease(let rhs)):
                    return lhs == rhs
                case (.execute(let lhsRequest, let lhsConnection), .execute(let rhsRequest, let rhsConnection)):
                    return lhsRequest.id == rhsRequest.id && lhsConnection == rhsConnection
                case (.close(let lhs), .close(let rhs)):
                    return lhs == rhs
                default:
                    return false
                }
            }
        }

        /// Whether a connection that was marked as authenticated must be closed when it is unpinned, because
        /// the pool does not know whose identity it was authenticated for.
        private let closeAuthenticatedConnectionsOnRelease: Bool
        private var entries: [Connection.ID: Entry] = [:]
        private var authenticated: Set<Connection.ID> = []
        private var isShuttingDown = false

        init(closeAuthenticatedConnectionsOnRelease: Bool) {
            self.closeAuthenticatedConnectionsOnRelease = closeAuthenticatedConnectionsOnRelease
        }

        var isEmpty: Bool { self.entries.isEmpty }

        /// Pins a connection that the state machine just leased for a ``ConnectionLeaseRequest``.
        mutating func register(_ connection: Connection) {
            assert(self.entries[connection.id] == nil, "Connection \(connection.id) is already pinned")
            self.entries[connection.id] = Entry(connection: connection)
        }

        /// Whether the connection is still pinned, i.e. it has neither been closed nor unpinned.
        func isPinned(_ connectionID: Connection.ID) -> Bool {
            self.entries[connectionID] != nil
        }

        func isAuthenticated(_ connectionID: Connection.ID) -> Bool {
            self.authenticated.contains(connectionID)
        }

        mutating func markAuthenticated(_ connectionID: Connection.ID) {
            if self.entries[connectionID] != nil {
                self.authenticated.insert(connectionID)
            }
        }

        mutating func execute(_ request: Request, on connectionID: Connection.ID) -> ExecuteAction {
            if self.isShuttingDown {
                return .fail(request, HTTPClientError.alreadyShutdown)
            }
            guard var entry = self.entries[connectionID], !entry.releaseRequested else {
                return .fail(request, HTTPClientError.connectionChanged)
            }
            if entry.isBusy {
                entry.queue.append(request)
                self.entries[connectionID] = entry
                return .queue(request)
            }
            entry.isBusy = true
            entry.requestsSent += 1
            self.entries[connectionID] = entry
            return .execute(request, entry.connection)
        }

        /// The connection finished a request and is idle again.
        mutating func connectionReleased(_ connectionID: Connection.ID) -> ReleaseAction {
            guard var entry = self.entries[connectionID] else {
                return .notPinned
            }
            entry.isBusy = false
            if let next = entry.queue.popFirst() {
                entry.isBusy = true
                entry.requestsSent += 1
                self.entries[connectionID] = entry
                return .execute(next, entry.connection)
            }
            if entry.releaseRequested {
                self.entries.removeValue(forKey: connectionID)
                return self.releaseAction(for: entry)
            }
            self.entries[connectionID] = entry
            return .none
        }

        /// The connection was closed. Returns the requests that were waiting for it.
        mutating func connectionClosed(_ connectionID: Connection.ID) -> (requests: [Request], error: Error) {
            self.authenticated.remove(connectionID)
            let error = self.isShuttingDown ? HTTPClientError.alreadyShutdown : HTTPClientError.connectionChanged
            guard let entry = self.entries.removeValue(forKey: connectionID) else {
                return ([], error)
            }
            return (Array(entry.queue), error)
        }

        /// The exchange no longer needs the connection.
        mutating func unpin(_ connectionID: Connection.ID) -> ReleaseAction {
            guard var entry = self.entries[connectionID] else {
                return .none
            }
            if entry.isBusy {
                // The connection is handed back, once the running request is finished.
                entry.releaseRequested = true
                self.entries[connectionID] = entry
                return .none
            }
            self.entries.removeValue(forKey: connectionID)
            return self.releaseAction(for: entry)
        }

        /// Removes a request that is waiting for a pinned connection.
        mutating func cancelQueuedRequest(_ requestID: Request.ID) -> Request? {
            for (connectionID, var entry) in self.entries {
                if let index = entry.queue.firstIndex(where: { $0.id == requestID }) {
                    let request = entry.queue.remove(at: index)
                    self.entries[connectionID] = entry
                    return request
                }
            }
            return nil
        }

        mutating func shutdown() {
            self.isShuttingDown = true
        }

        private func releaseAction(for entry: Entry) -> ReleaseAction {
            assert(entry.queue.isEmpty)
            if self.closeAuthenticatedConnectionsOnRelease && self.authenticated.contains(entry.connection.id) {
                return .close(entry.connection)
            }
            // The lease itself already counted as one use.
            return .forwardRelease(additionalUses: max(entry.requestsSent - 1, 0))
        }
    }
}
