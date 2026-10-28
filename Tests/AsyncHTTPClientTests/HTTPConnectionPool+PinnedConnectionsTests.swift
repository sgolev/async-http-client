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
import NIOEmbedded
import XCTest

@testable import AsyncHTTPClient

final class HTTPConnectionPool_PinnedConnectionsTests: XCTestCase {
    private typealias Pins = HTTPConnectionPool.PinnedConnections

    private let eventLoop = EmbeddedEventLoop()

    private func makeRequest() -> HTTPConnectionPool.Request {
        HTTPConnectionPool.Request(MockHTTPScheduableRequest(eventLoop: self.eventLoop))
    }

    private func makeConnection(_ id: Int) -> HTTPConnectionPool.Connection {
        .__testOnly_connection(id: id, eventLoop: self.eventLoop)
    }

    func testRequestsRunOneAfterAnother() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        let connection = self.makeConnection(1)
        pins.register(connection)
        XCTAssertTrue(pins.isPinned(1))

        let first = self.makeRequest()
        let second = self.makeRequest()
        guard case .execute(let executed, connection) = pins.execute(first, on: 1) else {
            return XCTFail("Expected the first request to be executed")
        }
        XCTAssertEqual(executed.id, first.id)
        guard case .queue = pins.execute(second, on: 1) else {
            return XCTFail("Expected the second request to wait")
        }

        XCTAssertEqual(pins.connectionReleased(1), .execute(second, connection))
        XCTAssertEqual(pins.connectionReleased(1), .none)
        XCTAssertTrue(pins.isPinned(1))
    }

    func testUnpinWhileBusyForwardsReleaseWithAllUses() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        pins.register(self.makeConnection(1))

        for _ in 0..<3 {
            guard case .execute = pins.execute(self.makeRequest(), on: 1) else {
                return XCTFail("Expected the request to be executed")
            }
            XCTAssertEqual(pins.connectionReleased(1), .none)
        }
        guard case .execute = pins.execute(self.makeRequest(), on: 1) else {
            return XCTFail("Expected the request to be executed")
        }
        XCTAssertEqual(pins.unpin(1), .none)
        XCTAssertEqual(pins.connectionReleased(1), .forwardRelease(additionalUses: 3))
        XCTAssertFalse(pins.isPinned(1))
        // Further events are for the state machine again.
        XCTAssertEqual(pins.connectionReleased(1), .notPinned)
    }

    func testUnpinWhileIdle() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        pins.register(self.makeConnection(1))
        XCTAssertEqual(pins.unpin(1), .forwardRelease(additionalUses: 0))
        XCTAssertEqual(pins.unpin(1), .none)
    }

    func testAuthenticatedConnectionWithoutIdentityIsClosed() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: true)
        let connection = self.makeConnection(1)
        pins.register(connection)
        pins.markAuthenticated(1)
        XCTAssertTrue(pins.isAuthenticated(1))
        XCTAssertEqual(pins.unpin(1), .close(connection))
    }

    func testAuthenticatedConnectionWithIdentityIsKept() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        let connection = self.makeConnection(1)
        pins.register(connection)
        pins.markAuthenticated(1)
        XCTAssertEqual(pins.unpin(1), .forwardRelease(additionalUses: 0))
        // The connection stays authenticated while it lives in the pool...
        XCTAssertTrue(pins.isAuthenticated(1))
        pins.register(connection)
        XCTAssertTrue(pins.isAuthenticated(1))
        // ...but not after it was closed.
        _ = pins.connectionClosed(1)
        XCTAssertFalse(pins.isAuthenticated(1))
    }

    func testCloseFailsWaitingRequestsAndNothingIsForwarded() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        pins.register(self.makeConnection(1))
        guard case .execute = pins.execute(self.makeRequest(), on: 1) else {
            return XCTFail("Expected the request to be executed")
        }
        let waiting = self.makeRequest()
        guard case .queue = pins.execute(waiting, on: 1) else {
            return XCTFail("Expected the request to wait")
        }
        XCTAssertEqual(pins.unpin(1), .none)

        let (failed, error) = pins.connectionClosed(1)
        XCTAssertEqual(failed.map(\.id), [waiting.id])
        XCTAssertEqual(error as? HTTPClientError, .connectionChanged)
        XCTAssertFalse(pins.isPinned(1))
        XCTAssertEqual(pins.connectionReleased(1), .notPinned)

        guard case .fail(_, let sendError) = pins.execute(self.makeRequest(), on: 1) else {
            return XCTFail("Expected the request to fail")
        }
        XCTAssertEqual(sendError as? HTTPClientError, .connectionChanged)
    }

    func testCancelWaitingRequest() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        pins.register(self.makeConnection(1))
        guard case .execute = pins.execute(self.makeRequest(), on: 1) else {
            return XCTFail("Expected the request to be executed")
        }
        let waiting = self.makeRequest()
        _ = pins.execute(waiting, on: 1)
        XCTAssertEqual(pins.cancelQueuedRequest(waiting.id)?.id, waiting.id)
        XCTAssertNil(pins.cancelQueuedRequest(waiting.id))
        XCTAssertEqual(pins.connectionReleased(1), .none)
    }

    func testRequestsFailAfterShutdown() {
        var pins = Pins(closeAuthenticatedConnectionsOnRelease: false)
        pins.register(self.makeConnection(1))
        pins.shutdown()
        guard case .fail(_, let error) = pins.execute(self.makeRequest(), on: 1) else {
            return XCTFail("Expected the request to fail")
        }
        XCTAssertEqual(error as? HTTPClientError, .alreadyShutdown)
        XCTAssertEqual(pins.connectionClosed(1).error as? HTTPClientError, .alreadyShutdown)
    }

    func testPoolKeyPinning() throws {
        let request = try HTTPClient.Request(url: "https://user@example.com/")
        let key = ConnectionPool.Key(request)
        let alice = key.with(pinning: .identity(.init("alice")))
        XCTAssertNotEqual(key, alice)
        XCTAssertNotEqual(key.with(pinning: .anonymous), alice)
        XCTAssertEqual(alice, key.with(pinning: .identity(.init("alice"))))
        XCTAssertNotEqual(alice, key.with(pinning: .identity(.init("bob"))))
        XCTAssertNotEqual(alice, key.with(pinning: .identity(.init(1))))
        XCTAssertFalse(alice.description.contains("alice"))
        XCTAssertEqual(alice.with(pinning: nil), key)
    }
}
