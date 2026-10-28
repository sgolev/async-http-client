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
import NIOHTTP1
import XCTest

@testable import AsyncHTTPClient

final class HTTP1ProxyConnectRequestHandlerTests: XCTestCase {
    private func makeChannel() throws -> (EmbeddedChannel, HTTP1ProxyConnectRequestHandler) {
        let channel = EmbeddedChannel()
        let handler = HTTP1ProxyConnectRequestHandler()
        try channel.pipeline.syncOperations.addHandler(handler)
        try channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 0)).wait()
        return (channel, handler)
    }

    private let head = HTTP1ProxyConnectRequestHandler.makeConnectHead(
        targetHost: "swift.org",
        targetPort: 443,
        headers: HTTP1ProxyConnectRequestHandler.removingReservedHeaders(from: [
            "Host": "evil.com", "Proxy-Authorization": "stripped", "X-Foo": "bar",
        ])
    )

    func testConnectHead() {
        XCTAssertEqual(self.head.method, .CONNECT)
        XCTAssertEqual(self.head.uri, "swift.org:443")
        XCTAssertEqual(self.head.headers["host"], ["swift.org"])
        XCTAssertEqual(self.head.headers["x-foo"], ["bar"])
        XCTAssertFalse(self.head.headers.contains(name: "proxy-authorization"))
    }

    func testTunnel() throws {
        let (channel, handler) = try self.makeChannel()
        let response = handler.sendConnect(self.head)
        XCTAssertEqual(try channel.readOutbound(as: HTTPClientRequestPart.self), .head(self.head))
        XCTAssertEqual(try channel.readOutbound(as: HTTPClientRequestPart.self), .end(nil))

        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .ok)))
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        let result = try response.wait()
        XCTAssertEqual(result.head.status, .ok)
        XCTAssertFalse(result.connectionReusable)
        XCTAssertTrue(channel.isActive)
        XCTAssertNoThrow(try channel.finish())
    }

    func testRefusalOnKeptAliveConnectionAllowsAnotherRequest() throws {
        let (channel, handler) = try self.makeChannel()
        let first = handler.sendConnect(self.head)
        let refusal = HTTPResponseHead(
            version: .http1_1,
            status: .proxyAuthenticationRequired,
            headers: ["Content-Length": "4", "Proxy-Authenticate": "Basic"]
        )
        try channel.writeInbound(HTTPClientResponsePart.head(refusal))
        try channel.writeInbound(HTTPClientResponsePart.body(ByteBuffer(string: "nope")))
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        let result = try first.wait()
        XCTAssertEqual(result.head.status, .proxyAuthenticationRequired)
        XCTAssertEqual(result.body, ByteBuffer(string: "nope"))
        XCTAssertTrue(result.connectionReusable)

        let second = handler.sendConnect(self.head)
        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .ok)))
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        XCTAssertEqual(try second.wait().head.status, .ok)
    }

    func testRefusalWithConnectionCloseClosesTheChannel() throws {
        let (channel, handler) = try self.makeChannel()
        let response = handler.sendConnect(self.head)
        try channel.writeInbound(
            HTTPClientResponsePart.head(
                .init(version: .http1_1, status: .proxyAuthenticationRequired, headers: ["Connection": "close"])
            )
        )
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        XCTAssertFalse(try response.wait().connectionReusable)
        XCTAssertFalse(channel.isActive)
    }

    func testRefusalWhoseBodyWasNotDecodedIsNotReused() throws {
        // swift-nio without apple/swift-nio#3773 announces a body but never delivers it.
        let (channel, handler) = try self.makeChannel()
        let response = handler.sendConnect(self.head)
        try channel.writeInbound(
            HTTPClientResponsePart.head(
                .init(version: .http1_1, status: .proxyAuthenticationRequired, headers: ["Content-Length": "4"])
            )
        )
        try channel.writeInbound(HTTPClientResponsePart.end(nil))
        XCTAssertFalse(try response.wait().connectionReusable)
        XCTAssertFalse(channel.isActive)
    }

    func testBodyOnTunnelResponseFails() throws {
        let (channel, handler) = try self.makeChannel()
        let response = handler.sendConnect(self.head)
        try channel.writeInbound(HTTPClientResponsePart.head(.init(version: .http1_1, status: .ok)))
        try channel.writeInbound(HTTPClientResponsePart.body(ByteBuffer(string: "x")))
        XCTAssertThrowsError(try response.wait()) {
            XCTAssertEqual($0 as? HTTPClientError, .invalidProxyResponse)
        }
        XCTAssertFalse(channel.isActive)
    }

    func testCloseWhileWaitingFails() throws {
        let (channel, handler) = try self.makeChannel()
        let response = handler.sendConnect(self.head)
        try channel.close().wait()
        XCTAssertThrowsError(try response.wait()) {
            XCTAssertEqual($0 as? HTTPClientError, .remoteConnectionClosed)
        }
        XCTAssertThrowsError(try handler.sendConnect(self.head).wait()) {
            XCTAssertEqual($0 as? HTTPClientError, .remoteConnectionClosed)
        }
    }
}
