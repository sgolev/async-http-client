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

import AsyncHTTPClient
import Logging
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import XCTest

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
final class HTTPClientAuthenticatorTests: XCTestCase {
    // MARK: - Basic and Bearer

    func testBasicPreemptive() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            var request = HTTPClientRequest(url: bin.baseURL + "basic")
            request.authenticator = BasicAuthenticator(username: "user", password: "pass")
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.history.count, 1)
            _ = try await response.body.collect(upTo: 1024)
        }
    }

    func testBasicAfterChallenge() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        var configuration = HTTPClient.Configuration()
        configuration.authenticator = BasicAuthenticator(username: "user", password: "pass", preemptive: false)
        try await withClient(configuration) { client in

            let response = try await client.execute(
                HTTPClientRequest(url: bin.baseURL + "basic"),
                deadline: .now() + .seconds(10)
            )
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.history.map(\.responseHead.status), [.unauthorized, .ok])
            XCTAssertNil(response.history[0].request.headers.first(name: "Authorization"))
            XCTAssertEqual(response.history[1].request.headers.first(name: "Authorization"), "Basic dXNlcjpwYXNz")
            // The unread 401 body was drained, so the connection was reused.
            XCTAssertEqual(bin.createdConnections, 1)
            _ = try await response.body.collect(upTo: 1024)
        }
    }

    func testBearerTokenRefresh() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            let rejected = NIOLockedValueBox<[String?]>([])
            var request = HTTPClientRequest(url: bin.baseURL + "bearer")
            request.authenticator = BearerAuthenticator { rejectedToken in
                rejected.withLockedValue { $0.append(rejectedToken) }
                return rejectedToken == nil ? "expired" : "fresh"
            }
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(rejected.withLockedValue { $0 }, [nil, "expired"])
            XCTAssertEqual(response.history.count, 2)
        }
    }

    // MARK: - Connection pinning

    func testConnectionBasedSchemeWithIdentity() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            func execute(as user: String) async throws -> (body: String, history: Int, wasAuthenticated: Bool) {
                let authenticator = ConnectionSchemeAuthenticator(identity: user)
                var request = HTTPClientRequest(url: bin.baseURL + "connection")
                request.authenticator = authenticator
                let response = try await client.execute(request, deadline: .now() + .seconds(10))
                XCTAssertEqual(response.status, .ok)
                let body = try await response.body.collect(upTo: 1024)
                return (String(buffer: body), response.history.count, authenticator.observedAuthenticatedConnection)
            }

            let first = try await execute(as: "alice")
            XCTAssertEqual(first.history, 2)
            XCTAssertFalse(first.wasAuthenticated)

            // The authenticated connection is reused for the same identity, without another handshake.
            let second = try await execute(as: "alice")
            XCTAssertEqual(second.history, 1)
            XCTAssertTrue(second.wasAuthenticated)
            XCTAssertEqual(second.body, first.body)

            // Another identity never gets that connection.
            let third = try await execute(as: "bob")
            XCTAssertEqual(third.history, 2)
            XCTAssertFalse(third.wasAuthenticated)
            XCTAssertNotEqual(third.body, first.body)

            // An unauthenticated request doesn't get it either.
            let plain = try await client.execute(
                HTTPClientRequest(url: bin.baseURL + "connection"),
                deadline: .now() + .seconds(10)
            )
            XCTAssertEqual(plain.status, .unauthorized)
        }
    }

    func testAuthenticatedConnectionWithoutIdentityIsClosed() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            for _ in 0..<2 {
                let authenticator = ConnectionSchemeAuthenticator(identity: nil)
                var request = HTTPClientRequest(url: bin.baseURL + "connection")
                request.authenticator = authenticator
                let response = try await client.execute(request, deadline: .now() + .seconds(10))
                XCTAssertEqual(response.status, .ok)
                XCTAssertEqual(response.history.count, 2)
                _ = try await response.body.collect(upTo: 1024)
                XCTAssertFalse(authenticator.observedAuthenticatedConnection)
            }
            XCTAssertEqual(bin.createdConnections, 2)
        }
    }

    func testLargeChallengeBodyLosesPinnedConnection() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            var request = HTTPClientRequest(url: bin.baseURL + "connection?challengeBodySize=\(2 * 1024 * 1024)")
            request.authenticator = ConnectionSchemeAuthenticator(identity: "alice")
            await XCTAssertThrowsError(try await client.execute(request, deadline: .now() + .seconds(10))) {
                XCTAssertEqual($0 as? HTTPClientError, .connectionChanged)
            }

            // A small challenge body is drained and the handshake succeeds.
            request.url = bin.baseURL + "connection?challengeBodySize=\(64 * 1024)"
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testPinnedConnectionClosedByServer() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            var request = HTTPClientRequest(url: bin.baseURL + "connection?close=1")
            request.authenticator = ConnectionSchemeAuthenticator(identity: "alice")
            await XCTAssertThrowsError(try await client.execute(request, deadline: .now() + .seconds(10))) {
                XCTAssertEqual($0 as? HTTPClientError, .connectionChanged)
            }
        }
    }

    func testSingleUseBodyIsNotSentTwice() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        try await withClient { client in

            var request = HTTPClientRequest(url: bin.baseURL + "basic")
            request.method = .POST
            request.body = .stream(AsyncStream<ByteBuffer> { $0.finish() }, length: .known(Int64(0)))
            request.authenticator = BasicAuthenticator(username: "user", password: "pass", preemptive: false)
            await XCTAssertThrowsError(try await client.execute(request, deadline: .now() + .seconds(10))) {
                XCTAssertEqual($0 as? HTTPClientError, .requestBodyNotReplayable)
            }

            // A replayable body is fine.
            request.body = .bytes(ByteBuffer(string: "hello"))
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
        }
    }

    func testRequestAuthenticatorIsDroppedOnCrossOriginRedirect() async throws {
        let target = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try target.shutdown()) }
        let origin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try origin.shutdown()) }

        let clientPeers = PeerRecorder()
        var configuration = HTTPClient.Configuration()
        configuration.authenticator = clientPeers
        try await withClient(configuration) { client in

            let requestPeers = PeerRecorder()
            var request = HTTPClientRequest(url: origin.baseURL + "redirect?to=" + target.baseURL + "basic")
            request.authenticator = requestPeers
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .unauthorized)

            XCTAssertEqual(requestPeers.peers.map(\.port), [origin.port])
            XCTAssertEqual(clientPeers.peers.map(\.port), [target.port])
            XCTAssertEqual(clientPeers.peers.first?.kind, .origin)
            XCTAssertEqual(clientPeers.peers.first?.scheme, "http")
        }
    }

    func testPinWaitsForConnectionUntilDeadline() async throws {
        let bin = HTTPBin(.http1_1(ssl: false)) { AuthTestHandler(connectionID: $0) }
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        var configuration = HTTPClient.Configuration()
        configuration.connectionPool.concurrentHTTP1ConnectionsPerHostSoftLimit = 1
        try await withClient(configuration) { client in

            let holding = HoldingAuthenticator()
            var holdingRequest = HTTPClientRequest(url: bin.baseURL + "basic")
            holdingRequest.authenticator = holding
            let holdingTask = Task {
                try await client.execute(holdingRequest, deadline: .now() + .seconds(30))
            }
            await holding.waitUntilPinned()

            var waitingRequest = HTTPClientRequest(url: bin.baseURL + "basic")
            waitingRequest.authenticator = HoldingAuthenticator(holds: false)
            await XCTAssertThrowsError(
                try await client.execute(waitingRequest, deadline: .now() + .milliseconds(200))
            ) {
                XCTAssertEqual($0 as? HTTPClientError, .deadlineExceeded)
            }

            holding.release()
            _ = try await holdingTask.value
            // Once the pin is released, the connection is available again.
            _ = try await client.execute(waitingRequest, deadline: .now() + .seconds(10))
        }
    }

    func testPinnedConnectionsAreHTTP1AndExposeTLSInfo() async throws {
        let bin = HTTPBin(.http2(compress: false))
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        var configuration = HTTPClient.Configuration(certificateVerification: .none)
        configuration.httpVersion = .automatic
        try await withClient(configuration) { client in

            let inspector = ConnectionInspector()
            var request = HTTPClientRequest(url: bin.baseURL + "get")
            request.authenticator = inspector
            let response = try await client.execute(request, deadline: .now() + .seconds(10))
            XCTAssertEqual(response.status, .ok)
            XCTAssertEqual(response.version, .http1_1)

            let connection = try XCTUnwrap(inspector.connection)
            XCTAssertEqual(connection.httpVersion, .http1_1)
            XCTAssertEqual(connection.tlsInfo?.negotiatedApplicationProtocol, "http/1.1")
            XCTAssertEqual(connection.tlsInfo?.peerCertificate, try TestTLS.certificate.toDERBytes())

            // Requests that don't pin a connection still use HTTP/2.
            let unpinned = try await client.execute(
                HTTPClientRequest(url: bin.baseURL + "get"),
                deadline: .now() + .seconds(10)
            )
            XCTAssertEqual(unpinned.version, .http2)
        }
    }

    // MARK: - Proxy

    func testProxyAuthenticatorOnKeptAliveConnection() async throws {
        let bin = HTTPBin(
            proxy: .simulateChallenge(
                authorization: "Basic dXNlcjpwYXNz",
                challenge: #"Basic realm="proxy""#,
                closeOnChallenge: false
            )
        )
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        let recorder = PeerRecorder(inner: BasicAuthenticator(username: "user", password: "pass", preemptive: false))
        let configuration = HTTPClient.Configuration(
            proxy: .server(host: "localhost", port: bin.port, authenticator: recorder)
        ).enableFastFailureModeForTesting()
        try await withClient(configuration) { client in
            let response = try await client.execute(
                HTTPClientRequest(url: "http://test/ok"),
                deadline: .now() + .seconds(10)
            )
            XCTAssertEqual(response.status, .ok)
        }
        XCTAssertEqual(bin.createdConnections, 1)
        XCTAssertEqual(recorder.peers.first?.kind, .proxy)
        XCTAssertEqual(recorder.peers.first?.port, bin.port)
        XCTAssertEqual(recorder.requests.first?.method, .CONNECT)
        XCTAssertEqual(recorder.requests.first?.url, "test:80")
    }

    func testProxyAuthenticatorReconnectsAfterClose() throws {
        let bin = HTTPBin(
            .http1_1(ssl: true),
            proxy: .simulateChallenge(
                authorization: "Basic dXNlcjpwYXNz",
                challenge: #"Basic realm="proxy""#,
                closeOnChallenge: true
            )
        )
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: .init(
                certificateVerification: .none,
                proxy: .server(
                    host: "localhost",
                    port: bin.port,
                    authenticator: BasicAuthenticator(username: "user", password: "pass", preemptive: false)
                )
            )
        )
        defer { XCTAssertNoThrow(try client.syncShutdown()) }

        // Proxy authenticators also work for the EventLoopFuture based API, and with TLS through the tunnel.
        let response = try client.get(url: "https://test/ok").wait()
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(bin.createdConnections, 2)
    }

    func testProxyAuthenticatorWithWrongCredentials() throws {
        let bin = HTTPBin(
            proxy: .simulateChallenge(
                authorization: "Basic dXNlcjpwYXNz",
                challenge: #"Basic realm="proxy""#,
                closeOnChallenge: false
            )
        )
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        let client = HTTPClient(
            eventLoopGroupProvider: .singleton,
            configuration: .init(
                proxy: .server(
                    host: "localhost",
                    port: bin.port,
                    authenticator: BasicAuthenticator(username: "user", password: "wrong", preemptive: false)
                )
            ).enableFastFailureModeForTesting()
        )
        defer { XCTAssertNoThrow(try client.syncShutdown()) }

        XCTAssertThrowsError(try client.get(url: "http://test/ok").wait()) {
            XCTAssertEqual($0 as? HTTPClientError, .proxyAuthenticationRequired)
        }
    }

    func testProxyChallengeWithBody() async throws {
        // NOTE: relies on apple/swift-nio#3773. Until it is released, `HTTPResponseDecoder` does not decode the body
        // of a non-2xx response to CONNECT, so the connection can't be reused.
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["AHC_SWIFT_NIO_3773"] != nil,
            "Requires apple/swift-nio#3773"
        )
        let bin = HTTPBin(
            proxy: .simulateChallenge(
                authorization: "Basic dXNlcjpwYXNz",
                challenge: #"Basic realm="proxy""#,
                closeOnChallenge: false,
                body: "<html>Proxy authentication required</html>"
            )
        )
        defer { XCTAssertNoThrow(try bin.shutdown()) }
        let authenticator = BasicAuthenticator(username: "user", password: "pass", preemptive: false)
        try await withClient(.init(proxy: .server(host: "localhost", port: bin.port, authenticator: authenticator))) {
            let response = try await $0.execute(
                HTTPClientRequest(url: "http://test/ok"),
                deadline: .now() + .seconds(10)
            )
            XCTAssertEqual(response.status, .ok)
        }
        // The retry was sent on the connection that was challenged.
        XCTAssertEqual(bin.createdConnections, 1)
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
private func withClient<Result>(
    _ configuration: HTTPClient.Configuration = .init(),
    _ body: (HTTPClient) async throws -> Result
) async throws -> Result {
    let client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
    do {
        let result = try await body(client)
        try await client.shutdown()
        return result
    } catch {
        try? await client.shutdown()
        throw error
    }
}

// MARK: - Test authenticators

/// Implements a three step, connection based scheme ("TestConn"), similar to NTLM.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
private final class ConnectionSchemeAuthenticator: HTTPClientAuthenticator {
    let identity: String?
    private let _observedAuthenticatedConnection = NIOLockedValueBox(false)
    var observedAuthenticatedConnection: Bool { self._observedAuthenticatedConnection.withLockedValue { $0 } }

    init(identity: String?) {
        self.identity = identity
    }

    func authenticate(_ request: HTTPClientRequest, exchange: HTTPClientExchange) async throws -> HTTPClientResponse {
        let connection: HTTPClientConnection
        if let identity {
            connection = try await exchange.pinConnection(with: identity)
        } else {
            connection = try await exchange.pinConnection()
        }
        self._observedAuthenticatedConnection.withLockedValue { $0 = connection.isAuthenticated }
        if connection.isAuthenticated {
            return try await exchange.send(request)
        }

        var negotiate = request
        negotiate.headers.replaceOrAdd(name: "Authorization", value: "TestConn step1")
        let challengeResponse = try await exchange.send(negotiate)
        guard challengeResponse.status == .unauthorized,
            let challenge = challengeResponse.authenticationChallenges(for: exchange.peer).first?.token68
        else {
            return challengeResponse
        }

        var authenticate = request
        authenticate.headers.replaceOrAdd(name: "Authorization", value: "TestConn \(challenge)")
        let response = try await exchange.send(authenticate)
        if response.status == .ok {
            exchange.markConnectionAuthenticated()
        }
        return response
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
private final class PeerRecorder: HTTPClientAuthenticator {
    private let inner: (any HTTPClientAuthenticator)?
    private let state = NIOLockedValueBox<(peers: [HTTPClientExchange.Peer], requests: [HTTPClientRequest])>(([], []))

    var peers: [HTTPClientExchange.Peer] { self.state.withLockedValue { $0.peers } }
    var requests: [HTTPClientRequest] { self.state.withLockedValue { $0.requests } }

    init(inner: (any HTTPClientAuthenticator)? = nil) {
        self.inner = inner
    }

    func authenticate(_ request: HTTPClientRequest, exchange: HTTPClientExchange) async throws -> HTTPClientResponse {
        self.state.withLockedValue {
            $0.peers.append(exchange.peer)
            $0.requests.append(request)
        }
        if let inner = self.inner {
            return try await inner.authenticate(request, exchange: exchange)
        }
        return try await exchange.send(request)
    }
}

/// Pins a connection and holds on to it until released.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
private final class HoldingAuthenticator: HTTPClientAuthenticator {
    private let holds: Bool
    private let pinned: AsyncStream<Void>
    private let pinnedContinuation: AsyncStream<Void>.Continuation
    private let released: AsyncStream<Void>
    private let releasedContinuation: AsyncStream<Void>.Continuation

    init(holds: Bool = true) {
        self.holds = holds
        (self.pinned, self.pinnedContinuation) = AsyncStream.makeStream()
        (self.released, self.releasedContinuation) = AsyncStream.makeStream()
    }

    func waitUntilPinned() async {
        for await _ in self.pinned { return }
    }

    func release() {
        self.releasedContinuation.finish()
    }

    func authenticate(_ request: HTTPClientRequest, exchange: HTTPClientExchange) async throws -> HTTPClientResponse {
        _ = try await exchange.pinConnection(with: "holder")
        self.pinnedContinuation.yield()
        if self.holds {
            for await _ in self.released {}
        }
        var request = request
        request.headers.replaceOrAdd(name: "Authorization", value: "Basic dXNlcjpwYXNz")
        return try await exchange.send(request)
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
private final class ConnectionInspector: HTTPClientAuthenticator {
    private let _connection = NIOLockedValueBox<HTTPClientConnection?>(nil)
    var connection: HTTPClientConnection? { self._connection.withLockedValue { $0 } }

    func authenticate(_ request: HTTPClientRequest, exchange: HTTPClientExchange) async throws -> HTTPClientResponse {
        let connection = try await exchange.pinConnection()
        self._connection.withLockedValue { $0 = connection }
        return try await exchange.send(request)
    }
}

// MARK: - Test servers

/// Serves:
/// - `/basic`: requires `Basic dXNlcjpwYXNz`.
/// - `/bearer`: requires `Bearer fresh`, rejects other tokens with `error="invalid_token"`.
/// - `/connection`: a connection based three step scheme. `close=1` closes the connection after a challenge,
///   `challengeBodySize=n` adds a body of `n` bytes to challenges.
/// - `/redirect?to=url`: redirects to `url`.
/// - anything else: 200.
///
/// Successful responses contain the connection ID.
final class AuthTestHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let connectionID: Int
    private var head: HTTPRequestHead?
    private var pendingChallenge: String?
    private var isAuthenticated = false

    init(connectionID: Int) {
        self.connectionID = connectionID
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch self.unwrapInboundIn(data) {
        case .head(let head):
            self.head = head
        case .body:
            break
        case .end:
            guard let head = self.head else { return }
            self.head = nil
            self.respond(to: head, context: context)
        }
    }

    private func respond(to head: HTTPRequestHead, context: ChannelHandlerContext) {
        let (path, query) = Self.split(head.uri)
        let authorization = head.headers.first(name: "Authorization")
        switch path {
        case "/basic":
            if authorization == "Basic dXNlcjpwYXNz" {
                self.ok(context)
            } else {
                self.challenge(context, #"Basic realm="test""#, body: "unauthorized")
            }

        case "/bearer":
            if authorization == "Bearer fresh" {
                self.ok(context)
            } else {
                self.challenge(context, #"Bearer realm="test", error="invalid_token""#)
            }

        case "/connection":
            let close = query["close"] == "1"
            let body = query["challengeBodySize"].flatMap(Int.init).map { String(repeating: "x", count: $0) }
            if self.isAuthenticated {
                return self.ok(context)
            }
            switch authorization {
            case "TestConn step1":
                let challenge = "challenge-\(self.connectionID)"
                self.pendingChallenge = challenge
                self.challenge(context, "TestConn \(challenge)", body: body, close: close)
            case .some(let value) where self.pendingChallenge.map({ "TestConn \($0)" }) == value:
                self.isAuthenticated = true
                self.ok(context)
            default:
                self.pendingChallenge = nil
                self.challenge(context, "TestConn", body: body, close: close)
            }

        case "/redirect":
            var headers = HTTPHeaders()
            headers.add(name: "Location", value: query["to"] ?? "/")
            headers.add(name: "Content-Length", value: "0")
            self.write(context, status: .found, headers: headers, body: nil)

        default:
            self.ok(context)
        }
    }

    private func ok(_ context: ChannelHandlerContext) {
        self.write(context, status: .ok, headers: [:], body: "connection:\(self.connectionID)")
    }

    private func challenge(
        _ context: ChannelHandlerContext,
        _ challenge: String,
        body: String? = nil,
        close: Bool = false
    ) {
        var headers = HTTPHeaders()
        headers.add(name: "WWW-Authenticate", value: challenge)
        if close {
            headers.add(name: "Connection", value: "close")
        }
        self.write(context, status: .unauthorized, headers: headers, body: body, close: close)
    }

    private func write(
        _ context: ChannelHandlerContext,
        status: HTTPResponseStatus,
        headers: HTTPHeaders,
        body: String?,
        close: Bool = false
    ) {
        var headers = headers
        if !headers.contains(name: "Content-Length") {
            headers.add(name: "Content-Length", value: "\(body?.utf8.count ?? 0)")
        }
        context.write(
            self.wrapOutboundOut(.head(.init(version: .http1_1, status: status, headers: headers))),
            promise: nil
        )
        if let body {
            context.write(self.wrapOutboundOut(.body(.byteBuffer(ByteBuffer(string: body)))), promise: nil)
        }
        let promise = close ? context.eventLoop.makePromise(of: Void.self) : nil
        context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: promise)
        promise?.futureResult.assumeIsolated().whenComplete { _ in context.close(promise: nil) }
    }

    private static func split(_ uri: String) -> (path: String, query: [String: String]) {
        guard let questionMark = uri.firstIndex(of: "?") else { return (uri, [:]) }
        var query: [String: String] = [:]
        for pair in uri[uri.index(after: questionMark)...].split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1)
            query[String(parts[0])] = parts.count > 1 ? String(parts[1]) : ""
        }
        return (String(uri[..<questionMark]), query)
    }
}
