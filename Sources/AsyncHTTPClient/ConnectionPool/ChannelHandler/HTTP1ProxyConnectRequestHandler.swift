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
import NIOHTTP1

/// Sends `CONNECT` requests to an HTTP proxy.
///
/// The handler makes no decisions. It sends the requests it is given and reports the responses, including their
/// bodies. Whether a refusal is retried is up to the proxy's authenticator. After a refusal (a non-2xx response) the connection can be used
/// for another `CONNECT` request, if the proxy keeps it alive. After a 2xx response the connection is a tunnel and
/// the handler must be removed together with the HTTP codec.
final class HTTP1ProxyConnectRequestHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPClientResponsePart
    typealias OutboundOut = HTTPClientRequestPart

    struct Response {
        var head: HTTPResponseHead
        var body: ByteBuffer?
        /// Whether another `CONNECT` request can be sent on the connection. Always `false` for a 2xx response.
        var connectionReusable: Bool
    }

    private enum State {
        case idle
        case awaitingHead(EventLoopPromise<Response>)
        case receivingBody(HTTPResponseHead, ByteBuffer?, EventLoopPromise<Response>)
        case tunnelEstablished
        case closed
    }

    /// `host` is set by the handler. `proxy-authorization` must be set by an authenticator, not as a connect header.
    private static let reservedConnectHeaders: Set<String> = ["host", "proxy-authorization"]

    /// Removes the headers that can't be set with ``HTTPClient/Configuration/Proxy/connectHeaders``.
    static func removingReservedHeaders(from connectHeaders: HTTPHeaders) -> HTTPHeaders {
        var headers = HTTPHeaders()
        for (name, value) in connectHeaders where !Self.reservedConnectHeaders.contains(name.lowercased()) {
            headers.add(name: name, value: value)
        }
        return headers
    }

    static func makeConnectHead(targetHost: String, targetPort: Int, headers: HTTPHeaders) -> HTTPRequestHead {
        var head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "\(targetHost):\(targetPort)")
        head.headers = headers
        head.headers.remove(name: "host")
        head.headers.add(name: "host", value: targetHost)
        return head
    }

    /// The body of a refusal is usually a short error page.
    static let maximumBodySize = 64 * 1024

    private var state = State.idle
    private var context: ChannelHandlerContext?

    init() {}

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        self.fail(HTTPClientError.remoteConnectionClosed, close: false)
    }

    /// Sends a `CONNECT` request. Must be called on the channel's event loop.
    func sendConnect(_ head: HTTPRequestHead) -> EventLoopFuture<Response> {
        guard let context = self.context else {
            preconditionFailure("The handler must be added to a pipeline before sending")
        }
        context.eventLoop.assertInEventLoop()
        precondition(head.method == .CONNECT)

        guard case .idle = self.state, context.channel.isActive else {
            return context.eventLoop.makeFailedFuture(HTTPClientError.remoteConnectionClosed)
        }
        let promise = context.eventLoop.makePromise(of: Response.self)
        self.state = .awaitingHead(promise)
        context.write(self.wrapOutboundOut(.head(head)), promise: nil)
        context.write(self.wrapOutboundOut(.end(nil)), promise: nil)
        context.flush()
        return promise.futureResult
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch self.unwrapInboundIn(data) {
        case .head(let head):
            guard case .awaitingHead(let promise) = self.state else {
                return self.fail(HTTPClientError.invalidProxyResponse, close: true)
            }
            self.state = .receivingBody(head, nil, promise)

        case .body(var part):
            guard case .receivingBody(let head, var body, let promise) = self.state else {
                return self.fail(HTTPClientError.invalidProxyResponse, close: true)
            }
            // A 2xx response to CONNECT switches to tunnel mode right after the head. It has no body.
            guard !Self.opensTunnel(head),
                (body?.readableBytes ?? 0) + part.readableBytes <= Self.maximumBodySize
            else {
                return self.fail(HTTPClientError.invalidProxyResponse, close: true)
            }
            if body == nil {
                body = part
            } else {
                body!.writeBuffer(&part)
            }
            self.state = .receivingBody(head, body, promise)

        case .end:
            guard case .receivingBody(let head, let body, let promise) = self.state else {
                return self.fail(HTTPClientError.invalidProxyResponse, close: true)
            }
            if Self.opensTunnel(head) {
                self.state = .tunnelEstablished
                promise.succeed(Response(head: head, body: nil, connectionReusable: false))
                return
            }

            let reusable = head.isKeepAlive && Self.framingIsConsistent(head, body: body)
            if reusable {
                self.state = .idle
            } else {
                self.state = .closed
                context.close(promise: nil)
            }
            promise.succeed(Response(head: head, body: body, connectionReusable: reusable))
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.fail(HTTPClientError.remoteConnectionClosed, close: false)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.fail(error, close: true)
    }

    private func fail(_ error: Error, close: Bool) {
        let previous = self.state
        switch previous {
        case .tunnelEstablished:
            return
        case .idle, .closed, .awaitingHead, .receivingBody:
            break
        }
        self.state = .closed
        switch previous {
        case .awaitingHead(let promise), .receivingBody(_, _, let promise):
            promise.fail(error)
        case .idle, .closed, .tunnelEstablished:
            break
        }
        if close {
            self.context?.close(promise: nil)
        }
    }

    private static func opensTunnel(_ head: HTTPResponseHead) -> Bool {
        (200..<300).contains(head.status.code)
    }

    /// Detects whether the HTTP decoder skipped the body of a refusal.
    ///
    // NOTE: relies on apple/swift-nio#3773. Before that change `HTTPResponseDecoder` treats every response to
    // `CONNECT` as bodiless, so the body of a refusal is not consumed and would be parsed as the next response.
    // With an affected swift-nio version, a refusal that announces a body is therefore never reused.
    private static func framingIsConsistent(_ head: HTTPResponseHead, body: ByteBuffer?) -> Bool {
        let announcesBody =
            head.headers["transfer-encoding"].contains { $0.lowercased().contains("chunked") }
            || head.headers["content-length"].contains { (Int($0) ?? 0) > 0 }
        return !announcesBody || body != nil
    }
}

@available(*, unavailable)
extension HTTP1ProxyConnectRequestHandler: Sendable {}

extension ConnectionTarget {
    /// The host and port to open a tunnel to with a `CONNECT` request.
    var proxyConnectTarget: (host: String, port: Int) {
        switch self {
        case .ipAddress(let serialization, let address):
            return (serialization, address.port!)
        case .domain(name: let domain, let port):
            return (domain, port)
        case .unixSocket:
            fatalError("Unix Domain Sockets do not support proxies")
        }
    }
}
