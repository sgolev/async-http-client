//===----------------------------------------------------------------------===//
//
// This source file is part of the AsyncHTTPClient open source project
//
// Copyright (c) 2018-2019 Apple Inc. and the AsyncHTTPClient project authors
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

extension HTTPClient.Configuration {
    /// Proxy server configuration
    /// Specifies the remote address of an HTTP proxy.
    ///
    /// Adding an `Proxy` to your client's `HTTPClient.Configuration`
    /// will cause requests to be passed through the specified proxy using the
    /// HTTP `CONNECT` method.
    ///
    /// If a `TLSConfiguration` is used in conjunction with `HTTPClient.Configuration.Proxy`,
    /// TLS will be established _after_ successful proxy, between your client
    /// and the destination server.
    public struct Proxy: Sendable, Hashable {
        enum ProxyType: Hashable {
            case http
            case socks
        }

        /// Specifies Proxy server host.
        public var host: String
        /// Specifies Proxy server port.
        public var port: Int

        var type: ProxyType

        /// Extra headers sent only on the HTTP `CONNECT` request to the proxy.
        ///
        /// These headers are not sent to the
        /// destination server, and are ignored for SOCKS proxies.
        /// The `host` and `proxy-authorization` headers cannot be overridden through this property
        /// Note: Excluded from hash, because HTTPHeaders are not hashable.
        public var connectHeaders: HTTPHeaders = [:]

        /// Stores the ``authenticator``. `Proxy` has no availability restrictions, so it can't store an existential
        /// of the protocol directly.
        private var _authenticator: (any Sendable)?

        /// Authenticates the client with the proxy. Ignored for SOCKS proxies.
        ///
        /// The authenticator is called with the `CONNECT` request that opens a tunnel through the proxy, and an
        /// ``HTTPClientExchange`` whose ``HTTPClientExchange/peer`` is a proxy. The request's URL is the
        /// authority (`host:port`) the tunnel is opened to. Since tunnels are opened for both the async/await API and
        /// the `EventLoopFuture` based API, the authenticator is used for both.
        ///
        /// Note: Excluded from equality and hash.
        @available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
        public var authenticator: (any HTTPClientAuthenticator)? {
            get { self._authenticator as? any HTTPClientAuthenticator }
            set { self._authenticator = newValue }
        }

        init(host: String, port: Int, type: ProxyType) {
            self.host = host
            self.port = port
            self.type = type
        }

        /// Create an HTTP proxy configuration.
        ///
        /// - parameters:
        ///     - host: proxy server host.
        ///     - port: proxy server port.
        ///     - connectHeaders: extra headers sent only on the `CONNECT` request to the proxy.
        public static func server(host: String, port: Int, connectHeaders: HTTPHeaders = [:]) -> Self {
            var proxy = Self(host: host, port: port, type: .http)
            proxy.connectHeaders = connectHeaders
            return proxy
        }

        /// Create an HTTP proxy configuration.
        ///
        /// - parameters:
        ///     - host: proxy server host.
        ///     - port: proxy server port.
        ///     - connectHeaders: extra headers sent only on the `CONNECT` request to the proxy.
        ///     - authenticator: authenticates the client with the proxy.
        @available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
        public static func server(
            host: String,
            port: Int,
            connectHeaders: HTTPHeaders = [:],
            authenticator: any HTTPClientAuthenticator
        ) -> Self {
            var proxy = Self.server(host: host, port: port, connectHeaders: connectHeaders)
            proxy.authenticator = authenticator
            return proxy
        }

        /// Create a SOCKSv5 proxy configuration.
        /// - parameter host: The SOCKSv5 proxy address.
        /// - parameter port: The SOCKSv5 proxy port, defaults to 1080.
        /// - returns: A new instance of `Proxy` configured to connect to a `SOCKSv5` server.
        public static func socksServer(host: String, port: Int = 1080) -> Proxy {
            .init(host: host, port: port, type: .socks)
        }

        // `authenticator` is omitted (authenticators are not equatable)
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.host == rhs.host && lhs.port == rhs.port && lhs.type == rhs.type
                && lhs.connectHeaders == rhs.connectHeaders
        }

        // `connectHeaders` is omitted (HTTPHeaders is not hashable), as is `authenticator`
        public func hash(into hasher: inout Hasher) {
            hasher.combine(self.host)
            hasher.combine(self.port)
            hasher.combine(self.type)
        }
    }
}
