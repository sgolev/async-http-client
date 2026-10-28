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

extension HTTPClient {
    /// Information about the TLS session of a connection.
    ///
    /// Authentication schemes use it to bind credentials to the TLS channel, for example with the
    /// `tls-server-end-point` channel binding (RFC 5929).
    public struct TLSInfo: Sendable, Hashable {
        /// The application protocol negotiated with ALPN, if any.
        public var negotiatedApplicationProtocol: String?

        /// The DER encoded certificate the server presented, if it is available.
        ///
        /// - Note: The certificate is currently not available for connections that use
        ///   `NIOTransportServices`.
        public var peerCertificate: [UInt8]?

        public init(negotiatedApplicationProtocol: String? = nil, peerCertificate: [UInt8]? = nil) {
            self.negotiatedApplicationProtocol = negotiatedApplicationProtocol
            self.peerCertificate = peerCertificate
        }
    }
}
