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
import Crypto
import SwiftASN1
import X509

/// Whether credentials are bound to the TLS channel they are sent on.
public enum ChannelBindingPolicy: Sendable, Hashable {
    /// Don't bind credentials to the channel.
    case disabled
    /// Bind credentials to the channel, if the connection uses TLS and the server certificate is available.
    case automatic
    /// Bind credentials to the channel. Fail, if that is not possible.
    case required
}

/// TLS channel bindings, that bind credentials to a TLS connection to protect them from relay attacks.
public enum TLSChannelBinding {
    /// The `tls-server-end-point` channel binding (RFC 5929, section 4) for a server certificate.
    ///
    /// The binding is `"tls-server-end-point:"` followed by the hash of the DER encoded certificate. The hash
    /// function is the one of the certificate's signature algorithm, but SHA-256 if that is MD5 or SHA-1.
    public static func serverEndPoint(certificate: [UInt8]) -> [UInt8] {
        Array("tls-server-end-point:".utf8) + Self.serverEndPointHash(certificate: certificate)
    }

    static func serverEndPointHash(certificate: [UInt8]) -> [UInt8] {
        let algorithm = try? Certificate(derEncoded: certificate).signatureAlgorithm
        switch algorithm {
        case .sha384WithRSAEncryption, .ecdsaWithSHA384:
            return Array(SHA384.hash(data: certificate))
        case .sha512WithRSAEncryption, .ecdsaWithSHA512:
            return Array(SHA512.hash(data: certificate))
        default:
            return Array(SHA256.hash(data: certificate))
        }
    }

    /// Returns the `tls-server-end-point` binding for a pinned connection, according to `policy`.
    @available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
    static func binding(
        for connection: HTTPClientConnection,
        peer: HTTPClientExchange.Peer,
        policy: ChannelBindingPolicy
    ) throws -> [UInt8]? {
        switch policy {
        case .disabled:
            return nil
        case .automatic, .required:
            // Bindings protect the TLS channel to the origin. Proxy connections are plain text.
            if !peer.isProxy, let certificate = connection.tlsInfo?.peerCertificate {
                return Self.serverEndPoint(certificate: certificate)
            }
            if policy == .required {
                throw HTTPClientAuthenticationError.channelBindingUnavailable
            }
            return nil
        }
    }

    /// Encodes a `gss_channel_bindings_struct` without addresses (RFC 2744, section 3.11), as NTLM hashes it for
    /// `MsvAvChannelBindings`.
    static func gssChannelBindingsStructure(applicationData: [UInt8]) -> [UInt8] {
        var bytes: [UInt8] = []
        // initiator_addrtype, initiator_address.length, acceptor_addrtype, acceptor_address.length
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 16))
        bytes.appendLittleEndian(UInt32(applicationData.count))
        bytes.append(contentsOf: applicationData)
        return bytes
    }
}

extension Array where Element == UInt8 {
    mutating func appendLittleEndian<Integer: FixedWidthInteger>(_ value: Integer) {
        Swift.withUnsafeBytes(of: value.littleEndian) { self.append(contentsOf: $0) }
    }
}
