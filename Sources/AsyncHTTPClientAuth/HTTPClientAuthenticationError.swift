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

/// An error thrown by the authenticators of `AsyncHTTPClientAuth`.
public struct HTTPClientAuthenticationError: Error, Hashable, CustomStringConvertible {
    private enum Code: Hashable {
        case malformedChallenge
        case mutualAuthenticationFailed
        case serverSignatureMismatch
        case channelBindingUnavailable
        case negotiateUnavailable
        case gssFailure(major: UInt32, minor: UInt32, message: String)
    }

    private let code: Code

    private init(_ code: Code) {
        self.code = code
    }

    /// The peer sent a challenge or a message that could not be parsed.
    public static let malformedChallenge = Self(.malformedChallenge)

    /// The server did not prove its identity, although mutual authentication was required.
    public static let mutualAuthenticationFailed = Self(.mutualAuthenticationFailed)

    /// The server's signature (for example SCRAM's `v=` or Digest's `rspauth`) did not match.
    public static let serverSignatureMismatch = Self(.serverSignatureMismatch)

    /// Channel binding was required, but the connection has no TLS certificate to bind to.
    public static let channelBindingUnavailable = Self(.channelBindingUnavailable)

    /// No GSS-API implementation is available. On Linux, enable the `GSSAPI` package trait.
    public static let negotiateUnavailable = Self(.negotiateUnavailable)

    /// A GSS-API call failed.
    public static func gssFailure(major: UInt32, minor: UInt32, message: String) -> Self {
        Self(.gssFailure(major: major, minor: minor, message: message))
    }

    /// Whether the error is a GSS-API failure.
    public var isGSSFailure: Bool {
        if case .gssFailure = self.code { return true }
        return false
    }

    public var description: String {
        switch self.code {
        case .malformedChallenge:
            return "The authentication challenge is malformed"
        case .mutualAuthenticationFailed:
            return "The server did not authenticate itself"
        case .serverSignatureMismatch:
            return "The server's signature does not match"
        case .channelBindingUnavailable:
            return "Channel binding is required, but no TLS certificate is available"
        case .negotiateUnavailable:
            return "GSS-API is not available. On Linux, enable the GSSAPI package trait"
        case .gssFailure(let major, let minor, let message):
            return "GSS-API failure (major: \(major), minor: \(minor)): \(message)"
        }
    }
}
