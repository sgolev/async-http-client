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

import NIOHTTP1

/// An authentication challenge from a `WWW-Authenticate` or `Proxy-Authenticate` header (RFC 9110, section 11).
public struct HTTPAuthenticationChallenge: Sendable, Hashable {
    /// The authentication scheme, for example `"Basic"`. Compare it with ``matches(scheme:)``, since schemes are
    /// case-insensitive.
    public var scheme: String

    /// The token68 of the challenge, for example the base64 encoded data of a `Negotiate` challenge.
    public var token68: String?

    /// The challenge's parameters. The names are lower-cased. If a parameter occurs more than once, the first
    /// occurrence is used.
    public var parameters: [String: String]

    public init(scheme: String, token68: String? = nil, parameters: [String: String] = [:]) {
        self.scheme = scheme
        self.token68 = token68
        self.parameters = parameters
    }

    /// Returns whether the challenge is for `scheme`, ignoring case.
    public func matches(scheme: String) -> Bool {
        self.scheme.lowercased() == scheme.lowercased()
    }

    /// Returns the value of a parameter, ignoring the case of `name`.
    public subscript(parameter name: String) -> String? {
        self.parameters[name.lowercased()]
    }

    /// Parses all challenges in the given header field values.
    ///
    /// Each value may contain several challenges. Malformed parts are skipped.
    public static func parse(headerValues: some Sequence<String>) -> [HTTPAuthenticationChallenge] {
        var challenges: [HTTPAuthenticationChallenge] = []
        for value in headerValues {
            var parser = Parser(value)
            parser.parseChallenges(into: &challenges)
        }
        return challenges
    }

    /// Parses a comma separated list of `name=value` pairs, like the value of an `Authentication-Info` header.
    ///
    /// The names are lower-cased. If a parameter occurs more than once, the first occurrence is used.
    public static func parseParameters(_ value: String) -> [String: String] {
        // A parameter list is a challenge without the scheme.
        Self.parse(headerValues: ["_ " + value]).first?.parameters ?? [:]
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension HTTPClientResponse {
    /// The authentication challenges of the response, as the given peer sends them.
    ///
    /// For an origin server these are taken from `WWW-Authenticate`, for a proxy from `Proxy-Authenticate`.
    public func authenticationChallenges(for peer: HTTPClientExchange.Peer) -> [HTTPAuthenticationChallenge] {
        HTTPAuthenticationChallenge.parse(headerValues: self.headers[peer.challengeHeaderName])
    }
}

extension HTTPAuthenticationChallenge {
    // challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
    // auth-param  = token BWS "=" BWS ( token / quoted-string )
    // token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    private struct Parser {
        private let bytes: [UInt8]
        private var index = 0

        init(_ value: String) {
            self.bytes = Array(value.utf8)
        }

        private var current: UInt8? { self.index < self.bytes.count ? self.bytes[self.index] : nil }

        mutating func parseChallenges(into challenges: inout [HTTPAuthenticationChallenge]) {
            var challenge: HTTPAuthenticationChallenge?
            while true {
                self.skip { $0 == UInt8(ascii: " ") || $0 == UInt8(ascii: "\t") || $0 == UInt8(ascii: ",") }
                guard self.current != nil else { break }
                guard let token = self.read(while: Self.isTokenCharacter) else {
                    self.skipListElement()
                    continue
                }
                self.skipWhitespace()

                if self.current == UInt8(ascii: "=") {
                    // An auth-param of the current challenge.
                    self.index += 1
                    if challenge != nil, let value = self.readValue() {
                        challenge!.parameters[token.lowercased()] = challenge!.parameters[token.lowercased()] ?? value
                    } else {
                        self.skipListElement()
                    }
                    continue
                }

                // A new challenge, followed by either a token68 or the first auth-param.
                if let finished = challenge {
                    challenges.append(finished)
                }
                challenge = HTTPAuthenticationChallenge(scheme: token)
                if let next = self.current, next != UInt8(ascii: ","), !self.isStartOfParameter(),
                    let token68 = self.read(while: Self.isToken68Character)
                {
                    challenge!.token68 = token68 + (self.read(while: { $0 == UInt8(ascii: "=") }) ?? "")
                }
            }
            if let finished = challenge {
                challenges.append(finished)
            }
        }

        /// Whether the input at the current position is `token BWS "=" BWS value`, rather than a token68 that ends
        /// with "=" padding.
        private func isStartOfParameter() -> Bool {
            var copy = self
            guard copy.read(while: Self.isTokenCharacter) != nil else { return false }
            copy.skipWhitespace()
            guard copy.current == UInt8(ascii: "=") else { return false }
            copy.index += 1
            copy.skipWhitespace()
            guard let next = copy.current else { return false }
            return next != UInt8(ascii: "=") && next != UInt8(ascii: ",")
        }

        /// Reads a quoted-string, or an unquoted value up to the next comma or whitespace. Unquoted values are read
        /// leniently, since some schemes send unquoted base64 (SCRAM's `data`, RFC 7804) and some servers unquoted
        /// Digest nonces.
        private mutating func readValue() -> String? {
            self.skipWhitespace()
            guard self.current == UInt8(ascii: "\"") else {
                return self.read {
                    $0 != UInt8(ascii: ",") && $0 != UInt8(ascii: " ") && $0 != UInt8(ascii: "\t")
                }
            }
            self.index += 1
            var value: [UInt8] = []
            while let byte = self.current {
                self.index += 1
                switch byte {
                case UInt8(ascii: "\""):
                    return String(decoding: value, as: UTF8.self)
                case UInt8(ascii: "\\"):
                    guard let escaped = self.current else { return nil }
                    self.index += 1
                    value.append(escaped)
                default:
                    value.append(byte)
                }
            }
            // Unterminated quoted-string
            return nil
        }

        private mutating func read(while predicate: (UInt8) -> Bool) -> String? {
            let start = self.index
            self.skip(while: predicate)
            guard self.index > start else { return nil }
            return String(decoding: self.bytes[start..<self.index], as: UTF8.self)
        }

        private mutating func skip(while predicate: (UInt8) -> Bool) {
            while let byte = self.current, predicate(byte) {
                self.index += 1
            }
        }

        private mutating func skipWhitespace() {
            self.skip { $0 == UInt8(ascii: " ") || $0 == UInt8(ascii: "\t") }
        }

        /// Skips to the next comma that is not inside a quoted-string.
        private mutating func skipListElement() {
            var inQuotes = false
            while let byte = self.current, inQuotes || byte != UInt8(ascii: ",") {
                if byte == UInt8(ascii: "\\") && inQuotes {
                    self.index += 1
                } else if byte == UInt8(ascii: "\"") {
                    inQuotes.toggle()
                }
                self.index += 1
            }
        }

        private static let tokenSymbols = Set("!#$%&'*+-.^_`|~".utf8)
        private static let token68Symbols = Set("-._~+/".utf8)

        private static func isAlphanumeric(_ byte: UInt8) -> Bool {
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte | 0x20)
                || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        }

        private static func isTokenCharacter(_ byte: UInt8) -> Bool {
            Self.isAlphanumeric(byte) || Self.tokenSymbols.contains(byte)
        }

        private static func isToken68Character(_ byte: UInt8) -> Bool {
            Self.isAlphanumeric(byte) || Self.token68Symbols.contains(byte)
        }
    }
}
