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
import NIOCore
import NIOHTTP1

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Date
#else
import struct Foundation.Date
#endif

/// Signs requests with AWS Signature Version 4 (header based).
///
/// Unlike challenge based schemes, request signing needs no round trip: every request is signed before it is sent.
///
/// - Note: Paths are encoded once, as S3 expects. Other services expect already encoded paths to be encoded twice.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
public struct AWSSignatureV4Authenticator: HTTPClientAuthenticator {
    public struct Credentials: Sendable, Hashable {
        public var accessKeyID: String
        public var secretAccessKey: String
        public var sessionToken: String?

        public init(accessKeyID: String, secretAccessKey: String, sessionToken: String? = nil) {
            self.accessKeyID = accessKeyID
            self.secretAccessKey = secretAccessKey
            self.sessionToken = sessionToken
        }
    }

    public enum Payload: Sendable, Hashable {
        /// The body is collected in memory and its SHA-256 hash is signed.
        case signed
        /// The body is not signed (`UNSIGNED-PAYLOAD`). Only some services, like S3, accept that.
        case unsigned
    }

    public var credentials: Credentials
    public var region: String
    public var service: String
    public var payload: Payload
    private let clock: @Sendable () -> Date

    /// The largest body that is collected to be signed.
    static let maximumSignedBodySize = 16 * 1024 * 1024

    public init(credentials: Credentials, region: String, service: String, payload: Payload = .signed) {
        self.init(credentials: credentials, region: region, service: service, payload: payload, clock: { Date() })
    }

    init(
        credentials: Credentials,
        region: String,
        service: String,
        payload: Payload,
        clock: @escaping @Sendable () -> Date
    ) {
        self.credentials = credentials
        self.region = region
        self.service = service
        self.payload = payload
        self.clock = clock
    }

    public func authenticate(
        _ request: HTTPClientRequest,
        exchange: HTTPClientExchange
    ) async throws -> HTTPClientResponse {
        var request = request
        try await self.sign(&request)
        return try await exchange.send(request)
    }

    /// Adds `Authorization`, `x-amz-date` and the other signed headers to the request.
    func sign(_ request: inout HTTPClientRequest) async throws {
        let payloadHash: String
        switch self.payload {
        case .signed:
            let body = try await request.collectBody(upTo: Self.maximumSignedBodySize)
            payloadHash = SHA256.hash(data: Array(body.readableBytesView)).hexString
        case .unsigned:
            payloadHash = "UNSIGNED-PAYLOAD"
        }

        let (date, dateTime) = Self.timestamps(self.clock())
        let url = AWSURL(request.url)
        request.headers.replaceOrAdd(name: "host", value: url.host)
        request.headers.replaceOrAdd(name: "x-amz-date", value: dateTime)
        if let sessionToken = self.credentials.sessionToken {
            request.headers.replaceOrAdd(name: "x-amz-security-token", value: sessionToken)
        }
        if self.service == "s3" || self.payload == .unsigned {
            request.headers.replaceOrAdd(name: "x-amz-content-sha256", value: payloadHash)
        }

        let (canonicalRequest, signedHeaders) = Self.canonicalRequest(
            method: request.method.rawValue,
            url: url,
            headers: request.headers,
            payloadHash: payloadHash
        )
        let scope = "\(date)/\(self.region)/\(self.service)/aws4_request"
        let stringToSign = [
            "AWS4-HMAC-SHA256",
            dateTime,
            scope,
            SHA256.hash(data: Array(canonicalRequest.utf8)).hexString,
        ].joined(separator: "\n")

        var key = Array("AWS4\(self.credentials.secretAccessKey)".utf8)
        for component in [date, self.region, self.service, "aws4_request"] {
            key = Self.hmac(key: key, component)
        }
        let signature = Self.hmac(key: key, stringToSign).hexString

        request.headers.replaceOrAdd(
            name: "Authorization",
            value:
                "AWS4-HMAC-SHA256 Credential=\(self.credentials.accessKeyID)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
        )
    }

    static func canonicalRequest(
        method: String,
        url: AWSURL,
        headers: HTTPHeaders,
        payloadHash: String
    ) -> (canonicalRequest: String, signedHeaders: String) {
        var canonicalHeaders: [String: [String]] = [:]
        for (name, value) in headers {
            let collapsed = value.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ")
            canonicalHeaders[name.lowercased(), default: []].append(collapsed)
        }
        let names = canonicalHeaders.keys.sorted()
        let canonicalRequest = [
            method,
            url.canonicalPath,
            url.canonicalQuery,
            names.map { "\($0):\(canonicalHeaders[$0]!.joined(separator: ","))\n" }.joined(),
            names.joined(separator: ";"),
            payloadHash,
        ].joined(separator: "\n")
        return (canonicalRequest, names.joined(separator: ";"))
    }

    /// `yyyyMMdd` and `yyyyMMdd'T'HHmmss'Z'` in UTC.
    static func timestamps(_ date: Date) -> (date: String, dateTime: String) {
        let seconds = Int(date.timeIntervalSince1970.rounded(.down))
        let (days, secondOfDay) = seconds.quotientAndRemainder(dividingBy: 86_400)
        // Howard Hinnant's civil_from_days
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let dayOfEra = z - era * 146_097
        let yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146_096) / 365
        let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)
        let mp = (5 * dayOfYear + 2) / 153
        let day = dayOfYear - (153 * mp + 2) / 5 + 1
        let month = mp < 10 ? mp + 3 : mp - 9
        let year = yearOfEra + era * 400 + (month <= 2 ? 1 : 0)

        func pad(_ value: Int, _ width: Int) -> String {
            let string = String(value)
            return String(repeating: "0", count: max(0, width - string.count)) + string
        }
        let dateString = pad(year, 4) + pad(month, 2) + pad(day, 2)
        let time = pad(secondOfDay / 3600, 2) + pad(secondOfDay % 3600 / 60, 2) + pad(secondOfDay % 60, 2)
        return (dateString, "\(dateString)T\(time)Z")
    }

    private static func hmac(key: [UInt8], _ message: String) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: Array(message.utf8), using: SymmetricKey(data: key)))
    }
}

/// The parts of a URL that SigV4 signs.
struct AWSURL {
    var host: String
    var path: String
    var query: String

    init(_ url: String) {
        var rest = Substring(url)
        if let fragment = rest.firstIndex(of: "#") {
            rest = rest[..<fragment]
        }
        if let schemeEnd = rest.firstRange(of: "://") {
            rest = rest[schemeEnd.upperBound...]
        }
        let authorityEnd = rest.firstIndex(where: { $0 == "/" || $0 == "?" }) ?? rest.endIndex
        var authority = rest[..<authorityEnd]
        if let userInfoEnd = authority.lastIndex(of: "@") {
            authority = authority[authority.index(after: userInfoEnd)...]
        }
        // Default ports are omitted from the Host header.
        if authority.hasSuffix(":443") || authority.hasSuffix(":80") {
            authority = authority[..<authority.lastIndex(of: ":")!]
        }
        self.host = String(authority)
        let pathAndQuery = rest[authorityEnd...]
        if let queryStart = pathAndQuery.firstIndex(of: "?") {
            self.path = String(pathAndQuery[..<queryStart])
            self.query = String(pathAndQuery[pathAndQuery.index(after: queryStart)...])
        } else {
            self.path = String(pathAndQuery)
            self.query = ""
        }
    }

    var canonicalPath: String {
        guard !self.path.isEmpty else { return "/" }
        return self.path.split(separator: "/", omittingEmptySubsequences: false)
            .map { Self.encode(Self.decode($0)) }
            .joined(separator: "/")
    }

    var canonicalQuery: String {
        var parameters: [(name: String, value: String)] = []
        for pair in self.query.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let value: Substring = parts.count > 1 ? parts[1] : ""
            parameters.append((Self.encode(Self.decode(parts[0])), Self.encode(Self.decode(value))))
        }
        parameters.sort { lhs, rhs in
            lhs.name == rhs.name ? lhs.value < rhs.value : lhs.name < rhs.name
        }
        return parameters.map { "\($0.name)=\($0.value)" }.joined(separator: "&")
    }

    /// Percent encodes everything but unreserved characters (RFC 3986).
    static func encode(_ bytes: [UInt8]) -> String {
        var result = ""
        for byte in bytes {
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
                UInt8(ascii: "~"):
                result.append(Character(Unicode.Scalar(byte)))
            default:
                result += "%" + [byte].hexString.uppercased()
            }
        }
        return result
    }

    static func decode(_ string: Substring) -> [UInt8] {
        var bytes: [UInt8] = []
        var iterator = Array(string.utf8).makeIterator()
        while let byte = iterator.next() {
            if byte == UInt8(ascii: "%"), let high = iterator.next(), let low = iterator.next(),
                let value = UInt8(String(decoding: [high, low], as: UTF8.self), radix: 16)
            {
                bytes.append(value)
            } else {
                bytes.append(byte)
            }
        }
        return bytes
    }
}
