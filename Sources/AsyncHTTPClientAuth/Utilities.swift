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
import NIOCore
import NIOHTTP1

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Data
#else
import struct Foundation.Data
#endif

enum Base64 {
    static func encode(_ bytes: some Sequence<UInt8>) -> String {
        Data(bytes).base64EncodedString()
    }

    static func decode(_ string: String) -> [UInt8]? {
        Data(base64Encoded: string).map(Array.init)
    }
}

extension Sequence<UInt8> {
    var hexString: String {
        let digits = Array("0123456789abcdef".utf8)
        var result: [UInt8] = []
        for byte in self {
            result.append(digits[Int(byte >> 4)])
            result.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: result, as: UTF8.self)
    }
}

enum RandomBytes {
    static func generate(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}

extension String {
    /// The UTF-16 little endian encoding, which Windows calls "Unicode".
    var utf16LittleEndianBytes: [UInt8] {
        self.utf16.flatMap { [UInt8(truncatingIfNeeded: $0), UInt8(truncatingIfNeeded: $0 >> 8)] }
    }

    /// Escapes a string for a quoted-string (RFC 9110, section 5.6.4).
    var quotedStringEscaped: String {
        var result = ""
        for character in self {
            if character == "\"" || character == "\\" {
                result.append("\\")
            }
            result.append(character)
        }
        return result
    }
}

@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
extension HTTPClientRequest {
    /// The request-target as it appears in the request line: the authority for `CONNECT` requests, the path and
    /// query otherwise (RFC 9112, section 3.2).
    var requestTarget: String {
        if self.method == .CONNECT {
            return self.url
        }
        var url = Substring(self.url)
        if let fragment = url.firstIndex(of: "#") {
            url = url[..<fragment]
        }
        guard let schemeEnd = url.firstRange(of: "://") else {
            return url.isEmpty ? "/" : String(url)
        }
        let afterAuthority = url[schemeEnd.upperBound...]
        guard let pathStart = afterAuthority.firstIndex(where: { $0 == "/" || $0 == "?" }) else {
            return "/"
        }
        let target = afterAuthority[pathStart...]
        return target.first == "?" ? "/" + target : String(target)
    }

    /// Collects the body, so that it can be hashed, and replaces it with the collected bytes.
    mutating func collectBody(upTo maxBytes: Int) async throws -> ByteBuffer {
        guard let body = self.body else {
            return ByteBuffer()
        }
        var collected = ByteBuffer()
        for try await var part in body {
            guard collected.readableBytes + part.readableBytes <= maxBytes else {
                throw NIOTooManyBytesError(maxBytes: maxBytes)
            }
            collected.writeBuffer(&part)
        }
        self.body = .bytes(collected)
        return collected
    }
}
