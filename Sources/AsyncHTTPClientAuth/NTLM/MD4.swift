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

/// MD4 (RFC 1320). NTLM needs it to derive keys from passwords, but swift-crypto doesn't provide it.
///
/// - Warning: MD4 is broken. Don't use it for anything but NTLM.
enum MD4 {
    static func hash(_ message: [UInt8]) -> [UInt8] {
        var a: UInt32 = 0x6745_2301
        var b: UInt32 = 0xefcd_ab89
        var c: UInt32 = 0x98ba_dcfe
        var d: UInt32 = 0x1032_5476

        var padded = message
        padded.append(0x80)
        while padded.count % 64 != 56 {
            padded.append(0)
        }
        padded.appendLittleEndian(UInt64(message.count) &* 8)

        @inline(__always) func rotateLeft(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }

        for blockStart in stride(from: 0, to: padded.count, by: 64) {
            var x = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                let offset = blockStart + i * 4
                x[i] =
                    UInt32(padded[offset]) | UInt32(padded[offset + 1]) << 8 | UInt32(padded[offset + 2]) << 16
                    | UInt32(padded[offset + 3]) << 24
            }
            let (aa, bb, cc, dd) = (a, b, c, d)

            func f(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (~x & z) }
            func g(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }
            func h(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }

            // Round 1
            for i in stride(from: 0, to: 16, by: 4) {
                a = rotateLeft(a &+ f(b, c, d) &+ x[i], 3)
                d = rotateLeft(d &+ f(a, b, c) &+ x[i + 1], 7)
                c = rotateLeft(c &+ f(d, a, b) &+ x[i + 2], 11)
                b = rotateLeft(b &+ f(c, d, a) &+ x[i + 3], 19)
            }
            // Round 2
            for i in 0..<4 {
                a = rotateLeft(a &+ g(b, c, d) &+ x[i] &+ 0x5A82_7999, 3)
                d = rotateLeft(d &+ g(a, b, c) &+ x[i + 4] &+ 0x5A82_7999, 5)
                c = rotateLeft(c &+ g(d, a, b) &+ x[i + 8] &+ 0x5A82_7999, 9)
                b = rotateLeft(b &+ g(c, d, a) &+ x[i + 12] &+ 0x5A82_7999, 13)
            }
            // Round 3
            for i in [0, 2, 1, 3] {
                a = rotateLeft(a &+ h(b, c, d) &+ x[i] &+ 0x6ED9_EBA1, 3)
                d = rotateLeft(d &+ h(a, b, c) &+ x[i + 8] &+ 0x6ED9_EBA1, 9)
                c = rotateLeft(c &+ h(d, a, b) &+ x[i + 4] &+ 0x6ED9_EBA1, 11)
                b = rotateLeft(b &+ h(c, d, a) &+ x[i + 12] &+ 0x6ED9_EBA1, 15)
            }

            a = a &+ aa
            b = b &+ bb
            c = c &+ cc
            d = d &+ dd
        }

        var digest: [UInt8] = []
        for word in [a, b, c, d] {
            digest.appendLittleEndian(word)
        }
        return digest
    }
}
