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

import Crypto

/// The NTLM messages and the NTLMv2 computations of [MS-NLMP].
///
/// Only NTLMv2 with extended session security is implemented. Key exchange (`NTLMSSP_NEGOTIATE_KEY_EXCH`), signing
/// and sealing are not needed for HTTP and are not negotiated.
enum NTLM {
    static let signature: [UInt8] = Array("NTLMSSP".utf8) + [0]

    struct Flags: OptionSet {
        let rawValue: UInt32

        static let unicode = Flags(rawValue: 0x0000_0001)
        static let requestTarget = Flags(rawValue: 0x0000_0004)
        static let ntlm = Flags(rawValue: 0x0000_0200)
        static let alwaysSign = Flags(rawValue: 0x0000_8000)
        static let extendedSessionSecurity = Flags(rawValue: 0x0008_0000)
        static let targetInfo = Flags(rawValue: 0x0080_0000)
        static let version = Flags(rawValue: 0x0200_0000)
        static let bits128 = Flags(rawValue: 0x2000_0000)
        static let bits56 = Flags(rawValue: 0x8000_0000)

        static let client: Flags = [
            .unicode, .requestTarget, .ntlm, .alwaysSign, .extendedSessionSecurity, .targetInfo, .bits128, .bits56,
        ]
    }

    enum AVPairID: UInt16 {
        case eol = 0x0000
        case nbComputerName = 0x0001
        case nbDomainName = 0x0002
        case dnsComputerName = 0x0003
        case dnsDomainName = 0x0004
        case dnsTreeName = 0x0005
        case flags = 0x0006
        case timestamp = 0x0007
        case singleHost = 0x0008
        case targetName = 0x0009
        case channelBindings = 0x000A
    }

    struct AVPair: Equatable {
        var id: UInt16
        var value: [UInt8]
    }

    // MARK: Messages

    /// NEGOTIATE_MESSAGE ([MS-NLMP] 2.2.1.1)
    static func negotiateMessage(flags: Flags = .client) -> [UInt8] {
        var message = Self.signature
        message.appendLittleEndian(UInt32(1))
        message.appendLittleEndian(flags.rawValue)
        // DomainNameFields and WorkstationFields are empty.
        message.append(contentsOf: [UInt8](repeating: 0, count: 16))
        return message
    }

    /// CHALLENGE_MESSAGE ([MS-NLMP] 2.2.1.2)
    struct ChallengeMessage {
        var flags: Flags
        var serverChallenge: [UInt8]
        var targetInfo: [AVPair]
        var bytes: [UInt8]

        init(_ bytes: [UInt8]) throws {
            guard bytes.count >= 48, Array(bytes[0..<8]) == NTLM.signature, bytes.readUInt32(at: 8) == 2 else {
                throw HTTPClientAuthenticationError.malformedChallenge
            }
            self.bytes = bytes
            self.flags = Flags(rawValue: bytes.readUInt32(at: 20))
            self.serverChallenge = Array(bytes[24..<32])
            let targetInfo = try bytes.readField(at: 40)
            self.targetInfo = try NTLM.parseAVPairs(targetInfo)
        }

        var timestamp: [UInt8]? {
            self.targetInfo.first(where: { $0.id == AVPairID.timestamp.rawValue })?.value
        }
    }

    /// AUTHENTICATE_MESSAGE ([MS-NLMP] 2.2.1.3) with a MIC.
    static func authenticateMessage(
        negotiate: [UInt8],
        challenge: ChallengeMessage,
        user: String,
        domain: String,
        password: String,
        workstation: String,
        targetName: String?,
        channelBinding: [UInt8]?,
        clientChallenge: [UInt8],
        currentTime: [UInt8]
    ) -> [UInt8] {
        let responseKeyNT = Self.ntowfv2(password: password, user: user, domain: domain)

        // With a server timestamp, the MIC must be sent and the LM response is zero ([MS-NLMP] 3.1.5.1.2).
        let serverTimestamp = challenge.timestamp
        var targetInfo = challenge.targetInfo.filter { $0.id != AVPairID.eol.rawValue }
        if serverTimestamp != nil {
            targetInfo.append(AVPair(id: AVPairID.flags.rawValue, value: [0x02, 0, 0, 0]))
        }
        let bindingHash =
            channelBinding.map {
                Array(Insecure.MD5.hash(data: TLSChannelBinding.gssChannelBindingsStructure(applicationData: $0)))
            } ?? [UInt8](repeating: 0, count: 16)
        targetInfo.append(AVPair(id: AVPairID.channelBindings.rawValue, value: bindingHash))
        if let targetName {
            targetInfo.append(AVPair(id: AVPairID.targetName.rawValue, value: targetName.utf16LittleEndianBytes))
        }
        targetInfo.append(AVPair(id: AVPairID.eol.rawValue, value: []))

        let temp = Self.clientBlob(
            time: serverTimestamp ?? currentTime,
            clientChallenge: clientChallenge,
            targetInfo: Self.encodeAVPairs(targetInfo)
        )
        let ntProofStr = Self.hmacMD5(key: responseKeyNT, challenge.serverChallenge + temp)
        let ntResponse = ntProofStr + temp
        let lmResponse: [UInt8]
        if serverTimestamp != nil {
            lmResponse = [UInt8](repeating: 0, count: 24)
        } else {
            lmResponse = Self.hmacMD5(key: responseKeyNT, challenge.serverChallenge + clientChallenge) + clientChallenge
        }
        // Without key exchange, the exported session key is the session base key.
        let exportedSessionKey = Self.hmacMD5(key: responseKeyNT, ntProofStr)

        let flags = Flags.client.intersection(challenge.flags).union([.unicode, .ntlm])
        let payloads = [
            lmResponse,
            ntResponse,
            domain.utf16LittleEndianBytes,
            user.utf16LittleEndianBytes,
            workstation.utf16LittleEndianBytes,
            [],  // EncryptedRandomSessionKey
        ]

        var message = Self.signature
        message.appendLittleEndian(UInt32(3))
        // Fields, flags, version and MIC take 88 bytes.
        var offset = 88
        for payload in payloads {
            message.appendLittleEndian(UInt16(payload.count))
            message.appendLittleEndian(UInt16(payload.count))
            message.appendLittleEndian(UInt32(offset))
            offset += payload.count
        }
        message.appendLittleEndian(flags.rawValue)
        message.append(contentsOf: [UInt8](repeating: 0, count: 8))  // Version
        let micOffset = message.count
        message.append(contentsOf: [UInt8](repeating: 0, count: 16))  // MIC
        for payload in payloads {
            message.append(contentsOf: payload)
        }

        let mic = Self.hmacMD5(key: exportedSessionKey, negotiate + challenge.bytes + message)
        message.replaceSubrange(micOffset..<(micOffset + 16), with: mic)
        return message
    }

    // MARK: NTLMv2 ([MS-NLMP] 3.3.2)

    static func ntowfv2(password: String, user: String, domain: String) -> [UInt8] {
        let ntHash = MD4.hash(password.utf16LittleEndianBytes)
        return Self.hmacMD5(key: ntHash, (user.uppercased() + domain).utf16LittleEndianBytes)
    }

    /// The `temp` structure of NTOWFv2 based responses.
    static func clientBlob(time: [UInt8], clientChallenge: [UInt8], targetInfo: [UInt8]) -> [UInt8] {
        var blob: [UInt8] = [0x01, 0x01, 0, 0, 0, 0, 0, 0]
        blob.append(contentsOf: time)
        blob.append(contentsOf: clientChallenge)
        blob.append(contentsOf: [0, 0, 0, 0])
        blob.append(contentsOf: targetInfo)
        blob.append(contentsOf: [0, 0, 0, 0])
        return blob
    }

    static func hmacMD5(key: [UInt8], _ message: [UInt8]) -> [UInt8] {
        Array(HMAC<Insecure.MD5>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    /// The current time as a Windows FILETIME: 100 nanosecond intervals since January 1, 1601.
    static func fileTime(unixTimeInterval: Double) -> [UInt8] {
        let intervals = UInt64((unixTimeInterval + 11_644_473_600) * 10_000_000)
        var bytes: [UInt8] = []
        bytes.appendLittleEndian(intervals)
        return bytes
    }

    static func parseAVPairs(_ bytes: [UInt8]) throws -> [AVPair] {
        var pairs: [AVPair] = []
        var offset = 0
        while offset + 4 <= bytes.count {
            let id = bytes.readUInt16(at: offset)
            let length = Int(bytes.readUInt16(at: offset + 2))
            guard offset + 4 + length <= bytes.count else {
                throw HTTPClientAuthenticationError.malformedChallenge
            }
            pairs.append(AVPair(id: id, value: Array(bytes[(offset + 4)..<(offset + 4 + length)])))
            offset += 4 + length
            if id == AVPairID.eol.rawValue {
                break
            }
        }
        return pairs
    }

    static func encodeAVPairs(_ pairs: [AVPair]) -> [UInt8] {
        var bytes: [UInt8] = []
        for pair in pairs {
            bytes.appendLittleEndian(pair.id)
            bytes.appendLittleEndian(UInt16(pair.value.count))
            bytes.append(contentsOf: pair.value)
        }
        return bytes
    }
}

extension Array where Element == UInt8 {
    func readUInt16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) | UInt16(self[offset + 1]) << 8
    }

    func readUInt32(at offset: Int) -> UInt32 {
        UInt32(self.readUInt16(at: offset)) | UInt32(self.readUInt16(at: offset + 2)) << 16
    }

    /// Reads the payload a `{Len, MaxLen, BufferOffset}` field at `offset` points to.
    func readField(at offset: Int) throws -> [UInt8] {
        let length = Int(self.readUInt16(at: offset))
        let start = Int(self.readUInt32(at: offset + 4))
        guard start + length <= self.count else {
            throw HTTPClientAuthenticationError.malformedChallenge
        }
        return Array(self[start..<(start + length)])
    }
}
