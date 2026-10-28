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
import NIOHTTP1
import SwiftASN1
import X509
import XCTest

@testable import AsyncHTTPClientAuth

#if canImport(FoundationEssentials)
import struct FoundationEssentials.Date
#else
import struct Foundation.Date
#endif

/// Known answer tests from the specifications.
@available(macOS 10.15, iOS 13.0, watchOS 6.0, tvOS 13.0, *)
final class AuthenticationVectorTests: XCTestCase {
    // MARK: MD4 (RFC 1320, appendix A.5)

    func testMD4() {
        let vectors = [
            ("", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            ("a", "bde52cb31de33e46245e05fbdbd6fb24"),
            ("abc", "a448017aaf21d8525fc10ae87aa6729d"),
            ("message digest", "d9130a8164549fe818874806e1c7014b"),
            ("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536"
            ),
        ]
        for (message, digest) in vectors {
            XCTAssertEqual(MD4.hash(Array(message.utf8)).hexString, digest, message)
        }
    }

    // MARK: NTLMv2 ([MS-NLMP] 4.2.4)

    func testNTLMv2() {
        let responseKeyNT = NTLM.ntowfv2(password: "Password", user: "User", domain: "Domain")
        XCTAssertEqual(responseKeyNT.hexString, "0c868a403bfd7a93a3001ef22ef02e3f")

        let serverChallenge: [UInt8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        let clientChallenge = [UInt8](repeating: 0xaa, count: 8)
        let targetInfo = NTLM.encodeAVPairs([
            .init(id: NTLM.AVPairID.nbDomainName.rawValue, value: "Domain".utf16LittleEndianBytes),
            .init(id: NTLM.AVPairID.nbComputerName.rawValue, value: "Server".utf16LittleEndianBytes),
            .init(id: NTLM.AVPairID.eol.rawValue, value: []),
        ])
        let temp = NTLM.clientBlob(
            time: [UInt8](repeating: 0, count: 8),
            clientChallenge: clientChallenge,
            targetInfo: targetInfo
        )
        let ntProofStr = NTLM.hmacMD5(key: responseKeyNT, serverChallenge + temp)
        XCTAssertEqual(ntProofStr.hexString, "68cd0ab851e51c96aabc927bebef6a1c")

        let sessionBaseKey = NTLM.hmacMD5(key: responseKeyNT, ntProofStr)
        XCTAssertEqual(sessionBaseKey.hexString, "8de40ccadbc14a82f15cb0ad0de95ca3")

        let lmv2 = NTLM.hmacMD5(key: responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
        XCTAssertEqual(lmv2.hexString, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
    }

    func testNTLMMessages() throws {
        let negotiate = NTLM.negotiateMessage()
        XCTAssertEqual(Array(negotiate[0..<8]), NTLM.signature)
        XCTAssertEqual(negotiate.readUInt32(at: 8), 1)

        let challengeBytes = NTLMTestServer.challengeMessage(
            serverChallenge: [1, 2, 3, 4, 5, 6, 7, 8],
            timestamp: [UInt8](repeating: 1, count: 8)
        )
        let challenge = try NTLM.ChallengeMessage(challengeBytes)
        XCTAssertEqual(challenge.serverChallenge, [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(challenge.timestamp, [UInt8](repeating: 1, count: 8))

        let authenticate = NTLM.authenticateMessage(
            negotiate: negotiate,
            challenge: challenge,
            user: "User",
            domain: "Domain",
            password: "Password",
            workstation: "COMPUTER",
            targetName: "HTTP/example.com",
            channelBinding: Array("tls-server-end-point:abc".utf8),
            clientChallenge: [UInt8](repeating: 0xaa, count: 8),
            currentTime: [UInt8](repeating: 0, count: 8)
        )
        let verified = try NTLMTestServer.verify(
            authenticate: authenticate,
            negotiate: negotiate,
            challenge: challengeBytes,
            password: "Password"
        )
        XCTAssertEqual(verified.user, "User")
        XCTAssertEqual(verified.domain, "Domain")
        XCTAssertTrue(verified.micIsValid)
        XCTAssertEqual(
            verified.channelBindings,
            Array(
                Insecure.MD5.hash(
                    data: TLSChannelBinding.gssChannelBindingsStructure(
                        applicationData: Array("tls-server-end-point:abc".utf8)
                    )
                )
            )
        )
        XCTAssertEqual(verified.targetName, "HTTP/example.com")
        // With a server timestamp, the LM response is zero.
        XCTAssertEqual(try authenticate.readField(at: 12), [UInt8](repeating: 0, count: 24))
    }

    // MARK: Digest (RFC 7616, section 3.9.1)

    func testDigest() throws {
        let challengeHeader =
            #"Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#
        let parsed = try XCTUnwrap(HTTPAuthenticationChallenge.parse(headerValues: [challengeHeader]).first)
        var challenge = try XCTUnwrap(DigestAuthenticator.Challenge(parsed))
        XCTAssertEqual(challenge.qop, .auth)

        func response(_ algorithm: DigestAuthenticator.Algorithm) throws -> String {
            challenge.algorithm = algorithm
            var session = DigestAuthenticator.Session(challenge: challenge)
            session.nonceCount = 1
            let authorization = DigestAuthenticator.authorization(
                username: "Mufasa",
                password: "Circle of Life",
                method: "GET",
                uri: "/dir/index.html",
                entityBody: [],
                session: session,
                cnonce: "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
            )
            let fields = try XCTUnwrap(
                HTTPAuthenticationChallenge.parse(headerValues: [authorization.headerValue]).first
            )
            XCTAssertEqual(fields[parameter: "nc"], "00000001")
            XCTAssertEqual(fields[parameter: "uri"], "/dir/index.html")
            XCTAssertEqual(fields[parameter: "opaque"], "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS")
            return try XCTUnwrap(fields[parameter: "response"])
        }

        XCTAssertEqual(try response(.sha256), "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1")
        XCTAssertEqual(try response(.md5), "8ca523f5e9506fed4657c9700eebdbec")
    }

    func testRequestTarget() {
        func target(_ url: String, method: HTTPMethod = .GET) -> String {
            var request = HTTPClientRequest(url: url)
            request.method = method
            return request.requestTarget
        }
        XCTAssertEqual(target("https://example.com"), "/")
        XCTAssertEqual(target("https://example.com/a/b?c=d#e"), "/a/b?c=d")
        XCTAssertEqual(target("https://example.com?c=d"), "/?c=d")
        XCTAssertEqual(target("example.com:443", method: .CONNECT), "example.com:443")
    }

    // MARK: SCRAM

    func testSCRAMSHA256() throws {
        // RFC 7677, section 3
        var client = SCRAMClient(mechanism: .sha256, username: "user", nonce: "rOprNGfwEbeRWgbNEkqO")
        XCTAssertEqual(client.clientFirstMessage, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO")
        let clientFinal = try client.clientFinalMessage(
            serverFirstMessage: "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
        ) { salt, iterations in
            try SCRAMClient.saltedPassword(mechanism: .sha256, password: "pencil", salt: salt, iterations: iterations)
        }
        XCTAssertEqual(
            clientFinal,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        )
        XCTAssertNoThrow(try client.verify(serverFinalMessage: "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="))
        XCTAssertThrowsError(try client.verify(serverFinalMessage: "v=AAAATRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")) {
            XCTAssertEqual($0 as? HTTPClientAuthenticationError, .serverSignatureMismatch)
        }
    }

    func testSCRAMSHA1() throws {
        // RFC 5802, section 5
        var client = SCRAMClient(mechanism: .sha1, username: "user", nonce: "fyko+d2lbbFgONRv9qkxdawL")
        let clientFinal = try client.clientFinalMessage(
            serverFirstMessage: "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        ) { salt, iterations in
            try SCRAMClient.saltedPassword(mechanism: .sha1, password: "pencil", salt: salt, iterations: iterations)
        }
        XCTAssertEqual(
            clientFinal,
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="
        )
        XCTAssertNoThrow(try client.verify(serverFinalMessage: "v=rmF9pqV8S7suAoZWja4dJRkFsKQ="))
    }

    func testSCRAMRejectsForeignNonce() {
        var client = SCRAMClient(mechanism: .sha256, username: "user", nonce: "abc")
        XCTAssertThrowsError(
            try client.clientFinalMessage(serverFirstMessage: "r=xyz123,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096") { _, _ in []
            }
        ) {
            XCTAssertEqual($0 as? HTTPClientAuthenticationError, .malformedChallenge)
        }
    }

    // MARK: AWS Signature Version 4 (aws-sig-v4-test-suite, get-vanilla)

    func testSigV4GetVanilla() async throws {
        let authenticator = AWSSignatureV4Authenticator(
            credentials: .init(accessKeyID: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            region: "us-east-1",
            service: "service",
            payload: .signed,
            clock: { Date(timeIntervalSince1970: 1_440_938_160) }
        )
        var request = HTTPClientRequest(url: "https://example.amazonaws.com/")
        try await authenticator.sign(&request)
        XCTAssertEqual(request.headers.first(name: "x-amz-date"), "20150830T123600Z")
        XCTAssertEqual(
            request.headers.first(name: "Authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        )
    }

    func testSigV4CanonicalQuery() {
        let url = AWSURL("https://example.com:443/a%20b/c?b=2&a=1&a=0&space=x%20y")
        XCTAssertEqual(url.host, "example.com")
        XCTAssertEqual(url.canonicalPath, "/a%20b/c")
        XCTAssertEqual(url.canonicalQuery, "a=0&a=1&b=2&space=x%20y")
        XCTAssertEqual(
            AWSSignatureV4Authenticator.timestamps(Date(timeIntervalSince1970: 951_782_400)).date,
            "20000229"
        )
    }

    // MARK: Channel binding (RFC 5929)

    func testServerEndPointUsesTheCertificatesHashAlgorithm() throws {
        let key = P384.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("example.com") }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(key.publicKey),
            notValidBefore: Date(timeIntervalSince1970: 0),
            notValidAfter: Date(timeIntervalSince1970: 4_000_000_000),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: .init(),
            issuerPrivateKey: .init(key)
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        let der = serializer.serializedBytes

        let binding = TLSChannelBinding.serverEndPoint(certificate: der)
        XCTAssertEqual(binding, Array("tls-server-end-point:".utf8) + Array(SHA384.hash(data: der)))
        // Unparsable certificates fall back to SHA-256.
        XCTAssertEqual(TLSChannelBinding.serverEndPoint(certificate: [1, 2, 3]).count, 21 + 32)
    }
}
