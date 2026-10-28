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
import NIOHTTP1
import XCTest

final class HTTPAuthenticationChallengeTests: XCTestCase {
    func testSingleChallengeWithParameters() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            #"Basic realm="simple", charset="UTF-8""#
        ])
        XCTAssertEqual(
            challenges,
            [.init(scheme: "Basic", parameters: ["realm": "simple", "charset": "UTF-8"])]
        )
        XCTAssertTrue(challenges[0].matches(scheme: "basic"))
        XCTAssertEqual(challenges[0][parameter: "Realm"], "simple")
    }

    func testMultipleChallengesInOneValue() {
        // RFC 9110, section 11.6.1
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            #"Basic realm="simple", Newauth realm="apps", type=1, title="Login to \"apps\"""#
        ])
        XCTAssertEqual(
            challenges,
            [
                .init(scheme: "Basic", parameters: ["realm": "simple"]),
                .init(scheme: "Newauth", parameters: ["realm": "apps", "type": "1", "title": #"Login to "apps""#]),
            ]
        )
    }

    func testChallengesAcrossValues() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: ["Negotiate", "NTLM", "Basic realm=x"])
        XCTAssertEqual(challenges.map(\.scheme), ["Negotiate", "NTLM", "Basic"])
    }

    func testToken68() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            "Negotiate YIIBdgYGKwYBBQUCoIIBajCC/AWg+xk=, NTLM TlRMTVNTUAACAAAA==, Basic realm=x"
        ])
        XCTAssertEqual(
            challenges,
            [
                .init(scheme: "Negotiate", token68: "YIIBdgYGKwYBBQUCoIIBajCC/AWg+xk="),
                .init(scheme: "NTLM", token68: "TlRMTVNTUAACAAAA=="),
                .init(scheme: "Basic", parameters: ["realm": "x"]),
            ]
        )
    }

    func testQuotedCommasAndEmptyElements() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            #" ,Digest realm="a, b", nonce="n" , , qop="auth,auth-int", algorithm=SHA-256 ,"#
        ])
        XCTAssertEqual(
            challenges,
            [
                .init(
                    scheme: "Digest",
                    parameters: ["realm": "a, b", "nonce": "n", "qop": "auth,auth-int", "algorithm": "SHA-256"]
                )
            ]
        )
    }

    func testWhitespaceAroundEqualsAndRepeatedParameters() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            #"Bearer realm = "example", error="invalid_token", realm="ignored""#
        ])
        XCTAssertEqual(
            challenges,
            [.init(scheme: "Bearer", parameters: ["realm": "example", "error": "invalid_token"])]
        )
    }

    func testMalformedPartsAreSkipped() {
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            #"=broken, realm="orphan", Basic realm="ok", Digest nonce="unterminated"#
        ])
        XCTAssertEqual(challenges, [.init(scheme: "Basic", parameters: ["realm": "ok"]), .init(scheme: "Digest")])
    }

    func testUnquotedBase64Values() {
        // RFC 7804 sends base64 data unquoted, although "/" and "=" are not token characters.
        let challenges = HTTPAuthenticationChallenge.parse(headerValues: [
            "SCRAM-SHA-256 sid=AAAABBBBCCCCDDDD, data=cj1yT3By/k5H+ZndF==, Digest nonce=a/b="
        ])
        XCTAssertEqual(
            challenges,
            [
                .init(scheme: "SCRAM-SHA-256", parameters: ["sid": "AAAABBBBCCCCDDDD", "data": "cj1yT3By/k5H+ZndF=="]),
                .init(scheme: "Digest", parameters: ["nonce": "a/b="]),
            ]
        )
    }

    func testParameterList() {
        XCTAssertEqual(
            HTTPAuthenticationChallenge.parseParameters(#"nextnonce="abc", qop=auth, rspauth="d,e", nc=00000001"#),
            ["nextnonce": "abc", "qop": "auth", "rspauth": "d,e", "nc": "00000001"]
        )
    }

    func testResponseChallengesForPeer() {
        let response = HTTPClientResponse(
            status: .proxyAuthenticationRequired,
            headers: ["WWW-Authenticate": "Basic realm=origin", "Proxy-Authenticate": "Basic realm=proxy"]
        )
        let origin = HTTPClientExchange.Peer(kind: .origin, scheme: "https", host: "example.com", port: 443)
        let proxy = HTTPClientExchange.Peer(kind: .proxy, scheme: "http", host: "proxy", port: 3128)
        XCTAssertEqual(response.authenticationChallenges(for: origin).first?[parameter: "realm"], "origin")
        XCTAssertEqual(response.authenticationChallenges(for: proxy).first?[parameter: "realm"], "proxy")
        XCTAssertEqual(proxy.challengeStatus, .proxyAuthenticationRequired)
        XCTAssertEqual(proxy.credentialsHeaderName, "Proxy-Authorization")
        XCTAssertEqual(origin.challengeStatus, .unauthorized)
        XCTAssertEqual(origin.credentialsHeaderName, "Authorization")
    }
}
