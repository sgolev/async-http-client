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
import NIOConcurrencyHelpers
import NIOCore
import NIOHTTP1
import NIOPosix

@testable import AsyncHTTPClientAuth

/// State of a single connection to the ``AuthTestServer``. Only accessed on the server's event loop.
final class TestConnectionState: @unchecked Sendable {
    let id: Int
    var values: [String: Any] = [:]

    init(id: Int) {
        self.id = id
    }
}

struct TestResponse {
    var status: HTTPResponseStatus
    var headers: HTTPHeaders = [:]
    var body: String = ""
}

/// An HTTP/1.1 server that answers every request with `responder`.
final class AuthTestServer: Sendable {
    typealias Responder = @Sendable (HTTPRequestHead, TestConnectionState) -> TestResponse

    private let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    private let channel: Channel
    private let counters = NIOLockedValueBox((connections: 0, requests: 0))

    var baseURL: String { "http://127.0.0.1:\(self.channel.localAddress!.port!)" }
    var connections: Int { self.counters.withLockedValue { $0.connections } }
    var requests: Int { self.counters.withLockedValue { $0.requests } }

    init(responder: @escaping Responder) {
        let counters = self.counters
        self.channel = try! ServerBootstrap(group: self.group)
            .childChannelInitializer { channel in
                let id = counters.withLockedValue {
                    $0.connections += 1
                    return $0.connections
                }
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.configureHTTPServerPipeline()
                    try channel.pipeline.syncOperations.addHandler(
                        Handler(state: TestConnectionState(id: id), responder: responder, counters: counters)
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0).wait()
    }

    func shutdown() throws {
        try self.group.syncShutdownGracefully()
    }

    private final class Handler: ChannelInboundHandler {
        typealias InboundIn = HTTPServerRequestPart
        typealias OutboundOut = HTTPServerResponsePart

        let state: TestConnectionState
        let responder: Responder
        let counters: NIOLockedValueBox<(connections: Int, requests: Int)>
        var head: HTTPRequestHead?

        init(
            state: TestConnectionState,
            responder: @escaping Responder,
            counters: NIOLockedValueBox<(connections: Int, requests: Int)>
        ) {
            self.state = state
            self.responder = responder
            self.counters = counters
        }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            switch self.unwrapInboundIn(data) {
            case .head(let head):
                self.head = head
            case .body:
                break
            case .end:
                guard let head = self.head else { return }
                self.counters.withLockedValue { $0.requests += 1 }
                var response = self.responder(head, self.state)
                response.headers.replaceOrAdd(name: "Content-Length", value: "\(response.body.utf8.count)")
                context.write(
                    self.wrapOutboundOut(
                        .head(.init(version: .http1_1, status: response.status, headers: response.headers))
                    ),
                    promise: nil
                )
                context.write(self.wrapOutboundOut(.body(.byteBuffer(ByteBuffer(string: response.body)))), promise: nil)
                context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)
            }
        }
    }
}

/// The server side of NTLM, as far as the tests need it.
enum NTLMTestServer {
    struct Verified {
        var user: String
        var domain: String
        var micIsValid: Bool
        var channelBindings: [UInt8]?
        var targetName: String?
    }

    struct VerificationFailed: Error {}

    static func challengeMessage(serverChallenge: [UInt8], timestamp: [UInt8]) -> [UInt8] {
        let targetInfo = NTLM.encodeAVPairs([
            .init(id: NTLM.AVPairID.nbDomainName.rawValue, value: "Domain".utf16LittleEndianBytes),
            .init(id: NTLM.AVPairID.nbComputerName.rawValue, value: "Server".utf16LittleEndianBytes),
            .init(id: NTLM.AVPairID.timestamp.rawValue, value: timestamp),
            .init(id: NTLM.AVPairID.eol.rawValue, value: []),
        ])
        var message = NTLM.signature
        message.appendLittleEndian(UInt32(2))
        // TargetNameFields: empty
        message.appendLittleEndian(UInt16(0))
        message.appendLittleEndian(UInt16(0))
        message.appendLittleEndian(UInt32(48))
        message.appendLittleEndian(NTLM.Flags.client.rawValue)
        message.append(contentsOf: serverChallenge)
        message.append(contentsOf: [UInt8](repeating: 0, count: 8))
        message.appendLittleEndian(UInt16(targetInfo.count))
        message.appendLittleEndian(UInt16(targetInfo.count))
        message.appendLittleEndian(UInt32(48))
        message.append(contentsOf: targetInfo)
        return message
    }

    static func verify(
        authenticate: [UInt8],
        negotiate: [UInt8],
        challenge: [UInt8],
        password: String
    ) throws -> Verified {
        guard authenticate.count >= 88, Array(authenticate[0..<8]) == NTLM.signature,
            authenticate.readUInt32(at: 8) == 3
        else {
            throw VerificationFailed()
        }
        let ntResponse = try authenticate.readField(at: 20)
        let domain = String(decoding: Self.utf16(try authenticate.readField(at: 28)), as: UTF16.self)
        let user = String(decoding: Self.utf16(try authenticate.readField(at: 36)), as: UTF16.self)
        guard ntResponse.count > 16 + 28 + 4 else { throw VerificationFailed() }

        let ntProofStr = Array(ntResponse[0..<16])
        let temp = Array(ntResponse[16...])
        let key = NTLM.ntowfv2(password: password, user: user, domain: domain)
        let serverChallenge = Array(challenge[24..<32])
        guard NTLM.hmacMD5(key: key, serverChallenge + temp) == ntProofStr else {
            throw VerificationFailed()
        }

        let sessionKey = NTLM.hmacMD5(key: key, ntProofStr)
        var zeroed = authenticate
        zeroed.replaceSubrange(72..<88, with: [UInt8](repeating: 0, count: 16))
        let mic = NTLM.hmacMD5(key: sessionKey, negotiate + challenge + zeroed)

        let pairs = try NTLM.parseAVPairs(Array(temp[28..<(temp.count - 4)]))
        let bindings = pairs.first { $0.id == NTLM.AVPairID.channelBindings.rawValue }?.value
        let targetName = pairs.first { $0.id == NTLM.AVPairID.targetName.rawValue }.map {
            String(decoding: Self.utf16($0.value), as: UTF16.self)
        }
        return Verified(
            user: user,
            domain: domain,
            micIsValid: mic == Array(authenticate[72..<88]),
            channelBindings: bindings,
            targetName: targetName
        )
    }

    private static func utf16(_ bytes: [UInt8]) -> [UInt16] {
        stride(from: 0, to: bytes.count - 1, by: 2).map { UInt16(bytes[$0]) | UInt16(bytes[$0 + 1]) << 8 }
    }
}
