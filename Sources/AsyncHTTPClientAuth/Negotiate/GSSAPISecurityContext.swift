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

import NIOConcurrencyHelpers
import NIOPosix

#if canImport(GSS) || (GSSAPI && canImport(CAsyncHTTPClientGSSAPI))

#if canImport(GSS)
// NOTE: The GSS.framework path has not been compiled yet. It was written on Linux.
import GSS
#else
import CAsyncHTTPClientGSSAPI
#endif

/// Creates `Negotiate` tokens with the system's GSS-API and the default credentials.
///
/// GSS-API calls may block, for example to contact the KDC. They run on `NIOThreadPool.singleton`.
struct GSSAPISecurityContextProvider: NegotiateSecurityContextProvider {
    func credentialIdentity() async throws -> String {
        try await NIOThreadPool.singleton.runIfActive {
            try GSSAPI.defaultCredentialName()
        }
    }

    func makeContext(
        servicePrincipalName: String,
        channelBinding: [UInt8]?
    ) async throws
        -> any NegotiateSecurityContext
    {
        try await NIOThreadPool.singleton.runIfActive {
            try GSSAPISecurityContext(servicePrincipalName: servicePrincipalName, channelBinding: channelBinding)
        }
    }
}

/// A GSS-API security context with the SPNEGO mechanism.
final class GSSAPISecurityContext: NegotiateSecurityContext, @unchecked Sendable {
    // Protected by `lock`.
    private var context: gss_ctx_id_t?
    private let targetName: gss_name_t?
    private let channelBinding: [UInt8]?
    private let lock = NIOLock()

    init(servicePrincipalName: String, channelBinding: [UInt8]?) throws {
        var minor: OM_uint32 = 0
        var name: gss_name_t?
        var nameBytes = Array(servicePrincipalName.utf8)
        let major = nameBytes.withUnsafeMutableBytes { bytes in
            var buffer = gss_buffer_desc(length: bytes.count, value: bytes.baseAddress)
            return gss_import_name(&minor, &buffer, GSSAPI.hostBasedServiceNameType, &name)
        }
        guard !GSSAPI.isError(major) else {
            throw GSSAPI.error(major: major, minor: minor)
        }
        self.targetName = name
        self.channelBinding = channelBinding
    }

    deinit {
        var minor: OM_uint32 = 0
        if self.context != nil {
            gss_delete_sec_context(&minor, &self.context, nil)
        }
        var name = self.targetName
        if name != nil {
            gss_release_name(&minor, &name)
        }
    }

    func step(_ token: [UInt8]?) async throws -> (token: [UInt8]?, isComplete: Bool) {
        try await NIOThreadPool.singleton.runIfActive {
            try self.lock.withLock {
                try self.step0(token)
            }
        }
    }

    private func step0(_ token: [UInt8]?) throws -> (token: [UInt8]?, isComplete: Bool) {
        var minor: OM_uint32 = 0
        var output = gss_buffer_desc(length: 0, value: nil)
        defer { gss_release_buffer(&minor, &output) }

        var input = token ?? []
        var applicationData = self.channelBinding ?? []
        let flags = OM_uint32(GSS_C_MUTUAL_FLAG) | OM_uint32(GSS_C_SEQUENCE_FLAG)

        let major = input.withUnsafeMutableBytes { inputBytes in
            applicationData.withUnsafeMutableBytes { applicationDataBytes in
                var inputBuffer = gss_buffer_desc(length: inputBytes.count, value: inputBytes.baseAddress)
                var bindings = gss_channel_bindings_struct(
                    initiator_addrtype: 0,
                    initiator_address: gss_buffer_desc(length: 0, value: nil),
                    acceptor_addrtype: 0,
                    acceptor_address: gss_buffer_desc(length: 0, value: nil),
                    application_data: gss_buffer_desc(
                        length: applicationDataBytes.count,
                        value: applicationDataBytes.baseAddress
                    )
                )
                return withUnsafeMutablePointer(to: &inputBuffer) { inputPointer in
                    withUnsafeMutablePointer(to: &bindings) { bindingsPointer in
                        gss_init_sec_context(
                            &minor,
                            nil,  // GSS_C_NO_CREDENTIAL: the default credentials
                            &self.context,
                            self.targetName,
                            GSSAPI.spnegoMechanism,
                            flags,
                            0,
                            self.channelBinding == nil ? nil : bindingsPointer,
                            token == nil ? nil : inputPointer,
                            nil,
                            &output,
                            nil,
                            nil
                        )
                    }
                }
            }
        }
        guard !GSSAPI.isError(major) else {
            throw GSSAPI.error(major: major, minor: minor)
        }

        var outputToken: [UInt8]?
        if output.length > 0, let value = output.value {
            outputToken = Array(UnsafeRawBufferPointer(start: value, count: output.length))
        }
        return (outputToken, !GSSAPI.continueNeeded(major))
    }
}

enum GSSAPI {
    static var hostBasedServiceNameType: gss_OID {
        #if canImport(GSS)
        // `GSS_C_NT_HOSTBASED_SERVICE` is a macro for the address of this global.
        withUnsafeMutablePointer(to: &__gss_c_nt_hostbased_service_oid_desc) { $0 }
        #else
        CAsyncHTTPClientGSSAPI_hostBasedServiceNameType()
        #endif
    }

    static var spnegoMechanism: gss_OID {
        #if canImport(GSS)
        withUnsafeMutablePointer(to: &__gss_spnego_mechanism_oid_desc) { $0 }
        #else
        CAsyncHTTPClientGSSAPI_spnegoMechanism()
        #endif
    }

    /// `GSS_ERROR()`: a calling or routine error is set.
    static func isError(_ major: OM_uint32) -> Bool {
        major & 0xFFFF_0000 != 0
    }

    /// `GSS_S_CONTINUE_NEEDED` is set.
    static func continueNeeded(_ major: OM_uint32) -> Bool {
        major & 1 != 0
    }

    /// The name of the default initiator credentials, for example `alice@EXAMPLE.COM`.
    static func defaultCredentialName() throws -> String {
        var minor: OM_uint32 = 0
        var credential: gss_cred_id_t?
        var major = gss_acquire_cred(
            &minor,
            nil,  // GSS_C_NO_NAME
            0xFFFF_FFFF,  // GSS_C_INDEFINITE
            nil,  // GSS_C_NO_OID_SET
            gss_cred_usage_t(GSS_C_INITIATE),
            &credential,
            nil,
            nil
        )
        guard !Self.isError(major) else {
            throw Self.error(major: major, minor: minor)
        }
        defer { gss_release_cred(&minor, &credential) }

        var name: gss_name_t?
        major = gss_inquire_cred(&minor, credential, &name, nil, nil, nil)
        guard !Self.isError(major) else {
            throw Self.error(major: major, minor: minor)
        }
        defer { gss_release_name(&minor, &name) }

        var buffer = gss_buffer_desc(length: 0, value: nil)
        major = gss_display_name(&minor, name, &buffer, nil)
        guard !Self.isError(major) else {
            throw Self.error(major: major, minor: minor)
        }
        defer { gss_release_buffer(&minor, &buffer) }
        return Self.string(buffer)
    }

    static func error(major: OM_uint32, minor: OM_uint32) -> HTTPClientAuthenticationError {
        let messages =
            Self.statusMessages(major, type: Int32(GSS_C_GSS_CODE))
            + Self.statusMessages(minor, type: Int32(GSS_C_MECH_CODE))
        return .gssFailure(major: major, minor: minor, message: messages.joined(separator: ": "))
    }

    private static func statusMessages(_ status: OM_uint32, type: Int32) -> [String] {
        guard status != 0 else { return [] }
        var messages: [String] = []
        var messageContext: OM_uint32 = 0
        repeat {
            var minor: OM_uint32 = 0
            var buffer = gss_buffer_desc(length: 0, value: nil)
            let major = gss_display_status(&minor, status, type, nil, &messageContext, &buffer)
            guard !Self.isError(major) else { break }
            messages.append(Self.string(buffer))
            gss_release_buffer(&minor, &buffer)
        } while messageContext != 0
        return messages
    }

    private static func string(_ buffer: gss_buffer_desc) -> String {
        guard let value = buffer.value else { return "" }
        return String(decoding: UnsafeRawBufferPointer(start: value, count: buffer.length), as: UTF8.self)
    }
}

#else

/// GSS-API is not available. On Linux, enable the `GSSAPI` package trait.
struct GSSAPISecurityContextProvider: NegotiateSecurityContextProvider {
    func credentialIdentity() async throws -> String {
        throw HTTPClientAuthenticationError.negotiateUnavailable
    }

    func makeContext(
        servicePrincipalName: String,
        channelBinding: [UInt8]?
    ) async throws
        -> any NegotiateSecurityContext
    {
        throw HTTPClientAuthenticationError.negotiateUnavailable
    }
}

#endif
