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

#ifndef CASYNC_HTTP_CLIENT_GSSAPI_H
#define CASYNC_HTTP_CLIENT_GSSAPI_H

// Only built on Linux, when the `GSSAPI` package trait is enabled. Requires the MIT Kerberos headers.
// On Apple platforms AsyncHTTPClientAuth uses GSS.framework instead.
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

/// The SPNEGO mechanism (1.3.6.1.5.5.2), which the `Negotiate` HTTP authentication scheme uses (RFC 4559).
gss_OID CAsyncHTTPClientGSSAPI_spnegoMechanism(void);

/// `GSS_C_NT_HOSTBASED_SERVICE`. Swift can't access the mutable global directly in Swift 6 mode.
gss_OID CAsyncHTTPClientGSSAPI_hostBasedServiceNameType(void);

#endif
