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

#include "CAsyncHTTPClientGSSAPI.h"

gss_OID CAsyncHTTPClientGSSAPI_spnegoMechanism(void) {
    static gss_OID_desc spnego = {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
    return &spnego;
}

gss_OID CAsyncHTTPClientGSSAPI_hostBasedServiceNameType(void) {
    return GSS_C_NT_HOSTBASED_SERVICE;
}
