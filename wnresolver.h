/*
Created by Matt David on 4/18/16.
Copyright (c) 2016, Netki, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse
or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef C_PARTNER_API_CLIENT_WNRESOLVER_H
#define C_PARTNER_API_CLIENT_WNRESOLVER_H

#include "netki.h"

#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct {
    char *resolveConfPath;
    char *trustAnchorPath;
    NKHttpCallback httpCallback;
} NKResolverHandle;

extern int NKResolveWalletName(NKResolverHandle *handle, char *walletName, char *currency, char *walletAddress);
extern int NKResolveWalletNameCurrencies(NKResolverHandle *handle, char *walletName, char **currencies, int *currencyCount);

extern NKResolverHandle *NKResolverHandlerInit();
extern void NKResolverSetHttpCallback(NKResolverHandle *handle, NKHttpCallback funcPtr);
extern void NKResolverSetResolveConfPath(NKResolverHandle *handle, char *resolveConfPath);
extern void NKResolverSetTrustAnchorPath(NKResolverHandle *handle, char *trustAnchorPath);

#if defined(__cplusplus)
extern "C"
}
#endif

#endif //C_PARTNER_API_CLIENT_WNRESOLVER_H
