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

#include <unbound.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include "wnresolver.h"
#include "sha2.h"
#include "base64.h"

/*
 * Utility Functionality
 */

void lowerString(char *s) {
    for (int i = 0; s[i] != '\0'; i++) {
        s[i] = (char) tolower(s[i]);
    }
}

char *trimString(char *str) {
    char *end;

    while (isspace(*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) end--;
    *(end + 1) = 0;
    return str;
}

int stringContains(char *haystack, char **needles, int count) {
    for (int i = 0; i < count; i++) {
        if (strstr(haystack, needles[i])) return 1;
    }
    return 0;
}

char *ensureDot(char *str) {
    if (str[((int) strlen(str) - 1)] == '.')
        return str;

    char *ret = calloc(strlen(str) + 2, sizeof(char));
    sprintf(ret, "%s.", str);
    return ret;
}

char *_GetHeaderValue(char **headers, char *key) {
    char *ptr, *found = NULL, *retValue;
    for (int i = 0; i < HTTP_RESULT_HEADER_COUNT; i++) {
        ptr = headers[i];
        if (ptr == NULL) return NULL;
        char *headerValue = strsep(&ptr, ":");
        if (!ptr) continue;
        lowerString(headerValue);
        trimString(headerValue);
        found = strstr(headerValue, key);

        if (found && found == headerValue) {
            retValue = strdup(ptr);
            retValue = trimString(retValue);
            return retValue;
        }
    }
    return NULL;
}

char *_walletNameToDnsName(char *walletName, char *currency) {

    char *dnsName = calloc(1024, sizeof(char));

    lowerString(walletName);
    if (currency)
        lowerString(currency);

    // Handle Email Formatted WalletNames
    int foundEmail = 0;
    for (int i = 0; i < strlen(walletName); i++) {
        if (walletName[i] == '@') foundEmail = i;
    }

    if (foundEmail) {
        unsigned char *hash = calloc(28, sizeof(char));
        char *localPart = calloc(255, sizeof(char));
        char *domainPart = calloc(255, sizeof(char));
        char newWalletName[512];

        strncpy(localPart, walletName, foundEmail);
        strncpy(domainPart, walletName + foundEmail + 1, strlen(walletName) - foundEmail);
        BRSHA224(hash, localPart, strlen(localPart));
        sprintf(newWalletName, "%s.%s", NK_BytesToHexString(hash, 28), domainPart);
        walletName = newWalletName;
    }

    walletName = ensureDot(walletName);
    if (currency)
        sprintf(dnsName, "_%s._wallet.%s", currency, walletName);
    else
        sprintf(dnsName, "_wallet.%s", walletName);

    return dnsName;
}

/*
 * NKResolverHandle Utilities
 */
NKResolverHandle *NKResolverHandlerInit() {
    NKResolverHandle *handle = calloc(1, sizeof(NKResolverHandle));
    handle->httpCallback = NULL;
    handle->resolveConfPath = "/etc/resolv.conf";
    handle->trustAnchorPath = "/usr/local/etc/unbound/root.key";
    return handle;
}

void NKResolverSetHttpCallback(NKResolverHandle *handle, NKHttpCallback funcPtr) {
    handle->httpCallback = funcPtr;
}

void NKResolverSetResolveConfPath(NKResolverHandle *handle, char *resolveConfPath) {
    handle->resolveConfPath = resolveConfPath;
}

void NKResolverSetTrustAnchorPath(NKResolverHandle *handle, char *trustAnchorPath) {
    handle->trustAnchorPath = trustAnchorPath;
}

/*
 * Wallet Name URL Processing
 */
char *NKProcessWalletNameURL(NKResolverHandle *handle, char *url) {

    const char *colon = ":";
    const char *question = "?";

    if (!handle->httpCallback) return 0;

    char *returnData = calloc(HTTP_BUFFER_SIZE, sizeof(char));
    char **returnHeaders = calloc(HTTP_RESULT_HEADER_COUNT, sizeof(char *));
    long httpStatusCode = 0;

    (*(handle->httpCallback))(url, "GET", NULL, NULL, 0, returnData, returnHeaders, &httpStatusCode);
    if (httpStatusCode >= 300) return 0;

    char *result = trimString(returnData);

    char *contentType = _GetHeaderValue(returnHeaders, "content-type");
    char *allowedContentTypes[] = {"application/octet-stream", "text/plain", "text/html"};
    if (stringContains(contentType, allowedContentTypes, 3)) {
        char *start = result;
        char *scheme = strsep(&result, colon);
        if (strcmp(scheme, "bitcoin") == 0) {
            char *addr = strsep(&result, question);
            return addr;
        }
        return start;
    }

    return 0;
}

/*
 * Wallet Name Resolution
 */
int NKResolveWalletName(NKResolverHandle *handle, char *walletName, char *currency, char *walletAddress) {

    struct ub_ctx *ctx;
    struct ub_result *result;
    int retval;

    ctx = ub_ctx_create();
    if (!ctx) {
        fprintf(stderr, "error: could not create unbound context\n");
        return 0;
    }

    /* read /etc/resolv.conf for DNS proxy settings (from DHCP) */
    if ((retval = ub_ctx_resolvconf(ctx, handle->resolveConfPath)) != 0) {
        fprintf(stderr, "error reading resolve.conf: %s. errno says: %s\n", ub_strerror(retval), strerror(errno));
        return 0;
    }

    /* read public keys for DNSSEC verification */
    if ((retval = ub_ctx_add_ta_file(ctx, handle->trustAnchorPath)) != 0) {
        fprintf(stderr, "error adding keys: %s\n", ub_strerror(retval));
        return 1;
    }

    char *dnsName = _walletNameToDnsName(walletName, currency);
    retval = ub_resolve(ctx, dnsName, 16 /* TXT */, 1 /* IN */, &result);
    if (retval != 0) {
        fprintf(stderr, "resolve error: %s\n", ub_strerror(retval));
        return 0;
    }

    if (!result->havedata) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returned No Data\n");
        return 0;
    }

    if (result->bogus) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returned Bogus Results: %s", result->why_bogus);
    }

    if (!result->secure) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returns Insecure Results\n");
    }

    if (result->havedata) {
        int namelen = (int) result->data[0][0];
        if (namelen != (result->len[0] - 1)) {
            fprintf(stderr, "error: DNS+DNSSEC Text Record Data Length Mismatch");
            return 0;
        }
        char *ptr = result->data[0] + 1;
        memcpy(walletAddress, ptr, namelen);
    }

    ub_resolve_free(result);
    ub_ctx_delete(ctx);

    char *hashOut = calloc((size_t) ((int) strlen(walletAddress) / 3) * 4 + 1, sizeof(char));
    size_t hashLen;
    base64decode(walletAddress, strlen(walletAddress), (unsigned char *) hashOut, &hashLen);
    if (!hashLen) {
        return 1;
    }

    char *httpPtr, *httpsPtr;
    httpPtr = strstr(hashOut, "http://");
    httpsPtr = strstr(hashOut, "https://");
    if (httpPtr == hashOut || httpsPtr == hashOut) {
        char *addr = NKProcessWalletNameURL(handle, hashOut);
        if (addr) {
            memset(walletAddress, 0, strlen(addr) + 1);
            memcpy(walletAddress, addr, strlen(addr));
            return 1;
        }
    }

    return 1;
}

int NKResolveWalletNameCurrencies(NKResolverHandle *handle, char *walletName, char **currencies, int *currencyCount) {

    struct ub_ctx *ctx;
    struct ub_result *result;
    int retval;

    ctx = ub_ctx_create();
    if (!ctx) {
        fprintf(stderr, "error: could not create unbound context\n");
        return 0;
    }

    /* read /etc/resolv.conf for DNS proxy settings (from DHCP) */
    if ((retval = ub_ctx_resolvconf(ctx, handle->resolveConfPath)) != 0) {
        fprintf(stderr, "error reading resolve.conf: %s. errno says: %s\n", ub_strerror(retval), strerror(errno));
        return 0;
    }

    /* read public keys for DNSSEC verification */
    if ((retval = ub_ctx_add_ta_file(ctx, handle->trustAnchorPath)) != 0) {
        fprintf(stderr, "error adding keys: %s\n", ub_strerror(retval));
        return 1;
    }

    char *dnsName = _walletNameToDnsName(walletName, NULL);
    retval = ub_resolve(ctx, dnsName, 16 /* TXT */, 1 /* IN */, &result);
    if (retval != 0) {
        fprintf(stderr, "resolve error: %s\n", ub_strerror(retval));
        return 0;
    }

    if (!result->havedata) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returned No Data\n");
        return 0;
    }

    if (result->bogus) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returned Bogus Results: %s", result->why_bogus);
    }

    if (!result->secure) {
        fprintf(stderr, "error: DNS+DNSSEC Query Returns Insecure Results\n");
    }

    if (result->havedata) {
        int namelen = (int) result->data[0][0];
        if (namelen != (result->len[0] - 1)) {
            fprintf(stderr, "error: DNS+DNSSEC Text Record Data Length Mismatch");
            return 0;
        }
        char *ptr = result->data[0] + 1;
        int i = 0;
        while (ptr != NULL) {
            if (currencies[i] != NULL) {
                fprintf(stderr, "Too Many Currencies (not enough memory) Available, Unable to Return More Than %i", i);
                return 0;
            }
            currencies[i++] = strdup(strsep(&ptr, " "));
        }
        *currencyCount = i;
    }

    ub_resolve_free(result);
    ub_ctx_delete(ctx);

    return 1;
}