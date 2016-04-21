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

#include "cJSON.h"
#include <secp256k1.h>

#ifndef C_NETKI_H
#define C_NETKI_H

# ifdef __cplusplus
extern "C" {
# endif

#define HTTP_BUFFER_SIZE (256 * 1024) /* 256kB */
#define HTTP_RESULT_HEADER_COUNT 64

#define ARG_REQUIRED(REQ) if(!REQ) {\
    fprintf(stderr, "Required Argument " #REQ " Missing\n");\
    return 0;\
}

typedef struct {
    cJSON *data;
    long http_code;
} NKResult;

/*
 * NK_OPT_HTTPS_REQUEST_FUNC must be a function defined with the following signature:
 *
 * void functionName(char *url, char *method, char *submitData, char** headers, int headerCount, char *returnData, uint8_t *returnHttpStatusCode);
 *
 */

typedef void (*NKHttpCallback)(char *url, char *method, char *submitData, char **headers, int headerCount, char *returnData, char **returnHeaders, long *returnHttpStatusCode);

typedef struct {
    char *partnerId;
    char *apiKey;
    char *apiUrl;
    unsigned char *userKey;
    secp256k1_pubkey *partnerSigningKey;
    secp256k1_ecdsa_signature *keySignature;
    NKHttpCallback httpCallback;
} NKHandle;

typedef struct {
    char *name;
    char *status;
    char *delegationStatus;
    char *delegationMessage;
    int walletNameCount;
    char *nextRoll;
    char **dsRecords;
    char **nameservers;
    char *publicSigningKey;
} NKDomain;

typedef struct {
    char *id;
    char *name;
} NKPartner;

typedef struct NKWallet NKWallet;

struct NKWallet {
    char *currency;
    char *walletAddress;
    NKWallet *next;
};

typedef struct {
    char *id;
    char *domainName;
    char *name;
    char *externalId;
    int walletCount;
    NKWallet *wallets;
} NKWalletName;

// Internal Operations
int NKProcessRequest(NKHandle *handle, char *url, char *method, char *data, NKResult *result);
unsigned char *NK_PubkeySerializeDER(secp256k1_context *ctx, secp256k1_pubkey *pubkey, size_t *strLen);
char *NK_BytesToHexString(uint8_t *data, size_t length);

// Wallet Name Operations
extern int NKGetWalletNames(NKHandle *handle, char *domain, char *externalID, NKWalletName **walletNames);
extern int NKSetCurrencyAddress(NKWalletName *wn, char *currency, char *walletAddress);
extern NKWalletName *NKCreateWalletName(char *domainName, char *name, char *externalId);
extern char * NKGetWalletAddress(NKWalletName *wn, char *currency);
extern char ** NKGetUsedCurrencies(NKWalletName *wn);
extern int NKRemoveCurrencyAddress(NKWalletName *wn, char *currency);
extern int NKDeleteWalletName(NKHandle  *handle, NKWalletName *wn);
extern int NKSaveWalletName(NKHandle *handle, NKWalletName *wn);

// Domain Operations
extern int NKGetDomains(NKHandle *handle, NKDomain **domains);
extern NKDomain *NKCreateDomain(NKHandle *handle, char *domainName, NKPartner *partner);
extern int NKDeleteDomain(NKHandle *handle, NKDomain *domain);
extern int NKLoadDomainStatus(NKHandle *handle, NKDomain *domain);
extern int NKLoadDomainDNSSECDetails(NKHandle *handle, NKDomain *domain);

// Partner Operations
extern int NKGetPartners(NKHandle *handle, NKPartner **partners);
extern NKPartner *NKCreatePartner(NKHandle *handle, char *partnerName);
extern int NKDeletePartner(NKHandle *handle, NKPartner *partner);

// Netki Handle
extern NKHandle *NKHandleInit();
extern void NKSetPartnerID(NKHandle *handle, char* partnerId);
extern void NKSetApiKey(NKHandle *handle, char *apiKey);
extern void NKSetApiUrl(NKHandle *handle, char *apiUrl);
extern void NKSetUserKey(NKHandle *handle, unsigned char *userKey32);
extern void NKSetPartnerSigningKey(NKHandle *handle, secp256k1_pubkey *pubkey);
extern void NKSetKeySignature(NKHandle *handle, secp256k1_ecdsa_signature *sig);
extern void NKSetHttpCallback(NKHandle *handle, NKHttpCallback funcPtr);

# ifdef __cplusplus
}
# endif

#endif //C_NETKI_H
