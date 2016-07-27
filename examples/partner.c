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

#include <ntsid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secp256k1.h"
#include "../netki.h"
#include "../sha2.h"
#include "curlHttpCallbackImpl.h"

unsigned char *PubkeySerializeDER(secp256k1_context *ctx, secp256k1_pubkey *pubkey, size_t *strLen) {

    unsigned char *pointstr = calloc(88, sizeof(unsigned char));
    size_t outputLen = 65;
    static const uint8_t oidSeq[] = {0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
                                     0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x03, 0x42, 0x00};
    memcpy(pointstr, oidSeq, 23);

    int serializeRes = secp256k1_ec_pubkey_serialize(ctx, pointstr + 23, &outputLen, pubkey, SECP256K1_EC_UNCOMPRESSED);
    if (!serializeRes) {
        free(pointstr);
        return NULL;
    }

    *strLen = 88;
    return pointstr;
}

int main() {

    /*
     * Partner API Example - Distributed API Access
     */

    // Setup Hardcoded Private Keys
    unsigned char userKey[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                               0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

    unsigned char partnerKey[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD,
                                  0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF,
                                  0xDE, 0xAD, 0xBE, 0xEF};

    secp256k1_context *secpCtx;
    secp256k1_pubkey partnerPubKey, userPubKey;
    secp256k1_ecdsa_signature keySig;
    unsigned char *userPubKeyDER;
    size_t partnerPubKeyLen, partnerKeySigDERLen = 255;
    int dontCare = 0;

    unsigned char *partnerKeySigDER = calloc(255, sizeof(char));

    secpCtx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    dontCare = secp256k1_ec_pubkey_create(secpCtx, &partnerPubKey, partnerKey);
    dontCare = secp256k1_ec_pubkey_create(secpCtx, &userPubKey, userKey);

    size_t userDerLen = 88;
    unsigned char MSG[32];
    userPubKeyDER = PubkeySerializeDER(secpCtx, &userPubKey, &userDerLen);
    BRSHA256(&MSG, userPubKeyDER, userDerLen);

    secp256k1_ecdsa_sign(secpCtx, &keySig, MSG, partnerKey, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_der(secpCtx, partnerKeySigDER, &partnerKeySigDERLen, &keySig);

    NKHandle *handle = NKHandleInit();
    NKSetApiUrl(handle, "http://localhost:5000");
    NKSetUserKey(handle, userKey);
    NKSetPartnerSigningKey(handle, PubkeySerializeDER(secpCtx, &partnerPubKey, &partnerPubKeyLen), partnerPubKeyLen);
    NKSetKeySignature(handle, partnerKeySigDER, partnerKeySigDERLen);
    NKSetHttpCallback(handle, CurlHttpImplementation);

    NKWalletName **walletNames = calloc(1, sizeof(NKWalletName *));
    int walletNameCount = NKGetWalletNames(handle, "partnerdomain.com", NULL, walletNames);
    printf("Wallet Name Count: %d\n", walletNameCount);

    free(handle);

    /*
     * Partner API Example - API Key Access
     */
    handle = NKHandleInit();
    NKSetPartnerID(handle, "partnerId");
    NKSetApiKey(handle, "apiKey");
    NKSetHttpCallback(handle, CurlHttpImplementation);

    // Wallet Creation, Manipulation, Save and Delete
    NKWalletName *wn = NKCreateWalletName("partnerdomain.com", "walletName", "externalId");
    NKSetCurrencyAddress(wn, "btc", "1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
    NKSetCurrencyAddress(wn, "ltc", "LT5RqgZN6R5fwUCvNESsxqAX88oWNBBJjy");
    NKSetCurrencyAddress(wn, "tbtc", "https://address.service.com/uuid-793472509475029750243");
    NKSaveWalletName(handle, wn);

    char *retrievedWalletAddress;
    retrievedWalletAddress = NKGetWalletAddress(wn, "btc");
    printf("Wallet Address: %s\n", retrievedWalletAddress);

    char **usedCurrencies;
    usedCurrencies = NKGetUsedCurrencies(walletNames[0]);
    for(int i = 0; i < walletNames[0]->walletCount; i++) {
        printf("Available Currency: %s\n", usedCurrencies[i]);
    }

    NKRemoveCurrencyAddress(walletNames[0], "ltc");
    NKSetCurrencyAddress(walletNames[0], "btc", "1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
    NKSaveWalletName(handle, walletNames[0]);

    return 0;
}