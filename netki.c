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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <printf.h>
#include "netki.h"
#include "sha2.h"

/*
 * NKHandle Utilities
 */
NKHandle *NKHandleInit() {
    NKHandle *handle = calloc(1, sizeof(NKHandle));
    handle->flags = 0;
    handle->partnerId = NULL;
    handle->apiKey = NULL;
    handle->apiUrl = strdup("https://api.netki.com");
    handle->userKey = NULL;
    handle->partnerSigningKey = NULL;
    handle->keySignature = NULL;
    handle->httpCallback = NULL;

    return handle;
}

void NKSetPartnerID(NKHandle *handle, char *partnerId) {
    handle->partnerId = partnerId;
}

void NKSetApiKey(NKHandle *handle, char *apiKey) {
    handle->apiKey = apiKey;
}

void NKSetApiUrl(NKHandle *handle, char *apiUrl) {
    handle->apiUrl = apiUrl;
}

void NKSetUserKey(NKHandle *handle, unsigned char *userKey32) {
    handle->userKey = userKey32;
}

void NKSetPartnerSigningKey(NKHandle *handle, secp256k1_pubkey *pubkey) {
    handle->partnerSigningKey = pubkey;
}

void NKSetKeySignature(NKHandle *handle, secp256k1_ecdsa_signature *sig) {
    handle->keySignature = sig;
}

void NKSetHttpCallback(NKHandle *handle, NKHttpCallback funcPtr) {
    handle->httpCallback = funcPtr;
}

/*
 * Wallet Names
 */
int NKGetWalletNames(NKHandle *handle, char *domain, char *externalID, NKWalletName **walletNames) {

    ARG_REQUIRED(handle)

    NKResult result;
    char url[512] = "/v1/partner/walletname";
    int walletNameCount = 0;

    // Build URL Query String
    if(domain || externalID) {
        strcat(url, "?");
        if(domain) {
            strcat(url, "domain=");
            strcat(url, domain);
        }
        if(externalID) {
            if(domain) strcat(url, "&");
            strcat(url, "external_id=");
            strcat(url, externalID);
        }
    }

    // Process API Request
    int res = NKProcessRequest(handle, url, "GET", NULL, &result);
    if (!res)
        return 0;

    // Check for Error and Print Message if necessary
    if (result.http_code >= 300 && cJSON_GetObjectItem(result.data, "message")->valuestring) {
        fprintf(stderr, "Get WalletNames Failed: %s", cJSON_GetObjectItem(result.data, "message")->valuestring);
        cJSON_Delete(result.data);
        return 0;
    }

    // Get and Parse WalletNames
    cJSON *walletNameArray = cJSON_GetObjectItem(result.data, "wallet_names");
    if (!walletNameArray) {
        cJSON_Delete(result.data);
        return 0;
    }

    walletNameCount = cJSON_GetArraySize(walletNameArray);
    realloc(walletNames, sizeof(NKWalletName) * walletNameCount);

    for (int i = 0; i < walletNameCount; i++) {
        cJSON *walletNameJson = cJSON_GetArrayItem(walletNameArray, i);
        walletNames[i] = NKCreateWalletName(
                cJSON_GetObjectItem(walletNameJson, "domain_name")->valuestring,
                cJSON_GetObjectItem(walletNameJson, "name")->valuestring,
                cJSON_GetObjectItem(walletNameJson, "external_id")->valuestring
        );

        if(!walletNames[i]) {
            cJSON_Delete(result.data);
            return 0;
        }

        walletNames[i]->id = strdup(cJSON_GetObjectItem(walletNameJson, "id")->valuestring);

        cJSON *walletArray = cJSON_GetObjectItem(walletNameJson, "wallets");
        for (int j = 0; j < cJSON_GetArraySize(walletArray); j++) {
            cJSON *walletJson = cJSON_GetArrayItem(walletArray, j);
            NKSetCurrencyAddress(
                    walletNames[i],
                    cJSON_GetObjectItem(walletJson, "currency")->valuestring,
                    cJSON_GetObjectItem(walletJson, "wallet_address")->valuestring
            );
        }
    }

    cJSON_Delete(result.data);
    return walletNameCount;
}

NKWalletName *NKCreateWalletName(char *domainName, char *name, char *externalId) {

    ARG_REQUIRED(domainName)
    ARG_REQUIRED(name)
    ARG_REQUIRED(externalId)

    NKWalletName *wn = calloc(1, sizeof(NKWalletName));
    wn->domainName = strdup(domainName);
    wn->name = strdup(name);
    wn->externalId = strdup(externalId);
    wn->id = NULL;
    wn->wallets = NULL;
    wn->walletCount = 0;
    return wn;
}

int NKSetCurrencyAddress(NKWalletName *wn, char *currency, char *walletAddress) {

    ARG_REQUIRED(wn)
    ARG_REQUIRED(currency)
    ARG_REQUIRED(walletAddress)

    if (wn->wallets == NULL) {
        wn->wallets = calloc(1, sizeof(NKWallet));
        wn->wallets[0].currency = strdup(currency);
        wn->wallets[0].walletAddress = strdup(walletAddress);
        wn->wallets[0].next = NULL;
        wn->walletCount++;
        return 1;
    }

    NKWallet *ptr = wn->wallets;
    NKWallet *prevPtr = ptr;
    while (ptr != NULL) {
        if (strcmp(ptr->currency, currency) == 0) {
            ptr->walletAddress = strdup(walletAddress);
            return 1;
        }
        prevPtr = ptr;
        ptr = ptr->next;
    }

    NKWallet *newWallet = calloc(1, sizeof(NKWallet));
    prevPtr->next = newWallet;
    newWallet->currency = strdup(currency);
    newWallet->walletAddress = strdup(walletAddress);
    newWallet->next = NULL;
    wn->walletCount++;

    return 1;

}

char *NKGetWalletAddress(NKWalletName *wn, char *currency) {

    ARG_REQUIRED(wn)
    ARG_REQUIRED(currency)

    NKWallet *ptr = wn->wallets;
    while (ptr != NULL) {
        if (strcmp(ptr->currency, currency) == 0) {
            return ptr->walletAddress;
        }
        ptr = ptr->next;
    }
    return NULL;
}

int NKRemoveCurrencyAddress(NKWalletName *wn, char *currency) {

    ARG_REQUIRED(wn)
    ARG_REQUIRED(currency)

    if (NKGetWalletAddress(wn, currency) == NULL)
        return 0;

    NKWallet *ptr = wn->wallets;
    NKWallet *prevPtr = wn->wallets;
    while (ptr != NULL) {
        if (strcmp(ptr->currency, currency) == 0) {
            if (ptr == wn->wallets) {
                wn->wallets = ptr->next;
            } else {
                prevPtr->next = ptr->next;
            }
            free(ptr);
            return 1;

        }
        prevPtr = ptr;
        ptr = ptr->next;
    }

    return 0;
}

char **NKGetUsedCurrencies(NKWalletName *wn) {

    ARG_REQUIRED(wn)

    char **currencies = calloc((size_t) wn->walletCount, sizeof(char *));
    NKWallet *ptr = wn->wallets;
    int i = 0;
    while (ptr != NULL) {
        currencies[i] = calloc(strlen(ptr->currency), sizeof(char));
        strcpy(currencies[i], ptr->currency);
        i++;
        ptr = ptr->next;
    }
    return currencies;
}

int NKSaveWalletName(NKHandle *handle, NKWalletName *wn) {

    ARG_REQUIRED(handle)
    ARG_REQUIRED(wn)

    cJSON *root, *walletName, *walletNameArray;
    if (!wn->wallets) {
        fprintf(stderr, "Cannot Save Empty Wallet Name %s.%s\n", wn->name, wn->domainName);
        return 0;
    }

    walletName = cJSON_CreateObject();
    cJSON_AddItemToObject(walletName, "domain_name", cJSON_CreateString(wn->domainName));
    cJSON_AddItemToObject(walletName, "name", cJSON_CreateString(wn->name));
    cJSON_AddItemToObject(walletName, "external_id", cJSON_CreateString(wn->externalId));
    if (wn->id)
        cJSON_AddItemToObject(walletName, "id", cJSON_CreateString(wn->id));

    NKWallet *ptr = wn->wallets;
    cJSON *walletArray = cJSON_CreateArray();
    cJSON_AddItemToObject(walletName, "wallets", walletArray);

    while (ptr != NULL) {
        cJSON *walletJson = cJSON_CreateObject();
        cJSON_AddItemToObject(walletJson, "currency", cJSON_CreateString(ptr->currency));
        cJSON_AddItemToObject(walletJson, "wallet_address", cJSON_CreateString(ptr->walletAddress));
        cJSON_AddItemToArray(walletArray, walletJson);
        ptr = ptr->next;
    }

    root = cJSON_CreateObject();
    walletNameArray = cJSON_CreateArray();
    cJSON_AddItemToArray(walletNameArray, walletName);
    cJSON_AddItemToObject(root, "wallet_names", walletNameArray);

    char *method;
    if (wn->id)
        method = strdup("PUT");
    else
        method = strdup("POST");

    NKResult result;
    int res = NKProcessRequest(handle, "/v1/partner/walletname", method, cJSON_Print(root), &result);

    if (!wn->id) {
        cJSON *walletNamesArray = cJSON_GetObjectItem(result.data, "wallet_names");
        cJSON *wnObject = cJSON_GetArrayItem(walletNamesArray, 0);
        wn->id = strdup(cJSON_GetObjectItem(wnObject, "id")->valuestring);
    }

    if (result.data)
        cJSON_Delete(result.data);

    return res;
}

int NKDeleteWalletName(NKHandle *handle, NKWalletName *wn) {

    char url[512];
    NKResult result;

    ARG_REQUIRED(handle)
    ARG_REQUIRED(wn)

    if (wn->id == NULL) {
        fprintf(stderr, "Unable to Delete Wallet Name: ID Missing");
        return 0;
    }

    sprintf(url, "/v1/partner/walletname/%s/%s", wn->domainName, wn->id);
    NKProcessRequest(handle, url, "DELETE", NULL, &result);
    if(result.http_code == 204)
        return 1;

    return 0;
}

/*
 * Domains
 */
int NKGetDomains(NKHandle *handle, NKDomain **domains) {

    NKResult result;
    int res;
    int domainCount = 0;

    ARG_REQUIRED(handle);
    ARG_REQUIRED(domains);

    res = NKProcessRequest(handle, "/api/domain", "GET", NULL, &result);
    if (!res || !result.data) {
        return 0;
    }

    cJSON *domainArray = cJSON_GetObjectItem(result.data, "domains");
    if (!domainArray) {
        cJSON_Delete(result.data);
        return 0;
    }

    domainCount = cJSON_GetArraySize(domainArray);
    realloc(domains, domainCount * sizeof(NKDomain));
    for (int i = 0; i < domainCount; i++) {
        cJSON *item = cJSON_GetArrayItem(domainArray, i);
        domains[i]->name = strdup(cJSON_GetObjectItem(item, "domain_name")->valuestring);
    }

    cJSON_Delete(result.data);
    return domainCount;
}

NKDomain *NKCreateDomain(NKHandle *handle, char *domainName, NKPartner *partner) {

    NKDomain *domain;
    NKResult result;
    int res;

    ARG_REQUIRED(handle)
    ARG_REQUIRED(domainName)

    char *data = NULL;
    if (partner != NULL) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "partner_id", cJSON_CreateString(partner->id));
        data = cJSON_Print(root);
    }

    char url[255];
    sprintf(url, "/v1/partner/domain/%s", domainName);
    res = NKProcessRequest(handle, url, "POST", data, &result);
    if (!res || !result.data)
        return 0;

    domain = calloc(1, sizeof(NKDomain));
    domain->name = strdup(domainName);
    domain->status = cJSON_GetObjectItem(result.data, "status")->valuestring;
    cJSON *nsArray = cJSON_GetObjectItem(result.data, "nameservers");
    domain->nameservers = calloc((size_t) cJSON_GetArraySize(nsArray), sizeof(char *));
    for (int i = 0; i < cJSON_GetArraySize(nsArray); i++) {
        domain->nameservers[i] = strdup(cJSON_GetArrayItem(nsArray, i)->valuestring);
    }

    if (result.data)
        cJSON_Delete(result.data);

    return domain;
}

int NKDeleteDomain(NKHandle *handle, NKDomain *domain) {
    NKResult result;
    int res;
    char url[255];

    ARG_REQUIRED(handle)
    ARG_REQUIRED(domain)

    sprintf(url, "/v1/partner/domain/%s", domain->name);
    res = NKProcessRequest(handle, url, "DELETE", NULL, &result);
    if (!res || !result.data)
        return 0;
    return 1;
}

int NKLoadDomainStatus(NKHandle *handle, NKDomain *domain) {
    NKResult result;
    int res;
    char url[255];

    ARG_REQUIRED(handle)
    ARG_REQUIRED(domain)

    sprintf(url, "/v1/partner/domain/%s", domain->name);
    res = NKProcessRequest(handle, url, "GET", NULL, &result);

    if (!res || !result.data)
        return 0;

    domain->status = strdup(cJSON_GetObjectItem(result.data, "status")->valuestring);
    domain->delegationStatus = strdup(cJSON_GetObjectItem(result.data, "delegation_status")->valuestring);
    domain->delegationMessage = strdup(cJSON_GetObjectItem(result.data, "delegation_message")->valuestring);
    domain->walletNameCount = cJSON_GetObjectItem(result.data, "wallet_name_count")->valueint;

    cJSON_Delete(result.data);
    return 1;
}

int NKLoadDomainDNSSECDetails(NKHandle *handle, NKDomain *domain) {
    NKResult result;
    int res;
    char url[255];

    ARG_REQUIRED(handle)
    ARG_REQUIRED(domain)

    sprintf(url, "/v1/partner/domain/dnssec/%s", domain->name);
    res = NKProcessRequest(handle, url, "GET", NULL, &result);

    if (!res || !result.data)
        return 0;

    domain->publicSigningKey = strdup(cJSON_GetObjectItem(result.data, "public_key_signing_key")->valuestring);
    domain->nextRoll = strdup(cJSON_GetObjectItem(result.data, "nextroll_date")->valuestring);

    cJSON *dsRecords = cJSON_GetObjectItem(result.data, "ds_records");
    cJSON *nsRecords = cJSON_GetObjectItem(result.data, "nameservers");

    if (domain->nameservers == NULL)
        domain->nameservers = calloc((size_t) cJSON_GetArraySize(nsRecords), sizeof(char *));
    else
        realloc(domain->nameservers, cJSON_GetArraySize(nsRecords) * sizeof(char *));

    if (domain->dsRecords == NULL)
        domain->dsRecords = calloc((size_t) cJSON_GetArraySize(dsRecords), sizeof(char *));
    else
        realloc(domain->dsRecords, cJSON_GetArraySize(dsRecords) * sizeof(char *));

    int i;
    for (i = 0; i < cJSON_GetArraySize(nsRecords); i++) {
        domain->nameservers[i] = strdup(cJSON_GetArrayItem(nsRecords, i)->valuestring);
    }
    for (i = 0; i < cJSON_GetArraySize(dsRecords); i++) {
        domain->dsRecords[i] = strdup(cJSON_GetArrayItem(dsRecords, i)->valuestring);
    }

    return 1;
}

/*
 * Partners
 */
int NKGetPartners(NKHandle *handle, NKPartner **partners) {

    NKResult result;
    int partnerCount = 0;

    ARG_REQUIRED(handle)
    ARG_REQUIRED(partners)

    int res = NKProcessRequest(handle, "/v1/admin/partner", "GET", NULL, &result);
    if (!res || !result.data)
        return 0;

    cJSON *partnerArray = cJSON_GetObjectItem(result.data, "partners");
    if (!partnerArray) {
        cJSON_Delete(result.data);
        return 0;
    }

    partnerCount = cJSON_GetArraySize(partnerArray);
    realloc(partners, partnerCount * sizeof(NKPartner));
    for (int i = 0; i < partnerCount; i++) {
        cJSON *item = cJSON_GetArrayItem(partnerArray, i);
        partners[i]->name = strdup(cJSON_GetObjectItem(item, "name")->valuestring);
        partners[i]->id = strdup(cJSON_GetObjectItem(item, "id")->valuestring);
    }

    cJSON_Delete(result.data);
    return partnerCount;
}

NKPartner *NKCreatePartner(NKHandle *handle, char *partnerName) {

    NKResult result;
    char url[255];
    NKPartner *returnPartner;

    ARG_REQUIRED(handle)
    ARG_REQUIRED(partnerName)

    sprintf(url, "/v1/admin/partner/%s", partnerName);
    int res = NKProcessRequest(handle, url, "POST", NULL, &result);
    if (!res || !result.data)
        return 0;

    cJSON *partnerItem = cJSON_GetObjectItem(result.data, "partner");
    returnPartner = calloc(1, sizeof(NKPartner));
    returnPartner->name = strdup(cJSON_GetObjectItem(partnerItem, "name")->valuestring);
    returnPartner->id = strdup(cJSON_GetObjectItem(partnerItem, "id")->valuestring);

    cJSON_Delete(result.data);
    return returnPartner;

}

int NKDeletePartner(NKHandle *handle, NKPartner *partner) {
    NKResult result;
    char url[255];

    ARG_REQUIRED(handle)
    ARG_REQUIRED(partner)

    sprintf(url, "/v1/admin/partner/%s", partner->name);
    int res = NKProcessRequest(handle, url, "DELETE", NULL, &result);
    if (!res || !result.data)
        return 0;

    if (result.http_code == 204)
        return 1;
    return 0;
}

/*
 * NKRequest
 */
int string_in_list(char *str, char **list, int len) {

    ARG_REQUIRED(str)
    ARG_REQUIRED(list)

    for (int i = 0; i < len; i++) {
        if (!strcmp(list[i], str)) {
            return 1;
        }
    }
    return 0;
}

char *_CreateHeader(char *key, char *value) {

    ARG_REQUIRED(key)
    ARG_REQUIRED(value)

    char *ret = calloc(strlen(key) + strlen(value) + 2, sizeof(char));
    sprintf(ret, "%s: %s", key, value);
    return ret;
}

int NKProcessRequest(NKHandle *handle, char *url, char *method, char *data, NKResult *result) {

    char **headers = NULL;
    int headerCount = 0;
    char *returnData;
    long httpStatusCode = 0;

    // Init http_code
    result->http_code = 0;

    ARG_REQUIRED(handle)
    ARG_REQUIRED(url)
    ARG_REQUIRED(method)
    ARG_REQUIRED(result)

    // Only allowed methods
    char *allowedMethods[] = {"GET", "POST", "PUT", "DELETE"};
    if (!string_in_list(method, allowedMethods, 4)) {
        fprintf(stderr, "Method %s NOT ALLOWED", method);
        return 0;
    }

    // Distributed API Access Data
    secp256k1_ecdsa_signature requestSig;
    secp256k1_pubkey userPubkey;
    secp256k1_context *ecdsaCtx;

    size_t userPubkeyDataLen, partnerPubkeyDataLen, sigDataLen, requestSigDerLen = 255, partnerKeySigLen = 255;

    // Build URL
    char finalUrl[strlen(handle->apiUrl) + strlen(url) + 1];
    strcpy(finalUrl, handle->apiUrl);
    strcat(finalUrl, url);

    // Setup Headers Based on Partner API Key or Distributed API Access
    if (handle->partnerId && handle->apiKey) {

        headerCount = 3;
        headers = calloc((size_t) headerCount, sizeof(char *));
        headers[0] = _CreateHeader("Content-Type", "application/json");
        headers[1] = _CreateHeader("X-Partner-ID", handle->partnerId);
        headers[2] = _CreateHeader("Authorization", handle->apiKey);

    } else if (handle->userKey && handle->keySignature && handle->partnerSigningKey) {

        unsigned char *userPubKeyDER, *partnerPubKeyDER, *requestSigDer, *requestKeySigDer;

        // Create SECP256K1 Context
        ecdsaCtx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        // Create User Public Key from Private Key
        int pubkeyRes = secp256k1_ec_pubkey_create(ecdsaCtx, &userPubkey, handle->userKey);
        if (!pubkeyRes) {
            fprintf(stderr, "Unable to Create ECDSA SECP256K1 Public Key from Private Key Data");
            return 0;
        }

        // Serialize User Public Key and Partner Public Key using DER-Encoding
        userPubKeyDER = NK_PubkeySerializeDER(ecdsaCtx, &userPubkey, &userPubkeyDataLen);
        partnerPubKeyDER = NK_PubkeySerializeDER(ecdsaCtx, handle->partnerSigningKey, &partnerPubkeyDataLen);

        // Setup Data to Hash->Sign
        sigDataLen = strlen(finalUrl) + 1;
        if (data)
            sigDataLen += strlen(data);

        char urlPlusData[sigDataLen];
        strcpy(urlPlusData, finalUrl);
        if (data)
            strcat(urlPlusData, data);

        // Hash Data
        unsigned char hashData[32];
        BRSHA256(hashData, urlPlusData, strlen(urlPlusData));

        // Sign Data
        int signRes = secp256k1_ecdsa_sign(ecdsaCtx, &requestSig, hashData, handle->userKey, NULL, NULL);
        if (!signRes) {
            fprintf(stderr, "Process Request Signing Failed");
            return 0;
        }

        // Convert Signatures to DER
        requestSigDer = calloc(requestSigDerLen, sizeof(char));
        int serializeRes = secp256k1_ecdsa_signature_serialize_der(ecdsaCtx, requestSigDer, &requestSigDerLen,
                                                                   &requestSig);
        if (!serializeRes) {
            fprintf(stderr, "Signature Serialization to DER-encoding failed");
            return 0;
        }

        requestKeySigDer = calloc(partnerKeySigLen, sizeof(char));
        int keysigRes = secp256k1_ecdsa_signature_serialize_der(ecdsaCtx, requestKeySigDer, &partnerKeySigLen,
                                                                handle->keySignature);
        if (!keysigRes) {
            fprintf(stderr, "Partner Key Signature Serialization to DER-encoding failed");
            return 0;
        }

        // Set Distributed API Access Headers
        headerCount = 5;
        headers = calloc((size_t) headerCount, sizeof(char *));
        headers[0] = _CreateHeader("Content-Type", "application/json");
        headers[1] = _CreateHeader("X-Identity", NK_BytesToHexString(userPubKeyDER, userPubkeyDataLen));
        headers[2] = _CreateHeader("X-Signature", NK_BytesToHexString(requestSigDer, requestSigDerLen));
        headers[3] = _CreateHeader("X-Partner-Key", NK_BytesToHexString(partnerPubKeyDER, partnerPubkeyDataLen));
        headers[4] = _CreateHeader("X-Partner-KeySig", NK_BytesToHexString(requestKeySigDer, partnerKeySigLen));
    }

    // Allocate Return Data Buffer
    returnData = calloc(HTTP_BUFFER_SIZE, sizeof(char));
    if (!returnData)
        fprintf(stderr, "Error allocating %d bytes.\n", HTTP_BUFFER_SIZE);

    char **returnHeaders = calloc(64, sizeof(char *));

    (*(handle->httpCallback))(finalUrl, method, data, headers, headerCount, returnData, returnHeaders, &httpStatusCode);
    if(httpStatusCode == 204) {
        free(returnData);
        free(returnHeaders);
        return 1;
    }

    cJSON *jsonRoot = cJSON_Parse(returnData);
    free(returnData);
    free(returnHeaders);

    if (!jsonRoot)
        return 0;

    // Return Result
    result->data = jsonRoot;
    result->http_code = httpStatusCode;
    return 1;
}

/*
 * Utility Functionality
 */
unsigned char *NK_PubkeySerializeDER(secp256k1_context *ctx, secp256k1_pubkey *pubkey, size_t *strLen) {

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

char *NK_BytesToHexString(uint8_t *data, size_t length) {
    char *buf_str = calloc(2 * length + 1, sizeof(char));
    char *buf_ptr = buf_str;
    for (int i = 0; i < length; i++) {
        buf_ptr += sprintf(buf_ptr, "%02X", data[i]);
    }
    *(buf_ptr + 1) = '\0';
    return buf_str;
}

int NKIsError(NKResult *result) {
    if (result->http_code >= 400) return 1;
    return 0;
}

char *NKGetError(NKResult *result) {
    if (result->http_code < 400) return NULL;
    if (result->data == NULL) return NULL;
    return cJSON_GetObjectItem(result->data, "message")->valuestring;
}

char **NKGetAllErrors(NKResult *result) {
    if (result->http_code < 400) return NULL;
    if (result->data == NULL) return NULL;

    cJSON *failureArray = cJSON_GetObjectItem(result->data, "failures");
    int failureCount = cJSON_GetArraySize(failureArray);

    char **failures = calloc((size_t) (failureCount + 1), sizeof(char *));
    failures[0] = strdup(cJSON_GetObjectItem(result->data, "message")->valuestring);
    for (int i = 0; i < failureCount; i++) {
        cJSON *arrayItem = cJSON_GetArrayItem(failureArray, i);
        failures[i + 1] = strdup(cJSON_GetObjectItem(arrayItem, "message")->valuestring);
    }
    return failures;
}