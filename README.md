# C Netki Partner Client

This is a C implementation of the Netki Partner API Client that includes a native Wallet Name Resolver.

## Requirements

* **[libsecp256k1](https://github.com/bitcoin/secp256k1)** - ECC using SECP256K1 Curve
* **[libunbound](http://unbound.net)** - Wallet Name Resolution
* **HTTP Callback function** - Partner API Client & Wallet Name Resolution

## Installation
```bash
$ git clone https://github.com/netkicorp/c-partner-api-client
$ cmake
```

## Using the Netki Partner API Client
```c
#include <netki.h>

void httpCallback(char *url, char *method, char *submitData, char **headers, int headerCount, char *returnData, char **returnHeaders, long *returnHttpStatusCode) {
...
}

NKHandle *handle = NKHandleInit();
NKSetPartnerID(handle, "partnerId");
NKSetApiKey(handle, "apiKey");
NKSetHttpCallback(handle, httpCallback);

// Example Wallet Name Creation (for more detail see examples/partner.c)
NKWalletName *wn = NKCreateWalletName("partnerdomain.com", "walletName", "externalId");
NKSetCurrencyAddress(wn, "btc", "1CpLXM15vjULK3ZPGUTDMUcGATGR9xGitv");
NKSaveWalletName(handle, wn);

```
    
### Datatypes
```c
// Handle for Netki Partner API Client Operations
typedef struct NKHandle;

// typedef struct describing a Wallet Name 
typedef struct NKWalletName;

// typedef struct describing a Domain
typedef struct NKDomain;

// typedef struct describing a Partner
typedef struct NKPartner;

// Callback function type used for HTTP implementations for this library
typedef void (*NKHttpCallback)(char *url, char *method, char *submitData, char **headers, int headerCount, char *returnData, char **returnHeaders, long *returnHttpStatusCode);
```

### Functions

#### Netki Handle Operations
```c
// Initialize and Return NKHandle
NKHandle *NKHandleInit();

// Set NKHandle's HTTP Callback Function
void NKSetHttpCallback(NKHandle *handle, NKHttpCallback funcPtr);

// Set NKHandle's API URL (if not Netki Production API URL)
void NKSetApiUrl(NKHandle *handle, char *apiUrl);

// Set NKHandle's PartnerId for API Key Access
void NKSetPartnerID(NKHandle *handle, char* partnerId);

// Set NKHandle's API Key for API Key Access
void NKSetApiKey(NKHandle *handle, char *apiKey);

// Set NKHandle's User Private Key for Distributed API Access
void NKSetUserKey(NKHandle *handle, unsigned char *userKey, size_t keySize);

// Set NKHandle's Partner Signing Key for Distributed API Access
void NKSetPartnerSigningKey(NKHandle *handle, unsigned char *der_pubkey, size_t len);

// Set NKHandle's Key Signature for Distributed API Access
void NKSetKeySignature(NKHandle *handle, unsigned char *der_sig, size_t len);
```

#### Wallet Name Operations
```c
// Get All Wallet Names (domain and externalID are optional and can be NULL) from Netki Partner API. 
// Returns wallet name count and writes to walletNames
int NKGetWalletNames(NKHandle *handle, char *domain, char *externalID, NKWalletName **walletNames);

// Set a wallet address or URL for a currency on a Wallet Name
int NKSetCurrencyAddress(NKWalletName *wn, char *currency, char *walletAddress);

// Create a new Wallet Name
NKWalletName *NKCreateWalletName(char *domainName, char *name, char *externalId);

// Get a Wallet Name's configured wallet address for a given currency / asset type
char * NKGetWalletAddress(NKWalletName *wn, char *currency);

// Get a char array of used currencies (count = wn->walletCount)
char ** NKGetUsedCurrencies(NKWalletName *wn);

// Remove a configured currency / asset type from a Wallet Name 
int NKRemoveCurrencyAddress(NKWalletName *wn, char *currency);

// Delete a Wallet Name on Netki Partner API
int NKDeleteWalletName(NKHandle  *handle, NKWalletName *wn);

// Save a Wallet Name to Netki Partner API
int NKSaveWalletName(NKHandle *handle, NKWalletName *wn);
```

#### Domain Operations
```c
// Get all domains from Netki Partner API
int NKGetDomains(NKHandle *handle, NKDomain **domains);

// Create new domain on Netki Partner API
NKDomain *NKCreateDomain(NKHandle *handle, char *domainName, NKPartner *partner);

// Delete domain from Netki Partner API
int NKDeleteDomain(NKHandle *handle, NKDomain *domain);

// Load Domain Status from Netki Partner API
int NKLoadDomainStatus(NKHandle *handle, NKDomain *domain);

// Load DNSSEC Details from Netki Partner API
int NKLoadDomainDNSSECDetails(NKHandle *handle, NKDomain *domain);
```

#### Partner Operations
```c
// Get all partners from Netki Partner API
int NKGetPartners(NKHandle *handle, NKPartner **partners);

// Create new partner on Netki Partner API
NKPartner *NKCreatePartner(NKHandle *handle, char *partnerName);

// Delete existing partner from Netki Partner API
int NKDeletePartner(NKHandle *handle, NKPartner *partner);
```
    
## Using the Netki Wallet Name Resolver
```c
#include <netki/netki.h>
#include <netki/wnresolver.h>

void httpCallback(char *url, char *method, char *submitData, char **headers, int headerCount, char *returnData, char **returnHeaders, long *returnHttpStatusCode) {
...
}

NKResolverHandle *handle = NKResolverHandlerInit();
NKResolverSetResolveConfPath(handle, "/etc/resolv.conf");
NKResolverSetTrustAnchorPath(handle, "/usr/local/etc/unbound/root.key");
NKResolverSetHttpCallback(handle, httpCallback);

char **supportedCurrencies = calloc(16, sizeof(char*));
int supportedCurrencyCount;
char *walletAddress = calloc(255, sizeof(char));

NKResolveWalletNameCurrencies(resolverHandle, "batwallet.brucewayne.rocks", supportedCurrencies, &supportedCurrencyCount);
NKResolveWalletName(resolverHandle, "batwallet.brucewayne.rocks", "btc", walletAddress);
```

### Datatypes
```c
// Handle for Netki WalletName Resolving Operations
NKResolverHandle
```

### Functions
```c
// Initialize and Return NKResolverHandle
NKResolverHandle *NKResolverHandlerInit();

// Set NKResolverHandle's HTTP Callback Function
void NKResolverSetHttpCallback(NKResolverHandle *handle, NKHttpCallback funcPtr);

// Set path to resolv.conf
void NKResolverSetResolveConfPath(NKResolverHandle *handle, char *resolveConfPath);

// Set path to DNSSEC trust anchor
void NKResolverSetTrustAnchorPath(NKResolverHandle *handle, char *trustAnchorPath);

// Resolve WalletName and Currency Combination
int NKResolveWalletName(NKResolverHandle *handle, char *walletName, char *currency, char *walletAddress);

// Resolve Available Currencies of WalletName
int NKResolveWalletNameCurrencies(NKResolverHandle *handle, char *walletName, char **currencies, int *currencyCount);
```

## HTTP Callback Function

The Netki Partner API Client and Wallet Name Resolver require the use of HTTPS in order to communicate with the Netki Partner API as well as to resolve Wallet Names containing Address Service URLs. 

Because each platform handles and maintains their respective HTTP implementations differently, both the NKHandle and NKResolverHandle require that you set an HTTP callback function (NKHttpCallback). The function must be of the form:

```c
callbackFunc(char *url, char *method, char *submitData, char **headers, int headerCount, char *returnData, char **returnHeaders, long *returnHttpStatusCode);
```

[examples/curlHttpCallbackImpl.c](examples/curlHttpCallbackImpl.c) contains an reference HTTP callback implementation using [libcurl](https://curl.haxx.se/libcurl/). The callback function is called **CurlHttpImplementation**.

## Examples

See [examples/partner.c](examples/partner.c) for a full example of accessing the Netki Partner API using both API Key & Distributed API Access.

See [examples/wnresolver.c](examples/wnresolver.c) for a full examples of resolving Wallet Names and retrieving available currencies supported by Wallet Names.