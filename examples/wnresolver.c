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
#include <getopt.h>
#include <libgen.h>
#include "../wnresolver.h"
#include "curlHttpCallbackImpl.h"

void printUsage(char *execName) {
    fprintf(stderr, "Usage: %s %-26s-> Lookup <currency> Wallet Address for <walletName>\n", basename(execName), "-w walletName -c currency");
    fprintf(stderr, "Usage: %s %-26s-> Lookup Available Currencies for <walletName>\n", basename(execName), "-w walletName");
}

int main(int argc, char **argv) {

    char *inWalletName = NULL;
    char *inCurrency = NULL;

    int c = 0;

    if(argc == 1) {
        printUsage(argv[0]);
        return 1;
    }

    while((c = getopt(argc, argv, "hc:w:")) != -1) {
        switch(c) {
            case 'c':
                inCurrency = optarg;
                break;

            case 'w':
                inWalletName = optarg;
                break;

            case 'h':
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    /*
     * Wallet Name Resolution Example
     */
    NKResolverHandle *resolverHandle = NKResolverHandlerInit();
    NKResolverSetResolveConfPath(resolverHandle, "/var/run/resolv.conf");
    NKResolverSetTrustAnchorPath(resolverHandle, "/usr/local/etc/unbound/root.key");
    NKResolverSetHttpCallback(resolverHandle, CurlHttpImplementation);

    char *walletAddress;
    char **supportedCurrencies;
    int supportedCurrencyCount = 0;

    if(inWalletName != NULL && inCurrency != NULL) {

        walletAddress = calloc(1024, sizeof(char));

        // Resolve Wallet Address for WalletName/Currency combination
        NKResolveWalletName(resolverHandle, inWalletName, inCurrency, walletAddress);
        fprintf(stdout, "Wallet Address - %s (%s): %s\n", inWalletName, inCurrency, walletAddress);

        free(walletAddress);

    } else if(inWalletName != NULL) {

        supportedCurrencies = calloc(64, sizeof(char *));

        // Get Supported Currencies
        NKResolveWalletNameCurrencies(resolverHandle, inWalletName, supportedCurrencies, &supportedCurrencyCount);
        if(!supportedCurrencyCount) {
            fprintf(stderr, "No Supported Currencies for Wallet Name: %s\n", inWalletName);
            return 1;
        }

        fprintf(stdout, "Supported Currencies for Wallet Name (%s): ", inWalletName);
        for(int i = 0; i < supportedCurrencyCount; i++) {
            if (i > 0 && i < supportedCurrencyCount)
                fprintf(stdout, ", ");
            fprintf(stdout, "%s", supportedCurrencies[i]);
            free(supportedCurrencies[i]);
        }
        fprintf(stdout, "\n");
        free(supportedCurrencies);
    } else {
        printUsage(argv[0]);
    }

    return 0;
}