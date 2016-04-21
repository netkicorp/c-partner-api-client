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
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "../netki.h"

/*********************************************
 * Example Curl HTTP Callback Implementation
 *********************************************/
struct write_result {
    char *data;
    int pos;
};

struct header_write_result {
    char **headers;
    int pos;
};

static size_t curl_write(void *ptr, size_t size, size_t nmemb, void *stream) {

    struct write_result *result = (struct write_result *) stream;

    // Will we overflow on this write?
    if (result->pos + size * nmemb >= HTTP_BUFFER_SIZE - 1) {
        fprintf(stderr, "curl error: too small buffer\n");
        return 0;
    }

    // Copy curl's stream buffer into our own buffer
    memcpy(result->data + result->pos, ptr, size * nmemb);

    // Advance the position
    result->pos += size * nmemb;

    return size * nmemb;
}

static size_t header_write(void *ptr, size_t size, size_t nmemb, void *stream) {

    struct header_write_result *result = (struct header_write_result *) stream;

    // Will we overflow on this write?
    if(result->pos > HTTP_RESULT_HEADER_COUNT - 1) {
        fprintf(stderr, "curl error: too small buffer\n");
        return 0;
    }

    // Copy curl's stream buffer into our own buffer
    result->headers[result->pos] = calloc(255, sizeof(char));
    memcpy(result->headers[result->pos], ptr, size * nmemb);

    // Advance the position
    result->headers[++result->pos] = NULL;

    return size * nmemb;
}

void CurlHttpImplementation(char *url, char *method, char *submitData, char **headers, int headerCount,
                             char *returnData, char **returnHeaders, long *returnHttpStatusCode) {

    struct write_result write_result = {
            .data = returnData,
            .pos = 0
    };

    struct header_write_result header_write_result = {
            .headers = returnHeaders,
            .pos = 0
    };

    CURL *curl = curl_easy_init();
    struct curl_slist *headerList = NULL;
    for(int i = 0; i < headerCount; i++) {
        headerList = curl_slist_append(headerList, headers[i]);
    }

    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);

    if(returnHeaders){
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_write);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &header_write_result);
    }

    if(headerList != NULL)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);

    if (strcmp(method, "POST") == 0) {
        curl_easy_setopt(curl, CURLOPT_POST, 1);
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    }

    if (submitData) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, submitData);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(submitData));
    }

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        return;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, returnHttpStatusCode);
    returnData[write_result.pos] = '\0';

    curl_easy_cleanup(curl);
    curl_slist_free_all(headerList);
}