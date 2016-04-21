//
// Created by Matt David on 4/13/16.
//

#ifndef C_PARTNER_API_CLIENT_BASE64_H
#define C_PARTNER_API_CLIENT_BASE64_H

#include <stdatomic.h>

int base64decode (char *in, size_t inLen, unsigned char *out, size_t *outLen);

#endif //C_PARTNER_API_CLIENT_BASE64_H
