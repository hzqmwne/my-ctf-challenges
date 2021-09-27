// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES_WHITEBOX_H_
#define AES_WHITEBOX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

void aes_whitebox_encrypt_with_external_xor(const uint8_t m[16], uint8_t c[16]);

#ifdef __cplusplus
}
#endif

#endif  // AES_WHITEBOX_H_
