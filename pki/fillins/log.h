// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BSSL_FILLINS_LOG_H_
#define BSSL_FILLINS_LOG_H_

#include <iostream>

// This header defines the logging macros, inherited from chrome.

// TODO(crbug.com/boringssl/663): Replace this with methods on the delegate.
#define DVLOG(l) 0 && std::cerr
#define LOG(l) 0 && std::cerr

#endif  // BSSL_FILLINS_LOG_H_
