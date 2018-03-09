/*
 * Copyright 2017-2018 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.signature.api.sign;

import be.atbash.ee.security.signature.api.SignatureKeyInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static be.atbash.ee.security.signature.api.Constants.HEADER_DATE;
import static be.atbash.ee.security.signature.api.Constants.HEADER_DIGEST;

/**
 * Information about how the signature needs to be build.
 */

public class SignatureInfo {

    private boolean needsDigest;
    private List<String> headers;
    private SignatureKeyInfo signatureKeyInfo;

    public SignatureInfo(boolean needsDigest, SignatureKeyInfo signatureKeyInfo, String... headers) {
        this.needsDigest = needsDigest;
        this.headers = new ArrayList<>(Arrays.asList(headers));

        addRequiredDateHeader();
        if (needsDigest && !this.headers.contains(HEADER_DIGEST)) {
            this.headers.add(HEADER_DIGEST);
        }
        this.signatureKeyInfo = signatureKeyInfo;
    }

    public SignatureInfo(SignatureKeyInfo signatureKeyInfo, List<String> headers) {
        this.signatureKeyInfo = signatureKeyInfo;
        this.headers = headers;
        addRequiredDateHeader();
    }

    private void addRequiredDateHeader() {
        if (!this.headers.contains(HEADER_DATE)) {
            // 2.1.3 Date is always required
            //If not specified,
            //implementations MUST operate as if the field were specified with a
            //single value, the ‘Date‘ header, in the list of HTTP headers.
            ArrayList<String> temp = new ArrayList<>(this.headers);  // We can have a unmodifiable List
            temp.add(HEADER_DATE);
            this.headers = temp;
        }
    }

    public boolean isNeedsDigest() {
        return needsDigest;
    }

    public List<String> getHeaders() {
        return headers;
    }

    public SignatureKeyInfo getSignatureKeyInfo() {
        return signatureKeyInfo;
    }
}
