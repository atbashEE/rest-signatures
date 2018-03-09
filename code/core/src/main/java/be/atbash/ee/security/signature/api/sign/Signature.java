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

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.common.Algorithm;
import be.atbash.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static be.atbash.ee.security.signature.api.Constants.HEADER_DATE;

/**
 * Information about the signature header.
 */
// Adapted from Tomitribe http-signatures-java
public class Signature {

    /**
     * REQUIRED.  The `keyId` field is an opaque string that the server can
     * use to look up the component they need to validate the signature.  It
     * could be an SSH key fingerprint, a URL to machine-readable key data,
     * an LDAP DN, etc.  Management of keys and assignment of `keyId` is out
     * of scope for this document.
     */
    private final String keyId;

    /**
     * REQUIRED.  The `algorithm` parameter is used to specify the digital
     * signature algorithm to use when generating the signature.  Valid
     * values for this parameter can be found in the Signature Algorithms
     * registry located at http://www.iana.org/assignments/signature-
     * algorithms and MUST NOT be marked "deprecated".
     */
    private final Algorithm algorithm;

    /**
     * OPTIONAL.  The `headers` parameter is used to specify the list of
     * HTTP headers included when generating the signature for the message.
     * If specified, it should be a lowercased, quoted list of HTTP header
     * fields, separated by a single space character.  If not specified,
     * implementations MUST operate as if the field were specified with a
     * single value, the `Date` header, in the list of HTTP headers.  Note
     * that the list order is important, and MUST be specified in the order
     * the HTTP header field-value pairs are concatenated together during
     * signing.
     */
    private final String signature;

    /**
     * REQUIRED.  The `signature` parameter is a base 64 encoded digital
     * signature, as described in RFC 4648 [RFC4648], Section 4 [4].  The
     * client uses the `algorithm` and `headers` signature parameters to
     * form a canonicalized `signing string`.  This `signing string` is then
     * signed with the key associated with `keyId` and the algorithm
     * corresponding to `algorithm`.  The `signature` parameter is then set
     * to the base 64 encoding of the signature.
     */
    private final List<String> headers;

    //private final boolean isAuthenticationBased = false;  // FIXME For the moment, we only support Signature header (not Authorization header with signature scheme.

    Signature(String keyId, Algorithm algorithm, String signature, List<String> headers) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId is required.");
        }
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm is required.");
        }
        if (signature == null) {
            throw new IllegalArgumentException("signature is required.");
        }

        this.keyId = keyId;
        this.algorithm = algorithm;

        this.signature = signature;

        if (headers.size() == 0) {
            this.headers = Collections.singletonList(HEADER_DATE);
        } else {
            this.headers = Collections.unmodifiableList(lowercase(headers));
        }
    }

    private List<String> lowercase(List<String> headers) {
        List<String> list = new ArrayList<>(headers.size());
        for (String header : headers) {
            list.add(header.toLowerCase());
        }
        return list;
    }

    public String getKeyId() {
        return keyId;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public String getSignature() {
        return signature;
    }

    public List<String> getHeaders() {
        return headers;
    }

    @Override
    public String toString() {
        return Constants.KEY_ID + "=\"" + keyId + "\"," +
                Constants.ALGORITHM + "=\"" + algorithm + "\"," +
                Constants.HEADERS + "=\"" + StringUtils.toDelimitedString(" ", headers) + "\"," +
                Constants.SIGNATURE + "=\"" + signature + '\"';
    }

}
