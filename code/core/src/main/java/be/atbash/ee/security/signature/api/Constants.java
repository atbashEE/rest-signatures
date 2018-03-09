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
package be.atbash.ee.security.signature.api;

import java.util.Collections;
import java.util.List;

/**
 * Constant values used by the Signature Specification
 */
public final class Constants {

    private Constants() {
    }

    /**
     * Identifier for the Signature Authentication scheme
     */
    public static final String SCHEME = "Signature";

    /**
     * Parameter name for challenge-selected SSH Public Key Fingerprint
     */
    public static final String KEY_ID = "keyId";

    public static final String HEADER_REQUEST_TARGET = "(request-target)";

    public static final String HEADER_DATE = "date";

    public static final String HEADER_DATE_FORMAT = "EEE, dd MMM yyyy HH:mm:ss zzz";

    public static final String HEADER_DIGEST = "digest";

    public static final List<String> DEFAULT_HEADERS = Collections.singletonList(HEADER_DATE);

    /**
     * List of headers to always exclude from signature calculation
     */
    public static final List<String> IGNORE_HEADERS = Collections.singletonList("authorization");

    /**
     * Http request header representing client credentials
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2617.txt">RFC 2617: HTTP Authentication: Basic and Digest Access Authentication</a>
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * Parameter name for the "headers" authorization parameter
     */
    public static final String HEADERS = "headers";

    /**
     * Parameter name for the "signature" authorization parameter
     */
    public static final String SIGNATURE = "signature";

    /**
     * Parameter name for the "signature" authorization parameter
     */
    public static final String SIGNATURE_HEADER = "Signature";

    /**
     * Challenge header "algorithm" parameter
     */
    public static final String ALGORITHM = "algorithm";

}
