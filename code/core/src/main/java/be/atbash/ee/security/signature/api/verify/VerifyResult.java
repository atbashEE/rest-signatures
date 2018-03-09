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
package be.atbash.ee.security.signature.api.verify;

import be.atbash.ee.security.signature.api.common.URIInfo;

import javax.ws.rs.core.MultivaluedMap;
import java.security.Key;

/**
 * Enumeration of possible results from {@link Verifier#verify(MultivaluedMap, String, URIInfo)}.
 */
public enum VerifyResult {

    /**
     * Signature is valid
     */
    SUCCESS("success"),

    /**
     *
     */
    INCORRECT_AUTHORIZATION_HEADER("Incorrect Authorization Header"),

    /**
     *
     */
    NO_AUTHORIZATION_HEADER("TODO"),

    /**
     *
     */
    NO_SIGNATURE_HEADER("No signature header found"),

    /**
     * Not all headers identified by the {@link Authorization} are present in the {@link RequestContent}
     */
    INCOMPLETE_REQUEST("Missing header defined in Signature"),

    /**
     * The value of the date header falls outside of the current time of the {@link Verifier}, plus or minus the skew
     */
    EXPIRED_DATE_HEADER("Date header identified as expired"),

    /**
     * The {@link Verifier} cannot find a {@link Key} matching the keyId of the {@link Authorization}
     */
    KEY_NOT_FOUND("Signature key not found"),

    /**
     * The selected {@link Key} rejected the signature as invalid
     */
    FAILED_KEY_VERIFY("Failed Signature verification"),

    /**
     * Disgest values doesn't match
     */
    DIGEST_MISMATCH("Digest check of message failed");

    private String message;

    VerifyResult(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
