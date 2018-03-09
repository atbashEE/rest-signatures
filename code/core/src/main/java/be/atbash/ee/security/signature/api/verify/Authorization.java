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

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.common.Algorithm;
import be.atbash.ee.security.signature.api.util.HeaderUtil;
import be.atbash.ee.security.signature.exception.MissingAlgorithmException;
import be.atbash.ee.security.signature.exception.MissingKeyIdException;
import be.atbash.ee.security.signature.exception.MissingSignatureException;
import be.atbash.util.base64.Base64Codec;

import java.io.Serializable;
import java.util.*;

/**
 * Representation of the "Authorization: Signature..." header sent by the client.
 */
public final class Authorization implements Serializable {

    private static final long serialVersionUID = -5642537789425001043L;

    private boolean correctAuthorizationHeader;
    private String keyId;
    private String signature;
    private List<String> headers;
    private Algorithm algorithm;

    /**
     * Construct an {@link Authorization} instance
     */
    public Authorization(String authorizationHeader) {
        fromHeader(authorizationHeader);
    }

    public boolean isCorrectAuthorizationHeader() {
        return correctAuthorizationHeader;
    }

    public String getKeyId() {
        return keyId;
    }

    /**
     * @return the signature as a Base64-encoded string
     */
    public String getSignature() {
        return signature;
    }

    /**
     * @return the signature as an unencoded byte array for verification using a {@link Verifier}
     */
    public byte[] getSignatureBytes() {
        return Base64Codec.decode(signature);
    }

    public List<String> getHeaders() {
        return headers;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    private void fromHeader(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.toLowerCase().startsWith(Constants.SCHEME.toLowerCase())) {

            String authParameters = stripScheme(authorizationHeader);
            Map<String, String> parameters = HeaderUtil.parseAuthenticationParameters(authParameters);

            keyId = parameters.get(Constants.KEY_ID);
            if (keyId == null) {
                throw new MissingKeyIdException();
            }

            String algorithmValue = parameters.get(Constants.ALGORITHM);
            if (algorithmValue == null) {
                throw new MissingAlgorithmException(true);
            }
            algorithm = Algorithm.get(algorithmValue);

            signature = parameters.get(Constants.SIGNATURE);
            if (signature == null) {
                throw new MissingSignatureException();
            }

            String headersValue = parameters.get(Constants.HEADERS);

            if (headersValue == null) {
                this.headers = Constants.DEFAULT_HEADERS;
            } else {
                List<String> headerList = parseTokens(headersValue);
                this.headers = filterHeaders(headerList);
            }

            correctAuthorizationHeader = true;
        }
    }

    private String stripScheme(String authorizationHeader) {
        return authorizationHeader.substring(Constants.SCHEME.length() + 1).trim();
    }

    private List<String> parseTokens(String tokens) {
        if (tokens == null || tokens.trim().isEmpty()) {
            return Collections.emptyList();
        } else {
            return Collections.unmodifiableList(Arrays.asList(tokens.trim().split("\\s+")));
        }
    }

    private List<String> filterHeaders(List<String> headers) {
        if (headers == null) {
            return Collections.emptyList();
        }

        List<String> _headers = new ArrayList<>(headers.size());
        for (String header : headers) {
            if (!Constants.IGNORE_HEADERS.contains(header.toLowerCase())) {
                _headers.add(header.toLowerCase());
            }
        }

        return Collections.unmodifiableList(_headers);
    }

}
