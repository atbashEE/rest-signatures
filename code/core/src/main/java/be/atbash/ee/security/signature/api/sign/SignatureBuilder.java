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
import be.atbash.ee.security.signature.api.util.HeaderUtil;
import be.atbash.ee.security.signature.exception.MissingAlgorithmException;
import be.atbash.ee.security.signature.exception.MissingKeyIdException;
import be.atbash.ee.security.signature.exception.MissingSignatureException;

import java.util.*;

/**
 *
 */
public class SignatureBuilder {

    private String keyId;
    private Algorithm algorithm;
    private String signature;
    private List<String> headers;

    //private Boolean correctAuthorizationHeader;

    public SignatureBuilder fromHeader(String signature) {
        if (signature != null) {

            Map<String, String> parameters = HeaderUtil.parseAuthenticationParameters((signature));

            keyId = parameters.get(Constants.KEY_ID.toLowerCase());
            if (keyId == null) {
                throw new MissingKeyIdException();
            }

            String algorithmValue = parameters.get(Constants.ALGORITHM.toLowerCase());
            if (algorithmValue == null) {
                throw new MissingAlgorithmException(true);
            }
            algorithm = Algorithm.get(algorithmValue);

            this.signature = parameters.get(Constants.SIGNATURE.toLowerCase());
            if (this.signature == null) {
                throw new MissingSignatureException();
            }

            String headersValue = parameters.get(Constants.HEADERS.toLowerCase());

            if (headersValue == null) {
                this.headers = Constants.DEFAULT_HEADERS;
            } else {
                List<String> headerList = parseTokens(headersValue);
                this.headers = filterHeaders(headerList);
            }

            //correctAuthorizationHeader = true;

        }

        return this;
    }

    public SignatureBuilder fromSignatureInfo(SignatureInfo signatureInfo) {
        keyId = signatureInfo.getSignatureKeyInfo().getKeyId();
        algorithm = signatureInfo.getSignatureKeyInfo().getAlgorithm();
        headers = new ArrayList<>(signatureInfo.getHeaders());
        return this;
    }

    public SignatureBuilder withEncodedSignature(String encodedSignature) {
        signature = encodedSignature;
        return this;
    }

    public Signature build() {
        return new Signature(keyId, algorithm, signature, headers);
    }

    // TODO For the Authorization
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