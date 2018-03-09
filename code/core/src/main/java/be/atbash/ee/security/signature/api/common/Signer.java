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
package be.atbash.ee.security.signature.api.common;

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.sign.KeySigner;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.ee.security.signature.exception.MissingRequiredHeaderException;
import be.atbash.util.StringUtils;
import be.atbash.util.base64.Base64Codec;

import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 */
// Adapted from Tomitribe http-signatures-java
public class Signer {

    public String sign(MultivaluedMap<String, ?> headers, SignatureInfo signatureInfo, URIInfo uriInfo) throws UnsupportedEncodingException {

        Map<String, String> signatureHeaders = defineHeaders(headers);

        String signingString = createSigningString(signatureInfo.getHeaders(), uriInfo.getMethod(), uriInfo.getPath(), signatureHeaders);

        KeySigner keySigner = KeySigner.AbstractKeySigner.createKeySigner(signatureInfo.getSignatureKeyInfo().getAlgorithm(), signatureInfo.getSignatureKeyInfo().getKey());
        byte[] binarySignature = keySigner.sign(signingString.getBytes("UTF-8"));

        return Base64Codec.encodeToString(binarySignature, false);

    }

    private Map<String, String> defineHeaders(MultivaluedMap<String, ?> headers) {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, ? extends List<?>> entry : headers.entrySet()) {
            result.put(entry.getKey(), getHeaderValue(entry.getValue()));
        }
        return result;
    }

    private String getHeaderValue(List<?> headerValues) {
        /*
        section 2.3 Signature String Construction point 2.
        If there are multiple instances of the same header field, all
       header field values associated with the header field MUST be
       concatenated, separated by a ASCII comma and an ASCII space ‘, ‘,
       and used in the order in which they will appear in the
       transmitted HTTP message.
        */
        StringBuilder result = new StringBuilder();
        for (Object headerValue : headerValues) {

            if (result.length() > 1) {
                result.append(", ");
            }
            result.append(headerValue.toString());
        }

        return result.toString();
    }

    private String createSigningString(List<String> required, String method, String uri, Map<String, String> headers) {
        method = lowercase(method);
        headers = lowercase(headers);

        List<String> list = new ArrayList<>(required.size());

        for (String key : required) {
            if (Constants.HEADER_REQUEST_TARGET.equals(key)) {
                list.add(StringUtils.toDelimitedString(" ", Constants.HEADER_REQUEST_TARGET + ":", method, uri));

            } else {
                String value = headers.get(key);
                if (value == null) {
                    throw new MissingRequiredHeaderException(key);
                }

                list.add(key + ": " + value);
            }
        }

        return StringUtils.toDelimitedString("\n", list);
    }

    private Map<String, String> lowercase(Map<String, String> headers) {
        Map<String, String> map = new HashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            map.put(entry.getKey().toLowerCase(), entry.getValue());
        }

        return map;
    }

    private String lowercase(String spec) {
        return spec.toLowerCase();
    }
}
