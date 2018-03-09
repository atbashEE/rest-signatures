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

import be.atbash.ee.security.signature.api.common.Signer;
import be.atbash.ee.security.signature.api.common.URIInfo;

import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;

/**
 *
 */

public final class SignatureGenerator {

    private static SignatureGenerator INSTANCE = new SignatureGenerator();

    private Signer signer;

    private SignatureGenerator() {
        signer = new Signer();
    }

    public Signature create(SignatureInfo signatureInfo, URIInfo uriInfo, MultivaluedMap<String, ?> headers) throws UnsupportedEncodingException {

        String encodedSignature = signer.sign(headers, signatureInfo, uriInfo);

        return new SignatureBuilder().fromSignatureInfo(signatureInfo).withEncodedSignature(encodedSignature).build();
    }

    public static SignatureGenerator getInstance() {
        return INSTANCE;
    }
}
