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
package be.atbash.ee.security.signature.jaxrs.provider;

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.ee.security.signature.api.sign.SignatureInfoProvider;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import java.net.URI;

/**
 *
 */

@ApplicationScoped
@Priority(Integer.MAX_VALUE)
public class DefaultSignatureInfoProvider implements SignatureInfoProvider {

    @Override
    public SignatureInfo provideInfoFor(String method, URI uri, SignatureKeyInfo signatureKeyInfo) {
        boolean needsDigest = false;
        if ("POST".equals(method) || "PUT".equals(method)) {
            needsDigest = true;
        }
        return new SignatureInfo(needsDigest, signatureKeyInfo, Constants.HEADER_REQUEST_TARGET);
    }
}
