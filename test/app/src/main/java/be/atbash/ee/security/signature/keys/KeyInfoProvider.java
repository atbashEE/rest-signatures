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
package be.atbash.ee.security.signature.keys;

import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.SignatureKeyInfoProvider;
import be.atbash.ee.security.signature.api.common.Algorithm;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.net.URI;

/**
 *
 */
@ApplicationScoped
public class KeyInfoProvider implements SignatureKeyInfoProvider {

    @Inject
    private JWKManager jwkManager;

    private SignatureKeyInfo keyInfo;
    private SignatureKeyInfo rsaKeyInfo;

    @PostConstruct
    public void init() {
        keyInfo = new SignatureKeyInfo("hmac-sha256", "signature-demo", "I love security");
        rsaKeyInfo = new SignatureKeyInfo(Algorithm.get("rsa-sha256"), "fb943c5c-8653-4144-b00e-0a714bdc958e", jwkManager.getKey());
    }

    @Override
    public SignatureKeyInfo provideKeyFor(String method, URI uri) {

        if (uri.getPath().contains("keys")) {
            return rsaKeyInfo;
        } else {
            return keyInfo;
        }
    }

}
