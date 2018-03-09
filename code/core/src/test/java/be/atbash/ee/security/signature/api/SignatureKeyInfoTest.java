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

import be.atbash.ee.security.signature.api.common.Algorithm;
import be.atbash.ee.security.signature.exception.MissingAlgorithmException;
import be.atbash.ee.security.signature.exception.MissingKeyException;
import be.atbash.ee.security.signature.exception.MissingKeyIdException;
import org.junit.Test;

/**
 *
 */

public class SignatureKeyInfoTest extends AbstractTestWithRSAKey {

    @Test
    public void happyCase_HMAC() {
        new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
    }

    @Test(expected = NullPointerException.class)
    public void case_HMAC_noPassphrase() {
        new SignatureKeyInfo("hmac-sha256", "hmac-key-1", null);
    }

    @Test(expected = MissingKeyIdException.class)
    public void case_HMAC_noKeyId() {
        new SignatureKeyInfo("hmac-sha256", null, "don't tell");
    }

    @Test(expected = MissingAlgorithmException.class)
    public void case_HMAC_noAlgo() {
        new SignatureKeyInfo(null, "hmac-key-1", "don't tell");
    }

    @Test
    public void happyCase_Key() {
        new SignatureKeyInfo(Algorithm.RSA_SHA256, "rsa-1", publicKey);
    }

    @Test(expected = MissingKeyException.class)
    public void case_missingKey() {
        new SignatureKeyInfo(Algorithm.RSA_SHA256, "rsa-1", null);
    }

    @Test(expected = MissingKeyIdException.class)
    public void case_missingKeyId() {
        new SignatureKeyInfo(Algorithm.RSA_SHA256, null, publicKey);
    }

    @Test(expected = MissingAlgorithmException.class)
    public void case_MissingAlgo() {
        new SignatureKeyInfo(null, "rsa-1", publicKey);
    }

}