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

import be.atbash.ee.security.signature.exception.UnsupportedAlgorithmException;
import org.junit.Test;

import static be.atbash.ee.security.signature.api.common.Algorithm.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AlgorithmTest {

    @Test
    public void portableName() {
        assertThat(HMAC_SHA1.getPortableName()).isEqualTo("hmac-sha1");
        assertThat(HMAC_SHA256.getPortableName()).isEqualTo("hmac-sha256");
        assertThat(HMAC_SHA384.getPortableName()).isEqualTo("hmac-sha384");
        assertThat(HMAC_SHA512.getPortableName()).isEqualTo("hmac-sha512");
        assertThat(RSA_SHA1.getPortableName()).isEqualTo("rsa-sha1");
        assertThat(RSA_SHA256.getPortableName()).isEqualTo("rsa-sha256");
        assertThat(RSA_SHA384.getPortableName()).isEqualTo("rsa-sha384");
        assertThat(RSA_SHA512.getPortableName()).isEqualTo("rsa-sha512");
        assertThat(DSA_SHA1.getPortableName()).isEqualTo("dsa-sha1");
        assertThat(DSA_SHA224.getPortableName()).isEqualTo("dsa-sha224");
        assertThat(DSA_SHA256.getPortableName()).isEqualTo("dsa-sha256");
    }

    @Test
    public void jvmNames() {
        assertThat(HMAC_SHA1.getJmvName()).isEqualTo("HmacSHA1");
        assertThat(HMAC_SHA256.getJmvName()).isEqualTo("HmacSHA256");
        assertThat(HMAC_SHA384.getJmvName()).isEqualTo("HmacSHA384");
        assertThat(HMAC_SHA512.getJmvName()).isEqualTo("HmacSHA512");
        assertThat(RSA_SHA1.getJmvName()).isEqualTo("SHA1withRSA");
        assertThat(RSA_SHA256.getJmvName()).isEqualTo("SHA256withRSA");
        assertThat(RSA_SHA384.getJmvName()).isEqualTo("SHA384withRSA");
        assertThat(RSA_SHA512.getJmvName()).isEqualTo("SHA512withRSA");
        assertThat(DSA_SHA1.getJmvName()).isEqualTo("SHA1withDSA");
        assertThat(DSA_SHA224.getJmvName()).isEqualTo("SHA224withDSA");
        assertThat(DSA_SHA256.getJmvName()).isEqualTo("SHA256withDSA");
    }

    @Test
    public void getWithPortableName() {
        for (Algorithm algorithm : Algorithm.values()) {
            assertThat(Algorithm.get(algorithm.getPortableName())).isEqualTo(algorithm);
        }
    }

    @Test
    public void getWithJvmName() {
        for (Algorithm algorithm : Algorithm.values()) {
            assertThat(Algorithm.get(algorithm.getJmvName())).isEqualTo(algorithm);
        }
    }

    @Test
    public void getNotCaseSensitive() {
        for (Algorithm algorithm : Algorithm.values()) {

            assertThat(Algorithm.get(algorithm.getPortableName().toLowerCase())).isEqualTo(algorithm);
            assertThat(Algorithm.get(algorithm.getPortableName().toUpperCase())).isEqualTo(algorithm);

            assertThat(Algorithm.get(algorithm.getJmvName().toLowerCase())).isEqualTo(algorithm);
            assertThat(Algorithm.get(algorithm.getJmvName().toUpperCase())).isEqualTo(algorithm);

        }
    }

    @Test
    public void nonAlphaNumericsIgnored() {
        for (Algorithm algorithm : Algorithm.values()) {
            assertThat(Algorithm.get(algorithm.getPortableName().replace("-", " :-./ "))).isEqualTo(algorithm);
            assertThat(Algorithm.get(algorithm.getJmvName().replace("with", " -/with:."))).isEqualTo(algorithm);

        }
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void unsupportedAlgorithmException() {
        Algorithm.get("HmacMD256");
    }

}