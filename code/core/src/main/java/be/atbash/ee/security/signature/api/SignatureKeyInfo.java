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
import be.atbash.ee.security.signature.exception.MissingKeyIdException;

import java.security.Key;

/**
 * Definition of the Signature Key. Sender side.
 */
public class SignatureKeyInfo extends SignatureKeyData {

    private String keyId;

    public SignatureKeyInfo(String algoPortableName, String keyId, String passphrase) {
        super(algoPortableName, passphrase);
        if (keyId == null) {
            throw new MissingKeyIdException();
        }

        this.keyId = keyId;
    }

    public SignatureKeyInfo(Algorithm algorithm, String keyId, Key key) {
        super(key);
        if (keyId == null) {
            throw new MissingKeyIdException();
        }

        if (algorithm == null) {
            throw new MissingAlgorithmException(false);
        }

        // FIXME See that we can verify that a correct Key is specified for the algorithm
        this.algorithm = algorithm;
        this.keyId = keyId;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public String getKeyId() {
        return keyId;
    }
}
