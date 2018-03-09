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
import be.atbash.ee.security.signature.exception.IncorrectAlgorithmException;
import be.atbash.ee.security.signature.exception.MissingKeyException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * Only required for the verification of the signature. Receiver side.
 */

public class SignatureKeyData {

    protected Algorithm algorithm;

    private Key key;

    public SignatureKeyData(String algoPortableName, String passphrase) {
        algorithm = Algorithm.get(algoPortableName);
        if (!Mac.class.equals(algorithm.getType())) {
            throw new IncorrectAlgorithmException(algoPortableName); // TODO Better exception message
        }
        key = new SecretKeySpec(passphrase.getBytes(), algorithm.getJmvName());
    }

    public SignatureKeyData(Key key) {
        if (key == null) {
            throw new MissingKeyException();
        }
        this.key = key;
    }

    public Key getKey() {
        return key;
    }
}
