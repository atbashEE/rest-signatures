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

import be.atbash.ee.security.signature.api.common.Algorithm;
import be.atbash.ee.security.signature.exception.UnsupportedAlgorithmException;

import javax.crypto.Mac;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;

/**
 *
 */
// Adapted from Tomitribe http-signatures-java
public interface KeySigner {
    byte[] sign(byte[] signingStringBytes);

    abstract class AbstractKeySigner implements KeySigner {
        public static KeySigner createKeySigner(Algorithm algorithm, Key key) {
            KeySigner result;
            if (java.security.Signature.class.equals(algorithm.getType())) {

                result = new Asymmetric(algorithm, PrivateKey.class.cast(key));

            } else if (Mac.class.equals(algorithm.getType())) {

                result = new Symmetric(algorithm, key);

            } else {

                throw new UnsupportedAlgorithmException(algorithm.getPortableName());
            }
            return result;

        }

    }

    class Asymmetric extends AbstractKeySigner {

        private Algorithm algorithm;
        private PrivateKey key;

        private Asymmetric(Algorithm algorithm, final PrivateKey key) {
            this.algorithm = algorithm;
            this.key = key;
        }

        @Override
        public byte[] sign(byte[] signingStringBytes) {
            try {

                // TODO reuse same instance over and over again.
                Signature instance = Signature.getInstance(algorithm.getJmvName());

                instance.initSign(key);
                instance.update(signingStringBytes);
                return instance.sign();

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);
            }
        }
    }

    class Symmetric extends AbstractKeySigner {

        private Algorithm algorithm;
        private Key key;

        private Symmetric(Algorithm algorithm, final Key key) {
            this.algorithm = algorithm;
            this.key = key;
        }

        @Override
        public byte[] sign(byte[] signingStringBytes) {

            try {

                Mac mac = Mac.getInstance(algorithm.getJmvName());
                mac.init(key);
                return mac.doFinal(signingStringBytes);

            } catch (NoSuchAlgorithmException e) {

                throw new UnsupportedAlgorithmException(algorithm.getJmvName());

            } catch (Exception e) {

                throw new IllegalStateException(e);

            }
        }
    }
}