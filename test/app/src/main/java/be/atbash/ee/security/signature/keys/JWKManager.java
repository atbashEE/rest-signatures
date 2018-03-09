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

import be.atbash.ee.security.signature.exception.ServiceConfigurationException;
import be.atbash.ee.security.signature.exception.ServiceUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.text.ParseException;
import java.util.Scanner;

/**
 *
 */
@ApplicationScoped
public class JWKManager {

    private JWK jwk;

    @PostConstruct
    public void init() {
        jwk = readJWK();
    }

    private JWK readJWK() {
        JWK result;
        String jwkFile = "rsa.key";

        InputStream inputStream = JWKManager.class.getClassLoader().getResourceAsStream(jwkFile);
        try {
            if (inputStream == null) {
                inputStream = new FileInputStream(jwkFile);
            }
            String content = new Scanner(inputStream).useDelimiter("\\Z").next();
            result = JWK.parse(content);
        } catch (FileNotFoundException e) {
            throw new ServiceConfigurationException(String.format("JWK File not found at %s", jwkFile));
        } catch (ParseException e) {
            throw new ServiceConfigurationException(String.format("Parsing the JWK file failed with %s", e.getMessage()));
        }

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new ServiceUnexpectedException(e);
        }

        return result;
    }

    public Key getKey() {
        try {
            return ((RSAKey) jwk).toPrivateKey();
        } catch (JOSEException e) {
            throw new ServiceUnexpectedException(e);
        }
    }

}
