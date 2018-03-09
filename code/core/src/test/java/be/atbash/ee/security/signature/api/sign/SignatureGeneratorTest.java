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

import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.common.URIInfo;
import org.junit.Test;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;

/**
 *
 */

public class SignatureGeneratorTest {

    @Test
    public void create() throws UnsupportedEncodingException {

        SignatureKeyInfo keyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(false, keyInfo, "content-length", "host", "date", "(request-target)");
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("Host", "example.org");
        headers.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.addFirst("Content-Length", "18");

        URIInfo uriInfo = new URIInfo("GET", "/foo");
        SignatureGenerator.getInstance().create(signatureInfo, uriInfo, headers);

    }
}