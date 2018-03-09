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

import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.sign.Signature;
import be.atbash.ee.security.signature.api.sign.SignatureGenerator;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.ee.security.signature.exception.MissingRequiredHeaderException;
import org.junit.Test;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class SignerTest {

    @Test
    public void scenario1() throws UnsupportedEncodingException {

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        headers.add("content-length");
        headers.add("host");
        headers.add("date");
        headers.add("(request-target)");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Host", "example.org");
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        requestHeader.addFirst("Content-Type", "application/json");
        requestHeader.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        requestHeader.addFirst("Accept", "*/*");
        requestHeader.addFirst("Content-Length", "18");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=");

    }

    @Test
    public void scenario2() throws UnsupportedEncodingException {
        // method changed.  should get a different signature
        URIInfo uriInfo = new URIInfo("PUT", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        headers.add("content-length");
        headers.add("host");
        headers.add("date");
        headers.add("(request-target)");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Host", "example.org");
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        requestHeader.addFirst("Content-Type", "application/json");
        requestHeader.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        requestHeader.addFirst("Accept", "*/*");
        requestHeader.addFirst("Content-Length", "18");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=");

    }

    @Test
    public void scenario3() throws UnsupportedEncodingException {
        // only Digest changed.  not part of the signature, should have no effect
        URIInfo uriInfo = new URIInfo("PUT", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        headers.add("content-length");
        headers.add("host");
        headers.add("date");
        headers.add("(request-target)");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Host", "example.org");
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        requestHeader.addFirst("Content-Type", "application/json");
        requestHeader.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
        requestHeader.addFirst("Accept", "*/*");
        requestHeader.addFirst("Content-Length", "18");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=");

    }

    @Test
    public void scenario4() throws UnsupportedEncodingException {
        // uri changed.  should get a different signature
        URIInfo uriInfo = new URIInfo("PUT", "/foo/bar");
        List<String> headers = new ArrayList<>();
        headers.add("content-length");
        headers.add("host");
        headers.add("date");
        headers.add("(request-target)");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Host", "example.org");
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        requestHeader.addFirst("Content-Type", "application/json");
        requestHeader.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
        requestHeader.addFirst("Accept", "*/*");
        requestHeader.addFirst("Content-Length", "18");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("IWTDxmOoEJI67YxY3eDIRzxrsAtlYYCuGZxKlkUSYdA=");

    }

    @Test
    public void scenario5() throws UnsupportedEncodingException {
        // just date should be required
        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("WbB9VXuVdRt1LKQ5mDuT+tiaChn8R7WhdAWAY1lhKZQ=");

    }

    @Test
    public void scenario6() throws UnsupportedEncodingException {
        // one second later
        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:36 GMT");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("kRkh0bV1wKZSXBgexUB+zlPU88/za5K/gk/F0Aikg7Q=");

    }

    @Test
    public void scenario7() throws UnsupportedEncodingException {
        // adding other headers shouldn't matter
        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:36 GMT");
        requestHeader.addFirst("Content-Type", "application/json");
        requestHeader.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
        requestHeader.addFirst("Accept", "*//*");
        requestHeader.addFirst("Content-Length", "18");

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);

        assertThat(signature.getSignature()).isEqualTo("kRkh0bV1wKZSXBgexUB+zlPU88/za5K/gk/F0Aikg7Q=");

    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingDefaultHeader1() throws Exception {

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();

        SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);
    }

    @Test(expected = MissingRequiredHeaderException.class)
    public void missingDefaultHeader2() throws Exception {

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");
        List<String> headers = new ArrayList<>();
        headers.add("accept");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "don't tell");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);

        MultivaluedMap<String, String> requestHeader = new MultivaluedHashMap<>();
        requestHeader.addFirst("Date", "Tue, 07 Jun 2014 20:51:36 GMT");

        SignatureGenerator.getInstance().create(signatureInfo, uriInfo, requestHeader);
    }

}