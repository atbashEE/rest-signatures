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
package be.atbash.ee.security.signature.api.verify;

import be.atbash.ee.security.signature.api.SignatureKeyData;
import be.atbash.ee.security.signature.api.SignatureKeyDataProvider;
import be.atbash.ee.security.signature.api.common.URIInfo;
import be.atbash.ee.security.signature.exception.UnsupportedAlgorithmException;
import be.atbash.ee.security.signature.exception.WrongHeaderDateFormatException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.security.Key;
import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class VerifierTest {

    private static final String KEY_ID1 = "hmac-key-1";

    @Mock
    private SignatureKeyDataProvider signatureKeyDataProviderMock;

    private Key key;

    @Before
    public void setup() {
        key = new SecretKeySpec("don't tell".getBytes(), "HmacSHA256");
    }

    @Test
    public void verify() throws ParseException {
        SignatureKeyData signatureKeyData = new SignatureKeyData(key);
        when(signatureKeyDataProviderMock.getKeyData(KEY_ID1)).thenReturn(signatureKeyData);

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("host", "example.org");
        headers.addFirst("date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.addFirst("content-length", "18");
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.SUCCESS);
    }

    @Test
    public void verify_noSignature() throws ParseException {
        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.NO_SIGNATURE_HEADER);
    }

    @Test
    public void verify_missingHeaders() throws ParseException {

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.INCOMPLETE_REQUEST);
    }

    @Test
    public void verify_expiredDateHeader_after() throws ParseException {

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:52:35 GMT");  // 1 min later then date header

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");
        headers.addFirst("date", "Tue, 07 Jun 2014 20:51:35 GMT");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.EXPIRED_DATE_HEADER);
    }

    @Test
    public void verify_expiredDateHeader_before() throws ParseException {

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:50:35 GMT");  // 1 min before then date header

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");
        headers.addFirst("date", "Tue, 07 Jun 2014 20:51:35 GMT");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.EXPIRED_DATE_HEADER);
    }

    @Test
    public void verify_dateHeader_timezoneSupport() throws ParseException {

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");
        headers.addFirst("date", "Tue, 07 Jun 2014 19:51:35 GMT+01:00");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.EXPIRED_DATE_HEADER);
    }

    @Test(expected = WrongHeaderDateFormatException.class)
    public void verify_WrongDateHeader() {

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");
        headers.addFirst("date", "Garbage header value");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);
        // FIXME Should WrongHeaderDateFormatException also become a VerifyResult
    }

    @Test
    public void verify_DigestHeader() throws ParseException {
        SignatureKeyData signatureKeyData = new SignatureKeyData(key);
        when(signatureKeyDataProviderMock.getKeyData(KEY_ID1)).thenReturn(signatureKeyData);

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 19:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"digest\", signature=\"/3vTaqVxGTVfmyVZ7+FwO7G9nU4jJ0yHnlilazNDzNA=\"");
        headers.addFirst("digest", "SHA256=ScJqOBdPgrLX6wyX1He2wcnTsTJDG6_ouJw_YQjKwxQ");
        headers.addFirst("date", "Tue, 07 Jun 2014 19:51:35 GMT+01:00");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "The payload contents", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.SUCCESS);
    }

    @Test
    public void verify_WrongDigestHeader() throws ParseException {

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 19:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"digest\", signature=\"/3vTaqVxGTVfmyVZ7+FwO7G9nU4jJ0yHnlilazNDzNA=\"");
        headers.addFirst("digest", "SHA256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu8DBPE=");
        headers.addFirst("date", "Tue, 07 Jun 2014 19:51:35 GMT+01:00");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "The payload contents", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.DIGEST_MISMATCH);
    }

    @Test
    public void verify_WrongSignature() throws ParseException {
        SignatureKeyData signatureKeyData = new SignatureKeyData(key);
        when(signatureKeyDataProviderMock.getKeyData(KEY_ID1)).thenReturn(signatureKeyData);

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 19:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"digest\", signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");
        headers.addFirst("digest", "SHA256=ScJqOBdPgrLX6wyX1He2wcnTsTJDG6_ouJw_YQjKwxQ");
        headers.addFirst("date", "Tue, 07 Jun 2014 19:51:35 GMT+01:00");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "The payload contents", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.FAILED_KEY_VERIFY);
    }

    @Test
    public void verify_noKey() throws ParseException {
        when(signatureKeyDataProviderMock.getKeyData(KEY_ID1)).thenReturn(null);

        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("host", "example.org");
        headers.addFirst("date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.addFirst("content-length", "18");
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        VerifyResult result = Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        assertThat(result).isEqualTo(VerifyResult.KEY_NOT_FOUND);
    }

    @Test(expected = UnsupportedAlgorithmException.class)
    public void verify_wrongAlgorithm() throws ParseException {
        ConfigurableFixedTimeProvider.setFixedDate("07/06/2014 20:51:35 GMT");

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.addFirst("host", "example.org");
        headers.addFirst("date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.addFirst("content-length", "18");
        headers.addFirst("signature", "keyId=\"hmac-key-1\",algorithm=\"non existing\",headers=\"content-length host date (request-target)\",signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        URIInfo uriInfo = new URIInfo("GET", "/foo/Bar");

        Verifier.getInstance(signatureKeyDataProviderMock, 1000).verify(headers, "", uriInfo);

        // FIXME Should UnsupportedAlgorithmException also become a VerifyResult
    }

}