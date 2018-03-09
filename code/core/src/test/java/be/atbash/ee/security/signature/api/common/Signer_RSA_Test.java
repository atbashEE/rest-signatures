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

import be.atbash.ee.security.signature.api.AbstractTestWithRSAKey;
import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import org.junit.Before;
import org.junit.Test;

import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class Signer_RSA_Test extends AbstractTestWithRSAKey {

    private final String method = "POST";
    private final String uri = "/foo?param=value&pet=dog";
    private MultivaluedMap<String, String> headers;

    @Before
    public void setup() {
        headers = new MultivaluedHashMap<>();
        headers.addFirst("Host", "example.org");
        headers.addFirst("Date", "Thu, 05 Jan 2012 21:31:40 GMT");
        headers.addFirst("Content-Type", "application/json");
        headers.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.addFirst("Accept", "*/*");
        headers.addFirst("Content-Length", "18");
    }

    @Test
    public void rsaSha1() throws Exception {
        final Algorithm algorithm = Algorithm.RSA_SHA1;

        assertSignature(algorithm, "kcX/cWMRQEjUPfF6AO7ANZ/eQkpRd" +
                        "/4+dr3g1B5HZBn3vRDxGFbDRY19HeJUUlBAgmvolRwLlrVkz" +
                        "LOmYdug6Ff01UUl6gX+TksGbsxagbNUNoEx0hrX3+8Jbd+x8" +
                        "gx9gZxA7DwXww1u3bGrmChnfkdOofY52KhUllUox4mmBeI=",
                "date");

        assertSignature(algorithm, "F6g4qdBSHBcWo1iMsHetQU9TnPF39" +
                        "naVHQogAhgvY6wh0/cdkquN4D6CInTyEHtMuv7xlOt0yBaVt" +
                        "brrNP5JZKquYMW2JC3FXdtIiaYWhLUb/Nmb+JPr6C8AnxMzc" +
                        "fNfuOZFn3X7ekA32qbfnYr7loHqpEGUr+G1NYsckEXdlM4=",
                "(request-target)", "host", "date");
    }

    @Test
    public void rsaSha256() throws Exception {
        final Algorithm algorithm = Algorithm.RSA_SHA256;

        assertSignature(algorithm, "ATp0r26dbMIxOopqw0OfABDT7CKMI" +
                        "oENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYT" +
                        "b5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3" +
                        "TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=",
                "date");

        assertSignature(algorithm, "DT9vcDFbit2ahGZowjUzzih+sVpKM" +
                        "IPZrXy1DMljImYNSJ3UEweTMfF3MUFjdNwYH59IDJoB+QTg3" +
                        "Rpm5xLvMWD7tql/Ng/NCJs8gYSNjOQidArEpWp88c5IQPDXn" +
                        "1lnJMU6dNXZNxc8Yqj+mIYhwHpKEKTqnvEtnCvB/6y/dIM=",
                "(request-target)", "host", "date");
    }

    @Test
    public void rsaSha384() throws Exception {
        final Algorithm algorithm = Algorithm.RSA_SHA384;

        assertSignature(algorithm, "AYtR6NQy+59Ta3X1GYNlfOzJo4Sg+" +
                        "aB+ulDkR6Q2/8egvByRx5l0+t/2abAaFHf33SDojHYWPlpuj" +
                        "HM26ExZPFXeYzG9sRctKD7XKrA/F6LRXEm1RXLFvfvLXQw4P" +
                        "4HE1PMH+gCw2E+6IoTnbcimQtZ82SkF1uDRtLDhR6iqpFI="
                , "date");

        assertSignature(algorithm, "mRaP0Z5lh9XKGDahdsomoKR9Kjsj9" +
                        "a/lgUEpZDQpvSZq5NhODEjmQh1qRn6Sx/c+AFl67yzDYAMXx" +
                        "9h49ZOpKpuj4FGrz5/DIK7cdn9wXBKqDYgDfwOF9O5jNOE1r" +
                        "9zbORTH0XxA8WE9H/MXoOrDIH1NjM5o9I4ErT4zKnD5OsQ="
                , "(request-target)", "host", "date");
    }

    @Test
    public void rsaSha512() throws Exception {
        final Algorithm algorithm = Algorithm.RSA_SHA512;

        assertSignature(algorithm, "IItboA8OJgL8WSAnJa8MND04s9j7d" +
                        "B6IJIBVpOGJph8Tmkc5yUAYjvO/UQUKytRBe5CSv2GLfTAmE" +
                        "7SuRgGGMwdQZubNJqRCiVPKBpuA47lXrKgC/wB0QAMkPHI6c" +
                        "PllBZRixmjZuU9mIbuLjXMHR+v/DZwOHT9k8x0ILUq2rKE="
                , "date");

        assertSignature(algorithm, "ggIa4bcI7q377gNoQ7qVYxTA4pEOl" +
                        "xlFzRtiQV0SdPam4sK58SFO9EtzE0P1zVTymTnsSRChmFU2p" +
                        "n+R9VzkAhQ+yEbTqzu+mgHc4P1L5IeeXQ5aAmGENfkRbm2vd" +
                        "OZzP5j6ruB+SJXIlhnaum2lsuyytSS0m/GkWvFJVZFu33M="
                , "(request-target)", "host", "date");
    }

    private void assertSignature(Algorithm algorithm, String expected, String... sign) throws UnsupportedEncodingException {

        Signer signer = new Signer();

        URIInfo uriInfo = new URIInfo(method, uri);

        SignatureKeyInfo keyInfo = new SignatureKeyInfo(algorithm, "x", privateKey);
        SignatureInfo signatureInfo = new SignatureInfo(false, keyInfo, sign);
        String signed = signer.sign(headers, signatureInfo, uriInfo);
        assertThat(signed).isEqualTo(expected);

    }
}