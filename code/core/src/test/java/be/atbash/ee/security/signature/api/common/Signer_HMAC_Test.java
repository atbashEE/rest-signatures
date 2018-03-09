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
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class Signer_HMAC_Test {

    private String method = "GET";
    private String uri = "/foo/Bar";
    private MultivaluedMap<String, String> headers;

    @Before
    public void setup() {
        headers = new MultivaluedHashMap<>();
        headers.addFirst("Host", "example.org");
        headers.addFirst("Date", "Tue, 07 Jun 2014 20:51:35 GMT");
        headers.addFirst("Content-Type", "application/json");
        headers.addFirst("Digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
        headers.addFirst("Accept", "*/*");
        headers.addFirst("Content-Length", "18");
    }

    @Test
    public void hmacSha1() throws UnsupportedEncodingException {

        Algorithm algorithm = Algorithm.HMAC_SHA1;

        assertSignature(algorithm, "DMP1G2BKLf1o9iKg0NvPZo8RigY=", "don't tell", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "P6FNqBvdGQcaNTecru8KR1ObHLY=", "another key", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "VPEKHCIXUlAqXNCmoB+aSelBZkU=", "don't tell", "content-length", "host", "date");
        assertSignature(algorithm, "mhWHbBqk3ArpoYlT60VING3P1gQ=", "another key", "content-length", "host", "date");
    }

    @Test
    public void hmacSha256() throws UnsupportedEncodingException {

        Algorithm hmacSha256 = Algorithm.HMAC_SHA256;

        assertSignature(hmacSha256, "yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=", "don't tell", "content-length", "host", "date", "(request-target)");
        assertSignature(hmacSha256, "sr+ungXeJjxCEJvJSFS0o+P9deafROte/1n3q+Ig6mg=", "another key", "content-length", "host", "date", "(request-target)");
        assertSignature(hmacSha256, "R6gbUcVfoGGkCy//JjBSF7jkD9wIQA4DKruUgtv/P1M=", "don't tell", "content-length", "host", "date");
        assertSignature(hmacSha256, "KrB+54zf29LFZrkwgVTUlJOyOeBtl0BzOp6FdjbDo70=", "another key", "content-length", "host", "date");
    }

    @Test
    public void hmacSha384() throws UnsupportedEncodingException {

        Algorithm algorithm = Algorithm.HMAC_SHA384;

        assertSignature(algorithm, "9YsBcpHITHOBbqf0TrcMl5OlWF/qxPVNpIy8EUviDSWLkpDDkSmWSoTicACzZmoV", "don't tell", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "bY/D5QJFyOVKZVHsuL6e9LsOOEGgC3s2GUspvHVNjNHfDNwMi0ZlFuPXcPCIQArz", "another key", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "KH54rBfQcOE6GAwIvIVVAiYnld0Lru5/5ujiV+ebCeL0wJXDhAybmiXCYZ3efYUl", "don't tell", "content-length", "host", "date");
        assertSignature(algorithm, "cih898vWdxaF5T3r3m8iKCOiW7sAbBGESuzNnI+Ips1rQelWZJHOe71MZKQuFc1V", "another key", "content-length", "host", "date");
    }

    @Test
    public void hmacSha512() throws UnsupportedEncodingException {

        Algorithm algorithm = Algorithm.HMAC_SHA512;

        assertSignature(algorithm, "HKObooU+mlMdFoxn29Yk0U8JZlFMXlpLqdcVd4OyJHInyjbJNTtkSoVFU4EgogzGTQRLed9Ja8+SxwGS8Lw2UQ==", "don't tell", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "qxy0NC6BelTV0O8eVWYyyptgsVx/UjAorCLDjirznEEC6ay4orgGvmCFHlz1O1uYEY7t2xTCk5Dw5Rhnf20bEA==", "another key", "content-length", "host", "date", "(request-target)");
        assertSignature(algorithm, "WHVT+7KsEIzmJ69ujXuRXPzRvb4yfrZZSXlxnnnuRR5r3H9MyJ7y1t1xWgu9pEmj41gzdogF4pF3hR0Z7f62Jw==", "don't tell", "content-length", "host", "date");
        assertSignature(algorithm, "+w0a5Sw0+pOzA0OHXiVD5DDx2xdOqZcebhFtaXINUPWFhf68pVdWSzOPjGGHa/zIhsE152FT4E1mHbrPZO71Eg==", "another key", "content-length", "host", "date");
    }

    private void assertSignature(Algorithm algorithm, String expected, String keyString, String... sign) throws UnsupportedEncodingException {

        Signer signer = new Signer();

        URIInfo uriInfo = new URIInfo(method, uri);

        SignatureKeyInfo keyInfo = new SignatureKeyInfo(algorithm, "x", new SecretKeySpec(keyString.getBytes(), algorithm.getJmvName()));
        SignatureInfo signatureInfo = new SignatureInfo(false, keyInfo, sign);
        String signed = signer.sign(headers, signatureInfo, uriInfo);
        assertThat(signed).isEqualTo(expected);

    }

}