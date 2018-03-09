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

import be.atbash.ee.security.signature.api.AbstractTestWithRSAKey;
import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.common.Algorithm;
import be.atbash.ee.security.signature.exception.AtbashSignatureException;
import be.atbash.ee.security.signature.exception.MissingAlgorithmException;
import be.atbash.ee.security.signature.exception.MissingKeyIdException;
import be.atbash.ee.security.signature.exception.MissingSignatureException;
import be.atbash.util.StringUtils;
import org.junit.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */

public class SignatureBuilderTest extends AbstractTestWithRSAKey {

    @Test
    public void fromHeader() {
        String header = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        Signature signature = new SignatureBuilder().fromHeader(header).build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=");
        assertThat(signature.getHeaders()).containsOnly("(request-target)", "host", "date", "digest", "content-length");

    }

    @Test
    public void fromHeader_noHeaders() {
        /*
         * Authorization header parameters (keyId, algorithm, headers, signature)
         * may legally not include 'headers'
         */

        String header = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"";

        Signature signature = new SignatureBuilder().fromHeader(header).build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("Base64(HMAC-SHA256(signing string))");
        assertThat(signature.getHeaders()).containsOnly("date");

    }

    @Test
    public void fromHeader_StrictOrder() {
        /*
         * Order in headers parameter must be retained
         */

        String header = "Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\"," +
                "headers=\"one two three four five six\"" +
                ",signature=\"Base64(HMAC-SHA256(signing string))\"";

        Signature signature = new SignatureBuilder().fromHeader(header).build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("Base64(HMAC-SHA256(signing string))");
        assertThat(signature.getHeaders()).containsSequence("one", "two", "three", "four", "five", "six");

    }

    @Test
    public void fromHeader_noSignaturePrefix() {
        String header = "keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"";

        Signature signature = new SignatureBuilder().fromHeader(header).build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("Base64(HMAC-SHA256(signing string))");
        assertThat(signature.getHeaders()).containsOnly("date");
    }

    @Test
    public void fromHeader_whitespaceTolerance() {
        /*
         * Authorization header parameters (keyId, algorithm, headers, signature)
         * may have whitespace between them
         */
        String header = "  \nkeyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   signature=\"Base64(HMAC-SHA256(signing string))\"  \n";

        Signature signature = new SignatureBuilder().fromHeader(header).build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("Base64(HMAC-SHA256(signing string))");
        assertThat(signature.getHeaders()).containsOnly("date");
    }

    @Test
    public void orderTolerance() {
        /*
         * Authorization header parameters (keyId, algorithm, headers, signature)
         * can be in any order
         */

        List<String> headers = new ArrayList<>();
        headers.add("date");
        headers.add("accept");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "Atbash");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=").build();

        final List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\""
        );

        for (int tries = 10; tries > 0; tries--) {
            Collections.shuffle(input);

            String authorization = StringUtils.toDelimitedString(",", input);

            parseAndAssert(authorization, expected);
        }
    }

    @Test
    public void caseNormalization() {

        /*
         * Headers supplied in the constructor should be lowercased
         * Algorithm supplied in the constructor should be lowercased
         */
        List<String> headers = new ArrayList<>();
        headers.add("dAte");
        headers.add("aCcEpt");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hMaC-ShA256", "hmac-key-1", "Atbash");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature signature = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=").build();

        assertThat(signature.getKeyId()).isEqualTo("hmac-key-1");
        assertThat(signature.getAlgorithm().toString()).isEqualTo("hmac-sha256");
        assertThat(signature.getSignature()).isEqualTo("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=");
        assertThat(signature.getHeaders()).containsOnly("date", "accept");

    }

    @Test
    public void ambiguousParameters() {

        /*
         * 2.2.  Ambiguous Parameters
         * <p/>
         * If any of the parameters listed above are erroneously duplicated in
         * the associated header field, then the last parameter defined MUST be
         * used.  Any parameter that is not recognized as a parameter, or is not
         * well-formed, MUST be ignored.
         */

        List<String> headers = new ArrayList<>();
        headers.add("date");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha1", "hmac-key-3", "Atbash");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=").build();

        List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "keyId=\"hmac-key-3\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept content-length\"",
                "algorithm=\"hmac-sha1\"",
                "headers=\"date\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"",
                "signature=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        String authorization = StringUtils.toDelimitedString(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void parameterCaseTolerance() {

        List<String> headers = new ArrayList<>();
        headers.add("date");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo(Algorithm.RSA_SHA256, "hmac-key-3", publicKey);
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=").build();

        List<String> input = Arrays.asList(
                "keyId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "KeyId=\"hmac-key-3\"",
                "algorithm=\"hmac-sha256\"",
                "headers=\"date accept content-length\"",
                "aLgorithm=\"rsa-sha256\"",
                "headers=\"date\"",
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"",
                "SIGNATURE=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        String authorization = StringUtils.toDelimitedString(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void unknownParameters() {

        List<String> headers = new ArrayList<>();
        headers.add("date");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo(Algorithm.RSA_SHA256, "hmac-key-3", publicKey);
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("PIft5ByT/Nr5RWvB+QLQRyFAvbGmauCOE7FTL0tI+Jg=").build();

        final List<String> input = Arrays.asList(
                "scopeId=\"hmac-key-1\"",
                "keyId=\"hmac-key-2\"",
                "keyId=\"hmac-key-3\"",
                "precision=\"hmac-sha256\"",
                "algorithm=\"rsa-sha256\"",
                "topics=\"date accept content-length\"",
                "headers=\"date\"",
                "signature=\"PIft5ByT/Nr5RWvB+QLQRyFAvbGmauCOE7FTL0tI+Jg=\"",
                "signage=\"DPIsA/PWeYjySmfjw2P2SLJXZj1szDOei/Hh8nTcaPo=\""
        );

        String authorization = StringUtils.toDelimitedString(",", input);

        parseAndAssert(authorization, expected);
    }

    @Test
    public void trailingCommaTolerance() {
        String authorization = "" +
                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"date accept\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"" +
                " , ";

        List<String> headers = new ArrayList<>();
        headers.add("date");
        headers.add("accept");
        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "Atbash");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=").build();

        parseAndAssert(authorization, expected);
    }

    @Test
    public void testToString() {

        List<String> headers = new ArrayList<>();
        headers.add("(request-target)");
        headers.add("host");
        headers.add("date");
        headers.add("digest");
        headers.add("content-length");

        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo("hmac-sha256", "hmac-key-1", "Atbash");
        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, headers);
        Signature expected = new SignatureBuilder().fromSignatureInfo(signatureInfo)
                .withEncodedSignature("Base64(HMAC-SHA256(signing string))").build();

        String authorization = "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"Base64(HMAC-SHA256(signing string))\"";

        assertThat(expected.toString()).isEqualTo(authorization);
    }

    /**
     * Parsing should only ever throw SignatureHeaderFormatException
     * <p/>
     * We want to avoid NullPointerException, StringIndexOutOfBoundsException and
     * any other exception that might result.
     */
    @Test
    public void throwsAuthorizationException() {

        final Random random = new Random();

        StringBuilder header = new StringBuilder("Signature keyId=\"hmac-key-1\",algorithm=\"hmac-sha256\",\n" +
                "   headers=\"(request-target) host date digest content-length\",\n" +
                "   signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"");

        while (header.length() > 0) {

            // Delete a random character and parse again
            header.deleteCharAt(random.nextInt(header.length()));

            try {

                new SignatureBuilder().fromHeader(header.toString()).build();
            } catch (AtbashSignatureException e) {
                // pass
            } catch (Throwable e) {
                fail("SignatureHeaderFormatException should be the only possible exception type: caught " + e.getClass().getName());
            }
        }
    }

    @Test(expected = MissingKeyIdException.class)
    public void missingKeyId() {
        String header = "" +
//                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        new SignatureBuilder().fromHeader(header).build();
    }

    @Test(expected = MissingAlgorithmException.class)
    public void missingAlgorithm() {
        String header = "" +
                "keyId=\"hmac-key-1\"," +
//                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"," +
                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        new SignatureBuilder().fromHeader(header).build();
    }

    @Test(expected = MissingSignatureException.class)
    public void missingSignature() {
        String header = "" +
                "keyId=\"hmac-key-1\"," +
                "algorithm=\"hmac-sha256\"," +
                "headers=\"(request-target) host date digest content-length\"";
//                "signature=\"yT/NrPI9mKB5R7FTLRyFWvB+QLQOEAvbGmauC0tI+Jg=\"";

        new SignatureBuilder().fromHeader(header).build();
    }

    private static void parseAndAssert(String header, Signature expected) {
        Signature actual = new SignatureBuilder().fromHeader(header).build();
        assertSignature(expected, actual);
    }

    private static void assertSignature(Signature expected, Signature actual) {
        assertThat(actual.getKeyId()).isEqualTo(expected.getKeyId());
        assertThat(actual.getAlgorithm()).isEqualTo(expected.getAlgorithm());
        assertThat(actual.getSignature()).isEqualTo(expected.getSignature());

        assertThat(actual.getHeaders()).containsExactlyElementsOf(expected.getHeaders());

    }
}