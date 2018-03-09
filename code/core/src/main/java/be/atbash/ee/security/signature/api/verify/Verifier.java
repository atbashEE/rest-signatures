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

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.SignatureKeyData;
import be.atbash.ee.security.signature.api.SignatureKeyDataProvider;
import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.common.Signer;
import be.atbash.ee.security.signature.api.common.URIInfo;
import be.atbash.ee.security.signature.api.sign.Signature;
import be.atbash.ee.security.signature.api.sign.SignatureBuilder;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.ee.security.signature.exception.WrongHeaderDateFormatException;
import be.atbash.util.base64.Base64Codec;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.ws.rs.core.MultivaluedMap;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static be.atbash.ee.security.signature.api.Constants.HEADER_DATE_FORMAT;

/**
 *
 */
public final class Verifier {

    private static Map<SignatureKeyDataProvider, Verifier> INSTANCES = new HashMap<>();

    private SignatureKeyDataProvider signatureKeyDataProvider;

    private int skew;

    private TimeProvider timeProvider;

    private Verifier(SignatureKeyDataProvider signatureKeyDataProvider, int skew) {
        this.signatureKeyDataProvider = signatureKeyDataProvider;
        this.skew = skew;
        timeProvider = TimeProviderFactory.getTimeProvider();
    }

    public VerifyResult verify(MultivaluedMap<String, ?> headers, String entityBody, URIInfo uriInfo) {
        String signatureHeader = getFirst(headers, Constants.SIGNATURE_HEADER).toString();
        if (signatureHeader.isEmpty()) {
            return VerifyResult.NO_SIGNATURE_HEADER;
        }

        Signature signature = new SignatureBuilder().fromHeader(signatureHeader).build();

        // FIXME How signature verification
        /*
        if (!authorization.isCorrectAuthorizationHeader()) {
            return VerifyResult.INCORRECT_AUTHORIZATION_HEADER;
        }
        */
        // verify that all headers declared by the authorization are present in the request
        for (String header : signature.getHeaders()) {
            if (!Constants.HEADER_REQUEST_TARGET.equals(header) && (headers.get(header) == null || headers.get(header).isEmpty())) {
                return VerifyResult.INCOMPLETE_REQUEST;
            }
        }

        // if date is declared by the authorization, verify that its value is within $skew of the current time
        if (signature.getHeaders().contains(Constants.HEADER_DATE) && skew >= 0) { // TODO skew negative means we allow for any date
            Date requestTime = getDateGMT(headers);

            Date currentTime = timeProvider.now();
            Date past = new Date(currentTime.getTime() - skew);
            Date future = new Date(currentTime.getTime() + skew);
            if (requestTime.before(past) || requestTime.after(future)) {
                return VerifyResult.EXPIRED_DATE_HEADER;
            }
        }

        if (signature.getHeaders().contains(Constants.HEADER_DIGEST)) {

            byte[] digest;
            try {
                // FIXME algorithm must be taken from the header.
                digest = MessageDigest.getInstance("SHA-256").digest(entityBody.getBytes(Charset.forName("UTF-8")));
            } catch (NoSuchAlgorithmException e) {
                throw new AtbashUnexpectedException(e);
            }
            String digestHeader = "SHA256=" + Base64Codec.encodeToString(digest, true);

            if (!digestHeader.equals(getFirst(headers, Constants.HEADER_DIGEST))) {

                return VerifyResult.DIGEST_MISMATCH;
            }
        }

        SignatureKeyData keyData = signatureKeyDataProvider.getKeyData(signature.getKeyId());
        if (keyData == null) {
            return VerifyResult.KEY_NOT_FOUND;
        }

        Key key = keyData.getKey();
        if (key == null) {
            return VerifyResult.KEY_NOT_FOUND;
        }
        Signer signer = new Signer();

        SignatureKeyInfo signatureKeyInfo = new SignatureKeyInfo(signature.getAlgorithm(), signature.getKeyId(), key);

        SignatureInfo signatureInfo = new SignatureInfo(signatureKeyInfo, signature.getHeaders());
        try {

            String encodedSignature = signer.sign(headers, signatureInfo, uriInfo);
            if (encodedSignature.equals(signature.getSignature())) {
                return VerifyResult.SUCCESS;
            }
        } catch (UnsupportedEncodingException e) {
            throw new AtbashUnexpectedException(e);
        }

        return VerifyResult.FAILED_KEY_VERIFY;

    }

    private Date getDateGMT(MultivaluedMap<String, ?> headers) {
        Date result;
        String dateHeaderValue = getFirst(headers, Constants.HEADER_DATE).toString();
        try {
            result = new SimpleDateFormat(HEADER_DATE_FORMAT, Locale.US).parse(dateHeaderValue);
        } catch (ParseException e) {
            throw new WrongHeaderDateFormatException(dateHeaderValue);
        }
        return result;

    }

    private Object getFirst(MultivaluedMap<String, ?> headers, String key) {
        Object result = "";

        List<?> items = headers.get(key.toLowerCase());
        if (items != null && !items.isEmpty()) {
            result = items.get(0);
        }
        return result;

    }

    public static Verifier getInstance(SignatureKeyDataProvider signatureKeyDataProvider, int skew) {
        Verifier result = INSTANCES.get(signatureKeyDataProvider);
        if (result == null) {
            result = new Verifier(signatureKeyDataProvider, skew);
            INSTANCES.put(signatureKeyDataProvider, result);
        }
        return result;
    }
}
