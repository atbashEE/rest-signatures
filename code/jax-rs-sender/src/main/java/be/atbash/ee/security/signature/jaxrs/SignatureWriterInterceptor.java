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
package be.atbash.ee.security.signature.jaxrs;

import be.atbash.ee.security.signature.api.Constants;
import be.atbash.ee.security.signature.api.common.URIInfo;
import be.atbash.ee.security.signature.api.sign.Signature;
import be.atbash.ee.security.signature.api.sign.SignatureGenerator;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.util.base64.Base64Codec;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.WriterInterceptor;
import javax.ws.rs.ext.WriterInterceptorContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 */

public class SignatureWriterInterceptor implements WriterInterceptor {

    @Override
    public void aroundWriteTo(WriterInterceptorContext context) throws IOException, WebApplicationException {

        Boolean needsDigest = (Boolean) context.getProperty(Constants.HEADER_DIGEST);

        OutputStream originalStream = null;
        ByteArrayOutputStream out = null;

        if (needsDigest) {
            originalStream = context.getOutputStream();

            out = new ByteArrayOutputStream();
            context.setOutputStream(out);

        }

        context.proceed();

        if (needsDigest) {
            byte[] payload = out.toByteArray();
            originalStream.write(payload);

            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
                String digestHeader = "SHA256=" + Base64Codec.encodeToString(digest, true);
                context.getHeaders().add(Constants.HEADER_DIGEST, digestHeader);
            } catch (NoSuchAlgorithmException e) {
                throw new AtbashUnexpectedException(e);
            }

        }
        SignatureInfo signatureInfo = (SignatureInfo) context.getProperty(SignatureInfo.class.getName());
        URIInfo uriInfo = (URIInfo) context.getProperty(URIInfo.class.getName());

        MultivaluedMap<String, Object> headers = context.getHeaders();

        Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, headers);
        headers.add(Constants.SIGNATURE_HEADER, signature.toString());

    }

}
