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
import be.atbash.ee.security.signature.api.SignatureKeyInfo;
import be.atbash.ee.security.signature.api.SignatureKeyInfoProvider;
import be.atbash.ee.security.signature.api.common.URIInfo;
import be.atbash.ee.security.signature.api.sign.Signature;
import be.atbash.ee.security.signature.api.sign.SignatureGenerator;
import be.atbash.ee.security.signature.api.sign.SignatureInfo;
import be.atbash.ee.security.signature.api.sign.SignatureInfoProvider;
import be.atbash.ee.security.signature.jaxrs.provider.ProviderHelper;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.inject.spi.CDI;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.core.MultivaluedMap;
import java.io.IOException;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;

import static be.atbash.ee.security.signature.api.Constants.HEADER_DATE;
import static be.atbash.ee.security.signature.api.Constants.HEADER_DATE_FORMAT;

/**
 *
 */

public class SignatureClientRequestFilter implements ClientRequestFilter {

    private ProviderHelper helper;

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        checkHelper();
        SignatureInfo signatureInfo = findSignatureInfo(requestContext.getMethod(), requestContext.getUri());

        handleDateHeader(requestContext);

        if (signatureInfo.isNeedsDigest()) {
            requestContext.setProperty(Constants.HEADER_DIGEST, Boolean.TRUE);
        }

        URIInfo uriInfo = new URIInfoClient(requestContext);

        if (requestContext.getEntity() == null) {
            // No entity, means we don't execute the WriterInterceptor and thus we need to set the Authorization header here.
            MultivaluedMap<String, Object> headers = requestContext.getHeaders();

            Signature signature = SignatureGenerator.getInstance().create(signatureInfo, uriInfo, headers);
            headers.add(Constants.SIGNATURE_HEADER, signature.toString());

        } else {
            // Pass the info as properties so that the WriterInterceptor has access to them.
            // WriterInterceptor has access to less detailed info.
            requestContext.setProperty(SignatureInfo.class.getName(), signatureInfo);

            requestContext.setProperty(URIInfo.class.getName(), uriInfo);
        }
    }

    private void handleDateHeader(ClientRequestContext requestContext) {
        Date now = new Date();
        String stringNow = new SimpleDateFormat(HEADER_DATE_FORMAT, Locale.US).format(now);

        requestContext.getHeaders().add(HEADER_DATE, stringNow);

    }

    private SignatureInfo findSignatureInfo(String method, URI uri) {
        SignatureKeyInfo signatureKeyInfo = null;
        Iterator<SignatureKeyInfoProvider> iteratorKey = helper.getKeyInfoProviders().iterator();
        while (iteratorKey.hasNext()) {
            SignatureKeyInfoProvider keyInfoProvider = iteratorKey.next();
            signatureKeyInfo = keyInfoProvider.provideKeyFor(method, uri);
            if (signatureKeyInfo != null) {
                break;
            }

        }

        if (signatureKeyInfo == null) {
            throw new IllegalArgumentException("No Key info associated for URI");
        }

        SignatureInfo signatureInfo = null;

        Iterator<SignatureInfoProvider> iteratorInfo = helper.getInfoProviders().iterator();
        while (iteratorInfo.hasNext()) {
            SignatureInfoProvider signatureInfoProvider = iteratorInfo.next();
            signatureInfo = signatureInfoProvider.provideInfoFor(method, uri, signatureKeyInfo);
            if (signatureInfo != null) {
                break;
            }
        }

        if (signatureInfo == null) {
            throw new AtbashUnexpectedException("No SignatureInfo available, should not be possible (DefaultSignatureInfoProvider should always be available ");
        }

        return signatureInfo;
    }

    private void checkHelper() {
        if (helper == null) {
            helper = CDI.current().select(ProviderHelper.class).get();
        }
    }

}
