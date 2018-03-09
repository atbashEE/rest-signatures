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

import be.atbash.ee.security.signature.api.SignatureKeyDataProvider;
import be.atbash.ee.security.signature.api.common.URIInfo;
import be.atbash.ee.security.signature.api.verify.Verifier;
import be.atbash.ee.security.signature.api.verify.VerifyResult;
import be.atbash.ee.security.signature.jaxrs.annotation.RestSignatureCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.nio.charset.Charset;

/**
 *
 */
@Provider
public class SignatureServerRequestFilter implements ContainerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(SignatureServerRequestFilter.class);

    @Context
    private ResourceInfo resourceInfo;

    @Inject
    private Instance<SignatureKeyDataProvider> signatureKeyDataProvider;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!containsRestSignatureCheckAnnotation()) {
            return;
        }

        String entityBody = getEntityBody(requestContext);
        URIInfo uriInfo = new URIInfoServer(requestContext);

        SignatureKeyDataProvider signatureKeyDataProvider = this.signatureKeyDataProvider.get();
        // FIXME Skew Config
        Verifier verifier = Verifier.getInstance(signatureKeyDataProvider, 30000);

        try {
            VerifyResult verifyResult = verifier.verify(requestContext.getHeaders(), entityBody, uriInfo);

            if (VerifyResult.NO_AUTHORIZATION_HEADER == verifyResult) {
                // FIXME is this correct?
                return;
            }

            if (VerifyResult.SUCCESS != verifyResult) {
                logger.warn(verifyResult.getMessage());
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        } catch (Exception e) {
            logger.warn(e.getMessage());
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());

        }
    }

    private boolean containsRestSignatureCheckAnnotation() {
        Method method = resourceInfo.getResourceMethod();

        RestSignatureCheck annotation = method.getAnnotation(RestSignatureCheck.class);
        if (annotation == null) {
            Class<?> classType = resourceInfo.getResourceClass();
            annotation = getAnnotation(classType, RestSignatureCheck.class);
        }
        return annotation != null;
    }

    private String getEntityBody(ContainerRequestContext requestContext) {
        InputStream in = requestContext.getEntityStream();

        String entity = null;
        try {
            entity = read(in);

            requestContext.setEntityStream(new ByteArrayInputStream(entity.getBytes(Charset.forName("UTF-8"))));

        } catch (IOException ex) {
            //TODO Handle logging error
        }
        return entity;
    }

    private static String read(InputStream input) throws IOException {
        java.util.Scanner s = new java.util.Scanner(input).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    private static <A extends Annotation> A getAnnotation(Class<?> someClass, Class<A> someAnnotation) {
        A result = null;
        if (someClass.isAnnotationPresent(someAnnotation)) {
            result = someClass.getAnnotation(someAnnotation);
        } else {
            if (someClass != Object.class) {
                result = getAnnotation(someClass.getSuperclass(), someAnnotation);
            }
        }
        return result;
    }
}
