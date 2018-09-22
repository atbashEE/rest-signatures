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
package be.atbash.ee.security.signature.view;

import be.atbash.ee.security.signature.jaxrs.SignatureClientRequestFilter;
import be.atbash.ee.security.signature.jaxrs.SignatureWriterInterceptor;

import javax.enterprise.inject.Model;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 *
 */
@Model
public class HelloBean {

    public void getWithHMAC() {
        System.out.println("Client - GET example with HMAC ");
        Client client = ClientBuilder.newClient();
        client.register(SignatureClientRequestFilter.class);
        client.register(SignatureWriterInterceptor.class);
        Response response = client.target("http://localhost:8080/service/data")
                .path("hello")
                .request(MediaType.APPLICATION_JSON)
                .get();

        System.out.println("Client - received status : " + response.getStatus());
        System.out.println("Client - received response : " + response.readEntity(String.class));
    }

    public void postWithHMAC() {
        System.out.println("Client - POST example with HMAC ");
        Client client = ClientBuilder.newClient();
        client.register(SignatureClientRequestFilter.class);
        client.register(SignatureWriterInterceptor.class);
        Response response = client.target("http://localhost:8080/service/data")
                .path("greeting")
                .request(MediaType.APPLICATION_JSON)
                .post(Entity.entity(new Data("Rudy"), MediaType.APPLICATION_JSON));

        System.out.println("Client - received status : " + response.getStatus());
        System.out.println("Client - received response : " + response.readEntity(String.class));
    }

    public void postWithRSA() {
        System.out.println("Client - POST example with RSA keys ");
        Client client = ClientBuilder.newClient();
        client.register(SignatureClientRequestFilter.class);
        client.register(SignatureWriterInterceptor.class);
        Response response = client.target("http://localhost:8080/service/data")
                .path("keys")
                .request(MediaType.APPLICATION_JSON)
                .post(Entity.entity(new Data("rsa"), MediaType.APPLICATION_JSON));

        System.out.println("Client - received status : " + response.getStatus());
        System.out.println("Client - received response : " + response.readEntity(String.class));
    }
}
