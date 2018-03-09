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
package be.atbash.ee.security.signature.jaxrs.provider;

import be.atbash.ee.security.signature.api.SignatureKeyInfoProvider;
import be.atbash.ee.security.signature.api.sign.SignatureInfoProvider;

import javax.annotation.PostConstruct;
import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class ProviderHelper {

    @Inject
    @Any
    private Instance<SignatureInfoProvider> infoImplementations;

    @Inject
    @Any
    private Instance<SignatureKeyInfoProvider> keyInfoImplementations;

    // FIXME Unmodifiable
    private List<SignatureInfoProvider> infoProviders;

    // FIXME Unmodifiable
    private List<SignatureKeyInfoProvider> keyInfoProviders;

    @PostConstruct
    public void init() {
        infoProviders = new ArrayList<>();
        for (SignatureInfoProvider infoProvider : infoImplementations) {
            infoProviders.add(infoProvider);
        }

        Collections.sort(infoProviders, new SignatureInfoProviderComparator());

        keyInfoProviders = new ArrayList<>();
        for (SignatureKeyInfoProvider keyInfoProvider : keyInfoImplementations) {
            keyInfoProviders.add(keyInfoProvider);
        }

    }

    public List<SignatureInfoProvider> getInfoProviders() {
        return infoProviders;
    }

    public List<SignatureKeyInfoProvider> getKeyInfoProviders() {
        return keyInfoProviders;
    }

    private static class SignatureInfoProviderComparator implements Comparator<SignatureInfoProvider> {

        @Override
        public int compare(SignatureInfoProvider sip1, SignatureInfoProvider sip2) {
            Integer priority1 = getPriority(sip1);
            Integer priority2 = getPriority(sip2);
            return priority1.compareTo(priority2);
        }

        private int getPriority(SignatureInfoProvider provider) {
            int result = 1000;
            Priority priority = provider.getClass().getAnnotation(Priority.class);
            if (priority != null) {
                result = priority.value();
            }
            return result;
        }
    }
}
