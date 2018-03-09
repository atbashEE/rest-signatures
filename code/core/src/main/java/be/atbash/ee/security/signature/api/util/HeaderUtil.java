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
package be.atbash.ee.security.signature.api.util;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */

public final class HeaderUtil {

    private static final Pattern RFC2617_PARAM = Pattern.compile("(\\w+)=\"([^\"]*)\"");

    private HeaderUtil() {
    }

    public static Map<String, String> parseAuthenticationParameters(String header) {
        Map<String, String> params = new HashMap<>();

        final Matcher matcher = RFC2617_PARAM.matcher(header);
        while (matcher.find()) {
            // toLowerCase so that we have case tolerance
            params.put(matcher.group(1).toLowerCase(), matcher.group(2));
        }

        return Collections.unmodifiableMap(params);
    }

}
