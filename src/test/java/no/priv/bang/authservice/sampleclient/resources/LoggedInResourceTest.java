/*
 * Copyright 2019-2025 Steinar Bang
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
package no.priv.bang.authservice.sampleclient.resources;

import static org.assertj.core.api.Assertions.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

import no.priv.bang.authservice.sampleclient.ShiroTestBase;

class LoggedInResourceTest extends ShiroTestBase {

    @Test
    void testGetIndex() throws Exception {
        var resource = new LoggedInResource();
        var htmlfile = resource.getIndex();
        try(var reader = new BufferedReader(new InputStreamReader(htmlfile))) {
            var html = reader.lines().collect(Collectors.joining("+n"));
            assertThat(html).startsWith("<html");
        }
    }

    @Test
    void testGetAdmin() throws Exception {
        var resource = new LoggedInResource();
        var htmlfile = resource.getAdmin();
        try(var reader = new BufferedReader(new InputStreamReader(htmlfile))) {
            var html = reader.lines().collect(Collectors.joining("+n"));
            assertThat(html).startsWith("<html");
        }
    }

}
