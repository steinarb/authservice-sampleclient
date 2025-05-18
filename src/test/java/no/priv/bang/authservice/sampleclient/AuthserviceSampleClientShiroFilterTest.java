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
package no.priv.bang.authservice.sampleclient;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.session.mgt.eis.MemorySessionDAO;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class AuthserviceSampleClientShiroFilterTest extends ShiroTestBase {

    private static MemorySessionDAO session = new MemorySessionDAO();
    private static ServletContext context;

    @BeforeAll
    static void setup() {
        getSecurityManager();
        context = mock(ServletContext.class);
        when(context.getContextPath()).thenReturn("/authservice");
    }

    @Test
    void testAuthenticationSucceed() throws Exception {
        var filter = new AuthserviceSampleClientShiroFilter();
        filter.setServletContext(context);
        filter.setRealm(realm);
        filter.setSession(session);
        filter.activate();

        var request = mock(HttpServletRequest.class);
        when(request.getMethod()).thenReturn("GET");
        var response = mock(HttpServletResponse.class, Mockito.CALLS_REAL_METHODS);
        var bodyWriter = new StringWriter();
        var responseWriter = new PrintWriter(bodyWriter);
        when(response.getWriter()).thenReturn(responseWriter);

        // Get the security manager from the filter and log in
        // to verify that the filter setup is working
        var securitymanager = filter.getSecurityManager();
        var token = new UsernamePasswordToken("admin", "admin".toCharArray(), true);
        var info = securitymanager.authenticate(token);
        assertEquals(1, info.getPrincipals().asList().size());
    }

}
