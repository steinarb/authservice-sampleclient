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

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.stream.Collectors;

import javax.servlet.http.HttpSession;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.core.HttpHeaders;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.subject.WebSubject;
import org.junit.jupiter.api.Test;

import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

import no.priv.bang.authservice.sampleclient.ShiroTestBase;
import no.priv.bang.osgi.service.mocks.logservice.MockLogService;

class LoginResourceTest extends ShiroTestBase {

    @Test
    void testGetLogin() throws Exception {
        var resource = new LoginResource();
        var htmlfile = resource.getLogin();
        try(var reader = new BufferedReader(new InputStreamReader(htmlfile))) {
            var html = reader.lines().collect(Collectors.joining("+n"));
            assertThat(html).startsWith("<html");
        }
    }

    @Test
    void testPostLogin() {
        var logservice = new MockLogService();
        var session = mock(HttpSession.class);
        var dummyrequest = new MockHttpServletRequest();
        dummyrequest.setSession(session);
        var dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "admin";
        var password = "admin";
        var redirectUrl = "https://myserver.com/resource";
        var response = resource.postLogin(username, password, redirectUrl);
        assertEquals(302, response.getStatus());
        assertEquals(redirectUrl, response.getLocation().toString());
    }

    @Test
    void testPostLoginWithNullRedirectUrl() {
        var logservice = new MockLogService();
        var session = mock(HttpSession.class);
        var dummyrequest = new MockHttpServletRequest();
        dummyrequest.setSession(session);
        var dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "admin";
        var password = "admin";
        var response = resource.postLogin(username, password, null);
        assertEquals(302, response.getStatus());
        assertEquals("", response.getLocation().toString());
    }

    @Test
    void testPostLoginWithUnknownUser() {
        var logservice = new MockLogService();
        var dummyrequest = new MockHttpServletRequest();
        var dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "notauser";
        var password = "admin";
        var redirectUrl = "https://myserver.com/resource";
        var response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testPostLoginWithWrongPassword() {
        var logservice = new MockLogService();
        var dummyrequest = new MockHttpServletRequest();
        var dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "admin";
        var password = "wrongpassword";
        var redirectUrl = "https://myserver.com/resource";
        var response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testPostLoginWithLockedAccount() {
        try {
            lockAccount("jad");
            // Set up the request
            var logservice = new MockLogService();
            var dummyrequest = new MockHttpServletRequest();
            var dummyresponse = new MockHttpServletResponse();
            createSubjectAndBindItToThread(dummyrequest, dummyresponse);
            var resource = new LoginResource();
            resource.setLogservice(logservice);
            var username = "jad";
            var password = "wrong";
            var redirectUrl = "https://myserver.com/resource";
            var response = resource.postLogin(username, password, redirectUrl);
            assertEquals(401, response.getStatus());
        } finally {
            unlockAccount("jad");
        }
    }

    @Test
    void testPostLoginWithAuthenticationException() {
        createSubjectThrowingExceptionAndBindItToThread(AuthenticationException.class);
        var logservice = new MockLogService();
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "jad";
        var password = "wrong";
        var redirectUrl = "https://myserver.com/resource";
        var response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testLoginWithUnexpectedException() {
        createSubjectThrowingExceptionAndBindItToThread(IllegalArgumentException.class);
        var logservice = new MockLogService();
        var resource = new LoginResource();
        resource.setLogservice(logservice);
        var username = "jad";
        var password = "wrong";
        var redirectUrl = "https://myserver.com/resource";
        assertThrows(InternalServerErrorException.class, () -> resource.postLogin(username, password, redirectUrl));
    }

    @Test
    void testLogout() {
        var resource = new LoginResource();
        var httpheaders = mock(HttpHeaders.class);
        when(httpheaders.getHeaderString(anyString())).thenReturn("http://localhost/localpath");
        resource.httpHeaders = httpheaders;

        var response = resource.logout();
        assertEquals(302, response.getStatus());
    }

    @Test
    void testFindRedirectLocation() {
        var resource = new LoginResource();
        var locationWithoutOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("../.."), locationWithoutOriginalUri);

        var httpHeadersWithoutOriginalUri = mock(HttpHeaders.class);
        resource.httpHeaders = httpHeadersWithoutOriginalUri;
        var locationAlsoWithoutOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("../.."), locationAlsoWithoutOriginalUri);

        var httpHeadersWithOriginalUri = mock(HttpHeaders.class);
        when(httpHeadersWithOriginalUri.getHeaderString(anyString())).thenReturn("http://lorenzo.hjemme.lan");
        resource.httpHeaders = httpHeadersWithOriginalUri;
        var locationWithOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("http://lorenzo.hjemme.lan"), locationWithOriginalUri);
    }

    @Test
    void testLoadHtmlFileWithIOExceptionThrown() throws Exception {
        var mockstream = mock(InputStream.class);
        when(mockstream.read(any(byte[].class), anyInt(), anyInt())).thenThrow(IOException.class);

        var resource = new LoginResource() {
            @Override
                InputStream getClasspathResource(String resource) {
                return mockstream;
            }
        };
        var logservice = new MockLogService();
        resource.setLogservice(logservice);

        assertThrows(InternalServerErrorException.class, () -> resource.loadHtmlFile("nonexistingfile.html", logservice));
    }

    private void lockAccount(String username) {
        getShiroAccountFromRealm(username).setLocked(true);
    }

    private void unlockAccount(String username) {
        getShiroAccountFromRealm(username).setLocked(false);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private WebSubject createSubjectThrowingExceptionAndBindItToThread(Class exceptionClass) {
        var subject = mock(WebSubject.class);
        doThrow(exceptionClass).when(subject).login(any());
        ThreadContext.bind(subject);
        return subject;
    }

}
