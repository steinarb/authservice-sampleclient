/*
 * Copyright 2019-2021 Steinar Bang
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
import static org.mockito.Matchers.any;
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
import javax.ws.rs.core.Response;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.subject.WebSubject;
import org.jsoup.nodes.Document;
import org.junit.jupiter.api.Test;

import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

import no.priv.bang.authservice.sampleclient.ShiroTestBase;
import no.priv.bang.osgi.service.mocks.logservice.MockLogService;

class LoginResourceTest extends ShiroTestBase {

    @Test
    void testGetLogin() {
        LoginResource resource = new LoginResource();
        InputStream htmlfile = resource.getLogin();
        String html = new BufferedReader(new InputStreamReader(htmlfile)).lines().collect(Collectors.joining("+n"));
        assertThat(html).startsWith("<html");
    }

    @Test
    void testPostLogin() {
        MockLogService logservice = new MockLogService();
        HttpSession session = mock(HttpSession.class);
        MockHttpServletRequest dummyrequest = new MockHttpServletRequest();
        dummyrequest.setSession(session);
        MockHttpServletResponse dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "admin";
        String password = "admin";
        String redirectUrl = "https://myserver.com/resource";
        Response response = resource.postLogin(username, password, redirectUrl);
        assertEquals(302, response.getStatus());
        assertEquals(redirectUrl, response.getLocation().toString());
    }

    @Test
    void testPostLoginWithNullRedirectUrl() {
        MockLogService logservice = new MockLogService();
        HttpSession session = mock(HttpSession.class);
        MockHttpServletRequest dummyrequest = new MockHttpServletRequest();
        dummyrequest.setSession(session);
        MockHttpServletResponse dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "admin";
        String password = "admin";
        Response response = resource.postLogin(username, password, null);
        assertEquals(302, response.getStatus());
        assertEquals("", response.getLocation().toString());
    }

    @Test
    void testPostLoginWithUnknownUser() {
        MockLogService logservice = new MockLogService();
        MockHttpServletRequest dummyrequest = new MockHttpServletRequest();
        MockHttpServletResponse dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "notauser";
        String password = "admin";
        String redirectUrl = "https://myserver.com/resource";
        Response response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testPostLoginWithWrongPassword() {
        MockLogService logservice = new MockLogService();
        MockHttpServletRequest dummyrequest = new MockHttpServletRequest();
        MockHttpServletResponse dummyresponse = new MockHttpServletResponse();
        createSubjectAndBindItToThread(dummyrequest, dummyresponse);
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "admin";
        String password = "wrongpassword";
        String redirectUrl = "https://myserver.com/resource";
        Response response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testPostLoginWithLockedAccount() throws Exception {
        try {
            lockAccount("jad");
            // Set up the request
            MockLogService logservice = new MockLogService();
            MockHttpServletRequest dummyrequest = new MockHttpServletRequest();
            MockHttpServletResponse dummyresponse = new MockHttpServletResponse();
            createSubjectAndBindItToThread(dummyrequest, dummyresponse);
            LoginResource resource = new LoginResource();
            resource.logservice = logservice;
            String username = "jad";
            String password = "wrong";
            String redirectUrl = "https://myserver.com/resource";
            Response response = resource.postLogin(username, password, redirectUrl);
            assertEquals(401, response.getStatus());
        } finally {
            unlockAccount("jad");
        }
    }

    @Test
    void testPostLoginWithAuthenticationException() {
        createSubjectThrowingExceptionAndBindItToThread(AuthenticationException.class);
        MockLogService logservice = new MockLogService();
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "jad";
        String password = "wrong";
        String redirectUrl = "https://myserver.com/resource";
        Response response = resource.postLogin(username, password, redirectUrl);
        assertEquals(401, response.getStatus());
    }

    @Test
    void testLoginWithUnexpectedException() {
        createSubjectThrowingExceptionAndBindItToThread(IllegalArgumentException.class);
        MockLogService logservice = new MockLogService();
        LoginResource resource = new LoginResource();
        resource.logservice = logservice;
        String username = "jad";
        String password = "wrong";
        String redirectUrl = "https://myserver.com/resource";
        assertThrows(InternalServerErrorException.class, () -> {
                Response response = resource.postLogin(username, password, redirectUrl);
                assertEquals(401, response.getStatus());
            });
    }

    @Test
    void testLogout() {
        LoginResource resource = new LoginResource();
        HttpHeaders httpheaders = mock(HttpHeaders.class);
        when(httpheaders.getHeaderString(anyString())).thenReturn("http://localhost/localpath");
        resource.httpHeaders = httpheaders;

        Response response = resource.logout();
        assertEquals(302, response.getStatus());
    }

    @Test
    void testFindRedirectLocation() {
        LoginResource resource = new LoginResource();
        URI locationWithoutOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("../.."), locationWithoutOriginalUri);

        HttpHeaders httpHeadersWithoutOriginalUri = mock(HttpHeaders.class);
        resource.httpHeaders = httpHeadersWithoutOriginalUri;
        URI locationAlsoWithoutOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("../.."), locationAlsoWithoutOriginalUri);

        HttpHeaders httpHeadersWithOriginalUri = mock(HttpHeaders.class);
        when(httpHeadersWithOriginalUri.getHeaderString(anyString())).thenReturn("http://lorenzo.hjemme.lan");
        resource.httpHeaders = httpHeadersWithOriginalUri;
        URI locationWithOriginalUri = resource.findRedirectLocation();
        assertEquals(URI.create("http://lorenzo.hjemme.lan"), locationWithOriginalUri);
    }

    @SuppressWarnings("unchecked")
    @Test
    void testLoadHtmlFileWithIOExceptionThrown() throws Exception {
        InputStream mockstream = mock(InputStream.class);
        when(mockstream.read(any(byte[].class), anyInt(), anyInt())).thenThrow(IOException.class);

        LoginResource resource = new LoginResource() {
                @Override
                InputStream getClasspathResource(String resource) {
                    return mockstream;
                }
            };
        MockLogService logservice = new MockLogService();
        resource.logservice = logservice;

        assertThrows(InternalServerErrorException.class, () -> {
                Document html = resource.loadHtmlFile("nonexistingfile.html", logservice);
                assertThat(html.html()).contains("message not found");
            });
    }

    private void lockAccount(String username) {
        getShiroAccountFromRealm(username).setLocked(true);
    }

    private void unlockAccount(String username) {
        getShiroAccountFromRealm(username).setLocked(false);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private WebSubject createSubjectThrowingExceptionAndBindItToThread(Class exceptionClass) {
        WebSubject subject = mock(WebSubject.class);
        doThrow(exceptionClass).when(subject).login(any());
        ThreadContext.bind(subject);
        return subject;
    }

}
