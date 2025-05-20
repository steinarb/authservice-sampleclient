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

import java.io.InputStream;
import java.net.URI;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.jsoup.nodes.Document;
import org.osgi.service.log.LogService;
import org.osgi.service.log.Logger;

@Path("")
public class LoginResource extends HtmlTemplateResource {
    private static final String LOGIN_ERROR = "Login error: ";
    private static final String LOGIN_HTML = "web/login.html";

    @Context
    HttpHeaders httpHeaders;

    LogService logservice;
    private Logger logger;

    @Inject
    void setLogservice(LogService logservice) {
        this.logservice = logservice;
        this.logger = logservice.getLogger(getClass());
    }

    @GET
    @Path("/login")
    @Produces(MediaType.TEXT_HTML)
    public InputStream getLogin() {
        return getClass().getClassLoader().getResourceAsStream(LOGIN_HTML);
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces("text/html")
    public Response postLogin(@FormParam("username") String username, @FormParam("password") String password, @CookieParam("NSREDIRECT") String redirectUrl) {
        var subject = SecurityUtils.getSubject();

        var token = new UsernamePasswordToken(username, password.toCharArray(), true);
        try {
            subject.login(token);

            return Response.status(Response.Status.FOUND).location(URI.create(notNullUrl(redirectUrl))).entity("Login successful!").build();
        } catch(UnknownAccountException e) {
            var message = "unknown user";
            logger.warn(LOGIN_ERROR + message, e);
            var html = loadHtmlFileAndSetMessage(LOGIN_HTML, message, logservice);
            fillFormValues(html, redirectUrl, username, password);
            return Response.status(Response.Status.UNAUTHORIZED).entity(html.html()).build();
        } catch (IncorrectCredentialsException  e) {
            var message = "wrong password";
            logger.warn(LOGIN_ERROR + message, e);
            Document html = loadHtmlFileAndSetMessage(LOGIN_HTML, message, logservice);
            fillFormValues(html, redirectUrl, username, password);
            return Response.status(Response.Status.UNAUTHORIZED).entity(html.html()).build();
        } catch (LockedAccountException  e) {
            String message = "locked account";
            logger.warn(LOGIN_ERROR + message, e);
            var html = loadHtmlFileAndSetMessage(LOGIN_HTML, message, logservice);
            fillFormValues(html, redirectUrl, username, password);
            return Response.status(Response.Status.UNAUTHORIZED).entity(html.html()).build();
        } catch (AuthenticationException e) {
            var message = "general authentication error";
            logger.warn(LOGIN_ERROR + message, e);
            var html = loadHtmlFileAndSetMessage(LOGIN_HTML, message, logservice);
            fillFormValues(html, redirectUrl, username, password);
            return Response.status(Response.Status.UNAUTHORIZED).entity(html.html()).build();
        } catch (Exception e) {
            logger.warn("Login error: internal server error", e);
            throw new InternalServerErrorException();
        } finally {
            token.clear();
        }
    }

    @GET
    @Path("/logout")
    @Produces("text/html")
    public Response logout() {
        var subject = SecurityUtils.getSubject();

        subject.logout();
        var redirectUrl = httpHeaders.getHeaderString("Referer");
        return Response.status(Response.Status.FOUND).location(URI.create(redirectUrl)).entity("Login successful!").build();
    }

    String notNullUrl(String redirectUrl) {
        if (redirectUrl == null) {
            return "";
        }

        return redirectUrl;
    }

    URI findRedirectLocation() {
        if (httpHeaders != null) {
            var originLocation = httpHeaders.getHeaderString("Origin");
            if (originLocation != null) {
                return URI.create(originLocation);
            }
        }

        return URI.create("../..");
    }

}
