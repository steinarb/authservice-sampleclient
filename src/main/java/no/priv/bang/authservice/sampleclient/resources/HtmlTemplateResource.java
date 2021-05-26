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

import java.io.IOException;
import java.io.InputStream;

import javax.ws.rs.InternalServerErrorException;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.osgi.service.log.LogService;
import org.osgi.service.log.Logger;

public class HtmlTemplateResource {

    static void setError(Document html, String message) {
        setMessage(html, "Error: " + message);
    }

    protected Document loadHtmlFile(String htmlFile, LogService logservice) {
        try (InputStream body = getClasspathResource(htmlFile)) {
            return Jsoup.parse(body, "UTF-8", "");
        } catch (IOException e) {
            Logger logger = logservice.getLogger(getClass());
            String message = "Got exception loading the index.html file";
            logger.error(message, e);
            throw new InternalServerErrorException(message, e);
        }
    }

    InputStream getClasspathResource(String resource) {
        return getClass().getClassLoader().getResourceAsStream(resource);
    }

    protected Document loadHtmlFileAndSetMessage(String htmlFile, String message, LogService logservice) {
        Document html = loadHtmlFile(htmlFile, logservice);
        setError(html, message);
        return html;
    }

    static void setMessage(Document html, String message) {
        Element banner = html.select("p[id=messagebanner]").get(0);
        banner.text(message);
    }

    public HtmlTemplateResource() {
        super();
    }

}
