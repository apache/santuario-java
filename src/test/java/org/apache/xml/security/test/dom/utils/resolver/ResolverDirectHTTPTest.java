/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.dom.utils.resolver;

import org.apache.xml.security.Init;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.implementations.ResolverDirectHTTP;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;


public class ResolverDirectHTTPTest {

    //change these properties to match your environment
    private static final String url = "http://www.apache.org";
    private static final String proxyHost = "127.0.0.1";
    private static final String proxyPort = "3128";
    private static final String proxyUsername = "proxyUser";
    private static final String proxyPassword = "proxyPass";
    private static final String serverUsername = "serverUser";
    private static final String serverPassword = "serverPass";

    @BeforeEach
    public void setUp() {
        Init.init();
    }

    @Test
    public void testBug40783() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("id");
        uri.setNodeValue("urn:ddd:uuu");
        doc.createElement("test").setAttributeNode(uri);
        try {
            ResourceResolver resolver = ResourceResolver.getInstance(uri, null, true);
            fail("No exception thrown, but resolver found: " + resolver);
        } catch (ResourceResolverException e) {
            //
        }
    }

    @Test
    @Disabled
    public void testProxyAuth() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        resolverDirectHTTP.engineSetProperty("http.proxy.host",proxyHost);
        resolverDirectHTTP.engineSetProperty("http.proxy.port", proxyPort);
        resolverDirectHTTP.engineSetProperty("http.proxy.username", proxyUsername);
        resolverDirectHTTP.engineSetProperty("http.proxy.password", proxyPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true);
        resolverDirectHTTP.engineResolveURI(context);
    }

    @Test
    @Disabled
    public void testProxyAuthWithWrongPassword() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        resolverDirectHTTP.engineSetProperty("http.proxy.host",proxyHost);
        resolverDirectHTTP.engineSetProperty("http.proxy.port", proxyPort);
        resolverDirectHTTP.engineSetProperty("http.proxy.username", proxyUsername);
        resolverDirectHTTP.engineSetProperty("http.proxy.password", "wrongPassword");
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true);
        try {
            resolverDirectHTTP.engineResolveURI(context);
            fail("Expected ResourceResolverException");
        } catch (ResourceResolverException e) {
            assertEquals("Server returned HTTP response code: 407 for URL: " + url, e.getMessage());
        }
    }

    @Test
    @Disabled
    public void testServerAuth() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        resolverDirectHTTP.engineSetProperty("http.basic.username", serverUsername);
        resolverDirectHTTP.engineSetProperty("http.basic.password", serverPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true);
        resolverDirectHTTP.engineResolveURI(context);
    }

    @Test
    @Disabled
    public void testServerAuthWithWrongPassword() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        resolverDirectHTTP.engineSetProperty("http.basic.username", serverUsername);
        resolverDirectHTTP.engineSetProperty("http.basic.password", "wrongPassword");
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true);
        try {
            resolverDirectHTTP.engineResolveURI(context);
            fail("Expected ResourceResolverException");
        } catch (ResourceResolverException e) {
            assertEquals("Server returned HTTP response code: 401 for URL: " + url, e.getMessage());
        }
    }

    @Test
    @Disabled
    public void testProxyAndServerAuth() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uri = doc.createAttribute("URI");
        uri.setNodeValue(url);

        ResolverDirectHTTP resolverDirectHTTP = new ResolverDirectHTTP();
        resolverDirectHTTP.engineSetProperty("http.proxy.host",proxyHost);
        resolverDirectHTTP.engineSetProperty("http.proxy.port", proxyPort);
        resolverDirectHTTP.engineSetProperty("http.proxy.username", proxyUsername);
        resolverDirectHTTP.engineSetProperty("http.proxy.password", proxyPassword);
        resolverDirectHTTP.engineSetProperty("http.basic.username", serverUsername);
        resolverDirectHTTP.engineSetProperty("http.basic.password", serverPassword);
        ResourceResolverContext context =
            new ResourceResolverContext(uri, url, true);
        resolverDirectHTTP.engineResolveURI(context);
    }
}
