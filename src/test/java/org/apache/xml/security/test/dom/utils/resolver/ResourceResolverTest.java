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


import java.io.File;

import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;

import static org.junit.Assert.fail;

/**
 * Unit test for {@link org.apache.xml.security.utils.resolver.ResourceResolver}
 *
 */
public class ResourceResolverTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger
            (ResourceResolverTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    /**
     * Tests registering a custom resolver implementation.
     */
    @org.junit.Test
    public void testCustomResolver() throws Exception {
        String className =
            "org.apache.xml.security.test.dom.utils.resolver.OfflineResolver";
        ResourceResolver.registerAtStart(className);
        Document doc = XMLUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        uriAttr.setValue("http://www.apache.org");
        ResourceResolver res =
            ResourceResolver.getInstance(uriAttr, "http://www.apache.org", true);
        try {
            uriAttr.setValue("http://xmldsig.pothole.com/xml-stylesheet.txt");
            res.resolve(uriAttr, null, true);
        } catch (Exception e) {
            fail(uriAttr.getValue()
                + " should be resolvable by the OfflineResolver");
        }
        try {
            uriAttr.setValue("http://www.apache.org");
            res.resolve(uriAttr, null, true);
            fail(uriAttr.getValue() + " should not be resolvable by the OfflineResolver");
        } catch (Exception e) {
            //
        }
    }

    @org.junit.Test
    public void testLocalFileWithEmptyBaseURI() throws Exception {
        Document doc = XMLUtils.newDocument();
        Attr uriAttr = doc.createAttribute("URI");
        String basedir = System.getProperty("basedir");
        String file = new File(basedir, "pom.xml").toURI().toString();
        uriAttr.setValue(file);
        ResourceResolver res = ResourceResolver.getInstance(uriAttr, file, false);
        try {
            res.resolve(uriAttr, "", true);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

}