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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package javax.xml.crypto.test.dsig;


import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import javax.xml.crypto.dsig.XMLSignatureException;

import javax.xml.crypto.test.KeySelectors;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * This is a testcase to validate all "signatureAlgorithms"
 * testcases from IAIK
 *
 */
public class IaikSignatureAlgosTest {

    private SignatureValidator validator;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public IaikSignatureAlgosTest() {
        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");
        base +=  fs + "src/test/resources" + fs
            + "at" + fs + "iaik" + fs + "ixsil";
        validator = new SignatureValidator(new File
            (base, "signatureAlgorithms/signatures"));
    }

    @org.junit.Test
    public void test_dsaSignature() throws Exception {
        String file = "dSASignature.xml";

        boolean coreValidity = validator.validate(file, new
            KeySelectors.KeyValueKeySelector());
        assertTrue("Signature failed core validation", coreValidity);
    }

    @org.junit.Test
    public void test_rsaSignature() throws Exception {
        String file = "rSASignature.xml";

        boolean coreValidity = validator.validate(file, new
            KeySelectors.KeyValueKeySelector());
        assertTrue("Signature failed core validation", coreValidity);
    }

    @org.junit.Test
    public void test_hmacShortSignature() throws Exception {
        String file = "hMACShortSignature.xml";

        try {
            validator.validate(file, new
                KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII)));
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            // pass
        }
    }

    @org.junit.Test
    public void test_hmacSignature() throws Exception {
        String file = "hMACSignature.xml";

        boolean coreValidity = validator.validate(file, new
            KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII)));
        assertTrue("Signature failed core validation", coreValidity);
    }

}