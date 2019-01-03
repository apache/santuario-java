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
import java.security.Security;

import javax.xml.crypto.test.KeySelectors;

import static org.junit.Assert.assertTrue;

/**
 * This is a testcase to validate all "merlin-exc-c14n-one"
 * testcases from Baltimore
 *
 */
public class BaltimoreExcC14n1Test {

    private SignatureValidator validator;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public BaltimoreExcC14n1Test() {
        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");

        base += fs + "src/test/resources" + fs + "ie" +
            fs + "baltimore" + fs + "merlin-examples";
        validator = new SignatureValidator(new File
            (base, "merlin-exc-c14n-one"));
    }

    @org.junit.Test
    public void testExcSignature() throws Exception {
        String file = "exc-signature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue("Signature failed core validation", coreValidity);
    }

}