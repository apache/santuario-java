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


import java.security.Security;
import java.util.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


/**
 * Unit test for javax.xml.crypto.dsig.SignedInfo
 *
 */
public class SignedInfoTest {
    private XMLSignatureFactory fac;
    private CanonicalizationMethod cm;
    private SignatureMethod sm;
    private List<Reference> references;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public SignedInfoTest() throws Exception {
        fac = XMLSignatureFactory.getInstance
            ("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        cm = fac.newCanonicalizationMethod
            (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
             (C14NMethodParameterSpec) null);
        sm = fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null);
        references = new ArrayList<>();
        references.add(fac.newReference
                       ("http://www.sun.com/index.html",
                        fac.newDigestMethod(DigestMethod.SHA1, null)));
    }

    @SuppressWarnings("rawtypes")
    @org.junit.Test
    public void testConstructor() {
        // test XMLSignatureFactory.newSignedInfo(
        //	CanonicalizationMethod cm,
        //      SignatureMethod sm, List references)
        SignedInfo si;

        for (int i = 0; i < 3; i++) {
            try {
                switch (i) {
                case 0:
                    si = fac.newSignedInfo(null, sm, references);
                    break;
                case 1:
                    si = fac.newSignedInfo(cm, null, references);
                    break;
                case 2:
                    si = fac.newSignedInfo(cm, sm, null);
                    break;
                }
                fail("Should throw a NPE for null parameter");
            } catch(NullPointerException npe) {
            } catch(Exception ex) {
                fail("Should throw a NPE instead of " + ex +
                     " for null parameter");
            }
        }

        List<Reference> empty = new ArrayList<>();
        try {
            si = fac.newSignedInfo(cm, sm, empty);
            fail("Should throw an IAE for empty references");
        } catch(IllegalArgumentException iae) {
        } catch(Exception ex) {
            fail("Should throw an IAE instead of " + ex +
                 " for empty references");
        }

        // use raw List type to test for invalid Reference entries
        List invalidRefs = new ArrayList();
        addEntryToRawList(invalidRefs, "String");
        try {
            fac.newSignedInfo(cm, sm, invalidRefs);
            fail("Should throw an CCE for illegal references");
        } catch(ClassCastException cce) {
        } catch(Exception ex) {
            fail("Should throw an IAE instead of " + ex +
                 " for empty references");
        }

        si = fac.newSignedInfo(cm, sm, references);
        assertNotNull(si);
        assertEquals(si.getCanonicalizationMethod().getAlgorithm(),
                     cm.getAlgorithm());
        assertEquals(si.getCanonicalizationMethod().getParameterSpec(),
                     cm.getParameterSpec());
        assertEquals(si.getSignatureMethod().getAlgorithm(),
                     sm.getAlgorithm());
        assertEquals(si.getSignatureMethod().getParameterSpec(),
                     sm.getParameterSpec());
        assertTrue(Arrays.equals(si.getReferences().toArray(),
                                 references.toArray()));
        assertNull(si.getId());

        // test XMLSignatureFactory.newSignedInfo(
        //      CanonicalizationMethod cm,
        //      SignatureMethod sm, List references, String id)
        si = fac.newSignedInfo(cm, sm, references, null);
        assertNotNull(si);

        si = fac.newSignedInfo(cm, sm, references, "id");
        assertNotNull(si);
        assertEquals(si.getId(), "id");
    }

    @SuppressWarnings({
     "unchecked", "rawtypes"
    })
    private static void addEntryToRawList(List list, Object entry) {
        list.add(entry);
    }
}