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
package org.apache.xml.security.test.dom.algorithms;

import java.lang.reflect.Field;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.util.Map;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class SignatureAlgorithmTest {

    static org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureAlgorithmTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    @org.junit.jupiter.api.Test
    public void testSameKeySeveralAlgorithmSigning() throws Exception {
        Document doc = XMLUtils.newDocument();
        SignatureAlgorithm signatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
        PrivateKey pk = KeyPairGenerator.getInstance("RSA").genKeyPair().getPrivate();
        signatureAlgorithm.initSign(pk);
        signatureAlgorithm.update((byte)2);
        signatureAlgorithm.sign();
        SignatureAlgorithm otherSignatureAlgorithm =
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);

        try {
            otherSignatureAlgorithm.initSign(pk);
        } catch (XMLSecurityException ex) {
            LOG.warn(
                "Test testSameKeySeveralAlgorithmSigning skipped as necessary algorithms "
                + "not available"
            );
            return;
        }

        otherSignatureAlgorithm.update((byte)2);
        otherSignatureAlgorithm.sign();
    }

    @org.junit.jupiter.api.Test
    public void testConstructionWithProvider() throws Exception {
        Field algorithmHashField = SignatureAlgorithm.class.getDeclaredField("algorithmHash");
        algorithmHashField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Class<?>> algorithmHash = (Map<String, Class<?>>)algorithmHashField.get(null);
        assertFalse(algorithmHash.isEmpty());

        Document doc = XMLUtils.newDocument();
        Provider provider = new org.bouncycastle.jce.provider.BouncyCastleProvider();

        for (String algorithmURI : algorithmHash.keySet()) {
            SignatureAlgorithm signatureAlgorithm = new SignatureAlgorithm(doc, algorithmURI, provider);
            assertEquals("BC", signatureAlgorithm.getJCEProviderName());
        }
    }
}
