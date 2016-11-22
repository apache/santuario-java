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
package org.apache.xml.security.test.stax.signature;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Assert;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * A set of test-cases for Signature creation.
 */
public class SignatureCreationTest extends AbstractSignatureCreationTest {

    @Test
    public void testSignatureCreation() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                Assert.assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testExceptionOnElementToSignNotFound() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "NotExistingElement"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        try {
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();
            Assert.fail("Exception expected");
        } catch (XMLStreamException e) {
            Assert.assertTrue(e.getCause() instanceof XMLSecurityException);
            Assert.assertEquals("Part to sign not found: {urn:example:po}NotExistingElement", e.getCause().getMessage());
        }
    }

    @Test
    public void testEnvelopedSignatureCreation() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(
                        new QName("urn:example:po", "PurchaseOrder"),
                        SecurePart.Modifier.Content,
                        new String[]{
                                "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        },
                        "http://www.w3.org/2000/09/xmldsig#sha1"
                );
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                Assert.assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignRootElementInRequest() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(null,
                              SecurePart.Modifier.Content,
                              new String[]{
                                      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                                      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                              },
                              "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        //first child element must be the dsig:Signature @see SANTUARIO-324:
        Node childNode = document.getDocumentElement().getFirstChild();
        while (childNode != null) {
            if (childNode.getNodeType() == Node.ELEMENT_NODE) {
                Element element = (Element)childNode;
                Assert.assertEquals(element.getLocalName(), "Signature");
                break;
            }
            childNode = childNode.getNextSibling();
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignAtSpecificPosition() throws Exception {
        signAtSpecificPosition(-1);
        signAtSpecificPosition(0);
        signAtSpecificPosition(1);
        signAtSpecificPosition(2);
        signAtSpecificPosition(999);
    }

    private void signAtSpecificPosition(int position) throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Specify the signature position
        properties.setSignaturePosition(position);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart
                = new SecurePart(null,
                SecurePart.Modifier.Content,
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument
                = this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        //find first child element:
        Node childNode = XMLUtils.getNextElement(document.getDocumentElement().getFirstChild());

        int expectedPosition = position < 0 ? 0 : position;
        int curPos = 0;
        while (curPos != expectedPosition) {
            Node node = XMLUtils.getNextElement(childNode.getNextSibling());
            curPos++;
            if (node != null) {
                childNode = node;
            } else {
                break;
            }
        }

        Assert.assertEquals(childNode.getLocalName(), "Signature");

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testIdAttributeNS() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Specify the signature position
        properties.setIdAttributeNS(new QName(null, "ID"));
        
        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart
                = new SecurePart(null,
                SecurePart.Modifier.Content,
                new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                },
                "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument
                = this.getClass().getClassLoader().getResourceAsStream(
                "org/apache/xml/security/testcases/SAML2ArtifactResponseUnsigned.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));

        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(),null,true,"ID");
    }
    
    
    @Test
    public void testMultipleElements() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);
        securePart =
                new SecurePart(new QName("urn:example:po", "ShippingAddress"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testMultipleSignatures() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // Now do second signature
        sourceDocument = new ByteArrayInputStream(baos.toByteArray());
        outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        baos = new ByteArrayOutputStream();
        xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//dsig:Signature";
        NodeList sigElements =
                (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
        Assert.assertTrue(sigElements.getLength() == 2);

        for (SecurePart secPart : properties.getSignatureSecureParts()) {
            if (secPart.getName() == null) {
                continue;
            }
            expression = "//*[local-name()='" + secPart.getName().getLocalPart() + "']";
            Element signedElement =
                    (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            Assert.assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, "Id", true);
        }

        for (int i = 0; i < sigElements.getLength(); i++) {
            XMLSignature signature = new XMLSignature((Element)sigElements.item(i), "");
            Assert.assertTrue(signature.checkSignatureValue(cert));
        }
    }

    @Test
    public void testHMACSignatureCreation() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        byte[] hmacKey = "secret".getBytes("ASCII");
        SecretKey key = new SecretKeySpec(hmacKey, "http://www.w3.org/2000/09/xmldsig#hmac-sha1");
        properties.setSignatureKey(key);

        properties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1");

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, key, properties.getSignatureSecureParts());
    }

    @Test
    public void testStrongSignatureCreation() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        properties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testECDSASignatureCreation() throws Exception {

        if (Security.getProvider("BC") == null) {
            return;
        }

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource(
                        "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testStrongECDSASignatureCreation() throws Exception {

        if (Security.getProvider("BC") == null) {
            return;
        }

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource(
                        "org/apache/xml/security/samples/input/ecdsa.jks").openStream(),
                "security".toCharArray()
        );
        Key key = keyStore.getKey("ECDSA", "security".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("ECDSA");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
        properties.setSignatureDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testDifferentC14nMethod() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testDifferentC14nMethodForReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"},
                "http://www.w3.org/2000/09/xmldsig#sha1");
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        Element element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_Transform.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_Transform.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_SignatureMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_SignatureMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_XMLDSIG_RSASHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_XMLDSIG_SHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testDifferentDigestMethodForReference() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart = new SecurePart(
                new QName("urn:example:po", "PaymentInfo"),
                SecurePart.Modifier.Content,
                new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
                "http://www.w3.org/2001/04/xmlenc#sha256");
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_CanonicalizationMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        Element element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_Transform.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_Transform.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_C14N_EXCL, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_SignatureMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_SignatureMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals(XMLSecurityConstants.NS_XMLDSIG_RSASHA1, element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_DigestMethod.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_DigestMethod.getLocalPart());
        Assert.assertEquals(1, nodeList.getLength());
        element = (Element)nodeList.item(0);
        Assert.assertEquals("http://www.w3.org/2001/04/xmlenc#sha256", element.getAttribute(XMLSecurityConstants.ATT_NULL_Algorithm.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testC14n11Method() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/2006/12/xml-c14n11");

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }
        
        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testExcC14nInclusivePrefixes() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm(XMLSecurityConstants.NS_C14N_EXCL);
        properties.setAddExcC14NInclusivePrefixes(true);

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces.getNamespaceURI(), XMLSecurityConstants.TAG_c14nExcl_InclusiveNamespaces.getLocalPart());
        Assert.assertEquals(2, nodeList.getLength());
        Assert.assertEquals("", ((Element)nodeList.item(0)).getAttribute(XMLSecurityConstants.ATT_NULL_PrefixList.getLocalPart()));
        Assert.assertEquals("", ((Element)nodeList.item(1)).getAttribute(XMLSecurityConstants.ATT_NULL_PrefixList.getLocalPart()));

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationKeyValue() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationSKI() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier);
        properties.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(
            this.getClass().getClassLoader().getResource("test.jceks").openStream(),
            "secret".toCharArray()
        );
        Key key = keyStore.getKey("rsakey", "secret".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("rsakey");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationX509Certificate() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationX509SubjectName() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_X509SubjectName);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
            this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
            "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationTransformBase64() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"),
                        SecurePart.Modifier.Content,
                        new String[]{"http://www.w3.org/2000/09/xmldsig#base64"},
                        "http://www.w3.org/2000/09/xmldsig#sha1");
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext-base64.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testNoKeyInfo() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});

        properties.setSignatureCanonicalizationAlgorithm("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_NoKeyInfo);

        SecurePart securePart =
               new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts(), null, false, "Id");

    }

    @Test
    public void testSignatureCreationKeyName() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        // System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(baos.toByteArray())) {
            document = XMLUtils.createDocumentBuilder(false).parse(is);
        }

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOM(document, cert, properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationWithoutId() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);
        properties.setSignatureGenerateIds(false);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Content);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document =
                XMLUtils.createDocumentBuilder(false).parse(new ByteArrayInputStream(baos.toByteArray()));

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOMWihtoutId(document, cert.getPublicKey(), properties.getSignatureSecureParts());
    }

    @Test
    public void testSignatureCreationWithoutOmittedDefaultTransform() throws Exception {
        // Set up the Configuration
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<XMLSecurityConstants.Action>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyName);
        properties.setSignatureGenerateIds(false);
        properties.setSignatureDefaultCanonicalizationTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
        properties.setSignatureIncludeDigestTransform(false);

        // Set the key up
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        Key key = keyStore.getKey("transmitter", "default".toCharArray());
        properties.setSignatureKey(key);
        X509Certificate cert = (X509Certificate)keyStore.getCertificate("transmitter");
        properties.setSignatureCerts(new X509Certificate[]{cert});
        properties.setSignatureKeyName(cert.getIssuerDN().getName());

        SecurePart securePart =
                new SecurePart(null, SecurePart.Modifier.Element, new String[]{
                        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
                        properties.getSignatureDefaultCanonicalizationTransform()
                }, "http://www.w3.org/2000/09/xmldsig#sha1");
        securePart.setSecureEntireRequest(true);
        properties.addSignaturePart(securePart);

        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, "UTF-8");

        InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream(
                        "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);

        XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
        xmlStreamWriter.close();

        //System.out.println("Got:\n" + new String(baos.toByteArray(), "UTF-8"));
        Document document =
                XMLUtils.createDocumentBuilder(false).parse(new ByteArrayInputStream(baos.toByteArray()));

        NodeList nodeList = document.getElementsByTagNameNS(XMLSecurityConstants.TAG_dsig_KeyName.getNamespaceURI(), XMLSecurityConstants.TAG_dsig_KeyName.getLocalPart());
        assertEquals(1, nodeList.getLength());
        assertEquals(cert.getIssuerDN().getName(), nodeList.item(0).getFirstChild().getTextContent());

        // Verify using DOM
        verifyUsingDOMWihtoutIdAndDefaultTransform(document, cert.getPublicKey(), properties.getSignatureSecureParts());
    }
}
