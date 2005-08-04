/*
 * Copyright 2005 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
/*
 * $Id$
 */
package org.jcp.xml.dsig.internal.dom;

import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.utils.XMLUtils;

/**
 * DOM-based implementation of SignedInfo.
 *
 * @author Sean Mullan
 */
public final class DOMSignedInfo extends DOMStructure implements SignedInfo {

    static Logger log = Logger.getLogger(DOMSignedInfo.class.getName());

    private List references;
    private CanonicalizationMethod canonicalizationMethod;
    private SignatureMethod signatureMethod;
    private String id;
    private Document ownerDoc;
    private Element localSiElem;
    private InputStream canonData;

    // a reference to the enclosing XMLSignature
    private XMLSignature signature;	

    /**
     * Creates a <code>DOMSignedInfo</code> from the specified parameters. Use
     * this constructor when the <code>Id</code> is not specified.
     *
     * @param cm the canonicalization method
     * @param sm the signature method
     * @param references the list of references. The list is copied.
     * @throws NullPointerException if
     *    <code>cm</code>, <code>sm</code>, or <code>references</code> is 
     *    <code>null</code>
     * @throws IllegalArgumentException if <code>references</code> is empty
     * @throws ClassCastException if any of the references are not of
     *    type <code>Reference</code>
     */
    public DOMSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, 
	List references) {
        if (cm == null || sm == null || references == null) {
            throw new NullPointerException();
        }
        this.canonicalizationMethod = cm;
        this.signatureMethod = sm;
	this.references = Collections.unmodifiableList
	    (new ArrayList(references));
	if (this.references.isEmpty()) {
	    throw new IllegalArgumentException("list of references must " +
	        "contain at least one entry");
	}
	Iterator i = this.references.iterator();
	while (i.hasNext()) {
	    Object obj = i.next();
	    if (!(obj instanceof Reference)) {
		throw new ClassCastException("list of references contains " +
		    "an illegal type");
	    }
	}
    }

    /**
     * Creates a <code>DOMSignedInfo</code> from the specified parameters.
     *
     * @param cm the canonicalization method
     * @param sm the signature method
     * @param references the list of references. The list is copied.
     * @param id an optional identifer that will allow this
     *    <code>SignedInfo</code> to be referenced by other signatures and
     *    objects
     * @throws NullPointerException if <code>cm</code>, <code>sm</code>,
     *    or <code>references</code> is <code>null</code>
     * @throws IllegalArgumentException if <code>references</code> is empty
     * @throws ClassCastException if any of the references are not of
     *    type <code>Reference</code>
     */
    public DOMSignedInfo(CanonicalizationMethod cm, SignatureMethod sm, 
	List references, String id) {
        this(cm, sm, references);
        this.id = id;
    }

    /**
     * Creates a <code>DOMSignedInfo</code> from an element.
     *
     * @param siElem a SignedInfo element
     */
    public DOMSignedInfo(Element siElem, XMLSignature signature, 
	XMLCryptoContext context) throws MarshalException {
	localSiElem = siElem;
	this.signature = signature;
	ownerDoc = siElem.getOwnerDocument();

        // get Id attribute, if specified
        id = DOMUtils.getAttributeValue(siElem, "Id");

        // unmarshal CanonicalizationMethod
	Element cmElem = DOMUtils.getFirstChildElement(siElem);
	canonicalizationMethod = new DOMCanonicalizationMethod(cmElem, context);

        // unmarshal SignatureMethod
	Element smElem = DOMUtils.getNextSiblingElement(cmElem);
	signatureMethod = DOMSignatureMethod.unmarshal(smElem);

	// unmarshal References
	ArrayList refList = new ArrayList();
	Element refElem = DOMUtils.getNextSiblingElement(smElem);
	while (refElem != null) {
	    refList.add(new DOMReference(refElem, context));
	    refElem = DOMUtils.getNextSiblingElement(refElem);
	}
	references = Collections.unmodifiableList(refList);
    }

    public CanonicalizationMethod getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    public SignatureMethod getSignatureMethod() {
        return signatureMethod;
    }

    public String getId() {
        return id;
    }

    public List getReferences() {
	return references;
    }

    public InputStream getCanonicalizedData() {
	return canonData;
    }

    public byte[] canonicalize(XMLCryptoContext context)
	throws XMLSignatureException {

	if (context == null) {
            throw new NullPointerException("context cannot be null");
	}

	XMLUtils.circumventBug2650(ownerDoc);
	SubDocumentData sdd = new SubDocumentData(localSiElem, true, null);

	OctetStreamData data = null;
	try {
	    data = (OctetStreamData) ((DOMCanonicalizationMethod) 
		canonicalizationMethod).canonicalize(sdd, context);
	} catch (TransformException te) {
	    throw new XMLSignatureException(te);
	}

	byte[] signedInfoBytes;
	try {
            signedInfoBytes = Utils.readBytesFromStream(data.getOctetStream());
	} catch (IOException ioe) {
            throw new XMLSignatureException(ioe);
	}

        // this whole block should only be done if logging is enabled
	if (log.isLoggable(Level.FINE)) {
            InputStreamReader isr = new InputStreamReader
		(new ByteArrayInputStream(signedInfoBytes));
            char[] siBytes = new char[signedInfoBytes.length];
            try {
                isr.read(siBytes);
            } catch (IOException ioex) {} //ignore since this is logging code
            log.log(Level.FINE, "Canonicalized SignedInfo:\n" 
		+ new String(siBytes));
	}

	this.canonData = new ByteArrayInputStream(signedInfoBytes);
	return signedInfoBytes;
    }

    public void marshal(Node parent, String dsPrefix, DOMCryptoContext context)
	throws MarshalException {
	marshal(parent, dsPrefix, context, null);
    }

    public void marshal(Node parent, String dsPrefix, DOMCryptoContext context,
	XMLSignature signature) throws MarshalException {
	this.signature = signature;
        ownerDoc = DOMUtils.getOwnerDocument(parent);

	Element siElem = DOMUtils.createElement
	    (ownerDoc, "SignedInfo", XMLSignature.XMLNS, dsPrefix);

	// create and append CanonicalizationMethod element
	DOMCanonicalizationMethod dcm = 
	    (DOMCanonicalizationMethod) canonicalizationMethod;
	dcm.marshal(siElem, dsPrefix, context); 

	// create and append SignatureMethod element
	((DOMSignatureMethod) signatureMethod).marshal
	    (siElem, dsPrefix, context);

	// create and append Reference elements
	Iterator i = references.iterator();
	while (i.hasNext()) {
	    DOMReference reference = (DOMReference) i.next();
	    reference.marshal(siElem, dsPrefix, context);
	}

	// append Id attribute
        DOMUtils.setAttributeID(siElem, "Id", id);
	    
	parent.appendChild(siElem);
	localSiElem = siElem;
    }

    public boolean equals(Object o) {
	if (this == o) {
	    return true;
	}

	if (!(o instanceof SignedInfo)) {
	    return false;
	}
	SignedInfo osi = (SignedInfo) o;

	boolean idEqual = (id == null ? osi.getId() == null : 
	    id.equals(osi.getId()));

	return (canonicalizationMethod.equals(osi.getCanonicalizationMethod()) 
	    && signatureMethod.equals(osi.getSignatureMethod()) && 
	    references.equals(osi.getReferences()) && idEqual);
    }
}
