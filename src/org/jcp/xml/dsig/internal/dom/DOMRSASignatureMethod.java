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
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.w3c.dom.Element;

import org.apache.xml.security.utils.Base64;

/**
 * DOM-based implementation of SignatureMethod for RSA algorithm.
 * Use DOMHMACSignatureMethod for HMAC algorithms.
 *
 * @author Sean Mullan
 */
public final class DOMRSASignatureMethod extends DOMSignatureMethod { 

    static Logger log = Logger.getLogger(DOMRSASignatureMethod.class.getName());
    private Signature signature;

    /**
     * Creates a <code>DOMRSASignatureMethod</code> for the specified 
     * input parameters.
     *
     * @param params algorithm-specific parameters (may be null)
     * @throws InvalidAlgorithmParameterException if the parameters are not
     *    appropriate for this signature method
     */
    public DOMRSASignatureMethod(AlgorithmParameterSpec params) 
	throws InvalidAlgorithmParameterException {
	super(SignatureMethod.RSA_SHA1, params);
    }

    /**
     * Creates a <code>DOMRSASignatureMethod</code> from an element.
     *
     * @param smElem a SignatureMethod element
     */
    public DOMRSASignatureMethod(Element smElem) throws MarshalException {
	super(smElem);
    }

    protected void checkParams(SignatureMethodParameterSpec params) 
	throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("no parameters " +
                "should be specified for RSA signature algorithm");
        }
    }

    protected SignatureMethodParameterSpec unmarshalParams(Element paramsElem)
        throws MarshalException {
        throw new MarshalException("no parameters should " +
            "be specified for RSA signature algorithm");
    }

    protected void marshalParams(Element parent, String dsPrefix)
        throws MarshalException {
        // should never get invoked
        throw new MarshalException("no parameters should " +
            "be specified for RSA signature algorithm");
    }

    protected boolean paramsEqual(AlgorithmParameterSpec spec) {
	// params should always be null
	return (getParameterSpec() == spec);
    }

    public boolean verify(Key key, byte[] data, byte[] sig) 
	throws InvalidKeyException, SignatureException {
    	if (key == null || sig == null) {
    	    throw new NullPointerException("key or signature cannot be null");
    	}

        if (!(key instanceof PublicKey)) {
	    throw new InvalidKeyException("key must be PublicKey");
        }
	if (signature == null) {
	    try {
                // FIXME: do other hashes besides sha-1
                signature = Signature.getInstance("SHA1withRSA");
	    } catch (NoSuchAlgorithmException nsae) {
		throw new SignatureException("SHA1withRSA Signature not found");
	    }
	}
        signature.initVerify((PublicKey) key);
        signature.update(data);
        log.log(Level.FINE, "verifying data: " + Base64.encode(data));
        log.log(Level.FINE, "verifying with key: " + key);
        return signature.verify(sig );  
    }

    public byte[] sign(Key key, byte[] data) throws InvalidKeyException {
    	if (key == null || data == null) {
    	    throw new NullPointerException();
    	}

        if (!(key instanceof PrivateKey)) {
            throw new InvalidKeyException("key must be PrivateKey");
        }
        log.log(Level.FINE, "Signing data: " + Base64.encode(data));
        log.log(Level.FINE, "Signing with key: " + key);
	if (signature == null) {
	    try {
                // FIXME: do other hashes besides sha-1
                signature = Signature.getInstance("SHA1withRSA");
	    } catch (NoSuchAlgorithmException nsae) {
		throw new InvalidKeyException("SHA1withRSA Signature not found");
	    }
	}
        signature.initSign((PrivateKey) key);
        try {
            signature.update(data);
	    return signature.sign();
        } catch (SignatureException se) {
	    // should never occur!
	    throw new RuntimeException(se.getMessage());
        }
    }
}
