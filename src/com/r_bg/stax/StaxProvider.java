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
 * ===========================================================================
 *
 * (C) Copyright IBM Corp. 2003 All Rights Reserved.
 *
 * ===========================================================================
 */
/*
 * Portions copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
/*
 * $Id: XMLDSigRI.java 375655 2006-02-07 18:35:54Z mullan $
 */
package com.r_bg.stax;

import java.security.AccessController;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import javax.xml.crypto.dsig.Transform;

/**
 * The XMLDSig RI Provider.
 *
 * @author Joyce Leung
 */

/**
 * Defines the XMLDSigRI provider.
 */

public final class StaxProvider extends Provider {

    static final long serialVersionUID = -5049765099299494554L;

    private static final String INFO = "XMLDSig " + 
    "(Stax XMLSignatureFactory; Stax KeyInfoFactory)";

    public StaxProvider() {
	/* We are the XMLDSig provider */
	super("XMLDSig", 1.0, INFO);
	
	final Map map = new HashMap();
        map.put("XMLSignatureFactory.Stax", 
	        "com.r_bg.stax.StaxXMLSignatureFactory");
        map.put((String) "TransformService." + Transform.BASE64, 
	        "com.r_bg.stax.transforms.StaxBase64Transform");
	map.put((String) "TransformService." + Transform.BASE64 +
		" MechanismType", "Stax");
	
       	AccessController.doPrivileged(new java.security.PrivilegedAction() {
	    public Object run() {
		putAll(map);
		return null;
	    }
	});
    }
}
