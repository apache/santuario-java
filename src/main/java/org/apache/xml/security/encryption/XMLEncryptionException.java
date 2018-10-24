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
package org.apache.xml.security.encryption;

import org.apache.xml.security.exceptions.XMLSecurityException;

/**
 *
 */
public class XMLEncryptionException extends XMLSecurityException {
    /**
     *
     */
    private static final long serialVersionUID = 1L;

    /**
     *
     *
     */
    public XMLEncryptionException() {
        super();
    }

    public XMLEncryptionException(Exception ex) {
        super(ex);
    }

    /**
     *
     * @param msgID
     */
    public XMLEncryptionException(String msgID) {
        super(msgID);
    }

    /**
     *
     * @param msgID
     * @param exArgs
     */
    public XMLEncryptionException(String msgID, Object ... exArgs) {
        super(msgID, exArgs);
    }

    /**
     * @param originalException
     * @param msgID
     */
    public XMLEncryptionException(Exception originalException, String msgID) {
        super(originalException, msgID);

    }

    @Deprecated
    public XMLEncryptionException(String msgID, Exception originalException) {
        this(originalException, msgID);
    }

    /**
     * @param originalException
     * @param msgID
     * @param exArgs
     */
    public XMLEncryptionException(Exception originalException, String msgID, Object[] exArgs) {
        super(originalException, msgID, exArgs);
    }

    @Deprecated
    public XMLEncryptionException(String msgID, Object[] exArgs, Exception originalException) {
        this(originalException, msgID, exArgs);
    }
}
