/*
 * Copyright 2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * imitations under the License.
 */

/*
 * XSEC
 *
 * XKMSResultTypeImpl := Implementation of base schema of XKMS Request messages
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/framework/XSECException.hpp>
#include <xsec/framework/XSECEnv.hpp>
#include <xsec/xkms/XKMSConstants.hpp>

#include "XKMSResultTypeImpl.hpp"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Constructor Destructor
// --------------------------------------------------------------------------------

XKMSResultTypeImpl::XKMSResultTypeImpl(
	const XSECEnv * env) :
XKMSMessageAbstractTypeImpl(env),
mp_resultMajorAttr(NULL),
mp_resultMinorAttr(NULL),
mp_requestSignatureValueElement(NULL)
{

}

XKMSResultTypeImpl::XKMSResultTypeImpl(
	const XSECEnv * env, 
	DOMElement * node) :
XKMSMessageAbstractTypeImpl(env, node),
mp_requestSignatureValueElement(NULL)
{

}

XKMSResultTypeImpl::~XKMSResultTypeImpl() {

}
	
// --------------------------------------------------------------------------------
//           Load
// --------------------------------------------------------------------------------

void XKMSResultTypeImpl::load(void) {

	if (mp_messageAbstractTypeElement == NULL) {

		// Attempt to load an empty element
		throw XSECException(XSECException::ResultTypeError,
			"XKMSResultType::load - called on empty DOM");

	}

	XKMSMessageAbstractTypeImpl::load();

	/* Now load the result attributes */

	mp_resultMajorAttr = 
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagResultMajor);
	mp_resultMinorAttr = 
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagResultMinor);
	mp_requestIdAttr =
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagRequestId);

	/* Decode responses */
	if (mp_resultMajorAttr == NULL) {
		// Attempt to load an empty element
		throw XSECException(XSECException::ResultTypeError,
			"XKMSResultType::load - No Major Response code found");
	}

	const XMLCh * res = mp_resultMajorAttr->getNodeValue();

	// Result types have now been updated, and are URIs with the XKMS namespace prepended
	// to the actual result value

	int res2 = XMLString::indexOf(res, chPound);
	if (res2 == -1 || XMLString::compareNString(res, XKMSConstants::s_unicodeStrURIXKMS, res2)) {
			throw XSECException(XSECException::ResultTypeError,
				"XKMSResultType::load - ResultType not in XKMS Name Space");
	}

	res = &res[res2+1];
	for (m_resultMajor = XKMSResultType::Pending; 
		m_resultMajor > XKMSResultType::NoneMajor; 
		m_resultMajor = (XKMSResultType::ResultMajor) (m_resultMajor-1)) {

		if (strEquals(XKMSConstants::s_tagResultMajorCodes[m_resultMajor], res))
			break;

	}

	if (mp_resultMinorAttr != NULL) {

		res = mp_resultMinorAttr->getNodeValue();
		int res2 = XMLString::indexOf(res, chPound);
		if (res2 == -1 ||
			XMLString::compareNString(res, XKMSConstants::s_unicodeStrURIXKMS, res2)) {

			throw XSECException(XSECException::ResultTypeError,
				"XKMSResultType::load - ResultType not in XKMS Name Space");
		}

		res = &res[res2+1];

		for (m_resultMinor = XKMSResultType::NotSynchronous; 
			m_resultMinor > XKMSResultType::NoneMinor; 
			m_resultMinor = (XKMSResultType::ResultMinor) (m_resultMinor-1)) {

			if (strEquals(XKMSConstants::s_tagResultMinorCodes[m_resultMinor], res))
				break;

		}
	}

	else
		m_resultMinor = XKMSResultType::NoneMinor;

	/* Check to see if there is a RequestSignatureValue node */
	mp_requestSignatureValueElement = (DOMElement *) findFirstChildOfType(mp_messageAbstractTypeElement, DOMNode::ELEMENT_NODE);
	while (mp_requestSignatureValueElement != NULL && 
		!strEquals(getXKMSLocalName(mp_requestSignatureValueElement), XKMSConstants::s_tagRequestSignatureValue)) {

		mp_requestSignatureValueElement = findNextElementChild(mp_requestSignatureValueElement);

	}

	if (mp_requestSignatureValueElement != NULL) {

		if (findFirstChildOfType(mp_requestSignatureValueElement, DOMNode::TEXT_NODE) == NULL) {
			throw XSECException(XSECException::ResultTypeError,
				"XKMSResultType::load - RequestSignatureValue must have text node as child");
		}
	}

}

// --------------------------------------------------------------------------------
//           Create from scratch
// --------------------------------------------------------------------------------

DOMElement * XKMSResultTypeImpl::createBlankResultType(
		const XMLCh * tag,
		const XMLCh * service,
		const XMLCh * id,
		ResultMajor rmaj,
		ResultMinor rmin) {

	DOMElement * ret = 
		XKMSMessageAbstractTypeImpl::createBlankMessageAbstractType(tag, service, id);

	safeBuffer s;

	s.sbXMLChIn(XKMSConstants::s_unicodeStrURIXKMS);
	s.sbXMLChCat(XKMSConstants::s_tagResultMajorCodes[rmaj]);

	ret->setAttributeNS(NULL, 
		XKMSConstants::s_tagResultMajor,
		s.rawXMLChBuffer());

	if (rmin != XKMSResultType::NoneMinor) {

		s.sbXMLChIn(XKMSConstants::s_unicodeStrURIXKMS);
		s.sbXMLChCat(XKMSConstants::s_tagResultMinorCodes[rmin]);
	
		ret->setAttributeNS(NULL, 
			XKMSConstants::s_tagResultMinor,
			s.rawXMLChBuffer());
	}

	m_resultMajor = rmaj;
	m_resultMinor = rmin;

	mp_resultMajorAttr = 
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagResultMajor);
	mp_resultMinorAttr = 
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagResultMinor);

	return ret;
}

// --------------------------------------------------------------------------------
//           Getter interface
// --------------------------------------------------------------------------------

XKMSResultType::ResultMajor XKMSResultTypeImpl::getResultMajor(void) const {

	return m_resultMajor;

}

XKMSResultType::ResultMinor XKMSResultTypeImpl::getResultMinor(void) const {

	return m_resultMinor;

}

const XMLCh * XKMSResultTypeImpl::getRequestId(void) const {

	if (mp_requestIdAttr != NULL)
		return mp_requestIdAttr->getNodeValue();
	
	return NULL;

}

const XMLCh * XKMSResultTypeImpl::getRequestSignatureValue(void) const {

	if (mp_requestSignatureValueElement != NULL)
		return findFirstChildOfType(mp_requestSignatureValueElement, 
									DOMNode::TEXT_NODE)->getNodeValue();

	return NULL;

}

// --------------------------------------------------------------------------------
//           Setter interface
// --------------------------------------------------------------------------------

void XKMSResultTypeImpl::setResultMajor(ResultMajor) {}
void XKMSResultTypeImpl::setResultMinor(ResultMinor) {}

void XKMSResultTypeImpl::setRequestId(const XMLCh * id) {

	if (mp_messageAbstractTypeElement == NULL) {

		// Attempt update when not initialised
		throw XSECException(XSECException::MessageAbstractTypeError,
			"XKMSResultType::setRequestId - called on non-initialised structure");

	}

	mp_messageAbstractTypeElement->setAttributeNS(NULL, XKMSConstants::s_tagRequestId, id);
	mp_requestIdAttr = 
		mp_messageAbstractTypeElement->getAttributeNodeNS(NULL, XKMSConstants::s_tagRequestId);

}

void XKMSResultTypeImpl::setRequestSignatureValue(const XMLCh * value) {

	if (mp_requestSignatureValueElement != NULL) {
		findFirstChildOfType(mp_requestSignatureValueElement, DOMNode::TEXT_NODE)->setNodeValue(value);
		return;
	}

	// Get some setup values
	safeBuffer str;
	DOMDocument *doc = mp_env->getParentDocument();
	const XMLCh * prefix = mp_env->getXKMSNSPrefix();

	makeQName(str, prefix, XKMSConstants::s_tagRequestSignatureValue);

	mp_requestSignatureValueElement = doc->createElementNS(XKMSConstants::s_unicodeStrURIXKMS, 
												str.rawXMLChBuffer());

	mp_requestSignatureValueElement->appendChild(doc->createTextNode(value));

	/* Find where this sits, and insert */
	DOMElement * c = findFirstElementChild(mp_messageAbstractTypeElement);
	while (c != NULL) {

		if (!(strEquals(getXKMSLocalName(c), XKMSConstants::s_tagMessageExtension) ||
			strEquals(getDSIGLocalName(c), XKMSConstants::s_tagSignature) ||
			strEquals(getXKMSLocalName(c), XKMSConstants::s_tagOpaqueClientData)))
			
			break;

	}

	if (c != NULL) {
		mp_messageAbstractTypeElement->insertBefore(mp_requestSignatureValueElement, c);
		if (mp_env->getPrettyPrintFlag()) {
			mp_messageAbstractTypeElement->insertBefore(
				mp_env->getParentDocument()->createTextNode(DSIGConstants::s_unicodeStrNL), c);
		}
	}
	else {
		mp_messageAbstractTypeElement->appendChild(mp_requestSignatureValueElement);
		mp_env->doPrettyPrint(mp_messageAbstractTypeElement);
	}

}

