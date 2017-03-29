/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package es.salenda.grails.plugin.springsecurity.saml;

import groovy.transform.CompileStatic;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

/**
 * A {@link org.springframework.security.saml.SAMLAuthenticationProvider} subclass to return 
 * principal as UserDetails Object. 
 * 
 * @author feroz.panwaskar
 */
@CompileStatic
public class GrailsSAMLAuthenticationProvider extends SAMLAuthenticationProvider {
	public GrailsSAMLAuthenticationProvider() {
		super();
	}
	
	/**
     * @param credential credential used to authenticate user
     * @param userDetail loaded user details, can be null
     * @return principal to store inside Authentication object
     */
	@Override
    protected Object getPrincipal(SAMLCredential credential, Object userDetail) {
		if (userDetail != null) {
			return userDetail;
		}
        
		return credential.getNameID().getValue();
    }
}