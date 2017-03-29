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
package es.salenda.grails.plugin.springsecurity.saml

import grails.core.GrailsDomainClass
import grails.plugin.springsecurity.SpringSecurityService
import groovy.transform.CompileDynamic

/**
 * A subclass of {@link SpringSecurityService} to replace {@link this.getCurrentUser()}
 * method. The parent implementation performs a database load, but we do not have
 * database users here, so we simply return the authentication details.
 * 
 * @author alvaro.sanchez
 */
@CompileDynamic
class SamlSecurityService extends SpringSecurityService {

	static transactional = false
	def config

	Object getCurrentUser() {
		def userDetails
		if (!isLoggedIn()) {
			userDetails = null
		} else {
			userDetails = getAuthentication().details
			if ( config?.saml.autoCreate.active ) { 
				userDetails =  getCurrentPersistedUser(userDetails)
			}
		}
		return userDetails
	}
	
	private Object getCurrentPersistedUser(userDetails) {
		if (userDetails) {
			String className = config?.userLookup.userDomainClassName
			String userKey = config?.saml.autoCreate.key
			if (className && userKey) {
				Class<GrailsDomainClass> userClass = grailsApplication.getDomainClass(className)?.clazz
				return userClass."findBy${userKey.capitalize()}"(userDetails."$userKey")
			}
		} else { return null}
	}
}
