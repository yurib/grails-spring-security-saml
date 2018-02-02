/* Copyright 2006-2015 the original author or authors.
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

import grails.util.Holders
import org.springframework.security.saml.SAMLLogoutFilter


class SamlTagLib {
	static namespace = 'sec'

	static final String LOGOUT_SLUG = '/j_spring_security_logout'

    /** Dependency injection for springSecurityService. */
    def springSecurityService

	def getSecurityConfig() {
		Holders.grailsApplication.config.grails.plugin.springsecurity
	}

	/**
     * {@inheritDocs}
     */
    def loggedInUserInfo = { attrs, body ->
        String field = assertAttribute('field', attrs, 'loggedInUserInfo')

        def source = springSecurityService.authentication?.details?."${field}"

        if (source) {
            out << source.encodeAsHTML()
        }
        else {
            out << body()
        }
    }

	/**
	 * {@inheritDocs}
	 */
	def loginLink = { attrs, body ->
		def contextPath = request.contextPath
		def url = securityConfig.auth.loginFormUrl
		def selectIdp = attrs.remove('selectIdp')

		url = "${contextPath}${url}"
		if (!selectIdp) {
			def defaultIdp = securityConfig.saml.metadata.defaultIdp
			def providers = securityConfig.saml.metadata.providers
			if( providers[defaultIdp] ) {
				url += "?idp=${providers[defaultIdp]}"
			}
		}

		def elementClass = generateClassAttribute(attrs)
		def elementId = generateIdAttribute(attrs)

		out << "<a href='${url}'${elementId}${elementClass}>${body()}</a>"
	}

	/**
	 * {@inheritDocs}
	 */
	def logoutLink = { attrs, body ->
		def local = attrs.remove('local')
		def contextPath = request.contextPath

		def url = LOGOUT_SLUG

		def samlEnabled = securityConfig.saml.active
		if(samlEnabled){
			url = SAMLLogoutFilter.FILTER_URL
		}

		def elementClass = generateClassAttribute(attrs)
		def elementId = generateIdAttribute(attrs)

		out << """<a href='${contextPath}${url}${local?'?local=true':''}'${elementId}${elementClass}>${body()}</a>"""
	}

	private String generateIdAttribute(Map attrs) {
		def elementId = ""
		if (attrs.id) {
			elementId = " id=\'${attrs.id}\'"
		}
		elementId
	}

	private String generateClassAttribute(Map attrs) {
		def elementClass = ""
		if (attrs.class) {
			elementClass = " class=\'${attrs.class}\'"
		}
		elementClass
	}

    protected assertAttribute(String name, attrs, String tag) {
        if (!attrs.containsKey(name)) {
            throwTagError "Tag [$tag] is missing required attribute [$name]"
        }
        attrs.remove name
    }

}
