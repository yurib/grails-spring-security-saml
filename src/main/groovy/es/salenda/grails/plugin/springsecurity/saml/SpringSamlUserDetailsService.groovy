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
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import org.springframework.beans.BeanUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.userdetails.SAMLUserDetailsService
import org.springframework.dao.DataAccessException

/**
 * A {@link GormUserDetailsService} extension to read attributes from a LDAP-backed 
 * SAML identity provider. It also reads roles from database
 *
 * @author alvaro.sanchez
 */
@CompileDynamic
class SpringSamlUserDetailsService extends GormUserDetailsService implements SAMLUserDetailsService {
	// Spring bean injected configuration parameters
	String authorityClassName
	String authorityJoinClassName
	String authorityNameField
	Boolean samlAutoCreateActive
	Boolean samlAutoAssignAuthorities = true
	String samlAutoCreateKey
	Map samlUserAttributeMappings
	Map samlUserGroupToRoleMapping
	String samlUserGroupAttribute
	String userDomainClassName
	String authoritiesPropertyName
	String authorityPropertyName

	Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {

		if (credential) {
			String username = getSamlUsername(credential)
			if (!username) {
				throw new UsernameNotFoundException("No username supplied in saml response.")
			}

			def user = generateSecurityUser(username)
			user = mapAdditionalAttributes(credential, user)
			if (user) {
				log.debug "Loading database roles for $username..."

				def grantedAuthorities = []
				def userClazz = user.class
				if (samlAutoCreateActive) {
					def authorities = getAuthoritiesForUser(credential)
					user = saveUser(userClazz, user, authorities)
				}

				//TODO move to function
				Class<GrailsDomainClass> UserRoleClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
				if(UserRoleClass) {
					UserRoleClass.withTransaction {
						def auths = UserRoleClass.findAllWhere(user: user).collect { it.role }

						auths.each { authority ->
							grantedAuthorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))

						}
					}
				} else {
					user."${authoritiesPropertyName}".each { authority ->
						grantedAuthorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))
					}
				}
				return createUserDetails(user, grantedAuthorities)
			} else {
				throw new InstantiationException('could not instantiate new user')
			}
		}
	}

	protected String getSamlUsername(credential) {

		if (samlUserAttributeMappings?.username) {

			def attribute = credential.getAttribute(samlUserAttributeMappings.username)
			def value = attribute?.attributeValues?.value
			return value?.first()
		} else {
			// if no mapping provided for username attribute then assume it is the returned subject in the assertion
			return credential.nameID?.value
		}
	}

	protected Object mapAdditionalAttributes(credential, user) {
		samlUserAttributeMappings.each { key, value ->
			def attribute = credential.getAttribute(value)
			def samlValue = attribute?.attributeValues?.value
			if (samlValue) {
				user."$key" = samlValue?.first()
			}
		}
		user
	}

	protected Collection<GrantedAuthority> getAuthoritiesForUser(SAMLCredential credential) {
		Set<GrantedAuthority> authorities = new HashSet<SimpleGrantedAuthority>()

		def samlGroups = getSamlGroups(credential)

		samlGroups.each { groupName ->
			def role = samlUserGroupToRoleMapping.get(groupName)
			def authority = getRole(role)

			if (authority) {
				authorities.add(new SimpleGrantedAuthority(authority."$authorityNameField"))
			}
		}

		return authorities
	}

	/**
	 * Extract the groups that the user is a member of from the saml assertion.
	 * Expects the saml.userGroupAttribute to specify the saml assertion attribute that holds 
	 * returned group membership data.
	 *
	 * Expects the group strings to be of the format "CN=groupName,someOtherParam=someOtherValue"
	 *
	 * @param credential
	 * @return list of groups
	 */
	protected List getSamlGroups(SAMLCredential credential) {
		def userGroups = []

		if (samlUserGroupAttribute) {
			def attributes = credential.getAttribute(samlUserGroupAttribute)

			attributes.each { attribute ->
				attribute.attributeValues?.each { attributeValue ->
					log.debug "Processing group attribute value: ${attributeValue}"

					def groupString = attributeValue.value
					groupString?.tokenize(',').each { token ->
						def keyValuePair = token.tokenize('=')

						if (keyValuePair.first() == 'CN') {
							userGroups << keyValuePair.last()
						}
					}
				}
			}
		}

		userGroups
	}

	private Object generateSecurityUser(username) {
		if (userDomainClassName) {
			Class<GrailsDomainClass> UserClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
			if (UserClass) {
				def user = BeanUtils.instantiateClass(UserClass)
				user.username = username
				user.password = "password"
				return user
			} else {
				throw new ClassNotFoundException("domain class ${userDomainClassName} not found")
			}
		} else {
			throw new ClassNotFoundException("security user domain class undefined")
		}
	}

	private def saveUser(userClazz, user, authorities) {
		if (userClazz && samlAutoCreateActive && samlAutoCreateKey && authorityNameField ) {

			Map whereClause = [:]
			whereClause.put "$samlAutoCreateKey".toString(), user."$samlAutoCreateKey"
			Class<GrailsDomainClass> UserRoleClass = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz

			userClazz.withTransaction {
				def existingUser = userClazz.findWhere(whereClause)
				if (!existingUser) {
					if (!user.save()) throw new UsernameNotFoundException("Could not save user ${user}");
				} else {
					user = updateUserProperties(existingUser, user)

					if (samlAutoAssignAuthorities) {
						if(UserRoleClass) {
							UserRoleClass.removeAll user
						} else {
							user."${authoritiesPropertyName}".removeAll()
						}
					}
					user.save()
				}
				if (samlAutoAssignAuthorities) {
					authorities.each { grantedAuthority ->
						def role = getRole(grantedAuthority."${authorityNameField}")
						if(UserRoleClass) {
							UserRoleClass.create(user, role)
						} else {
							user."addTo${authoritiesPropertyName.capitalize()}"(role)
						}
					}
					user.save()
				}

			}
		}
		return user
	}

	private Object updateUserProperties(existingUser, user) {
		samlUserAttributeMappings.each { key, value ->
			existingUser."$key" = user."$key"
		}
		return existingUser
	}

	private Object getRole(String authority) {
		if (authority && authorityNameField && authorityClassName) {
			Class<GrailsDomainClass> Role = grailsApplication.getDomainClass(authorityClassName).clazz
			if (Role) {
				Map whereClause = [:]
				whereClause.put "$authorityNameField".toString(), authority
				Role.withTransaction {
					Role.findOrSaveWhere(whereClause)
				}
			} else {
				throw new ClassNotFoundException("domain class ${authorityClassName} not found")
			}
		}
	}
}
