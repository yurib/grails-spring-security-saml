package es.salenda.grails.plugin.springsecurity.saml

import grails.core.GrailsApplication
import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import org.opensaml.saml2.core.impl.AssertionImpl
import org.opensaml.saml2.core.impl.NameIDImpl
import org.springframework.security.saml.SAMLCredential
import spock.lang.Specification
import test.TestRole
import test.TestSamlUser
import test.TestUserRole

@Integration
@Rollback
class SpringSamlUserDetailsServiceSpec extends Specification {

	String username = "jackSparrow"

	GrailsApplication grailsApplication

	def "Test getting user details from db"() {
		given:
			TestSamlUser user = TestSamlUser.build([username:username,email:'bob@fake.com'])
			TestRole role = TestRole.build(authority:"testauth")
			TestUserRole userRole = TestUserRole.build(user:user,role:role)
			SpringSamlUserDetailsService service = new SpringSamlUserDetailsService(samlAutoAssignAuthorities: false,samlAutoCreateActive: true,userDomainClassName: "test.TestSamlUser",samlAutoCreateKey: 'username',authorityNameField: 'authority',authorityJoinClassName: 'test.TestUserRole')
			service.grailsApplication = grailsApplication

		when:
			SAMLCredential cred
			cred = new SAMLCredential(new NameIDImpl("", "", ""), new AssertionImpl("", "", ""), null, null)
			cred.metaClass.getNameID = { [value: "$username"] }
			def loadedUser = service.loadUserBySAML(cred)

		then:
			user.username == username && user.email == 'bob@fake.com' && loadedUser && loadedUser.username == username

	}



}
