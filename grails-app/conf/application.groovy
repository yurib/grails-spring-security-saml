grails {
	plugin {
		springsecurity {
			rejectIfNoRule = false
			userLookup {
				userDomainClassName = 'test.TestSamlUser'
				usernamePropertyName = 'username'
				enabledPropertyName = 'enabled'
				passwordPropertyName = 'password'
				authoritiesPropertyName = 'roles'
				authorityJoinClassName = 'test.TestUserRole'
			}
			interceptUrlMap = [
					[pattern: '/',               access: ['permitAll']],
					[pattern: '/error',          access: ['permitAll']],
					[pattern: '/index',          access: ['permitAll']],
					[pattern: '/index.gsp',      access: ['permitAll']],
					[pattern: '/shutdown',       access: ['permitAll']],
					[pattern: '/assets/**',      access: ['permitAll']],
					[pattern: '/**/js/**',       access: ['permitAll']],
					[pattern: '/**/css/**',      access: ['permitAll']],
					[pattern: '/**/images/**',   access: ['permitAll']],
					[pattern: '/**/favicon.ico', access: ['permitAll']],
					[pattern: '/login',          access: ['permitAll']],
					[pattern: '/login/**',       access: ['permitAll']],
					[pattern: '/logout',         access: ['permitAll']],
					[pattern: '/logout/**',      access: ['permitAll']]
			]
			authority {
				className = 'test.TestRole'
				nameField = 'authority'
			}
			saml {
				userAttributeMappings = [firstName:'firstName', email:'email']
				userGroupToRoleMapping = [user:'ROLE_USER', admin:'ROLE_ADMIN']
				autoCreate {
					active =  true
				}
				metadata {
					defaultIdp = 'okta'
					url = '/saml/metadata'
					providers = [ okta: 'https://abc.oktapreview.com/app/sdffdgfd2zsdgdfgfdd1Jds/sso/saml/metadata' ]
				}
				keyManager {
					storeFile = 'classpath:security/keystore.jks'
					storePass = 'nalle123'
					passwords = [ ping: 'ping123' ]
					defaultKey = 'ping'
				}
			}
		}
	}
}

