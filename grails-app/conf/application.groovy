grails {
	plugin {
		springsecurity {
			rejectIfNoRule = false
			userLookup {
				usernamePropertyName = 'username'
				enabledPropertyName = 'enabled'
				passwordPropertyName = 'password'
				authoritiesPropertyName = 'roles'
			}
			interceptUrlMap = [
					[pattern: '/',               access: ['permitAll']],
					[pattern: '/error',          access: ['permitAll']],
					[pattern: '/index',          access: ['permitAll']],
					[pattern: '/index.gsp',      access: ['permitAll']],
					[pattern: '/shutdown',       access: ['permitAll']],
					[pattern: '/assets/**',      access: ['permitAll']],
					[pattern: '/static/**',      access: ['permitAll']],
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
					providers = [ okta: 'https://fanatics.oktapreview.com/app/exk9iw2zvmRiR6d1J0h7/sso/saml/metadata' ]
				}
				keyManager {
					storeFile = 'classpath:security/keystore.jks'
					storePass = 'Fanatics2016'
					passwords = [ ping: 'superBowl2017' ]
					defaultKey = 'ping'
				}
			}
		}
	}
}

