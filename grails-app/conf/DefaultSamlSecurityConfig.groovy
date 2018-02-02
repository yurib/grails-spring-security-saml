security {
	saml {
		userAttributeMappings = [:]
		active = true
		targetUrlParameter = 'returnUrl'
		entityBaseURL = null
		useReferer = false
		afterLoginUrl = '/'
		afterLogoutUrl = '/'
		userGroupAttribute = "memberOf"
		responseSkew = 60
		autoCreate {
			active =  false
			key = 'username'
			assignAuthorities = true
		}
		metadata {
			defaultIdp = null //'ping'
			url = '/saml/metadata'
			providers = [:] //[ ping :'security/idp-local.xml']
			sp {
				file = null //'security/sp.xml'
				defaults = [
					local: true, 
					alias: null, //'test'
					securityProfile: 'metaiop',
					signingKey: 'ping',
					encryptionKey: 'ping', 
					tlsKey: 'ping',
					requireArtifactResolveSigned: false,
					requireLogoutRequestSigned: false, 
					requireLogoutResponseSigned: false ]
			}
		}
		keyManager {
			storeFile = null //'classpath:security/keystore.jks'
			storePass = null //'nalle123'
			passwords = [:]  //[ ping: 'ping123' ]
			defaultKey = null //'ping'
		}
	}
}
