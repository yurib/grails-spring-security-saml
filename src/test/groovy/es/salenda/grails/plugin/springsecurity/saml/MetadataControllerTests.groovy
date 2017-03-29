package es.salenda.grails.plugin.springsecurity.saml

import grails.test.mixin.*
import org.junit.*
import spring.security.saml.MetadataController

@TestFor(MetadataController)
class MetadataControllerTests {
	
	def metadata
	
	@Before
	void init() {
		metadata = [hostedSPName: 'splocal', SPEntityNames: ['testsp'], IDPEntityNames: ['testidp'] ]
		controller.metadata = metadata
	}
	
	void testIndexReturnsMetadataValuesInModel() {
		def model = controller.index()
		
		assert model.hostedSP == metadata.hostedSPName
		assert model.spList == metadata.SPEntityNames
		assert model.idpList == metadata.IDPEntityNames
	}
}