package spring.security.saml

import es.salenda.grails.plugin.springsecurity.saml.GrailsSAMLAuthenticationProvider
import es.salenda.grails.plugin.springsecurity.saml.SamlSecurityService
import es.salenda.grails.plugin.springsecurity.saml.SpringSamlUserDetailsService
import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import grails.plugins.Plugin
import groovy.transform.CompileDynamic
import org.apache.commons.httpclient.HttpClient
import org.jdom.Document
import org.jdom.input.SAXBuilder
import org.jdom.output.Format
import org.jdom.output.XMLOutputter
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider
import org.opensaml.xml.parse.BasicParserPool
import org.springframework.core.io.ClassPathResource
import org.springframework.core.io.support.PathMatchingResourcePatternResolver
import org.springframework.core.io.support.ResourcePatternResolver
import org.springframework.security.saml.*
import org.springframework.security.saml.context.SAMLContextProviderImpl
import org.springframework.security.saml.key.EmptyKeyManager
import org.springframework.security.saml.key.JKSKeyManager
import org.springframework.security.saml.log.SAMLDefaultLogger
import org.springframework.security.saml.metadata.*
import org.springframework.security.saml.processor.*
import org.springframework.security.saml.util.VelocityFactory
import org.springframework.security.saml.websso.*
import org.springframework.security.web.DefaultRedirectStrategy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy

@CompileDynamic
class SpringSecuritySamlGrailsPlugin extends Plugin {
    // the plugin version
    def version = "3.0.0"

    // the version or versions of Grails the plugin is designed for
    String grailsVersion = "3.1.0 > *"
    List loadAfter = ['springSecurityCore']

    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "plugin/test/**",
        'grails-app/domain/**',
        "grails-app/views/error.gsp",
        'docs/**',
        'scripts/PublishGithub.groovy'
    ]


    // TODO Fill in these fields
    def title = "SAML 2.x support for the Spring Security Plugin" // Headline display name of the plugin
    def author = "Alvaro Sanchez-Mariscal"
    def authorEmail = "alvaro.sanchez@salenda.es"
    def description = '''\
SAML 2.x support for the Spring Security Plugin
'''
    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/spring-security-saml"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
    def organization = [:]

    // Any additional developers beyond the author specified above.
    def developers = [ [ name: "Feroz Panwaskar", email: "feroz.panwaskar@gmail.com" ], [ name: "Jeff Beck", email: "beckje01@gmail.com" ], [ name: "Sphoorti Acharya", email: "sphoortiacharya@gmail.com" ]]

    // Location of the plugin's issue tracker.
    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPSPRINGSECURITYSAML" ]

    // Online location of the plugin's browseable source code.
    def scm = [ url: "https://github.com/sphoortia/spring-security-saml" ]

    def providers = []

    def springClosure =  { ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.active) { return }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultSamlSecurityConfig'

        conf = SpringSecurityUtils.securityConfig
        if (!conf.saml.active) { return }

        println 'Configuring Spring Security SAML ...'

        //Due to Spring DSL limitations, need to import these beans as XML definitions
        def beansFile = "classpath*:security/springSecuritySamlBeans.xml"
        log.debug "Importing beans from ${beansFile}..."
        delegate.importBeans beansFile

        xmlns context:"http://www.springframework.org/schema/context"
        context.'annotation-config'()
        context.'component-scan'('base-package': "org.springframework.security.saml")

        SpringSecurityUtils.registerProvider 'samlAuthenticationProvider'
        SpringSecurityUtils.registerLogoutHandler 'successLogoutHandler'
        SpringSecurityUtils.registerLogoutHandler 'logoutHandler'
        //https://www.codeproject.com/articles/598581/how-to-integrate-spring-oauth-with-spring-saml
//        //Add auto generation of default SP metadata.
        SpringSecurityUtils.registerFilter 'metadataGeneratorFilter', SecurityFilterPosition.FIRST.order + 1

        SpringSecurityUtils.registerFilter 'samlEntryPoint', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 1
        SpringSecurityUtils.registerFilter 'metadataFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 2
        SpringSecurityUtils.registerFilter 'samlProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 3
        SpringSecurityUtils.registerFilter 'samlLogoutFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 4
        SpringSecurityUtils.registerFilter 'samlLogoutProcessingFilter', SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order + 5

        successRedirectHandler(SavedRequestAwareAuthenticationSuccessHandler) {
            alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
            defaultTargetUrl = conf.saml.afterLoginUrl
        }

        successLogoutHandler(SimpleUrlLogoutSuccessHandler) {
            defaultTargetUrl = conf.saml.afterLogoutUrl
        }

        samlLogger(SAMLDefaultLogger)

        if(conf.saml.keyManager.storeFile && conf.saml.keyManager.storePass) {
            keyManager(JKSKeyManager,
                    conf.saml.keyManager.storeFile, conf.saml.keyManager.storePass, conf.saml.keyManager.passwords, conf.saml.keyManager.defaultKey)
        } else {
            keyManager(EmptyKeyManager)

        }

        def idpSelectionPath = conf.saml.entryPoint.idpSelectionPath
        samlEntryPoint(SAMLEntryPoint) {
            filterProcessesUrl = conf.auth.loginFormUrl 						// '/saml/login'
            if (idpSelectionPath) {
                idpSelectionPath = idpSelectionPath 					// '/index.gsp'
            }
            defaultProfileOptions = ref('webProfileOptions')
        }

        webProfileOptions(WebSSOProfileOptions) {
            includeScoping = false
        }

        metadataFilter(MetadataDisplayFilter) {
            filterProcessesUrl = conf.saml.metadata.url 						// '/saml/metadata'
        }

        metadataGenerator(MetadataGenerator)

        // TODO: Update to handle any type of meta data providers for default to file based instead http provider.
        log.debug "Dynamically defining bean metadata providers... "
        def providerBeanName = "extendedMetadataDelegate"
        conf.saml.metadata.providers.each {k,v ->
//            def providerBeanName = "${k}ExtendedMetadataDelegate"
            println "Registering metadata key: ${k} and value: $v"
            if( v.startsWith('http')) {
                "${providerBeanName}"(HTTPMetadataProvider) { spMetadataBean ->
                    spMetadataBean.constructorArgs = [v, 5000]
                    parserPool=ref('parserPool')
                }
            } else {
                "${providerBeanName}"(ExtendedMetadataDelegate) { extMetaDataDelegateBean ->
                    filesystemMetadataProvider(FilesystemMetadataProvider) { bean ->
                        if (v.startsWith("/") || v.indexOf(':') == 1) {
                            File resource = new File(v)
                            bean.constructorArgs = [resource]
                        }else{
                            ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver()
                            def resource = new ClassPathResource(v)
                            try{
                                bean.constructorArgs = [resource.getFile()]
                            }catch (FileNotFoundException fe){
                                final InputStream is = resource.getInputStream();
                                try {
                                    final InputStreamReader reader = new InputStreamReader(is);
                                    try {
                                        final Document headerDoc = new SAXBuilder().build(reader);
                                        XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
                                        String xmlString = outputter.outputString(headerDoc);
                                        File temp = File.createTempFile("idp-local",".xml");
                                        BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
                                        bw.write(xmlString);
                                        bw.close();
                                        bean.constructorArgs = [temp]
                                        temp.deleteOnExit();
                                    } finally {
                                        reader.close();
                                    }
                                } finally {
                                    is.close();
                                }
                            }
                        }
                        parserPool = ref('parserPool')
                    }

                    extMetaDataDelegateBean.constructorArgs = [ref('filesystemMetadataProvider'), new ExtendedMetadata()]
                }
            }
            providers << ref(providerBeanName)
        }

// you can only define a single service provider configuration
        def spFile = conf.saml.metadata.sp.file
        def defaultSpConfig = conf.saml.metadata.sp.defaults
        if (spFile) {

            spMetadata(ExtendedMetadataDelegate) { spMetadataBean ->
                spMetadataProvider(FilesystemMetadataProvider) { spMetadataProviderBean ->
                    if (spFile.startsWith("/") || spFile.indexOf(':') == 1) {
                        File spResource = new File(spFile)
                        spMetadataProviderBean.constructorArgs = [spResource]
                    }else{
                        def spResource = new ClassPathResource(spFile)
                        try{
                            spMetadataProviderBean.constructorArgs = [spResource.getFile()]
                        } catch(FileNotFoundException fe){
                            final InputStream is = spResource.getInputStream();
                            try {
                                final InputStreamReader reader = new InputStreamReader(is);
                                try {
                                    final Document headerDoc = new SAXBuilder().build(reader);
                                    XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat());
                                    String xmlString = outputter.outputString(headerDoc);
                                    File temp = File.createTempFile("sp-local",".xml");
                                    BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
                                    bw.write(xmlString);
                                    bw.close();
                                    spMetadataProviderBean.constructorArgs = [temp]
                                    temp.deleteOnExit();
                                } finally {
                                    reader.close();
                                }
                            } finally {
                                is.close();
                            }

                        }
                    }

                    parserPool = ref('parserPool')
                }

                //TODO consider adding idp discovery default
                spMetadataDefaults(ExtendedMetadata) { extMetadata ->
                    local = defaultSpConfig."local"
                    alias = defaultSpConfig."alias"
                    securityProfile = defaultSpConfig."securityProfile"
                    signingKey = defaultSpConfig."signingKey"
                    encryptionKey = defaultSpConfig."encryptionKey"
                    tlsKey = defaultSpConfig."tlsKey"
                    requireArtifactResolveSigned = defaultSpConfig."requireArtifactResolveSigned"
                    requireLogoutRequestSigned = defaultSpConfig."requireLogoutRequestSigned"
                    requireLogoutResponseSigned = defaultSpConfig."requireLogoutResponseSigned"
                }

                spMetadataBean.constructorArgs = [ref('spMetadataProvider'), ref('spMetadataDefaults')]
            }

            providers << ref('spMetadata')
        }

        metadata(CachingMetadataManager) { metadataBean ->
            // At this point, due to Spring DSL limitations, only one provider
            // can be defined so just picking the first one
            metadataBean.constructorArgs = [providers.first()]
            providers = providers

            if (defaultSpConfig?."alias") {
                hostedSPName = defaultSpConfig?."alias"
            }

            // defaultIDP = conf.saml.metadata.providers[conf.saml.metadata.defaultIdp]
        }

        userDetailsService(SpringSamlUserDetailsService) {
            grailsApplication = grailsApplication
            authorityClassName = conf.authority.className
            authorityJoinClassName = conf.userLookup.authorityJoinClassName
            authorityNameField = conf.authority.nameField
            samlAutoCreateActive = conf.saml.autoCreate.active
            samlAutoAssignAuthorities = conf.saml.autoCreate.assignAuthorities
            samlAutoCreateKey = conf.saml.autoCreate.key
            samlUserAttributeMappings = conf.saml.userAttributeMappings
            samlUserGroupAttribute = conf.saml.userGroupAttribute
            samlUserGroupToRoleMapping = conf.saml.userGroupToRoleMapping
            userDomainClassName = conf.userLookup.userDomainClassName
        }

        samlAuthenticationProvider(GrailsSAMLAuthenticationProvider) {
            userDetails = ref('userDetailsService')
            hokConsumer = ref('webSSOprofileConsumer')
        }

        contextProvider(SAMLContextProviderImpl)

        samlProcessingFilter(SAMLProcessingFilter) {
            authenticationManager = ref('authenticationManager')
            authenticationSuccessHandler = ref('successRedirectHandler')
            sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
            authenticationFailureHandler = ref('authenticationFailureHandler')
        }

        authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
            redirectStrategy = ref('redirectStrategy')
            defaultFailureUrl = conf.failureHandler.defaultFailureUrl //'/login/authfail?login_error=1'
            useForward = conf.failureHandler.useForward // false
            ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
            exceptionMappings = conf.failureHandler.exceptionMappings // [:]
        }

        redirectStrategy(DefaultRedirectStrategy) {
            contextRelative = conf.redirectStrategy.contextRelative // false
        }

        sessionFixationProtectionStrategy(SessionFixationProtectionStrategy)

        logoutHandler(SecurityContextLogoutHandler) {
            invalidateHttpSession = true
        }

        samlLogoutFilter(SAMLLogoutFilter,
                ref('successLogoutHandler'), ref('logoutHandler'), ref('logoutHandler'))

        samlLogoutProcessingFilter(SAMLLogoutProcessingFilter,
                ref('successLogoutHandler'), ref('logoutHandler'))

        webSSOprofileConsumer(WebSSOProfileConsumerImpl){
            responseSkew = conf.saml.responseSkew
        }

        webSSOprofile(WebSSOProfileImpl)

        ecpprofile(WebSSOProfileECPImpl)

        logoutprofile(SingleLogoutProfileImpl)

        postBinding(HTTPPostBinding, ref('parserPool'), ref('velocityEngine'))

        redirectBinding(HTTPRedirectDeflateBinding, ref('parserPool'))

        artifactBinding(HTTPArtifactBinding,
                ref('parserPool'),
                ref('velocityEngine'),
                ref('artifactResolutionProfile')
        )

        artifactResolutionProfile(ArtifactResolutionProfileImpl, ref('httpClient')) {
            processor = ref('soapProcessor')
        }

        httpClient(HttpClient)

        soapProcessor(SAMLProcessorImpl, ref('soapBinding'))

        soapBinding(HTTPSOAP11Binding, ref('parserPool'))

        paosBinding(HTTPPAOS11Binding, ref('parserPool'))

        bootStrap(SAMLBootstrap)

        velocityEngine(VelocityFactory) { bean ->
            bean.factoryMethod = "getEngine"
        }

        parserPool(BasicParserPool)

        //-- Self registartion of SP metadata
        metadataGeneratorFilter(MetadataGeneratorFilter) { bean ->
            bean.constructorArgs = [ref('metadataGenerator')]
        }

//        securityTagLib(SamlTagLib) {
//            springSecurityService = ref('springSecurityService')
//            webExpressionHandler = ref('webExpressionHandler')
//            webInvocationPrivilegeEvaluator = ref('webInvocationPrivilegeEvaluator')
//        }

        springSecurityService(SamlSecurityService) {
            config = conf
            authenticationTrustResolver = ref('authenticationTrustResolver')
            grailsApplication = grailsApplication
            passwordEncoder = ref('passwordEncoder')
            objectDefinitionSource = ref('objectDefinitionSource')
        }

        println '...finished configuring Spring Security SAML'
    }


    Closure doWithSpring() {
//        springClosure.resolveStrategy = Closure.DELEGATE_FIRST
        springClosure
    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        /*
        def metadata = applicationContext.getBean('metadata')
        def providerBeans = []
        providers.each {
            providerBeans << applicationContext.getBean(it.beanName)
        }
        metadata.setProviders(providerBeans)
        */
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }
}
