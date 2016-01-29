crypto = require "crypto"
url = require "url"
request = require "request"
Q = require "q"
convert = require "./lib/convert"
xrds = require "./lib/xrds"

_associations = {}
_discoveries = {}

AX_MAX_VALUES_COUNT = 1000

openid = exports

openid.RelyingParty = class RelyingParty
	constructor: (@returnUrl, @realm = null, @stateless, @strict, @extensions) ->
	authenticate: (identifier, immediate) ->
		openid.authenticate identifier, @returnUrl, @realm, immediate, @stateless, @extensions, @strict
	verifyAssertion: (url) ->
		openid.verifyAssertion url, @stateless, @extensions, @strict

_toBase64 = (binary) -> convert.base64.encode convert.btwoc binary
_fromBase64 = (str) -> convert.unbtwoc convert.base64.decode str
_xor = (a, b) ->
	throw new Error "Length must match for xor" if a.length isnt b.length
	r = ""
	for i in [0...a.length]
		r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i))
	r

openid.saveAssociation = (provider, type, handle, secret, expiry_time_in_seconds) ->
	Q.delay expiry_time_in_seconds * 1000
	.then -> openid.removeAssociation handle
	
	_associations[handle] = {provider, type, secret}
	Q()
openid.loadAssociation = (handle) -> Q _associations[handle]
openid.removeAssociation = (handle) ->
	delete _associations[handle]
	Q()

openid.saveDiscoveredInformation = (key, provider) ->
	_discoveries[key] = provider
	Q()
openid.loadDiscoveredInformation = (key) -> Q _discoveries[key]

_buildUrl = (theUrl, params = {}) ->
	theUrl = url.parse theUrl, true
	delete theUrl.search
	theUrl.query ?= {}
	theUrl.query[key] = value for own key, value of params
	url.format theUrl

_get = (url, qs, maxRedirects = 5) ->
	openid.request {
		method: "GET"
		url
		qs
		maxRedirects
		headers: "Accept": "application/xrds+xml,text/html,text/plain,*/*"
	}

_post = (url, form, maxRedirects = 5) ->
	openid.request {
		method: "POST"
		url
		form
		maxRedirects
		headers: "Content-Type": "application/x-www-form-urlencoded"
	}

openid.request = (options) ->
	(Q.denodeify request) options
	.then ([response, body]) -> [body, response.headers, response.statusCode]

_decodePostData = (data) ->
	lines = data.split "\n"
	result = {}
	for line in lines
		line = line[0...-1] if line[-1..] is "\r"
		[key, value...] = line.split ":"
		continue if not value?
		result[key] = value.join ":"
	result

_normalizeIdentifier = (identifier) ->
	identifier = identifier.replace /^\s+|\s+$/g, ''
	return null if not identifier
	identifier = identifier[6..] if identifier.indexOf("xri://") is 0
	return identifier if /^[(=@\+\$!]/.test identifier
	return identifier if identifier.indexOf("http") is 0
	return "http://" + identifier

_parseXrds = (xrdsUrl, xrdsData) ->
	services = xrds.parse xrdsData
	return null if not services?
	
	for service in services
		provider = {}
		provider.endpoint = service.uri
		provider.claimedIdentifier = service.id if /https?:\/\/xri./.test xrdsUrl
		switch service.type
			when "http://specs.openid.net/auth/2.0/signon"
				provider.version = "http://specs.openid.net/auth/2.0"
				provider.localIdentifier = service.id
			when "http://specs.openid.net/auth/2.0/server"
				provider.version = "http://specs.openid.net/auth/2.0"
			when "http://openid.net/signon/1.0" or "http://openid.net/signon/1.1"
				provider.version = service.type
				provider.localIdentifier = service.delegate
			else continue

_matchMetaTag = (html) ->
	metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/ig.exec html
	return null if not metaTagMatches or metaTagMatches.length < 2
	
	contentMatches = /content="(.*?)"/ig.exec metaTagMatches[1]
	return null if not contentMatches or contentMatches.length < 2
	
	contentMatches[1]

_matchLinkTag = (html, rel) ->
	providerLinkMatches = new RegExp("<link\\s+.*?rel=[\"'][^\"']*?#{rel}[^\"']*?[\"'].*?>", 'ig').exec html
	return null if not providerLinkMatches or providerLinkMatches.length < 1
	
	href = /href=["'](.*?)["']/ig.exec providerLinkMatches[0]
	return null if not href or href.length < 2
	
	href[1]

_parseHtml = (htmlUrl, html, hops) -> Q do ->
	metaUrl = _matchMetaTag(html)
	return _resolveXri(metaUrl, hops + 1) if metaUrl?
	provider = _matchLinkTag(html, 'openid2.provider')
	Q if not provider?
			provider = _matchLinkTag(html, 'openid.server')
			if provider?
				localId = _matchLinkTag(html, 'openid.delegate')
				[
					version: 'http://openid.net/signon/1.1'
					endpoint: provider
					claimedIdentifier: htmlUrl
					localIdentifier: localId
				]
			else null
		else
			localId = _matchLinkTag(html, 'openid2.local_id')
			[
				version: 'http://specs.openid.net/auth/2.0/signon'
				endpoint: provider
				claimedIdentifier: htmlUrl
				localIdentifier: localId
			]

_parseHostMeta = (hostMeta) ->
	match = /^Link: <([^\n\r]+?)>;/.exec hostMeta
	if match? and match.length > 0
		xriUrl = match[1]
		_resolveXri xriUrl
	else
		Q()

_resolveXri = (xriUrl, hops = 1) -> Q do ->
	return if hops >= 5
	_get(xriUrl).then ([data, headers, statusCode]) ->
		return if Number(statusCode) isnt 200
		if (xrdsLocation = headers['x-xrds-location'])?
			_get(xrdsLocation).then ([data, ..., statusCode]) ->
				_parseXrds(xrdsLocation, data) if Number(statusCode) is 200 and data?
		else if data?
			contentType = headers['content-type']
			# text/xml is not compliant, but some hosting providers refuse header
			# changes, so text/xml is encountered
			if contentType and (contentType.indexOf('application/xrds+xml') is 0 or contentType.indexOf('text/xml') is 0)
				_parseXrds(xriUrl, data)
			else _resolveHtml(xriUrl, hops + 1, data)

_resolveHtml = (identifier, hops = 1, data) -> Q do ->
	return if hops >= 5
	if data?
		_parseHtml identifier, data, hops
	else _get(identifier).then ([data, ..., statusCode]) ->
		_parseHtml identifier, data, hops + 1 if Number(statusCode) is 200 and data?

_resolveHostMeta = (identifier, strict, fallBackToProxy) -> Q do ->
	host = url.parse identifier
	hostMetaUrl = if fallBackToProxy and not strict
			'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host
		else host.protocol + '//' + host.host + '/.well-known/host-meta'
	if hostMetaUrl
		_get(hostMetaUrl).then ([data, headers, statusCode]) ->
			if Number(statusCode) isnt 200 or not data?
				_resolveHostMeta identifier, strict, true if not fallBackToProxy and not strict
			else
				#Attempt to parse the data but if this fails it may be because
				#the response to hostMetaUrl was some other http/html resource.
				#Therefore fallback to the proxy if no providers are found.
				_parseHostMeta(data).then (providers) ->
					if (not providers? or providers.length is 0) and not fallBackToProxy and not strict
						_resolveHostMeta identifier, strict, true
					else providers

openid.discover = (identifier, strict) -> Q do ->
	identifier = _normalizeIdentifier identifier
	throw new Error 'Invalid identifier' if not identifier
	if identifier.indexOf('http') isnt 0
		# XRDS
		identifier = "https://xri.net/#{identifier}?_xrd_r=application/xrds%2Bxml"
	# Try XRDS/Yadis discovery
	_resolveXri(identifier).then (providers) ->
		if not providers? or providers.length is 0
			# Fallback to HTML discovery
			_resolveHtml(identifier).then (providers) ->
				if not providers or providers.length is 0
					_resolveHostMeta identifier, strict
				else providers
		else
			# Add claimed identifier to providers with local identifiers
			# and OpenID 1.0/1.1 providers to ensure correct resolution 
			# of identities and services
			for provider in providers
				if not provider.claimedIdentifier and (provider.localIdentifier or provider.version.indexOf('2.0') is -1)
					provider.claimedIdentifier = identifier
			providers

_createDiffieHellmanKeyExchange = (algorithm) ->
	defaultPrime = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr'
	dh = crypto.createDiffieHellman defaultPrime, 'base64'
	dh.generateKeys()
	dh

openid.associate = (provider, strict, algorithm = 'DH-SHA256') -> Q do ->
	params = _generateAssociationRequestParameters provider.version, algorithm
	if algorithm.indexOf('no-encryption') is -1
		dh = _createDiffieHellmanKeyExchange algorithm
		params['openid.dh_modulus'] = _toBase64 dh.getPrime 'binary'
		params['openid.dh_gen'] = _toBase64 dh.getGenerator 'binary'
		params['openid.dh_consumer_public'] = _toBase64 dh.getPublicKey 'binary'
	_post(provider.endpoint, params).then ([data, headers, statusCode]) ->
		statusCode = Number(statusCode)
		if statusCode isnt 200 and statusCode isnt 400 or not data?
			error = new Error "HTTP request failed"
			error.error = 'HTTP request failed'
			error.error_code = String(statusCode)
			error.ns = 'http://specs.openid.net/auth/2.0'
			throw error
		data = _decodePostData data
		if data.error_code is 'unsupported-type' or not data.ns?
			unacceptable = strict and provider.endpoint.toLowerCase().indexOf('https:') isnt 0
			switch algorithm
				when 'DH-SHA1'
					if unacceptable
						throw new Error 'Channel is insecure and no encryption method is supported by provider'
					else return openid.associate(provider, strict, 'no-encryption-256')
				when 'no-encryption-256'
					if unacceptable
						throw new Error 'Channel is insecure and no encryption method is supported by provider'
					# else if provider.version.indexOf("2.0") is -1
						# 2011-07-22: This is an OpenID 1.0/1.1 provider which means
						#  HMAC-SHA1 has already been attempted with a blank session
						#  type as per the OpenID 1.0/1.1 specification.
						#  (See http://openid.net/specs/openid-authentication-1_1.html#mode_associate)
						#  However, providers like wordpress.com don't follow the 
						#  standard and reject these requests, but accept OpenID 2.0
						#  style requests without a session type, so we have to give
						#  those a shot as well.
						# throw new Error 'Provider is OpenID 1.0/1.1 and does not support OpenID 1.0/1.1 association.'
					else return openid.associate(provider, strict, 'no-encryption')
				when 'DH-SHA256'
					return openid.associate(provider, strict, 'DH-SHA1')
		
		if not data.error
			hashAlgorithm = if algorithm.indexOf('256') isnt -1 then 'sha256' else 'sha1'
			if algorithm.indexOf('no-encryption') is -1
				serverPublic = _fromBase64(data.dh_server_public)
				sharedSecret = convert.btwoc(dh.computeSecret(serverPublic, 'binary', 'binary').toString())
				hash = crypto.createHash(hashAlgorithm)
				hash.update sharedSecret
				sharedSecret = hash.digest('binary')
				encMacKey = convert.base64.decode(data.enc_mac_key)
				secret = convert.base64.encode(_xor(encMacKey, sharedSecret))
			else secret = data.mac_key
			if not data.assoc_handle?
				throw new Error "OpenID provider does not seem to support association; you need to use stateless mode"
			openid.saveAssociation provider, hashAlgorithm, data.assoc_handle, secret, data.expires_in * 1
			.thenResolve data
		else throw new Error data.error

_generateAssociationRequestParameters = (version, algorithm) ->
	params = 'openid.mode': 'associate'
	if version.indexOf('2.0') isnt -1
		params['openid.ns'] = 'http://specs.openid.net/auth/2.0'
	switch algorithm
		when 'DH-SHA1'
			params['openid.assoc_type'] = 'HMAC-SHA1'
			params['openid.session_type'] = 'DH-SHA1'
		when 'no-encryption-256'
			if version.indexOf('2.0') is -1
				params['openid.session_type'] = ''
				# OpenID 1.0/1.1 requires blank
				params['openid.assoc_type'] = 'HMAC-SHA1'
			else
				params['openid.session_type'] = 'no-encryption'
				params['openid.assoc_type'] = 'HMAC-SHA256'
		when 'no-encryption'
			if version.indexOf('2.0') != -1
				params['openid.session_type'] = 'no-encryption'
			params['openid.assoc_type'] = 'HMAC-SHA1'
		else
			params['openid.assoc_type'] = 'HMAC-SHA256'
			params['openid.session_type'] = 'DH-SHA256'
	params

openid.authenticate = (identifier, returnUrl, realm, immediate, stateless, extensions, strict) ->
	i = 0
	openid.discover(identifier, strict)
	.then (providers) ->
		if not providers or providers.length is 0
			throw new Error 'No providers found for the given identifier'
		providers
	.then nextProvider = (providers) ->
		provider = providers[i++]
		throw "Finished" if not provider? and i > providers.length
		promise = if not stateless
				openid.associate(provider).then (answer) ->
					throw new answer?.error if not answer or answer.error
					_requestAuthentication provider, answer.assoc_handle, returnUrl, realm, immediate, extensions or {}
			else _requestAuthentication provider, null, returnUrl, realm, immediate, extensions or {}
		promise.then (authUrl) ->
			if authUrl then switch
				when provider.claimedIdentifier
					useLocalIdentifierAsKey = provider.version.indexOf("2.0") is -1 and provider.localIdentifier and provider.claimedIdentifier isnt provider.localIdentifier
					openid.saveDiscoveredInformation (if useLocalIdentifierAsKey then provider.localIdentifier else provider.claimedIdentifier), provider
					.thenResolve authUrl
				when provider.version.indexOf("2.0") isnt -1
					authUrl
				else throw "Next" # 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier'
			else throw "Next" # "No authUrl"
		.catch (error) -> switch error
			when "Finished"
				throw new Error 'No usable providers found for the given identifier'
			when "Next"
				nextProvider providers
			else throw error

_requestAuthentication = (provider, assoc_handle, returnUrl, realm, immediate, extensions) -> Q do ->
	params = 'openid.mode': if immediate then 'checkid_immediate' else 'checkid_setup'
	params['openid.ns'] = 'http://specs.openid.net/auth/2.0' if provider.version.indexOf('2.0') isnt -1
	for own i, extension of extensions
		params[key] = value for own key, value of extension.requestParams
	if provider.claimedIdentifier
		params['openid.claimed_id'] = provider.claimedIdentifier
		params['openid.identity'] = if provider.localIdentifier then provider.localIdentifier else provider.claimedIdentifier
	else if provider.version.indexOf('2.0') isnt -1
		params['openid.claimed_id'] = params['openid.identity'] = 'http://specs.openid.net/auth/2.0/identifier_select'
	else throw new Error 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier'
	params['openid.assoc_handle'] = assoc_handle if assoc_handle
	params['openid.return_to'] = returnUrl if returnUrl # Value should be missing if RP does not want user to be sent back
	if realm
		if provider.version.indexOf('2.0') isnt -1
			params['openid.realm'] = realm
		else params['openid.trust_root'] = realm
	else if not returnUrl then throw new Error 'No return URL or realm specified'
	_buildUrl provider.endpoint, params

openid.verifyAssertion = (theUrl, stateless, extensions = {}, strict) ->
	# MISSING: Support for Node.js Request(?)
	params = url.parse(theUrl, true).query
	_verifyAssertionData params, stateless, extensions, strict

_verifyAssertionData = (params, stateless, extensions, strict) -> Q do ->
	if assertionError = _getAssertionError params
		error = new Error assertionError
		error.authenticated = false
		throw error
	_invalidateAssociationHandleIfRequested params
	.catch -> throw new Error 'Unable to invalidate association handle'
	# TODO: Check nonce if OpenID 2.0
	.then -> _verifyDiscoveredInformation params, stateless, extensions, strict

_getAssertionError = (params) ->
	return "Assertion request is malformed" if not params?
	switch params['openid.mode']
		when "error" then params['openid.error']
		when "cancel" then 'Authentication cancelled'
		else null

_invalidateAssociationHandleIfRequested = (params) -> Q do ->
	if params['is_valid'] is 'true' and params['openid.invalidate_handle']?
		openid.removeAssociation(params['openid.invalidate_handle'])

_verifyDiscoveredInformation = (params, stateless, extensions, strict) -> Q do ->
	claimedIdentifier = params['openid.claimed_id']
	useLocalIdentifierAsKey = false
	if not claimedIdentifier?
		if not params['openid.ns']?
			# OpenID 1.0/1.1 response without a claimed identifier
			# We need to load discovered information using the
			# local identifier
			useLocalIdentifierAsKey = true
		else
			# OpenID 2.0+:
			# If there is no claimed identifier, then the
			# assertion is not about an identity
			return authenticated: false
	claimedIdentifier = params['openid.identity'] if useLocalIdentifierAsKey
	claimedIdentifier = _getCanonicalClaimedIdentifier claimedIdentifier
	openid.loadDiscoveredInformation claimedIdentifier
	.catch -> throw new Error 'An error occured when loading previously discovered information about the claimed identifier'
	.then (provider) ->
		if provider
			return _verifyAssertionAgainstProviders([provider], params, stateless, extensions)
		else if useLocalIdentifierAsKey
			throw new Error 'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.'
		openid.discover(claimedIdentifier, strict).then (providers) ->
			if !providers or !providers.length
				throw new Error 'No OpenID provider was discovered for the asserted claimed identifier'
			_verifyAssertionAgainstProviders providers, params, stateless, extensions

_verifyAssertionAgainstProviders = (providers, params, stateless, extensions) -> Q do ->
	for provider in providers
		continue if !!params['openid.ns'] and (not provider.version or provider.version.indexOf(params['openid.ns']) isnt 0)
		if !!provider.version and provider.version.indexOf('2.0') isnt -1
			endpoint = params['openid.op_endpoint']
			continue if provider.endpoint isnt endpoint
			if provider.claimedIdentifier
				claimedIdentifier = _getCanonicalClaimedIdentifier params['openid.claimed_id']
				if provider.claimedIdentifier isnt claimedIdentifier
					throw new Error 'Claimed identifier in assertion response does not match discovered claimed identifier'
		if !!provider.localIdentifier and provider.localIdentifier isnt params['openid.identity']
			throw new Error 'Identity in assertion response does not match discovered local identifier'
		return _checkSignature(params, provider, stateless).then (result) ->
			if extensions and result.authenticated
				for own ext, value of extensions
					instance = value
					instance.fillResult params, result
			return result
	throw new Error 'No valid providers were discovered for the asserted claimed identifier'

_checkSignature = (params, provider, stateless) -> Q do ->
	if not params['openid.signed']? or not params['openid.sig']?
		error = new Error 'No signature in response'
		error.authenticated = false
		throw error
	if stateless
		_checkSignatureUsingProvider params, provider
	else
		_checkSignatureUsingAssociation params

_checkSignatureUsingAssociation = (params) -> Q do ->
	if not params['openid.assoc_handle']?
		throw new Error 'No association handle in provider response. Find out whether the provider supports associations and/or use stateless mode.'
	openid.loadAssociation(params['openid.assoc_handle'])
	.catch ->
		error = new Error 'Error loading association'
		error.authenticated = false
		throw error
	.then (association) ->
		if !association
			error = new Error 'Invalid association handle'
			error.authenticated = false
			throw error
		if association.provider.version.indexOf('2.0') isnt -1 and association.provider.endpoint isnt params['openid.op_endpoint']
			error = new Error 'Association handle does not match provided endpoint'
			error.authenticated = false
			throw error
		message = ''
		signedParams = params['openid.signed'].split ','
		for param in signedParams
			value = params['openid.' + param]
			if not value?
				error = new Error 'At least one parameter referred in signature is not present in response'
				error.authenticated = false
				throw error
			message += param + ':' + value + '\n'
		hmac = crypto.createHmac(association.type, convert.base64.decode(association.secret))
		hmac.update message, 'utf8'
		ourSignature = hmac.digest('base64')
		if ourSignature is params['openid.sig']
			authenticated: true
			claimedIdentifier: if association.provider.version.indexOf('2.0') isnt -1 then params['openid.claimed_id'] else association.provider.claimedIdentifier
		else
				error = new Error 'Invalid signature'
				error.authenticated = false
				throw error

_checkSignatureUsingProvider = (params, provider) -> Q do ->
	requestParams = 'openid.mode': 'check_authentication'
	requestParams[key] = value for own key, value of params when key isnt 'openid.mode'
	_post (if params['openid.ns']? then params['openid.op_endpoint'] or provider.endpoint else provider.endpoint), requestParams
	.then ([data, headers, statusCode]) ->
		if Number(statusCode) isnt 200 or not data?
			error = new Error "Invalid assertion response from provider"
			error.authenticated = false
			throw error
		else
			data = _decodePostData data
			if String(!!data['is_valid']) is 'true'
				authenticated: true
				claimedIdentifier: if provider.version.indexOf('2.0') != -1 then params['openid.claimed_id'] else params['openid.identity']
			else
				error = new Error "Invalid signature"
				error.authenticated = false
				throw error

_getCanonicalClaimedIdentifier = (claimedIdentifier) ->
	return claimedIdentifier if not claimedIdentifier
	index = claimedIdentifier.indexOf '#'
	if index isnt -1
		return claimedIdentifier[...index]
	claimedIdentifier

### ==================================================================
# Extensions
# ==================================================================
###

_getExtensionAlias = (params, ns) ->
	for k, v of params
		if v is ns
			return k.replace('openid.ns.', '')

### 
# Simple Registration Extension
# http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
###

sreg_keys = ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone']

openid.SimpleRegistration = class SimpleRegistration
	constructor: (options) ->
		@requestParams = 'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1'
		if options.policy_url
			@requestParams['openid.sreg.policy_url'] = options.policy_url
		required = []
		optional = []
		for key in sreg_keys when options[key]
			(if options[key] is 'required' then required else optional).push key
		if required.length
			@requestParams['openid.sreg.required'] = required.join(',')
		if optional.length
			@requestParams['openid.sreg.optional'] = optional.join(',')
	
	fillResult: (params, result) ->
		extension = _getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') or 'sreg'
		for key in sreg_keys
			if params['openid.' + extension + '.' + key]
				result[key] = params['openid.' + extension + '.' + key]
		return

### 
# User Interface Extension
# http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html
###

openid.UserInterface = class UserInterface
	constructor: (options) ->
		if typeof options isnt 'object'
			options = mode: options or 'popup'
		@requestParams = 'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0'
		for k, v of options
			@requestParams['openid.ui.' + k] = v

	fillResult: (params, result) ->
		# TODO: Fill results
		return

### 
# Attribute Exchange Extension
# http://openid.net/specs/openid-attribute-exchange-1_0.html
# Also see:
#	 - http://www.axschema.org/types/
#	 - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
###

attributeMapping = 
	'http://axschema.org/contact/country/home': 'country'
	'http://axschema.org/contact/email': 'email'
	'http://axschema.org/namePerson/first': 'firstname'
	'http://axschema.org/pref/language': 'language'
	'http://axschema.org/namePerson/last': 'lastname'
	# The following are not in the Google document:
	'http://axschema.org/namePerson/friendly': 'nickname'
	'http://axschema.org/namePerson': 'fullname'

openid.AttributeExchange = class AttributeExchange
	constructor: (options) ->
		@requestParams =
			'openid.ns.ax': 'http://openid.net/srv/ax/1.0'
			'openid.ax.mode': 'fetch_request'
		required = []
		optional = []
		for own ns, value of options
			(if value is 'required' then required else optional).push ns
		required = for ns, i in required
			attr = attributeMapping[ns] or 'req' + i
			@requestParams['openid.ax.type.' + attr] = ns
			attr
		optional = for ns, i in optional
			attr = attributeMapping[ns] or 'opt' + i
			@requestParams['openid.ax.type.' + attr] = ns
			attr
		
		@requestParams['openid.ax.required'] = required.join(',') if required.length
		@requestParams['openid.ax.if_available'] = optional.join(',') if optional.length

	fillResult: (params, result) ->
		extension = _getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') or 'ax'
		regex = new RegExp('^openid\\.' + extension + '\\.(value|type|count)\\.(\\w+)(\\.(\\d+)){0,1}$')
		aliases = {}
		counters = {}
		values = {}
		for own k, value of params when (matches = k.match(regex)) then switch matches[1]
			when 'type'
				aliases[value] = matches[2]
			when 'count'
				# counter sanitization
				count = parseInt(value, 10)
				# values number limitation (potential attack by overflow ?)
				counters[matches[2]] = if count < AX_MAX_VALUES_COUNT then count else AX_MAX_VALUES_COUNT
			else
				if matches[3]
					# matches multi-value, aka "count" aliases
					# counter sanitization
					count = parseInt(matches[4], 10)
					# "in bounds" verification
					if count > 0 and count <= (counters[matches[2]] or AX_MAX_VALUES_COUNT)
						if not values[matches[2]]
							values[matches[2]] = []
						values[matches[2]][count - 1] = value
				else
					# matches single-value aliases
					values[matches[2]] = value
		for ns, value of aliases when value of values
			result[value] = values[value]
			result[ns] = values[value]
		return

openid.OAuthHybrid = class OAuthHybrid
	constructor: (options) ->
		@requestParams =
			'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0'
			'openid.oauth.consumer': options['consumerKey']
			'openid.oauth.scope': options['scope']
	
	fillResult: (params, result) ->
		extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/oauth/1.0') or 'oauth'
		token_attr = 'openid.' + extension + '.request_token'
		result['request_token'] = params[token_attr] if params[token_attr]?
		return

### 
# Provider Authentication Policy Extension (PAPE)
# http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
#
# Note that this extension does not validate that the provider is obeying the
# authentication request, it only allows the request to be made.
#
# TODO: verify requested 'max_auth_age' against response 'auth_time'
# TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'
# TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'
#
###

### Just the keys that aren't open to customisation ###

pape_request_keys = ['max_auth_age', 'preferred_auth_policies', 'preferred_auth_level_types']
pape_response_keys = ['auth_policies', 'auth_time']

### Some short-hand mappings for auth_policies ###

papePolicyNameMap = 
	'phishing-resistant': 'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant'
	'multi-factor': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor'
	'multi-factor-physical': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical'
	'none': 'http://schemas.openid.net/pape/policies/2007/06/none'

### you can express multiple pape 'preferred_auth_policies', so replace each
# with the full policy URI as per papePolicyNameMapping.
###

_getLongPolicyName = (policyNames) ->
	(for policy in policyNames.split(' ')
		if policy of papePolicyNameMap then papePolicyNameMap[policy] else policy
	).join ' '

_getShortPolicyName = (policyNames) ->
	for policy, i in policyNames.split(' ')
		for shortName, v of papePolicyNameMap
			policies[i] = shortName if value is v

openid.PAPE = class PAPE
	constructor: (options) ->
		@requestParams = 'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0'
		for k, v of options
			@requestParams['openid.pape.' + k] = if k is 'preferred_auth_policies'
					_getLongPolicyName(v)
				else v

	fillResult: (params, result) ->
		extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/pape/1.0') or 'pape'
		paramString = 'openid.' + extension + '.'
		for own p, v of params
			if p[...paramString.length] is paramString
				thisParam = p[paramString.length...]
				result[thisParam] = if thisParam is 'auth_policies'
						 _getShortPolicyName(v)
					else v
		return
