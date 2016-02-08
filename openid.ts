/* OpenID for node.js
 *
 * http://ox.no/software/node-openid
 * http://github.com/havard/node-openid
 *
 * Copyright (C) 2010 by Håvard Stranden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *
 * -*- Mode: JS; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * vim: set sw=2 ts=2 et tw=80 :
 */

import convert = require('./lib/convert')
import crypto = require('crypto-browserify')
import request = require('request')
import querystring = require('querystring-es3')
import url = require('url')
import xrds = require('./lib/xrds')
import http = require('http')

type EncryptionAlgorithms = "DH-SHA256" | "DH-SHA1" | "no-encryption-256" | "no-encryption"
type HashingAlgorithms = "sha256" | "sha1"
type StringDict = {[index: string]: string}
type RequestOrUrl = http.IncomingMessage|string

let _associations: {[index: string]: OpenIDProviderAssociation} = {}
let _discoveries: {[index: string]: OpenIDProvider} = {}
let _nonces: {[index: string]: Date} = {}

const AX_MAX_VALUES_COUNT = 1000

export let RelyingParty = class RelyingParty {
    returnUrl: string
    realm: string
    stateless: boolean
    strict: boolean
    extensions: OpenIDExtension[]
    
    constructor(returnUrl: string, realm: string, stateless: boolean, strict: boolean, extensions: OpenIDExtension[] = []) {
      this.returnUrl = returnUrl
      this.realm = realm || null
      this.stateless = stateless
      this.strict = strict
      this.extensions = extensions
    }
    
    authenticate(identifier: string, immediate: boolean, callback: (error?: {message: string}, result?: string) => void) {
      authenticate(identifier, this.returnUrl, this.realm, immediate, this.stateless, callback, this.extensions, this.strict)
    }
    
    verifyAssertion(requestOrUrl: RequestOrUrl, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
      verifyAssertion(requestOrUrl, this.returnUrl, callback, this.stateless, this.extensions, this.strict)
    }
}

let _toBase64 = (binary: string) => convert.base64.encode(convert.btwoc(binary))
let _fromBase64 = (str: string) => convert.unbtwoc(convert.base64.decode(str))

let _xor = function (a: string, b: string) {
  if (a.length !== b.length) {
    throw new Error('Length must match for xor')
  }
  let r = ''
  for (let i = 0; i < a.length; ++i) {
    r += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i))
  }
  return r
}

interface OpenIDProviderAssociation {
    provider: OpenIDProvider,
    type: HashingAlgorithms,
    secret: string
}

export let saveAssociation = function (provider: OpenIDProvider, type: HashingAlgorithms, handle: string, secret: string, expiry_time_in_seconds: number, callback: (err: void) => void) {
  setTimeout(function () {
    removeAssociation(handle)
  }, expiry_time_in_seconds * 1000)
  _associations[handle] = <OpenIDProviderAssociation>{provider: provider, type: type, secret: secret}
  callback(null) // Custom implementations may report error as first argument
}

export let loadAssociation = function (handle: string, callback: (err: void, res: OpenIDProviderAssociation) => void) {
  if (_associations[handle] != null) {
    let response = _associations[handle]
    callback(null, _associations[handle])
  } else {
    callback(null, null)
  }
}

export let removeAssociation = function (handle: string) {
  delete _associations[handle]
  return true
}

export let saveDiscoveredInformation = function (key: string, provider: OpenIDProvider, callback: (err: any) => void) {
  _discoveries[key] = provider
  return callback(null)
}

export let loadDiscoveredInformation = function (key: string, callback: (err: any, res: OpenIDProvider) => void) {
  if (_discoveries[key] == null) {
    return callback(null, null)
  }
  return callback(null, _discoveries[key])
}

let _buildUrl = function (urlStr: string, params: StringDict) {
  let theUrl = url.parse(urlStr, true)
  delete theUrl['search']
  if (params) {
    if (!theUrl.query) {
      theUrl.query = params
    } else {
      for (let key in params) {
        if (params.hasOwnProperty(key)) {
          theUrl.query[key] = params[key]
        }
      }
    }
  }
  return url.format(theUrl)
}

let _get = function (getUrl: string, params: StringDict, callback: (errOrBody: any, headers?: StringDict, statusCode?: number) => void, redirects: number = 5) {
  let options = {
    url: getUrl,
    maxRedirects: redirects,
    qs: params,
    headers: { 'Accept': 'application/xrds+xml,text/html,text/plain,*/*' }
  }
  request.get(options, <request.RequestCallback>function (error, response, body) {
    if (error) {
      callback(error)
    } else {
      callback(body, response.headers, response.statusCode)
    }
  })
}

let _post = function (postUrl: string, data: StringDict, callback: (errOrBody: any, headers?: StringDict, statusCode?: number) => void, redirects: number = 5) {
  let options = {
    url: postUrl,
    maxRedirects: redirects,
    form: data,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  }
  request.post(options, <request.RequestCallback>function (error, response, body) {
    if (error) {
      callback(error)
    } else {
      callback(body, response.headers, response.statusCode)
    }
  })
}

let _decodePostData = function (data: string) {
  let lines = data.split('\n')
  let result: {[index: string]:string} = {}
  for (let line of lines) {
    if (line.length > 0 && line[line.length - 1] === '\r') {
      line = line.substring(0, line.length - 1)
    }
    let colon = line.indexOf(':')
    if (colon === -1) {
      continue
    }
    let key = line.substr(0, colon)
    let value = line.substr(colon + 1)
    result[key] = value
  }
  return result
}

let _normalizeIdentifier = function (identifier: string) {
  identifier = identifier.replace(/^\s+|\s+$/g, '')
  if (!identifier) return null
  if (identifier.indexOf('xri://') === 0) {
    identifier = identifier.substring(6)
  }

  if (/^[(=@\+\$!]/.test(identifier)) {
    return identifier
  }

  if (identifier.indexOf('http') === 0) {
    return identifier
  }
  return 'http://' + identifier
}

interface OpenIDProvider {
    endpoint?: string,
    claimedIdentifier?: string,
    version?: string,
    localIdentifier?: string
}

let _parseXrds = function (xrdsUrl: string, xrdsData: string) {
  let services = xrds.parse(xrdsData)
  if (services == null) {
    return null
  }

  let providers: OpenIDProvider[] = []
  for (let service of services) {
    let provider: OpenIDProvider = {}

    provider.endpoint = service.uri
    if (/https?:\/\/xri./.test(xrdsUrl)) {
      provider.claimedIdentifier = service.id
    }
    if (service.type === 'http://specs.openid.net/auth/2.0/signon') {
      provider.version = 'http://specs.openid.net/auth/2.0'
      provider.localIdentifier = service.id
    } else if (service.type === 'http://specs.openid.net/auth/2.0/server') {
      provider.version = 'http://specs.openid.net/auth/2.0'
    } else if (service.type === 'http://openid.net/signon/1.0' ||
      service.type === 'http://openid.net/signon/1.1') {
      provider.version = service.type
      provider.localIdentifier = service.delegate
    } else {
      continue
    }
    providers.push(provider)
  }

  return providers
}

let _matchMetaTag = function (html: string) {
  let metaTagMatches = /<meta\s+.*?http-equiv="x-xrds-location"\s+(.*?)>/ig.exec(html)
  if (!metaTagMatches || metaTagMatches.length < 2) {
    return null
  }

  let contentMatches = /content="(.*?)"/ig.exec(metaTagMatches[1])
  if (!contentMatches || contentMatches.length < 2) {
    return null
  }

  return contentMatches[1]
}

let _matchLinkTag = function (html: string, rel: string) {
  let providerLinkMatches = new RegExp('<link\\s+.*?rel=["\'][^"\']*?' + rel + '[^"\']*?["\'].*?>', 'ig').exec(html)

  if (!providerLinkMatches || providerLinkMatches.length < 1) {
    return null
  }

  let href = /href=["'](.*?)["']/ig.exec(providerLinkMatches[0])

  if (!href || href.length < 2) {
    return null
  }
  return href[1]
}

let _parseHtml = function (htmlUrl: string, html: string, callback: (providers: OpenIDProvider[]) => void, hops?: number) {
  let metaUrl = _matchMetaTag(html)
  if (metaUrl != null) {
    return _resolveXri(metaUrl, callback, hops + 1)
  }

  let provider = _matchLinkTag(html, 'openid2.provider')
  if (provider == null) {
    provider = _matchLinkTag(html, 'openid.server')
    if (provider == null) {
      callback(null)
    } else {
      let localId = _matchLinkTag(html, 'openid.delegate')
      callback([{
        version: 'http://openid.net/signon/1.1',
        endpoint: provider,
        claimedIdentifier: htmlUrl,
        localIdentifier: localId
      }])
    }
  } else {
    let localId = _matchLinkTag(html, 'openid2.local_id')
    callback([{
      version: 'http://specs.openid.net/auth/2.0/signon',
      endpoint: provider,
      claimedIdentifier: htmlUrl,
      localIdentifier: localId
    }])
  }
}

let _parseHostMeta = function (hostMeta: string, callback: (providers: OpenIDProvider[]) => void) {
  let match = /^Link: <([^\n\r]+?)>;/.exec(hostMeta)
  if (match != null && match.length > 0) {
    let xriUrl = match[1]
    _resolveXri(xriUrl, callback)
  } else {
    callback(null)
  }
}

let _resolveXri = function (xriUrl: string, callback: (providers: OpenIDProvider[]) => void, hops?: number) {
  if (!hops) {
    hops = 1
  } else if (hops >= 5) {
    return callback(null)
  }

  _get(xriUrl, null, function (data: string, headers: {[index:string]:string}, statusCode: number) {
    if (statusCode !== 200) {
      return callback(null)
    }

    let xrdsLocation: string = headers['x-xrds-location']
    if (xrdsLocation != null) {
      _get(xrdsLocation, null, function (data: string, headers: {}, statusCode: number) {
        if (statusCode !== 200 || data == null) {
          callback(null)
        } else {
          callback(_parseXrds(xrdsLocation, data))
        }
      })
    } else if (data != null) {
      let contentType: string = headers['content-type']
      // text/xml is not compliant, but some hosting providers refuse header
      // changes, so text/xml is encountered
      if (contentType && (contentType.indexOf('application/xrds+xml') === 0 || contentType.indexOf('text/xml') === 0)) {
        return callback(_parseXrds(xriUrl, data))
      } else {
        return _resolveHtml(xriUrl, callback, hops + 1, data)
      }
    }
  })
}

let _resolveHtml = function (identifier: string, callback: (providers: OpenIDProvider[]) => void, hops?: number, data?: string) {
  if (!hops) {
    hops = 1
  } else if (hops >= 5) {
    return callback(null)
  }

  if (data == null) {
    _get(identifier, null, function (data: string, headers: {}, statusCode: number) {
      if (statusCode !== 200 || data == null) {
        callback(null)
      } else {
        _parseHtml(identifier, data, callback, hops + 1)
      }
    })
  } else {
    _parseHtml(identifier, data, callback, hops)
  }
}

let _resolveHostMeta = function (identifier: string, strict: boolean, callback: (providers: OpenIDProvider[]) => void, fallBackToProxy?: boolean) {
  let host = url.parse(identifier)
  let hostMetaUrl: string
  if (fallBackToProxy && !strict) {
    hostMetaUrl = 'https://www.google.com/accounts/o8/.well-known/host-meta?hd=' + host.host
  } else {
    hostMetaUrl = host.protocol + '//' + host.host + '/.well-known/host-meta'
  }
  if (!hostMetaUrl) {
    callback(null)
  } else {
    _get(hostMetaUrl, null, function (data: string, headers: {}, statusCode: number) {
      if (statusCode !== 200 || data == null) {
        if (!fallBackToProxy && !strict) {
          _resolveHostMeta(identifier, strict, callback, true)
        } else {
          callback(null)
        }
      } else {
        // Attempt to parse the data but if this fails it may be because
        // the response to hostMetaUrl was some other http/html resource.
        // Therefore fallback to the proxy if no providers are found.
        _parseHostMeta(data, function (providers) {
          if ((providers == null || providers.length === 0) && !fallBackToProxy && !strict) {
            _resolveHostMeta(identifier, strict, callback, true)
          } else {
            callback(providers)
          }
        })
      }
    })
  }
}

export let discover = function (identifier: string, strict: boolean, callback: (error?: {message: string}, providers?: OpenIDProvider[]) => void) {
  identifier = _normalizeIdentifier(identifier)
  if (!identifier) {
    return callback({message: 'Invalid identifier'}, null)
  }
  if (identifier.indexOf('http') !== 0) {
    // XRDS
    identifier = 'https://xri.net/' + identifier + '?_xrd_r=application/xrds%2Bxml'
  }

  // Try XRDS/Yadis discovery
  _resolveXri(identifier, function (providers) {
    if (providers == null || providers.length === 0) {
      // Fallback to HTML discovery
      _resolveHtml(identifier, function (providers) {
        if (providers == null || providers.length === 0) {
          _resolveHostMeta(identifier, strict, function (providers) {
            callback(null, providers)
          })
        } else {
          callback(null, providers)
        }
      })
    } else {
      // Add claimed identifier to providers with local identifiers
      // and OpenID 1.0/1.1 providers to ensure correct resolution
      // of identities and services
      for (let provider of providers) {
        if (!provider.claimedIdentifier &&
          (provider.localIdentifier || provider.version.indexOf('2.0') === -1)) {
          provider.claimedIdentifier = identifier
        }
      }
      callback(null, providers)
    }
  })
}

let _createDiffieHellmanKeyExchange = function (algorithm?: EncryptionAlgorithms) {
  let defaultPrime = 'ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr'
  let dh = crypto.createDiffieHellman(defaultPrime, 'base64')
  dh.generateKeys()
  return dh
}

export let associate = function (provider: OpenIDProvider, callback: (error?: any, result?: any) => void, strict?: boolean, algorithm: EncryptionAlgorithms = "DH-SHA256") {
  let params = _generateAssociationRequestParameters(provider.version, algorithm)
  let dh: crypto.DiffieHellman = null
  if (algorithm.indexOf('no-encryption') === -1) {
    dh = _createDiffieHellmanKeyExchange(algorithm)
    params['openid.dh_modulus'] = _toBase64(dh.getPrime('binary'))
    params['openid.dh_gen'] = _toBase64(dh.getGenerator('binary'))
    params['openid.dh_consumer_public'] = _toBase64(dh.getPublicKey('binary'))
  }

  _post(provider.endpoint, params, function (dataStr: string, headers: StringDict, statusCode: number) {
    if ((statusCode !== 200 && statusCode !== 400) || dataStr == null) {
      return callback({
        message: 'HTTP request failed'
      }, {
        error: 'HTTP request failed',
        error_code: '' + statusCode,
        ns: 'http://specs.openid.net/auth/2.0'
      })
    }

    let data = _decodePostData(dataStr)

    if (data["error_code"] === 'unsupported-type' || data["ns"] == null) {
      if (algorithm === 'DH-SHA1') {
        if (strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
          return callback({message: 'Channel is insecure and no encryption method is supported by provider'}, null)
        } else {
          return associate(provider, callback, strict, 'no-encryption-256')
        }
      } else if (algorithm === 'no-encryption-256') {
        if (strict && provider.endpoint.toLowerCase().indexOf('https:') !== 0) {
          return callback({message: 'Channel is insecure and no encryption method is supported by provider'}, null)
        /* } else if(provider.version.indexOf('2.0') === -1) {
          // 2011-07-22: This is an OpenID 1.0/1.1 provider which means
          // HMAC-SHA1 has already been attempted with a blank session
          // type as per the OpenID 1.0/1.1 specification.
          // (See http://openid.net/specs/openid-authentication-1_1.html#mode_associate)
          // However, providers like wordpress.com don't follow the
          // standard and reject these requests, but accept OpenID 2.0
          // style requests without a session type, so we have to give
          // those a shot as well.
          callback({ message: 'Provider is OpenID 1.0/1.1 and does not support OpenID 1.0/1.1 association.' }) */
        } else {
          return associate(provider, callback, strict, 'no-encryption')
        }
      } else if (algorithm === 'DH-SHA256') {
        return associate(provider, callback, strict, 'DH-SHA1')
      }
    }

    if (data["error"]) {
      callback({message: data["error"]}, data)
    } else {
      let secret: string = null
      let hashAlgorithm: HashingAlgorithms = algorithm.indexOf('256') !== -1 ? 'sha256' : 'sha1'

      if (algorithm.indexOf('no-encryption') !== -1) {
        secret = data["mac_key"]
      } else {
        let serverPublic = _fromBase64(data["dh_server_public"])
        let sharedSecret = convert.btwoc(dh.computeSecret(serverPublic, 'binary', 'binary'))
        let hash = crypto.createHash(hashAlgorithm)
        hash.update(sharedSecret)
        sharedSecret = hash.digest('binary')
        let encMacKey = convert.base64.decode(data["enc_mac_key"])
        secret = convert.base64.encode(_xor(encMacKey, sharedSecret))
      }

      if (data["assoc_handle"] == null) {
        return callback({message: 'OpenID provider does not seem to support association; you need to use stateless mode'}, null)
      }

      saveAssociation(provider, hashAlgorithm, data["assoc_handle"], secret, parseInt(data["expires_in"]) * 1, function (error) {
          if (error) {
            return callback(error)
          }
          callback(null, data)
        })
    }
  })
}

let _generateAssociationRequestParameters = function (version: string, algorithm: EncryptionAlgorithms) {
  let params: StringDict = {
    'openid.mode': 'associate'
  }

  if (version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0'
  }

  if (algorithm === 'DH-SHA1') {
    params['openid.assoc_type'] = 'HMAC-SHA1'
    params['openid.session_type'] = 'DH-SHA1'
  } else if (algorithm === 'no-encryption-256') {
    if (version.indexOf('2.0') === -1) {
      params['openid.session_type'] = '' // OpenID 1.0/1.1 requires blank
      params['openid.assoc_type'] = 'HMAC-SHA1'
    } else {
      params['openid.session_type'] = 'no-encryption'
      params['openid.assoc_type'] = 'HMAC-SHA256'
    }
  } else if (algorithm === 'no-encryption') {
    if (version.indexOf('2.0') !== -1) {
      params['openid.session_type'] = 'no-encryption'
    }
    params['openid.assoc_type'] = 'HMAC-SHA1'
  } else {
    params['openid.assoc_type'] = 'HMAC-SHA256'
    params['openid.session_type'] = 'DH-SHA256'
  }

  return params
}

export let authenticate = function (identifier: string, returnUrl: string, realm: string, immediate: boolean, stateless: boolean, callback: (error?: {message: string}, result?: string) => void, extensions: OpenIDExtension[], strict: boolean) {
  discover(identifier, strict, function (error, providers) {
    if (error) {
      return callback(error)
    }
    if (!providers || providers.length === 0) {
      return callback({ message: 'No providers found for the given identifier' }, null)
    }

    let providerIndex = -1;
    
    (function chooseProvider (error?: {message: string}, authUrl?: string) {
      if (!error && authUrl) {
        let provider = providers[providerIndex]

        if (provider.claimedIdentifier) {
          let useLocalIdentifierAsKey = provider.version.indexOf('2.0') === -1 && provider.localIdentifier && provider.claimedIdentifier !== provider.localIdentifier

          return saveDiscoveredInformation(useLocalIdentifierAsKey ? provider.localIdentifier : provider.claimedIdentifier,
            provider, function (error) {
              if (error) {
                return callback(error)
              }
              return callback(null, authUrl)
            })
        } else if (provider.version.indexOf('2.0') !== -1) {
          return callback(null, authUrl)
        } else {
          chooseProvider({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' })
        }
      }
      if (++providerIndex >= providers.length) {
        return callback({ message: 'No usable providers found for the given identifier' }, null)
      }

      let currentProvider = providers[providerIndex]
      if (stateless) {
        _requestAuthentication(currentProvider, null, returnUrl,
          realm, immediate, extensions || [], chooseProvider)
      } else {
        associate(currentProvider, function (error, answer) {
          if (error || !answer || answer.error) {
            chooseProvider(error || answer.error, null)
          } else {
            _requestAuthentication(currentProvider, answer.assoc_handle, returnUrl,
              realm, immediate, extensions || [], chooseProvider)
          }
        })
      }
    })()
  })
}

let _requestAuthentication = function (provider: OpenIDProvider, assoc_handle: string, returnUrl: string, realm: string, immediate: boolean, extensions: OpenIDExtension[], callback: (error?: {message: string}, result?: string) => void) {
  let params: StringDict = {
    'openid.mode': immediate ? 'checkid_immediate' : 'checkid_setup'
  }

  if (provider.version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0'
  }

  for (let i in extensions) {
    if (!extensions.hasOwnProperty(i)) continue

    let extension = extensions[i]
    for (let key in extension.requestParams) {
      if (!extension.requestParams.hasOwnProperty(key)) continue
      params[key] = extension.requestParams[key]
    }
  }

  if (provider.claimedIdentifier) {
    params['openid.claimed_id'] = provider.claimedIdentifier
    if (provider.localIdentifier) {
      params['openid.identity'] = provider.localIdentifier
    } else {
      params['openid.identity'] = provider.claimedIdentifier
    }
  } else if (provider.version.indexOf('2.0') !== -1) {
    params['openid.claimed_id'] = params['openid.identity'] =
      'http://specs.openid.net/auth/2.0/identifier_select'
  } else {
    return callback({ message: 'OpenID 1.0/1.1 provider cannot be used without a claimed identifier' })
  }

  if (assoc_handle) {
    params['openid.assoc_handle'] = assoc_handle
  }

  if (returnUrl) {
    // Value should be missing if RP does not want
    // user to be sent back
    params['openid.return_to'] = returnUrl
  }

  if (realm) {
    if (provider.version.indexOf('2.0') !== -1) {
      params['openid.realm'] = realm
    } else {
      params['openid.trust_root'] = realm
    }
  } else if (!returnUrl) {
    return callback({ message: 'No return URL or realm specified' })
  }

  callback(null, _buildUrl(provider.endpoint, params))
}

export let verifyAssertion = function (requestOrUrl: RequestOrUrl, originalReturnUrl: string, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void, stateless: boolean, extensions: OpenIDExtension[], strict: boolean) {
  extensions = extensions || []
  let assertionUrl: string;
  if (typeof requestOrUrl !== "string") {
    if (requestOrUrl.method === 'POST') {
      if ((<string>requestOrUrl.headers['content-type'] || '').toLowerCase().indexOf('application/x-www-form-urlencoded') === 0) {
        // POST response received
        let data = ''

        requestOrUrl.on('data', function (chunk?: string) {
          data += chunk
        })

        requestOrUrl.on('end', function () {
          let params = <StringDict>querystring.parse(data)
          return _verifyAssertionData(params, callback, stateless, extensions, strict)
        })
      } else {
        return callback({ message: 'Invalid POST response from OpenID provider' })
      }

      return // Avoid falling through to GET method assertion
    } else if (requestOrUrl.method !== 'GET') {
      return callback({ message: 'Invalid request method from OpenID provider' })
    }
    assertionUrl = requestOrUrl.url
  } else {
    assertionUrl = requestOrUrl
  }

  let parsedUrl = url.parse(assertionUrl, true)
  let params = <StringDict>parsedUrl.query

  if (!_verifyReturnUrl(parsedUrl, originalReturnUrl)) {
    return callback({ message: 'Invalid return URL' })
  }
  return _verifyAssertionData(params, callback, stateless, extensions, strict)
}

let _verifyReturnUrl = function (assertionUrl: url.Url, originalReturnUrlNotParsed: string) {
  let receivedReturnUrlNotParsed: string = assertionUrl.query['openid.return_to']
  if (receivedReturnUrlNotParsed == null) {
    return false
  }

  let receivedReturnUrl = url.parse(receivedReturnUrlNotParsed, true)
  if (!receivedReturnUrl) {
    return false
  }
  let originalReturnUrl = url.parse(originalReturnUrlNotParsed, true)
  if (!originalReturnUrl) {
    return false
  }

  if (originalReturnUrl.protocol !== receivedReturnUrl.protocol || // Verify scheme against original return URL
    originalReturnUrl.host !== receivedReturnUrl.host || // Verify authority against original return URL
    assertionUrl.pathname !== receivedReturnUrl.pathname) { // Verify path against current request URL
    return false
  }

  // Any query parameters that are present in the "openid.return_to" URL MUST also be present
  // with the same values in the URL of the HTTP request the RP received
  for (let param in <StringDict>receivedReturnUrl.query) {
    if (receivedReturnUrl.query.hasOwnProperty(param) && receivedReturnUrl.query[param] !== assertionUrl.query[param]) {
      return false
    }
  }

  return true
}

let _verifyAssertionData = function (params: StringDict, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void, stateless: boolean, extensions: OpenIDExtension[], strict: boolean) {
  let assertionError = _getAssertionError(params)
  if (assertionError) {
    return callback({ message: assertionError }, { authenticated: false })
  }

  if (!_invalidateAssociationHandleIfRequested(params)) {
    return callback({message: 'Unable to invalidate association handle'})
  }

  if (!_checkNonce(params)) {
    return callback({ message: 'Invalid or replayed nonce' })
  }

  _verifyDiscoveredInformation(params, stateless, extensions, strict, callback)
}

let _getAssertionError = function (params: StringDict) {
  if (params == null) {
    return 'Assertion request is malformed'
  } else if (params['openid.mode'] === 'error') {
    return params['openid.error']
  } else if (params['openid.mode'] === 'cancel') {
    return 'Authentication cancelled'
  }

  return null
}

let _invalidateAssociationHandleIfRequested = function (params: StringDict) {
  if (params['is_valid'] === 'true' && params['openid.invalidate_handle'] != null) {
    if (!removeAssociation(params['openid.invalidate_handle'])) {
      return false
    }
  }

  return true
}

let _checkNonce = function (params: StringDict) {
  if (params['openid.ns'] == null) {
    return true // OpenID 1.1 has no nonce
  }
  if (params['openid.response_nonce'] == null) {
    return false
  }

  let nonce = params['openid.response_nonce']
  let timestampEnd = nonce.indexOf('Z')
  if (timestampEnd === -1) {
    return false
  }

  // Check for valid timestamp in nonce
  let timestamp = new Date(Date.parse(nonce.substring(0, timestampEnd + 1)))
  if (Object.prototype.toString.call(timestamp) !== '[object Date]' || isNaN(<any>timestamp)) {
    return false
  }

  // Remove old nonces from our store (nonces that are more skewed than 5 minutes)
  _removeOldNonces()

  // Check if nonce is skewed by more than 5 minutes
  if (Math.abs(new Date().getTime() - timestamp.getTime()) > 300000) {
    return false
  }

  // Check if nonce is replayed
  if (_nonces[nonce] != null) {
    return false
  }

  // Store the nonce
  _nonces[nonce] = timestamp
  return true
}

let _removeOldNonces = function () {
  for (let nonce in _nonces) {
    if (_nonces.hasOwnProperty(nonce) && Math.abs(new Date().getTime() - _nonces[nonce].getTime()) > 300000) {
      delete _nonces[nonce]
    }
  }
}

let _verifyDiscoveredInformation = function (params: StringDict, stateless: boolean, extensions: OpenIDExtension[], strict: boolean, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
  let claimedIdentifier = params['openid.claimed_id']
  let useLocalIdentifierAsKey = false
  if (claimedIdentifier == null) {
    if (params['openid.ns'] == null) {
      // OpenID 1.0/1.1 response without a claimed identifier
      // We need to load discovered information using the
      // local identifier
      useLocalIdentifierAsKey = true
    } else {
      // OpenID 2.0+:
      // If there is no claimed identifier, then the
      // assertion is not about an identity
      return callback(null, { authenticated: false })
    }
  }

  if (useLocalIdentifierAsKey) {
    claimedIdentifier = params['openid.identity']
  }

  claimedIdentifier = _getCanonicalClaimedIdentifier(claimedIdentifier)
  loadDiscoveredInformation(claimedIdentifier, function (error, provider) {
    if (error) {
      return callback({message: 'An error occured when loading previously discovered information about the claimed identifier'})
    }

    if (provider) {
      return _verifyAssertionAgainstProviders([provider], params, stateless, extensions, callback)
    } else if (useLocalIdentifierAsKey) {
      return callback({message: 'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.'})
    }

    discover(claimedIdentifier, strict, function (error, providers) {
      if (error) {
        return callback(error)
      }
      if (!providers || !providers.length) {
        return callback({message: 'No OpenID provider was discovered for the asserted claimed identifier'})
      }

      _verifyAssertionAgainstProviders(providers, params, stateless, extensions, callback)
    })
  })
}

let _verifyAssertionAgainstProviders = function (providers: OpenIDProvider[], params: StringDict, stateless: boolean, extensions: OpenIDExtension[], callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
  for (let provider of providers) {
    if (!!params['openid.ns'] && (!provider.version || provider.version.indexOf(params['openid.ns']) !== 0)) continue

    if (!!provider.version && provider.version.indexOf('2.0') !== -1) {
      let endpoint = params['openid.op_endpoint']
      if (provider.endpoint !== endpoint) continue
      if (provider.claimedIdentifier) {
        let claimedIdentifier = _getCanonicalClaimedIdentifier(params['openid.claimed_id'])
        if (provider.claimedIdentifier !== claimedIdentifier) {
          return callback({message: 'Claimed identifier in assertion response does not match discovered claimed identifier'})
        }
      }
    }

    if (!!provider.localIdentifier && provider.localIdentifier !== params['openid.identity']) {
      return callback({message: 'Identity in assertion response does not match discovered local identifier'})
    }

    return _checkSignature(params, provider, stateless, function (error, result) {
      if (error) {
        return callback(error)
      }
      if (extensions && result.authenticated) {
        for (let ext of extensions) {
          ext.fillResult(params, result)
        }
      }

      return callback(null, result)
    })
  }

  callback({ message: 'No valid providers were discovered for the asserted claimed identifier' })
}

let _checkSignature = function (params: StringDict, provider: OpenIDProvider, stateless: boolean, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
  if (params['openid.signed'] == null ||
    params['openid.sig'] == null) {
    return callback({ message: 'No signature in response' }, { authenticated: false })
  }

  if (stateless) {
    _checkSignatureUsingProvider(params, provider, callback)
  } else {
    _checkSignatureUsingAssociation(params, callback)
  }
}

let _checkSignatureUsingAssociation = function (params: StringDict, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
  if (params['openid.assoc_handle'] == null) {
    return callback({message: 'No association handle in provider response. Find out whether the provider supports associations and/or use stateless mode.'})
  }
  loadAssociation(params['openid.assoc_handle'], function (error, association) {
    if (error) {
      return callback({message: 'Error loading association'}, {authenticated: false})
    }
    if (!association) {
      return callback({message: 'Invalid association handle'}, {authenticated: false})
    }
    if (association.provider.version.indexOf('2.0') !== -1 && association.provider.endpoint !== params['openid.op_endpoint']) {
      return callback({message: 'Association handle does not match provided endpoint'}, {authenticated: false})
    }

    let message = ''
    let signedParams = params['openid.signed'].split(',')
    for (let param of signedParams) {
      let value = params['openid.' + param]
      if (value == null) {
        return callback({message: 'At least one parameter referred in signature is not present in response'}, {authenticated: false})
      }
      message += param + ':' + value + '\n'
    }

    let hmac = crypto.createHmac(association.type, convert.base64.decode(association.secret))
    hmac.update(message, 'utf8')
    let ourSignature: string = hmac.digest('base64')

    if (ourSignature === params['openid.sig']) {
      callback(null, {authenticated: true, claimedIdentifier: association.provider.version.indexOf('2.0') !== -1 ? params['openid.claimed_id'] : association.provider.claimedIdentifier})
    } else {
      callback({message: 'Invalid signature'}, {authenticated: false})
    }
  })
}

let _checkSignatureUsingProvider = function (params: StringDict, provider: OpenIDProvider, callback: (error?: {message: string}, result?: {authenticated: boolean, claimedIdentifier?: string}) => void) {
  let requestParams: StringDict = {
    'openid.mode': 'check_authentication'
  }
  for (let key in params) {
    if (params.hasOwnProperty(key) && key !== 'openid.mode') {
      requestParams[key] = params[key]
    }
  }

  _post(params['openid.ns'] != null ? (params['openid.op_endpoint'] || provider.endpoint) : provider.endpoint, requestParams, function (dataStr, headers, statusCode) {
    if (statusCode !== 200 || dataStr == null) {
      return callback({ message: 'Invalid assertion response from provider' }, { authenticated: false })
    } else {
      let data = _decodePostData(<string>dataStr)
      if (data['is_valid'] === 'true') {
        return callback(null, {
          authenticated: true,
          claimedIdentifier: provider.version.indexOf('2.0') !== -1 ? params['openid.claimed_id'] : params['openid.identity']
        })
      } else {
        return callback({message: 'Invalid signature'}, {authenticated: false})
      }
    }
  })
}

let _getCanonicalClaimedIdentifier = function (claimedIdentifier: string) {
  if (!claimedIdentifier) {
    return claimedIdentifier
  }

  let index = claimedIdentifier.indexOf('#')
  if (index !== -1) {
    return claimedIdentifier.substring(0, index)
  }

  return claimedIdentifier
}

/* ==================================================================
 * Extensions
 * ==================================================================
 */

interface OpenIDExtension {
    fillResult(params: any, result: any): void
    requestParams: StringDict
}

let _getExtensionAlias = function (params: StringDict, ns: String) {
  for (let k in params)
    if (params[k] === ns) return k.replace('openid.ns.', '')
  return
}

/*
 * Simple Registration Extension
 * http://openid.net/specs/openid-simple-registration-extension-1_1-01.html
 */

let sreg_keys = ['nickname', 'email', 'fullname', 'dob', 'gender', 'postcode', 'country', 'language', 'timezone']

export class SimpleRegistration implements OpenIDExtension {
  requestParams: StringDict
  
  constructor(options: {[index: string]: any}) {
    this.requestParams = {'openid.ns.sreg': 'http://openid.net/extensions/sreg/1.1'}
    if (options["policy_url"]) this.requestParams['openid.sreg.policy_url'] = options["policy_url"]
    let required: string[] = []
    let optional: string[] = []
    for (let key of sreg_keys) {
      if (options[key]) {
        if (options[key] === 'required') {
          required.push(key)
        } else {
          optional.push(key)
        }
      }
     if (required.length) {
       this.requestParams['openid.sreg.required'] = required.join(',')
     }
     if (optional.length) {
       this.requestParams['openid.sreg.optional'] = optional.join(',')
     }
    }
  }
  
  fillResult(params: StringDict, result: StringDict) {
    let extension = _getExtensionAlias(params, 'http://openid.net/extensions/sreg/1.1') || 'sreg'
    for (let key of sreg_keys) {
      if (params['openid.' + extension + '.' + key]) {
        result[key] = params['openid.' + extension + '.' + key]
      }
    }
  }
}

/*
 * User Interface Extension
 * http://svn.openid.net/repos/specifications/user_interface/1.0/trunk/openid-user-interface-extension-1_0.html
 */
export class UserInterface implements OpenIDExtension {
  requestParams: StringDict
  
  constructor(options: {[index: string]: any}) {
    if (typeof options !== 'object') {
      options = {mode: options || 'popup'}
    }

    this.requestParams = {'openid.ns.ui': 'http://specs.openid.net/extensions/ui/1.0'}
    for (let k in options) {
      this.requestParams['openid.ui.' + k] = options[k]
    }
  }
  
  fillResult(params: StringDict, result: StringDict) {
    // TODO: Fill results
  }
}

/*
 * Attribute Exchange Extension
 * http://openid.net/specs/openid-attribute-exchange-1_0.html
 * Also see:
 *  - http://www.axschema.org/types/
 *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
 */

let attributeMapping: StringDict = {
  'http://axschema.org/contact/country/home': 'country',
  'http://axschema.org/contact/email': 'email',
  'http://axschema.org/namePerson/first': 'firstname',
  'http://axschema.org/pref/language': 'language',
  'http://axschema.org/namePerson/last': 'lastname',
  // The following are not in the Google document:
  'http://axschema.org/namePerson/friendly': 'nickname',
  'http://axschema.org/namePerson': 'fullname'
}

export class AttributeExchange implements OpenIDExtension {
  requestParams: StringDict
  
  constructor(options: {[index: string]: any}) {
    this.requestParams = {'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
    'openid.ax.mode': 'fetch_request'}
    let required: string[] = []
    let optional: string[] = []
    for (let ns in options) {
      if (!options.hasOwnProperty(ns)) continue
      if (options[ns] === 'required') {
        required.push(ns)
      } else {
        optional.push(ns)
      }
    }
    required = required.map((ns, i) => {
      let attr = attributeMapping[ns] || 'req' + i
      this.requestParams['openid.ax.type.' + attr] = ns
      return attr
    })
    optional = optional.map((ns, i) => {
      let attr = attributeMapping[ns] || 'opt' + i
      this.requestParams['openid.ax.type.' + attr] = ns
      return attr
    })
    if (required.length) {
      this.requestParams['openid.ax.required'] = required.join(',')
    }
    if (optional.length) {
      this.requestParams['openid.ax.if_available'] = optional.join(',')
    }
  }
  
  fillResult(params: StringDict, result: StringDict) {
    let extension = _getExtensionAlias(params, 'http://openid.net/srv/ax/1.0') || 'ax'
    let regex = new RegExp('^openid\\.' + extension + '\\.(value|type|count)\\.(\\w+)(\\.(\\d+)){0,1}$')
    let aliases: StringDict = {}
    let counters: {[index: string]: number} = {}
    let values: {[index: string]: string[] | string} = {}
    for (let k in params) {
      if (!params.hasOwnProperty(k)) continue
      let matches = k.match(regex)
      if (!matches) continue
      if (matches[1] === 'type') {
        aliases[params[k]] = matches[2]
      } else if (matches[1] === 'count') {
        // counter sanitization
        let count = parseInt(params[k], 10)

        // values number limitation (potential attack by overflow ?)
        counters[matches[2]] = (count < AX_MAX_VALUES_COUNT) ? count : AX_MAX_VALUES_COUNT
      } else {
        if (matches[3]) {
          // matches multi-value, aka "count" aliases

          // counter sanitization
          let count = parseInt(matches[4], 10)

          // "in bounds" verification
          if (count > 0 && count <= (counters[matches[2]] || AX_MAX_VALUES_COUNT)) {
            if (!values[matches[2]]) {
              values[matches[2]] = []
            }
            values[matches[2]][count - 1] = params[k]
          }
        } else {
          // matches single-value aliases
          values[matches[2]] = params[k]
        }
      }
    }
    for (let ns in aliases) {
      if (aliases[ns] in values) {
        result[aliases[ns]] = <string>values[aliases[ns]]
        result[ns] = <string>values[aliases[ns]]
      }
    }
  }
}

export class OAuthHybrid implements OpenIDExtension {
  requestParams: StringDict
  
  constructor(options: StringDict) {
    this.requestParams = {
      'openid.ns.oauth': 'http://specs.openid.net/extensions/oauth/1.0',
      'openid.oauth.consumer': options['consumerKey'],
      'openid.oauth.scope': options['scope']
    }
  }
  
  fillResult(params: StringDict, result: StringDict) {
    let extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/oauth/1.0') || 'oauth'
    let token_attr = 'openid.' + extension + '.request_token'

    if (params[token_attr] !== undefined) {
      result['request_token'] = params[token_attr]
    }
  }
}

/*
 * Provider Authentication Policy Extension (PAPE)
 * http://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html
 *
 * Note that this extension does not validate that the provider is obeying the
 * authentication request, it only allows the request to be made.
 *
 * TODO: verify requested 'max_auth_age' against response 'auth_time'
 * TODO: verify requested 'auth_level.ns.<cust>' (etc) against response 'auth_level.ns.<cust>'
 * TODO: verify requested 'preferred_auth_policies' against response 'auth_policies'
 *
 */

/* Just the keys that aren't open to customisation */
// let pape_request_keys = ['max_auth_age', 'preferred_auth_policies', 'preferred_auth_level_types']
// let pape_response_keys = ['auth_policies', 'auth_time']

/* Some short-hand mappings for auth_policies */
let papePolicyNameMap: StringDict = {
  'phishing-resistant': 'http://schemas.openid.net/pape/policies/2007/06/phishing-resistant',
  'multi-factor': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
  'multi-factor-physical': 'http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical',
  'none': 'http://schemas.openid.net/pape/policies/2007/06/none'
}

/* you can express multiple pape 'preferred_auth_policies', so replace each
 * with the full policy URI as per papePolicyNameMapping.
 */
let _getLongPolicyName = function (policyNames: string) {
  let policies = policyNames.split(' ')
  for (let i in policies) {
    if (policies[i] in papePolicyNameMap) {
      policies[i] = papePolicyNameMap[policies[i]]
    }
  }
  return policies.join(' ')
}

let _getShortPolicyName = function (policyNames: string) {
  let policies = policyNames.split(' ')
  for (let i in policies) {
    for (let shortName in papePolicyNameMap) {
      if (papePolicyNameMap[shortName] === policies[i]) {
        policies[i] = shortName
      }
    }
  }
  return policies.join(' ')
}

export class PAPE implements OpenIDExtension {
  requestParams: StringDict
  
  constructor(options: StringDict) {
    this.requestParams = {'openid.ns.pape': 'http://specs.openid.net/extensions/pape/1.0'}
    for (let k in options) {
      if (k === 'preferred_auth_policies') {
        this.requestParams['openid.pape.' + k] = _getLongPolicyName(options[k])
      } else {
        this.requestParams['openid.pape.' + k] = options[k]
      }
    }
  }
  
  fillResult(params: StringDict, result: StringDict) {
    let extension = _getExtensionAlias(params, 'http://specs.openid.net/extensions/pape/1.0') || 'pape'
    let paramString = 'openid.' + extension + '.'
    let thisParam: string
    for (let p in params) {
      if (params.hasOwnProperty(p)) {
        if (p.substr(0, paramString.length) === paramString) {
          thisParam = p.substr(paramString.length)
          if (thisParam === 'auth_policies') {
            result[thisParam] = _getShortPolicyName(params[p])
          } else {
            result[thisParam] = params[p]
          }
        }
      }
    }
  }
}
