(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var punycode = require('punycode');

exports.parse = urlParse;
exports.resolve = urlResolve;
exports.resolveObject = urlResolveObject;
exports.format = urlFormat;

exports.Url = Url;

function Url() {
  this.protocol = null;
  this.slashes = null;
  this.auth = null;
  this.host = null;
  this.port = null;
  this.hostname = null;
  this.hash = null;
  this.search = null;
  this.query = null;
  this.pathname = null;
  this.path = null;
  this.href = null;
}

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
    delims = ['<', '>', '"', '`', ' ', '\r', '\n', '\t'],

    // RFC 2396: characters not allowed for various reasons.
    unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
    autoEscape = ['\''].concat(unwise),
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
    nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([a-z0-9A-Z_-]{0,63})(.*)$/,
    // protocols that can allow "unsafe" and "unwise" chars.
    unsafeProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that never have a hostname.
    hostlessProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that always contain a // bit.
    slashedProtocol = {
      'http': true,
      'https': true,
      'ftp': true,
      'gopher': true,
      'file': true,
      'http:': true,
      'https:': true,
      'ftp:': true,
      'gopher:': true,
      'file:': true
    },
    querystring = require('querystring');

function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && isObject(url) && url instanceof Url) return url;

  var u = new Url;
  u.parse(url, parseQueryString, slashesDenoteHost);
  return u;
}

Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
  if (!isString(url)) {
    throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
  }

  var rest = url;

  // trim before proceeding.
  // This is to support parse stuff like "  http://foo.com  \n"
  rest = rest.trim();

  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === '//';
    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      this.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    //
    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the last @ sign, unless some host-ending character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    //
    // ex:
    // http://a@b@c/ => user:a@b host:c
    // http://a@b?@c => user:a host:c path:/?@c

    // v0.12 TODO(isaacs): This is not quite how Chrome does things.
    // Review our test case against browsers more comprehensively.

    // find the first instance of any hostEndingChars
    var hostEnd = -1;
    for (var i = 0; i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }

    // at this point, either we have an explicit point where the
    // auth portion cannot go past, or the last @ char is the decider.
    var auth, atSign;
    if (hostEnd === -1) {
      // atSign can be anywhere.
      atSign = rest.lastIndexOf('@');
    } else {
      // atSign must be in auth portion.
      // http://a@b/c@d => host:b auth:a path:/c@d
      atSign = rest.lastIndexOf('@', hostEnd);
    }

    // Now we have a portion which is definitely the auth.
    // Pull that off.
    if (atSign !== -1) {
      auth = rest.slice(0, atSign);
      rest = rest.slice(atSign + 1);
      this.auth = decodeURIComponent(auth);
    }

    // the host is the remaining to the left of the first non-host char
    hostEnd = -1;
    for (var i = 0; i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    // if we still have not hit it, then the entire thing is a host.
    if (hostEnd === -1)
      hostEnd = rest.length;

    this.host = rest.slice(0, hostEnd);
    rest = rest.slice(hostEnd);

    // pull out port.
    this.parseHost();

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    this.hostname = this.hostname || '';

    // if hostname begins with [ and ends with ]
    // assume that it's an IPv6 address.
    var ipv6Hostname = this.hostname[0] === '[' &&
        this.hostname[this.hostname.length - 1] === ']';

    // validate a little.
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length; i < l; i++) {
        var part = hostparts[i];
        if (!part) continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = '';
          for (var j = 0, k = part.length; j < k; j++) {
            if (part.charCodeAt(j) > 127) {
              // we replace non-ASCII char with a temporary placeholder
              // we need this to make sure size of hostname is not
              // broken by replacing non-ASCII by nothing
              newpart += 'x';
            } else {
              newpart += part[j];
            }
          }
          // we test again with ASCII char only
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i);
            var notHost = hostparts.slice(i + 1);
            var bit = part.match(hostnamePartStart);
            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }
            if (notHost.length) {
              rest = '/' + notHost.join('.') + rest;
            }
            this.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    if (this.hostname.length > hostnameMaxLen) {
      this.hostname = '';
    } else {
      // hostnames are always lower case.
      this.hostname = this.hostname.toLowerCase();
    }

    if (!ipv6Hostname) {
      // IDNA Support: Returns a puny coded representation of "domain".
      // It only converts the part of the domain name that
      // has non ASCII characters. I.e. it dosent matter if
      // you call it with a domain that already is in ASCII.
      var domainArray = this.hostname.split('.');
      var newOut = [];
      for (var i = 0; i < domainArray.length; ++i) {
        var s = domainArray[i];
        newOut.push(s.match(/[^A-Za-z0-9_-]/) ?
            'xn--' + punycode.encode(s) : s);
      }
      this.hostname = newOut.join('.');
    }

    var p = this.port ? ':' + this.port : '';
    var h = this.hostname || '';
    this.host = h + p;
    this.href += this.host;

    // strip [ and ] from the hostname
    // the host field still retains them, though
    if (ipv6Hostname) {
      this.hostname = this.hostname.substr(1, this.hostname.length - 2);
      if (rest[0] !== '/') {
        rest = '/' + rest;
      }
    }
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {

    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (var i = 0, l = autoEscape.length; i < l; i++) {
      var ae = autoEscape[i];
      var esc = encodeURIComponent(ae);
      if (esc === ae) {
        esc = escape(ae);
      }
      rest = rest.split(ae).join(esc);
    }
  }


  // chop off from the tail first.
  var hash = rest.indexOf('#');
  if (hash !== -1) {
    // got a fragment string.
    this.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }
  var qm = rest.indexOf('?');
  if (qm !== -1) {
    this.search = rest.substr(qm);
    this.query = rest.substr(qm + 1);
    if (parseQueryString) {
      this.query = querystring.parse(this.query);
    }
    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    this.search = '';
    this.query = {};
  }
  if (rest) this.pathname = rest;
  if (slashedProtocol[lowerProto] &&
      this.hostname && !this.pathname) {
    this.pathname = '/';
  }

  //to support http.request
  if (this.pathname || this.search) {
    var p = this.pathname || '';
    var s = this.search || '';
    this.path = p + s;
  }

  // finally, reconstruct the href based on what has been validated.
  this.href = this.format();
  return this;
};

// format a parsed object into a url string
function urlFormat(obj) {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (isString(obj)) obj = urlParse(obj);
  if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
  return obj.format();
}

Url.prototype.format = function() {
  var auth = this.auth || '';
  if (auth) {
    auth = encodeURIComponent(auth);
    auth = auth.replace(/%3A/i, ':');
    auth += '@';
  }

  var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

  if (this.host) {
    host = auth + this.host;
  } else if (this.hostname) {
    host = auth + (this.hostname.indexOf(':') === -1 ?
        this.hostname :
        '[' + this.hostname + ']');
    if (this.port) {
      host += ':' + this.port;
    }
  }

  if (this.query &&
      isObject(this.query) &&
      Object.keys(this.query).length) {
    query = querystring.stringify(this.query);
  }

  var search = this.search || (query && ('?' + query)) || '';

  if (protocol && protocol.substr(-1) !== ':') protocol += ':';

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (this.slashes ||
      (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = '//' + (host || '');
    if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
  if (search && search.charAt(0) !== '?') search = '?' + search;

  pathname = pathname.replace(/[?#]/g, function(match) {
    return encodeURIComponent(match);
  });
  search = search.replace('#', '%23');

  return protocol + host + pathname + search + hash;
};

function urlResolve(source, relative) {
  return urlParse(source, false, true).resolve(relative);
}

Url.prototype.resolve = function(relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};

function urlResolveObject(source, relative) {
  if (!source) return relative;
  return urlParse(source, false, true).resolveObject(relative);
}

Url.prototype.resolveObject = function(relative) {
  if (isString(relative)) {
    var rel = new Url();
    rel.parse(relative, false, true);
    relative = rel;
  }

  var result = new Url();
  Object.keys(this).forEach(function(k) {
    result[k] = this[k];
  }, this);

  // hash is always overridden, no matter what.
  // even href="" will remove it.
  result.hash = relative.hash;

  // if the relative url is empty, then there's nothing left to do here.
  if (relative.href === '') {
    result.href = result.format();
    return result;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    // take everything except the protocol from relative
    Object.keys(relative).forEach(function(k) {
      if (k !== 'protocol')
        result[k] = relative[k];
    });

    //urlParse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[result.protocol] &&
        result.hostname && !result.pathname) {
      result.path = result.pathname = '/';
    }

    result.href = result.format();
    return result;
  }

  if (relative.protocol && relative.protocol !== result.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      Object.keys(relative).forEach(function(k) {
        result[k] = relative[k];
      });
      result.href = result.format();
      return result;
    }

    result.protocol = relative.protocol;
    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || '').split('/');
      while (relPath.length && !(relative.host = relPath.shift()));
      if (!relative.host) relative.host = '';
      if (!relative.hostname) relative.hostname = '';
      if (relPath[0] !== '') relPath.unshift('');
      if (relPath.length < 2) relPath.unshift('');
      result.pathname = relPath.join('/');
    } else {
      result.pathname = relative.pathname;
    }
    result.search = relative.search;
    result.query = relative.query;
    result.host = relative.host || '';
    result.auth = relative.auth;
    result.hostname = relative.hostname || relative.host;
    result.port = relative.port;
    // to support http.request
    if (result.pathname || result.search) {
      var p = result.pathname || '';
      var s = result.search || '';
      result.path = p + s;
    }
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  }

  var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
      isRelAbs = (
          relative.host ||
          relative.pathname && relative.pathname.charAt(0) === '/'
      ),
      mustEndAbs = (isRelAbs || isSourceAbs ||
                    (result.host && relative.pathname)),
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // result.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    result.hostname = '';
    result.port = null;
    if (result.host) {
      if (srcPath[0] === '') srcPath[0] = result.host;
      else srcPath.unshift(result.host);
    }
    result.host = '';
    if (relative.protocol) {
      relative.hostname = null;
      relative.port = null;
      if (relative.host) {
        if (relPath[0] === '') relPath[0] = relative.host;
        else relPath.unshift(relative.host);
      }
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    result.host = (relative.host || relative.host === '') ?
                  relative.host : result.host;
    result.hostname = (relative.hostname || relative.hostname === '') ?
                      relative.hostname : result.hostname;
    result.search = relative.search;
    result.query = relative.query;
    srcPath = relPath;
    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) srcPath = [];
    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    result.search = relative.search;
    result.query = relative.query;
  } else if (!isNullOrUndefined(relative.search)) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      //occationaly the auth can get stuck only in host
      //this especialy happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ?
                       result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }
    result.search = relative.search;
    result.query = relative.query;
    //to support http.request
    if (!isNull(result.pathname) || !isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') +
                    (result.search ? result.search : '');
    }
    result.href = result.format();
    return result;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    result.pathname = null;
    //to support http.request
    if (result.search) {
      result.path = '/' + result.search;
    } else {
      result.path = null;
    }
    result.href = result.format();
    return result;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  var last = srcPath.slice(-1)[0];
  var hasTrailingSlash = (
      (result.host || relative.host) && (last === '.' || last === '..') ||
      last === '');

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  var up = 0;
  for (var i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];
    if (last == '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      up--;
    }
  }

  // if the path is allowed to go above the root, restore leading ..s
  if (!mustEndAbs && !removeAllDots) {
    for (; up--; up) {
      srcPath.unshift('..');
    }
  }

  if (mustEndAbs && srcPath[0] !== '' &&
      (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
    srcPath.unshift('');
  }

  if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
    srcPath.push('');
  }

  var isAbsolute = srcPath[0] === '' ||
      (srcPath[0] && srcPath[0].charAt(0) === '/');

  // put the host back
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? '' :
                                    srcPath.length ? srcPath.shift() : '';
    //occationaly the auth can get stuck only in host
    //this especialy happens in cases like
    //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    var authInHost = result.host && result.host.indexOf('@') > 0 ?
                     result.host.split('@') : false;
    if (authInHost) {
      result.auth = authInHost.shift();
      result.host = result.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || (result.host && srcPath.length);

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  if (!srcPath.length) {
    result.pathname = null;
    result.path = null;
  } else {
    result.pathname = srcPath.join('/');
  }

  //to support request.http
  if (!isNull(result.pathname) || !isNull(result.search)) {
    result.path = (result.pathname ? result.pathname : '') +
                  (result.search ? result.search : '');
  }
  result.auth = relative.auth || result.auth;
  result.slashes = result.slashes || relative.slashes;
  result.href = result.format();
  return result;
};

Url.prototype.parseHost = function() {
  var host = this.host;
  var port = portPattern.exec(host);
  if (port) {
    port = port[0];
    if (port !== ':') {
      this.port = port.substr(1);
    }
    host = host.substr(0, host.length - port.length);
  }
  if (host) this.hostname = host;
};

function isString(arg) {
  return typeof arg === "string";
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isNull(arg) {
  return arg === null;
}
function isNullOrUndefined(arg) {
  return  arg == null;
}

},{"punycode":2,"querystring":6}],2:[function(require,module,exports){
(function (global){
/*! https://mths.be/punycode v1.4.1 by @mathias */
;(function(root) {

	/** Detect free variables */
	var freeExports = typeof exports == 'object' && exports &&
		!exports.nodeType && exports;
	var freeModule = typeof module == 'object' && module &&
		!module.nodeType && module;
	var freeGlobal = typeof global == 'object' && global;
	if (
		freeGlobal.global === freeGlobal ||
		freeGlobal.window === freeGlobal ||
		freeGlobal.self === freeGlobal
	) {
		root = freeGlobal;
	}

	/**
	 * The `punycode` object.
	 * @name punycode
	 * @type Object
	 */
	var punycode,

	/** Highest positive signed 32-bit float value */
	maxInt = 2147483647, // aka. 0x7FFFFFFF or 2^31-1

	/** Bootstring parameters */
	base = 36,
	tMin = 1,
	tMax = 26,
	skew = 38,
	damp = 700,
	initialBias = 72,
	initialN = 128, // 0x80
	delimiter = '-', // '\x2D'

	/** Regular expressions */
	regexPunycode = /^xn--/,
	regexNonASCII = /[^\x20-\x7E]/, // unprintable ASCII chars + non-ASCII chars
	regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g, // RFC 3490 separators

	/** Error messages */
	errors = {
		'overflow': 'Overflow: input needs wider integers to process',
		'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
		'invalid-input': 'Invalid input'
	},

	/** Convenience shortcuts */
	baseMinusTMin = base - tMin,
	floor = Math.floor,
	stringFromCharCode = String.fromCharCode,

	/** Temporary variable */
	key;

	/*--------------------------------------------------------------------------*/

	/**
	 * A generic error utility function.
	 * @private
	 * @param {String} type The error type.
	 * @returns {Error} Throws a `RangeError` with the applicable error message.
	 */
	function error(type) {
		throw new RangeError(errors[type]);
	}

	/**
	 * A generic `Array#map` utility function.
	 * @private
	 * @param {Array} array The array to iterate over.
	 * @param {Function} callback The function that gets called for every array
	 * item.
	 * @returns {Array} A new array of values returned by the callback function.
	 */
	function map(array, fn) {
		var length = array.length;
		var result = [];
		while (length--) {
			result[length] = fn(array[length]);
		}
		return result;
	}

	/**
	 * A simple `Array#map`-like wrapper to work with domain name strings or email
	 * addresses.
	 * @private
	 * @param {String} domain The domain name or email address.
	 * @param {Function} callback The function that gets called for every
	 * character.
	 * @returns {Array} A new string of characters returned by the callback
	 * function.
	 */
	function mapDomain(string, fn) {
		var parts = string.split('@');
		var result = '';
		if (parts.length > 1) {
			// In email addresses, only the domain name should be punycoded. Leave
			// the local part (i.e. everything up to `@`) intact.
			result = parts[0] + '@';
			string = parts[1];
		}
		// Avoid `split(regex)` for IE8 compatibility. See #17.
		string = string.replace(regexSeparators, '\x2E');
		var labels = string.split('.');
		var encoded = map(labels, fn).join('.');
		return result + encoded;
	}

	/**
	 * Creates an array containing the numeric code points of each Unicode
	 * character in the string. While JavaScript uses UCS-2 internally,
	 * this function will convert a pair of surrogate halves (each of which
	 * UCS-2 exposes as separate characters) into a single code point,
	 * matching UTF-16.
	 * @see `punycode.ucs2.encode`
	 * @see <https://mathiasbynens.be/notes/javascript-encoding>
	 * @memberOf punycode.ucs2
	 * @name decode
	 * @param {String} string The Unicode input string (UCS-2).
	 * @returns {Array} The new array of code points.
	 */
	function ucs2decode(string) {
		var output = [],
		    counter = 0,
		    length = string.length,
		    value,
		    extra;
		while (counter < length) {
			value = string.charCodeAt(counter++);
			if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
				// high surrogate, and there is a next character
				extra = string.charCodeAt(counter++);
				if ((extra & 0xFC00) == 0xDC00) { // low surrogate
					output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
				} else {
					// unmatched surrogate; only append this code unit, in case the next
					// code unit is the high surrogate of a surrogate pair
					output.push(value);
					counter--;
				}
			} else {
				output.push(value);
			}
		}
		return output;
	}

	/**
	 * Creates a string based on an array of numeric code points.
	 * @see `punycode.ucs2.decode`
	 * @memberOf punycode.ucs2
	 * @name encode
	 * @param {Array} codePoints The array of numeric code points.
	 * @returns {String} The new Unicode string (UCS-2).
	 */
	function ucs2encode(array) {
		return map(array, function(value) {
			var output = '';
			if (value > 0xFFFF) {
				value -= 0x10000;
				output += stringFromCharCode(value >>> 10 & 0x3FF | 0xD800);
				value = 0xDC00 | value & 0x3FF;
			}
			output += stringFromCharCode(value);
			return output;
		}).join('');
	}

	/**
	 * Converts a basic code point into a digit/integer.
	 * @see `digitToBasic()`
	 * @private
	 * @param {Number} codePoint The basic numeric code point value.
	 * @returns {Number} The numeric value of a basic code point (for use in
	 * representing integers) in the range `0` to `base - 1`, or `base` if
	 * the code point does not represent a value.
	 */
	function basicToDigit(codePoint) {
		if (codePoint - 48 < 10) {
			return codePoint - 22;
		}
		if (codePoint - 65 < 26) {
			return codePoint - 65;
		}
		if (codePoint - 97 < 26) {
			return codePoint - 97;
		}
		return base;
	}

	/**
	 * Converts a digit/integer into a basic code point.
	 * @see `basicToDigit()`
	 * @private
	 * @param {Number} digit The numeric value of a basic code point.
	 * @returns {Number} The basic code point whose value (when used for
	 * representing integers) is `digit`, which needs to be in the range
	 * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
	 * used; else, the lowercase form is used. The behavior is undefined
	 * if `flag` is non-zero and `digit` has no uppercase form.
	 */
	function digitToBasic(digit, flag) {
		//  0..25 map to ASCII a..z or A..Z
		// 26..35 map to ASCII 0..9
		return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
	}

	/**
	 * Bias adaptation function as per section 3.4 of RFC 3492.
	 * https://tools.ietf.org/html/rfc3492#section-3.4
	 * @private
	 */
	function adapt(delta, numPoints, firstTime) {
		var k = 0;
		delta = firstTime ? floor(delta / damp) : delta >> 1;
		delta += floor(delta / numPoints);
		for (/* no initialization */; delta > baseMinusTMin * tMax >> 1; k += base) {
			delta = floor(delta / baseMinusTMin);
		}
		return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
	}

	/**
	 * Converts a Punycode string of ASCII-only symbols to a string of Unicode
	 * symbols.
	 * @memberOf punycode
	 * @param {String} input The Punycode string of ASCII-only symbols.
	 * @returns {String} The resulting string of Unicode symbols.
	 */
	function decode(input) {
		// Don't use UCS-2
		var output = [],
		    inputLength = input.length,
		    out,
		    i = 0,
		    n = initialN,
		    bias = initialBias,
		    basic,
		    j,
		    index,
		    oldi,
		    w,
		    k,
		    digit,
		    t,
		    /** Cached calculation results */
		    baseMinusT;

		// Handle the basic code points: let `basic` be the number of input code
		// points before the last delimiter, or `0` if there is none, then copy
		// the first basic code points to the output.

		basic = input.lastIndexOf(delimiter);
		if (basic < 0) {
			basic = 0;
		}

		for (j = 0; j < basic; ++j) {
			// if it's not a basic code point
			if (input.charCodeAt(j) >= 0x80) {
				error('not-basic');
			}
			output.push(input.charCodeAt(j));
		}

		// Main decoding loop: start just after the last delimiter if any basic code
		// points were copied; start at the beginning otherwise.

		for (index = basic > 0 ? basic + 1 : 0; index < inputLength; /* no final expression */) {

			// `index` is the index of the next character to be consumed.
			// Decode a generalized variable-length integer into `delta`,
			// which gets added to `i`. The overflow checking is easier
			// if we increase `i` as we go, then subtract off its starting
			// value at the end to obtain `delta`.
			for (oldi = i, w = 1, k = base; /* no condition */; k += base) {

				if (index >= inputLength) {
					error('invalid-input');
				}

				digit = basicToDigit(input.charCodeAt(index++));

				if (digit >= base || digit > floor((maxInt - i) / w)) {
					error('overflow');
				}

				i += digit * w;
				t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);

				if (digit < t) {
					break;
				}

				baseMinusT = base - t;
				if (w > floor(maxInt / baseMinusT)) {
					error('overflow');
				}

				w *= baseMinusT;

			}

			out = output.length + 1;
			bias = adapt(i - oldi, out, oldi == 0);

			// `i` was supposed to wrap around from `out` to `0`,
			// incrementing `n` each time, so we'll fix that now:
			if (floor(i / out) > maxInt - n) {
				error('overflow');
			}

			n += floor(i / out);
			i %= out;

			// Insert `n` at position `i` of the output
			output.splice(i++, 0, n);

		}

		return ucs2encode(output);
	}

	/**
	 * Converts a string of Unicode symbols (e.g. a domain name label) to a
	 * Punycode string of ASCII-only symbols.
	 * @memberOf punycode
	 * @param {String} input The string of Unicode symbols.
	 * @returns {String} The resulting Punycode string of ASCII-only symbols.
	 */
	function encode(input) {
		var n,
		    delta,
		    handledCPCount,
		    basicLength,
		    bias,
		    j,
		    m,
		    q,
		    k,
		    t,
		    currentValue,
		    output = [],
		    /** `inputLength` will hold the number of code points in `input`. */
		    inputLength,
		    /** Cached calculation results */
		    handledCPCountPlusOne,
		    baseMinusT,
		    qMinusT;

		// Convert the input in UCS-2 to Unicode
		input = ucs2decode(input);

		// Cache the length
		inputLength = input.length;

		// Initialize the state
		n = initialN;
		delta = 0;
		bias = initialBias;

		// Handle the basic code points
		for (j = 0; j < inputLength; ++j) {
			currentValue = input[j];
			if (currentValue < 0x80) {
				output.push(stringFromCharCode(currentValue));
			}
		}

		handledCPCount = basicLength = output.length;

		// `handledCPCount` is the number of code points that have been handled;
		// `basicLength` is the number of basic code points.

		// Finish the basic string - if it is not empty - with a delimiter
		if (basicLength) {
			output.push(delimiter);
		}

		// Main encoding loop:
		while (handledCPCount < inputLength) {

			// All non-basic code points < n have been handled already. Find the next
			// larger one:
			for (m = maxInt, j = 0; j < inputLength; ++j) {
				currentValue = input[j];
				if (currentValue >= n && currentValue < m) {
					m = currentValue;
				}
			}

			// Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
			// but guard against overflow
			handledCPCountPlusOne = handledCPCount + 1;
			if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
				error('overflow');
			}

			delta += (m - n) * handledCPCountPlusOne;
			n = m;

			for (j = 0; j < inputLength; ++j) {
				currentValue = input[j];

				if (currentValue < n && ++delta > maxInt) {
					error('overflow');
				}

				if (currentValue == n) {
					// Represent delta as a generalized variable-length integer
					for (q = delta, k = base; /* no condition */; k += base) {
						t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
						if (q < t) {
							break;
						}
						qMinusT = q - t;
						baseMinusT = base - t;
						output.push(
							stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0))
						);
						q = floor(qMinusT / baseMinusT);
					}

					output.push(stringFromCharCode(digitToBasic(q, 0)));
					bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
					delta = 0;
					++handledCPCount;
				}
			}

			++delta;
			++n;

		}
		return output.join('');
	}

	/**
	 * Converts a Punycode string representing a domain name or an email address
	 * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
	 * it doesn't matter if you call it on a string that has already been
	 * converted to Unicode.
	 * @memberOf punycode
	 * @param {String} input The Punycoded domain name or email address to
	 * convert to Unicode.
	 * @returns {String} The Unicode representation of the given Punycode
	 * string.
	 */
	function toUnicode(input) {
		return mapDomain(input, function(string) {
			return regexPunycode.test(string)
				? decode(string.slice(4).toLowerCase())
				: string;
		});
	}

	/**
	 * Converts a Unicode string representing a domain name or an email address to
	 * Punycode. Only the non-ASCII parts of the domain name will be converted,
	 * i.e. it doesn't matter if you call it with a domain that's already in
	 * ASCII.
	 * @memberOf punycode
	 * @param {String} input The domain name or email address to convert, as a
	 * Unicode string.
	 * @returns {String} The Punycode representation of the given domain name or
	 * email address.
	 */
	function toASCII(input) {
		return mapDomain(input, function(string) {
			return regexNonASCII.test(string)
				? 'xn--' + encode(string)
				: string;
		});
	}

	/*--------------------------------------------------------------------------*/

	/** Define the public API */
	punycode = {
		/**
		 * A string representing the current Punycode.js version number.
		 * @memberOf punycode
		 * @type String
		 */
		'version': '1.4.1',
		/**
		 * An object of methods to convert from JavaScript's internal character
		 * representation (UCS-2) to Unicode code points, and back.
		 * @see <https://mathiasbynens.be/notes/javascript-encoding>
		 * @memberOf punycode
		 * @type Object
		 */
		'ucs2': {
			'decode': ucs2decode,
			'encode': ucs2encode
		},
		'decode': decode,
		'encode': encode,
		'toASCII': toASCII,
		'toUnicode': toUnicode
	};

	/** Expose `punycode` */
	// Some AMD build optimizers, like r.js, check for specific condition patterns
	// like the following:
	if (
		typeof define == 'function' &&
		typeof define.amd == 'object' &&
		define.amd
	) {
		define('punycode', function() {
			return punycode;
		});
	} else if (freeExports && freeModule) {
		if (module.exports == freeExports) {
			// in Node.js, io.js, or RingoJS v0.8.0+
			freeModule.exports = punycode;
		} else {
			// in Narwhal or RingoJS v0.7.0-
			for (key in punycode) {
				punycode.hasOwnProperty(key) && (freeExports[key] = punycode[key]);
			}
		}
	} else {
		// in Rhino or a web browser
		root.punycode = punycode;
	}

}(this));

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{}],3:[function(require,module,exports){
/*
 * quantize.js Copyright 2008 Nick Rabinowitz
 * Ported to node.js by Olivier Lesnicki
 * Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
 */

// fill out a couple protovis dependencies
/*
 * Block below copied from Protovis: http://mbostock.github.com/protovis/
 * Copyright 2010 Stanford Visualization Group
 * Licensed under the BSD License: http://www.opensource.org/licenses/bsd-license.php
 */
if (!pv) {
    var pv = {
        map: function(array, f) {
            var o = {};
            return f ? array.map(function(d, i) {
                o.index = i;
                return f.call(o, d);
            }) : array.slice();
        },
        naturalOrder: function(a, b) {
            return (a < b) ? -1 : ((a > b) ? 1 : 0);
        },
        sum: function(array, f) {
            var o = {};
            return array.reduce(f ? function(p, d, i) {
                o.index = i;
                return p + f.call(o, d);
            } : function(p, d) {
                return p + d;
            }, 0);
        },
        max: function(array, f) {
            return Math.max.apply(null, f ? pv.map(array, f) : array);
        }
    }
}

/**
 * Basic Javascript port of the MMCQ (modified median cut quantization)
 * algorithm from the Leptonica library (http://www.leptonica.com/).
 * Returns a color map you can use to map original pixels to the reduced
 * palette. Still a work in progress.
 * 
 * @author Nick Rabinowitz
 * @example
 
// array of pixels as [R,G,B] arrays
var myPixels = [[190,197,190], [202,204,200], [207,214,210], [211,214,211], [205,207,207]
                // etc
                ];
var maxColors = 4;
 
var cmap = MMCQ.quantize(myPixels, maxColors);
var newPalette = cmap.palette();
var newPixels = myPixels.map(function(p) { 
    return cmap.map(p); 
});
 
 */
var MMCQ = (function() {
    // private constants
    var sigbits = 5,
        rshift = 8 - sigbits,
        maxIterations = 1000,
        fractByPopulations = 0.75;

    // get reduced-space color index for a pixel

    function getColorIndex(r, g, b) {
        return (r << (2 * sigbits)) + (g << sigbits) + b;
    }

    // Simple priority queue

    function PQueue(comparator) {
        var contents = [],
            sorted = false;

        function sort() {
            contents.sort(comparator);
            sorted = true;
        }

        return {
            push: function(o) {
                contents.push(o);
                sorted = false;
            },
            peek: function(index) {
                if (!sorted) sort();
                if (index === undefined) index = contents.length - 1;
                return contents[index];
            },
            pop: function() {
                if (!sorted) sort();
                return contents.pop();
            },
            size: function() {
                return contents.length;
            },
            map: function(f) {
                return contents.map(f);
            },
            debug: function() {
                if (!sorted) sort();
                return contents;
            }
        };
    }

    // 3d color space box

    function VBox(r1, r2, g1, g2, b1, b2, histo) {
        var vbox = this;
        vbox.r1 = r1;
        vbox.r2 = r2;
        vbox.g1 = g1;
        vbox.g2 = g2;
        vbox.b1 = b1;
        vbox.b2 = b2;
        vbox.histo = histo;
    }
    VBox.prototype = {
        volume: function(force) {
            var vbox = this;
            if (!vbox._volume || force) {
                vbox._volume = ((vbox.r2 - vbox.r1 + 1) * (vbox.g2 - vbox.g1 + 1) * (vbox.b2 - vbox.b1 + 1));
            }
            return vbox._volume;
        },
        count: function(force) {
            var vbox = this,
                histo = vbox.histo;
            if (!vbox._count_set || force) {
                var npix = 0,
                    i, j, k, index;
                for (i = vbox.r1; i <= vbox.r2; i++) {
                    for (j = vbox.g1; j <= vbox.g2; j++) {
                        for (k = vbox.b1; k <= vbox.b2; k++) {
                            index = getColorIndex(i, j, k);
                            npix += (histo[index] || 0);
                        }
                    }
                }
                vbox._count = npix;
                vbox._count_set = true;
            }
            return vbox._count;
        },
        copy: function() {
            var vbox = this;
            return new VBox(vbox.r1, vbox.r2, vbox.g1, vbox.g2, vbox.b1, vbox.b2, vbox.histo);
        },
        avg: function(force) {
            var vbox = this,
                histo = vbox.histo;
            if (!vbox._avg || force) {
                var ntot = 0,
                    mult = 1 << (8 - sigbits),
                    rsum = 0,
                    gsum = 0,
                    bsum = 0,
                    hval,
                    i, j, k, histoindex;
                for (i = vbox.r1; i <= vbox.r2; i++) {
                    for (j = vbox.g1; j <= vbox.g2; j++) {
                        for (k = vbox.b1; k <= vbox.b2; k++) {
                            histoindex = getColorIndex(i, j, k);
                            hval = histo[histoindex] || 0;
                            ntot += hval;
                            rsum += (hval * (i + 0.5) * mult);
                            gsum += (hval * (j + 0.5) * mult);
                            bsum += (hval * (k + 0.5) * mult);
                        }
                    }
                }
                if (ntot) {
                    vbox._avg = [~~(rsum / ntot), ~~ (gsum / ntot), ~~ (bsum / ntot)];
                } else {
                    //console.log('empty box');
                    vbox._avg = [~~(mult * (vbox.r1 + vbox.r2 + 1) / 2), ~~ (mult * (vbox.g1 + vbox.g2 + 1) / 2), ~~ (mult * (vbox.b1 + vbox.b2 + 1) / 2)];
                }
            }
            return vbox._avg;
        },
        contains: function(pixel) {
            var vbox = this,
                rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            return (rval >= vbox.r1 && rval <= vbox.r2 &&
                gval >= vbox.g1 && gval <= vbox.g2 &&
                bval >= vbox.b1 && bval <= vbox.b2);
        }
    };

    // Color map

    function CMap() {
        this.vboxes = new PQueue(function(a, b) {
            return pv.naturalOrder(
                a.vbox.count() * a.vbox.volume(),
                b.vbox.count() * b.vbox.volume()
            )
        });;
    }
    CMap.prototype = {
        push: function(vbox) {
            this.vboxes.push({
                vbox: vbox,
                color: vbox.avg()
            });
        },
        palette: function() {
            return this.vboxes.map(function(vb) {
                return vb.color
            });
        },
        size: function() {
            return this.vboxes.size();
        },
        map: function(color) {
            var vboxes = this.vboxes;
            for (var i = 0; i < vboxes.size(); i++) {
                if (vboxes.peek(i).vbox.contains(color)) {
                    return vboxes.peek(i).color;
                }
            }
            return this.nearest(color);
        },
        nearest: function(color) {
            var vboxes = this.vboxes,
                d1, d2, pColor;
            for (var i = 0; i < vboxes.size(); i++) {
                d2 = Math.sqrt(
                    Math.pow(color[0] - vboxes.peek(i).color[0], 2) +
                    Math.pow(color[1] - vboxes.peek(i).color[1], 2) +
                    Math.pow(color[2] - vboxes.peek(i).color[2], 2)
                );
                if (d2 < d1 || d1 === undefined) {
                    d1 = d2;
                    pColor = vboxes.peek(i).color;
                }
            }
            return pColor;
        },
        forcebw: function() {
            // XXX: won't  work yet
            var vboxes = this.vboxes;
            vboxes.sort(function(a, b) {
                return pv.naturalOrder(pv.sum(a.color), pv.sum(b.color))
            });

            // force darkest color to black if everything < 5
            var lowest = vboxes[0].color;
            if (lowest[0] < 5 && lowest[1] < 5 && lowest[2] < 5)
                vboxes[0].color = [0, 0, 0];

            // force lightest color to white if everything > 251
            var idx = vboxes.length - 1,
                highest = vboxes[idx].color;
            if (highest[0] > 251 && highest[1] > 251 && highest[2] > 251)
                vboxes[idx].color = [255, 255, 255];
        }
    };

    // histo (1-d array, giving the number of pixels in
    // each quantized region of color space), or null on error

    function getHisto(pixels) {
        var histosize = 1 << (3 * sigbits),
            histo = new Array(histosize),
            index, rval, gval, bval;
        pixels.forEach(function(pixel) {
            rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            index = getColorIndex(rval, gval, bval);
            histo[index] = (histo[index] || 0) + 1;
        });
        return histo;
    }

    function vboxFromPixels(pixels, histo) {
        var rmin = 1000000,
            rmax = 0,
            gmin = 1000000,
            gmax = 0,
            bmin = 1000000,
            bmax = 0,
            rval, gval, bval;
        // find min/max
        pixels.forEach(function(pixel) {
            rval = pixel[0] >> rshift;
            gval = pixel[1] >> rshift;
            bval = pixel[2] >> rshift;
            if (rval < rmin) rmin = rval;
            else if (rval > rmax) rmax = rval;
            if (gval < gmin) gmin = gval;
            else if (gval > gmax) gmax = gval;
            if (bval < bmin) bmin = bval;
            else if (bval > bmax) bmax = bval;
        });
        return new VBox(rmin, rmax, gmin, gmax, bmin, bmax, histo);
    }

    function medianCutApply(histo, vbox) {
        if (!vbox.count()) return;

        var rw = vbox.r2 - vbox.r1 + 1,
            gw = vbox.g2 - vbox.g1 + 1,
            bw = vbox.b2 - vbox.b1 + 1,
            maxw = pv.max([rw, gw, bw]);
        // only one pixel, no split
        if (vbox.count() == 1) {
            return [vbox.copy()]
        }
        /* Find the partial sum arrays along the selected axis. */
        var total = 0,
            partialsum = [],
            lookaheadsum = [],
            i, j, k, sum, index;
        if (maxw == rw) {
            for (i = vbox.r1; i <= vbox.r2; i++) {
                sum = 0;
                for (j = vbox.g1; j <= vbox.g2; j++) {
                    for (k = vbox.b1; k <= vbox.b2; k++) {
                        index = getColorIndex(i, j, k);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        } else if (maxw == gw) {
            for (i = vbox.g1; i <= vbox.g2; i++) {
                sum = 0;
                for (j = vbox.r1; j <= vbox.r2; j++) {
                    for (k = vbox.b1; k <= vbox.b2; k++) {
                        index = getColorIndex(j, i, k);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        } else { /* maxw == bw */
            for (i = vbox.b1; i <= vbox.b2; i++) {
                sum = 0;
                for (j = vbox.r1; j <= vbox.r2; j++) {
                    for (k = vbox.g1; k <= vbox.g2; k++) {
                        index = getColorIndex(j, k, i);
                        sum += (histo[index] || 0);
                    }
                }
                total += sum;
                partialsum[i] = total;
            }
        }
        partialsum.forEach(function(d, i) {
            lookaheadsum[i] = total - d
        });

        function doCut(color) {
            var dim1 = color + '1',
                dim2 = color + '2',
                left, right, vbox1, vbox2, d2, count2 = 0;
            for (i = vbox[dim1]; i <= vbox[dim2]; i++) {
                if (partialsum[i] > total / 2) {
                    vbox1 = vbox.copy();
                    vbox2 = vbox.copy();
                    left = i - vbox[dim1];
                    right = vbox[dim2] - i;
                    if (left <= right)
                        d2 = Math.min(vbox[dim2] - 1, ~~ (i + right / 2));
                    else d2 = Math.max(vbox[dim1], ~~ (i - 1 - left / 2));
                    // avoid 0-count boxes
                    while (!partialsum[d2]) d2++;
                    count2 = lookaheadsum[d2];
                    while (!count2 && partialsum[d2 - 1]) count2 = lookaheadsum[--d2];
                    // set dimensions
                    vbox1[dim2] = d2;
                    vbox2[dim1] = vbox1[dim2] + 1;
                    // console.log('vbox counts:', vbox.count(), vbox1.count(), vbox2.count());
                    return [vbox1, vbox2];
                }
            }

        }
        // determine the cut planes
        return maxw == rw ? doCut('r') :
            maxw == gw ? doCut('g') :
            doCut('b');
    }

    function quantize(pixels, maxcolors) {
        // short-circuit
        if (!pixels.length || maxcolors < 2 || maxcolors > 256) {
            // console.log('wrong number of maxcolors');
            return false;
        }

        // XXX: check color content and convert to grayscale if insufficient

        var histo = getHisto(pixels),
            histosize = 1 << (3 * sigbits);

        // check that we aren't below maxcolors already
        var nColors = 0;
        histo.forEach(function() {
            nColors++
        });
        if (nColors <= maxcolors) {
            // XXX: generate the new colors from the histo and return
        }

        // get the beginning vbox from the colors
        var vbox = vboxFromPixels(pixels, histo),
            pq = new PQueue(function(a, b) {
                return pv.naturalOrder(a.count(), b.count())
            });
        pq.push(vbox);

        // inner function to do the iteration

        function iter(lh, target) {
            var ncolors = 1,
                niters = 0,
                vbox;
            while (niters < maxIterations) {
                vbox = lh.pop();
                if (!vbox.count()) { /* just put it back */
                    lh.push(vbox);
                    niters++;
                    continue;
                }
                // do the cut
                var vboxes = medianCutApply(histo, vbox),
                    vbox1 = vboxes[0],
                    vbox2 = vboxes[1];

                if (!vbox1) {
                    // console.log("vbox1 not defined; shouldn't happen!");
                    return;
                }
                lh.push(vbox1);
                if (vbox2) { /* vbox2 can be null */
                    lh.push(vbox2);
                    ncolors++;
                }
                if (ncolors >= target) return;
                if (niters++ > maxIterations) {
                    // console.log("infinite loop; perhaps too few pixels!");
                    return;
                }
            }
        }

        // first set of colors, sorted by population
        iter(pq, fractByPopulations * maxcolors);
        // console.log(pq.size(), pq.debug().length, pq.debug().slice());

        // Re-sort by the product of pixel occupancy times the size in color space.
        var pq2 = new PQueue(function(a, b) {
            return pv.naturalOrder(a.count() * a.volume(), b.count() * b.volume())
        });
        while (pq.size()) {
            pq2.push(pq.pop());
        }

        // next set - generate the median cuts using the (npix * vol) sorting.
        iter(pq2, maxcolors - pq2.size());

        // calculate the actual colors
        var cmap = new CMap();
        while (pq2.size()) {
            cmap.push(pq2.pop());
        }

        return cmap;
    }

    return {
        quantize: quantize
    }
})();

module.exports = MMCQ.quantize

},{}],4:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

// If obj.hasOwnProperty has been overridden, then calling
// obj.hasOwnProperty(prop) will break.
// See: https://github.com/joyent/node/issues/1707
function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

module.exports = function(qs, sep, eq, options) {
  sep = sep || '&';
  eq = eq || '=';
  var obj = {};

  if (typeof qs !== 'string' || qs.length === 0) {
    return obj;
  }

  var regexp = /\+/g;
  qs = qs.split(sep);

  var maxKeys = 1000;
  if (options && typeof options.maxKeys === 'number') {
    maxKeys = options.maxKeys;
  }

  var len = qs.length;
  // maxKeys <= 0 means that we should not limit keys count
  if (maxKeys > 0 && len > maxKeys) {
    len = maxKeys;
  }

  for (var i = 0; i < len; ++i) {
    var x = qs[i].replace(regexp, '%20'),
        idx = x.indexOf(eq),
        kstr, vstr, k, v;

    if (idx >= 0) {
      kstr = x.substr(0, idx);
      vstr = x.substr(idx + 1);
    } else {
      kstr = x;
      vstr = '';
    }

    k = decodeURIComponent(kstr);
    v = decodeURIComponent(vstr);

    if (!hasOwnProperty(obj, k)) {
      obj[k] = v;
    } else if (isArray(obj[k])) {
      obj[k].push(v);
    } else {
      obj[k] = [obj[k], v];
    }
  }

  return obj;
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

},{}],5:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

'use strict';

var stringifyPrimitive = function(v) {
  switch (typeof v) {
    case 'string':
      return v;

    case 'boolean':
      return v ? 'true' : 'false';

    case 'number':
      return isFinite(v) ? v : '';

    default:
      return '';
  }
};

module.exports = function(obj, sep, eq, name) {
  sep = sep || '&';
  eq = eq || '=';
  if (obj === null) {
    obj = undefined;
  }

  if (typeof obj === 'object') {
    return map(objectKeys(obj), function(k) {
      var ks = encodeURIComponent(stringifyPrimitive(k)) + eq;
      if (isArray(obj[k])) {
        return map(obj[k], function(v) {
          return ks + encodeURIComponent(stringifyPrimitive(v));
        }).join(sep);
      } else {
        return ks + encodeURIComponent(stringifyPrimitive(obj[k]));
      }
    }).join(sep);

  }

  if (!name) return '';
  return encodeURIComponent(stringifyPrimitive(name)) + eq +
         encodeURIComponent(stringifyPrimitive(obj));
};

var isArray = Array.isArray || function (xs) {
  return Object.prototype.toString.call(xs) === '[object Array]';
};

function map (xs, f) {
  if (xs.map) return xs.map(f);
  var res = [];
  for (var i = 0; i < xs.length; i++) {
    res.push(f(xs[i], i));
  }
  return res;
}

var objectKeys = Object.keys || function (obj) {
  var res = [];
  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) res.push(key);
  }
  return res;
};

},{}],6:[function(require,module,exports){
'use strict';

exports.decode = exports.parse = require('./decode');
exports.encode = exports.stringify = require('./encode');

},{"./decode":4,"./encode":5}],7:[function(require,module,exports){
var Vibrant;

Vibrant = require('./vibrant');

Vibrant.DefaultOpts.Image = require('./image/browser');

module.exports = Vibrant;


},{"./image/browser":13,"./vibrant":22}],8:[function(require,module,exports){
var Vibrant;

window.Vibrant = Vibrant = require('./browser');


},{"./browser":7}],9:[function(require,module,exports){
module.exports = function(r, g, b, a) {
  return a >= 125 && !(r > 250 && g > 250 && b > 250);
};


},{}],10:[function(require,module,exports){
module.exports.Default = require('./default');


},{"./default":9}],11:[function(require,module,exports){
var DefaultGenerator, DefaultOpts, Generator, Swatch, util,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty,
  slice = [].slice;

Swatch = require('../swatch');

util = require('../util');

Generator = require('./index');

DefaultOpts = {
  targetDarkLuma: 0.26,
  maxDarkLuma: 0.45,
  minLightLuma: 0.55,
  targetLightLuma: 0.74,
  minNormalLuma: 0.3,
  targetNormalLuma: 0.5,
  maxNormalLuma: 0.7,
  targetMutesSaturation: 0.3,
  maxMutesSaturation: 0.4,
  targetVibrantSaturation: 1.0,
  minVibrantSaturation: 0.35,
  weightSaturation: 3,
  weightLuma: 6,
  weightPopulation: 1
};

module.exports = DefaultGenerator = (function(superClass) {
  extend(DefaultGenerator, superClass);

  function DefaultGenerator(opts) {
    this.opts = util.defaults(opts, DefaultOpts);
    this.VibrantSwatch = null;
    this.LightVibrantSwatch = null;
    this.DarkVibrantSwatch = null;
    this.MutedSwatch = null;
    this.LightMutedSwatch = null;
    this.DarkMutedSwatch = null;
  }

  DefaultGenerator.prototype.generate = function(swatches) {
    this.swatches = swatches;
    this.maxPopulation = this.findMaxPopulation();
    this.generateVarationColors();
    return this.generateEmptySwatches();
  };

  DefaultGenerator.prototype.getVibrantSwatch = function() {
    return this.VibrantSwatch;
  };

  DefaultGenerator.prototype.getLightVibrantSwatch = function() {
    return this.LightVibrantSwatch;
  };

  DefaultGenerator.prototype.getDarkVibrantSwatch = function() {
    return this.DarkVibrantSwatch;
  };

  DefaultGenerator.prototype.getMutedSwatch = function() {
    return this.MutedSwatch;
  };

  DefaultGenerator.prototype.getLightMutedSwatch = function() {
    return this.LightMutedSwatch;
  };

  DefaultGenerator.prototype.getDarkMutedSwatch = function() {
    return this.DarkMutedSwatch;
  };

  DefaultGenerator.prototype.generateVarationColors = function() {
    this.VibrantSwatch = this.findColorVariation(this.opts.targetNormalLuma, this.opts.minNormalLuma, this.opts.maxNormalLuma, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.LightVibrantSwatch = this.findColorVariation(this.opts.targetLightLuma, this.opts.minLightLuma, 1, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.DarkVibrantSwatch = this.findColorVariation(this.opts.targetDarkLuma, 0, this.opts.maxDarkLuma, this.opts.targetVibrantSaturation, this.opts.minVibrantSaturation, 1);
    this.MutedSwatch = this.findColorVariation(this.opts.targetNormalLuma, this.opts.minNormalLuma, this.opts.maxNormalLuma, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
    this.LightMutedSwatch = this.findColorVariation(this.opts.targetLightLuma, this.opts.minLightLuma, 1, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
    return this.DarkMutedSwatch = this.findColorVariation(this.opts.targetDarkLuma, 0, this.opts.maxDarkLuma, this.opts.targetMutesSaturation, 0, this.opts.maxMutesSaturation);
  };

  DefaultGenerator.prototype.generateEmptySwatches = function() {
    var hsl;
    if (this.VibrantSwatch === null) {
      if (this.DarkVibrantSwatch !== null) {
        hsl = this.DarkVibrantSwatch.getHsl();
        hsl[2] = this.opts.targetNormalLuma;
        this.VibrantSwatch = new Swatch(util.hslToRgb(hsl[0], hsl[1], hsl[2]), 0);
      }
    }
    if (this.DarkVibrantSwatch === null) {
      if (this.VibrantSwatch !== null) {
        hsl = this.VibrantSwatch.getHsl();
        hsl[2] = this.opts.targetDarkLuma;
        return this.DarkVibrantSwatch = new Swatch(util.hslToRgb(hsl[0], hsl[1], hsl[2]), 0);
      }
    }
  };

  DefaultGenerator.prototype.findMaxPopulation = function() {
    var j, len, population, ref, swatch;
    population = 0;
    ref = this.swatches;
    for (j = 0, len = ref.length; j < len; j++) {
      swatch = ref[j];
      population = Math.max(population, swatch.getPopulation());
    }
    return population;
  };

  DefaultGenerator.prototype.findColorVariation = function(targetLuma, minLuma, maxLuma, targetSaturation, minSaturation, maxSaturation) {
    var j, len, luma, max, maxValue, ref, sat, swatch, value;
    max = null;
    maxValue = 0;
    ref = this.swatches;
    for (j = 0, len = ref.length; j < len; j++) {
      swatch = ref[j];
      sat = swatch.getHsl()[1];
      luma = swatch.getHsl()[2];
      if (sat >= minSaturation && sat <= maxSaturation && luma >= minLuma && luma <= maxLuma && !this.isAlreadySelected(swatch)) {
        value = this.createComparisonValue(sat, targetSaturation, luma, targetLuma, swatch.getPopulation(), this.maxPopulation);
        if (max === null || value > maxValue) {
          max = swatch;
          maxValue = value;
        }
      }
    }
    return max;
  };

  DefaultGenerator.prototype.createComparisonValue = function(saturation, targetSaturation, luma, targetLuma, population, maxPopulation) {
    return this.weightedMean(this.invertDiff(saturation, targetSaturation), this.opts.weightSaturation, this.invertDiff(luma, targetLuma), this.opts.weightLuma, population / maxPopulation, this.opts.weightPopulation);
  };

  DefaultGenerator.prototype.invertDiff = function(value, targetValue) {
    return 1 - Math.abs(value - targetValue);
  };

  DefaultGenerator.prototype.weightedMean = function() {
    var i, sum, sumWeight, value, values, weight;
    values = 1 <= arguments.length ? slice.call(arguments, 0) : [];
    sum = 0;
    sumWeight = 0;
    i = 0;
    while (i < values.length) {
      value = values[i];
      weight = values[i + 1];
      sum += value * weight;
      sumWeight += weight;
      i += 2;
    }
    return sum / sumWeight;
  };

  DefaultGenerator.prototype.isAlreadySelected = function(swatch) {
    return this.VibrantSwatch === swatch || this.DarkVibrantSwatch === swatch || this.LightVibrantSwatch === swatch || this.MutedSwatch === swatch || this.DarkMutedSwatch === swatch || this.LightMutedSwatch === swatch;
  };

  return DefaultGenerator;

})(Generator);


},{"../swatch":20,"../util":21,"./index":12}],12:[function(require,module,exports){
var Generator;

module.exports = Generator = (function() {
  function Generator() {}

  Generator.prototype.generate = function(swatches) {};

  Generator.prototype.getVibrantSwatch = function() {};

  Generator.prototype.getLightVibrantSwatch = function() {};

  Generator.prototype.getDarkVibrantSwatch = function() {};

  Generator.prototype.getMutedSwatch = function() {};

  Generator.prototype.getLightMutedSwatch = function() {};

  Generator.prototype.getDarkMutedSwatch = function() {};

  return Generator;

})();

module.exports.Default = require('./default');


},{"./default":11}],13:[function(require,module,exports){
var BrowserImage, Image, Url, isRelativeUrl, isSameOrigin,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

Image = require('./index');

Url = require('url');

isRelativeUrl = function(url) {
  var u;
  u = Url.parse(url);
  return u.protocol === null && u.host === null && u.port === null;
};

isSameOrigin = function(a, b) {
  var ua, ub;
  ua = Url.parse(a);
  ub = Url.parse(b);
  return ua.protocol === ub.protocol && ua.hostname === ub.hostname && ua.port === ub.port;
};

module.exports = BrowserImage = (function(superClass) {
  extend(BrowserImage, superClass);

  function BrowserImage(path, cb) {
    if (typeof path === 'object' && path instanceof HTMLImageElement) {
      this.img = path;
      path = this.img.src;
    } else {
      this.img = document.createElement('img');
      this.img.src = path;
    }
    if (!isRelativeUrl(path) && !isSameOrigin(window.location.href, path)) {
      this.img.crossOrigin = 'anonymous';
    }
    this.img.onload = (function(_this) {
      return function() {
        _this._initCanvas();
        return typeof cb === "function" ? cb(null, _this) : void 0;
      };
    })(this);
    if (this.img.complete) {
      this.img.onload();
    }
    this.img.onerror = (function(_this) {
      return function(e) {
        var err;
        err = new Error("Fail to load image: " + path);
        err.raw = e;
        return typeof cb === "function" ? cb(err) : void 0;
      };
    })(this);
  }

  BrowserImage.prototype._initCanvas = function() {
    this.canvas = document.createElement('canvas');
    this.context = this.canvas.getContext('2d');
    document.body.appendChild(this.canvas);
    this.width = this.canvas.width = this.img.width;
    this.height = this.canvas.height = this.img.height;
    return this.context.drawImage(this.img, 0, 0, this.width, this.height);
  };

  BrowserImage.prototype.clear = function() {
    return this.context.clearRect(0, 0, this.width, this.height);
  };

  BrowserImage.prototype.getWidth = function() {
    return this.width;
  };

  BrowserImage.prototype.getHeight = function() {
    return this.height;
  };

  BrowserImage.prototype.resize = function(w, h, r) {
    this.width = this.canvas.width = w;
    this.height = this.canvas.height = h;
    this.context.scale(r, r);
    return this.context.drawImage(this.img, 0, 0);
  };

  BrowserImage.prototype.update = function(imageData) {
    return this.context.putImageData(imageData, 0, 0);
  };

  BrowserImage.prototype.getPixelCount = function() {
    return this.width * this.height;
  };

  BrowserImage.prototype.getImageData = function() {
    return this.context.getImageData(0, 0, this.width, this.height);
  };

  BrowserImage.prototype.removeCanvas = function() {
    return this.canvas.parentNode.removeChild(this.canvas);
  };

  return BrowserImage;

})(Image);


},{"./index":14,"url":1}],14:[function(require,module,exports){
var Image;

module.exports = Image = (function() {
  function Image() {}

  Image.prototype.clear = function() {};

  Image.prototype.update = function(imageData) {};

  Image.prototype.getWidth = function() {};

  Image.prototype.getHeight = function() {};

  Image.prototype.scaleDown = function(opts) {
    var height, maxSide, ratio, width;
    width = this.getWidth();
    height = this.getHeight();
    ratio = 1;
    if (opts.maxDimension != null) {
      maxSide = Math.max(width, height);
      if (maxSide > opts.maxDimension) {
        ratio = opts.maxDimension / maxSide;
      }
    } else {
      ratio = 1 / opts.quality;
    }
    if (ratio < 1) {
      return this.resize(width * ratio, height * ratio, ratio);
    }
  };

  Image.prototype.resize = function(w, h, r) {};

  Image.prototype.getPixelCount = function() {};

  Image.prototype.getImageData = function() {};

  Image.prototype.removeCanvas = function() {};

  return Image;

})();


},{}],15:[function(require,module,exports){
var MMCQ, PQueue, RSHIFT, SIGBITS, Swatch, VBox, getColorIndex, ref, util;

ref = util = require('../../util'), getColorIndex = ref.getColorIndex, SIGBITS = ref.SIGBITS, RSHIFT = ref.RSHIFT;

Swatch = require('../../swatch');

VBox = require('./vbox');

PQueue = require('./pqueue');

module.exports = MMCQ = (function() {
  MMCQ.DefaultOpts = {
    maxIterations: 1000,
    fractByPopulations: 0.75
  };

  function MMCQ(opts) {
    this.opts = util.defaults(opts, this.constructor.DefaultOpts);
  }

  MMCQ.prototype.quantize = function(pixels, opts) {
    var color, colorCount, hist, pq, pq2, shouldIgnore, swatches, v, vbox;
    if (pixels.length === 0 || opts.colorCount < 2 || opts.colorCount > 256) {
      throw new Error("Wrong MMCQ parameters");
    }
    shouldIgnore = function() {
      return false;
    };
    if (Array.isArray(opts.filters) && opts.filters.length > 0) {
      shouldIgnore = function(r, g, b, a) {
        var f, i, len, ref1;
        ref1 = opts.filters;
        for (i = 0, len = ref1.length; i < len; i++) {
          f = ref1[i];
          if (!f(r, g, b, a)) {
            return true;
          }
        }
        return false;
      };
    }
    vbox = VBox.build(pixels, shouldIgnore);
    hist = vbox.hist;
    colorCount = Object.keys(hist).length;
    pq = new PQueue(function(a, b) {
      return a.count() - b.count();
    });
    pq.push(vbox);
    this._splitBoxes(pq, this.opts.fractByPopulations * opts.colorCount);
    pq2 = new PQueue(function(a, b) {
      return a.count() * a.volume() - b.count() * b.volume();
    });
    pq2.contents = pq.contents;
    this._splitBoxes(pq2, opts.colorCount - pq2.size());
    swatches = [];
    this.vboxes = [];
    while (pq2.size()) {
      v = pq2.pop();
      color = v.avg();
      if (!(typeof shouldIgnore === "function" ? shouldIgnore(color[0], color[1], color[2], 255) : void 0)) {
        this.vboxes.push(v);
        swatches.push(new Swatch(color, v.count()));
      }
    }
    return swatches;
  };

  MMCQ.prototype._splitBoxes = function(pq, target) {
    var colorCount, iteration, maxIterations, ref1, vbox, vbox1, vbox2;
    colorCount = 1;
    iteration = 0;
    maxIterations = this.opts.maxIterations;
    while (iteration < maxIterations) {
      iteration++;
      vbox = pq.pop();
      if (!vbox.count()) {
        continue;
      }
      ref1 = vbox.split(), vbox1 = ref1[0], vbox2 = ref1[1];
      pq.push(vbox1);
      if (vbox2) {
        pq.push(vbox2);
        colorCount++;
      }
      if (colorCount >= target || iteration > maxIterations) {
        return;
      }
    }
  };

  return MMCQ;

})();


},{"../../swatch":20,"../../util":21,"./pqueue":16,"./vbox":17}],16:[function(require,module,exports){
var PQueue;

module.exports = PQueue = (function() {
  function PQueue(comparator) {
    this.comparator = comparator;
    this.contents = [];
    this.sorted = false;
  }

  PQueue.prototype._sort = function() {
    this.contents.sort(this.comparator);
    return this.sorted = true;
  };

  PQueue.prototype.push = function(o) {
    this.contents.push(o);
    return this.sorted = false;
  };

  PQueue.prototype.peek = function(index) {
    if (!this.sorted) {
      this._sort();
    }
    if (index == null) {
      index = this.contents.length - 1;
    }
    return this.contents[index];
  };

  PQueue.prototype.pop = function() {
    if (!this.sorted) {
      this._sort();
    }
    return this.contents.pop();
  };

  PQueue.prototype.size = function() {
    return this.contents.length;
  };

  PQueue.prototype.map = function(f) {
    if (!this.sorted) {
      this._sort();
    }
    return this.contents.map(f);
  };

  return PQueue;

})();


},{}],17:[function(require,module,exports){
var RSHIFT, SIGBITS, VBox, getColorIndex, ref, util;

ref = util = require('../../util'), getColorIndex = ref.getColorIndex, SIGBITS = ref.SIGBITS, RSHIFT = ref.RSHIFT;

module.exports = VBox = (function() {
  VBox.build = function(pixels, shouldIgnore) {
    var a, b, bmax, bmin, g, gmax, gmin, hist, hn, i, index, n, offset, r, rmax, rmin;
    hn = 1 << (3 * SIGBITS);
    hist = new Uint32Array(hn);
    rmax = gmax = bmax = 0;
    rmin = gmin = bmin = Number.MAX_VALUE;
    n = pixels.length / 4;
    i = 0;
    while (i < n) {
      offset = i * 4;
      i++;
      r = pixels[offset + 0];
      g = pixels[offset + 1];
      b = pixels[offset + 2];
      a = pixels[offset + 3];
      if (shouldIgnore(r, g, b, a)) {
        continue;
      }
      r = r >> RSHIFT;
      g = g >> RSHIFT;
      b = b >> RSHIFT;
      index = getColorIndex(r, g, b);
      hist[index] += 1;
      if (r > rmax) {
        rmax = r;
      }
      if (r < rmin) {
        rmin = r;
      }
      if (g > gmax) {
        gmax = g;
      }
      if (g < gmin) {
        gmin = g;
      }
      if (b > bmax) {
        bmax = b;
      }
      if (b < bmin) {
        bmin = b;
      }
    }
    return new VBox(rmin, rmax, gmin, gmax, bmin, bmax, hist);
  };

  function VBox(r1, r2, g1, g2, b1, b2, hist1) {
    this.r1 = r1;
    this.r2 = r2;
    this.g1 = g1;
    this.g2 = g2;
    this.b1 = b1;
    this.b2 = b2;
    this.hist = hist1;
  }

  VBox.prototype.invalidate = function() {
    delete this._count;
    delete this._avg;
    return delete this._volume;
  };

  VBox.prototype.volume = function() {
    if (this._volume == null) {
      this._volume = (this.r2 - this.r1 + 1) * (this.g2 - this.g1 + 1) * (this.b2 - this.b1 + 1);
    }
    return this._volume;
  };

  VBox.prototype.count = function() {
    var c, hist;
    if (this._count == null) {
      hist = this.hist;
      c = 0;
      
      for (var r = this.r1; r <= this.r2; r++) {
        for (var g = this.g1; g <= this.g2; g++) {
          for (var b = this.b1; b <= this.b2; b++) {
            var index = getColorIndex(r, g, b);
            c += hist[index];
          }
        }
      }
      ;
      this._count = c;
    }
    return this._count;
  };

  VBox.prototype.clone = function() {
    return new VBox(this.r1, this.r2, this.g1, this.g2, this.b1, this.b2, this.hist);
  };

  VBox.prototype.avg = function() {
    var bsum, gsum, hist, mult, ntot, rsum;
    if (this._avg == null) {
      hist = this.hist;
      ntot = 0;
      mult = 1 << (8 - SIGBITS);
      rsum = gsum = bsum = 0;
      
      for (var r = this.r1; r <= this.r2; r++) {
        for (var g = this.g1; g <= this.g2; g++) {
          for (var b = this.b1; b <= this.b2; b++) {
            var index = getColorIndex(r, g, b);
            var h = hist[index];
            ntot += h;
            rsum += (h * (r + 0.5) * mult);
            gsum += (h * (g + 0.5) * mult);
            bsum += (h * (b + 0.5) * mult);
          }
        }
      }
      ;
      if (ntot) {
        this._avg = [~~(rsum / ntot), ~~(gsum / ntot), ~~(bsum / ntot)];
      } else {
        this._avg = [~~(mult * (this.r1 + this.r2 + 1) / 2), ~~(mult * (this.g1 + this.g2 + 1) / 2), ~~(mult * (this.b1 + this.b2 + 1) / 2)];
      }
    }
    return this._avg;
  };

  VBox.prototype.split = function() {
    var accSum, bw, d, doCut, gw, hist, i, j, maxd, maxw, ref1, reverseSum, rw, splitPoint, sum, total, vbox;
    hist = this.hist;
    if (!this.count()) {
      return null;
    }
    if (this.count() === 1) {
      return [this.clone()];
    }
    rw = this.r2 - this.r1 + 1;
    gw = this.g2 - this.g1 + 1;
    bw = this.b2 - this.b1 + 1;
    maxw = Math.max(rw, gw, bw);
    accSum = null;
    sum = total = 0;
    maxd = null;
    switch (maxw) {
      case rw:
        maxd = 'r';
        accSum = new Uint32Array(this.r2 + 1);
        
        for (var r = this.r1; r <= this.r2; r++) {
          sum = 0
          for (var g = this.g1; g <= this.g2; g++) {
            for (var b = this.b1; b <= this.b2; b++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[r] = total;
        }
        ;
        break;
      case gw:
        maxd = 'g';
        accSum = new Uint32Array(this.g2 + 1);
        
        for (var g = this.g1; g <= this.g2; g++) {
          sum = 0
          for (var r = this.r1; r <= this.r2; r++) {
            for (var b = this.b1; b <= this.b2; b++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[g] = total;
        }
        ;
        break;
      case bw:
        maxd = 'b';
        accSum = new Uint32Array(this.b2 + 1);
        
        for (var b = this.b1; b <= this.b2; b++) {
          sum = 0
          for (var r = this.r1; r <= this.r2; r++) {
            for (var g = this.g1; g <= this.g2; g++) {
              var index = getColorIndex(r, g, b);
              sum += hist[index];
            }
          }
          total += sum;
          accSum[b] = total;
        }
        ;
    }
    splitPoint = -1;
    reverseSum = new Uint32Array(accSum.length);
    for (i = j = 0, ref1 = accSum.length - 1; 0 <= ref1 ? j <= ref1 : j >= ref1; i = 0 <= ref1 ? ++j : --j) {
      d = accSum[i];
      if (splitPoint < 0 && d > total / 2) {
        splitPoint = i;
      }
      reverseSum[i] = total - d;
    }
    vbox = this;
    doCut = function(d) {
      var c2, d1, d2, dim1, dim2, left, right, vbox1, vbox2;
      dim1 = d + "1";
      dim2 = d + "2";
      d1 = vbox[dim1];
      d2 = vbox[dim2];
      vbox1 = vbox.clone();
      vbox2 = vbox.clone();
      left = splitPoint - d1;
      right = d2 - splitPoint;
      if (left <= right) {
        d2 = Math.min(d2 - 1, ~~(splitPoint + right / 2));
        d2 = Math.max(0, d2);
      } else {
        d2 = Math.max(d1, ~~(splitPoint - 1 - left / 2));
        d2 = Math.min(vbox[dim2], d2);
      }
      while (!accSum[d2]) {
        d2++;
      }
      c2 = reverseSum[d2];
      while (!c2 && accSum[d2 - 1]) {
        c2 = reverseSum[--d2];
      }
      vbox1[dim2] = d2;
      vbox2[dim1] = d2 + 1;
      return [vbox1, vbox2];
    };
    return doCut(maxd);
  };

  VBox.prototype.contains = function(p) {
    var b, g, r;
    r = p[0] >> RSHIFT;
    g = p[1] >> RSHIFT;
    b = p[2] >> RSHIFT;
    return r >= this.r1 && r <= this.r2 && g >= this.g1 && g <= this.g2 && b >= this.b1 && b <= this.b2;
  };

  return VBox;

})();


},{"../../util":21}],18:[function(require,module,exports){
var Quantizer;

module.exports = Quantizer = (function() {
  function Quantizer() {}

  Quantizer.prototype.initialize = function(pixels, opts) {};

  Quantizer.prototype.getQuantizedColors = function() {};

  return Quantizer;

})();

module.exports.MMCQ = require('./mmcq');


},{"./mmcq":19}],19:[function(require,module,exports){
var MMCQ, MMCQImpl, Quantizer, Swatch,
  extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
  hasProp = {}.hasOwnProperty;

Swatch = require('../swatch');

Quantizer = require('./index');

MMCQImpl = require('./impl/mmcq');

module.exports = MMCQ = (function(superClass) {
  extend(MMCQ, superClass);

  function MMCQ() {
    return MMCQ.__super__.constructor.apply(this, arguments);
  }

  MMCQ.prototype.initialize = function(pixels, opts) {
    var mmcq;
    this.opts = opts;
    mmcq = new MMCQImpl();
    return this.swatches = mmcq.quantize(pixels, this.opts);
  };

  MMCQ.prototype.getQuantizedColors = function() {
    return this.swatches;
  };

  return MMCQ;

})(Quantizer);


},{"../swatch":20,"./impl/mmcq":15,"./index":18}],20:[function(require,module,exports){
var Swatch, util;

util = require('./util');


/*
  From Vibrant.js by Jari Zwarts
  Ported to node.js by AKFish

  Swatch class
 */

module.exports = Swatch = (function() {
  Swatch.prototype.hsl = void 0;

  Swatch.prototype.rgb = void 0;

  Swatch.prototype.population = 1;

  Swatch.prototype.yiq = 0;

  function Swatch(rgb, population) {
    this.rgb = rgb;
    this.population = population;
  }

  Swatch.prototype.getHsl = function() {
    if (!this.hsl) {
      return this.hsl = util.rgbToHsl(this.rgb[0], this.rgb[1], this.rgb[2]);
    } else {
      return this.hsl;
    }
  };

  Swatch.prototype.getPopulation = function() {
    return this.population;
  };

  Swatch.prototype.getRgb = function() {
    return this.rgb;
  };

  Swatch.prototype.getHex = function() {
    return util.rgbToHex(this.rgb[0], this.rgb[1], this.rgb[2]);
  };

  Swatch.prototype.getTitleTextColor = function() {
    this._ensureTextColors();
    if (this.yiq < 200) {
      return "#fff";
    } else {
      return "#000";
    }
  };

  Swatch.prototype.getBodyTextColor = function() {
    this._ensureTextColors();
    if (this.yiq < 150) {
      return "#fff";
    } else {
      return "#000";
    }
  };

  Swatch.prototype._ensureTextColors = function() {
    if (!this.yiq) {
      return this.yiq = (this.rgb[0] * 299 + this.rgb[1] * 587 + this.rgb[2] * 114) / 1000;
    }
  };

  return Swatch;

})();


},{"./util":21}],21:[function(require,module,exports){
var DELTAE94, RSHIFT, SIGBITS;

DELTAE94 = {
  NA: 0,
  PERFECT: 1,
  CLOSE: 2,
  GOOD: 10,
  SIMILAR: 50
};

SIGBITS = 5;

RSHIFT = 8 - SIGBITS;

module.exports = {
  clone: function(o) {
    var _o, key, value;
    if (typeof o === 'object') {
      if (Array.isArray(o)) {
        return o.map((function(_this) {
          return function(v) {
            return _this.clone(v);
          };
        })(this));
      } else {
        _o = {};
        for (key in o) {
          value = o[key];
          _o[key] = this.clone(value);
        }
        return _o;
      }
    }
    return o;
  },
  defaults: function() {
    var _o, i, key, len, o, value;
    o = {};
    for (i = 0, len = arguments.length; i < len; i++) {
      _o = arguments[i];
      for (key in _o) {
        value = _o[key];
        if (o[key] == null) {
          o[key] = this.clone(value);
        }
      }
    }
    return o;
  },
  hexToRgb: function(hex) {
    var m;
    m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (m != null) {
      return [m[1], m[2], m[3]].map(function(s) {
        return parseInt(s, 16);
      });
    }
    return null;
  },
  rgbToHex: function(r, g, b) {
    return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1, 7);
  },
  rgbToHsl: function(r, g, b) {
    var d, h, l, max, min, s;
    r /= 255;
    g /= 255;
    b /= 255;
    max = Math.max(r, g, b);
    min = Math.min(r, g, b);
    h = void 0;
    s = void 0;
    l = (max + min) / 2;
    if (max === min) {
      h = s = 0;
    } else {
      d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      switch (max) {
        case r:
          h = (g - b) / d + (g < b ? 6 : 0);
          break;
        case g:
          h = (b - r) / d + 2;
          break;
        case b:
          h = (r - g) / d + 4;
      }
      h /= 6;
    }
    return [h, s, l];
  },
  hslToRgb: function(h, s, l) {
    var b, g, hue2rgb, p, q, r;
    r = void 0;
    g = void 0;
    b = void 0;
    hue2rgb = function(p, q, t) {
      if (t < 0) {
        t += 1;
      }
      if (t > 1) {
        t -= 1;
      }
      if (t < 1 / 6) {
        return p + (q - p) * 6 * t;
      }
      if (t < 1 / 2) {
        return q;
      }
      if (t < 2 / 3) {
        return p + (q - p) * (2 / 3 - t) * 6;
      }
      return p;
    };
    if (s === 0) {
      r = g = b = l;
    } else {
      q = l < 0.5 ? l * (1 + s) : l + s - (l * s);
      p = 2 * l - q;
      r = hue2rgb(p, q, h + 1 / 3);
      g = hue2rgb(p, q, h);
      b = hue2rgb(p, q, h - (1 / 3));
    }
    return [r * 255, g * 255, b * 255];
  },
  rgbToXyz: function(r, g, b) {
    var x, y, z;
    r /= 255;
    g /= 255;
    b /= 255;
    r = r > 0.04045 ? Math.pow((r + 0.005) / 1.055, 2.4) : r / 12.92;
    g = g > 0.04045 ? Math.pow((g + 0.005) / 1.055, 2.4) : g / 12.92;
    b = b > 0.04045 ? Math.pow((b + 0.005) / 1.055, 2.4) : b / 12.92;
    r *= 100;
    g *= 100;
    b *= 100;
    x = r * 0.4124 + g * 0.3576 + b * 0.1805;
    y = r * 0.2126 + g * 0.7152 + b * 0.0722;
    z = r * 0.0193 + g * 0.1192 + b * 0.9505;
    return [x, y, z];
  },
  xyzToCIELab: function(x, y, z) {
    var L, REF_X, REF_Y, REF_Z, a, b;
    REF_X = 95.047;
    REF_Y = 100;
    REF_Z = 108.883;
    x /= REF_X;
    y /= REF_Y;
    z /= REF_Z;
    x = x > 0.008856 ? Math.pow(x, 1 / 3) : 7.787 * x + 16 / 116;
    y = y > 0.008856 ? Math.pow(y, 1 / 3) : 7.787 * y + 16 / 116;
    z = z > 0.008856 ? Math.pow(z, 1 / 3) : 7.787 * z + 16 / 116;
    L = 116 * y - 16;
    a = 500 * (x - y);
    b = 200 * (y - z);
    return [L, a, b];
  },
  rgbToCIELab: function(r, g, b) {
    var ref, x, y, z;
    ref = this.rgbToXyz(r, g, b), x = ref[0], y = ref[1], z = ref[2];
    return this.xyzToCIELab(x, y, z);
  },
  deltaE94: function(lab1, lab2) {
    var L1, L2, WEIGHT_C, WEIGHT_H, WEIGHT_L, a1, a2, b1, b2, dL, da, db, xC1, xC2, xDC, xDE, xDH, xDL, xSC, xSH;
    WEIGHT_L = 1;
    WEIGHT_C = 1;
    WEIGHT_H = 1;
    L1 = lab1[0], a1 = lab1[1], b1 = lab1[2];
    L2 = lab2[0], a2 = lab2[1], b2 = lab2[2];
    dL = L1 - L2;
    da = a1 - a2;
    db = b1 - b2;
    xC1 = Math.sqrt(a1 * a1 + b1 * b1);
    xC2 = Math.sqrt(a2 * a2 + b2 * b2);
    xDL = L2 - L1;
    xDC = xC2 - xC1;
    xDE = Math.sqrt(dL * dL + da * da + db * db);
    if (Math.sqrt(xDE) > Math.sqrt(Math.abs(xDL)) + Math.sqrt(Math.abs(xDC))) {
      xDH = Math.sqrt(xDE * xDE - xDL * xDL - xDC * xDC);
    } else {
      xDH = 0;
    }
    xSC = 1 + 0.045 * xC1;
    xSH = 1 + 0.015 * xC1;
    xDL /= WEIGHT_L;
    xDC /= WEIGHT_C * xSC;
    xDH /= WEIGHT_H * xSH;
    return Math.sqrt(xDL * xDL + xDC * xDC + xDH * xDH);
  },
  rgbDiff: function(rgb1, rgb2) {
    var lab1, lab2;
    lab1 = this.rgbToCIELab.apply(this, rgb1);
    lab2 = this.rgbToCIELab.apply(this, rgb2);
    return this.deltaE94(lab1, lab2);
  },
  hexDiff: function(hex1, hex2) {
    var rgb1, rgb2;
    rgb1 = this.hexToRgb(hex1);
    rgb2 = this.hexToRgb(hex2);
    return this.rgbDiff(rgb1, rgb2);
  },
  DELTAE94_DIFF_STATUS: DELTAE94,
  getColorDiffStatus: function(d) {
    if (d < DELTAE94.NA) {
      return "N/A";
    }
    if (d <= DELTAE94.PERFECT) {
      return "Perfect";
    }
    if (d <= DELTAE94.CLOSE) {
      return "Close";
    }
    if (d <= DELTAE94.GOOD) {
      return "Good";
    }
    if (d < DELTAE94.SIMILAR) {
      return "Similar";
    }
    return "Wrong";
  },
  SIGBITS: SIGBITS,
  RSHIFT: RSHIFT,
  getColorIndex: function(r, g, b) {
    return (r << (2 * SIGBITS)) + (g << SIGBITS) + b;
  }
};


},{}],22:[function(require,module,exports){

/*
  From Vibrant.js by Jari Zwarts
  Ported to node.js by AKFish

  Color algorithm class that finds variations on colors in an image.

  Credits
  --------
  Lokesh Dhakar (http://www.lokeshdhakar.com) - Created ColorThief
  Google - Palette support library in Android
 */
var Builder, DefaultGenerator, Filter, Swatch, Vibrant, util,
  bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

Swatch = require('./swatch');

util = require('./util');

DefaultGenerator = require('./generator').Default;

Filter = require('./filter');

module.exports = Vibrant = (function() {
  Vibrant.DefaultOpts = {
    colorCount: 16,
    quality: 5,
    generator: new DefaultGenerator(),
    Image: null,
    Quantizer: require('./quantizer').MMCQ,
    filters: []
  };

  Vibrant.from = function(src) {
    return new Builder(src);
  };

  Vibrant.prototype.quantize = require('quantize');

  Vibrant.prototype._swatches = [];

  function Vibrant(sourceImage, opts) {
    this.sourceImage = sourceImage;
    if (opts == null) {
      opts = {};
    }
    this.swatches = bind(this.swatches, this);
    this.opts = util.defaults(opts, this.constructor.DefaultOpts);
    this.generator = this.opts.generator;
  }

  Vibrant.prototype.getPalette = function(cb) {
    var image;
    return image = new this.opts.Image(this.sourceImage, (function(_this) {
      return function(err, image) {
        var error;
        if (err != null) {
          return cb(err);
        }
        try {
          _this._process(image, _this.opts);
          return cb(null, _this.swatches());
        } catch (error1) {
          error = error1;
          return cb(error);
        }
      };
    })(this));
  };

  Vibrant.prototype.getSwatches = function(cb) {
    return this.getPalette(cb);
  };

  Vibrant.prototype._process = function(image, opts) {
    var imageData, quantizer;
    image.scaleDown(this.opts);
    imageData = image.getImageData();
    quantizer = new this.opts.Quantizer();
    quantizer.initialize(imageData.data, this.opts);
    this.all_swatches = quantizer.getQuantizedColors();
    return image.removeCanvas();
  };

  Vibrant.prototype.swatches = function() {
    return this.all_swatches;
  };

  return Vibrant;

})();

module.exports.Builder = Builder = (function() {
  function Builder(src1, opts1) {
    this.src = src1;
    this.opts = opts1 != null ? opts1 : {};
    this.opts.filters = util.clone(Vibrant.DefaultOpts.filters);
  }

  Builder.prototype.maxColorCount = function(n) {
    this.opts.colorCount = n;
    return this;
  };

  Builder.prototype.maxDimension = function(d) {
    this.opts.maxDimension = d;
    return this;
  };

  Builder.prototype.addFilter = function(f) {
    if (typeof f === 'function') {
      this.opts.filters.push(f);
    }
    return this;
  };

  Builder.prototype.removeFilter = function(f) {
    var i;
    if ((i = this.opts.filters.indexOf(f)) > 0) {
      this.opts.filters.splice(i);
    }
    return this;
  };

  Builder.prototype.clearFilters = function() {
    this.opts.filters = [];
    return this;
  };

  Builder.prototype.quality = function(q) {
    this.opts.quality = q;
    return this;
  };

  Builder.prototype.useImage = function(image) {
    this.opts.Image = image;
    return this;
  };

  Builder.prototype.useGenerator = function(generator) {
    this.opts.generator = generator;
    return this;
  };

  Builder.prototype.useQuantizer = function(quantizer) {
    this.opts.Quantizer = quantizer;
    return this;
  };

  Builder.prototype.build = function() {
    if (this.v == null) {
      this.v = new Vibrant(this.src, this.opts);
    }
    return this.v;
  };

  Builder.prototype.getSwatches = function(cb) {
    return this.build().getPalette(cb);
  };

  Builder.prototype.getPalette = function(cb) {
    return this.build().getPalette(cb);
  };

  Builder.prototype.from = function(src) {
    return new Vibrant(src, this.opts);
  };

  return Builder;

})();

module.exports.Util = util;

module.exports.Swatch = Swatch;

module.exports.Quantizer = require('./quantizer/');

module.exports.Generator = require('./generator/');

module.exports.Filter = require('./filter/');


},{"./filter":10,"./filter/":10,"./generator":12,"./generator/":12,"./quantizer":18,"./quantizer/":18,"./swatch":20,"./util":21,"quantize":3}]},{},[8])
//# sourceMappingURL=data:application/json;charset:utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvdXJsL3VybC5qcyIsIm5vZGVfbW9kdWxlcy9wdW55Y29kZS9wdW55Y29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWFudGl6ZS9xdWFudGl6ZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvZGVjb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9lbmNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2luZGV4LmpzIiwic3JjL2Jyb3dzZXIuY29mZmVlIiwic3JjL2J1bmRsZS5jb2ZmZWUiLCJzcmMvZmlsdGVyL2RlZmF1bHQuY29mZmVlIiwic3JjL2ZpbHRlci9pbmRleC5jb2ZmZWUiLCJzcmMvZ2VuZXJhdG9yL2RlZmF1bHQuY29mZmVlIiwic3JjL2dlbmVyYXRvci9pbmRleC5jb2ZmZWUiLCJzcmMvaW1hZ2UvYnJvd3Nlci5jb2ZmZWUiLCJzcmMvaW1hZ2UvaW5kZXguY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL21tY3EuY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL3BxdWV1ZS5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2ltcGwvdmJveC5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2luZGV4LmNvZmZlZSIsInNyYy9xdWFudGl6ZXIvbW1jcS5jb2ZmZWUiLCJzcmMvc3dhdGNoLmNvZmZlZSIsInNyYy91dGlsLmNvZmZlZSIsInNyYy92aWJyYW50LmNvZmZlZSJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDbnNCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7QUNyaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMWVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3BGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDbktBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzFCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDdkdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzVDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUMvRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3BEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3pQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDakNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDM0VBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDcE9BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gZSh0LG4scil7ZnVuY3Rpb24gcyhvLHUpe2lmKCFuW29dKXtpZighdFtvXSl7dmFyIGE9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtpZighdSYmYSlyZXR1cm4gYShvLCEwKTtpZihpKXJldHVybiBpKG8sITApO3ZhciBmPW5ldyBFcnJvcihcIkNhbm5vdCBmaW5kIG1vZHVsZSAnXCIrbytcIidcIik7dGhyb3cgZi5jb2RlPVwiTU9EVUxFX05PVF9GT1VORFwiLGZ9dmFyIGw9bltvXT17ZXhwb3J0czp7fX07dFtvXVswXS5jYWxsKGwuZXhwb3J0cyxmdW5jdGlvbihlKXt2YXIgbj10W29dWzFdW2VdO3JldHVybiBzKG4/bjplKX0sbCxsLmV4cG9ydHMsZSx0LG4scil9cmV0dXJuIG5bb10uZXhwb3J0c312YXIgaT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2Zvcih2YXIgbz0wO288ci5sZW5ndGg7bysrKXMocltvXSk7cmV0dXJuIHN9KSIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG52YXIgcHVueWNvZGUgPSByZXF1aXJlKCdwdW55Y29kZScpO1xuXG5leHBvcnRzLnBhcnNlID0gdXJsUGFyc2U7XG5leHBvcnRzLnJlc29sdmUgPSB1cmxSZXNvbHZlO1xuZXhwb3J0cy5yZXNvbHZlT2JqZWN0ID0gdXJsUmVzb2x2ZU9iamVjdDtcbmV4cG9ydHMuZm9ybWF0ID0gdXJsRm9ybWF0O1xuXG5leHBvcnRzLlVybCA9IFVybDtcblxuZnVuY3Rpb24gVXJsKCkge1xuICB0aGlzLnByb3RvY29sID0gbnVsbDtcbiAgdGhpcy5zbGFzaGVzID0gbnVsbDtcbiAgdGhpcy5hdXRoID0gbnVsbDtcbiAgdGhpcy5ob3N0ID0gbnVsbDtcbiAgdGhpcy5wb3J0ID0gbnVsbDtcbiAgdGhpcy5ob3N0bmFtZSA9IG51bGw7XG4gIHRoaXMuaGFzaCA9IG51bGw7XG4gIHRoaXMuc2VhcmNoID0gbnVsbDtcbiAgdGhpcy5xdWVyeSA9IG51bGw7XG4gIHRoaXMucGF0aG5hbWUgPSBudWxsO1xuICB0aGlzLnBhdGggPSBudWxsO1xuICB0aGlzLmhyZWYgPSBudWxsO1xufVxuXG4vLyBSZWZlcmVuY2U6IFJGQyAzOTg2LCBSRkMgMTgwOCwgUkZDIDIzOTZcblxuLy8gZGVmaW5lIHRoZXNlIGhlcmUgc28gYXQgbGVhc3QgdGhleSBvbmx5IGhhdmUgdG8gYmVcbi8vIGNvbXBpbGVkIG9uY2Ugb24gdGhlIGZpcnN0IG1vZHVsZSBsb2FkLlxudmFyIHByb3RvY29sUGF0dGVybiA9IC9eKFthLXowLTkuKy1dKzopL2ksXG4gICAgcG9ydFBhdHRlcm4gPSAvOlswLTldKiQvLFxuXG4gICAgLy8gUkZDIDIzOTY6IGNoYXJhY3RlcnMgcmVzZXJ2ZWQgZm9yIGRlbGltaXRpbmcgVVJMcy5cbiAgICAvLyBXZSBhY3R1YWxseSBqdXN0IGF1dG8tZXNjYXBlIHRoZXNlLlxuICAgIGRlbGltcyA9IFsnPCcsICc+JywgJ1wiJywgJ2AnLCAnICcsICdcXHInLCAnXFxuJywgJ1xcdCddLFxuXG4gICAgLy8gUkZDIDIzOTY6IGNoYXJhY3RlcnMgbm90IGFsbG93ZWQgZm9yIHZhcmlvdXMgcmVhc29ucy5cbiAgICB1bndpc2UgPSBbJ3snLCAnfScsICd8JywgJ1xcXFwnLCAnXicsICdgJ10uY29uY2F0KGRlbGltcyksXG5cbiAgICAvLyBBbGxvd2VkIGJ5IFJGQ3MsIGJ1dCBjYXVzZSBvZiBYU1MgYXR0YWNrcy4gIEFsd2F5cyBlc2NhcGUgdGhlc2UuXG4gICAgYXV0b0VzY2FwZSA9IFsnXFwnJ10uY29uY2F0KHVud2lzZSksXG4gICAgLy8gQ2hhcmFjdGVycyB0aGF0IGFyZSBuZXZlciBldmVyIGFsbG93ZWQgaW4gYSBob3N0bmFtZS5cbiAgICAvLyBOb3RlIHRoYXQgYW55IGludmFsaWQgY2hhcnMgYXJlIGFsc28gaGFuZGxlZCwgYnV0IHRoZXNlXG4gICAgLy8gYXJlIHRoZSBvbmVzIHRoYXQgYXJlICpleHBlY3RlZCogdG8gYmUgc2Vlbiwgc28gd2UgZmFzdC1wYXRoXG4gICAgLy8gdGhlbS5cbiAgICBub25Ib3N0Q2hhcnMgPSBbJyUnLCAnLycsICc/JywgJzsnLCAnIyddLmNvbmNhdChhdXRvRXNjYXBlKSxcbiAgICBob3N0RW5kaW5nQ2hhcnMgPSBbJy8nLCAnPycsICcjJ10sXG4gICAgaG9zdG5hbWVNYXhMZW4gPSAyNTUsXG4gICAgaG9zdG5hbWVQYXJ0UGF0dGVybiA9IC9eW2EtejAtOUEtWl8tXXswLDYzfSQvLFxuICAgIGhvc3RuYW1lUGFydFN0YXJ0ID0gL14oW2EtejAtOUEtWl8tXXswLDYzfSkoLiopJC8sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgY2FuIGFsbG93IFwidW5zYWZlXCIgYW5kIFwidW53aXNlXCIgY2hhcnMuXG4gICAgdW5zYWZlUHJvdG9jb2wgPSB7XG4gICAgICAnamF2YXNjcmlwdCc6IHRydWUsXG4gICAgICAnamF2YXNjcmlwdDonOiB0cnVlXG4gICAgfSxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBuZXZlciBoYXZlIGEgaG9zdG5hbWUuXG4gICAgaG9zdGxlc3NQcm90b2NvbCA9IHtcbiAgICAgICdqYXZhc2NyaXB0JzogdHJ1ZSxcbiAgICAgICdqYXZhc2NyaXB0Oic6IHRydWVcbiAgICB9LFxuICAgIC8vIHByb3RvY29scyB0aGF0IGFsd2F5cyBjb250YWluIGEgLy8gYml0LlxuICAgIHNsYXNoZWRQcm90b2NvbCA9IHtcbiAgICAgICdodHRwJzogdHJ1ZSxcbiAgICAgICdodHRwcyc6IHRydWUsXG4gICAgICAnZnRwJzogdHJ1ZSxcbiAgICAgICdnb3BoZXInOiB0cnVlLFxuICAgICAgJ2ZpbGUnOiB0cnVlLFxuICAgICAgJ2h0dHA6JzogdHJ1ZSxcbiAgICAgICdodHRwczonOiB0cnVlLFxuICAgICAgJ2Z0cDonOiB0cnVlLFxuICAgICAgJ2dvcGhlcjonOiB0cnVlLFxuICAgICAgJ2ZpbGU6JzogdHJ1ZVxuICAgIH0sXG4gICAgcXVlcnlzdHJpbmcgPSByZXF1aXJlKCdxdWVyeXN0cmluZycpO1xuXG5mdW5jdGlvbiB1cmxQYXJzZSh1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KSB7XG4gIGlmICh1cmwgJiYgaXNPYmplY3QodXJsKSAmJiB1cmwgaW5zdGFuY2VvZiBVcmwpIHJldHVybiB1cmw7XG5cbiAgdmFyIHUgPSBuZXcgVXJsO1xuICB1LnBhcnNlKHVybCwgcGFyc2VRdWVyeVN0cmluZywgc2xhc2hlc0Rlbm90ZUhvc3QpO1xuICByZXR1cm4gdTtcbn1cblxuVXJsLnByb3RvdHlwZS5wYXJzZSA9IGZ1bmN0aW9uKHVybCwgcGFyc2VRdWVyeVN0cmluZywgc2xhc2hlc0Rlbm90ZUhvc3QpIHtcbiAgaWYgKCFpc1N0cmluZyh1cmwpKSB7XG4gICAgdGhyb3cgbmV3IFR5cGVFcnJvcihcIlBhcmFtZXRlciAndXJsJyBtdXN0IGJlIGEgc3RyaW5nLCBub3QgXCIgKyB0eXBlb2YgdXJsKTtcbiAgfVxuXG4gIHZhciByZXN0ID0gdXJsO1xuXG4gIC8vIHRyaW0gYmVmb3JlIHByb2NlZWRpbmcuXG4gIC8vIFRoaXMgaXMgdG8gc3VwcG9ydCBwYXJzZSBzdHVmZiBsaWtlIFwiICBodHRwOi8vZm9vLmNvbSAgXFxuXCJcbiAgcmVzdCA9IHJlc3QudHJpbSgpO1xuXG4gIHZhciBwcm90byA9IHByb3RvY29sUGF0dGVybi5leGVjKHJlc3QpO1xuICBpZiAocHJvdG8pIHtcbiAgICBwcm90byA9IHByb3RvWzBdO1xuICAgIHZhciBsb3dlclByb3RvID0gcHJvdG8udG9Mb3dlckNhc2UoKTtcbiAgICB0aGlzLnByb3RvY29sID0gbG93ZXJQcm90bztcbiAgICByZXN0ID0gcmVzdC5zdWJzdHIocHJvdG8ubGVuZ3RoKTtcbiAgfVxuXG4gIC8vIGZpZ3VyZSBvdXQgaWYgaXQncyBnb3QgYSBob3N0XG4gIC8vIHVzZXJAc2VydmVyIGlzICphbHdheXMqIGludGVycHJldGVkIGFzIGEgaG9zdG5hbWUsIGFuZCB1cmxcbiAgLy8gcmVzb2x1dGlvbiB3aWxsIHRyZWF0IC8vZm9vL2JhciBhcyBob3N0PWZvbyxwYXRoPWJhciBiZWNhdXNlIHRoYXQnc1xuICAvLyBob3cgdGhlIGJyb3dzZXIgcmVzb2x2ZXMgcmVsYXRpdmUgVVJMcy5cbiAgaWYgKHNsYXNoZXNEZW5vdGVIb3N0IHx8IHByb3RvIHx8IHJlc3QubWF0Y2goL15cXC9cXC9bXkBcXC9dK0BbXkBcXC9dKy8pKSB7XG4gICAgdmFyIHNsYXNoZXMgPSByZXN0LnN1YnN0cigwLCAyKSA9PT0gJy8vJztcbiAgICBpZiAoc2xhc2hlcyAmJiAhKHByb3RvICYmIGhvc3RsZXNzUHJvdG9jb2xbcHJvdG9dKSkge1xuICAgICAgcmVzdCA9IHJlc3Quc3Vic3RyKDIpO1xuICAgICAgdGhpcy5zbGFzaGVzID0gdHJ1ZTtcbiAgICB9XG4gIH1cblxuICBpZiAoIWhvc3RsZXNzUHJvdG9jb2xbcHJvdG9dICYmXG4gICAgICAoc2xhc2hlcyB8fCAocHJvdG8gJiYgIXNsYXNoZWRQcm90b2NvbFtwcm90b10pKSkge1xuXG4gICAgLy8gdGhlcmUncyBhIGhvc3RuYW1lLlxuICAgIC8vIHRoZSBmaXJzdCBpbnN0YW5jZSBvZiAvLCA/LCA7LCBvciAjIGVuZHMgdGhlIGhvc3QuXG4gICAgLy9cbiAgICAvLyBJZiB0aGVyZSBpcyBhbiBAIGluIHRoZSBob3N0bmFtZSwgdGhlbiBub24taG9zdCBjaGFycyAqYXJlKiBhbGxvd2VkXG4gICAgLy8gdG8gdGhlIGxlZnQgb2YgdGhlIGxhc3QgQCBzaWduLCB1bmxlc3Mgc29tZSBob3N0LWVuZGluZyBjaGFyYWN0ZXJcbiAgICAvLyBjb21lcyAqYmVmb3JlKiB0aGUgQC1zaWduLlxuICAgIC8vIFVSTHMgYXJlIG9ibm94aW91cy5cbiAgICAvL1xuICAgIC8vIGV4OlxuICAgIC8vIGh0dHA6Ly9hQGJAYy8gPT4gdXNlcjphQGIgaG9zdDpjXG4gICAgLy8gaHR0cDovL2FAYj9AYyA9PiB1c2VyOmEgaG9zdDpjIHBhdGg6Lz9AY1xuXG4gICAgLy8gdjAuMTIgVE9ETyhpc2FhY3MpOiBUaGlzIGlzIG5vdCBxdWl0ZSBob3cgQ2hyb21lIGRvZXMgdGhpbmdzLlxuICAgIC8vIFJldmlldyBvdXIgdGVzdCBjYXNlIGFnYWluc3QgYnJvd3NlcnMgbW9yZSBjb21wcmVoZW5zaXZlbHkuXG5cbiAgICAvLyBmaW5kIHRoZSBmaXJzdCBpbnN0YW5jZSBvZiBhbnkgaG9zdEVuZGluZ0NoYXJzXG4gICAgdmFyIGhvc3RFbmQgPSAtMTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGhvc3RFbmRpbmdDaGFycy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIGhlYyA9IHJlc3QuaW5kZXhPZihob3N0RW5kaW5nQ2hhcnNbaV0pO1xuICAgICAgaWYgKGhlYyAhPT0gLTEgJiYgKGhvc3RFbmQgPT09IC0xIHx8IGhlYyA8IGhvc3RFbmQpKVxuICAgICAgICBob3N0RW5kID0gaGVjO1xuICAgIH1cblxuICAgIC8vIGF0IHRoaXMgcG9pbnQsIGVpdGhlciB3ZSBoYXZlIGFuIGV4cGxpY2l0IHBvaW50IHdoZXJlIHRoZVxuICAgIC8vIGF1dGggcG9ydGlvbiBjYW5ub3QgZ28gcGFzdCwgb3IgdGhlIGxhc3QgQCBjaGFyIGlzIHRoZSBkZWNpZGVyLlxuICAgIHZhciBhdXRoLCBhdFNpZ247XG4gICAgaWYgKGhvc3RFbmQgPT09IC0xKSB7XG4gICAgICAvLyBhdFNpZ24gY2FuIGJlIGFueXdoZXJlLlxuICAgICAgYXRTaWduID0gcmVzdC5sYXN0SW5kZXhPZignQCcpO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBhdFNpZ24gbXVzdCBiZSBpbiBhdXRoIHBvcnRpb24uXG4gICAgICAvLyBodHRwOi8vYUBiL2NAZCA9PiBob3N0OmIgYXV0aDphIHBhdGg6L2NAZFxuICAgICAgYXRTaWduID0gcmVzdC5sYXN0SW5kZXhPZignQCcsIGhvc3RFbmQpO1xuICAgIH1cblxuICAgIC8vIE5vdyB3ZSBoYXZlIGEgcG9ydGlvbiB3aGljaCBpcyBkZWZpbml0ZWx5IHRoZSBhdXRoLlxuICAgIC8vIFB1bGwgdGhhdCBvZmYuXG4gICAgaWYgKGF0U2lnbiAhPT0gLTEpIHtcbiAgICAgIGF1dGggPSByZXN0LnNsaWNlKDAsIGF0U2lnbik7XG4gICAgICByZXN0ID0gcmVzdC5zbGljZShhdFNpZ24gKyAxKTtcbiAgICAgIHRoaXMuYXV0aCA9IGRlY29kZVVSSUNvbXBvbmVudChhdXRoKTtcbiAgICB9XG5cbiAgICAvLyB0aGUgaG9zdCBpcyB0aGUgcmVtYWluaW5nIHRvIHRoZSBsZWZ0IG9mIHRoZSBmaXJzdCBub24taG9zdCBjaGFyXG4gICAgaG9zdEVuZCA9IC0xO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbm9uSG9zdENoYXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgaGVjID0gcmVzdC5pbmRleE9mKG5vbkhvc3RDaGFyc1tpXSk7XG4gICAgICBpZiAoaGVjICE9PSAtMSAmJiAoaG9zdEVuZCA9PT0gLTEgfHwgaGVjIDwgaG9zdEVuZCkpXG4gICAgICAgIGhvc3RFbmQgPSBoZWM7XG4gICAgfVxuICAgIC8vIGlmIHdlIHN0aWxsIGhhdmUgbm90IGhpdCBpdCwgdGhlbiB0aGUgZW50aXJlIHRoaW5nIGlzIGEgaG9zdC5cbiAgICBpZiAoaG9zdEVuZCA9PT0gLTEpXG4gICAgICBob3N0RW5kID0gcmVzdC5sZW5ndGg7XG5cbiAgICB0aGlzLmhvc3QgPSByZXN0LnNsaWNlKDAsIGhvc3RFbmQpO1xuICAgIHJlc3QgPSByZXN0LnNsaWNlKGhvc3RFbmQpO1xuXG4gICAgLy8gcHVsbCBvdXQgcG9ydC5cbiAgICB0aGlzLnBhcnNlSG9zdCgpO1xuXG4gICAgLy8gd2UndmUgaW5kaWNhdGVkIHRoYXQgdGhlcmUgaXMgYSBob3N0bmFtZSxcbiAgICAvLyBzbyBldmVuIGlmIGl0J3MgZW1wdHksIGl0IGhhcyB0byBiZSBwcmVzZW50LlxuICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lIHx8ICcnO1xuXG4gICAgLy8gaWYgaG9zdG5hbWUgYmVnaW5zIHdpdGggWyBhbmQgZW5kcyB3aXRoIF1cbiAgICAvLyBhc3N1bWUgdGhhdCBpdCdzIGFuIElQdjYgYWRkcmVzcy5cbiAgICB2YXIgaXB2Nkhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZVswXSA9PT0gJ1snICYmXG4gICAgICAgIHRoaXMuaG9zdG5hbWVbdGhpcy5ob3N0bmFtZS5sZW5ndGggLSAxXSA9PT0gJ10nO1xuXG4gICAgLy8gdmFsaWRhdGUgYSBsaXR0bGUuXG4gICAgaWYgKCFpcHY2SG9zdG5hbWUpIHtcbiAgICAgIHZhciBob3N0cGFydHMgPSB0aGlzLmhvc3RuYW1lLnNwbGl0KC9cXC4vKTtcbiAgICAgIGZvciAodmFyIGkgPSAwLCBsID0gaG9zdHBhcnRzLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgICAgICB2YXIgcGFydCA9IGhvc3RwYXJ0c1tpXTtcbiAgICAgICAgaWYgKCFwYXJ0KSBjb250aW51ZTtcbiAgICAgICAgaWYgKCFwYXJ0Lm1hdGNoKGhvc3RuYW1lUGFydFBhdHRlcm4pKSB7XG4gICAgICAgICAgdmFyIG5ld3BhcnQgPSAnJztcbiAgICAgICAgICBmb3IgKHZhciBqID0gMCwgayA9IHBhcnQubGVuZ3RoOyBqIDwgazsgaisrKSB7XG4gICAgICAgICAgICBpZiAocGFydC5jaGFyQ29kZUF0KGopID4gMTI3KSB7XG4gICAgICAgICAgICAgIC8vIHdlIHJlcGxhY2Ugbm9uLUFTQ0lJIGNoYXIgd2l0aCBhIHRlbXBvcmFyeSBwbGFjZWhvbGRlclxuICAgICAgICAgICAgICAvLyB3ZSBuZWVkIHRoaXMgdG8gbWFrZSBzdXJlIHNpemUgb2YgaG9zdG5hbWUgaXMgbm90XG4gICAgICAgICAgICAgIC8vIGJyb2tlbiBieSByZXBsYWNpbmcgbm9uLUFTQ0lJIGJ5IG5vdGhpbmdcbiAgICAgICAgICAgICAgbmV3cGFydCArPSAneCc7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBuZXdwYXJ0ICs9IHBhcnRbal07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIC8vIHdlIHRlc3QgYWdhaW4gd2l0aCBBU0NJSSBjaGFyIG9ubHlcbiAgICAgICAgICBpZiAoIW5ld3BhcnQubWF0Y2goaG9zdG5hbWVQYXJ0UGF0dGVybikpIHtcbiAgICAgICAgICAgIHZhciB2YWxpZFBhcnRzID0gaG9zdHBhcnRzLnNsaWNlKDAsIGkpO1xuICAgICAgICAgICAgdmFyIG5vdEhvc3QgPSBob3N0cGFydHMuc2xpY2UoaSArIDEpO1xuICAgICAgICAgICAgdmFyIGJpdCA9IHBhcnQubWF0Y2goaG9zdG5hbWVQYXJ0U3RhcnQpO1xuICAgICAgICAgICAgaWYgKGJpdCkge1xuICAgICAgICAgICAgICB2YWxpZFBhcnRzLnB1c2goYml0WzFdKTtcbiAgICAgICAgICAgICAgbm90SG9zdC51bnNoaWZ0KGJpdFsyXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAobm90SG9zdC5sZW5ndGgpIHtcbiAgICAgICAgICAgICAgcmVzdCA9ICcvJyArIG5vdEhvc3Quam9pbignLicpICsgcmVzdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHRoaXMuaG9zdG5hbWUgPSB2YWxpZFBhcnRzLmpvaW4oJy4nKTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmICh0aGlzLmhvc3RuYW1lLmxlbmd0aCA+IGhvc3RuYW1lTWF4TGVuKSB7XG4gICAgICB0aGlzLmhvc3RuYW1lID0gJyc7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIGhvc3RuYW1lcyBhcmUgYWx3YXlzIGxvd2VyIGNhc2UuXG4gICAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZS50b0xvd2VyQ2FzZSgpO1xuICAgIH1cblxuICAgIGlmICghaXB2Nkhvc3RuYW1lKSB7XG4gICAgICAvLyBJRE5BIFN1cHBvcnQ6IFJldHVybnMgYSBwdW55IGNvZGVkIHJlcHJlc2VudGF0aW9uIG9mIFwiZG9tYWluXCIuXG4gICAgICAvLyBJdCBvbmx5IGNvbnZlcnRzIHRoZSBwYXJ0IG9mIHRoZSBkb21haW4gbmFtZSB0aGF0XG4gICAgICAvLyBoYXMgbm9uIEFTQ0lJIGNoYXJhY3RlcnMuIEkuZS4gaXQgZG9zZW50IG1hdHRlciBpZlxuICAgICAgLy8geW91IGNhbGwgaXQgd2l0aCBhIGRvbWFpbiB0aGF0IGFscmVhZHkgaXMgaW4gQVNDSUkuXG4gICAgICB2YXIgZG9tYWluQXJyYXkgPSB0aGlzLmhvc3RuYW1lLnNwbGl0KCcuJyk7XG4gICAgICB2YXIgbmV3T3V0ID0gW107XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGRvbWFpbkFycmF5Lmxlbmd0aDsgKytpKSB7XG4gICAgICAgIHZhciBzID0gZG9tYWluQXJyYXlbaV07XG4gICAgICAgIG5ld091dC5wdXNoKHMubWF0Y2goL1teQS1aYS16MC05Xy1dLykgP1xuICAgICAgICAgICAgJ3huLS0nICsgcHVueWNvZGUuZW5jb2RlKHMpIDogcyk7XG4gICAgICB9XG4gICAgICB0aGlzLmhvc3RuYW1lID0gbmV3T3V0LmpvaW4oJy4nKTtcbiAgICB9XG5cbiAgICB2YXIgcCA9IHRoaXMucG9ydCA/ICc6JyArIHRoaXMucG9ydCA6ICcnO1xuICAgIHZhciBoID0gdGhpcy5ob3N0bmFtZSB8fCAnJztcbiAgICB0aGlzLmhvc3QgPSBoICsgcDtcbiAgICB0aGlzLmhyZWYgKz0gdGhpcy5ob3N0O1xuXG4gICAgLy8gc3RyaXAgWyBhbmQgXSBmcm9tIHRoZSBob3N0bmFtZVxuICAgIC8vIHRoZSBob3N0IGZpZWxkIHN0aWxsIHJldGFpbnMgdGhlbSwgdGhvdWdoXG4gICAgaWYgKGlwdjZIb3N0bmFtZSkge1xuICAgICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUuc3Vic3RyKDEsIHRoaXMuaG9zdG5hbWUubGVuZ3RoIC0gMik7XG4gICAgICBpZiAocmVzdFswXSAhPT0gJy8nKSB7XG4gICAgICAgIHJlc3QgPSAnLycgKyByZXN0O1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIC8vIG5vdyByZXN0IGlzIHNldCB0byB0aGUgcG9zdC1ob3N0IHN0dWZmLlxuICAvLyBjaG9wIG9mZiBhbnkgZGVsaW0gY2hhcnMuXG4gIGlmICghdW5zYWZlUHJvdG9jb2xbbG93ZXJQcm90b10pIHtcblxuICAgIC8vIEZpcnN0LCBtYWtlIDEwMCUgc3VyZSB0aGF0IGFueSBcImF1dG9Fc2NhcGVcIiBjaGFycyBnZXRcbiAgICAvLyBlc2NhcGVkLCBldmVuIGlmIGVuY29kZVVSSUNvbXBvbmVudCBkb2Vzbid0IHRoaW5rIHRoZXlcbiAgICAvLyBuZWVkIHRvIGJlLlxuICAgIGZvciAodmFyIGkgPSAwLCBsID0gYXV0b0VzY2FwZS5sZW5ndGg7IGkgPCBsOyBpKyspIHtcbiAgICAgIHZhciBhZSA9IGF1dG9Fc2NhcGVbaV07XG4gICAgICB2YXIgZXNjID0gZW5jb2RlVVJJQ29tcG9uZW50KGFlKTtcbiAgICAgIGlmIChlc2MgPT09IGFlKSB7XG4gICAgICAgIGVzYyA9IGVzY2FwZShhZSk7XG4gICAgICB9XG4gICAgICByZXN0ID0gcmVzdC5zcGxpdChhZSkuam9pbihlc2MpO1xuICAgIH1cbiAgfVxuXG5cbiAgLy8gY2hvcCBvZmYgZnJvbSB0aGUgdGFpbCBmaXJzdC5cbiAgdmFyIGhhc2ggPSByZXN0LmluZGV4T2YoJyMnKTtcbiAgaWYgKGhhc2ggIT09IC0xKSB7XG4gICAgLy8gZ290IGEgZnJhZ21lbnQgc3RyaW5nLlxuICAgIHRoaXMuaGFzaCA9IHJlc3Quc3Vic3RyKGhhc2gpO1xuICAgIHJlc3QgPSByZXN0LnNsaWNlKDAsIGhhc2gpO1xuICB9XG4gIHZhciBxbSA9IHJlc3QuaW5kZXhPZignPycpO1xuICBpZiAocW0gIT09IC0xKSB7XG4gICAgdGhpcy5zZWFyY2ggPSByZXN0LnN1YnN0cihxbSk7XG4gICAgdGhpcy5xdWVyeSA9IHJlc3Quc3Vic3RyKHFtICsgMSk7XG4gICAgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAgIHRoaXMucXVlcnkgPSBxdWVyeXN0cmluZy5wYXJzZSh0aGlzLnF1ZXJ5KTtcbiAgICB9XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoMCwgcW0pO1xuICB9IGVsc2UgaWYgKHBhcnNlUXVlcnlTdHJpbmcpIHtcbiAgICAvLyBubyBxdWVyeSBzdHJpbmcsIGJ1dCBwYXJzZVF1ZXJ5U3RyaW5nIHN0aWxsIHJlcXVlc3RlZFxuICAgIHRoaXMuc2VhcmNoID0gJyc7XG4gICAgdGhpcy5xdWVyeSA9IHt9O1xuICB9XG4gIGlmIChyZXN0KSB0aGlzLnBhdGhuYW1lID0gcmVzdDtcbiAgaWYgKHNsYXNoZWRQcm90b2NvbFtsb3dlclByb3RvXSAmJlxuICAgICAgdGhpcy5ob3N0bmFtZSAmJiAhdGhpcy5wYXRobmFtZSkge1xuICAgIHRoaXMucGF0aG5hbWUgPSAnLyc7XG4gIH1cblxuICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gIGlmICh0aGlzLnBhdGhuYW1lIHx8IHRoaXMuc2VhcmNoKSB7XG4gICAgdmFyIHAgPSB0aGlzLnBhdGhuYW1lIHx8ICcnO1xuICAgIHZhciBzID0gdGhpcy5zZWFyY2ggfHwgJyc7XG4gICAgdGhpcy5wYXRoID0gcCArIHM7XG4gIH1cblxuICAvLyBmaW5hbGx5LCByZWNvbnN0cnVjdCB0aGUgaHJlZiBiYXNlZCBvbiB3aGF0IGhhcyBiZWVuIHZhbGlkYXRlZC5cbiAgdGhpcy5ocmVmID0gdGhpcy5mb3JtYXQoKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vLyBmb3JtYXQgYSBwYXJzZWQgb2JqZWN0IGludG8gYSB1cmwgc3RyaW5nXG5mdW5jdGlvbiB1cmxGb3JtYXQob2JqKSB7XG4gIC8vIGVuc3VyZSBpdCdzIGFuIG9iamVjdCwgYW5kIG5vdCBhIHN0cmluZyB1cmwuXG4gIC8vIElmIGl0J3MgYW4gb2JqLCB0aGlzIGlzIGEgbm8tb3AuXG4gIC8vIHRoaXMgd2F5LCB5b3UgY2FuIGNhbGwgdXJsX2Zvcm1hdCgpIG9uIHN0cmluZ3NcbiAgLy8gdG8gY2xlYW4gdXAgcG90ZW50aWFsbHkgd29ua3kgdXJscy5cbiAgaWYgKGlzU3RyaW5nKG9iaikpIG9iaiA9IHVybFBhcnNlKG9iaik7XG4gIGlmICghKG9iaiBpbnN0YW5jZW9mIFVybCkpIHJldHVybiBVcmwucHJvdG90eXBlLmZvcm1hdC5jYWxsKG9iaik7XG4gIHJldHVybiBvYmouZm9ybWF0KCk7XG59XG5cblVybC5wcm90b3R5cGUuZm9ybWF0ID0gZnVuY3Rpb24oKSB7XG4gIHZhciBhdXRoID0gdGhpcy5hdXRoIHx8ICcnO1xuICBpZiAoYXV0aCkge1xuICAgIGF1dGggPSBlbmNvZGVVUklDb21wb25lbnQoYXV0aCk7XG4gICAgYXV0aCA9IGF1dGgucmVwbGFjZSgvJTNBL2ksICc6Jyk7XG4gICAgYXV0aCArPSAnQCc7XG4gIH1cblxuICB2YXIgcHJvdG9jb2wgPSB0aGlzLnByb3RvY29sIHx8ICcnLFxuICAgICAgcGF0aG5hbWUgPSB0aGlzLnBhdGhuYW1lIHx8ICcnLFxuICAgICAgaGFzaCA9IHRoaXMuaGFzaCB8fCAnJyxcbiAgICAgIGhvc3QgPSBmYWxzZSxcbiAgICAgIHF1ZXJ5ID0gJyc7XG5cbiAgaWYgKHRoaXMuaG9zdCkge1xuICAgIGhvc3QgPSBhdXRoICsgdGhpcy5ob3N0O1xuICB9IGVsc2UgaWYgKHRoaXMuaG9zdG5hbWUpIHtcbiAgICBob3N0ID0gYXV0aCArICh0aGlzLmhvc3RuYW1lLmluZGV4T2YoJzonKSA9PT0gLTEgP1xuICAgICAgICB0aGlzLmhvc3RuYW1lIDpcbiAgICAgICAgJ1snICsgdGhpcy5ob3N0bmFtZSArICddJyk7XG4gICAgaWYgKHRoaXMucG9ydCkge1xuICAgICAgaG9zdCArPSAnOicgKyB0aGlzLnBvcnQ7XG4gICAgfVxuICB9XG5cbiAgaWYgKHRoaXMucXVlcnkgJiZcbiAgICAgIGlzT2JqZWN0KHRoaXMucXVlcnkpICYmXG4gICAgICBPYmplY3Qua2V5cyh0aGlzLnF1ZXJ5KS5sZW5ndGgpIHtcbiAgICBxdWVyeSA9IHF1ZXJ5c3RyaW5nLnN0cmluZ2lmeSh0aGlzLnF1ZXJ5KTtcbiAgfVxuXG4gIHZhciBzZWFyY2ggPSB0aGlzLnNlYXJjaCB8fCAocXVlcnkgJiYgKCc/JyArIHF1ZXJ5KSkgfHwgJyc7XG5cbiAgaWYgKHByb3RvY29sICYmIHByb3RvY29sLnN1YnN0cigtMSkgIT09ICc6JykgcHJvdG9jb2wgKz0gJzonO1xuXG4gIC8vIG9ubHkgdGhlIHNsYXNoZWRQcm90b2NvbHMgZ2V0IHRoZSAvLy4gIE5vdCBtYWlsdG86LCB4bXBwOiwgZXRjLlxuICAvLyB1bmxlc3MgdGhleSBoYWQgdGhlbSB0byBiZWdpbiB3aXRoLlxuICBpZiAodGhpcy5zbGFzaGVzIHx8XG4gICAgICAoIXByb3RvY29sIHx8IHNsYXNoZWRQcm90b2NvbFtwcm90b2NvbF0pICYmIGhvc3QgIT09IGZhbHNlKSB7XG4gICAgaG9zdCA9ICcvLycgKyAoaG9zdCB8fCAnJyk7XG4gICAgaWYgKHBhdGhuYW1lICYmIHBhdGhuYW1lLmNoYXJBdCgwKSAhPT0gJy8nKSBwYXRobmFtZSA9ICcvJyArIHBhdGhuYW1lO1xuICB9IGVsc2UgaWYgKCFob3N0KSB7XG4gICAgaG9zdCA9ICcnO1xuICB9XG5cbiAgaWYgKGhhc2ggJiYgaGFzaC5jaGFyQXQoMCkgIT09ICcjJykgaGFzaCA9ICcjJyArIGhhc2g7XG4gIGlmIChzZWFyY2ggJiYgc2VhcmNoLmNoYXJBdCgwKSAhPT0gJz8nKSBzZWFyY2ggPSAnPycgKyBzZWFyY2g7XG5cbiAgcGF0aG5hbWUgPSBwYXRobmFtZS5yZXBsYWNlKC9bPyNdL2csIGZ1bmN0aW9uKG1hdGNoKSB7XG4gICAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChtYXRjaCk7XG4gIH0pO1xuICBzZWFyY2ggPSBzZWFyY2gucmVwbGFjZSgnIycsICclMjMnKTtcblxuICByZXR1cm4gcHJvdG9jb2wgKyBob3N0ICsgcGF0aG5hbWUgKyBzZWFyY2ggKyBoYXNoO1xufTtcblxuZnVuY3Rpb24gdXJsUmVzb2x2ZShzb3VyY2UsIHJlbGF0aXZlKSB7XG4gIHJldHVybiB1cmxQYXJzZShzb3VyY2UsIGZhbHNlLCB0cnVlKS5yZXNvbHZlKHJlbGF0aXZlKTtcbn1cblxuVXJsLnByb3RvdHlwZS5yZXNvbHZlID0gZnVuY3Rpb24ocmVsYXRpdmUpIHtcbiAgcmV0dXJuIHRoaXMucmVzb2x2ZU9iamVjdCh1cmxQYXJzZShyZWxhdGl2ZSwgZmFsc2UsIHRydWUpKS5mb3JtYXQoKTtcbn07XG5cbmZ1bmN0aW9uIHVybFJlc29sdmVPYmplY3Qoc291cmNlLCByZWxhdGl2ZSkge1xuICBpZiAoIXNvdXJjZSkgcmV0dXJuIHJlbGF0aXZlO1xuICByZXR1cm4gdXJsUGFyc2Uoc291cmNlLCBmYWxzZSwgdHJ1ZSkucmVzb2x2ZU9iamVjdChyZWxhdGl2ZSk7XG59XG5cblVybC5wcm90b3R5cGUucmVzb2x2ZU9iamVjdCA9IGZ1bmN0aW9uKHJlbGF0aXZlKSB7XG4gIGlmIChpc1N0cmluZyhyZWxhdGl2ZSkpIHtcbiAgICB2YXIgcmVsID0gbmV3IFVybCgpO1xuICAgIHJlbC5wYXJzZShyZWxhdGl2ZSwgZmFsc2UsIHRydWUpO1xuICAgIHJlbGF0aXZlID0gcmVsO1xuICB9XG5cbiAgdmFyIHJlc3VsdCA9IG5ldyBVcmwoKTtcbiAgT2JqZWN0LmtleXModGhpcykuZm9yRWFjaChmdW5jdGlvbihrKSB7XG4gICAgcmVzdWx0W2tdID0gdGhpc1trXTtcbiAgfSwgdGhpcyk7XG5cbiAgLy8gaGFzaCBpcyBhbHdheXMgb3ZlcnJpZGRlbiwgbm8gbWF0dGVyIHdoYXQuXG4gIC8vIGV2ZW4gaHJlZj1cIlwiIHdpbGwgcmVtb3ZlIGl0LlxuICByZXN1bHQuaGFzaCA9IHJlbGF0aXZlLmhhc2g7XG5cbiAgLy8gaWYgdGhlIHJlbGF0aXZlIHVybCBpcyBlbXB0eSwgdGhlbiB0aGVyZSdzIG5vdGhpbmcgbGVmdCB0byBkbyBoZXJlLlxuICBpZiAocmVsYXRpdmUuaHJlZiA9PT0gJycpIHtcbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gaHJlZnMgbGlrZSAvL2Zvby9iYXIgYWx3YXlzIGN1dCB0byB0aGUgcHJvdG9jb2wuXG4gIGlmIChyZWxhdGl2ZS5zbGFzaGVzICYmICFyZWxhdGl2ZS5wcm90b2NvbCkge1xuICAgIC8vIHRha2UgZXZlcnl0aGluZyBleGNlcHQgdGhlIHByb3RvY29sIGZyb20gcmVsYXRpdmVcbiAgICBPYmplY3Qua2V5cyhyZWxhdGl2ZSkuZm9yRWFjaChmdW5jdGlvbihrKSB7XG4gICAgICBpZiAoayAhPT0gJ3Byb3RvY29sJylcbiAgICAgICAgcmVzdWx0W2tdID0gcmVsYXRpdmVba107XG4gICAgfSk7XG5cbiAgICAvL3VybFBhcnNlIGFwcGVuZHMgdHJhaWxpbmcgLyB0byB1cmxzIGxpa2UgaHR0cDovL3d3dy5leGFtcGxlLmNvbVxuICAgIGlmIChzbGFzaGVkUHJvdG9jb2xbcmVzdWx0LnByb3RvY29sXSAmJlxuICAgICAgICByZXN1bHQuaG9zdG5hbWUgJiYgIXJlc3VsdC5wYXRobmFtZSkge1xuICAgICAgcmVzdWx0LnBhdGggPSByZXN1bHQucGF0aG5hbWUgPSAnLyc7XG4gICAgfVxuXG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIGlmIChyZWxhdGl2ZS5wcm90b2NvbCAmJiByZWxhdGl2ZS5wcm90b2NvbCAhPT0gcmVzdWx0LnByb3RvY29sKSB7XG4gICAgLy8gaWYgaXQncyBhIGtub3duIHVybCBwcm90b2NvbCwgdGhlbiBjaGFuZ2luZ1xuICAgIC8vIHRoZSBwcm90b2NvbCBkb2VzIHdlaXJkIHRoaW5nc1xuICAgIC8vIGZpcnN0LCBpZiBpdCdzIG5vdCBmaWxlOiwgdGhlbiB3ZSBNVVNUIGhhdmUgYSBob3N0LFxuICAgIC8vIGFuZCBpZiB0aGVyZSB3YXMgYSBwYXRoXG4gICAgLy8gdG8gYmVnaW4gd2l0aCwgdGhlbiB3ZSBNVVNUIGhhdmUgYSBwYXRoLlxuICAgIC8vIGlmIGl0IGlzIGZpbGU6LCB0aGVuIHRoZSBob3N0IGlzIGRyb3BwZWQsXG4gICAgLy8gYmVjYXVzZSB0aGF0J3Mga25vd24gdG8gYmUgaG9zdGxlc3MuXG4gICAgLy8gYW55dGhpbmcgZWxzZSBpcyBhc3N1bWVkIHRvIGJlIGFic29sdXRlLlxuICAgIGlmICghc2xhc2hlZFByb3RvY29sW3JlbGF0aXZlLnByb3RvY29sXSkge1xuICAgICAgT2JqZWN0LmtleXMocmVsYXRpdmUpLmZvckVhY2goZnVuY3Rpb24oaykge1xuICAgICAgICByZXN1bHRba10gPSByZWxhdGl2ZVtrXTtcbiAgICAgIH0pO1xuICAgICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH1cblxuICAgIHJlc3VsdC5wcm90b2NvbCA9IHJlbGF0aXZlLnByb3RvY29sO1xuICAgIGlmICghcmVsYXRpdmUuaG9zdCAmJiAhaG9zdGxlc3NQcm90b2NvbFtyZWxhdGl2ZS5wcm90b2NvbF0pIHtcbiAgICAgIHZhciByZWxQYXRoID0gKHJlbGF0aXZlLnBhdGhuYW1lIHx8ICcnKS5zcGxpdCgnLycpO1xuICAgICAgd2hpbGUgKHJlbFBhdGgubGVuZ3RoICYmICEocmVsYXRpdmUuaG9zdCA9IHJlbFBhdGguc2hpZnQoKSkpO1xuICAgICAgaWYgKCFyZWxhdGl2ZS5ob3N0KSByZWxhdGl2ZS5ob3N0ID0gJyc7XG4gICAgICBpZiAoIXJlbGF0aXZlLmhvc3RuYW1lKSByZWxhdGl2ZS5ob3N0bmFtZSA9ICcnO1xuICAgICAgaWYgKHJlbFBhdGhbMF0gIT09ICcnKSByZWxQYXRoLnVuc2hpZnQoJycpO1xuICAgICAgaWYgKHJlbFBhdGgubGVuZ3RoIDwgMikgcmVsUGF0aC51bnNoaWZ0KCcnKTtcbiAgICAgIHJlc3VsdC5wYXRobmFtZSA9IHJlbFBhdGguam9pbignLycpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXN1bHQucGF0aG5hbWUgPSByZWxhdGl2ZS5wYXRobmFtZTtcbiAgICB9XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICByZXN1bHQuaG9zdCA9IHJlbGF0aXZlLmhvc3QgfHwgJyc7XG4gICAgcmVzdWx0LmF1dGggPSByZWxhdGl2ZS5hdXRoO1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9IHJlbGF0aXZlLmhvc3RuYW1lIHx8IHJlbGF0aXZlLmhvc3Q7XG4gICAgcmVzdWx0LnBvcnQgPSByZWxhdGl2ZS5wb3J0O1xuICAgIC8vIHRvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKHJlc3VsdC5wYXRobmFtZSB8fCByZXN1bHQuc2VhcmNoKSB7XG4gICAgICB2YXIgcCA9IHJlc3VsdC5wYXRobmFtZSB8fCAnJztcbiAgICAgIHZhciBzID0gcmVzdWx0LnNlYXJjaCB8fCAnJztcbiAgICAgIHJlc3VsdC5wYXRoID0gcCArIHM7XG4gICAgfVxuICAgIHJlc3VsdC5zbGFzaGVzID0gcmVzdWx0LnNsYXNoZXMgfHwgcmVsYXRpdmUuc2xhc2hlcztcbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgdmFyIGlzU291cmNlQWJzID0gKHJlc3VsdC5wYXRobmFtZSAmJiByZXN1bHQucGF0aG5hbWUuY2hhckF0KDApID09PSAnLycpLFxuICAgICAgaXNSZWxBYnMgPSAoXG4gICAgICAgICAgcmVsYXRpdmUuaG9zdCB8fFxuICAgICAgICAgIHJlbGF0aXZlLnBhdGhuYW1lICYmIHJlbGF0aXZlLnBhdGhuYW1lLmNoYXJBdCgwKSA9PT0gJy8nXG4gICAgICApLFxuICAgICAgbXVzdEVuZEFicyA9IChpc1JlbEFicyB8fCBpc1NvdXJjZUFicyB8fFxuICAgICAgICAgICAgICAgICAgICAocmVzdWx0Lmhvc3QgJiYgcmVsYXRpdmUucGF0aG5hbWUpKSxcbiAgICAgIHJlbW92ZUFsbERvdHMgPSBtdXN0RW5kQWJzLFxuICAgICAgc3JjUGF0aCA9IHJlc3VsdC5wYXRobmFtZSAmJiByZXN1bHQucGF0aG5hbWUuc3BsaXQoJy8nKSB8fCBbXSxcbiAgICAgIHJlbFBhdGggPSByZWxhdGl2ZS5wYXRobmFtZSAmJiByZWxhdGl2ZS5wYXRobmFtZS5zcGxpdCgnLycpIHx8IFtdLFxuICAgICAgcHN5Y2hvdGljID0gcmVzdWx0LnByb3RvY29sICYmICFzbGFzaGVkUHJvdG9jb2xbcmVzdWx0LnByb3RvY29sXTtcblxuICAvLyBpZiB0aGUgdXJsIGlzIGEgbm9uLXNsYXNoZWQgdXJsLCB0aGVuIHJlbGF0aXZlXG4gIC8vIGxpbmtzIGxpa2UgLi4vLi4gc2hvdWxkIGJlIGFibGVcbiAgLy8gdG8gY3Jhd2wgdXAgdG8gdGhlIGhvc3RuYW1lLCBhcyB3ZWxsLiAgVGhpcyBpcyBzdHJhbmdlLlxuICAvLyByZXN1bHQucHJvdG9jb2wgaGFzIGFscmVhZHkgYmVlbiBzZXQgYnkgbm93LlxuICAvLyBMYXRlciBvbiwgcHV0IHRoZSBmaXJzdCBwYXRoIHBhcnQgaW50byB0aGUgaG9zdCBmaWVsZC5cbiAgaWYgKHBzeWNob3RpYykge1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9ICcnO1xuICAgIHJlc3VsdC5wb3J0ID0gbnVsbDtcbiAgICBpZiAocmVzdWx0Lmhvc3QpIHtcbiAgICAgIGlmIChzcmNQYXRoWzBdID09PSAnJykgc3JjUGF0aFswXSA9IHJlc3VsdC5ob3N0O1xuICAgICAgZWxzZSBzcmNQYXRoLnVuc2hpZnQocmVzdWx0Lmhvc3QpO1xuICAgIH1cbiAgICByZXN1bHQuaG9zdCA9ICcnO1xuICAgIGlmIChyZWxhdGl2ZS5wcm90b2NvbCkge1xuICAgICAgcmVsYXRpdmUuaG9zdG5hbWUgPSBudWxsO1xuICAgICAgcmVsYXRpdmUucG9ydCA9IG51bGw7XG4gICAgICBpZiAocmVsYXRpdmUuaG9zdCkge1xuICAgICAgICBpZiAocmVsUGF0aFswXSA9PT0gJycpIHJlbFBhdGhbMF0gPSByZWxhdGl2ZS5ob3N0O1xuICAgICAgICBlbHNlIHJlbFBhdGgudW5zaGlmdChyZWxhdGl2ZS5ob3N0KTtcbiAgICAgIH1cbiAgICAgIHJlbGF0aXZlLmhvc3QgPSBudWxsO1xuICAgIH1cbiAgICBtdXN0RW5kQWJzID0gbXVzdEVuZEFicyAmJiAocmVsUGF0aFswXSA9PT0gJycgfHwgc3JjUGF0aFswXSA9PT0gJycpO1xuICB9XG5cbiAgaWYgKGlzUmVsQWJzKSB7XG4gICAgLy8gaXQncyBhYnNvbHV0ZS5cbiAgICByZXN1bHQuaG9zdCA9IChyZWxhdGl2ZS5ob3N0IHx8IHJlbGF0aXZlLmhvc3QgPT09ICcnKSA/XG4gICAgICAgICAgICAgICAgICByZWxhdGl2ZS5ob3N0IDogcmVzdWx0Lmhvc3Q7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gKHJlbGF0aXZlLmhvc3RuYW1lIHx8IHJlbGF0aXZlLmhvc3RuYW1lID09PSAnJykgP1xuICAgICAgICAgICAgICAgICAgICAgIHJlbGF0aXZlLmhvc3RuYW1lIDogcmVzdWx0Lmhvc3RuYW1lO1xuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gICAgc3JjUGF0aCA9IHJlbFBhdGg7XG4gICAgLy8gZmFsbCB0aHJvdWdoIHRvIHRoZSBkb3QtaGFuZGxpbmcgYmVsb3cuXG4gIH0gZWxzZSBpZiAocmVsUGF0aC5sZW5ndGgpIHtcbiAgICAvLyBpdCdzIHJlbGF0aXZlXG4gICAgLy8gdGhyb3cgYXdheSB0aGUgZXhpc3RpbmcgZmlsZSwgYW5kIHRha2UgdGhlIG5ldyBwYXRoIGluc3RlYWQuXG4gICAgaWYgKCFzcmNQYXRoKSBzcmNQYXRoID0gW107XG4gICAgc3JjUGF0aC5wb3AoKTtcbiAgICBzcmNQYXRoID0gc3JjUGF0aC5jb25jYXQocmVsUGF0aCk7XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgfSBlbHNlIGlmICghaXNOdWxsT3JVbmRlZmluZWQocmVsYXRpdmUuc2VhcmNoKSkge1xuICAgIC8vIGp1c3QgcHVsbCBvdXQgdGhlIHNlYXJjaC5cbiAgICAvLyBsaWtlIGhyZWY9Jz9mb28nLlxuICAgIC8vIFB1dCB0aGlzIGFmdGVyIHRoZSBvdGhlciB0d28gY2FzZXMgYmVjYXVzZSBpdCBzaW1wbGlmaWVzIHRoZSBib29sZWFuc1xuICAgIGlmIChwc3ljaG90aWMpIHtcbiAgICAgIHJlc3VsdC5ob3N0bmFtZSA9IHJlc3VsdC5ob3N0ID0gc3JjUGF0aC5zaGlmdCgpO1xuICAgICAgLy9vY2NhdGlvbmFseSB0aGUgYXV0aCBjYW4gZ2V0IHN0dWNrIG9ubHkgaW4gaG9zdFxuICAgICAgLy90aGlzIGVzcGVjaWFseSBoYXBwZW5zIGluIGNhc2VzIGxpa2VcbiAgICAgIC8vdXJsLnJlc29sdmVPYmplY3QoJ21haWx0bzpsb2NhbDFAZG9tYWluMScsICdsb2NhbDJAZG9tYWluMicpXG4gICAgICB2YXIgYXV0aEluSG9zdCA9IHJlc3VsdC5ob3N0ICYmIHJlc3VsdC5ob3N0LmluZGV4T2YoJ0AnKSA+IDAgP1xuICAgICAgICAgICAgICAgICAgICAgICByZXN1bHQuaG9zdC5zcGxpdCgnQCcpIDogZmFsc2U7XG4gICAgICBpZiAoYXV0aEluSG9zdCkge1xuICAgICAgICByZXN1bHQuYXV0aCA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICAgICAgcmVzdWx0Lmhvc3QgPSByZXN1bHQuaG9zdG5hbWUgPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICB9XG4gICAgfVxuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gICAgLy90byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICAgIGlmICghaXNOdWxsKHJlc3VsdC5wYXRobmFtZSkgfHwgIWlzTnVsbChyZXN1bHQuc2VhcmNoKSkge1xuICAgICAgcmVzdWx0LnBhdGggPSAocmVzdWx0LnBhdGhuYW1lID8gcmVzdWx0LnBhdGhuYW1lIDogJycpICtcbiAgICAgICAgICAgICAgICAgICAgKHJlc3VsdC5zZWFyY2ggPyByZXN1bHQuc2VhcmNoIDogJycpO1xuICAgIH1cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgaWYgKCFzcmNQYXRoLmxlbmd0aCkge1xuICAgIC8vIG5vIHBhdGggYXQgYWxsLiAgZWFzeS5cbiAgICAvLyB3ZSd2ZSBhbHJlYWR5IGhhbmRsZWQgdGhlIG90aGVyIHN0dWZmIGFib3ZlLlxuICAgIHJlc3VsdC5wYXRobmFtZSA9IG51bGw7XG4gICAgLy90byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICAgIGlmIChyZXN1bHQuc2VhcmNoKSB7XG4gICAgICByZXN1bHQucGF0aCA9ICcvJyArIHJlc3VsdC5zZWFyY2g7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gbnVsbDtcbiAgICB9XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGlmIGEgdXJsIEVORHMgaW4gLiBvciAuLiwgdGhlbiBpdCBtdXN0IGdldCBhIHRyYWlsaW5nIHNsYXNoLlxuICAvLyBob3dldmVyLCBpZiBpdCBlbmRzIGluIGFueXRoaW5nIGVsc2Ugbm9uLXNsYXNoeSxcbiAgLy8gdGhlbiBpdCBtdXN0IE5PVCBnZXQgYSB0cmFpbGluZyBzbGFzaC5cbiAgdmFyIGxhc3QgPSBzcmNQYXRoLnNsaWNlKC0xKVswXTtcbiAgdmFyIGhhc1RyYWlsaW5nU2xhc2ggPSAoXG4gICAgICAocmVzdWx0Lmhvc3QgfHwgcmVsYXRpdmUuaG9zdCkgJiYgKGxhc3QgPT09ICcuJyB8fCBsYXN0ID09PSAnLi4nKSB8fFxuICAgICAgbGFzdCA9PT0gJycpO1xuXG4gIC8vIHN0cmlwIHNpbmdsZSBkb3RzLCByZXNvbHZlIGRvdWJsZSBkb3RzIHRvIHBhcmVudCBkaXJcbiAgLy8gaWYgdGhlIHBhdGggdHJpZXMgdG8gZ28gYWJvdmUgdGhlIHJvb3QsIGB1cGAgZW5kcyB1cCA+IDBcbiAgdmFyIHVwID0gMDtcbiAgZm9yICh2YXIgaSA9IHNyY1BhdGgubGVuZ3RoOyBpID49IDA7IGktLSkge1xuICAgIGxhc3QgPSBzcmNQYXRoW2ldO1xuICAgIGlmIChsYXN0ID09ICcuJykge1xuICAgICAgc3JjUGF0aC5zcGxpY2UoaSwgMSk7XG4gICAgfSBlbHNlIGlmIChsYXN0ID09PSAnLi4nKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICAgIHVwKys7XG4gICAgfSBlbHNlIGlmICh1cCkge1xuICAgICAgc3JjUGF0aC5zcGxpY2UoaSwgMSk7XG4gICAgICB1cC0tO1xuICAgIH1cbiAgfVxuXG4gIC8vIGlmIHRoZSBwYXRoIGlzIGFsbG93ZWQgdG8gZ28gYWJvdmUgdGhlIHJvb3QsIHJlc3RvcmUgbGVhZGluZyAuLnNcbiAgaWYgKCFtdXN0RW5kQWJzICYmICFyZW1vdmVBbGxEb3RzKSB7XG4gICAgZm9yICg7IHVwLS07IHVwKSB7XG4gICAgICBzcmNQYXRoLnVuc2hpZnQoJy4uJyk7XG4gICAgfVxuICB9XG5cbiAgaWYgKG11c3RFbmRBYnMgJiYgc3JjUGF0aFswXSAhPT0gJycgJiZcbiAgICAgICghc3JjUGF0aFswXSB8fCBzcmNQYXRoWzBdLmNoYXJBdCgwKSAhPT0gJy8nKSkge1xuICAgIHNyY1BhdGgudW5zaGlmdCgnJyk7XG4gIH1cblxuICBpZiAoaGFzVHJhaWxpbmdTbGFzaCAmJiAoc3JjUGF0aC5qb2luKCcvJykuc3Vic3RyKC0xKSAhPT0gJy8nKSkge1xuICAgIHNyY1BhdGgucHVzaCgnJyk7XG4gIH1cblxuICB2YXIgaXNBYnNvbHV0ZSA9IHNyY1BhdGhbMF0gPT09ICcnIHx8XG4gICAgICAoc3JjUGF0aFswXSAmJiBzcmNQYXRoWzBdLmNoYXJBdCgwKSA9PT0gJy8nKTtcblxuICAvLyBwdXQgdGhlIGhvc3QgYmFja1xuICBpZiAocHN5Y2hvdGljKSB7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVzdWx0Lmhvc3QgPSBpc0Fic29sdXRlID8gJycgOlxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgc3JjUGF0aC5sZW5ndGggPyBzcmNQYXRoLnNoaWZ0KCkgOiAnJztcbiAgICAvL29jY2F0aW9uYWx5IHRoZSBhdXRoIGNhbiBnZXQgc3R1Y2sgb25seSBpbiBob3N0XG4gICAgLy90aGlzIGVzcGVjaWFseSBoYXBwZW5zIGluIGNhc2VzIGxpa2VcbiAgICAvL3VybC5yZXNvbHZlT2JqZWN0KCdtYWlsdG86bG9jYWwxQGRvbWFpbjEnLCAnbG9jYWwyQGRvbWFpbjInKVxuICAgIHZhciBhdXRoSW5Ib3N0ID0gcmVzdWx0Lmhvc3QgJiYgcmVzdWx0Lmhvc3QuaW5kZXhPZignQCcpID4gMCA/XG4gICAgICAgICAgICAgICAgICAgICByZXN1bHQuaG9zdC5zcGxpdCgnQCcpIDogZmFsc2U7XG4gICAgaWYgKGF1dGhJbkhvc3QpIHtcbiAgICAgIHJlc3VsdC5hdXRoID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgcmVzdWx0Lmhvc3QgPSByZXN1bHQuaG9zdG5hbWUgPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgfVxuICB9XG5cbiAgbXVzdEVuZEFicyA9IG11c3RFbmRBYnMgfHwgKHJlc3VsdC5ob3N0ICYmIHNyY1BhdGgubGVuZ3RoKTtcblxuICBpZiAobXVzdEVuZEFicyAmJiAhaXNBYnNvbHV0ZSkge1xuICAgIHNyY1BhdGgudW5zaGlmdCgnJyk7XG4gIH1cblxuICBpZiAoIXNyY1BhdGgubGVuZ3RoKSB7XG4gICAgcmVzdWx0LnBhdGhuYW1lID0gbnVsbDtcbiAgICByZXN1bHQucGF0aCA9IG51bGw7XG4gIH0gZWxzZSB7XG4gICAgcmVzdWx0LnBhdGhuYW1lID0gc3JjUGF0aC5qb2luKCcvJyk7XG4gIH1cblxuICAvL3RvIHN1cHBvcnQgcmVxdWVzdC5odHRwXG4gIGlmICghaXNOdWxsKHJlc3VsdC5wYXRobmFtZSkgfHwgIWlzTnVsbChyZXN1bHQuc2VhcmNoKSkge1xuICAgIHJlc3VsdC5wYXRoID0gKHJlc3VsdC5wYXRobmFtZSA/IHJlc3VsdC5wYXRobmFtZSA6ICcnKSArXG4gICAgICAgICAgICAgICAgICAocmVzdWx0LnNlYXJjaCA/IHJlc3VsdC5zZWFyY2ggOiAnJyk7XG4gIH1cbiAgcmVzdWx0LmF1dGggPSByZWxhdGl2ZS5hdXRoIHx8IHJlc3VsdC5hdXRoO1xuICByZXN1bHQuc2xhc2hlcyA9IHJlc3VsdC5zbGFzaGVzIHx8IHJlbGF0aXZlLnNsYXNoZXM7XG4gIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICByZXR1cm4gcmVzdWx0O1xufTtcblxuVXJsLnByb3RvdHlwZS5wYXJzZUhvc3QgPSBmdW5jdGlvbigpIHtcbiAgdmFyIGhvc3QgPSB0aGlzLmhvc3Q7XG4gIHZhciBwb3J0ID0gcG9ydFBhdHRlcm4uZXhlYyhob3N0KTtcbiAgaWYgKHBvcnQpIHtcbiAgICBwb3J0ID0gcG9ydFswXTtcbiAgICBpZiAocG9ydCAhPT0gJzonKSB7XG4gICAgICB0aGlzLnBvcnQgPSBwb3J0LnN1YnN0cigxKTtcbiAgICB9XG4gICAgaG9zdCA9IGhvc3Quc3Vic3RyKDAsIGhvc3QubGVuZ3RoIC0gcG9ydC5sZW5ndGgpO1xuICB9XG4gIGlmIChob3N0KSB0aGlzLmhvc3RuYW1lID0gaG9zdDtcbn07XG5cbmZ1bmN0aW9uIGlzU3RyaW5nKGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gXCJzdHJpbmdcIjtcbn1cblxuZnVuY3Rpb24gaXNPYmplY3QoYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSAnb2JqZWN0JyAmJiBhcmcgIT09IG51bGw7XG59XG5cbmZ1bmN0aW9uIGlzTnVsbChhcmcpIHtcbiAgcmV0dXJuIGFyZyA9PT0gbnVsbDtcbn1cbmZ1bmN0aW9uIGlzTnVsbE9yVW5kZWZpbmVkKGFyZykge1xuICByZXR1cm4gIGFyZyA9PSBudWxsO1xufVxuIiwiLyohIGh0dHBzOi8vbXRocy5iZS9wdW55Y29kZSB2MS40LjEgYnkgQG1hdGhpYXMgKi9cbjsoZnVuY3Rpb24ocm9vdCkge1xuXG5cdC8qKiBEZXRlY3QgZnJlZSB2YXJpYWJsZXMgKi9cblx0dmFyIGZyZWVFeHBvcnRzID0gdHlwZW9mIGV4cG9ydHMgPT0gJ29iamVjdCcgJiYgZXhwb3J0cyAmJlxuXHRcdCFleHBvcnRzLm5vZGVUeXBlICYmIGV4cG9ydHM7XG5cdHZhciBmcmVlTW9kdWxlID0gdHlwZW9mIG1vZHVsZSA9PSAnb2JqZWN0JyAmJiBtb2R1bGUgJiZcblx0XHQhbW9kdWxlLm5vZGVUeXBlICYmIG1vZHVsZTtcblx0dmFyIGZyZWVHbG9iYWwgPSB0eXBlb2YgZ2xvYmFsID09ICdvYmplY3QnICYmIGdsb2JhbDtcblx0aWYgKFxuXHRcdGZyZWVHbG9iYWwuZ2xvYmFsID09PSBmcmVlR2xvYmFsIHx8XG5cdFx0ZnJlZUdsb2JhbC53aW5kb3cgPT09IGZyZWVHbG9iYWwgfHxcblx0XHRmcmVlR2xvYmFsLnNlbGYgPT09IGZyZWVHbG9iYWxcblx0KSB7XG5cdFx0cm9vdCA9IGZyZWVHbG9iYWw7XG5cdH1cblxuXHQvKipcblx0ICogVGhlIGBwdW55Y29kZWAgb2JqZWN0LlxuXHQgKiBAbmFtZSBwdW55Y29kZVxuXHQgKiBAdHlwZSBPYmplY3Rcblx0ICovXG5cdHZhciBwdW55Y29kZSxcblxuXHQvKiogSGlnaGVzdCBwb3NpdGl2ZSBzaWduZWQgMzItYml0IGZsb2F0IHZhbHVlICovXG5cdG1heEludCA9IDIxNDc0ODM2NDcsIC8vIGFrYS4gMHg3RkZGRkZGRiBvciAyXjMxLTFcblxuXHQvKiogQm9vdHN0cmluZyBwYXJhbWV0ZXJzICovXG5cdGJhc2UgPSAzNixcblx0dE1pbiA9IDEsXG5cdHRNYXggPSAyNixcblx0c2tldyA9IDM4LFxuXHRkYW1wID0gNzAwLFxuXHRpbml0aWFsQmlhcyA9IDcyLFxuXHRpbml0aWFsTiA9IDEyOCwgLy8gMHg4MFxuXHRkZWxpbWl0ZXIgPSAnLScsIC8vICdcXHgyRCdcblxuXHQvKiogUmVndWxhciBleHByZXNzaW9ucyAqL1xuXHRyZWdleFB1bnljb2RlID0gL154bi0tLyxcblx0cmVnZXhOb25BU0NJSSA9IC9bXlxceDIwLVxceDdFXS8sIC8vIHVucHJpbnRhYmxlIEFTQ0lJIGNoYXJzICsgbm9uLUFTQ0lJIGNoYXJzXG5cdHJlZ2V4U2VwYXJhdG9ycyA9IC9bXFx4MkVcXHUzMDAyXFx1RkYwRVxcdUZGNjFdL2csIC8vIFJGQyAzNDkwIHNlcGFyYXRvcnNcblxuXHQvKiogRXJyb3IgbWVzc2FnZXMgKi9cblx0ZXJyb3JzID0ge1xuXHRcdCdvdmVyZmxvdyc6ICdPdmVyZmxvdzogaW5wdXQgbmVlZHMgd2lkZXIgaW50ZWdlcnMgdG8gcHJvY2VzcycsXG5cdFx0J25vdC1iYXNpYyc6ICdJbGxlZ2FsIGlucHV0ID49IDB4ODAgKG5vdCBhIGJhc2ljIGNvZGUgcG9pbnQpJyxcblx0XHQnaW52YWxpZC1pbnB1dCc6ICdJbnZhbGlkIGlucHV0J1xuXHR9LFxuXG5cdC8qKiBDb252ZW5pZW5jZSBzaG9ydGN1dHMgKi9cblx0YmFzZU1pbnVzVE1pbiA9IGJhc2UgLSB0TWluLFxuXHRmbG9vciA9IE1hdGguZmxvb3IsXG5cdHN0cmluZ0Zyb21DaGFyQ29kZSA9IFN0cmluZy5mcm9tQ2hhckNvZGUsXG5cblx0LyoqIFRlbXBvcmFyeSB2YXJpYWJsZSAqL1xuXHRrZXk7XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqXG5cdCAqIEEgZ2VuZXJpYyBlcnJvciB1dGlsaXR5IGZ1bmN0aW9uLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gdHlwZSBUaGUgZXJyb3IgdHlwZS5cblx0ICogQHJldHVybnMge0Vycm9yfSBUaHJvd3MgYSBgUmFuZ2VFcnJvcmAgd2l0aCB0aGUgYXBwbGljYWJsZSBlcnJvciBtZXNzYWdlLlxuXHQgKi9cblx0ZnVuY3Rpb24gZXJyb3IodHlwZSkge1xuXHRcdHRocm93IG5ldyBSYW5nZUVycm9yKGVycm9yc1t0eXBlXSk7XG5cdH1cblxuXHQvKipcblx0ICogQSBnZW5lcmljIGBBcnJheSNtYXBgIHV0aWxpdHkgZnVuY3Rpb24uXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGFycmF5IFRoZSBhcnJheSB0byBpdGVyYXRlIG92ZXIuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeSBhcnJheVxuXHQgKiBpdGVtLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IEEgbmV3IGFycmF5IG9mIHZhbHVlcyByZXR1cm5lZCBieSB0aGUgY2FsbGJhY2sgZnVuY3Rpb24uXG5cdCAqL1xuXHRmdW5jdGlvbiBtYXAoYXJyYXksIGZuKSB7XG5cdFx0dmFyIGxlbmd0aCA9IGFycmF5Lmxlbmd0aDtcblx0XHR2YXIgcmVzdWx0ID0gW107XG5cdFx0d2hpbGUgKGxlbmd0aC0tKSB7XG5cdFx0XHRyZXN1bHRbbGVuZ3RoXSA9IGZuKGFycmF5W2xlbmd0aF0pO1xuXHRcdH1cblx0XHRyZXR1cm4gcmVzdWx0O1xuXHR9XG5cblx0LyoqXG5cdCAqIEEgc2ltcGxlIGBBcnJheSNtYXBgLWxpa2Ugd3JhcHBlciB0byB3b3JrIHdpdGggZG9tYWluIG5hbWUgc3RyaW5ncyBvciBlbWFpbFxuXHQgKiBhZGRyZXNzZXMuXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBkb21haW4gVGhlIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MuXG5cdCAqIEBwYXJhbSB7RnVuY3Rpb259IGNhbGxiYWNrIFRoZSBmdW5jdGlvbiB0aGF0IGdldHMgY2FsbGVkIGZvciBldmVyeVxuXHQgKiBjaGFyYWN0ZXIuXG5cdCAqIEByZXR1cm5zIHtBcnJheX0gQSBuZXcgc3RyaW5nIG9mIGNoYXJhY3RlcnMgcmV0dXJuZWQgYnkgdGhlIGNhbGxiYWNrXG5cdCAqIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gbWFwRG9tYWluKHN0cmluZywgZm4pIHtcblx0XHR2YXIgcGFydHMgPSBzdHJpbmcuc3BsaXQoJ0AnKTtcblx0XHR2YXIgcmVzdWx0ID0gJyc7XG5cdFx0aWYgKHBhcnRzLmxlbmd0aCA+IDEpIHtcblx0XHRcdC8vIEluIGVtYWlsIGFkZHJlc3Nlcywgb25seSB0aGUgZG9tYWluIG5hbWUgc2hvdWxkIGJlIHB1bnljb2RlZC4gTGVhdmVcblx0XHRcdC8vIHRoZSBsb2NhbCBwYXJ0IChpLmUuIGV2ZXJ5dGhpbmcgdXAgdG8gYEBgKSBpbnRhY3QuXG5cdFx0XHRyZXN1bHQgPSBwYXJ0c1swXSArICdAJztcblx0XHRcdHN0cmluZyA9IHBhcnRzWzFdO1xuXHRcdH1cblx0XHQvLyBBdm9pZCBgc3BsaXQocmVnZXgpYCBmb3IgSUU4IGNvbXBhdGliaWxpdHkuIFNlZSAjMTcuXG5cdFx0c3RyaW5nID0gc3RyaW5nLnJlcGxhY2UocmVnZXhTZXBhcmF0b3JzLCAnXFx4MkUnKTtcblx0XHR2YXIgbGFiZWxzID0gc3RyaW5nLnNwbGl0KCcuJyk7XG5cdFx0dmFyIGVuY29kZWQgPSBtYXAobGFiZWxzLCBmbikuam9pbignLicpO1xuXHRcdHJldHVybiByZXN1bHQgKyBlbmNvZGVkO1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYW4gYXJyYXkgY29udGFpbmluZyB0aGUgbnVtZXJpYyBjb2RlIHBvaW50cyBvZiBlYWNoIFVuaWNvZGVcblx0ICogY2hhcmFjdGVyIGluIHRoZSBzdHJpbmcuIFdoaWxlIEphdmFTY3JpcHQgdXNlcyBVQ1MtMiBpbnRlcm5hbGx5LFxuXHQgKiB0aGlzIGZ1bmN0aW9uIHdpbGwgY29udmVydCBhIHBhaXIgb2Ygc3Vycm9nYXRlIGhhbHZlcyAoZWFjaCBvZiB3aGljaFxuXHQgKiBVQ1MtMiBleHBvc2VzIGFzIHNlcGFyYXRlIGNoYXJhY3RlcnMpIGludG8gYSBzaW5nbGUgY29kZSBwb2ludCxcblx0ICogbWF0Y2hpbmcgVVRGLTE2LlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmVuY29kZWBcblx0ICogQHNlZSA8aHR0cHM6Ly9tYXRoaWFzYnluZW5zLmJlL25vdGVzL2phdmFzY3JpcHQtZW5jb2Rpbmc+XG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZS51Y3MyXG5cdCAqIEBuYW1lIGRlY29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gc3RyaW5nIFRoZSBVbmljb2RlIGlucHV0IHN0cmluZyAoVUNTLTIpLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IFRoZSBuZXcgYXJyYXkgb2YgY29kZSBwb2ludHMuXG5cdCAqL1xuXHRmdW5jdGlvbiB1Y3MyZGVjb2RlKHN0cmluZykge1xuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgY291bnRlciA9IDAsXG5cdFx0ICAgIGxlbmd0aCA9IHN0cmluZy5sZW5ndGgsXG5cdFx0ICAgIHZhbHVlLFxuXHRcdCAgICBleHRyYTtcblx0XHR3aGlsZSAoY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0dmFsdWUgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0aWYgKHZhbHVlID49IDB4RDgwMCAmJiB2YWx1ZSA8PSAweERCRkYgJiYgY291bnRlciA8IGxlbmd0aCkge1xuXHRcdFx0XHQvLyBoaWdoIHN1cnJvZ2F0ZSwgYW5kIHRoZXJlIGlzIGEgbmV4dCBjaGFyYWN0ZXJcblx0XHRcdFx0ZXh0cmEgPSBzdHJpbmcuY2hhckNvZGVBdChjb3VudGVyKyspO1xuXHRcdFx0XHRpZiAoKGV4dHJhICYgMHhGQzAwKSA9PSAweERDMDApIHsgLy8gbG93IHN1cnJvZ2F0ZVxuXHRcdFx0XHRcdG91dHB1dC5wdXNoKCgodmFsdWUgJiAweDNGRikgPDwgMTApICsgKGV4dHJhICYgMHgzRkYpICsgMHgxMDAwMCk7XG5cdFx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdFx0Ly8gdW5tYXRjaGVkIHN1cnJvZ2F0ZTsgb25seSBhcHBlbmQgdGhpcyBjb2RlIHVuaXQsIGluIGNhc2UgdGhlIG5leHRcblx0XHRcdFx0XHQvLyBjb2RlIHVuaXQgaXMgdGhlIGhpZ2ggc3Vycm9nYXRlIG9mIGEgc3Vycm9nYXRlIHBhaXJcblx0XHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHRcdFx0Y291bnRlci0tO1xuXHRcdFx0XHR9XG5cdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRvdXRwdXQucHVzaCh2YWx1ZSk7XG5cdFx0XHR9XG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQ7XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlcyBhIHN0cmluZyBiYXNlZCBvbiBhbiBhcnJheSBvZiBudW1lcmljIGNvZGUgcG9pbnRzLlxuXHQgKiBAc2VlIGBwdW55Y29kZS51Y3MyLmRlY29kZWBcblx0ICogQG1lbWJlck9mIHB1bnljb2RlLnVjczJcblx0ICogQG5hbWUgZW5jb2RlXG5cdCAqIEBwYXJhbSB7QXJyYXl9IGNvZGVQb2ludHMgVGhlIGFycmF5IG9mIG51bWVyaWMgY29kZSBwb2ludHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBuZXcgVW5pY29kZSBzdHJpbmcgKFVDUy0yKS5cblx0ICovXG5cdGZ1bmN0aW9uIHVjczJlbmNvZGUoYXJyYXkpIHtcblx0XHRyZXR1cm4gbWFwKGFycmF5LCBmdW5jdGlvbih2YWx1ZSkge1xuXHRcdFx0dmFyIG91dHB1dCA9ICcnO1xuXHRcdFx0aWYgKHZhbHVlID4gMHhGRkZGKSB7XG5cdFx0XHRcdHZhbHVlIC09IDB4MTAwMDA7XG5cdFx0XHRcdG91dHB1dCArPSBzdHJpbmdGcm9tQ2hhckNvZGUodmFsdWUgPj4+IDEwICYgMHgzRkYgfCAweEQ4MDApO1xuXHRcdFx0XHR2YWx1ZSA9IDB4REMwMCB8IHZhbHVlICYgMHgzRkY7XG5cdFx0XHR9XG5cdFx0XHRvdXRwdXQgKz0gc3RyaW5nRnJvbUNoYXJDb2RlKHZhbHVlKTtcblx0XHRcdHJldHVybiBvdXRwdXQ7XG5cdFx0fSkuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBiYXNpYyBjb2RlIHBvaW50IGludG8gYSBkaWdpdC9pbnRlZ2VyLlxuXHQgKiBAc2VlIGBkaWdpdFRvQmFzaWMoKWBcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IGNvZGVQb2ludCBUaGUgYmFzaWMgbnVtZXJpYyBjb2RlIHBvaW50IHZhbHVlLlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgbnVtZXJpYyB2YWx1ZSBvZiBhIGJhc2ljIGNvZGUgcG9pbnQgKGZvciB1c2UgaW5cblx0ICogcmVwcmVzZW50aW5nIGludGVnZXJzKSBpbiB0aGUgcmFuZ2UgYDBgIHRvIGBiYXNlIC0gMWAsIG9yIGBiYXNlYCBpZlxuXHQgKiB0aGUgY29kZSBwb2ludCBkb2VzIG5vdCByZXByZXNlbnQgYSB2YWx1ZS5cblx0ICovXG5cdGZ1bmN0aW9uIGJhc2ljVG9EaWdpdChjb2RlUG9pbnQpIHtcblx0XHRpZiAoY29kZVBvaW50IC0gNDggPCAxMCkge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDIyO1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gNjUgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDY1O1xuXHRcdH1cblx0XHRpZiAoY29kZVBvaW50IC0gOTcgPCAyNikge1xuXHRcdFx0cmV0dXJuIGNvZGVQb2ludCAtIDk3O1xuXHRcdH1cblx0XHRyZXR1cm4gYmFzZTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIGRpZ2l0L2ludGVnZXIgaW50byBhIGJhc2ljIGNvZGUgcG9pbnQuXG5cdCAqIEBzZWUgYGJhc2ljVG9EaWdpdCgpYFxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0gZGlnaXQgVGhlIG51bWVyaWMgdmFsdWUgb2YgYSBiYXNpYyBjb2RlIHBvaW50LlxuXHQgKiBAcmV0dXJucyB7TnVtYmVyfSBUaGUgYmFzaWMgY29kZSBwb2ludCB3aG9zZSB2YWx1ZSAod2hlbiB1c2VkIGZvclxuXHQgKiByZXByZXNlbnRpbmcgaW50ZWdlcnMpIGlzIGBkaWdpdGAsIHdoaWNoIG5lZWRzIHRvIGJlIGluIHRoZSByYW5nZVxuXHQgKiBgMGAgdG8gYGJhc2UgLSAxYC4gSWYgYGZsYWdgIGlzIG5vbi16ZXJvLCB0aGUgdXBwZXJjYXNlIGZvcm0gaXNcblx0ICogdXNlZDsgZWxzZSwgdGhlIGxvd2VyY2FzZSBmb3JtIGlzIHVzZWQuIFRoZSBiZWhhdmlvciBpcyB1bmRlZmluZWRcblx0ICogaWYgYGZsYWdgIGlzIG5vbi16ZXJvIGFuZCBgZGlnaXRgIGhhcyBubyB1cHBlcmNhc2UgZm9ybS5cblx0ICovXG5cdGZ1bmN0aW9uIGRpZ2l0VG9CYXNpYyhkaWdpdCwgZmxhZykge1xuXHRcdC8vICAwLi4yNSBtYXAgdG8gQVNDSUkgYS4ueiBvciBBLi5aXG5cdFx0Ly8gMjYuLjM1IG1hcCB0byBBU0NJSSAwLi45XG5cdFx0cmV0dXJuIGRpZ2l0ICsgMjIgKyA3NSAqIChkaWdpdCA8IDI2KSAtICgoZmxhZyAhPSAwKSA8PCA1KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBCaWFzIGFkYXB0YXRpb24gZnVuY3Rpb24gYXMgcGVyIHNlY3Rpb24gMy40IG9mIFJGQyAzNDkyLlxuXHQgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjMzQ5MiNzZWN0aW9uLTMuNFxuXHQgKiBAcHJpdmF0ZVxuXHQgKi9cblx0ZnVuY3Rpb24gYWRhcHQoZGVsdGEsIG51bVBvaW50cywgZmlyc3RUaW1lKSB7XG5cdFx0dmFyIGsgPSAwO1xuXHRcdGRlbHRhID0gZmlyc3RUaW1lID8gZmxvb3IoZGVsdGEgLyBkYW1wKSA6IGRlbHRhID4+IDE7XG5cdFx0ZGVsdGEgKz0gZmxvb3IoZGVsdGEgLyBudW1Qb2ludHMpO1xuXHRcdGZvciAoLyogbm8gaW5pdGlhbGl6YXRpb24gKi87IGRlbHRhID4gYmFzZU1pbnVzVE1pbiAqIHRNYXggPj4gMTsgayArPSBiYXNlKSB7XG5cdFx0XHRkZWx0YSA9IGZsb29yKGRlbHRhIC8gYmFzZU1pbnVzVE1pbik7XG5cdFx0fVxuXHRcdHJldHVybiBmbG9vcihrICsgKGJhc2VNaW51c1RNaW4gKyAxKSAqIGRlbHRhIC8gKGRlbHRhICsgc2tldykpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scyB0byBhIHN0cmluZyBvZiBVbmljb2RlXG5cdCAqIHN5bWJvbHMuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSByZXN1bHRpbmcgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scy5cblx0ICovXG5cdGZ1bmN0aW9uIGRlY29kZShpbnB1dCkge1xuXHRcdC8vIERvbid0IHVzZSBVQ1MtMlxuXHRcdHZhciBvdXRwdXQgPSBbXSxcblx0XHQgICAgaW5wdXRMZW5ndGggPSBpbnB1dC5sZW5ndGgsXG5cdFx0ICAgIG91dCxcblx0XHQgICAgaSA9IDAsXG5cdFx0ICAgIG4gPSBpbml0aWFsTixcblx0XHQgICAgYmlhcyA9IGluaXRpYWxCaWFzLFxuXHRcdCAgICBiYXNpYyxcblx0XHQgICAgaixcblx0XHQgICAgaW5kZXgsXG5cdFx0ICAgIG9sZGksXG5cdFx0ICAgIHcsXG5cdFx0ICAgIGssXG5cdFx0ICAgIGRpZ2l0LFxuXHRcdCAgICB0LFxuXHRcdCAgICAvKiogQ2FjaGVkIGNhbGN1bGF0aW9uIHJlc3VsdHMgKi9cblx0XHQgICAgYmFzZU1pbnVzVDtcblxuXHRcdC8vIEhhbmRsZSB0aGUgYmFzaWMgY29kZSBwb2ludHM6IGxldCBgYmFzaWNgIGJlIHRoZSBudW1iZXIgb2YgaW5wdXQgY29kZVxuXHRcdC8vIHBvaW50cyBiZWZvcmUgdGhlIGxhc3QgZGVsaW1pdGVyLCBvciBgMGAgaWYgdGhlcmUgaXMgbm9uZSwgdGhlbiBjb3B5XG5cdFx0Ly8gdGhlIGZpcnN0IGJhc2ljIGNvZGUgcG9pbnRzIHRvIHRoZSBvdXRwdXQuXG5cblx0XHRiYXNpYyA9IGlucHV0Lmxhc3RJbmRleE9mKGRlbGltaXRlcik7XG5cdFx0aWYgKGJhc2ljIDwgMCkge1xuXHRcdFx0YmFzaWMgPSAwO1xuXHRcdH1cblxuXHRcdGZvciAoaiA9IDA7IGogPCBiYXNpYzsgKytqKSB7XG5cdFx0XHQvLyBpZiBpdCdzIG5vdCBhIGJhc2ljIGNvZGUgcG9pbnRcblx0XHRcdGlmIChpbnB1dC5jaGFyQ29kZUF0KGopID49IDB4ODApIHtcblx0XHRcdFx0ZXJyb3IoJ25vdC1iYXNpYycpO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0LnB1c2goaW5wdXQuY2hhckNvZGVBdChqKSk7XG5cdFx0fVxuXG5cdFx0Ly8gTWFpbiBkZWNvZGluZyBsb29wOiBzdGFydCBqdXN0IGFmdGVyIHRoZSBsYXN0IGRlbGltaXRlciBpZiBhbnkgYmFzaWMgY29kZVxuXHRcdC8vIHBvaW50cyB3ZXJlIGNvcGllZDsgc3RhcnQgYXQgdGhlIGJlZ2lubmluZyBvdGhlcndpc2UuXG5cblx0XHRmb3IgKGluZGV4ID0gYmFzaWMgPiAwID8gYmFzaWMgKyAxIDogMDsgaW5kZXggPCBpbnB1dExlbmd0aDsgLyogbm8gZmluYWwgZXhwcmVzc2lvbiAqLykge1xuXG5cdFx0XHQvLyBgaW5kZXhgIGlzIHRoZSBpbmRleCBvZiB0aGUgbmV4dCBjaGFyYWN0ZXIgdG8gYmUgY29uc3VtZWQuXG5cdFx0XHQvLyBEZWNvZGUgYSBnZW5lcmFsaXplZCB2YXJpYWJsZS1sZW5ndGggaW50ZWdlciBpbnRvIGBkZWx0YWAsXG5cdFx0XHQvLyB3aGljaCBnZXRzIGFkZGVkIHRvIGBpYC4gVGhlIG92ZXJmbG93IGNoZWNraW5nIGlzIGVhc2llclxuXHRcdFx0Ly8gaWYgd2UgaW5jcmVhc2UgYGlgIGFzIHdlIGdvLCB0aGVuIHN1YnRyYWN0IG9mZiBpdHMgc3RhcnRpbmdcblx0XHRcdC8vIHZhbHVlIGF0IHRoZSBlbmQgdG8gb2J0YWluIGBkZWx0YWAuXG5cdFx0XHRmb3IgKG9sZGkgPSBpLCB3ID0gMSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cblx0XHRcdFx0aWYgKGluZGV4ID49IGlucHV0TGVuZ3RoKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ2ludmFsaWQtaW5wdXQnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGRpZ2l0ID0gYmFzaWNUb0RpZ2l0KGlucHV0LmNoYXJDb2RlQXQoaW5kZXgrKykpO1xuXG5cdFx0XHRcdGlmIChkaWdpdCA+PSBiYXNlIHx8IGRpZ2l0ID4gZmxvb3IoKG1heEludCAtIGkpIC8gdykpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGkgKz0gZGlnaXQgKiB3O1xuXHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblxuXHRcdFx0XHRpZiAoZGlnaXQgPCB0KSB7XG5cdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRiYXNlTWludXNUID0gYmFzZSAtIHQ7XG5cdFx0XHRcdGlmICh3ID4gZmxvb3IobWF4SW50IC8gYmFzZU1pbnVzVCkpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdHcgKj0gYmFzZU1pbnVzVDtcblxuXHRcdFx0fVxuXG5cdFx0XHRvdXQgPSBvdXRwdXQubGVuZ3RoICsgMTtcblx0XHRcdGJpYXMgPSBhZGFwdChpIC0gb2xkaSwgb3V0LCBvbGRpID09IDApO1xuXG5cdFx0XHQvLyBgaWAgd2FzIHN1cHBvc2VkIHRvIHdyYXAgYXJvdW5kIGZyb20gYG91dGAgdG8gYDBgLFxuXHRcdFx0Ly8gaW5jcmVtZW50aW5nIGBuYCBlYWNoIHRpbWUsIHNvIHdlJ2xsIGZpeCB0aGF0IG5vdzpcblx0XHRcdGlmIChmbG9vcihpIC8gb3V0KSA+IG1heEludCAtIG4pIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdG4gKz0gZmxvb3IoaSAvIG91dCk7XG5cdFx0XHRpICU9IG91dDtcblxuXHRcdFx0Ly8gSW5zZXJ0IGBuYCBhdCBwb3NpdGlvbiBgaWAgb2YgdGhlIG91dHB1dFxuXHRcdFx0b3V0cHV0LnNwbGljZShpKyssIDAsIG4pO1xuXG5cdFx0fVxuXG5cdFx0cmV0dXJuIHVjczJlbmNvZGUob3V0cHV0KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMgKGUuZy4gYSBkb21haW4gbmFtZSBsYWJlbCkgdG8gYVxuXHQgKiBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgcmVzdWx0aW5nIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBlbmNvZGUoaW5wdXQpIHtcblx0XHR2YXIgbixcblx0XHQgICAgZGVsdGEsXG5cdFx0ICAgIGhhbmRsZWRDUENvdW50LFxuXHRcdCAgICBiYXNpY0xlbmd0aCxcblx0XHQgICAgYmlhcyxcblx0XHQgICAgaixcblx0XHQgICAgbSxcblx0XHQgICAgcSxcblx0XHQgICAgayxcblx0XHQgICAgdCxcblx0XHQgICAgY3VycmVudFZhbHVlLFxuXHRcdCAgICBvdXRwdXQgPSBbXSxcblx0XHQgICAgLyoqIGBpbnB1dExlbmd0aGAgd2lsbCBob2xkIHRoZSBudW1iZXIgb2YgY29kZSBwb2ludHMgaW4gYGlucHV0YC4gKi9cblx0XHQgICAgaW5wdXRMZW5ndGgsXG5cdFx0ICAgIC8qKiBDYWNoZWQgY2FsY3VsYXRpb24gcmVzdWx0cyAqL1xuXHRcdCAgICBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsXG5cdFx0ICAgIGJhc2VNaW51c1QsXG5cdFx0ICAgIHFNaW51c1Q7XG5cblx0XHQvLyBDb252ZXJ0IHRoZSBpbnB1dCBpbiBVQ1MtMiB0byBVbmljb2RlXG5cdFx0aW5wdXQgPSB1Y3MyZGVjb2RlKGlucHV0KTtcblxuXHRcdC8vIENhY2hlIHRoZSBsZW5ndGhcblx0XHRpbnB1dExlbmd0aCA9IGlucHV0Lmxlbmd0aDtcblxuXHRcdC8vIEluaXRpYWxpemUgdGhlIHN0YXRlXG5cdFx0biA9IGluaXRpYWxOO1xuXHRcdGRlbHRhID0gMDtcblx0XHRiaWFzID0gaW5pdGlhbEJpYXM7XG5cblx0XHQvLyBIYW5kbGUgdGhlIGJhc2ljIGNvZGUgcG9pbnRzXG5cdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IDB4ODApIHtcblx0XHRcdFx0b3V0cHV0LnB1c2goc3RyaW5nRnJvbUNoYXJDb2RlKGN1cnJlbnRWYWx1ZSkpO1xuXHRcdFx0fVxuXHRcdH1cblxuXHRcdGhhbmRsZWRDUENvdW50ID0gYmFzaWNMZW5ndGggPSBvdXRwdXQubGVuZ3RoO1xuXG5cdFx0Ly8gYGhhbmRsZWRDUENvdW50YCBpcyB0aGUgbnVtYmVyIG9mIGNvZGUgcG9pbnRzIHRoYXQgaGF2ZSBiZWVuIGhhbmRsZWQ7XG5cdFx0Ly8gYGJhc2ljTGVuZ3RoYCBpcyB0aGUgbnVtYmVyIG9mIGJhc2ljIGNvZGUgcG9pbnRzLlxuXG5cdFx0Ly8gRmluaXNoIHRoZSBiYXNpYyBzdHJpbmcgLSBpZiBpdCBpcyBub3QgZW1wdHkgLSB3aXRoIGEgZGVsaW1pdGVyXG5cdFx0aWYgKGJhc2ljTGVuZ3RoKSB7XG5cdFx0XHRvdXRwdXQucHVzaChkZWxpbWl0ZXIpO1xuXHRcdH1cblxuXHRcdC8vIE1haW4gZW5jb2RpbmcgbG9vcDpcblx0XHR3aGlsZSAoaGFuZGxlZENQQ291bnQgPCBpbnB1dExlbmd0aCkge1xuXG5cdFx0XHQvLyBBbGwgbm9uLWJhc2ljIGNvZGUgcG9pbnRzIDwgbiBoYXZlIGJlZW4gaGFuZGxlZCBhbHJlYWR5LiBGaW5kIHRoZSBuZXh0XG5cdFx0XHQvLyBsYXJnZXIgb25lOlxuXHRcdFx0Zm9yIChtID0gbWF4SW50LCBqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPj0gbiAmJiBjdXJyZW50VmFsdWUgPCBtKSB7XG5cdFx0XHRcdFx0bSA9IGN1cnJlbnRWYWx1ZTtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQvLyBJbmNyZWFzZSBgZGVsdGFgIGVub3VnaCB0byBhZHZhbmNlIHRoZSBkZWNvZGVyJ3MgPG4saT4gc3RhdGUgdG8gPG0sMD4sXG5cdFx0XHQvLyBidXQgZ3VhcmQgYWdhaW5zdCBvdmVyZmxvd1xuXHRcdFx0aGFuZGxlZENQQ291bnRQbHVzT25lID0gaGFuZGxlZENQQ291bnQgKyAxO1xuXHRcdFx0aWYgKG0gLSBuID4gZmxvb3IoKG1heEludCAtIGRlbHRhKSAvIGhhbmRsZWRDUENvdW50UGx1c09uZSkpIHtcblx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHR9XG5cblx0XHRcdGRlbHRhICs9IChtIC0gbikgKiBoYW5kbGVkQ1BDb3VudFBsdXNPbmU7XG5cdFx0XHRuID0gbTtcblxuXHRcdFx0Zm9yIChqID0gMDsgaiA8IGlucHV0TGVuZ3RoOyArK2opIHtcblx0XHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA8IG4gJiYgKytkZWx0YSA+IG1heEludCkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA9PSBuKSB7XG5cdFx0XHRcdFx0Ly8gUmVwcmVzZW50IGRlbHRhIGFzIGEgZ2VuZXJhbGl6ZWQgdmFyaWFibGUtbGVuZ3RoIGludGVnZXJcblx0XHRcdFx0XHRmb3IgKHEgPSBkZWx0YSwgayA9IGJhc2U7IC8qIG5vIGNvbmRpdGlvbiAqLzsgayArPSBiYXNlKSB7XG5cdFx0XHRcdFx0XHR0ID0gayA8PSBiaWFzID8gdE1pbiA6IChrID49IGJpYXMgKyB0TWF4ID8gdE1heCA6IGsgLSBiaWFzKTtcblx0XHRcdFx0XHRcdGlmIChxIDwgdCkge1xuXHRcdFx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRcdHFNaW51c1QgPSBxIC0gdDtcblx0XHRcdFx0XHRcdGJhc2VNaW51c1QgPSBiYXNlIC0gdDtcblx0XHRcdFx0XHRcdG91dHB1dC5wdXNoKFxuXHRcdFx0XHRcdFx0XHRzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHQgKyBxTWludXNUICUgYmFzZU1pbnVzVCwgMCkpXG5cdFx0XHRcdFx0XHQpO1xuXHRcdFx0XHRcdFx0cSA9IGZsb29yKHFNaW51c1QgLyBiYXNlTWludXNUKTtcblx0XHRcdFx0XHR9XG5cblx0XHRcdFx0XHRvdXRwdXQucHVzaChzdHJpbmdGcm9tQ2hhckNvZGUoZGlnaXRUb0Jhc2ljKHEsIDApKSk7XG5cdFx0XHRcdFx0YmlhcyA9IGFkYXB0KGRlbHRhLCBoYW5kbGVkQ1BDb3VudFBsdXNPbmUsIGhhbmRsZWRDUENvdW50ID09IGJhc2ljTGVuZ3RoKTtcblx0XHRcdFx0XHRkZWx0YSA9IDA7XG5cdFx0XHRcdFx0KytoYW5kbGVkQ1BDb3VudDtcblx0XHRcdFx0fVxuXHRcdFx0fVxuXG5cdFx0XHQrK2RlbHRhO1xuXHRcdFx0KytuO1xuXG5cdFx0fVxuXHRcdHJldHVybiBvdXRwdXQuam9pbignJyk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBQdW55Y29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzc1xuXHQgKiB0byBVbmljb2RlLiBPbmx5IHRoZSBQdW55Y29kZWQgcGFydHMgb2YgdGhlIGlucHV0IHdpbGwgYmUgY29udmVydGVkLCBpLmUuXG5cdCAqIGl0IGRvZXNuJ3QgbWF0dGVyIGlmIHlvdSBjYWxsIGl0IG9uIGEgc3RyaW5nIHRoYXQgaGFzIGFscmVhZHkgYmVlblxuXHQgKiBjb252ZXJ0ZWQgdG8gVW5pY29kZS5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgUHVueWNvZGVkIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MgdG9cblx0ICogY29udmVydCB0byBVbmljb2RlLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgVW5pY29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gUHVueWNvZGVcblx0ICogc3RyaW5nLlxuXHQgKi9cblx0ZnVuY3Rpb24gdG9Vbmljb2RlKGlucHV0KSB7XG5cdFx0cmV0dXJuIG1hcERvbWFpbihpbnB1dCwgZnVuY3Rpb24oc3RyaW5nKSB7XG5cdFx0XHRyZXR1cm4gcmVnZXhQdW55Y29kZS50ZXN0KHN0cmluZylcblx0XHRcdFx0PyBkZWNvZGUoc3RyaW5nLnNsaWNlKDQpLnRvTG93ZXJDYXNlKCkpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgVW5pY29kZSBzdHJpbmcgcmVwcmVzZW50aW5nIGEgZG9tYWluIG5hbWUgb3IgYW4gZW1haWwgYWRkcmVzcyB0b1xuXHQgKiBQdW55Y29kZS4gT25seSB0aGUgbm9uLUFTQ0lJIHBhcnRzIG9mIHRoZSBkb21haW4gbmFtZSB3aWxsIGJlIGNvbnZlcnRlZCxcblx0ICogaS5lLiBpdCBkb2Vzbid0IG1hdHRlciBpZiB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQncyBhbHJlYWR5IGluXG5cdCAqIEFTQ0lJLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzIHRvIGNvbnZlcnQsIGFzIGFcblx0ICogVW5pY29kZSBzdHJpbmcuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBQdW55Y29kZSByZXByZXNlbnRhdGlvbiBvZiB0aGUgZ2l2ZW4gZG9tYWluIG5hbWUgb3Jcblx0ICogZW1haWwgYWRkcmVzcy5cblx0ICovXG5cdGZ1bmN0aW9uIHRvQVNDSUkoaW5wdXQpIHtcblx0XHRyZXR1cm4gbWFwRG9tYWluKGlucHV0LCBmdW5jdGlvbihzdHJpbmcpIHtcblx0XHRcdHJldHVybiByZWdleE5vbkFTQ0lJLnRlc3Qoc3RyaW5nKVxuXHRcdFx0XHQ/ICd4bi0tJyArIGVuY29kZShzdHJpbmcpXG5cdFx0XHRcdDogc3RyaW5nO1xuXHRcdH0pO1xuXHR9XG5cblx0LyotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSovXG5cblx0LyoqIERlZmluZSB0aGUgcHVibGljIEFQSSAqL1xuXHRwdW55Y29kZSA9IHtcblx0XHQvKipcblx0XHQgKiBBIHN0cmluZyByZXByZXNlbnRpbmcgdGhlIGN1cnJlbnQgUHVueWNvZGUuanMgdmVyc2lvbiBudW1iZXIuXG5cdFx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdFx0ICogQHR5cGUgU3RyaW5nXG5cdFx0ICovXG5cdFx0J3ZlcnNpb24nOiAnMS40LjEnLFxuXHRcdC8qKlxuXHRcdCAqIEFuIG9iamVjdCBvZiBtZXRob2RzIHRvIGNvbnZlcnQgZnJvbSBKYXZhU2NyaXB0J3MgaW50ZXJuYWwgY2hhcmFjdGVyXG5cdFx0ICogcmVwcmVzZW50YXRpb24gKFVDUy0yKSB0byBVbmljb2RlIGNvZGUgcG9pbnRzLCBhbmQgYmFjay5cblx0XHQgKiBAc2VlIDxodHRwczovL21hdGhpYXNieW5lbnMuYmUvbm90ZXMvamF2YXNjcmlwdC1lbmNvZGluZz5cblx0XHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0XHQgKiBAdHlwZSBPYmplY3Rcblx0XHQgKi9cblx0XHQndWNzMic6IHtcblx0XHRcdCdkZWNvZGUnOiB1Y3MyZGVjb2RlLFxuXHRcdFx0J2VuY29kZSc6IHVjczJlbmNvZGVcblx0XHR9LFxuXHRcdCdkZWNvZGUnOiBkZWNvZGUsXG5cdFx0J2VuY29kZSc6IGVuY29kZSxcblx0XHQndG9BU0NJSSc6IHRvQVNDSUksXG5cdFx0J3RvVW5pY29kZSc6IHRvVW5pY29kZVxuXHR9O1xuXG5cdC8qKiBFeHBvc2UgYHB1bnljb2RlYCAqL1xuXHQvLyBTb21lIEFNRCBidWlsZCBvcHRpbWl6ZXJzLCBsaWtlIHIuanMsIGNoZWNrIGZvciBzcGVjaWZpYyBjb25kaXRpb24gcGF0dGVybnNcblx0Ly8gbGlrZSB0aGUgZm9sbG93aW5nOlxuXHRpZiAoXG5cdFx0dHlwZW9mIGRlZmluZSA9PSAnZnVuY3Rpb24nICYmXG5cdFx0dHlwZW9mIGRlZmluZS5hbWQgPT0gJ29iamVjdCcgJiZcblx0XHRkZWZpbmUuYW1kXG5cdCkge1xuXHRcdGRlZmluZSgncHVueWNvZGUnLCBmdW5jdGlvbigpIHtcblx0XHRcdHJldHVybiBwdW55Y29kZTtcblx0XHR9KTtcblx0fSBlbHNlIGlmIChmcmVlRXhwb3J0cyAmJiBmcmVlTW9kdWxlKSB7XG5cdFx0aWYgKG1vZHVsZS5leHBvcnRzID09IGZyZWVFeHBvcnRzKSB7XG5cdFx0XHQvLyBpbiBOb2RlLmpzLCBpby5qcywgb3IgUmluZ29KUyB2MC44LjArXG5cdFx0XHRmcmVlTW9kdWxlLmV4cG9ydHMgPSBwdW55Y29kZTtcblx0XHR9IGVsc2Uge1xuXHRcdFx0Ly8gaW4gTmFyd2hhbCBvciBSaW5nb0pTIHYwLjcuMC1cblx0XHRcdGZvciAoa2V5IGluIHB1bnljb2RlKSB7XG5cdFx0XHRcdHB1bnljb2RlLmhhc093blByb3BlcnR5KGtleSkgJiYgKGZyZWVFeHBvcnRzW2tleV0gPSBwdW55Y29kZVtrZXldKTtcblx0XHRcdH1cblx0XHR9XG5cdH0gZWxzZSB7XG5cdFx0Ly8gaW4gUmhpbm8gb3IgYSB3ZWIgYnJvd3NlclxuXHRcdHJvb3QucHVueWNvZGUgPSBwdW55Y29kZTtcblx0fVxuXG59KHRoaXMpKTtcbiIsIi8qXG4gKiBxdWFudGl6ZS5qcyBDb3B5cmlnaHQgMjAwOCBOaWNrIFJhYmlub3dpdHpcbiAqIFBvcnRlZCB0byBub2RlLmpzIGJ5IE9saXZpZXIgTGVzbmlja2lcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBNSVQgbGljZW5zZTogaHR0cDovL3d3dy5vcGVuc291cmNlLm9yZy9saWNlbnNlcy9taXQtbGljZW5zZS5waHBcbiAqL1xuXG4vLyBmaWxsIG91dCBhIGNvdXBsZSBwcm90b3ZpcyBkZXBlbmRlbmNpZXNcbi8qXG4gKiBCbG9jayBiZWxvdyBjb3BpZWQgZnJvbSBQcm90b3ZpczogaHR0cDovL21ib3N0b2NrLmdpdGh1Yi5jb20vcHJvdG92aXMvXG4gKiBDb3B5cmlnaHQgMjAxMCBTdGFuZm9yZCBWaXN1YWxpemF0aW9uIEdyb3VwXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgQlNEIExpY2Vuc2U6IGh0dHA6Ly93d3cub3BlbnNvdXJjZS5vcmcvbGljZW5zZXMvYnNkLWxpY2Vuc2UucGhwXG4gKi9cbmlmICghcHYpIHtcbiAgICB2YXIgcHYgPSB7XG4gICAgICAgIG1hcDogZnVuY3Rpb24oYXJyYXksIGYpIHtcbiAgICAgICAgICAgIHZhciBvID0ge307XG4gICAgICAgICAgICByZXR1cm4gZiA/IGFycmF5Lm1hcChmdW5jdGlvbihkLCBpKSB7XG4gICAgICAgICAgICAgICAgby5pbmRleCA9IGk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGYuY2FsbChvLCBkKTtcbiAgICAgICAgICAgIH0pIDogYXJyYXkuc2xpY2UoKTtcbiAgICAgICAgfSxcbiAgICAgICAgbmF0dXJhbE9yZGVyOiBmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gKGEgPCBiKSA/IC0xIDogKChhID4gYikgPyAxIDogMCk7XG4gICAgICAgIH0sXG4gICAgICAgIHN1bTogZnVuY3Rpb24oYXJyYXksIGYpIHtcbiAgICAgICAgICAgIHZhciBvID0ge307XG4gICAgICAgICAgICByZXR1cm4gYXJyYXkucmVkdWNlKGYgPyBmdW5jdGlvbihwLCBkLCBpKSB7XG4gICAgICAgICAgICAgICAgby5pbmRleCA9IGk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHAgKyBmLmNhbGwobywgZCk7XG4gICAgICAgICAgICB9IDogZnVuY3Rpb24ocCwgZCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBwICsgZDtcbiAgICAgICAgICAgIH0sIDApO1xuICAgICAgICB9LFxuICAgICAgICBtYXg6IGZ1bmN0aW9uKGFycmF5LCBmKSB7XG4gICAgICAgICAgICByZXR1cm4gTWF0aC5tYXguYXBwbHkobnVsbCwgZiA/IHB2Lm1hcChhcnJheSwgZikgOiBhcnJheSk7XG4gICAgICAgIH1cbiAgICB9XG59XG5cbi8qKlxuICogQmFzaWMgSmF2YXNjcmlwdCBwb3J0IG9mIHRoZSBNTUNRIChtb2RpZmllZCBtZWRpYW4gY3V0IHF1YW50aXphdGlvbilcbiAqIGFsZ29yaXRobSBmcm9tIHRoZSBMZXB0b25pY2EgbGlicmFyeSAoaHR0cDovL3d3dy5sZXB0b25pY2EuY29tLykuXG4gKiBSZXR1cm5zIGEgY29sb3IgbWFwIHlvdSBjYW4gdXNlIHRvIG1hcCBvcmlnaW5hbCBwaXhlbHMgdG8gdGhlIHJlZHVjZWRcbiAqIHBhbGV0dGUuIFN0aWxsIGEgd29yayBpbiBwcm9ncmVzcy5cbiAqIFxuICogQGF1dGhvciBOaWNrIFJhYmlub3dpdHpcbiAqIEBleGFtcGxlXG4gXG4vLyBhcnJheSBvZiBwaXhlbHMgYXMgW1IsRyxCXSBhcnJheXNcbnZhciBteVBpeGVscyA9IFtbMTkwLDE5NywxOTBdLCBbMjAyLDIwNCwyMDBdLCBbMjA3LDIxNCwyMTBdLCBbMjExLDIxNCwyMTFdLCBbMjA1LDIwNywyMDddXG4gICAgICAgICAgICAgICAgLy8gZXRjXG4gICAgICAgICAgICAgICAgXTtcbnZhciBtYXhDb2xvcnMgPSA0O1xuIFxudmFyIGNtYXAgPSBNTUNRLnF1YW50aXplKG15UGl4ZWxzLCBtYXhDb2xvcnMpO1xudmFyIG5ld1BhbGV0dGUgPSBjbWFwLnBhbGV0dGUoKTtcbnZhciBuZXdQaXhlbHMgPSBteVBpeGVscy5tYXAoZnVuY3Rpb24ocCkgeyBcbiAgICByZXR1cm4gY21hcC5tYXAocCk7IFxufSk7XG4gXG4gKi9cbnZhciBNTUNRID0gKGZ1bmN0aW9uKCkge1xuICAgIC8vIHByaXZhdGUgY29uc3RhbnRzXG4gICAgdmFyIHNpZ2JpdHMgPSA1LFxuICAgICAgICByc2hpZnQgPSA4IC0gc2lnYml0cyxcbiAgICAgICAgbWF4SXRlcmF0aW9ucyA9IDEwMDAsXG4gICAgICAgIGZyYWN0QnlQb3B1bGF0aW9ucyA9IDAuNzU7XG5cbiAgICAvLyBnZXQgcmVkdWNlZC1zcGFjZSBjb2xvciBpbmRleCBmb3IgYSBwaXhlbFxuXG4gICAgZnVuY3Rpb24gZ2V0Q29sb3JJbmRleChyLCBnLCBiKSB7XG4gICAgICAgIHJldHVybiAociA8PCAoMiAqIHNpZ2JpdHMpKSArIChnIDw8IHNpZ2JpdHMpICsgYjtcbiAgICB9XG5cbiAgICAvLyBTaW1wbGUgcHJpb3JpdHkgcXVldWVcblxuICAgIGZ1bmN0aW9uIFBRdWV1ZShjb21wYXJhdG9yKSB7XG4gICAgICAgIHZhciBjb250ZW50cyA9IFtdLFxuICAgICAgICAgICAgc29ydGVkID0gZmFsc2U7XG5cbiAgICAgICAgZnVuY3Rpb24gc29ydCgpIHtcbiAgICAgICAgICAgIGNvbnRlbnRzLnNvcnQoY29tcGFyYXRvcik7XG4gICAgICAgICAgICBzb3J0ZWQgPSB0cnVlO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgIHB1c2g6IGZ1bmN0aW9uKG8pIHtcbiAgICAgICAgICAgICAgICBjb250ZW50cy5wdXNoKG8pO1xuICAgICAgICAgICAgICAgIHNvcnRlZCA9IGZhbHNlO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHBlZWs6IGZ1bmN0aW9uKGluZGV4KSB7XG4gICAgICAgICAgICAgICAgaWYgKCFzb3J0ZWQpIHNvcnQoKTtcbiAgICAgICAgICAgICAgICBpZiAoaW5kZXggPT09IHVuZGVmaW5lZCkgaW5kZXggPSBjb250ZW50cy5sZW5ndGggLSAxO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50c1tpbmRleF07XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgcG9wOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNvcnRlZCkgc29ydCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cy5wb3AoKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzaXplOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHMubGVuZ3RoO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIG1hcDogZnVuY3Rpb24oZikge1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cy5tYXAoZik7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZGVidWc6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIGlmICghc29ydGVkKSBzb3J0KCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzO1xuICAgICAgICAgICAgfVxuICAgICAgICB9O1xuICAgIH1cblxuICAgIC8vIDNkIGNvbG9yIHNwYWNlIGJveFxuXG4gICAgZnVuY3Rpb24gVkJveChyMSwgcjIsIGcxLCBnMiwgYjEsIGIyLCBoaXN0bykge1xuICAgICAgICB2YXIgdmJveCA9IHRoaXM7XG4gICAgICAgIHZib3gucjEgPSByMTtcbiAgICAgICAgdmJveC5yMiA9IHIyO1xuICAgICAgICB2Ym94LmcxID0gZzE7XG4gICAgICAgIHZib3guZzIgPSBnMjtcbiAgICAgICAgdmJveC5iMSA9IGIxO1xuICAgICAgICB2Ym94LmIyID0gYjI7XG4gICAgICAgIHZib3guaGlzdG8gPSBoaXN0bztcbiAgICB9XG4gICAgVkJveC5wcm90b3R5cGUgPSB7XG4gICAgICAgIHZvbHVtZTogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcztcbiAgICAgICAgICAgIGlmICghdmJveC5fdm9sdW1lIHx8IGZvcmNlKSB7XG4gICAgICAgICAgICAgICAgdmJveC5fdm9sdW1lID0gKCh2Ym94LnIyIC0gdmJveC5yMSArIDEpICogKHZib3guZzIgLSB2Ym94LmcxICsgMSkgKiAodmJveC5iMiAtIHZib3guYjEgKyAxKSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdmJveC5fdm9sdW1lO1xuICAgICAgICB9LFxuICAgICAgICBjb3VudDogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcyxcbiAgICAgICAgICAgICAgICBoaXN0byA9IHZib3guaGlzdG87XG4gICAgICAgICAgICBpZiAoIXZib3guX2NvdW50X3NldCB8fCBmb3JjZSkge1xuICAgICAgICAgICAgICAgIHZhciBucGl4ID0gMCxcbiAgICAgICAgICAgICAgICAgICAgaSwgaiwgaywgaW5kZXg7XG4gICAgICAgICAgICAgICAgZm9yIChpID0gdmJveC5yMTsgaSA8PSB2Ym94LnIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5nMTsgaiA8PSB2Ym94LmcyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGksIGosIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG5waXggKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB2Ym94Ll9jb3VudCA9IG5waXg7XG4gICAgICAgICAgICAgICAgdmJveC5fY291bnRfc2V0ID0gdHJ1ZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB2Ym94Ll9jb3VudDtcbiAgICAgICAgfSxcbiAgICAgICAgY29weTogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXM7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFZCb3godmJveC5yMSwgdmJveC5yMiwgdmJveC5nMSwgdmJveC5nMiwgdmJveC5iMSwgdmJveC5iMiwgdmJveC5oaXN0byk7XG4gICAgICAgIH0sXG4gICAgICAgIGF2ZzogZnVuY3Rpb24oZm9yY2UpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcyxcbiAgICAgICAgICAgICAgICBoaXN0byA9IHZib3guaGlzdG87XG4gICAgICAgICAgICBpZiAoIXZib3guX2F2ZyB8fCBmb3JjZSkge1xuICAgICAgICAgICAgICAgIHZhciBudG90ID0gMCxcbiAgICAgICAgICAgICAgICAgICAgbXVsdCA9IDEgPDwgKDggLSBzaWdiaXRzKSxcbiAgICAgICAgICAgICAgICAgICAgcnN1bSA9IDAsXG4gICAgICAgICAgICAgICAgICAgIGdzdW0gPSAwLFxuICAgICAgICAgICAgICAgICAgICBic3VtID0gMCxcbiAgICAgICAgICAgICAgICAgICAgaHZhbCxcbiAgICAgICAgICAgICAgICAgICAgaSwgaiwgaywgaGlzdG9pbmRleDtcbiAgICAgICAgICAgICAgICBmb3IgKGkgPSB2Ym94LnIxOyBpIDw9IHZib3gucjI7IGkrKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LmcxOyBqIDw9IHZib3guZzI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5iMTsgayA8PSB2Ym94LmIyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBoaXN0b2luZGV4ID0gZ2V0Q29sb3JJbmRleChpLCBqLCBrKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBodmFsID0gaGlzdG9baGlzdG9pbmRleF0gfHwgMDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBudG90ICs9IGh2YWw7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcnN1bSArPSAoaHZhbCAqIChpICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGdzdW0gKz0gKGh2YWwgKiAoaiArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBic3VtICs9IChodmFsICogKGsgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKG50b3QpIHtcbiAgICAgICAgICAgICAgICAgICAgdmJveC5fYXZnID0gW35+KHJzdW0gLyBudG90KSwgfn4gKGdzdW0gLyBudG90KSwgfn4gKGJzdW0gLyBudG90KV07XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgICAgLy9jb25zb2xlLmxvZygnZW1wdHkgYm94Jyk7XG4gICAgICAgICAgICAgICAgICAgIHZib3guX2F2ZyA9IFt+fihtdWx0ICogKHZib3gucjEgKyB2Ym94LnIyICsgMSkgLyAyKSwgfn4gKG11bHQgKiAodmJveC5nMSArIHZib3guZzIgKyAxKSAvIDIpLCB+fiAobXVsdCAqICh2Ym94LmIxICsgdmJveC5iMiArIDEpIC8gMildO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB2Ym94Ll9hdmc7XG4gICAgICAgIH0sXG4gICAgICAgIGNvbnRhaW5zOiBmdW5jdGlvbihwaXhlbCkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzLFxuICAgICAgICAgICAgICAgIHJ2YWwgPSBwaXhlbFswXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBndmFsID0gcGl4ZWxbMV0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgYnZhbCA9IHBpeGVsWzJdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIHJldHVybiAocnZhbCA+PSB2Ym94LnIxICYmIHJ2YWwgPD0gdmJveC5yMiAmJlxuICAgICAgICAgICAgICAgIGd2YWwgPj0gdmJveC5nMSAmJiBndmFsIDw9IHZib3guZzIgJiZcbiAgICAgICAgICAgICAgICBidmFsID49IHZib3guYjEgJiYgYnZhbCA8PSB2Ym94LmIyKTtcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBDb2xvciBtYXBcblxuICAgIGZ1bmN0aW9uIENNYXAoKSB7XG4gICAgICAgIHRoaXMudmJveGVzID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKFxuICAgICAgICAgICAgICAgIGEudmJveC5jb3VudCgpICogYS52Ym94LnZvbHVtZSgpLFxuICAgICAgICAgICAgICAgIGIudmJveC5jb3VudCgpICogYi52Ym94LnZvbHVtZSgpXG4gICAgICAgICAgICApXG4gICAgICAgIH0pOztcbiAgICB9XG4gICAgQ01hcC5wcm90b3R5cGUgPSB7XG4gICAgICAgIHB1c2g6IGZ1bmN0aW9uKHZib3gpIHtcbiAgICAgICAgICAgIHRoaXMudmJveGVzLnB1c2goe1xuICAgICAgICAgICAgICAgIHZib3g6IHZib3gsXG4gICAgICAgICAgICAgICAgY29sb3I6IHZib3guYXZnKClcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBwYWxldHRlOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZib3hlcy5tYXAoZnVuY3Rpb24odmIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gdmIuY29sb3JcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9LFxuICAgICAgICBzaXplOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHJldHVybiB0aGlzLnZib3hlcy5zaXplKCk7XG4gICAgICAgIH0sXG4gICAgICAgIG1hcDogZnVuY3Rpb24oY29sb3IpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ZXMgPSB0aGlzLnZib3hlcztcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdmJveGVzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgaWYgKHZib3hlcy5wZWVrKGkpLnZib3guY29udGFpbnMoY29sb3IpKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB2Ym94ZXMucGVlayhpKS5jb2xvcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5uZWFyZXN0KGNvbG9yKTtcbiAgICAgICAgfSxcbiAgICAgICAgbmVhcmVzdDogZnVuY3Rpb24oY29sb3IpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ZXMgPSB0aGlzLnZib3hlcyxcbiAgICAgICAgICAgICAgICBkMSwgZDIsIHBDb2xvcjtcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdmJveGVzLnNpemUoKTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgZDIgPSBNYXRoLnNxcnQoXG4gICAgICAgICAgICAgICAgICAgIE1hdGgucG93KGNvbG9yWzBdIC0gdmJveGVzLnBlZWsoaSkuY29sb3JbMF0sIDIpICtcbiAgICAgICAgICAgICAgICAgICAgTWF0aC5wb3coY29sb3JbMV0gLSB2Ym94ZXMucGVlayhpKS5jb2xvclsxXSwgMikgK1xuICAgICAgICAgICAgICAgICAgICBNYXRoLnBvdyhjb2xvclsyXSAtIHZib3hlcy5wZWVrKGkpLmNvbG9yWzJdLCAyKVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgICAgaWYgKGQyIDwgZDEgfHwgZDEgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgICAgICBkMSA9IGQyO1xuICAgICAgICAgICAgICAgICAgICBwQ29sb3IgPSB2Ym94ZXMucGVlayhpKS5jb2xvcjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gcENvbG9yO1xuICAgICAgICB9LFxuICAgICAgICBmb3JjZWJ3OiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIC8vIFhYWDogd29uJ3QgIHdvcmsgeWV0XG4gICAgICAgICAgICB2YXIgdmJveGVzID0gdGhpcy52Ym94ZXM7XG4gICAgICAgICAgICB2Ym94ZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihwdi5zdW0oYS5jb2xvciksIHB2LnN1bShiLmNvbG9yKSlcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICAvLyBmb3JjZSBkYXJrZXN0IGNvbG9yIHRvIGJsYWNrIGlmIGV2ZXJ5dGhpbmcgPCA1XG4gICAgICAgICAgICB2YXIgbG93ZXN0ID0gdmJveGVzWzBdLmNvbG9yO1xuICAgICAgICAgICAgaWYgKGxvd2VzdFswXSA8IDUgJiYgbG93ZXN0WzFdIDwgNSAmJiBsb3dlc3RbMl0gPCA1KVxuICAgICAgICAgICAgICAgIHZib3hlc1swXS5jb2xvciA9IFswLCAwLCAwXTtcblxuICAgICAgICAgICAgLy8gZm9yY2UgbGlnaHRlc3QgY29sb3IgdG8gd2hpdGUgaWYgZXZlcnl0aGluZyA+IDI1MVxuICAgICAgICAgICAgdmFyIGlkeCA9IHZib3hlcy5sZW5ndGggLSAxLFxuICAgICAgICAgICAgICAgIGhpZ2hlc3QgPSB2Ym94ZXNbaWR4XS5jb2xvcjtcbiAgICAgICAgICAgIGlmIChoaWdoZXN0WzBdID4gMjUxICYmIGhpZ2hlc3RbMV0gPiAyNTEgJiYgaGlnaGVzdFsyXSA+IDI1MSlcbiAgICAgICAgICAgICAgICB2Ym94ZXNbaWR4XS5jb2xvciA9IFsyNTUsIDI1NSwgMjU1XTtcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICAvLyBoaXN0byAoMS1kIGFycmF5LCBnaXZpbmcgdGhlIG51bWJlciBvZiBwaXhlbHMgaW5cbiAgICAvLyBlYWNoIHF1YW50aXplZCByZWdpb24gb2YgY29sb3Igc3BhY2UpLCBvciBudWxsIG9uIGVycm9yXG5cbiAgICBmdW5jdGlvbiBnZXRIaXN0byhwaXhlbHMpIHtcbiAgICAgICAgdmFyIGhpc3Rvc2l6ZSA9IDEgPDwgKDMgKiBzaWdiaXRzKSxcbiAgICAgICAgICAgIGhpc3RvID0gbmV3IEFycmF5KGhpc3Rvc2l6ZSksXG4gICAgICAgICAgICBpbmRleCwgcnZhbCwgZ3ZhbCwgYnZhbDtcbiAgICAgICAgcGl4ZWxzLmZvckVhY2goZnVuY3Rpb24ocGl4ZWwpIHtcbiAgICAgICAgICAgIHJ2YWwgPSBwaXhlbFswXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBndmFsID0gcGl4ZWxbMV0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgYnZhbCA9IHBpeGVsWzJdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChydmFsLCBndmFsLCBidmFsKTtcbiAgICAgICAgICAgIGhpc3RvW2luZGV4XSA9IChoaXN0b1tpbmRleF0gfHwgMCkgKyAxO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIGhpc3RvO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHZib3hGcm9tUGl4ZWxzKHBpeGVscywgaGlzdG8pIHtcbiAgICAgICAgdmFyIHJtaW4gPSAxMDAwMDAwLFxuICAgICAgICAgICAgcm1heCA9IDAsXG4gICAgICAgICAgICBnbWluID0gMTAwMDAwMCxcbiAgICAgICAgICAgIGdtYXggPSAwLFxuICAgICAgICAgICAgYm1pbiA9IDEwMDAwMDAsXG4gICAgICAgICAgICBibWF4ID0gMCxcbiAgICAgICAgICAgIHJ2YWwsIGd2YWwsIGJ2YWw7XG4gICAgICAgIC8vIGZpbmQgbWluL21heFxuICAgICAgICBwaXhlbHMuZm9yRWFjaChmdW5jdGlvbihwaXhlbCkge1xuICAgICAgICAgICAgcnZhbCA9IHBpeGVsWzBdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGd2YWwgPSBwaXhlbFsxXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBidmFsID0gcGl4ZWxbMl0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgaWYgKHJ2YWwgPCBybWluKSBybWluID0gcnZhbDtcbiAgICAgICAgICAgIGVsc2UgaWYgKHJ2YWwgPiBybWF4KSBybWF4ID0gcnZhbDtcbiAgICAgICAgICAgIGlmIChndmFsIDwgZ21pbikgZ21pbiA9IGd2YWw7XG4gICAgICAgICAgICBlbHNlIGlmIChndmFsID4gZ21heCkgZ21heCA9IGd2YWw7XG4gICAgICAgICAgICBpZiAoYnZhbCA8IGJtaW4pIGJtaW4gPSBidmFsO1xuICAgICAgICAgICAgZWxzZSBpZiAoYnZhbCA+IGJtYXgpIGJtYXggPSBidmFsO1xuICAgICAgICB9KTtcbiAgICAgICAgcmV0dXJuIG5ldyBWQm94KHJtaW4sIHJtYXgsIGdtaW4sIGdtYXgsIGJtaW4sIGJtYXgsIGhpc3RvKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBtZWRpYW5DdXRBcHBseShoaXN0bywgdmJveCkge1xuICAgICAgICBpZiAoIXZib3guY291bnQoKSkgcmV0dXJuO1xuXG4gICAgICAgIHZhciBydyA9IHZib3gucjIgLSB2Ym94LnIxICsgMSxcbiAgICAgICAgICAgIGd3ID0gdmJveC5nMiAtIHZib3guZzEgKyAxLFxuICAgICAgICAgICAgYncgPSB2Ym94LmIyIC0gdmJveC5iMSArIDEsXG4gICAgICAgICAgICBtYXh3ID0gcHYubWF4KFtydywgZ3csIGJ3XSk7XG4gICAgICAgIC8vIG9ubHkgb25lIHBpeGVsLCBubyBzcGxpdFxuICAgICAgICBpZiAodmJveC5jb3VudCgpID09IDEpIHtcbiAgICAgICAgICAgIHJldHVybiBbdmJveC5jb3B5KCldXG4gICAgICAgIH1cbiAgICAgICAgLyogRmluZCB0aGUgcGFydGlhbCBzdW0gYXJyYXlzIGFsb25nIHRoZSBzZWxlY3RlZCBheGlzLiAqL1xuICAgICAgICB2YXIgdG90YWwgPSAwLFxuICAgICAgICAgICAgcGFydGlhbHN1bSA9IFtdLFxuICAgICAgICAgICAgbG9va2FoZWFkc3VtID0gW10sXG4gICAgICAgICAgICBpLCBqLCBrLCBzdW0sIGluZGV4O1xuICAgICAgICBpZiAobWF4dyA9PSBydykge1xuICAgICAgICAgICAgZm9yIChpID0gdmJveC5yMTsgaSA8PSB2Ym94LnIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICBzdW0gPSAwO1xuICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3guZzE7IGogPD0gdmJveC5nMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaSwgaiwgayk7XG4gICAgICAgICAgICAgICAgICAgICAgICBzdW0gKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgICAgICAgcGFydGlhbHN1bVtpXSA9IHRvdGFsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgaWYgKG1heHcgPT0gZ3cpIHtcbiAgICAgICAgICAgIGZvciAoaSA9IHZib3guZzE7IGkgPD0gdmJveC5nMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgc3VtID0gMDtcbiAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LnIxOyBqIDw9IHZib3gucjI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmIxOyBrIDw9IHZib3guYjI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGosIGksIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgc3VtICs9IChoaXN0b1tpbmRleF0gfHwgMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgICAgICAgIHBhcnRpYWxzdW1baV0gPSB0b3RhbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHsgLyogbWF4dyA9PSBidyAqL1xuICAgICAgICAgICAgZm9yIChpID0gdmJveC5iMTsgaSA8PSB2Ym94LmIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICBzdW0gPSAwO1xuICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3gucjE7IGogPD0gdmJveC5yMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guZzE7IGsgPD0gdmJveC5nMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaiwgaywgaSk7XG4gICAgICAgICAgICAgICAgICAgICAgICBzdW0gKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgICAgICAgcGFydGlhbHN1bVtpXSA9IHRvdGFsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHBhcnRpYWxzdW0uZm9yRWFjaChmdW5jdGlvbihkLCBpKSB7XG4gICAgICAgICAgICBsb29rYWhlYWRzdW1baV0gPSB0b3RhbCAtIGRcbiAgICAgICAgfSk7XG5cbiAgICAgICAgZnVuY3Rpb24gZG9DdXQoY29sb3IpIHtcbiAgICAgICAgICAgIHZhciBkaW0xID0gY29sb3IgKyAnMScsXG4gICAgICAgICAgICAgICAgZGltMiA9IGNvbG9yICsgJzInLFxuICAgICAgICAgICAgICAgIGxlZnQsIHJpZ2h0LCB2Ym94MSwgdmJveDIsIGQyLCBjb3VudDIgPSAwO1xuICAgICAgICAgICAgZm9yIChpID0gdmJveFtkaW0xXTsgaSA8PSB2Ym94W2RpbTJdOyBpKyspIHtcbiAgICAgICAgICAgICAgICBpZiAocGFydGlhbHN1bVtpXSA+IHRvdGFsIC8gMikge1xuICAgICAgICAgICAgICAgICAgICB2Ym94MSA9IHZib3guY29weSgpO1xuICAgICAgICAgICAgICAgICAgICB2Ym94MiA9IHZib3guY29weSgpO1xuICAgICAgICAgICAgICAgICAgICBsZWZ0ID0gaSAtIHZib3hbZGltMV07XG4gICAgICAgICAgICAgICAgICAgIHJpZ2h0ID0gdmJveFtkaW0yXSAtIGk7XG4gICAgICAgICAgICAgICAgICAgIGlmIChsZWZ0IDw9IHJpZ2h0KVxuICAgICAgICAgICAgICAgICAgICAgICAgZDIgPSBNYXRoLm1pbih2Ym94W2RpbTJdIC0gMSwgfn4gKGkgKyByaWdodCAvIDIpKTtcbiAgICAgICAgICAgICAgICAgICAgZWxzZSBkMiA9IE1hdGgubWF4KHZib3hbZGltMV0sIH5+IChpIC0gMSAtIGxlZnQgLyAyKSk7XG4gICAgICAgICAgICAgICAgICAgIC8vIGF2b2lkIDAtY291bnQgYm94ZXNcbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCFwYXJ0aWFsc3VtW2QyXSkgZDIrKztcbiAgICAgICAgICAgICAgICAgICAgY291bnQyID0gbG9va2FoZWFkc3VtW2QyXTtcbiAgICAgICAgICAgICAgICAgICAgd2hpbGUgKCFjb3VudDIgJiYgcGFydGlhbHN1bVtkMiAtIDFdKSBjb3VudDIgPSBsb29rYWhlYWRzdW1bLS1kMl07XG4gICAgICAgICAgICAgICAgICAgIC8vIHNldCBkaW1lbnNpb25zXG4gICAgICAgICAgICAgICAgICAgIHZib3gxW2RpbTJdID0gZDI7XG4gICAgICAgICAgICAgICAgICAgIHZib3gyW2RpbTFdID0gdmJveDFbZGltMl0gKyAxO1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZygndmJveCBjb3VudHM6JywgdmJveC5jb3VudCgpLCB2Ym94MS5jb3VudCgpLCB2Ym94Mi5jb3VudCgpKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFt2Ym94MSwgdmJveDJdO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICB9XG4gICAgICAgIC8vIGRldGVybWluZSB0aGUgY3V0IHBsYW5lc1xuICAgICAgICByZXR1cm4gbWF4dyA9PSBydyA/IGRvQ3V0KCdyJykgOlxuICAgICAgICAgICAgbWF4dyA9PSBndyA/IGRvQ3V0KCdnJykgOlxuICAgICAgICAgICAgZG9DdXQoJ2InKTtcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBxdWFudGl6ZShwaXhlbHMsIG1heGNvbG9ycykge1xuICAgICAgICAvLyBzaG9ydC1jaXJjdWl0XG4gICAgICAgIGlmICghcGl4ZWxzLmxlbmd0aCB8fCBtYXhjb2xvcnMgPCAyIHx8IG1heGNvbG9ycyA+IDI1Nikge1xuICAgICAgICAgICAgLy8gY29uc29sZS5sb2coJ3dyb25nIG51bWJlciBvZiBtYXhjb2xvcnMnKTtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFhYWDogY2hlY2sgY29sb3IgY29udGVudCBhbmQgY29udmVydCB0byBncmF5c2NhbGUgaWYgaW5zdWZmaWNpZW50XG5cbiAgICAgICAgdmFyIGhpc3RvID0gZ2V0SGlzdG8ocGl4ZWxzKSxcbiAgICAgICAgICAgIGhpc3Rvc2l6ZSA9IDEgPDwgKDMgKiBzaWdiaXRzKTtcblxuICAgICAgICAvLyBjaGVjayB0aGF0IHdlIGFyZW4ndCBiZWxvdyBtYXhjb2xvcnMgYWxyZWFkeVxuICAgICAgICB2YXIgbkNvbG9ycyA9IDA7XG4gICAgICAgIGhpc3RvLmZvckVhY2goZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICBuQ29sb3JzKytcbiAgICAgICAgfSk7XG4gICAgICAgIGlmIChuQ29sb3JzIDw9IG1heGNvbG9ycykge1xuICAgICAgICAgICAgLy8gWFhYOiBnZW5lcmF0ZSB0aGUgbmV3IGNvbG9ycyBmcm9tIHRoZSBoaXN0byBhbmQgcmV0dXJuXG4gICAgICAgIH1cblxuICAgICAgICAvLyBnZXQgdGhlIGJlZ2lubmluZyB2Ym94IGZyb20gdGhlIGNvbG9yc1xuICAgICAgICB2YXIgdmJveCA9IHZib3hGcm9tUGl4ZWxzKHBpeGVscywgaGlzdG8pLFxuICAgICAgICAgICAgcHEgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKGEuY291bnQoKSwgYi5jb3VudCgpKVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIHBxLnB1c2godmJveCk7XG5cbiAgICAgICAgLy8gaW5uZXIgZnVuY3Rpb24gdG8gZG8gdGhlIGl0ZXJhdGlvblxuXG4gICAgICAgIGZ1bmN0aW9uIGl0ZXIobGgsIHRhcmdldCkge1xuICAgICAgICAgICAgdmFyIG5jb2xvcnMgPSAxLFxuICAgICAgICAgICAgICAgIG5pdGVycyA9IDAsXG4gICAgICAgICAgICAgICAgdmJveDtcbiAgICAgICAgICAgIHdoaWxlIChuaXRlcnMgPCBtYXhJdGVyYXRpb25zKSB7XG4gICAgICAgICAgICAgICAgdmJveCA9IGxoLnBvcCgpO1xuICAgICAgICAgICAgICAgIGlmICghdmJveC5jb3VudCgpKSB7IC8qIGp1c3QgcHV0IGl0IGJhY2sgKi9cbiAgICAgICAgICAgICAgICAgICAgbGgucHVzaCh2Ym94KTtcbiAgICAgICAgICAgICAgICAgICAgbml0ZXJzKys7XG4gICAgICAgICAgICAgICAgICAgIGNvbnRpbnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAvLyBkbyB0aGUgY3V0XG4gICAgICAgICAgICAgICAgdmFyIHZib3hlcyA9IG1lZGlhbkN1dEFwcGx5KGhpc3RvLCB2Ym94KSxcbiAgICAgICAgICAgICAgICAgICAgdmJveDEgPSB2Ym94ZXNbMF0sXG4gICAgICAgICAgICAgICAgICAgIHZib3gyID0gdmJveGVzWzFdO1xuXG4gICAgICAgICAgICAgICAgaWYgKCF2Ym94MSkge1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZyhcInZib3gxIG5vdCBkZWZpbmVkOyBzaG91bGRuJ3QgaGFwcGVuIVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBsaC5wdXNoKHZib3gxKTtcbiAgICAgICAgICAgICAgICBpZiAodmJveDIpIHsgLyogdmJveDIgY2FuIGJlIG51bGwgKi9cbiAgICAgICAgICAgICAgICAgICAgbGgucHVzaCh2Ym94Mik7XG4gICAgICAgICAgICAgICAgICAgIG5jb2xvcnMrKztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKG5jb2xvcnMgPj0gdGFyZ2V0KSByZXR1cm47XG4gICAgICAgICAgICAgICAgaWYgKG5pdGVycysrID4gbWF4SXRlcmF0aW9ucykge1xuICAgICAgICAgICAgICAgICAgICAvLyBjb25zb2xlLmxvZyhcImluZmluaXRlIGxvb3A7IHBlcmhhcHMgdG9vIGZldyBwaXhlbHMhXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gZmlyc3Qgc2V0IG9mIGNvbG9ycywgc29ydGVkIGJ5IHBvcHVsYXRpb25cbiAgICAgICAgaXRlcihwcSwgZnJhY3RCeVBvcHVsYXRpb25zICogbWF4Y29sb3JzKTtcbiAgICAgICAgLy8gY29uc29sZS5sb2cocHEuc2l6ZSgpLCBwcS5kZWJ1ZygpLmxlbmd0aCwgcHEuZGVidWcoKS5zbGljZSgpKTtcblxuICAgICAgICAvLyBSZS1zb3J0IGJ5IHRoZSBwcm9kdWN0IG9mIHBpeGVsIG9jY3VwYW5jeSB0aW1lcyB0aGUgc2l6ZSBpbiBjb2xvciBzcGFjZS5cbiAgICAgICAgdmFyIHBxMiA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihhLmNvdW50KCkgKiBhLnZvbHVtZSgpLCBiLmNvdW50KCkgKiBiLnZvbHVtZSgpKVxuICAgICAgICB9KTtcbiAgICAgICAgd2hpbGUgKHBxLnNpemUoKSkge1xuICAgICAgICAgICAgcHEyLnB1c2gocHEucG9wKCkpO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gbmV4dCBzZXQgLSBnZW5lcmF0ZSB0aGUgbWVkaWFuIGN1dHMgdXNpbmcgdGhlIChucGl4ICogdm9sKSBzb3J0aW5nLlxuICAgICAgICBpdGVyKHBxMiwgbWF4Y29sb3JzIC0gcHEyLnNpemUoKSk7XG5cbiAgICAgICAgLy8gY2FsY3VsYXRlIHRoZSBhY3R1YWwgY29sb3JzXG4gICAgICAgIHZhciBjbWFwID0gbmV3IENNYXAoKTtcbiAgICAgICAgd2hpbGUgKHBxMi5zaXplKCkpIHtcbiAgICAgICAgICAgIGNtYXAucHVzaChwcTIucG9wKCkpO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIGNtYXA7XG4gICAgfVxuXG4gICAgcmV0dXJuIHtcbiAgICAgICAgcXVhbnRpemU6IHF1YW50aXplXG4gICAgfVxufSkoKTtcblxubW9kdWxlLmV4cG9ydHMgPSBNTUNRLnF1YW50aXplXG4iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxuJ3VzZSBzdHJpY3QnO1xuXG4vLyBJZiBvYmouaGFzT3duUHJvcGVydHkgaGFzIGJlZW4gb3ZlcnJpZGRlbiwgdGhlbiBjYWxsaW5nXG4vLyBvYmouaGFzT3duUHJvcGVydHkocHJvcCkgd2lsbCBicmVhay5cbi8vIFNlZTogaHR0cHM6Ly9naXRodWIuY29tL2pveWVudC9ub2RlL2lzc3Vlcy8xNzA3XG5mdW5jdGlvbiBoYXNPd25Qcm9wZXJ0eShvYmosIHByb3ApIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIHByb3ApO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uKHFzLCBzZXAsIGVxLCBvcHRpb25zKSB7XG4gIHNlcCA9IHNlcCB8fCAnJic7XG4gIGVxID0gZXEgfHwgJz0nO1xuICB2YXIgb2JqID0ge307XG5cbiAgaWYgKHR5cGVvZiBxcyAhPT0gJ3N0cmluZycgfHwgcXMubGVuZ3RoID09PSAwKSB7XG4gICAgcmV0dXJuIG9iajtcbiAgfVxuXG4gIHZhciByZWdleHAgPSAvXFwrL2c7XG4gIHFzID0gcXMuc3BsaXQoc2VwKTtcblxuICB2YXIgbWF4S2V5cyA9IDEwMDA7XG4gIGlmIChvcHRpb25zICYmIHR5cGVvZiBvcHRpb25zLm1heEtleXMgPT09ICdudW1iZXInKSB7XG4gICAgbWF4S2V5cyA9IG9wdGlvbnMubWF4S2V5cztcbiAgfVxuXG4gIHZhciBsZW4gPSBxcy5sZW5ndGg7XG4gIC8vIG1heEtleXMgPD0gMCBtZWFucyB0aGF0IHdlIHNob3VsZCBub3QgbGltaXQga2V5cyBjb3VudFxuICBpZiAobWF4S2V5cyA+IDAgJiYgbGVuID4gbWF4S2V5cykge1xuICAgIGxlbiA9IG1heEtleXM7XG4gIH1cblxuICBmb3IgKHZhciBpID0gMDsgaSA8IGxlbjsgKytpKSB7XG4gICAgdmFyIHggPSBxc1tpXS5yZXBsYWNlKHJlZ2V4cCwgJyUyMCcpLFxuICAgICAgICBpZHggPSB4LmluZGV4T2YoZXEpLFxuICAgICAgICBrc3RyLCB2c3RyLCBrLCB2O1xuXG4gICAgaWYgKGlkeCA+PSAwKSB7XG4gICAgICBrc3RyID0geC5zdWJzdHIoMCwgaWR4KTtcbiAgICAgIHZzdHIgPSB4LnN1YnN0cihpZHggKyAxKTtcbiAgICB9IGVsc2Uge1xuICAgICAga3N0ciA9IHg7XG4gICAgICB2c3RyID0gJyc7XG4gICAgfVxuXG4gICAgayA9IGRlY29kZVVSSUNvbXBvbmVudChrc3RyKTtcbiAgICB2ID0gZGVjb2RlVVJJQ29tcG9uZW50KHZzdHIpO1xuXG4gICAgaWYgKCFoYXNPd25Qcm9wZXJ0eShvYmosIGspKSB7XG4gICAgICBvYmpba10gPSB2O1xuICAgIH0gZWxzZSBpZiAoaXNBcnJheShvYmpba10pKSB7XG4gICAgICBvYmpba10ucHVzaCh2KTtcbiAgICB9IGVsc2Uge1xuICAgICAgb2JqW2tdID0gW29ialtrXSwgdl07XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIG9iajtcbn07XG5cbnZhciBpc0FycmF5ID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoeHMpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh4cykgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59O1xuIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbid1c2Ugc3RyaWN0JztcblxudmFyIHN0cmluZ2lmeVByaW1pdGl2ZSA9IGZ1bmN0aW9uKHYpIHtcbiAgc3dpdGNoICh0eXBlb2Ygdikge1xuICAgIGNhc2UgJ3N0cmluZyc6XG4gICAgICByZXR1cm4gdjtcblxuICAgIGNhc2UgJ2Jvb2xlYW4nOlxuICAgICAgcmV0dXJuIHYgPyAndHJ1ZScgOiAnZmFsc2UnO1xuXG4gICAgY2FzZSAnbnVtYmVyJzpcbiAgICAgIHJldHVybiBpc0Zpbml0ZSh2KSA/IHYgOiAnJztcblxuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gJyc7XG4gIH1cbn07XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ob2JqLCBzZXAsIGVxLCBuYW1lKSB7XG4gIHNlcCA9IHNlcCB8fCAnJic7XG4gIGVxID0gZXEgfHwgJz0nO1xuICBpZiAob2JqID09PSBudWxsKSB7XG4gICAgb2JqID0gdW5kZWZpbmVkO1xuICB9XG5cbiAgaWYgKHR5cGVvZiBvYmogPT09ICdvYmplY3QnKSB7XG4gICAgcmV0dXJuIG1hcChvYmplY3RLZXlzKG9iaiksIGZ1bmN0aW9uKGspIHtcbiAgICAgIHZhciBrcyA9IGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUoaykpICsgZXE7XG4gICAgICBpZiAoaXNBcnJheShvYmpba10pKSB7XG4gICAgICAgIHJldHVybiBtYXAob2JqW2tdLCBmdW5jdGlvbih2KSB7XG4gICAgICAgICAgcmV0dXJuIGtzICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZSh2KSk7XG4gICAgICAgIH0pLmpvaW4oc2VwKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiBrcyArIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUob2JqW2tdKSk7XG4gICAgICB9XG4gICAgfSkuam9pbihzZXApO1xuXG4gIH1cblxuICBpZiAoIW5hbWUpIHJldHVybiAnJztcbiAgcmV0dXJuIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUobmFtZSkpICsgZXEgK1xuICAgICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShvYmopKTtcbn07XG5cbnZhciBpc0FycmF5ID0gQXJyYXkuaXNBcnJheSB8fCBmdW5jdGlvbiAoeHMpIHtcbiAgcmV0dXJuIE9iamVjdC5wcm90b3R5cGUudG9TdHJpbmcuY2FsbCh4cykgPT09ICdbb2JqZWN0IEFycmF5XSc7XG59O1xuXG5mdW5jdGlvbiBtYXAgKHhzLCBmKSB7XG4gIGlmICh4cy5tYXApIHJldHVybiB4cy5tYXAoZik7XG4gIHZhciByZXMgPSBbXTtcbiAgZm9yICh2YXIgaSA9IDA7IGkgPCB4cy5sZW5ndGg7IGkrKykge1xuICAgIHJlcy5wdXNoKGYoeHNbaV0sIGkpKTtcbiAgfVxuICByZXR1cm4gcmVzO1xufVxuXG52YXIgb2JqZWN0S2V5cyA9IE9iamVjdC5rZXlzIHx8IGZ1bmN0aW9uIChvYmopIHtcbiAgdmFyIHJlcyA9IFtdO1xuICBmb3IgKHZhciBrZXkgaW4gb2JqKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChvYmosIGtleSkpIHJlcy5wdXNoKGtleSk7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn07XG4iLCIndXNlIHN0cmljdCc7XG5cbmV4cG9ydHMuZGVjb2RlID0gZXhwb3J0cy5wYXJzZSA9IHJlcXVpcmUoJy4vZGVjb2RlJyk7XG5leHBvcnRzLmVuY29kZSA9IGV4cG9ydHMuc3RyaW5naWZ5ID0gcmVxdWlyZSgnLi9lbmNvZGUnKTtcbiIsInZhciBWaWJyYW50O1xuXG5WaWJyYW50ID0gcmVxdWlyZSgnLi92aWJyYW50Jyk7XG5cblZpYnJhbnQuRGVmYXVsdE9wdHMuSW1hZ2UgPSByZXF1aXJlKCcuL2ltYWdlL2Jyb3dzZXInKTtcblxubW9kdWxlLmV4cG9ydHMgPSBWaWJyYW50O1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12WW5KdmQzTmxjaTVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5aWNtOTNjMlZ5TG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lRVUZCUVN4SlFVRkJPenRCUVVGQkxFOUJRVUVzUjBGQlZTeFBRVUZCTEVOQlFWRXNWMEZCVWpzN1FVRkRWaXhQUVVGUExFTkJRVU1zVjBGQlZ5eERRVUZETEV0QlFYQkNMRWRCUVRSQ0xFOUJRVUVzUTBGQlVTeHBRa0ZCVWpzN1FVRkZOVUlzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZCYVVJaWZRPT1cbiIsInZhciBWaWJyYW50O1xuXG53aW5kb3cuVmlicmFudCA9IFZpYnJhbnQgPSByZXF1aXJlKCcuL2Jyb3dzZXInKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdlluVnVaR3hsTG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwySjFibVJzWlM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1NVRkJRVHM3UVVGQlFTeE5RVUZOTEVOQlFVTXNUMEZCVUN4SFFVRnBRaXhQUVVGQkxFZEJRVlVzVDBGQlFTeERRVUZSTEZkQlFWSWlmUT09XG4iLCJtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uKHIsIGcsIGIsIGEpIHtcbiAgcmV0dXJuIGEgPj0gMTI1ICYmICEociA+IDI1MCAmJiBnID4gMjUwICYmIGIgPiAyNTApO1xufTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdlptbHNkR1Z5TDJSbFptRjFiSFF1WTI5bVptVmxJaXdpYzI5MWNtTmxVbTl2ZENJNklpSXNJbk52ZFhKalpYTWlPbHNpTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdlptbHNkR1Z5TDJSbFptRjFiSFF1WTI5bVptVmxJbDBzSW01aGJXVnpJanBiWFN3aWJXRndjR2x1WjNNaU9pSkJRVUZCTEUxQlFVMHNRMEZCUXl4UFFVRlFMRWRCUVdsQ0xGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFMRVZCUVZVc1EwRkJWanRUUVVObUxFTkJRVUVzU1VGQlN5eEhRVUZNTEVsQlFXRXNRMEZCU1N4RFFVRkRMRU5CUVVFc1IwRkJTU3hIUVVGS0xFbEJRVmtzUTBGQlFTeEhRVUZKTEVkQlFXaENMRWxCUVhkQ0xFTkJRVUVzUjBGQlNTeEhRVUUzUWp0QlFVUkdJbjA9XG4iLCJtb2R1bGUuZXhwb3J0cy5EZWZhdWx0ID0gcmVxdWlyZSgnLi9kZWZhdWx0Jyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZabWxzZEdWeUwybHVaR1Y0TG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwyWnBiSFJsY2k5cGJtUmxlQzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzVFVGQlRTeERRVUZETEU5QlFVOHNRMEZCUXl4UFFVRm1MRWRCUVhsQ0xFOUJRVUVzUTBGQlVTeFhRVUZTSW4wPVxuIiwidmFyIERlZmF1bHRHZW5lcmF0b3IsIERlZmF1bHRPcHRzLCBHZW5lcmF0b3IsIFN3YXRjaCwgdXRpbCxcbiAgZXh0ZW5kID0gZnVuY3Rpb24oY2hpbGQsIHBhcmVudCkgeyBmb3IgKHZhciBrZXkgaW4gcGFyZW50KSB7IGlmIChoYXNQcm9wLmNhbGwocGFyZW50LCBrZXkpKSBjaGlsZFtrZXldID0gcGFyZW50W2tleV07IH0gZnVuY3Rpb24gY3RvcigpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGNoaWxkOyB9IGN0b3IucHJvdG90eXBlID0gcGFyZW50LnByb3RvdHlwZTsgY2hpbGQucHJvdG90eXBlID0gbmV3IGN0b3IoKTsgY2hpbGQuX19zdXBlcl9fID0gcGFyZW50LnByb3RvdHlwZTsgcmV0dXJuIGNoaWxkOyB9LFxuICBoYXNQcm9wID0ge30uaGFzT3duUHJvcGVydHksXG4gIHNsaWNlID0gW10uc2xpY2U7XG5cblN3YXRjaCA9IHJlcXVpcmUoJy4uL3N3YXRjaCcpO1xuXG51dGlsID0gcmVxdWlyZSgnLi4vdXRpbCcpO1xuXG5HZW5lcmF0b3IgPSByZXF1aXJlKCcuL2luZGV4Jyk7XG5cbkRlZmF1bHRPcHRzID0ge1xuICB0YXJnZXREYXJrTHVtYTogMC4yNixcbiAgbWF4RGFya0x1bWE6IDAuNDUsXG4gIG1pbkxpZ2h0THVtYTogMC41NSxcbiAgdGFyZ2V0TGlnaHRMdW1hOiAwLjc0LFxuICBtaW5Ob3JtYWxMdW1hOiAwLjMsXG4gIHRhcmdldE5vcm1hbEx1bWE6IDAuNSxcbiAgbWF4Tm9ybWFsTHVtYTogMC43LFxuICB0YXJnZXRNdXRlc1NhdHVyYXRpb246IDAuMyxcbiAgbWF4TXV0ZXNTYXR1cmF0aW9uOiAwLjQsXG4gIHRhcmdldFZpYnJhbnRTYXR1cmF0aW9uOiAxLjAsXG4gIG1pblZpYnJhbnRTYXR1cmF0aW9uOiAwLjM1LFxuICB3ZWlnaHRTYXR1cmF0aW9uOiAzLFxuICB3ZWlnaHRMdW1hOiA2LFxuICB3ZWlnaHRQb3B1bGF0aW9uOiAxXG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IERlZmF1bHRHZW5lcmF0b3IgPSAoZnVuY3Rpb24oc3VwZXJDbGFzcykge1xuICBleHRlbmQoRGVmYXVsdEdlbmVyYXRvciwgc3VwZXJDbGFzcyk7XG5cbiAgZnVuY3Rpb24gRGVmYXVsdEdlbmVyYXRvcihvcHRzKSB7XG4gICAgdGhpcy5vcHRzID0gdXRpbC5kZWZhdWx0cyhvcHRzLCBEZWZhdWx0T3B0cyk7XG4gICAgdGhpcy5WaWJyYW50U3dhdGNoID0gbnVsbDtcbiAgICB0aGlzLkxpZ2h0VmlicmFudFN3YXRjaCA9IG51bGw7XG4gICAgdGhpcy5EYXJrVmlicmFudFN3YXRjaCA9IG51bGw7XG4gICAgdGhpcy5NdXRlZFN3YXRjaCA9IG51bGw7XG4gICAgdGhpcy5MaWdodE11dGVkU3dhdGNoID0gbnVsbDtcbiAgICB0aGlzLkRhcmtNdXRlZFN3YXRjaCA9IG51bGw7XG4gIH1cblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZW5lcmF0ZSA9IGZ1bmN0aW9uKHN3YXRjaGVzKSB7XG4gICAgdGhpcy5zd2F0Y2hlcyA9IHN3YXRjaGVzO1xuICAgIHRoaXMubWF4UG9wdWxhdGlvbiA9IHRoaXMuZmluZE1heFBvcHVsYXRpb24oKTtcbiAgICB0aGlzLmdlbmVyYXRlVmFyYXRpb25Db2xvcnMoKTtcbiAgICByZXR1cm4gdGhpcy5nZW5lcmF0ZUVtcHR5U3dhdGNoZXMoKTtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXRWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuVmlicmFudFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXRMaWdodFZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5MaWdodFZpYnJhbnRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0RGFya1ZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5EYXJrVmlicmFudFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXRNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLk11dGVkU3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldExpZ2h0TXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5MaWdodE11dGVkU3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldERhcmtNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLkRhcmtNdXRlZFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZW5lcmF0ZVZhcmF0aW9uQ29sb3JzID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5WaWJyYW50U3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldE5vcm1hbEx1bWEsIHRoaXMub3B0cy5taW5Ob3JtYWxMdW1hLCB0aGlzLm9wdHMubWF4Tm9ybWFsTHVtYSwgdGhpcy5vcHRzLnRhcmdldFZpYnJhbnRTYXR1cmF0aW9uLCB0aGlzLm9wdHMubWluVmlicmFudFNhdHVyYXRpb24sIDEpO1xuICAgIHRoaXMuTGlnaHRWaWJyYW50U3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldExpZ2h0THVtYSwgdGhpcy5vcHRzLm1pbkxpZ2h0THVtYSwgMSwgdGhpcy5vcHRzLnRhcmdldFZpYnJhbnRTYXR1cmF0aW9uLCB0aGlzLm9wdHMubWluVmlicmFudFNhdHVyYXRpb24sIDEpO1xuICAgIHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0RGFya0x1bWEsIDAsIHRoaXMub3B0cy5tYXhEYXJrTHVtYSwgdGhpcy5vcHRzLnRhcmdldFZpYnJhbnRTYXR1cmF0aW9uLCB0aGlzLm9wdHMubWluVmlicmFudFNhdHVyYXRpb24sIDEpO1xuICAgIHRoaXMuTXV0ZWRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0Tm9ybWFsTHVtYSwgdGhpcy5vcHRzLm1pbk5vcm1hbEx1bWEsIHRoaXMub3B0cy5tYXhOb3JtYWxMdW1hLCB0aGlzLm9wdHMudGFyZ2V0TXV0ZXNTYXR1cmF0aW9uLCAwLCB0aGlzLm9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcbiAgICB0aGlzLkxpZ2h0TXV0ZWRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0TGlnaHRMdW1hLCB0aGlzLm9wdHMubWluTGlnaHRMdW1hLCAxLCB0aGlzLm9wdHMudGFyZ2V0TXV0ZXNTYXR1cmF0aW9uLCAwLCB0aGlzLm9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcbiAgICByZXR1cm4gdGhpcy5EYXJrTXV0ZWRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0RGFya0x1bWEsIDAsIHRoaXMub3B0cy5tYXhEYXJrTHVtYSwgdGhpcy5vcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgdGhpcy5vcHRzLm1heE11dGVzU2F0dXJhdGlvbik7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2VuZXJhdGVFbXB0eVN3YXRjaGVzID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGhzbDtcbiAgICBpZiAodGhpcy5WaWJyYW50U3dhdGNoID09PSBudWxsKSB7XG4gICAgICBpZiAodGhpcy5EYXJrVmlicmFudFN3YXRjaCAhPT0gbnVsbCkge1xuICAgICAgICBoc2wgPSB0aGlzLkRhcmtWaWJyYW50U3dhdGNoLmdldEhzbCgpO1xuICAgICAgICBoc2xbMl0gPSB0aGlzLm9wdHMudGFyZ2V0Tm9ybWFsTHVtYTtcbiAgICAgICAgdGhpcy5WaWJyYW50U3dhdGNoID0gbmV3IFN3YXRjaCh1dGlsLmhzbFRvUmdiKGhzbFswXSwgaHNsWzFdLCBoc2xbMl0pLCAwKTtcbiAgICAgIH1cbiAgICB9XG4gICAgaWYgKHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggPT09IG51bGwpIHtcbiAgICAgIGlmICh0aGlzLlZpYnJhbnRTd2F0Y2ggIT09IG51bGwpIHtcbiAgICAgICAgaHNsID0gdGhpcy5WaWJyYW50U3dhdGNoLmdldEhzbCgpO1xuICAgICAgICBoc2xbMl0gPSB0aGlzLm9wdHMudGFyZ2V0RGFya0x1bWE7XG4gICAgICAgIHJldHVybiB0aGlzLkRhcmtWaWJyYW50U3dhdGNoID0gbmV3IFN3YXRjaCh1dGlsLmhzbFRvUmdiKGhzbFswXSwgaHNsWzFdLCBoc2xbMl0pLCAwKTtcbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZmluZE1heFBvcHVsYXRpb24gPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgaiwgbGVuLCBwb3B1bGF0aW9uLCByZWYsIHN3YXRjaDtcbiAgICBwb3B1bGF0aW9uID0gMDtcbiAgICByZWYgPSB0aGlzLnN3YXRjaGVzO1xuICAgIGZvciAoaiA9IDAsIGxlbiA9IHJlZi5sZW5ndGg7IGogPCBsZW47IGorKykge1xuICAgICAgc3dhdGNoID0gcmVmW2pdO1xuICAgICAgcG9wdWxhdGlvbiA9IE1hdGgubWF4KHBvcHVsYXRpb24sIHN3YXRjaC5nZXRQb3B1bGF0aW9uKCkpO1xuICAgIH1cbiAgICByZXR1cm4gcG9wdWxhdGlvbjtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5maW5kQ29sb3JWYXJpYXRpb24gPSBmdW5jdGlvbih0YXJnZXRMdW1hLCBtaW5MdW1hLCBtYXhMdW1hLCB0YXJnZXRTYXR1cmF0aW9uLCBtaW5TYXR1cmF0aW9uLCBtYXhTYXR1cmF0aW9uKSB7XG4gICAgdmFyIGosIGxlbiwgbHVtYSwgbWF4LCBtYXhWYWx1ZSwgcmVmLCBzYXQsIHN3YXRjaCwgdmFsdWU7XG4gICAgbWF4ID0gbnVsbDtcbiAgICBtYXhWYWx1ZSA9IDA7XG4gICAgcmVmID0gdGhpcy5zd2F0Y2hlcztcbiAgICBmb3IgKGogPSAwLCBsZW4gPSByZWYubGVuZ3RoOyBqIDwgbGVuOyBqKyspIHtcbiAgICAgIHN3YXRjaCA9IHJlZltqXTtcbiAgICAgIHNhdCA9IHN3YXRjaC5nZXRIc2woKVsxXTtcbiAgICAgIGx1bWEgPSBzd2F0Y2guZ2V0SHNsKClbMl07XG4gICAgICBpZiAoc2F0ID49IG1pblNhdHVyYXRpb24gJiYgc2F0IDw9IG1heFNhdHVyYXRpb24gJiYgbHVtYSA+PSBtaW5MdW1hICYmIGx1bWEgPD0gbWF4THVtYSAmJiAhdGhpcy5pc0FscmVhZHlTZWxlY3RlZChzd2F0Y2gpKSB7XG4gICAgICAgIHZhbHVlID0gdGhpcy5jcmVhdGVDb21wYXJpc29uVmFsdWUoc2F0LCB0YXJnZXRTYXR1cmF0aW9uLCBsdW1hLCB0YXJnZXRMdW1hLCBzd2F0Y2guZ2V0UG9wdWxhdGlvbigpLCB0aGlzLm1heFBvcHVsYXRpb24pO1xuICAgICAgICBpZiAobWF4ID09PSBudWxsIHx8IHZhbHVlID4gbWF4VmFsdWUpIHtcbiAgICAgICAgICBtYXggPSBzd2F0Y2g7XG4gICAgICAgICAgbWF4VmFsdWUgPSB2YWx1ZTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbWF4O1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmNyZWF0ZUNvbXBhcmlzb25WYWx1ZSA9IGZ1bmN0aW9uKHNhdHVyYXRpb24sIHRhcmdldFNhdHVyYXRpb24sIGx1bWEsIHRhcmdldEx1bWEsIHBvcHVsYXRpb24sIG1heFBvcHVsYXRpb24pIHtcbiAgICByZXR1cm4gdGhpcy53ZWlnaHRlZE1lYW4odGhpcy5pbnZlcnREaWZmKHNhdHVyYXRpb24sIHRhcmdldFNhdHVyYXRpb24pLCB0aGlzLm9wdHMud2VpZ2h0U2F0dXJhdGlvbiwgdGhpcy5pbnZlcnREaWZmKGx1bWEsIHRhcmdldEx1bWEpLCB0aGlzLm9wdHMud2VpZ2h0THVtYSwgcG9wdWxhdGlvbiAvIG1heFBvcHVsYXRpb24sIHRoaXMub3B0cy53ZWlnaHRQb3B1bGF0aW9uKTtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5pbnZlcnREaWZmID0gZnVuY3Rpb24odmFsdWUsIHRhcmdldFZhbHVlKSB7XG4gICAgcmV0dXJuIDEgLSBNYXRoLmFicyh2YWx1ZSAtIHRhcmdldFZhbHVlKTtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS53ZWlnaHRlZE1lYW4gPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgaSwgc3VtLCBzdW1XZWlnaHQsIHZhbHVlLCB2YWx1ZXMsIHdlaWdodDtcbiAgICB2YWx1ZXMgPSAxIDw9IGFyZ3VtZW50cy5sZW5ndGggPyBzbGljZS5jYWxsKGFyZ3VtZW50cywgMCkgOiBbXTtcbiAgICBzdW0gPSAwO1xuICAgIHN1bVdlaWdodCA9IDA7XG4gICAgaSA9IDA7XG4gICAgd2hpbGUgKGkgPCB2YWx1ZXMubGVuZ3RoKSB7XG4gICAgICB2YWx1ZSA9IHZhbHVlc1tpXTtcbiAgICAgIHdlaWdodCA9IHZhbHVlc1tpICsgMV07XG4gICAgICBzdW0gKz0gdmFsdWUgKiB3ZWlnaHQ7XG4gICAgICBzdW1XZWlnaHQgKz0gd2VpZ2h0O1xuICAgICAgaSArPSAyO1xuICAgIH1cbiAgICByZXR1cm4gc3VtIC8gc3VtV2VpZ2h0O1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmlzQWxyZWFkeVNlbGVjdGVkID0gZnVuY3Rpb24oc3dhdGNoKSB7XG4gICAgcmV0dXJuIHRoaXMuVmlicmFudFN3YXRjaCA9PT0gc3dhdGNoIHx8IHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggPT09IHN3YXRjaCB8fCB0aGlzLkxpZ2h0VmlicmFudFN3YXRjaCA9PT0gc3dhdGNoIHx8IHRoaXMuTXV0ZWRTd2F0Y2ggPT09IHN3YXRjaCB8fCB0aGlzLkRhcmtNdXRlZFN3YXRjaCA9PT0gc3dhdGNoIHx8IHRoaXMuTGlnaHRNdXRlZFN3YXRjaCA9PT0gc3dhdGNoO1xuICB9O1xuXG4gIHJldHVybiBEZWZhdWx0R2VuZXJhdG9yO1xuXG59KShHZW5lcmF0b3IpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12WjJWdVpYSmhkRzl5TDJSbFptRjFiSFF1WTI5bVptVmxJaXdpYzI5MWNtTmxVbTl2ZENJNklpSXNJbk52ZFhKalpYTWlPbHNpTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdloyVnVaWEpoZEc5eUwyUmxabUYxYkhRdVkyOW1abVZsSWwwc0ltNWhiV1Z6SWpwYlhTd2liV0Z3Y0dsdVozTWlPaUpCUVVGQkxFbEJRVUVzYzBSQlFVRTdSVUZCUVRzN096dEJRVUZCTEUxQlFVRXNSMEZCVXl4UFFVRkJMRU5CUVZFc1YwRkJVanM3UVVGRFZDeEpRVUZCTEVkQlFVOHNUMEZCUVN4RFFVRlJMRk5CUVZJN08wRkJRMUFzVTBGQlFTeEhRVUZaTEU5QlFVRXNRMEZCVVN4VFFVRlNPenRCUVVWYUxGZEJRVUVzUjBGRFJUdEZRVUZCTEdOQlFVRXNSVUZCWjBJc1NVRkJhRUk3UlVGRFFTeFhRVUZCTEVWQlFXRXNTVUZFWWp0RlFVVkJMRmxCUVVFc1JVRkJZeXhKUVVaa08wVkJSMEVzWlVGQlFTeEZRVUZwUWl4SlFVaHFRanRGUVVsQkxHRkJRVUVzUlVGQlpTeEhRVXBtTzBWQlMwRXNaMEpCUVVFc1JVRkJhMElzUjBGTWJFSTdSVUZOUVN4aFFVRkJMRVZCUVdVc1IwRk9aanRGUVU5QkxIRkNRVUZCTEVWQlFYVkNMRWRCVUhaQ08wVkJVVUVzYTBKQlFVRXNSVUZCYjBJc1IwRlNjRUk3UlVGVFFTeDFRa0ZCUVN4RlFVRjVRaXhIUVZSNlFqdEZRVlZCTEc5Q1FVRkJMRVZCUVhOQ0xFbEJWblJDTzBWQlYwRXNaMEpCUVVFc1JVRkJhMElzUTBGWWJFSTdSVUZaUVN4VlFVRkJMRVZCUVZrc1EwRmFXanRGUVdGQkxHZENRVUZCTEVWQlFXdENMRU5CWW14Q096czdRVUZsUml4TlFVRk5MRU5CUVVNc1QwRkJVQ3hIUVVOTk96czdSVUZEVXl3d1FrRkJReXhKUVVGRU8wbEJRMWdzU1VGQlF5eERRVUZCTEVsQlFVUXNSMEZCVVN4SlFVRkpMRU5CUVVNc1VVRkJUQ3hEUVVGakxFbEJRV1FzUlVGQmIwSXNWMEZCY0VJN1NVRkRVaXhKUVVGRExFTkJRVUVzWVVGQlJDeEhRVUZwUWp0SlFVTnFRaXhKUVVGRExFTkJRVUVzYTBKQlFVUXNSMEZCYzBJN1NVRkRkRUlzU1VGQlF5eERRVUZCTEdsQ1FVRkVMRWRCUVhGQ08wbEJRM0pDTEVsQlFVTXNRMEZCUVN4WFFVRkVMRWRCUVdVN1NVRkRaaXhKUVVGRExFTkJRVUVzWjBKQlFVUXNSMEZCYjBJN1NVRkRjRUlzU1VGQlF5eERRVUZCTEdWQlFVUXNSMEZCYlVJN1JVRlFVanM3TmtKQlUySXNVVUZCUVN4SFFVRlZMRk5CUVVNc1VVRkJSRHRKUVVGRExFbEJRVU1zUTBGQlFTeFhRVUZFTzBsQlExUXNTVUZCUXl4RFFVRkJMR0ZCUVVRc1IwRkJhVUlzU1VGQlF5eERRVUZCTEdsQ1FVRkVMRU5CUVVFN1NVRkZha0lzU1VGQlF5eERRVUZCTEhOQ1FVRkVMRU5CUVVFN1YwRkRRU3hKUVVGRExFTkJRVUVzY1VKQlFVUXNRMEZCUVR0RlFVcFJPenMyUWtGTlZpeG5Ra0ZCUVN4SFFVRnJRaXhUUVVGQk8xZEJRMmhDTEVsQlFVTXNRMEZCUVR0RlFVUmxPenMyUWtGSGJFSXNjVUpCUVVFc1IwRkJkVUlzVTBGQlFUdFhRVU55UWl4SlFVRkRMRU5CUVVFN1JVRkViMEk3T3paQ1FVZDJRaXh2UWtGQlFTeEhRVUZ6UWl4VFFVRkJPMWRCUTNCQ0xFbEJRVU1zUTBGQlFUdEZRVVJ0UWpzN05rSkJSM1JDTEdOQlFVRXNSMEZCWjBJc1UwRkJRVHRYUVVOa0xFbEJRVU1zUTBGQlFUdEZRVVJoT3pzMlFrRkhhRUlzYlVKQlFVRXNSMEZCY1VJc1UwRkJRVHRYUVVOdVFpeEpRVUZETEVOQlFVRTdSVUZFYTBJN096WkNRVWR5UWl4clFrRkJRU3hIUVVGdlFpeFRRVUZCTzFkQlEyeENMRWxCUVVNc1EwRkJRVHRGUVVScFFqczdOa0pCUjNCQ0xITkNRVUZCTEVkQlFYZENMRk5CUVVFN1NVRkRkRUlzU1VGQlF5eERRVUZCTEdGQlFVUXNSMEZCYVVJc1NVRkJReXhEUVVGQkxHdENRVUZFTEVOQlFXOUNMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zWjBKQlFURkNMRVZCUVRSRExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNZVUZCYkVRc1JVRkJhVVVzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4aFFVRjJSU3hGUVVObUxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNkVUpCUkZNc1JVRkRaMElzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4dlFrRkVkRUlzUlVGRE5FTXNRMEZFTlVNN1NVRkhha0lzU1VGQlF5eERRVUZCTEd0Q1FVRkVMRWRCUVhOQ0xFbEJRVU1zUTBGQlFTeHJRa0ZCUkN4RFFVRnZRaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEdWQlFURkNMRVZCUVRKRExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNXVUZCYWtRc1JVRkJLMFFzUTBGQkwwUXNSVUZEY0VJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eDFRa0ZFWXl4RlFVTlhMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zYjBKQlJHcENMRVZCUTNWRExFTkJSSFpETzBsQlIzUkNMRWxCUVVNc1EwRkJRU3hwUWtGQlJDeEhRVUZ4UWl4SlFVRkRMRU5CUVVFc2EwSkJRVVFzUTBGQmIwSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhqUVVFeFFpeEZRVUV3UXl4RFFVRXhReXhGUVVFMlF5eEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRmRCUVc1RUxFVkJRMjVDTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2RVSkJSR0VzUlVGRFdTeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRzlDUVVSc1FpeEZRVU4zUXl4RFFVUjRRenRKUVVkeVFpeEpRVUZETEVOQlFVRXNWMEZCUkN4SFFVRmxMRWxCUVVNc1EwRkJRU3hyUWtGQlJDeERRVUZ2UWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHZENRVUV4UWl4RlFVRTBReXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEdGQlFXeEVMRVZCUVdsRkxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNZVUZCZGtVc1JVRkRZaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEhGQ1FVUlBMRVZCUTJkQ0xFTkJSR2hDTEVWQlEyMUNMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zYTBKQlJIcENPMGxCUjJZc1NVRkJReXhEUVVGQkxHZENRVUZFTEVkQlFXOUNMRWxCUVVNc1EwRkJRU3hyUWtGQlJDeERRVUZ2UWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHVkJRVEZDTEVWQlFUSkRMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zV1VGQmFrUXNSVUZCSzBRc1EwRkJMMFFzUlVGRGJFSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXh4UWtGRVdTeEZRVU5YTEVOQlJGZ3NSVUZEWXl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHdENRVVJ3UWp0WFFVZHdRaXhKUVVGRExFTkJRVUVzWlVGQlJDeEhRVUZ0UWl4SlFVRkRMRU5CUVVFc2EwSkJRVVFzUTBGQmIwSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhqUVVFeFFpeEZRVUV3UXl4RFFVRXhReXhGUVVFMlF5eEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRmRCUVc1RUxFVkJRMnBDTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2NVSkJSRmNzUlVGRFdTeERRVVJhTEVWQlEyVXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhyUWtGRWNrSTdSVUZvUWtjN096WkNRVzFDZUVJc2NVSkJRVUVzUjBGQmRVSXNVMEZCUVR0QlFVTnlRaXhSUVVGQk8wbEJRVUVzU1VGQlJ5eEpRVUZETEVOQlFVRXNZVUZCUkN4TFFVRnJRaXhKUVVGeVFqdE5RVVZGTEVsQlFVY3NTVUZCUXl4RFFVRkJMR2xDUVVGRUxFdEJRWGRDTEVsQlFUTkNPMUZCUlVVc1IwRkJRU3hIUVVGTkxFbEJRVU1zUTBGQlFTeHBRa0ZCYVVJc1EwRkJReXhOUVVGdVFpeERRVUZCTzFGQlEwNHNSMEZCU1N4RFFVRkJMRU5CUVVFc1EwRkJTaXhIUVVGVExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTTdVVUZEWml4SlFVRkRMRU5CUVVFc1lVRkJSQ3hIUVVGcFFpeEpRVUZKTEUxQlFVb3NRMEZCVnl4SlFVRkpMRU5CUVVNc1VVRkJUQ3hEUVVGakxFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFXeENMRVZCUVhOQ0xFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFURkNMRVZCUVRoQ0xFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFXeERMRU5CUVZnc1JVRkJhMFFzUTBGQmJFUXNSVUZLYmtJN1QwRkdSanM3U1VGUlFTeEpRVUZITEVsQlFVTXNRMEZCUVN4cFFrRkJSQ3hMUVVGelFpeEpRVUY2UWp0TlFVVkZMRWxCUVVjc1NVRkJReXhEUVVGQkxHRkJRVVFzUzBGQmIwSXNTVUZCZGtJN1VVRkZSU3hIUVVGQkxFZEJRVTBzU1VGQlF5eERRVUZCTEdGQlFXRXNRMEZCUXl4TlFVRm1MRU5CUVVFN1VVRkRUaXhIUVVGSkxFTkJRVUVzUTBGQlFTeERRVUZLTEVkQlFWTXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJRenRsUVVObUxFbEJRVU1zUTBGQlFTeHBRa0ZCUkN4SFFVRnhRaXhKUVVGSkxFMUJRVW9zUTBGQlZ5eEpRVUZKTEVOQlFVTXNVVUZCVEN4RFFVRmpMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRV3hDTEVWQlFYTkNMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRVEZDTEVWQlFUaENMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRV3hETEVOQlFWZ3NSVUZCYTBRc1EwRkJiRVFzUlVGS2RrSTdUMEZHUmpzN1JVRlVjVUk3T3paQ1FXbENka0lzYVVKQlFVRXNSMEZCYlVJc1UwRkJRVHRCUVVOcVFpeFJRVUZCTzBsQlFVRXNWVUZCUVN4SFFVRmhPMEZCUTJJN1FVRkJRU3hUUVVGQkxIRkRRVUZCT3p0TlFVRkJMRlZCUVVFc1IwRkJZU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEZWQlFWUXNSVUZCY1VJc1RVRkJUU3hEUVVGRExHRkJRVkFzUTBGQlFTeERRVUZ5UWp0QlFVRmlPMWRCUTBFN1JVRklhVUk3T3paQ1FVdHVRaXhyUWtGQlFTeEhRVUZ2UWl4VFFVRkRMRlZCUVVRc1JVRkJZU3hQUVVGaUxFVkJRWE5DTEU5QlFYUkNMRVZCUVN0Q0xHZENRVUV2UWl4RlFVRnBSQ3hoUVVGcVJDeEZRVUZuUlN4aFFVRm9SVHRCUVVOc1FpeFJRVUZCTzBsQlFVRXNSMEZCUVN4SFFVRk5PMGxCUTA0c1VVRkJRU3hIUVVGWE8wRkJSVmc3UVVGQlFTeFRRVUZCTEhGRFFVRkJPenROUVVORkxFZEJRVUVzUjBGQlRTeE5RVUZOTEVOQlFVTXNUVUZCVUN4RFFVRkJMRU5CUVdkQ0xFTkJRVUVzUTBGQlFUdE5RVU4wUWl4SlFVRkJMRWRCUVU4c1RVRkJUU3hEUVVGRExFMUJRVkFzUTBGQlFTeERRVUZuUWl4RFFVRkJMRU5CUVVFN1RVRkZka0lzU1VGQlJ5eEhRVUZCTEVsQlFVOHNZVUZCVUN4SlFVRjVRaXhIUVVGQkxFbEJRVThzWVVGQmFFTXNTVUZEUkN4SlFVRkJMRWxCUVZFc1QwRkVVQ3hKUVVOdFFpeEpRVUZCTEVsQlFWRXNUMEZFTTBJc1NVRkZSQ3hEUVVGSkxFbEJRVU1zUTBGQlFTeHBRa0ZCUkN4RFFVRnRRaXhOUVVGdVFpeERRVVpPTzFGQlIwa3NTMEZCUVN4SFFVRlJMRWxCUVVNc1EwRkJRU3h4UWtGQlJDeERRVUYxUWl4SFFVRjJRaXhGUVVFMFFpeG5Ra0ZCTlVJc1JVRkJPRU1zU1VGQk9VTXNSVUZCYjBRc1ZVRkJjRVFzUlVGRFRpeE5RVUZOTEVOQlFVTXNZVUZCVUN4RFFVRkJMRU5CUkUwc1JVRkRhMElzU1VGQlF5eERRVUZCTEdGQlJHNUNPMUZCUlZJc1NVRkJSeXhIUVVGQkxFdEJRVThzU1VGQlVDeEpRVUZsTEV0QlFVRXNSMEZCVVN4UlFVRXhRanRWUVVORkxFZEJRVUVzUjBGQlRUdFZRVU5PTEZGQlFVRXNSMEZCVnl4TlFVWmlPMU5CVEVvN08wRkJTa1k3VjBGaFFUdEZRV3BDYTBJN096WkNRVzFDY0VJc2NVSkJRVUVzUjBGQmRVSXNVMEZCUXl4VlFVRkVMRVZCUVdFc1owSkJRV0lzUlVGRGJrSXNTVUZFYlVJc1JVRkRZaXhWUVVSaExFVkJRMFFzVlVGRVF5eEZRVU5YTEdGQlJGZzdWMEZGY2tJc1NVRkJReXhEUVVGQkxGbEJRVVFzUTBGRFJTeEpRVUZETEVOQlFVRXNWVUZCUkN4RFFVRlpMRlZCUVZvc1JVRkJkMElzWjBKQlFYaENMRU5CUkVZc1JVRkROa01zU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4blFrRkVia1FzUlVGRlJTeEpRVUZETEVOQlFVRXNWVUZCUkN4RFFVRlpMRWxCUVZvc1JVRkJhMElzVlVGQmJFSXNRMEZHUml4RlFVVnBReXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEZWQlJuWkRMRVZCUjBVc1ZVRkJRU3hIUVVGaExHRkJTR1lzUlVGSE9FSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhuUWtGSWNFTTdSVUZHY1VJN096WkNRVkYyUWl4VlFVRkJMRWRCUVZrc1UwRkJReXhMUVVGRUxFVkJRVkVzVjBGQlVqdFhRVU5XTEVOQlFVRXNSMEZCU1N4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFdEJRVUVzUjBGQlVTeFhRVUZxUWp0RlFVUk5PenMyUWtGSFdpeFpRVUZCTEVkQlFXTXNVMEZCUVR0QlFVTmFMRkZCUVVFN1NVRkVZVHRKUVVOaUxFZEJRVUVzUjBGQlRUdEpRVU5PTEZOQlFVRXNSMEZCV1R0SlFVTmFMRU5CUVVFc1IwRkJTVHRCUVVOS0xGZEJRVTBzUTBGQlFTeEhRVUZKTEUxQlFVMHNRMEZCUXl4TlFVRnFRanROUVVORkxFdEJRVUVzUjBGQlVTeE5RVUZQTEVOQlFVRXNRMEZCUVR0TlFVTm1MRTFCUVVFc1IwRkJVeXhOUVVGUExFTkJRVUVzUTBGQlFTeEhRVUZKTEVOQlFVbzdUVUZEYUVJc1IwRkJRU3hKUVVGUExFdEJRVUVzUjBGQlVUdE5RVU5tTEZOQlFVRXNTVUZCWVR0TlFVTmlMRU5CUVVFc1NVRkJTenRKUVV4UU8xZEJUVUVzUjBGQlFTeEhRVUZOTzBWQlZrMDdPelpDUVZsa0xHbENRVUZCTEVkQlFXMUNMRk5CUVVNc1RVRkJSRHRYUVVOcVFpeEpRVUZETEVOQlFVRXNZVUZCUkN4TFFVRnJRaXhOUVVGc1FpeEpRVUUwUWl4SlFVRkRMRU5CUVVFc2FVSkJRVVFzUzBGQmMwSXNUVUZCYkVRc1NVRkRSU3hKUVVGRExFTkJRVUVzYTBKQlFVUXNTMEZCZFVJc1RVRkVla0lzU1VGRGJVTXNTVUZCUXl4RFFVRkJMRmRCUVVRc1MwRkJaMElzVFVGRWJrUXNTVUZGUlN4SlFVRkRMRU5CUVVFc1pVRkJSQ3hMUVVGdlFpeE5RVVowUWl4SlFVVm5ReXhKUVVGRExFTkJRVUVzWjBKQlFVUXNTMEZCY1VJN1JVRkljRU03T3pzN1IwRnlTRlVpZlE9PVxuIiwidmFyIEdlbmVyYXRvcjtcblxubW9kdWxlLmV4cG9ydHMgPSBHZW5lcmF0b3IgPSAoZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIEdlbmVyYXRvcigpIHt9XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZW5lcmF0ZSA9IGZ1bmN0aW9uKHN3YXRjaGVzKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldFZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TGlnaHRWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldERhcmtWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldE11dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldExpZ2h0TXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0RGFya011dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICByZXR1cm4gR2VuZXJhdG9yO1xuXG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cy5EZWZhdWx0ID0gcmVxdWlyZSgnLi9kZWZhdWx0Jyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZaMlZ1WlhKaGRHOXlMMmx1WkdWNExtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMMmRsYm1WeVlYUnZjaTlwYm1SbGVDNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNTVUZCUVRzN1FVRkJRU3hOUVVGTkxFTkJRVU1zVDBGQlVDeEhRVU5OT3pzN2MwSkJRMG9zVVVGQlFTeEhRVUZWTEZOQlFVTXNVVUZCUkN4SFFVRkJPenR6UWtGRlZpeG5Ra0ZCUVN4SFFVRnJRaXhUUVVGQkxFZEJRVUU3TzNOQ1FVVnNRaXh4UWtGQlFTeEhRVUYxUWl4VFFVRkJMRWRCUVVFN08zTkNRVVYyUWl4dlFrRkJRU3hIUVVGelFpeFRRVUZCTEVkQlFVRTdPM05DUVVWMFFpeGpRVUZCTEVkQlFXZENMRk5CUVVFc1IwRkJRVHM3YzBKQlJXaENMRzFDUVVGQkxFZEJRWEZDTEZOQlFVRXNSMEZCUVRzN2MwSkJSWEpDTEd0Q1FVRkJMRWRCUVc5Q0xGTkJRVUVzUjBGQlFUczdPenM3TzBGQlJYUkNMRTFCUVUwc1EwRkJReXhQUVVGUExFTkJRVU1zVDBGQlppeEhRVUY1UWl4UFFVRkJMRU5CUVZFc1YwRkJVaUo5XG4iLCJ2YXIgQnJvd3NlckltYWdlLCBJbWFnZSwgVXJsLCBpc1JlbGF0aXZlVXJsLCBpc1NhbWVPcmlnaW4sXG4gIGV4dGVuZCA9IGZ1bmN0aW9uKGNoaWxkLCBwYXJlbnQpIHsgZm9yICh2YXIga2V5IGluIHBhcmVudCkgeyBpZiAoaGFzUHJvcC5jYWxsKHBhcmVudCwga2V5KSkgY2hpbGRba2V5XSA9IHBhcmVudFtrZXldOyB9IGZ1bmN0aW9uIGN0b3IoKSB7IHRoaXMuY29uc3RydWN0b3IgPSBjaGlsZDsgfSBjdG9yLnByb3RvdHlwZSA9IHBhcmVudC5wcm90b3R5cGU7IGNoaWxkLnByb3RvdHlwZSA9IG5ldyBjdG9yKCk7IGNoaWxkLl9fc3VwZXJfXyA9IHBhcmVudC5wcm90b3R5cGU7IHJldHVybiBjaGlsZDsgfSxcbiAgaGFzUHJvcCA9IHt9Lmhhc093blByb3BlcnR5O1xuXG5JbWFnZSA9IHJlcXVpcmUoJy4vaW5kZXgnKTtcblxuVXJsID0gcmVxdWlyZSgndXJsJyk7XG5cbmlzUmVsYXRpdmVVcmwgPSBmdW5jdGlvbih1cmwpIHtcbiAgdmFyIHU7XG4gIHUgPSBVcmwucGFyc2UodXJsKTtcbiAgcmV0dXJuIHUucHJvdG9jb2wgPT09IG51bGwgJiYgdS5ob3N0ID09PSBudWxsICYmIHUucG9ydCA9PT0gbnVsbDtcbn07XG5cbmlzU2FtZU9yaWdpbiA9IGZ1bmN0aW9uKGEsIGIpIHtcbiAgdmFyIHVhLCB1YjtcbiAgdWEgPSBVcmwucGFyc2UoYSk7XG4gIHViID0gVXJsLnBhcnNlKGIpO1xuICByZXR1cm4gdWEucHJvdG9jb2wgPT09IHViLnByb3RvY29sICYmIHVhLmhvc3RuYW1lID09PSB1Yi5ob3N0bmFtZSAmJiB1YS5wb3J0ID09PSB1Yi5wb3J0O1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSBCcm93c2VySW1hZ2UgPSAoZnVuY3Rpb24oc3VwZXJDbGFzcykge1xuICBleHRlbmQoQnJvd3NlckltYWdlLCBzdXBlckNsYXNzKTtcblxuICBmdW5jdGlvbiBCcm93c2VySW1hZ2UocGF0aCwgY2IpIHtcbiAgICBpZiAodHlwZW9mIHBhdGggPT09ICdvYmplY3QnICYmIHBhdGggaW5zdGFuY2VvZiBIVE1MSW1hZ2VFbGVtZW50KSB7XG4gICAgICB0aGlzLmltZyA9IHBhdGg7XG4gICAgICBwYXRoID0gdGhpcy5pbWcuc3JjO1xuICAgIH0gZWxzZSB7XG4gICAgICB0aGlzLmltZyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2ltZycpO1xuICAgICAgdGhpcy5pbWcuc3JjID0gcGF0aDtcbiAgICB9XG4gICAgaWYgKCFpc1JlbGF0aXZlVXJsKHBhdGgpICYmICFpc1NhbWVPcmlnaW4od2luZG93LmxvY2F0aW9uLmhyZWYsIHBhdGgpKSB7XG4gICAgICB0aGlzLmltZy5jcm9zc09yaWdpbiA9ICdhbm9ueW1vdXMnO1xuICAgIH1cbiAgICB0aGlzLmltZy5vbmxvYWQgPSAoZnVuY3Rpb24oX3RoaXMpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbigpIHtcbiAgICAgICAgX3RoaXMuX2luaXRDYW52YXMoKTtcbiAgICAgICAgcmV0dXJuIHR5cGVvZiBjYiA9PT0gXCJmdW5jdGlvblwiID8gY2IobnVsbCwgX3RoaXMpIDogdm9pZCAwO1xuICAgICAgfTtcbiAgICB9KSh0aGlzKTtcbiAgICBpZiAodGhpcy5pbWcuY29tcGxldGUpIHtcbiAgICAgIHRoaXMuaW1nLm9ubG9hZCgpO1xuICAgIH1cbiAgICB0aGlzLmltZy5vbmVycm9yID0gKGZ1bmN0aW9uKF90aGlzKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oZSkge1xuICAgICAgICB2YXIgZXJyO1xuICAgICAgICBlcnIgPSBuZXcgRXJyb3IoXCJGYWlsIHRvIGxvYWQgaW1hZ2U6IFwiICsgcGF0aCk7XG4gICAgICAgIGVyci5yYXcgPSBlO1xuICAgICAgICByZXR1cm4gdHlwZW9mIGNiID09PSBcImZ1bmN0aW9uXCIgPyBjYihlcnIpIDogdm9pZCAwO1xuICAgICAgfTtcbiAgICB9KSh0aGlzKTtcbiAgfVxuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuX2luaXRDYW52YXMgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLmNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2NhbnZhcycpO1xuICAgIHRoaXMuY29udGV4dCA9IHRoaXMuY2FudmFzLmdldENvbnRleHQoJzJkJyk7XG4gICAgZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh0aGlzLmNhbnZhcyk7XG4gICAgdGhpcy53aWR0aCA9IHRoaXMuY2FudmFzLndpZHRoID0gdGhpcy5pbWcud2lkdGg7XG4gICAgdGhpcy5oZWlnaHQgPSB0aGlzLmNhbnZhcy5oZWlnaHQgPSB0aGlzLmltZy5oZWlnaHQ7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dC5kcmF3SW1hZ2UodGhpcy5pbWcsIDAsIDAsIHRoaXMud2lkdGgsIHRoaXMuaGVpZ2h0KTtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLmNsZWFyID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dC5jbGVhclJlY3QoMCwgMCwgdGhpcy53aWR0aCwgdGhpcy5oZWlnaHQpO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuZ2V0V2lkdGggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy53aWR0aDtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLmdldEhlaWdodCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmhlaWdodDtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLnJlc2l6ZSA9IGZ1bmN0aW9uKHcsIGgsIHIpIHtcbiAgICB0aGlzLndpZHRoID0gdGhpcy5jYW52YXMud2lkdGggPSB3O1xuICAgIHRoaXMuaGVpZ2h0ID0gdGhpcy5jYW52YXMuaGVpZ2h0ID0gaDtcbiAgICB0aGlzLmNvbnRleHQuc2NhbGUociwgcik7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dC5kcmF3SW1hZ2UodGhpcy5pbWcsIDAsIDApO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24oaW1hZ2VEYXRhKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dC5wdXRJbWFnZURhdGEoaW1hZ2VEYXRhLCAwLCAwKTtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLmdldFBpeGVsQ291bnQgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy53aWR0aCAqIHRoaXMuaGVpZ2h0O1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuZ2V0SW1hZ2VEYXRhID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGV4dC5nZXRJbWFnZURhdGEoMCwgMCwgdGhpcy53aWR0aCwgdGhpcy5oZWlnaHQpO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUucmVtb3ZlQ2FudmFzID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuY2FudmFzLnBhcmVudE5vZGUucmVtb3ZlQ2hpbGQodGhpcy5jYW52YXMpO1xuICB9O1xuXG4gIHJldHVybiBCcm93c2VySW1hZ2U7XG5cbn0pKEltYWdlKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmFXMWhaMlV2WW5KdmQzTmxjaTVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5cGJXRm5aUzlpY205M2MyVnlMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaVFVRkJRU3hKUVVGQkxIRkVRVUZCTzBWQlFVRTdPenRCUVVGQkxFdEJRVUVzUjBGQlVTeFBRVUZCTEVOQlFWRXNVMEZCVWpzN1FVRkRVaXhIUVVGQkxFZEJRVTBzVDBGQlFTeERRVUZSTEV0QlFWSTdPMEZCUlU0c1lVRkJRU3hIUVVGblFpeFRRVUZETEVkQlFVUTdRVUZEWkN4TlFVRkJPMFZCUVVFc1EwRkJRU3hIUVVGSkxFZEJRVWNzUTBGQlF5eExRVUZLTEVOQlFWVXNSMEZCVmp0VFFVVktMRU5CUVVNc1EwRkJReXhSUVVGR0xFdEJRV01zU1VGQlpDeEpRVUZ6UWl4RFFVRkRMRU5CUVVNc1NVRkJSaXhMUVVGVkxFbEJRV2hETEVsQlFYZERMRU5CUVVNc1EwRkJReXhKUVVGR0xFdEJRVlU3UVVGSWNFTTdPMEZCUzJoQ0xGbEJRVUVzUjBGQlpTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktPMEZCUTJJc1RVRkJRVHRGUVVGQkxFVkJRVUVzUjBGQlN5eEhRVUZITEVOQlFVTXNTMEZCU2l4RFFVRlZMRU5CUVZZN1JVRkRUQ3hGUVVGQkxFZEJRVXNzUjBGQlJ5eERRVUZETEV0QlFVb3NRMEZCVlN4RFFVRldPMU5CUjB3c1JVRkJSU3hEUVVGRExGRkJRVWdzUzBGQlpTeEZRVUZGTEVOQlFVTXNVVUZCYkVJc1NVRkJPRUlzUlVGQlJTeERRVUZETEZGQlFVZ3NTMEZCWlN4RlFVRkZMRU5CUVVNc1VVRkJhRVFzU1VGQk5FUXNSVUZCUlN4RFFVRkRMRWxCUVVnc1MwRkJWeXhGUVVGRkxFTkJRVU03UVVGTU4wUTdPMEZCVDJZc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUczdPMFZCUlZNc2MwSkJRVU1zU1VGQlJDeEZRVUZQTEVWQlFWQTdTVUZEV0N4SlFVRkhMRTlCUVU4c1NVRkJVQ3hMUVVGbExGRkJRV1lzU1VGQk5FSXNTVUZCUVN4WlFVRm5RaXhuUWtGQkwwTTdUVUZEUlN4SlFVRkRMRU5CUVVFc1IwRkJSQ3hIUVVGUE8wMUJRMUFzU1VGQlFTeEhRVUZQTEVsQlFVTXNRMEZCUVN4SFFVRkhMRU5CUVVNc1NVRkdaRHRMUVVGQkxFMUJRVUU3VFVGSlJTeEpRVUZETEVOQlFVRXNSMEZCUkN4SFFVRlBMRkZCUVZFc1EwRkJReXhoUVVGVUxFTkJRWFZDTEV0QlFYWkNPMDFCUTFBc1NVRkJReXhEUVVGQkxFZEJRVWNzUTBGQlF5eEhRVUZNTEVkQlFWY3NTMEZNWWpzN1NVRlBRU3hKUVVGSExFTkJRVWtzWVVGQlFTeERRVUZqTEVsQlFXUXNRMEZCU2l4SlFVRXlRaXhEUVVGSkxGbEJRVUVzUTBGQllTeE5RVUZOTEVOQlFVTXNVVUZCVVN4RFFVRkRMRWxCUVRkQ0xFVkJRVzFETEVsQlFXNURMRU5CUVd4RE8wMUJRMFVzU1VGQlF5eERRVUZCTEVkQlFVY3NRMEZCUXl4WFFVRk1MRWRCUVcxQ0xGbEJSSEpDT3p0SlFVZEJMRWxCUVVNc1EwRkJRU3hIUVVGSExFTkJRVU1zVFVGQlRDeEhRVUZqTEVOQlFVRXNVMEZCUVN4TFFVRkJPMkZCUVVFc1UwRkJRVHRSUVVOYUxFdEJRVU1zUTBGQlFTeFhRVUZFTEVOQlFVRTdNRU5CUTBFc1IwRkJTU3hOUVVGTk8wMUJSa1U3U1VGQlFTeERRVUZCTEVOQlFVRXNRMEZCUVN4SlFVRkJPMGxCUzJRc1NVRkJSeXhKUVVGRExFTkJRVUVzUjBGQlJ5eERRVUZETEZGQlFWSTdUVUZEUlN4SlFVRkRMRU5CUVVFc1IwRkJSeXhEUVVGRExFMUJRVXdzUTBGQlFTeEZRVVJHT3p0SlFVZEJMRWxCUVVNc1EwRkJRU3hIUVVGSExFTkJRVU1zVDBGQlRDeEhRVUZsTEVOQlFVRXNVMEZCUVN4TFFVRkJPMkZCUVVFc1UwRkJReXhEUVVGRU8wRkJRMklzV1VGQlFUdFJRVUZCTEVkQlFVRXNSMEZCVFN4SlFVRkpMRXRCUVVvc1EwRkJWU3h6UWtGQlFTeEhRVUY1UWl4SlFVRnVRenRSUVVOT0xFZEJRVWNzUTBGQlF5eEhRVUZLTEVkQlFWVTdNRU5CUTFZc1IwRkJTVHROUVVoVE8wbEJRVUVzUTBGQlFTeERRVUZCTEVOQlFVRXNTVUZCUVR0RlFXNUNTanM3ZVVKQmVVSmlMRmRCUVVFc1IwRkJZU3hUUVVGQk8wbEJRMWdzU1VGQlF5eERRVUZCTEUxQlFVUXNSMEZCVlN4UlFVRlJMRU5CUVVNc1lVRkJWQ3hEUVVGMVFpeFJRVUYyUWp0SlFVTldMRWxCUVVNc1EwRkJRU3hQUVVGRUxFZEJRVmNzU1VGQlF5eERRVUZCTEUxQlFVMHNRMEZCUXl4VlFVRlNMRU5CUVcxQ0xFbEJRVzVDTzBsQlExZ3NVVUZCVVN4RFFVRkRMRWxCUVVrc1EwRkJReXhYUVVGa0xFTkJRVEJDTEVsQlFVTXNRMEZCUVN4TlFVRXpRanRKUVVOQkxFbEJRVU1zUTBGQlFTeExRVUZFTEVkQlFWTXNTVUZCUXl4RFFVRkJMRTFCUVUwc1EwRkJReXhMUVVGU0xFZEJRV2RDTEVsQlFVTXNRMEZCUVN4SFFVRkhMRU5CUVVNN1NVRkRPVUlzU1VGQlF5eERRVUZCTEUxQlFVUXNSMEZCVlN4SlFVRkRMRU5CUVVFc1RVRkJUU3hEUVVGRExFMUJRVklzUjBGQmFVSXNTVUZCUXl4RFFVRkJMRWRCUVVjc1EwRkJRenRYUVVOb1F5eEpRVUZETEVOQlFVRXNUMEZCVHl4RFFVRkRMRk5CUVZRc1EwRkJiVUlzU1VGQlF5eERRVUZCTEVkQlFYQkNMRVZCUVhsQ0xFTkJRWHBDTEVWQlFUUkNMRU5CUVRWQ0xFVkJRU3RDTEVsQlFVTXNRMEZCUVN4TFFVRm9ReXhGUVVGMVF5eEpRVUZETEVOQlFVRXNUVUZCZUVNN1JVRk9WenM3ZVVKQlVXSXNTMEZCUVN4SFFVRlBMRk5CUVVFN1YwRkRUQ3hKUVVGRExFTkJRVUVzVDBGQlR5eERRVUZETEZOQlFWUXNRMEZCYlVJc1EwRkJia0lzUlVGQmMwSXNRMEZCZEVJc1JVRkJlVUlzU1VGQlF5eERRVUZCTEV0QlFURkNMRVZCUVdsRExFbEJRVU1zUTBGQlFTeE5RVUZzUXp0RlFVUkxPenQ1UWtGSFVDeFJRVUZCTEVkQlFWVXNVMEZCUVR0WFFVTlNMRWxCUVVNc1EwRkJRVHRGUVVSUE96dDVRa0ZIVml4VFFVRkJMRWRCUVZjc1UwRkJRVHRYUVVOVUxFbEJRVU1zUTBGQlFUdEZRVVJST3p0NVFrRkhXQ3hOUVVGQkxFZEJRVkVzVTBGQlF5eERRVUZFTEVWQlFVa3NRMEZCU2l4RlFVRlBMRU5CUVZBN1NVRkRUaXhKUVVGRExFTkJRVUVzUzBGQlJDeEhRVUZUTEVsQlFVTXNRMEZCUVN4TlFVRk5MRU5CUVVNc1MwRkJVaXhIUVVGblFqdEpRVU42UWl4SlFVRkRMRU5CUVVFc1RVRkJSQ3hIUVVGVkxFbEJRVU1zUTBGQlFTeE5RVUZOTEVOQlFVTXNUVUZCVWl4SFFVRnBRanRKUVVNelFpeEpRVUZETEVOQlFVRXNUMEZCVHl4RFFVRkRMRXRCUVZRc1EwRkJaU3hEUVVGbUxFVkJRV3RDTEVOQlFXeENPMWRCUTBFc1NVRkJReXhEUVVGQkxFOUJRVThzUTBGQlF5eFRRVUZVTEVOQlFXMUNMRWxCUVVNc1EwRkJRU3hIUVVGd1FpeEZRVUY1UWl4RFFVRjZRaXhGUVVFMFFpeERRVUUxUWp0RlFVcE5PenQ1UWtGTlVpeE5RVUZCTEVkQlFWRXNVMEZCUXl4VFFVRkVPMWRCUTA0c1NVRkJReXhEUVVGQkxFOUJRVThzUTBGQlF5eFpRVUZVTEVOQlFYTkNMRk5CUVhSQ0xFVkJRV2xETEVOQlFXcERMRVZCUVc5RExFTkJRWEJETzBWQlJFMDdPM2xDUVVkU0xHRkJRVUVzUjBGQlpTeFRRVUZCTzFkQlEySXNTVUZCUXl4RFFVRkJMRXRCUVVRc1IwRkJVeXhKUVVGRExFTkJRVUU3UlVGRVJ6czdlVUpCUjJZc1dVRkJRU3hIUVVGakxGTkJRVUU3VjBGRFdpeEpRVUZETEVOQlFVRXNUMEZCVHl4RFFVRkRMRmxCUVZRc1EwRkJjMElzUTBGQmRFSXNSVUZCZVVJc1EwRkJla0lzUlVGQk5FSXNTVUZCUXl4RFFVRkJMRXRCUVRkQ0xFVkJRVzlETEVsQlFVTXNRMEZCUVN4TlFVRnlRenRGUVVSWk96dDVRa0ZIWkN4WlFVRkJMRWRCUVdNc1UwRkJRVHRYUVVOYUxFbEJRVU1zUTBGQlFTeE5RVUZOTEVOQlFVTXNWVUZCVlN4RFFVRkRMRmRCUVc1Q0xFTkJRU3RDTEVsQlFVTXNRMEZCUVN4TlFVRm9RenRGUVVSWk96czdPMGRCTTBSWEluMD1cbiIsInZhciBJbWFnZTtcblxubW9kdWxlLmV4cG9ydHMgPSBJbWFnZSA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gSW1hZ2UoKSB7fVxuXG4gIEltYWdlLnByb3RvdHlwZS5jbGVhciA9IGZ1bmN0aW9uKCkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLnVwZGF0ZSA9IGZ1bmN0aW9uKGltYWdlRGF0YSkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLmdldFdpZHRoID0gZnVuY3Rpb24oKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUuZ2V0SGVpZ2h0ID0gZnVuY3Rpb24oKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUuc2NhbGVEb3duID0gZnVuY3Rpb24ob3B0cykge1xuICAgIHZhciBoZWlnaHQsIG1heFNpZGUsIHJhdGlvLCB3aWR0aDtcbiAgICB3aWR0aCA9IHRoaXMuZ2V0V2lkdGgoKTtcbiAgICBoZWlnaHQgPSB0aGlzLmdldEhlaWdodCgpO1xuICAgIHJhdGlvID0gMTtcbiAgICBpZiAob3B0cy5tYXhEaW1lbnNpb24gIT0gbnVsbCkge1xuICAgICAgbWF4U2lkZSA9IE1hdGgubWF4KHdpZHRoLCBoZWlnaHQpO1xuICAgICAgaWYgKG1heFNpZGUgPiBvcHRzLm1heERpbWVuc2lvbikge1xuICAgICAgICByYXRpbyA9IG9wdHMubWF4RGltZW5zaW9uIC8gbWF4U2lkZTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgcmF0aW8gPSAxIC8gb3B0cy5xdWFsaXR5O1xuICAgIH1cbiAgICBpZiAocmF0aW8gPCAxKSB7XG4gICAgICByZXR1cm4gdGhpcy5yZXNpemUod2lkdGggKiByYXRpbywgaGVpZ2h0ICogcmF0aW8sIHJhdGlvKTtcbiAgICB9XG4gIH07XG5cbiAgSW1hZ2UucHJvdG90eXBlLnJlc2l6ZSA9IGZ1bmN0aW9uKHcsIGgsIHIpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5nZXRQaXhlbENvdW50ID0gZnVuY3Rpb24oKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUuZ2V0SW1hZ2VEYXRhID0gZnVuY3Rpb24oKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUucmVtb3ZlQ2FudmFzID0gZnVuY3Rpb24oKSB7fTtcblxuICByZXR1cm4gSW1hZ2U7XG5cbn0pKCk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZhVzFoWjJVdmFXNWtaWGd1WTI5bVptVmxJaXdpYzI5MWNtTmxVbTl2ZENJNklpSXNJbk52ZFhKalpYTWlPbHNpTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmFXMWhaMlV2YVc1a1pYZ3VZMjltWm1WbElsMHNJbTVoYldWeklqcGJYU3dpYldGd2NHbHVaM01pT2lKQlFVRkJMRWxCUVVFN08wRkJRVUVzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFRzN08ydENRVU5LTEV0QlFVRXNSMEZCVHl4VFFVRkJMRWRCUVVFN08ydENRVVZRTEUxQlFVRXNSMEZCVVN4VFFVRkRMRk5CUVVRc1IwRkJRVHM3YTBKQlJWSXNVVUZCUVN4SFFVRlZMRk5CUVVFc1IwRkJRVHM3YTBKQlJWWXNVMEZCUVN4SFFVRlhMRk5CUVVFc1IwRkJRVHM3YTBKQlJWZ3NVMEZCUVN4SFFVRlhMRk5CUVVNc1NVRkJSRHRCUVVOVUxGRkJRVUU3U1VGQlFTeExRVUZCTEVkQlFWRXNTVUZCUXl4RFFVRkJMRkZCUVVRc1EwRkJRVHRKUVVOU0xFMUJRVUVzUjBGQlV5eEpRVUZETEVOQlFVRXNVMEZCUkN4RFFVRkJPMGxCUlZRc1MwRkJRU3hIUVVGUk8wbEJRMUlzU1VGQlJ5eDVRa0ZCU0R0TlFVTkZMRTlCUVVFc1IwRkJWU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEV0QlFWUXNSVUZCWjBJc1RVRkJhRUk3VFVGRFZpeEpRVUZITEU5QlFVRXNSMEZCVlN4SlFVRkpMRU5CUVVNc1dVRkJiRUk3VVVGRFJTeExRVUZCTEVkQlFWRXNTVUZCU1N4RFFVRkRMRmxCUVV3c1IwRkJiMElzVVVGRU9VSTdUMEZHUmp0TFFVRkJMRTFCUVVFN1RVRkxSU3hMUVVGQkxFZEJRVkVzUTBGQlFTeEhRVUZKTEVsQlFVa3NRMEZCUXl4UlFVeHVRanM3U1VGUFFTeEpRVUZITEV0QlFVRXNSMEZCVVN4RFFVRllPMkZCUTBVc1NVRkJReXhEUVVGQkxFMUJRVVFzUTBGQlVTeExRVUZCTEVkQlFWRXNTMEZCYUVJc1JVRkJkVUlzVFVGQlFTeEhRVUZUTEV0QlFXaERMRVZCUVhWRExFdEJRWFpETEVWQlJFWTdPMFZCV2xNN08ydENRV1ZZTEUxQlFVRXNSMEZCVVN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVDeEhRVUZCT3p0clFrRkhVaXhoUVVGQkxFZEJRV1VzVTBGQlFTeEhRVUZCT3p0clFrRkZaaXhaUVVGQkxFZEJRV01zVTBGQlFTeEhRVUZCT3p0clFrRkZaQ3haUVVGQkxFZEJRV01zVTBGQlFTeEhRVUZCSW4wPVxuIiwidmFyIE1NQ1EsIFBRdWV1ZSwgUlNISUZULCBTSUdCSVRTLCBTd2F0Y2gsIFZCb3gsIGdldENvbG9ySW5kZXgsIHJlZiwgdXRpbDtcblxucmVmID0gdXRpbCA9IHJlcXVpcmUoJy4uLy4uL3V0aWwnKSwgZ2V0Q29sb3JJbmRleCA9IHJlZi5nZXRDb2xvckluZGV4LCBTSUdCSVRTID0gcmVmLlNJR0JJVFMsIFJTSElGVCA9IHJlZi5SU0hJRlQ7XG5cblN3YXRjaCA9IHJlcXVpcmUoJy4uLy4uL3N3YXRjaCcpO1xuXG5WQm94ID0gcmVxdWlyZSgnLi92Ym94Jyk7XG5cblBRdWV1ZSA9IHJlcXVpcmUoJy4vcHF1ZXVlJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gTU1DUSA9IChmdW5jdGlvbigpIHtcbiAgTU1DUS5EZWZhdWx0T3B0cyA9IHtcbiAgICBtYXhJdGVyYXRpb25zOiAxMDAwLFxuICAgIGZyYWN0QnlQb3B1bGF0aW9uczogMC43NVxuICB9O1xuXG4gIGZ1bmN0aW9uIE1NQ1Eob3B0cykge1xuICAgIHRoaXMub3B0cyA9IHV0aWwuZGVmYXVsdHMob3B0cywgdGhpcy5jb25zdHJ1Y3Rvci5EZWZhdWx0T3B0cyk7XG4gIH1cblxuICBNTUNRLnByb3RvdHlwZS5xdWFudGl6ZSA9IGZ1bmN0aW9uKHBpeGVscywgb3B0cykge1xuICAgIHZhciBjb2xvciwgY29sb3JDb3VudCwgaGlzdCwgcHEsIHBxMiwgc2hvdWxkSWdub3JlLCBzd2F0Y2hlcywgdiwgdmJveDtcbiAgICBpZiAocGl4ZWxzLmxlbmd0aCA9PT0gMCB8fCBvcHRzLmNvbG9yQ291bnQgPCAyIHx8IG9wdHMuY29sb3JDb3VudCA+IDI1Nikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiV3JvbmcgTU1DUSBwYXJhbWV0ZXJzXCIpO1xuICAgIH1cbiAgICBzaG91bGRJZ25vcmUgPSBmdW5jdGlvbigpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9O1xuICAgIGlmIChBcnJheS5pc0FycmF5KG9wdHMuZmlsdGVycykgJiYgb3B0cy5maWx0ZXJzLmxlbmd0aCA+IDApIHtcbiAgICAgIHNob3VsZElnbm9yZSA9IGZ1bmN0aW9uKHIsIGcsIGIsIGEpIHtcbiAgICAgICAgdmFyIGYsIGksIGxlbiwgcmVmMTtcbiAgICAgICAgcmVmMSA9IG9wdHMuZmlsdGVycztcbiAgICAgICAgZm9yIChpID0gMCwgbGVuID0gcmVmMS5sZW5ndGg7IGkgPCBsZW47IGkrKykge1xuICAgICAgICAgIGYgPSByZWYxW2ldO1xuICAgICAgICAgIGlmICghZihyLCBnLCBiLCBhKSkge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH07XG4gICAgfVxuICAgIHZib3ggPSBWQm94LmJ1aWxkKHBpeGVscywgc2hvdWxkSWdub3JlKTtcbiAgICBoaXN0ID0gdmJveC5oaXN0O1xuICAgIGNvbG9yQ291bnQgPSBPYmplY3Qua2V5cyhoaXN0KS5sZW5ndGg7XG4gICAgcHEgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgIHJldHVybiBhLmNvdW50KCkgLSBiLmNvdW50KCk7XG4gICAgfSk7XG4gICAgcHEucHVzaCh2Ym94KTtcbiAgICB0aGlzLl9zcGxpdEJveGVzKHBxLCB0aGlzLm9wdHMuZnJhY3RCeVBvcHVsYXRpb25zICogb3B0cy5jb2xvckNvdW50KTtcbiAgICBwcTIgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgIHJldHVybiBhLmNvdW50KCkgKiBhLnZvbHVtZSgpIC0gYi5jb3VudCgpICogYi52b2x1bWUoKTtcbiAgICB9KTtcbiAgICBwcTIuY29udGVudHMgPSBwcS5jb250ZW50cztcbiAgICB0aGlzLl9zcGxpdEJveGVzKHBxMiwgb3B0cy5jb2xvckNvdW50IC0gcHEyLnNpemUoKSk7XG4gICAgc3dhdGNoZXMgPSBbXTtcbiAgICB0aGlzLnZib3hlcyA9IFtdO1xuICAgIHdoaWxlIChwcTIuc2l6ZSgpKSB7XG4gICAgICB2ID0gcHEyLnBvcCgpO1xuICAgICAgY29sb3IgPSB2LmF2ZygpO1xuICAgICAgaWYgKCEodHlwZW9mIHNob3VsZElnbm9yZSA9PT0gXCJmdW5jdGlvblwiID8gc2hvdWxkSWdub3JlKGNvbG9yWzBdLCBjb2xvclsxXSwgY29sb3JbMl0sIDI1NSkgOiB2b2lkIDApKSB7XG4gICAgICAgIHRoaXMudmJveGVzLnB1c2godik7XG4gICAgICAgIHN3YXRjaGVzLnB1c2gobmV3IFN3YXRjaChjb2xvciwgdi5jb3VudCgpKSk7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBzd2F0Y2hlcztcbiAgfTtcblxuICBNTUNRLnByb3RvdHlwZS5fc3BsaXRCb3hlcyA9IGZ1bmN0aW9uKHBxLCB0YXJnZXQpIHtcbiAgICB2YXIgY29sb3JDb3VudCwgaXRlcmF0aW9uLCBtYXhJdGVyYXRpb25zLCByZWYxLCB2Ym94LCB2Ym94MSwgdmJveDI7XG4gICAgY29sb3JDb3VudCA9IDE7XG4gICAgaXRlcmF0aW9uID0gMDtcbiAgICBtYXhJdGVyYXRpb25zID0gdGhpcy5vcHRzLm1heEl0ZXJhdGlvbnM7XG4gICAgd2hpbGUgKGl0ZXJhdGlvbiA8IG1heEl0ZXJhdGlvbnMpIHtcbiAgICAgIGl0ZXJhdGlvbisrO1xuICAgICAgdmJveCA9IHBxLnBvcCgpO1xuICAgICAgaWYgKCF2Ym94LmNvdW50KCkpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICByZWYxID0gdmJveC5zcGxpdCgpLCB2Ym94MSA9IHJlZjFbMF0sIHZib3gyID0gcmVmMVsxXTtcbiAgICAgIHBxLnB1c2godmJveDEpO1xuICAgICAgaWYgKHZib3gyKSB7XG4gICAgICAgIHBxLnB1c2godmJveDIpO1xuICAgICAgICBjb2xvckNvdW50Kys7XG4gICAgICB9XG4gICAgICBpZiAoY29sb3JDb3VudCA+PSB0YXJnZXQgfHwgaXRlcmF0aW9uID4gbWF4SXRlcmF0aW9ucykge1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuICB9O1xuXG4gIHJldHVybiBNTUNRO1xuXG59KSgpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDJsdGNHd3ZiVzFqY1M1amIyWm1aV1VpTENKemIzVnlZMlZTYjI5MElqb2lJaXdpYzI5MWNtTmxjeUk2V3lJdlZYTmxjbk12WXpRdlJHOWpkVzFsYm5SekwxQnliMnBsWTNSekwzTmxiR3hsYnk5dWIyUmxMV3h2WjI4dFkyOXNiM0p6TDNOeVl5OXhkV0Z1ZEdsNlpYSXZhVzF3YkM5dGJXTnhMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaVFVRk5RU3hKUVVGQk96dEJRVUZCTEUxQlFXMURMRWxCUVVFc1IwRkJUeXhQUVVGQkxFTkJRVkVzV1VGQlVpeERRVUV4UXl4RlFVRkRMR2xEUVVGRUxFVkJRV2RDTEhGQ1FVRm9RaXhGUVVGNVFqczdRVUZEZWtJc1RVRkJRU3hIUVVGVExFOUJRVUVzUTBGQlVTeGpRVUZTT3p0QlFVTlVMRWxCUVVFc1IwRkJUeXhQUVVGQkxFTkJRVkVzVVVGQlVqczdRVUZEVUN4TlFVRkJMRWRCUVZNc1QwRkJRU3hEUVVGUkxGVkJRVkk3TzBGQlJWUXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHRGUVVOS0xFbEJRVU1zUTBGQlFTeFhRVUZFTEVkQlEwVTdTVUZCUVN4aFFVRkJMRVZCUVdVc1NVRkJaanRKUVVOQkxHdENRVUZCTEVWQlFXOUNMRWxCUkhCQ096czdSVUZIVnl4alFVRkRMRWxCUVVRN1NVRkRXQ3hKUVVGRExFTkJRVUVzU1VGQlJDeEhRVUZSTEVsQlFVa3NRMEZCUXl4UlFVRk1MRU5CUVdNc1NVRkJaQ3hGUVVGdlFpeEpRVUZETEVOQlFVRXNWMEZCVnl4RFFVRkRMRmRCUVdwRE8wVkJSRWM3TzJsQ1FVVmlMRkZCUVVFc1IwRkJWU3hUUVVGRExFMUJRVVFzUlVGQlV5eEpRVUZVTzBGQlExSXNVVUZCUVR0SlFVRkJMRWxCUVVjc1RVRkJUU3hEUVVGRExFMUJRVkFzUzBGQmFVSXNRMEZCYWtJc1NVRkJjMElzU1VGQlNTeERRVUZETEZWQlFVd3NSMEZCYTBJc1EwRkJlRU1zU1VGQk5rTXNTVUZCU1N4RFFVRkRMRlZCUVV3c1IwRkJhMElzUjBGQmJFVTdRVUZEUlN4WlFVRk5MRWxCUVVrc1MwRkJTaXhEUVVGVkxIVkNRVUZXTEVWQlJGSTdPMGxCUjBFc1dVRkJRU3hIUVVGbExGTkJRVUU3WVVGQlJ6dEpRVUZJTzBsQlJXWXNTVUZCUnl4TFFVRkxMRU5CUVVNc1QwRkJUaXhEUVVGakxFbEJRVWtzUTBGQlF5eFBRVUZ1UWl4RFFVRkJMRWxCUVdkRExFbEJRVWtzUTBGQlF5eFBRVUZQTEVOQlFVTXNUVUZCWWl4SFFVRnpRaXhEUVVGNlJEdE5RVU5GTEZsQlFVRXNSMEZCWlN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVDeEZRVUZWTEVOQlFWWTdRVUZEWWl4WlFVRkJPMEZCUVVFN1FVRkJRU3hoUVVGQkxITkRRVUZCT3p0VlFVTkZMRWxCUVVjc1EwRkJTU3hEUVVGQkxFTkJRVVVzUTBGQlJpeEZRVUZMTEVOQlFVd3NSVUZCVVN4RFFVRlNMRVZCUVZjc1EwRkJXQ3hEUVVGUU8wRkJRVEJDTEcxQ1FVRlBMRXRCUVdwRE96dEJRVVJHTzBGQlJVRXNaVUZCVHp0TlFVaE5MRVZCUkdwQ096dEpRVTlCTEVsQlFVRXNSMEZCVHl4SlFVRkpMRU5CUVVNc1MwRkJUQ3hEUVVGWExFMUJRVmdzUlVGQmJVSXNXVUZCYmtJN1NVRkRVQ3hKUVVGQkxFZEJRVThzU1VGQlNTeERRVUZETzBsQlExb3NWVUZCUVN4SFFVRmhMRTFCUVUwc1EwRkJReXhKUVVGUUxFTkJRVmtzU1VGQldpeERRVUZwUWl4RFFVRkRPMGxCUXk5Q0xFVkJRVUVzUjBGQlN5eEpRVUZKTEUxQlFVb3NRMEZCVnl4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS08yRkJRVlVzUTBGQlF5eERRVUZETEV0QlFVWXNRMEZCUVN4RFFVRkJMRWRCUVZrc1EwRkJReXhEUVVGRExFdEJRVVlzUTBGQlFUdEpRVUYwUWl4RFFVRllPMGxCUlV3c1JVRkJSU3hEUVVGRExFbEJRVWdzUTBGQlVTeEpRVUZTTzBsQlIwRXNTVUZCUXl4RFFVRkJMRmRCUVVRc1EwRkJZU3hGUVVGaUxFVkJRV2xDTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2EwSkJRVTRzUjBGQk1rSXNTVUZCU1N4RFFVRkRMRlZCUVdwRU8wbEJSMEVzUjBGQlFTeEhRVUZOTEVsQlFVa3NUVUZCU2l4RFFVRlhMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW83WVVGQlZTeERRVUZETEVOQlFVTXNTMEZCUml4RFFVRkJMRU5CUVVFc1IwRkJXU3hEUVVGRExFTkJRVU1zVFVGQlJpeERRVUZCTEVOQlFWb3NSMEZCZVVJc1EwRkJReXhEUVVGRExFdEJRVVlzUTBGQlFTeERRVUZCTEVkQlFWa3NRMEZCUXl4RFFVRkRMRTFCUVVZc1EwRkJRVHRKUVVFdlF5eERRVUZZTzBsQlEwNHNSMEZCUnl4RFFVRkRMRkZCUVVvc1IwRkJaU3hGUVVGRkxFTkJRVU03U1VGSGJFSXNTVUZCUXl4RFFVRkJMRmRCUVVRc1EwRkJZU3hIUVVGaUxFVkJRV3RDTEVsQlFVa3NRMEZCUXl4VlFVRk1MRWRCUVd0Q0xFZEJRVWNzUTBGQlF5eEpRVUZLTEVOQlFVRXNRMEZCY0VNN1NVRkhRU3hSUVVGQkxFZEJRVmM3U1VGRFdDeEpRVUZETEVOQlFVRXNUVUZCUkN4SFFVRlZPMEZCUTFZc1YwRkJUU3hIUVVGSExFTkJRVU1zU1VGQlNpeERRVUZCTEVOQlFVNDdUVUZEUlN4RFFVRkJMRWRCUVVrc1IwRkJSeXhEUVVGRExFZEJRVW9zUTBGQlFUdE5RVU5LTEV0QlFVRXNSMEZCVVN4RFFVRkRMRU5CUVVNc1IwRkJSaXhEUVVGQk8wMUJRMUlzU1VGQlJ5eDFRMEZCU1N4aFFVRmpMRXRCUVUwc1EwRkJRU3hEUVVGQkxFZEJRVWtzUzBGQlRTeERRVUZCTEVOQlFVRXNSMEZCU1N4TFFVRk5MRU5CUVVFc1EwRkJRU3hIUVVGSkxHTkJRVzVFTzFGQlEwVXNTVUZCUXl4RFFVRkJMRTFCUVUwc1EwRkJReXhKUVVGU0xFTkJRV0VzUTBGQllqdFJRVU5CTEZGQlFWRXNRMEZCUXl4SlFVRlVMRU5CUVdNc1NVRkJTU3hOUVVGS0xFTkJRVmNzUzBGQldDeEZRVUZyUWl4RFFVRkRMRU5CUVVNc1MwRkJSaXhEUVVGQkxFTkJRV3hDTEVOQlFXUXNSVUZHUmpzN1NVRklSanRYUVU5Qk8wVkJlRU5ST3p0cFFrRXdRMVlzVjBGQlFTeEhRVUZoTEZOQlFVTXNSVUZCUkN4RlFVRkxMRTFCUVV3N1FVRkRXQ3hSUVVGQk8wbEJRVUVzVlVGQlFTeEhRVUZoTzBsQlEySXNVMEZCUVN4SFFVRlpPMGxCUTFvc1lVRkJRU3hIUVVGblFpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRPMEZCUTNSQ0xGZEJRVTBzVTBGQlFTeEhRVUZaTEdGQlFXeENPMDFCUTBVc1UwRkJRVHROUVVOQkxFbEJRVUVzUjBGQlR5eEZRVUZGTEVOQlFVTXNSMEZCU0N4RFFVRkJPMDFCUTFBc1NVRkJSeXhEUVVGRExFbEJRVWtzUTBGQlF5eExRVUZNTEVOQlFVRXNRMEZCU2p0QlFVTkZMR2xDUVVSR096dE5RVWRCTEU5QlFXbENMRWxCUVVrc1EwRkJReXhMUVVGTUxFTkJRVUVzUTBGQmFrSXNSVUZCUXl4bFFVRkVMRVZCUVZFN1RVRkZVaXhGUVVGRkxFTkJRVU1zU1VGQlNDeERRVUZSTEV0QlFWSTdUVUZEUVN4SlFVRkhMRXRCUVVnN1VVRkRSU3hGUVVGRkxFTkJRVU1zU1VGQlNDeERRVUZSTEV0QlFWSTdVVUZEUVN4VlFVRkJMRWRCUmtZN08wMUJSMEVzU1VGQlJ5eFZRVUZCTEVsQlFXTXNUVUZCWkN4SlFVRjNRaXhUUVVGQkxFZEJRVmtzWVVGQmRrTTdRVUZEUlN4bFFVUkdPenRKUVZwR08wVkJTbGNpZlE9PVxuIiwidmFyIFBRdWV1ZTtcblxubW9kdWxlLmV4cG9ydHMgPSBQUXVldWUgPSAoZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIFBRdWV1ZShjb21wYXJhdG9yKSB7XG4gICAgdGhpcy5jb21wYXJhdG9yID0gY29tcGFyYXRvcjtcbiAgICB0aGlzLmNvbnRlbnRzID0gW107XG4gICAgdGhpcy5zb3J0ZWQgPSBmYWxzZTtcbiAgfVxuXG4gIFBRdWV1ZS5wcm90b3R5cGUuX3NvcnQgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLmNvbnRlbnRzLnNvcnQodGhpcy5jb21wYXJhdG9yKTtcbiAgICByZXR1cm4gdGhpcy5zb3J0ZWQgPSB0cnVlO1xuICB9O1xuXG4gIFBRdWV1ZS5wcm90b3R5cGUucHVzaCA9IGZ1bmN0aW9uKG8pIHtcbiAgICB0aGlzLmNvbnRlbnRzLnB1c2gobyk7XG4gICAgcmV0dXJuIHRoaXMuc29ydGVkID0gZmFsc2U7XG4gIH07XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5wZWVrID0gZnVuY3Rpb24oaW5kZXgpIHtcbiAgICBpZiAoIXRoaXMuc29ydGVkKSB7XG4gICAgICB0aGlzLl9zb3J0KCk7XG4gICAgfVxuICAgIGlmIChpbmRleCA9PSBudWxsKSB7XG4gICAgICBpbmRleCA9IHRoaXMuY29udGVudHMubGVuZ3RoIC0gMTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuY29udGVudHNbaW5kZXhdO1xuICB9O1xuXG4gIFBRdWV1ZS5wcm90b3R5cGUucG9wID0gZnVuY3Rpb24oKSB7XG4gICAgaWYgKCF0aGlzLnNvcnRlZCkge1xuICAgICAgdGhpcy5fc29ydCgpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5jb250ZW50cy5wb3AoKTtcbiAgfTtcblxuICBQUXVldWUucHJvdG90eXBlLnNpemUgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5jb250ZW50cy5sZW5ndGg7XG4gIH07XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5tYXAgPSBmdW5jdGlvbihmKSB7XG4gICAgaWYgKCF0aGlzLnNvcnRlZCkge1xuICAgICAgdGhpcy5fc29ydCgpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5jb250ZW50cy5tYXAoZik7XG4gIH07XG5cbiAgcmV0dXJuIFBRdWV1ZTtcblxufSkoKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwybHRjR3d2Y0hGMVpYVmxMbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDNGMVlXNTBhWHBsY2k5cGJYQnNMM0J4ZFdWMVpTNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNTVUZCUVRzN1FVRkJRU3hOUVVGTkxFTkJRVU1zVDBGQlVDeEhRVU5OTzBWQlExTXNaMEpCUVVNc1ZVRkJSRHRKUVVGRExFbEJRVU1zUTBGQlFTeGhRVUZFTzBsQlExb3NTVUZCUXl4RFFVRkJMRkZCUVVRc1IwRkJXVHRKUVVOYUxFbEJRVU1zUTBGQlFTeE5RVUZFTEVkQlFWVTdSVUZHUXpzN2JVSkJTV0lzUzBGQlFTeEhRVUZQTEZOQlFVRTdTVUZEVEN4SlFVRkRMRU5CUVVFc1VVRkJVU3hEUVVGRExFbEJRVllzUTBGQlpTeEpRVUZETEVOQlFVRXNWVUZCYUVJN1YwRkRRU3hKUVVGRExFTkJRVUVzVFVGQlJDeEhRVUZWTzBWQlJrdzdPMjFDUVVsUUxFbEJRVUVzUjBGQlRTeFRRVUZETEVOQlFVUTdTVUZEU2l4SlFVRkRMRU5CUVVFc1VVRkJVU3hEUVVGRExFbEJRVllzUTBGQlpTeERRVUZtTzFkQlEwRXNTVUZCUXl4RFFVRkJMRTFCUVVRc1IwRkJWVHRGUVVaT096dHRRa0ZKVGl4SlFVRkJMRWRCUVUwc1UwRkJReXhMUVVGRU8wbEJRMG9zU1VGQlJ5eERRVUZKTEVsQlFVTXNRMEZCUVN4TlFVRlNPMDFCUTBVc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeEZRVVJHT3pzN1RVRkZRU3hSUVVGVExFbEJRVU1zUTBGQlFTeFJRVUZSTEVOQlFVTXNUVUZCVml4SFFVRnRRanM3VjBGRE5VSXNTVUZCUXl4RFFVRkJMRkZCUVZNc1EwRkJRU3hMUVVGQk8wVkJTazQ3TzIxQ1FVMU9MRWRCUVVFc1IwRkJTeXhUUVVGQk8wbEJRMGdzU1VGQlJ5eERRVUZKTEVsQlFVTXNRMEZCUVN4TlFVRlNPMDFCUTBVc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeEZRVVJHT3p0WFFVVkJMRWxCUVVNc1EwRkJRU3hSUVVGUkxFTkJRVU1zUjBGQlZpeERRVUZCTzBWQlNFYzdPMjFDUVV0TUxFbEJRVUVzUjBGQlRTeFRRVUZCTzFkQlEwb3NTVUZCUXl4RFFVRkJMRkZCUVZFc1EwRkJRenRGUVVST096dHRRa0ZIVGl4SFFVRkJMRWRCUVVzc1UwRkJReXhEUVVGRU8wbEJRMGdzU1VGQlJ5eERRVUZKTEVsQlFVTXNRMEZCUVN4TlFVRlNPMDFCUTBVc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeEZRVVJHT3p0WFFVVkJMRWxCUVVNc1EwRkJRU3hSUVVGUkxFTkJRVU1zUjBGQlZpeERRVUZqTEVOQlFXUTdSVUZJUnlKOVxuIiwidmFyIFJTSElGVCwgU0lHQklUUywgVkJveCwgZ2V0Q29sb3JJbmRleCwgcmVmLCB1dGlsO1xuXG5yZWYgPSB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpLCBnZXRDb2xvckluZGV4ID0gcmVmLmdldENvbG9ySW5kZXgsIFNJR0JJVFMgPSByZWYuU0lHQklUUywgUlNISUZUID0gcmVmLlJTSElGVDtcblxubW9kdWxlLmV4cG9ydHMgPSBWQm94ID0gKGZ1bmN0aW9uKCkge1xuICBWQm94LmJ1aWxkID0gZnVuY3Rpb24ocGl4ZWxzLCBzaG91bGRJZ25vcmUpIHtcbiAgICB2YXIgYSwgYiwgYm1heCwgYm1pbiwgZywgZ21heCwgZ21pbiwgaGlzdCwgaG4sIGksIGluZGV4LCBuLCBvZmZzZXQsIHIsIHJtYXgsIHJtaW47XG4gICAgaG4gPSAxIDw8ICgzICogU0lHQklUUyk7XG4gICAgaGlzdCA9IG5ldyBVaW50MzJBcnJheShobik7XG4gICAgcm1heCA9IGdtYXggPSBibWF4ID0gMDtcbiAgICBybWluID0gZ21pbiA9IGJtaW4gPSBOdW1iZXIuTUFYX1ZBTFVFO1xuICAgIG4gPSBwaXhlbHMubGVuZ3RoIC8gNDtcbiAgICBpID0gMDtcbiAgICB3aGlsZSAoaSA8IG4pIHtcbiAgICAgIG9mZnNldCA9IGkgKiA0O1xuICAgICAgaSsrO1xuICAgICAgciA9IHBpeGVsc1tvZmZzZXQgKyAwXTtcbiAgICAgIGcgPSBwaXhlbHNbb2Zmc2V0ICsgMV07XG4gICAgICBiID0gcGl4ZWxzW29mZnNldCArIDJdO1xuICAgICAgYSA9IHBpeGVsc1tvZmZzZXQgKyAzXTtcbiAgICAgIGlmIChzaG91bGRJZ25vcmUociwgZywgYiwgYSkpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG4gICAgICByID0gciA+PiBSU0hJRlQ7XG4gICAgICBnID0gZyA+PiBSU0hJRlQ7XG4gICAgICBiID0gYiA+PiBSU0hJRlQ7XG4gICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICBoaXN0W2luZGV4XSArPSAxO1xuICAgICAgaWYgKHIgPiBybWF4KSB7XG4gICAgICAgIHJtYXggPSByO1xuICAgICAgfVxuICAgICAgaWYgKHIgPCBybWluKSB7XG4gICAgICAgIHJtaW4gPSByO1xuICAgICAgfVxuICAgICAgaWYgKGcgPiBnbWF4KSB7XG4gICAgICAgIGdtYXggPSBnO1xuICAgICAgfVxuICAgICAgaWYgKGcgPCBnbWluKSB7XG4gICAgICAgIGdtaW4gPSBnO1xuICAgICAgfVxuICAgICAgaWYgKGIgPiBibWF4KSB7XG4gICAgICAgIGJtYXggPSBiO1xuICAgICAgfVxuICAgICAgaWYgKGIgPCBibWluKSB7XG4gICAgICAgIGJtaW4gPSBiO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbmV3IFZCb3gocm1pbiwgcm1heCwgZ21pbiwgZ21heCwgYm1pbiwgYm1heCwgaGlzdCk7XG4gIH07XG5cbiAgZnVuY3Rpb24gVkJveChyMSwgcjIsIGcxLCBnMiwgYjEsIGIyLCBoaXN0MSkge1xuICAgIHRoaXMucjEgPSByMTtcbiAgICB0aGlzLnIyID0gcjI7XG4gICAgdGhpcy5nMSA9IGcxO1xuICAgIHRoaXMuZzIgPSBnMjtcbiAgICB0aGlzLmIxID0gYjE7XG4gICAgdGhpcy5iMiA9IGIyO1xuICAgIHRoaXMuaGlzdCA9IGhpc3QxO1xuICB9XG5cbiAgVkJveC5wcm90b3R5cGUuaW52YWxpZGF0ZSA9IGZ1bmN0aW9uKCkge1xuICAgIGRlbGV0ZSB0aGlzLl9jb3VudDtcbiAgICBkZWxldGUgdGhpcy5fYXZnO1xuICAgIHJldHVybiBkZWxldGUgdGhpcy5fdm9sdW1lO1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLnZvbHVtZSA9IGZ1bmN0aW9uKCkge1xuICAgIGlmICh0aGlzLl92b2x1bWUgPT0gbnVsbCkge1xuICAgICAgdGhpcy5fdm9sdW1lID0gKHRoaXMucjIgLSB0aGlzLnIxICsgMSkgKiAodGhpcy5nMiAtIHRoaXMuZzEgKyAxKSAqICh0aGlzLmIyIC0gdGhpcy5iMSArIDEpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fdm9sdW1lO1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLmNvdW50ID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGMsIGhpc3Q7XG4gICAgaWYgKHRoaXMuX2NvdW50ID09IG51bGwpIHtcbiAgICAgIGhpc3QgPSB0aGlzLmhpc3Q7XG4gICAgICBjID0gMDtcbiAgICAgIFxuICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgIGMgKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICA7XG4gICAgICB0aGlzLl9jb3VudCA9IGM7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl9jb3VudDtcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS5jbG9uZSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiBuZXcgVkJveCh0aGlzLnIxLCB0aGlzLnIyLCB0aGlzLmcxLCB0aGlzLmcyLCB0aGlzLmIxLCB0aGlzLmIyLCB0aGlzLmhpc3QpO1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLmF2ZyA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBic3VtLCBnc3VtLCBoaXN0LCBtdWx0LCBudG90LCByc3VtO1xuICAgIGlmICh0aGlzLl9hdmcgPT0gbnVsbCkge1xuICAgICAgaGlzdCA9IHRoaXMuaGlzdDtcbiAgICAgIG50b3QgPSAwO1xuICAgICAgbXVsdCA9IDEgPDwgKDggLSBTSUdCSVRTKTtcbiAgICAgIHJzdW0gPSBnc3VtID0gYnN1bSA9IDA7XG4gICAgICBcbiAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICB2YXIgaCA9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgICAgbnRvdCArPSBoO1xuICAgICAgICAgICAgcnN1bSArPSAoaCAqIChyICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgZ3N1bSArPSAoaCAqIChnICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgYnN1bSArPSAoaCAqIChiICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgO1xuICAgICAgaWYgKG50b3QpIHtcbiAgICAgICAgdGhpcy5fYXZnID0gW35+KHJzdW0gLyBudG90KSwgfn4oZ3N1bSAvIG50b3QpLCB+fihic3VtIC8gbnRvdCldO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5fYXZnID0gW35+KG11bHQgKiAodGhpcy5yMSArIHRoaXMucjIgKyAxKSAvIDIpLCB+fihtdWx0ICogKHRoaXMuZzEgKyB0aGlzLmcyICsgMSkgLyAyKSwgfn4obXVsdCAqICh0aGlzLmIxICsgdGhpcy5iMiArIDEpIC8gMildO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fYXZnO1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLnNwbGl0ID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGFjY1N1bSwgYncsIGQsIGRvQ3V0LCBndywgaGlzdCwgaSwgaiwgbWF4ZCwgbWF4dywgcmVmMSwgcmV2ZXJzZVN1bSwgcncsIHNwbGl0UG9pbnQsIHN1bSwgdG90YWwsIHZib3g7XG4gICAgaGlzdCA9IHRoaXMuaGlzdDtcbiAgICBpZiAoIXRoaXMuY291bnQoKSkge1xuICAgICAgcmV0dXJuIG51bGw7XG4gICAgfVxuICAgIGlmICh0aGlzLmNvdW50KCkgPT09IDEpIHtcbiAgICAgIHJldHVybiBbdGhpcy5jbG9uZSgpXTtcbiAgICB9XG4gICAgcncgPSB0aGlzLnIyIC0gdGhpcy5yMSArIDE7XG4gICAgZ3cgPSB0aGlzLmcyIC0gdGhpcy5nMSArIDE7XG4gICAgYncgPSB0aGlzLmIyIC0gdGhpcy5iMSArIDE7XG4gICAgbWF4dyA9IE1hdGgubWF4KHJ3LCBndywgYncpO1xuICAgIGFjY1N1bSA9IG51bGw7XG4gICAgc3VtID0gdG90YWwgPSAwO1xuICAgIG1heGQgPSBudWxsO1xuICAgIHN3aXRjaCAobWF4dykge1xuICAgICAgY2FzZSBydzpcbiAgICAgICAgbWF4ZCA9ICdyJztcbiAgICAgICAgYWNjU3VtID0gbmV3IFVpbnQzMkFycmF5KHRoaXMucjIgKyAxKTtcbiAgICAgICAgXG4gICAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICAgIHN1bSA9IDBcbiAgICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgICBzdW0gKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICBhY2NTdW1bcl0gPSB0b3RhbDtcbiAgICAgICAgfVxuICAgICAgICA7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSBndzpcbiAgICAgICAgbWF4ZCA9ICdnJztcbiAgICAgICAgYWNjU3VtID0gbmV3IFVpbnQzMkFycmF5KHRoaXMuZzIgKyAxKTtcbiAgICAgICAgXG4gICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgIHN1bSA9IDBcbiAgICAgICAgICBmb3IgKHZhciByID0gdGhpcy5yMTsgciA8PSB0aGlzLnIyOyByKyspIHtcbiAgICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgICBzdW0gKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICBhY2NTdW1bZ10gPSB0b3RhbDtcbiAgICAgICAgfVxuICAgICAgICA7XG4gICAgICAgIGJyZWFrO1xuICAgICAgY2FzZSBidzpcbiAgICAgICAgbWF4ZCA9ICdiJztcbiAgICAgICAgYWNjU3VtID0gbmV3IFVpbnQzMkFycmF5KHRoaXMuYjIgKyAxKTtcbiAgICAgICAgXG4gICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgIHN1bSA9IDBcbiAgICAgICAgICBmb3IgKHZhciByID0gdGhpcy5yMTsgciA8PSB0aGlzLnIyOyByKyspIHtcbiAgICAgICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgICBzdW0gKz0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICBhY2NTdW1bYl0gPSB0b3RhbDtcbiAgICAgICAgfVxuICAgICAgICA7XG4gICAgfVxuICAgIHNwbGl0UG9pbnQgPSAtMTtcbiAgICByZXZlcnNlU3VtID0gbmV3IFVpbnQzMkFycmF5KGFjY1N1bS5sZW5ndGgpO1xuICAgIGZvciAoaSA9IGogPSAwLCByZWYxID0gYWNjU3VtLmxlbmd0aCAtIDE7IDAgPD0gcmVmMSA/IGogPD0gcmVmMSA6IGogPj0gcmVmMTsgaSA9IDAgPD0gcmVmMSA/ICsraiA6IC0taikge1xuICAgICAgZCA9IGFjY1N1bVtpXTtcbiAgICAgIGlmIChzcGxpdFBvaW50IDwgMCAmJiBkID4gdG90YWwgLyAyKSB7XG4gICAgICAgIHNwbGl0UG9pbnQgPSBpO1xuICAgICAgfVxuICAgICAgcmV2ZXJzZVN1bVtpXSA9IHRvdGFsIC0gZDtcbiAgICB9XG4gICAgdmJveCA9IHRoaXM7XG4gICAgZG9DdXQgPSBmdW5jdGlvbihkKSB7XG4gICAgICB2YXIgYzIsIGQxLCBkMiwgZGltMSwgZGltMiwgbGVmdCwgcmlnaHQsIHZib3gxLCB2Ym94MjtcbiAgICAgIGRpbTEgPSBkICsgXCIxXCI7XG4gICAgICBkaW0yID0gZCArIFwiMlwiO1xuICAgICAgZDEgPSB2Ym94W2RpbTFdO1xuICAgICAgZDIgPSB2Ym94W2RpbTJdO1xuICAgICAgdmJveDEgPSB2Ym94LmNsb25lKCk7XG4gICAgICB2Ym94MiA9IHZib3guY2xvbmUoKTtcbiAgICAgIGxlZnQgPSBzcGxpdFBvaW50IC0gZDE7XG4gICAgICByaWdodCA9IGQyIC0gc3BsaXRQb2ludDtcbiAgICAgIGlmIChsZWZ0IDw9IHJpZ2h0KSB7XG4gICAgICAgIGQyID0gTWF0aC5taW4oZDIgLSAxLCB+fihzcGxpdFBvaW50ICsgcmlnaHQgLyAyKSk7XG4gICAgICAgIGQyID0gTWF0aC5tYXgoMCwgZDIpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZDIgPSBNYXRoLm1heChkMSwgfn4oc3BsaXRQb2ludCAtIDEgLSBsZWZ0IC8gMikpO1xuICAgICAgICBkMiA9IE1hdGgubWluKHZib3hbZGltMl0sIGQyKTtcbiAgICAgIH1cbiAgICAgIHdoaWxlICghYWNjU3VtW2QyXSkge1xuICAgICAgICBkMisrO1xuICAgICAgfVxuICAgICAgYzIgPSByZXZlcnNlU3VtW2QyXTtcbiAgICAgIHdoaWxlICghYzIgJiYgYWNjU3VtW2QyIC0gMV0pIHtcbiAgICAgICAgYzIgPSByZXZlcnNlU3VtWy0tZDJdO1xuICAgICAgfVxuICAgICAgdmJveDFbZGltMl0gPSBkMjtcbiAgICAgIHZib3gyW2RpbTFdID0gZDIgKyAxO1xuICAgICAgcmV0dXJuIFt2Ym94MSwgdmJveDJdO1xuICAgIH07XG4gICAgcmV0dXJuIGRvQ3V0KG1heGQpO1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLmNvbnRhaW5zID0gZnVuY3Rpb24ocCkge1xuICAgIHZhciBiLCBnLCByO1xuICAgIHIgPSBwWzBdID4+IFJTSElGVDtcbiAgICBnID0gcFsxXSA+PiBSU0hJRlQ7XG4gICAgYiA9IHBbMl0gPj4gUlNISUZUO1xuICAgIHJldHVybiByID49IHRoaXMucjEgJiYgciA8PSB0aGlzLnIyICYmIGcgPj0gdGhpcy5nMSAmJiBnIDw9IHRoaXMuZzIgJiYgYiA+PSB0aGlzLmIxICYmIGIgPD0gdGhpcy5iMjtcbiAgfTtcblxuICByZXR1cm4gVkJveDtcblxufSkoKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwybHRjR3d2ZG1KdmVDNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTl4ZFdGdWRHbDZaWEl2YVcxd2JDOTJZbTk0TG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lRVUZCUVN4SlFVRkJPenRCUVVGQkxFMUJRVzFETEVsQlFVRXNSMEZCVHl4UFFVRkJMRU5CUVZFc1dVRkJVaXhEUVVFeFF5eEZRVUZETEdsRFFVRkVMRVZCUVdkQ0xIRkNRVUZvUWl4RlFVRjVRanM3UVVGRmVrSXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHRGUVVOS0xFbEJRVU1zUTBGQlFTeExRVUZFTEVkQlFWRXNVMEZCUXl4TlFVRkVMRVZCUVZNc1dVRkJWRHRCUVVOT0xGRkJRVUU3U1VGQlFTeEZRVUZCTEVkQlFVc3NRMEZCUVN4SlFVRkhMRU5CUVVNc1EwRkJRU3hIUVVGRkxFOUJRVWc3U1VGRFVpeEpRVUZCTEVkQlFVOHNTVUZCU1N4WFFVRktMRU5CUVdkQ0xFVkJRV2hDTzBsQlExQXNTVUZCUVN4SFFVRlBMRWxCUVVFc1IwRkJUeXhKUVVGQkxFZEJRVTg3U1VGRGNrSXNTVUZCUVN4SFFVRlBMRWxCUVVFc1IwRkJUeXhKUVVGQkxFZEJRVThzVFVGQlRTeERRVUZETzBsQlF6VkNMRU5CUVVFc1IwRkJTU3hOUVVGTkxFTkJRVU1zVFVGQlVDeEhRVUZuUWp0SlFVTndRaXhEUVVGQkxFZEJRVWs3UVVGRlNpeFhRVUZOTEVOQlFVRXNSMEZCU1N4RFFVRldPMDFCUTBVc1RVRkJRU3hIUVVGVExFTkJRVUVzUjBGQlNUdE5RVU5pTEVOQlFVRTdUVUZEUVN4RFFVRkJMRWRCUVVrc1RVRkJUeXhEUVVGQkxFMUJRVUVzUjBGQlV5eERRVUZVTzAxQlExZ3NRMEZCUVN4SFFVRkpMRTFCUVU4c1EwRkJRU3hOUVVGQkxFZEJRVk1zUTBGQlZEdE5RVU5ZTEVOQlFVRXNSMEZCU1N4TlFVRlBMRU5CUVVFc1RVRkJRU3hIUVVGVExFTkJRVlE3VFVGRFdDeERRVUZCTEVkQlFVa3NUVUZCVHl4RFFVRkJMRTFCUVVFc1IwRkJVeXhEUVVGVU8wMUJSVmdzU1VGQlJ5eFpRVUZCTEVOQlFXRXNRMEZCWWl4RlFVRm5RaXhEUVVGb1FpeEZRVUZ0UWl4RFFVRnVRaXhGUVVGelFpeERRVUYwUWl4RFFVRklPMEZCUVdsRExHbENRVUZxUXpzN1RVRkZRU3hEUVVGQkxFZEJRVWtzUTBGQlFTeEpRVUZMTzAxQlExUXNRMEZCUVN4SFFVRkpMRU5CUVVFc1NVRkJTenROUVVOVUxFTkJRVUVzUjBGQlNTeERRVUZCTEVsQlFVczdUVUZIVkN4TFFVRkJMRWRCUVZFc1lVRkJRU3hEUVVGakxFTkJRV1FzUlVGQmFVSXNRMEZCYWtJc1JVRkJiMElzUTBGQmNFSTdUVUZEVWl4SlFVRkxMRU5CUVVFc1MwRkJRU3hEUVVGTUxFbEJRV1U3VFVGRlppeEpRVUZITEVOQlFVRXNSMEZCU1N4SlFVRlFPMUZCUTBVc1NVRkJRU3hIUVVGUExFVkJSRlE3TzAxQlJVRXNTVUZCUnl4RFFVRkJMRWRCUVVrc1NVRkJVRHRSUVVORkxFbEJRVUVzUjBGQlR5eEZRVVJVT3p0TlFVVkJMRWxCUVVjc1EwRkJRU3hIUVVGSkxFbEJRVkE3VVVGRFJTeEpRVUZCTEVkQlFVOHNSVUZFVkRzN1RVRkZRU3hKUVVGSExFTkJRVUVzUjBGQlNTeEpRVUZRTzFGQlEwVXNTVUZCUVN4SFFVRlBMRVZCUkZRN08wMUJSVUVzU1VGQlJ5eERRVUZCTEVkQlFVa3NTVUZCVUR0UlFVTkZMRWxCUVVFc1IwRkJUeXhGUVVSVU96dE5RVVZCTEVsQlFVY3NRMEZCUVN4SFFVRkpMRWxCUVZBN1VVRkRSU3hKUVVGQkxFZEJRVThzUlVGRVZEczdTVUUxUWtZN1YwRXJRa0VzU1VGQlNTeEpRVUZLTEVOQlFWTXNTVUZCVkN4RlFVRmxMRWxCUVdZc1JVRkJjVUlzU1VGQmNrSXNSVUZCTWtJc1NVRkJNMElzUlVGQmFVTXNTVUZCYWtNc1JVRkJkVU1zU1VGQmRrTXNSVUZCTmtNc1NVRkJOME03UlVGMlEwMDdPMFZCZVVOTExHTkJRVU1zUlVGQlJDeEZRVUZOTEVWQlFVNHNSVUZCVnl4RlFVRllMRVZCUVdkQ0xFVkJRV2hDTEVWQlFYRkNMRVZCUVhKQ0xFVkJRVEJDTEVWQlFURkNMRVZCUVN0Q0xFdEJRUzlDTzBsQlFVTXNTVUZCUXl4RFFVRkJMRXRCUVVRN1NVRkJTeXhKUVVGRExFTkJRVUVzUzBGQlJEdEpRVUZMTEVsQlFVTXNRMEZCUVN4TFFVRkVPMGxCUVVzc1NVRkJReXhEUVVGQkxFdEJRVVE3U1VGQlN5eEpRVUZETEVOQlFVRXNTMEZCUkR0SlFVRkxMRWxCUVVNc1EwRkJRU3hMUVVGRU8wbEJRVXNzU1VGQlF5eERRVUZCTEU5QlFVUTdSVUZCTDBJN08ybENRVWRpTEZWQlFVRXNSMEZCV1N4VFFVRkJPMGxCUTFZc1QwRkJUeXhKUVVGRExFTkJRVUU3U1VGRFVpeFBRVUZQTEVsQlFVTXNRMEZCUVR0WFFVTlNMRTlCUVU4c1NVRkJReXhEUVVGQk8wVkJTRVU3TzJsQ1FVdGFMRTFCUVVFc1IwRkJVU3hUUVVGQk8wbEJRMDRzU1VGQlR5eHZRa0ZCVUR0TlFVTkZMRWxCUVVNc1EwRkJRU3hQUVVGRUxFZEJRVmNzUTBGQlF5eEpRVUZETEVOQlFVRXNSVUZCUkN4SFFVRk5MRWxCUVVNc1EwRkJRU3hGUVVGUUxFZEJRVmtzUTBGQllpeERRVUZCTEVkQlFXdENMRU5CUVVNc1NVRkJReXhEUVVGQkxFVkJRVVFzUjBGQlRTeEpRVUZETEVOQlFVRXNSVUZCVUN4SFFVRlpMRU5CUVdJc1EwRkJiRUlzUjBGQmIwTXNRMEZCUXl4SlFVRkRMRU5CUVVFc1JVRkJSQ3hIUVVGTkxFbEJRVU1zUTBGQlFTeEZRVUZRTEVkQlFWa3NRMEZCWWl4RlFVUnFSRHM3VjBGRlFTeEpRVUZETEVOQlFVRTdSVUZJU3pzN2FVSkJTMUlzUzBGQlFTeEhRVUZQTEZOQlFVRTdRVUZEVEN4UlFVRkJPMGxCUVVFc1NVRkJUeXh0UWtGQlVEdE5RVU5GTEVsQlFVRXNSMEZCVHl4SlFVRkRMRU5CUVVFN1RVRkRVaXhEUVVGQkxFZEJRVWs3VFVGRFNqczdPenM3T3pzN096dE5RV1ZCTEVsQlFVTXNRMEZCUVN4TlFVRkVMRWRCUVZVc1JVRnNRbG83TzFkQmJVSkJMRWxCUVVNc1EwRkJRVHRGUVhCQ1NUczdhVUpCYzBKUUxFdEJRVUVzUjBGQlR5eFRRVUZCTzFkQlEwd3NTVUZCU1N4SlFVRktMRU5CUVZNc1NVRkJReXhEUVVGQkxFVkJRVllzUlVGQll5eEpRVUZETEVOQlFVRXNSVUZCWml4RlFVRnRRaXhKUVVGRExFTkJRVUVzUlVGQmNFSXNSVUZCZDBJc1NVRkJReXhEUVVGQkxFVkJRWHBDTEVWQlFUWkNMRWxCUVVNc1EwRkJRU3hGUVVFNVFpeEZRVUZyUXl4SlFVRkRMRU5CUVVFc1JVRkJia01zUlVGQmRVTXNTVUZCUXl4RFFVRkJMRWxCUVhoRE8wVkJSRXM3TzJsQ1FVZFFMRWRCUVVFc1IwRkJTeXhUUVVGQk8wRkJRMGdzVVVGQlFUdEpRVUZCTEVsQlFVOHNhVUpCUVZBN1RVRkRSU3hKUVVGQkxFZEJRVThzU1VGQlF5eERRVUZCTzAxQlExSXNTVUZCUVN4SFFVRlBPMDFCUTFBc1NVRkJRU3hIUVVGUExFTkJRVUVzU1VGQlN5eERRVUZETEVOQlFVRXNSMEZCU1N4UFFVRk1PMDFCUTFvc1NVRkJRU3hIUVVGUExFbEJRVUVzUjBGQlR5eEpRVUZCTEVkQlFVODdUVUZEY2tJN096czdPenM3T3pzN096czdPMDFCZVVKQkxFbEJRVWNzU1VGQlNEdFJRVU5GTEVsQlFVTXNRMEZCUVN4SlFVRkVMRWRCUVZFc1EwRkRUaXhEUVVGRExFTkJRVU1zUTBGQlF5eEpRVUZCTEVkQlFVOHNTVUZCVWl4RFFVUkpMRVZCUlU0c1EwRkJReXhEUVVGRExFTkJRVU1zU1VGQlFTeEhRVUZQTEVsQlFWSXNRMEZHU1N4RlFVZE9MRU5CUVVNc1EwRkJReXhEUVVGRExFbEJRVUVzUjBGQlR5eEpRVUZTTEVOQlNFa3NSVUZFVmp0UFFVRkJMRTFCUVVFN1VVRlBSU3hKUVVGRExFTkJRVUVzU1VGQlJDeEhRVUZSTEVOQlEwNHNRMEZCUXl4RFFVRkRMRU5CUVVNc1NVRkJRU3hIUVVGUExFTkJRVU1zU1VGQlF5eERRVUZCTEVWQlFVUXNSMEZCVFN4SlFVRkRMRU5CUVVFc1JVRkJVQ3hIUVVGWkxFTkJRV0lzUTBGQlVDeEhRVUY1UWl4RFFVRXhRaXhEUVVSSkxFVkJSVTRzUTBGQlF5eERRVUZETEVOQlFVTXNTVUZCUVN4SFFVRlBMRU5CUVVNc1NVRkJReXhEUVVGQkxFVkJRVVFzUjBGQlRTeEpRVUZETEVOQlFVRXNSVUZCVUN4SFFVRlpMRU5CUVdJc1EwRkJVQ3hIUVVGNVFpeERRVUV4UWl4RFFVWkpMRVZCUjA0c1EwRkJReXhEUVVGRExFTkJRVU1zU1VGQlFTeEhRVUZQTEVOQlFVTXNTVUZCUXl4RFFVRkJMRVZCUVVRc1IwRkJUU3hKUVVGRExFTkJRVUVzUlVGQlVDeEhRVUZaTEVOQlFXSXNRMEZCVUN4SFFVRjVRaXhEUVVFeFFpeERRVWhKTEVWQlVGWTdUMEU1UWtZN08xZEJNRU5CTEVsQlFVTXNRMEZCUVR0RlFUTkRSVHM3YVVKQk5rTk1MRXRCUVVFc1IwRkJUeXhUUVVGQk8wRkJRMHdzVVVGQlFUdEpRVUZCTEVsQlFVRXNSMEZCVHl4SlFVRkRMRU5CUVVFN1NVRkRVaXhKUVVGSExFTkJRVU1zU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RFFVRktPMEZCUTBVc1lVRkJUeXhMUVVSVU96dEpRVVZCTEVsQlFVY3NTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hEUVVGQkxFdEJRVmtzUTBGQlpqdEJRVU5GTEdGQlFVOHNRMEZCUXl4SlFVRkRMRU5CUVVFc1MwRkJSQ3hEUVVGQkxFTkJRVVFzUlVGRVZEczdTVUZIUVN4RlFVRkJMRWRCUVVzc1NVRkJReXhEUVVGQkxFVkJRVVFzUjBGQlRTeEpRVUZETEVOQlFVRXNSVUZCVUN4SFFVRlpPMGxCUTJwQ0xFVkJRVUVzUjBGQlN5eEpRVUZETEVOQlFVRXNSVUZCUkN4SFFVRk5MRWxCUVVNc1EwRkJRU3hGUVVGUUxFZEJRVms3U1VGRGFrSXNSVUZCUVN4SFFVRkxMRWxCUVVNc1EwRkJRU3hGUVVGRUxFZEJRVTBzU1VGQlF5eERRVUZCTEVWQlFWQXNSMEZCV1R0SlFVVnFRaXhKUVVGQkxFZEJRVThzU1VGQlNTeERRVUZETEVkQlFVd3NRMEZCVXl4RlFVRlVMRVZCUVdFc1JVRkJZaXhGUVVGcFFpeEZRVUZxUWp0SlFVTlFMRTFCUVVFc1IwRkJVenRKUVVOVUxFZEJRVUVzUjBGQlRTeExRVUZCTEVkQlFWRTdTVUZGWkN4SlFVRkJMRWRCUVU4N1FVRkRVQ3haUVVGUExFbEJRVkE3UVVGQlFTeFhRVU5QTEVWQlJGQTdVVUZGU1N4SlFVRkJMRWRCUVU4N1VVRkRVQ3hOUVVGQkxFZEJRVk1zU1VGQlNTeFhRVUZLTEVOQlFXZENMRWxCUVVNc1EwRkJRU3hGUVVGRUxFZEJRVTBzUTBGQmRFSTdVVUZEVkRzN096czdPenM3T3pzN096dEJRVWhITzBGQlJGQXNWMEY1UWs4c1JVRjZRbEE3VVVFd1Fra3NTVUZCUVN4SFFVRlBPMUZCUTFBc1RVRkJRU3hIUVVGVExFbEJRVWtzVjBGQlNpeERRVUZuUWl4SlFVRkRMRU5CUVVFc1JVRkJSQ3hIUVVGTkxFTkJRWFJDTzFGQlExUTdPenM3T3pzN096czdPenM3UVVGSVJ6dEJRWHBDVUN4WFFXbEVUeXhGUVdwRVVEdFJRV3RFU1N4SlFVRkJMRWRCUVU4N1VVRkRVQ3hOUVVGQkxFZEJRVk1zU1VGQlNTeFhRVUZLTEVOQlFXZENMRWxCUVVNc1EwRkJRU3hGUVVGRUxFZEJRVTBzUTBGQmRFSTdVVUZEVkRzN096czdPenM3T3pzN096dEJRWEJFU2p0SlFUQkZRU3hWUVVGQkxFZEJRV0VzUTBGQlF6dEpRVU5rTEZWQlFVRXNSMEZCWVN4SlFVRkpMRmRCUVVvc1EwRkJaMElzVFVGQlRTeERRVUZETEUxQlFYWkNPMEZCUTJJc1UwRkJVeXhwUjBGQlZEdE5RVU5GTEVOQlFVRXNSMEZCU1N4TlFVRlBMRU5CUVVFc1EwRkJRVHROUVVOWUxFbEJRVWNzVlVGQlFTeEhRVUZoTEVOQlFXSXNTVUZCYTBJc1EwRkJRU3hIUVVGSkxFdEJRVUVzUjBGQlVTeERRVUZxUXp0UlFVTkZMRlZCUVVFc1IwRkJZU3hGUVVSbU96dE5RVVZCTEZWQlFWY3NRMEZCUVN4RFFVRkJMRU5CUVZnc1IwRkJaMElzUzBGQlFTeEhRVUZSTzBGQlNqRkNPMGxCVFVFc1NVRkJRU3hIUVVGUE8wbEJRMUFzUzBGQlFTeEhRVUZSTEZOQlFVTXNRMEZCUkR0QlFVTk9MRlZCUVVFN1RVRkJRU3hKUVVGQkxFZEJRVThzUTBGQlFTeEhRVUZKTzAxQlExZ3NTVUZCUVN4SFFVRlBMRU5CUVVFc1IwRkJTVHROUVVOWUxFVkJRVUVzUjBGQlN5eEpRVUZMTEVOQlFVRXNTVUZCUVR0TlFVTldMRVZCUVVFc1IwRkJTeXhKUVVGTExFTkJRVUVzU1VGQlFUdE5RVU5XTEV0QlFVRXNSMEZCVVN4SlFVRkpMRU5CUVVNc1MwRkJUQ3hEUVVGQk8wMUJRMUlzUzBGQlFTeEhRVUZSTEVsQlFVa3NRMEZCUXl4TFFVRk1MRU5CUVVFN1RVRkRVaXhKUVVGQkxFZEJRVThzVlVGQlFTeEhRVUZoTzAxQlEzQkNMRXRCUVVFc1IwRkJVU3hGUVVGQkxFZEJRVXM3VFVGRFlpeEpRVUZITEVsQlFVRXNTVUZCVVN4TFFVRllPMUZCUTBVc1JVRkJRU3hIUVVGTExFbEJRVWtzUTBGQlF5eEhRVUZNTEVOQlFWTXNSVUZCUVN4SFFVRkxMRU5CUVdRc1JVRkJhVUlzUTBGQlF5eERRVUZGTEVOQlFVTXNWVUZCUVN4SFFVRmhMRXRCUVVFc1IwRkJVU3hEUVVGMFFpeERRVUZ3UWp0UlFVTk1MRVZCUVVFc1IwRkJTeXhKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVOQlFWUXNSVUZCV1N4RlFVRmFMRVZCUmxBN1QwRkJRU3hOUVVGQk8xRkJTVVVzUlVGQlFTeEhRVUZMTEVsQlFVa3NRMEZCUXl4SFFVRk1MRU5CUVZNc1JVRkJWQ3hGUVVGaExFTkJRVU1zUTBGQlJTeERRVUZETEZWQlFVRXNSMEZCWVN4RFFVRmlMRWRCUVdsQ0xFbEJRVUVzUjBGQlR5eERRVUY2UWl4RFFVRm9RanRSUVVOTUxFVkJRVUVzUjBGQlN5eEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRWxCUVVzc1EwRkJRU3hKUVVGQkxFTkJRV1FzUlVGQmNVSXNSVUZCY2tJc1JVRk1VRHM3UVVGUlFTeGhRVUZOTEVOQlFVTXNUVUZCVHl4RFFVRkJMRVZCUVVFc1EwRkJaRHRSUVVORkxFVkJRVUU3VFVGRVJqdE5RVWxCTEVWQlFVRXNSMEZCU3l4VlFVRlhMRU5CUVVFc1JVRkJRVHRCUVVOb1FpeGhRVUZOTEVOQlFVTXNSVUZCUkN4SlFVRlJMRTFCUVU4c1EwRkJRU3hGUVVGQkxFZEJRVXNzUTBGQlRDeERRVUZ5UWp0UlFVTkZMRVZCUVVFc1IwRkJTeXhWUVVGWExFTkJRVUVzUlVGQlJTeEZRVUZHTzAxQlJHeENPMDFCUjBFc1MwRkJUU3hEUVVGQkxFbEJRVUVzUTBGQlRpeEhRVUZqTzAxQlEyUXNTMEZCVFN4RFFVRkJMRWxCUVVFc1EwRkJUaXhIUVVGakxFVkJRVUVzUjBGQlN6dEJRVWR1UWl4aFFVRlBMRU5CUVVNc1MwRkJSQ3hGUVVGUkxFdEJRVkk3U1VFM1FrUTdWMEVyUWxJc1MwRkJRU3hEUVVGTkxFbEJRVTQ3UlVGc1NVczdPMmxDUVc5SlVDeFJRVUZCTEVkQlFWVXNVMEZCUXl4RFFVRkVPMEZCUTFJc1VVRkJRVHRKUVVGQkxFTkJRVUVzUjBGQlNTeERRVUZGTEVOQlFVRXNRMEZCUVN4RFFVRkdMRWxCUVUwN1NVRkRWaXhEUVVGQkxFZEJRVWtzUTBGQlJTeERRVUZCTEVOQlFVRXNRMEZCUml4SlFVRk5PMGxCUTFZc1EwRkJRU3hIUVVGSkxFTkJRVVVzUTBGQlFTeERRVUZCTEVOQlFVWXNTVUZCVFR0WFFVVldMRU5CUVVFc1NVRkJTeXhKUVVGRExFTkJRVUVzUlVGQlRpeEpRVUZoTEVOQlFVRXNTVUZCU3l4SlFVRkRMRU5CUVVFc1JVRkJia0lzU1VGQk1FSXNRMEZCUVN4SlFVRkxMRWxCUVVNc1EwRkJRU3hGUVVGb1F5eEpRVUYxUXl4RFFVRkJMRWxCUVVzc1NVRkJReXhEUVVGQkxFVkJRVGRETEVsQlFXOUVMRU5CUVVFc1NVRkJTeXhKUVVGRExFTkJRVUVzUlVGQk1VUXNTVUZCYVVVc1EwRkJRU3hKUVVGTExFbEJRVU1zUTBGQlFUdEZRVXd2UkNKOVxuIiwidmFyIFF1YW50aXplcjtcblxubW9kdWxlLmV4cG9ydHMgPSBRdWFudGl6ZXIgPSAoZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIFF1YW50aXplcigpIHt9XG5cbiAgUXVhbnRpemVyLnByb3RvdHlwZS5pbml0aWFsaXplID0gZnVuY3Rpb24ocGl4ZWxzLCBvcHRzKSB7fTtcblxuICBRdWFudGl6ZXIucHJvdG90eXBlLmdldFF1YW50aXplZENvbG9ycyA9IGZ1bmN0aW9uKCkge307XG5cbiAgcmV0dXJuIFF1YW50aXplcjtcblxufSkoKTtcblxubW9kdWxlLmV4cG9ydHMuTU1DUSA9IHJlcXVpcmUoJy4vbW1jcScpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDJsdVpHVjRMbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDNGMVlXNTBhWHBsY2k5cGJtUmxlQzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzU1VGQlFUczdRVUZCUVN4TlFVRk5MRU5CUVVNc1QwRkJVQ3hIUVVOTk96czdjMEpCUTBvc1ZVRkJRU3hIUVVGWkxGTkJRVU1zVFVGQlJDeEZRVUZUTEVsQlFWUXNSMEZCUVRzN2MwSkJSVm9zYTBKQlFVRXNSMEZCYjBJc1UwRkJRU3hIUVVGQk96czdPenM3UVVGRmRFSXNUVUZCVFN4RFFVRkRMRTlCUVU4c1EwRkJReXhKUVVGbUxFZEJRWE5DTEU5QlFVRXNRMEZCVVN4UlFVRlNJbjA9XG4iLCJ2YXIgTU1DUSwgTU1DUUltcGwsIFF1YW50aXplciwgU3dhdGNoLFxuICBleHRlbmQgPSBmdW5jdGlvbihjaGlsZCwgcGFyZW50KSB7IGZvciAodmFyIGtleSBpbiBwYXJlbnQpIHsgaWYgKGhhc1Byb3AuY2FsbChwYXJlbnQsIGtleSkpIGNoaWxkW2tleV0gPSBwYXJlbnRba2V5XTsgfSBmdW5jdGlvbiBjdG9yKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gY2hpbGQ7IH0gY3Rvci5wcm90b3R5cGUgPSBwYXJlbnQucHJvdG90eXBlOyBjaGlsZC5wcm90b3R5cGUgPSBuZXcgY3RvcigpOyBjaGlsZC5fX3N1cGVyX18gPSBwYXJlbnQucHJvdG90eXBlOyByZXR1cm4gY2hpbGQ7IH0sXG4gIGhhc1Byb3AgPSB7fS5oYXNPd25Qcm9wZXJ0eTtcblxuU3dhdGNoID0gcmVxdWlyZSgnLi4vc3dhdGNoJyk7XG5cblF1YW50aXplciA9IHJlcXVpcmUoJy4vaW5kZXgnKTtcblxuTU1DUUltcGwgPSByZXF1aXJlKCcuL2ltcGwvbW1jcScpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IE1NQ1EgPSAoZnVuY3Rpb24oc3VwZXJDbGFzcykge1xuICBleHRlbmQoTU1DUSwgc3VwZXJDbGFzcyk7XG5cbiAgZnVuY3Rpb24gTU1DUSgpIHtcbiAgICByZXR1cm4gTU1DUS5fX3N1cGVyX18uY29uc3RydWN0b3IuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcbiAgfVxuXG4gIE1NQ1EucHJvdG90eXBlLmluaXRpYWxpemUgPSBmdW5jdGlvbihwaXhlbHMsIG9wdHMpIHtcbiAgICB2YXIgbW1jcTtcbiAgICB0aGlzLm9wdHMgPSBvcHRzO1xuICAgIG1tY3EgPSBuZXcgTU1DUUltcGwoKTtcbiAgICByZXR1cm4gdGhpcy5zd2F0Y2hlcyA9IG1tY3EucXVhbnRpemUocGl4ZWxzLCB0aGlzLm9wdHMpO1xuICB9O1xuXG4gIE1NQ1EucHJvdG90eXBlLmdldFF1YW50aXplZENvbG9ycyA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLnN3YXRjaGVzO1xuICB9O1xuXG4gIHJldHVybiBNTUNRO1xuXG59KShRdWFudGl6ZXIpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDIxdFkzRXVZMjltWm1WbElpd2ljMjkxY21ObFVtOXZkQ0k2SWlJc0luTnZkWEpqWlhNaU9sc2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDIxdFkzRXVZMjltWm1WbElsMHNJbTVoYldWeklqcGJYU3dpYldGd2NHbHVaM01pT2lKQlFVRkJMRWxCUVVFc2FVTkJRVUU3UlVGQlFUczdPMEZCUVVFc1RVRkJRU3hIUVVGVExFOUJRVUVzUTBGQlVTeFhRVUZTT3p0QlFVTlVMRk5CUVVFc1IwRkJXU3hQUVVGQkxFTkJRVkVzVTBGQlVqczdRVUZEV2l4UlFVRkJMRWRCUVZjc1QwRkJRU3hEUVVGUkxHRkJRVkk3TzBGQlJWZ3NUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHM3T3pzN096dHBRa0ZEU2l4VlFVRkJMRWRCUVZrc1UwRkJReXhOUVVGRUxFVkJRVk1zU1VGQlZEdEJRVU5XTEZGQlFVRTdTVUZFYlVJc1NVRkJReXhEUVVGQkxFOUJRVVE3U1VGRGJrSXNTVUZCUVN4SFFVRlBMRWxCUVVrc1VVRkJTaXhEUVVGQk8xZEJRMUFzU1VGQlF5eERRVUZCTEZGQlFVUXNSMEZCV1N4SlFVRkpMRU5CUVVNc1VVRkJUQ3hEUVVGakxFMUJRV1FzUlVGQmMwSXNTVUZCUXl4RFFVRkJMRWxCUVhaQ08wVkJSa1k3TzJsQ1FVbGFMR3RDUVVGQkxFZEJRVzlDTEZOQlFVRTdWMEZEYkVJc1NVRkJReXhEUVVGQk8wVkJSR2xDT3pzN08wZEJURWdpZlE9PVxuIiwidmFyIFN3YXRjaCwgdXRpbDtcblxudXRpbCA9IHJlcXVpcmUoJy4vdXRpbCcpO1xuXG5cbi8qXG4gIEZyb20gVmlicmFudC5qcyBieSBKYXJpIFp3YXJ0c1xuICBQb3J0ZWQgdG8gbm9kZS5qcyBieSBBS0Zpc2hcblxuICBTd2F0Y2ggY2xhc3NcbiAqL1xuXG5tb2R1bGUuZXhwb3J0cyA9IFN3YXRjaCA9IChmdW5jdGlvbigpIHtcbiAgU3dhdGNoLnByb3RvdHlwZS5oc2wgPSB2b2lkIDA7XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5yZ2IgPSB2b2lkIDA7XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5wb3B1bGF0aW9uID0gMTtcblxuICBTd2F0Y2gucHJvdG90eXBlLnlpcSA9IDA7XG5cbiAgZnVuY3Rpb24gU3dhdGNoKHJnYiwgcG9wdWxhdGlvbikge1xuICAgIHRoaXMucmdiID0gcmdiO1xuICAgIHRoaXMucG9wdWxhdGlvbiA9IHBvcHVsYXRpb247XG4gIH1cblxuICBTd2F0Y2gucHJvdG90eXBlLmdldEhzbCA9IGZ1bmN0aW9uKCkge1xuICAgIGlmICghdGhpcy5oc2wpIHtcbiAgICAgIHJldHVybiB0aGlzLmhzbCA9IHV0aWwucmdiVG9Ic2wodGhpcy5yZ2JbMF0sIHRoaXMucmdiWzFdLCB0aGlzLnJnYlsyXSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiB0aGlzLmhzbDtcbiAgICB9XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRQb3B1bGF0aW9uID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMucG9wdWxhdGlvbjtcbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLmdldFJnYiA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLnJnYjtcbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLmdldEhleCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB1dGlsLnJnYlRvSGV4KHRoaXMucmdiWzBdLCB0aGlzLnJnYlsxXSwgdGhpcy5yZ2JbMl0pO1xuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0VGl0bGVUZXh0Q29sb3IgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLl9lbnN1cmVUZXh0Q29sb3JzKCk7XG4gICAgaWYgKHRoaXMueWlxIDwgMjAwKSB7XG4gICAgICByZXR1cm4gXCIjZmZmXCI7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBcIiMwMDBcIjtcbiAgICB9XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRCb2R5VGV4dENvbG9yID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5fZW5zdXJlVGV4dENvbG9ycygpO1xuICAgIGlmICh0aGlzLnlpcSA8IDE1MCkge1xuICAgICAgcmV0dXJuIFwiI2ZmZlwiO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gXCIjMDAwXCI7XG4gICAgfVxuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuX2Vuc3VyZVRleHRDb2xvcnMgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAoIXRoaXMueWlxKSB7XG4gICAgICByZXR1cm4gdGhpcy55aXEgPSAodGhpcy5yZ2JbMF0gKiAyOTkgKyB0aGlzLnJnYlsxXSAqIDU4NyArIHRoaXMucmdiWzJdICogMTE0KSAvIDEwMDA7XG4gICAgfVxuICB9O1xuXG4gIHJldHVybiBTd2F0Y2g7XG5cbn0pKCk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjM2RoZEdOb0xtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMM04zWVhSamFDNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNTVUZCUVRzN1FVRkJRU3hKUVVGQkxFZEJRVThzVDBGQlFTeERRVUZSTEZGQlFWSTdPenRCUVVOUU96czdPenM3TzBGQlRVRXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHR0UWtGRFNpeEhRVUZCTEVkQlFVczdPMjFDUVVOTUxFZEJRVUVzUjBGQlN6czdiVUpCUTB3c1ZVRkJRU3hIUVVGWk96dHRRa0ZEV2l4SFFVRkJMRWRCUVVzN08wVkJSVkVzWjBKQlFVTXNSMEZCUkN4RlFVRk5MRlZCUVU0N1NVRkRXQ3hKUVVGRExFTkJRVUVzUjBGQlJDeEhRVUZQTzBsQlExQXNTVUZCUXl4RFFVRkJMRlZCUVVRc1IwRkJZenRGUVVaSU96dHRRa0ZKWWl4TlFVRkJMRWRCUVZFc1UwRkJRVHRKUVVOT0xFbEJRVWNzUTBGQlNTeEpRVUZETEVOQlFVRXNSMEZCVWp0aFFVTkZMRWxCUVVNc1EwRkJRU3hIUVVGRUxFZEJRVThzU1VGQlNTeERRVUZETEZGQlFVd3NRMEZCWXl4SlFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGQkxFTkJRVUVzUTBGQmJrSXNSVUZCZFVJc1NVRkJReXhEUVVGQkxFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFUVkNMRVZCUVdkRExFbEJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVRXNRMEZCUVN4RFFVRnlReXhGUVVSVU8wdEJRVUVzVFVGQlFUdGhRVVZMTEVsQlFVTXNRMEZCUVN4SlFVWk9PenRGUVVSTk96dHRRa0ZMVWl4aFFVRkJMRWRCUVdVc1UwRkJRVHRYUVVOaUxFbEJRVU1zUTBGQlFUdEZRVVJaT3p0dFFrRkhaaXhOUVVGQkxFZEJRVkVzVTBGQlFUdFhRVU5PTEVsQlFVTXNRMEZCUVR0RlFVUkxPenR0UWtGSFVpeE5RVUZCTEVkQlFWRXNVMEZCUVR0WFFVTk9MRWxCUVVrc1EwRkJReXhSUVVGTUxFTkJRV01zU1VGQlF5eERRVUZCTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVc1Q0xFVkJRWFZDTEVsQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVVFc1EwRkJRU3hEUVVFMVFpeEZRVUZuUXl4SlFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGQkxFTkJRVUVzUTBGQmNrTTdSVUZFVFRzN2JVSkJSMUlzYVVKQlFVRXNSMEZCYlVJc1UwRkJRVHRKUVVOcVFpeEpRVUZETEVOQlFVRXNhVUpCUVVRc1EwRkJRVHRKUVVOQkxFbEJRVWNzU1VGQlF5eERRVUZCTEVkQlFVUXNSMEZCVHl4SFFVRldPMkZCUVcxQ0xFOUJRVzVDTzB0QlFVRXNUVUZCUVR0aFFVRXJRaXhQUVVFdlFqczdSVUZHYVVJN08yMUNRVWx1UWl4blFrRkJRU3hIUVVGclFpeFRRVUZCTzBsQlEyaENMRWxCUVVNc1EwRkJRU3hwUWtGQlJDeERRVUZCTzBsQlEwRXNTVUZCUnl4SlFVRkRMRU5CUVVFc1IwRkJSQ3hIUVVGUExFZEJRVlk3WVVGQmJVSXNUMEZCYmtJN1MwRkJRU3hOUVVGQk8yRkJRU3RDTEU5QlFTOUNPenRGUVVablFqczdiVUpCU1d4Q0xHbENRVUZCTEVkQlFXMUNMRk5CUVVFN1NVRkRha0lzU1VGQlJ5eERRVUZKTEVsQlFVTXNRMEZCUVN4SFFVRlNPMkZCUVdsQ0xFbEJRVU1zUTBGQlFTeEhRVUZFTEVkQlFVOHNRMEZCUXl4SlFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGQkxFTkJRVUVzUTBGQlRDeEhRVUZWTEVkQlFWWXNSMEZCWjBJc1NVRkJReXhEUVVGQkxFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFVd3NSMEZCVlN4SFFVRXhRaXhIUVVGblF5eEpRVUZETEVOQlFVRXNSMEZCU1N4RFFVRkJMRU5CUVVFc1EwRkJUQ3hIUVVGVkxFZEJRVE5ETEVOQlFVRXNSMEZCYTBRc1MwRkJNVVU3TzBWQlJHbENJbjA9XG4iLCJ2YXIgREVMVEFFOTQsIFJTSElGVCwgU0lHQklUUztcblxuREVMVEFFOTQgPSB7XG4gIE5BOiAwLFxuICBQRVJGRUNUOiAxLFxuICBDTE9TRTogMixcbiAgR09PRDogMTAsXG4gIFNJTUlMQVI6IDUwXG59O1xuXG5TSUdCSVRTID0gNTtcblxuUlNISUZUID0gOCAtIFNJR0JJVFM7XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBjbG9uZTogZnVuY3Rpb24obykge1xuICAgIHZhciBfbywga2V5LCB2YWx1ZTtcbiAgICBpZiAodHlwZW9mIG8gPT09ICdvYmplY3QnKSB7XG4gICAgICBpZiAoQXJyYXkuaXNBcnJheShvKSkge1xuICAgICAgICByZXR1cm4gby5tYXAoKGZ1bmN0aW9uKF90aGlzKSB7XG4gICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uKHYpIHtcbiAgICAgICAgICAgIHJldHVybiBfdGhpcy5jbG9uZSh2KTtcbiAgICAgICAgICB9O1xuICAgICAgICB9KSh0aGlzKSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBfbyA9IHt9O1xuICAgICAgICBmb3IgKGtleSBpbiBvKSB7XG4gICAgICAgICAgdmFsdWUgPSBvW2tleV07XG4gICAgICAgICAgX29ba2V5XSA9IHRoaXMuY2xvbmUodmFsdWUpO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBfbztcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG87XG4gIH0sXG4gIGRlZmF1bHRzOiBmdW5jdGlvbigpIHtcbiAgICB2YXIgX28sIGksIGtleSwgbGVuLCBvLCB2YWx1ZTtcbiAgICBvID0ge307XG4gICAgZm9yIChpID0gMCwgbGVuID0gYXJndW1lbnRzLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICBfbyA9IGFyZ3VtZW50c1tpXTtcbiAgICAgIGZvciAoa2V5IGluIF9vKSB7XG4gICAgICAgIHZhbHVlID0gX29ba2V5XTtcbiAgICAgICAgaWYgKG9ba2V5XSA9PSBudWxsKSB7XG4gICAgICAgICAgb1trZXldID0gdGhpcy5jbG9uZSh2YWx1ZSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG87XG4gIH0sXG4gIGhleFRvUmdiOiBmdW5jdGlvbihoZXgpIHtcbiAgICB2YXIgbTtcbiAgICBtID0gL14jPyhbYS1mXFxkXXsyfSkoW2EtZlxcZF17Mn0pKFthLWZcXGRdezJ9KSQvaS5leGVjKGhleCk7XG4gICAgaWYgKG0gIT0gbnVsbCkge1xuICAgICAgcmV0dXJuIFttWzFdLCBtWzJdLCBtWzNdXS5tYXAoZnVuY3Rpb24ocykge1xuICAgICAgICByZXR1cm4gcGFyc2VJbnQocywgMTYpO1xuICAgICAgfSk7XG4gICAgfVxuICAgIHJldHVybiBudWxsO1xuICB9LFxuICByZ2JUb0hleDogZnVuY3Rpb24ociwgZywgYikge1xuICAgIHJldHVybiBcIiNcIiArICgoMSA8PCAyNCkgKyAociA8PCAxNikgKyAoZyA8PCA4KSArIGIpLnRvU3RyaW5nKDE2KS5zbGljZSgxLCA3KTtcbiAgfSxcbiAgcmdiVG9Ic2w6IGZ1bmN0aW9uKHIsIGcsIGIpIHtcbiAgICB2YXIgZCwgaCwgbCwgbWF4LCBtaW4sIHM7XG4gICAgciAvPSAyNTU7XG4gICAgZyAvPSAyNTU7XG4gICAgYiAvPSAyNTU7XG4gICAgbWF4ID0gTWF0aC5tYXgociwgZywgYik7XG4gICAgbWluID0gTWF0aC5taW4ociwgZywgYik7XG4gICAgaCA9IHZvaWQgMDtcbiAgICBzID0gdm9pZCAwO1xuICAgIGwgPSAobWF4ICsgbWluKSAvIDI7XG4gICAgaWYgKG1heCA9PT0gbWluKSB7XG4gICAgICBoID0gcyA9IDA7XG4gICAgfSBlbHNlIHtcbiAgICAgIGQgPSBtYXggLSBtaW47XG4gICAgICBzID0gbCA+IDAuNSA/IGQgLyAoMiAtIG1heCAtIG1pbikgOiBkIC8gKG1heCArIG1pbik7XG4gICAgICBzd2l0Y2ggKG1heCkge1xuICAgICAgICBjYXNlIHI6XG4gICAgICAgICAgaCA9IChnIC0gYikgLyBkICsgKGcgPCBiID8gNiA6IDApO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlIGc6XG4gICAgICAgICAgaCA9IChiIC0gcikgLyBkICsgMjtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSBiOlxuICAgICAgICAgIGggPSAociAtIGcpIC8gZCArIDQ7XG4gICAgICB9XG4gICAgICBoIC89IDY7XG4gICAgfVxuICAgIHJldHVybiBbaCwgcywgbF07XG4gIH0sXG4gIGhzbFRvUmdiOiBmdW5jdGlvbihoLCBzLCBsKSB7XG4gICAgdmFyIGIsIGcsIGh1ZTJyZ2IsIHAsIHEsIHI7XG4gICAgciA9IHZvaWQgMDtcbiAgICBnID0gdm9pZCAwO1xuICAgIGIgPSB2b2lkIDA7XG4gICAgaHVlMnJnYiA9IGZ1bmN0aW9uKHAsIHEsIHQpIHtcbiAgICAgIGlmICh0IDwgMCkge1xuICAgICAgICB0ICs9IDE7XG4gICAgICB9XG4gICAgICBpZiAodCA+IDEpIHtcbiAgICAgICAgdCAtPSAxO1xuICAgICAgfVxuICAgICAgaWYgKHQgPCAxIC8gNikge1xuICAgICAgICByZXR1cm4gcCArIChxIC0gcCkgKiA2ICogdDtcbiAgICAgIH1cbiAgICAgIGlmICh0IDwgMSAvIDIpIHtcbiAgICAgICAgcmV0dXJuIHE7XG4gICAgICB9XG4gICAgICBpZiAodCA8IDIgLyAzKSB7XG4gICAgICAgIHJldHVybiBwICsgKHEgLSBwKSAqICgyIC8gMyAtIHQpICogNjtcbiAgICAgIH1cbiAgICAgIHJldHVybiBwO1xuICAgIH07XG4gICAgaWYgKHMgPT09IDApIHtcbiAgICAgIHIgPSBnID0gYiA9IGw7XG4gICAgfSBlbHNlIHtcbiAgICAgIHEgPSBsIDwgMC41ID8gbCAqICgxICsgcykgOiBsICsgcyAtIChsICogcyk7XG4gICAgICBwID0gMiAqIGwgLSBxO1xuICAgICAgciA9IGh1ZTJyZ2IocCwgcSwgaCArIDEgLyAzKTtcbiAgICAgIGcgPSBodWUycmdiKHAsIHEsIGgpO1xuICAgICAgYiA9IGh1ZTJyZ2IocCwgcSwgaCAtICgxIC8gMykpO1xuICAgIH1cbiAgICByZXR1cm4gW3IgKiAyNTUsIGcgKiAyNTUsIGIgKiAyNTVdO1xuICB9LFxuICByZ2JUb1h5ejogZnVuY3Rpb24ociwgZywgYikge1xuICAgIHZhciB4LCB5LCB6O1xuICAgIHIgLz0gMjU1O1xuICAgIGcgLz0gMjU1O1xuICAgIGIgLz0gMjU1O1xuICAgIHIgPSByID4gMC4wNDA0NSA/IE1hdGgucG93KChyICsgMC4wMDUpIC8gMS4wNTUsIDIuNCkgOiByIC8gMTIuOTI7XG4gICAgZyA9IGcgPiAwLjA0MDQ1ID8gTWF0aC5wb3coKGcgKyAwLjAwNSkgLyAxLjA1NSwgMi40KSA6IGcgLyAxMi45MjtcbiAgICBiID0gYiA+IDAuMDQwNDUgPyBNYXRoLnBvdygoYiArIDAuMDA1KSAvIDEuMDU1LCAyLjQpIDogYiAvIDEyLjkyO1xuICAgIHIgKj0gMTAwO1xuICAgIGcgKj0gMTAwO1xuICAgIGIgKj0gMTAwO1xuICAgIHggPSByICogMC40MTI0ICsgZyAqIDAuMzU3NiArIGIgKiAwLjE4MDU7XG4gICAgeSA9IHIgKiAwLjIxMjYgKyBnICogMC43MTUyICsgYiAqIDAuMDcyMjtcbiAgICB6ID0gciAqIDAuMDE5MyArIGcgKiAwLjExOTIgKyBiICogMC45NTA1O1xuICAgIHJldHVybiBbeCwgeSwgel07XG4gIH0sXG4gIHh5elRvQ0lFTGFiOiBmdW5jdGlvbih4LCB5LCB6KSB7XG4gICAgdmFyIEwsIFJFRl9YLCBSRUZfWSwgUkVGX1osIGEsIGI7XG4gICAgUkVGX1ggPSA5NS4wNDc7XG4gICAgUkVGX1kgPSAxMDA7XG4gICAgUkVGX1ogPSAxMDguODgzO1xuICAgIHggLz0gUkVGX1g7XG4gICAgeSAvPSBSRUZfWTtcbiAgICB6IC89IFJFRl9aO1xuICAgIHggPSB4ID4gMC4wMDg4NTYgPyBNYXRoLnBvdyh4LCAxIC8gMykgOiA3Ljc4NyAqIHggKyAxNiAvIDExNjtcbiAgICB5ID0geSA+IDAuMDA4ODU2ID8gTWF0aC5wb3coeSwgMSAvIDMpIDogNy43ODcgKiB5ICsgMTYgLyAxMTY7XG4gICAgeiA9IHogPiAwLjAwODg1NiA/IE1hdGgucG93KHosIDEgLyAzKSA6IDcuNzg3ICogeiArIDE2IC8gMTE2O1xuICAgIEwgPSAxMTYgKiB5IC0gMTY7XG4gICAgYSA9IDUwMCAqICh4IC0geSk7XG4gICAgYiA9IDIwMCAqICh5IC0geik7XG4gICAgcmV0dXJuIFtMLCBhLCBiXTtcbiAgfSxcbiAgcmdiVG9DSUVMYWI6IGZ1bmN0aW9uKHIsIGcsIGIpIHtcbiAgICB2YXIgcmVmLCB4LCB5LCB6O1xuICAgIHJlZiA9IHRoaXMucmdiVG9YeXoociwgZywgYiksIHggPSByZWZbMF0sIHkgPSByZWZbMV0sIHogPSByZWZbMl07XG4gICAgcmV0dXJuIHRoaXMueHl6VG9DSUVMYWIoeCwgeSwgeik7XG4gIH0sXG4gIGRlbHRhRTk0OiBmdW5jdGlvbihsYWIxLCBsYWIyKSB7XG4gICAgdmFyIEwxLCBMMiwgV0VJR0hUX0MsIFdFSUdIVF9ILCBXRUlHSFRfTCwgYTEsIGEyLCBiMSwgYjIsIGRMLCBkYSwgZGIsIHhDMSwgeEMyLCB4REMsIHhERSwgeERILCB4REwsIHhTQywgeFNIO1xuICAgIFdFSUdIVF9MID0gMTtcbiAgICBXRUlHSFRfQyA9IDE7XG4gICAgV0VJR0hUX0ggPSAxO1xuICAgIEwxID0gbGFiMVswXSwgYTEgPSBsYWIxWzFdLCBiMSA9IGxhYjFbMl07XG4gICAgTDIgPSBsYWIyWzBdLCBhMiA9IGxhYjJbMV0sIGIyID0gbGFiMlsyXTtcbiAgICBkTCA9IEwxIC0gTDI7XG4gICAgZGEgPSBhMSAtIGEyO1xuICAgIGRiID0gYjEgLSBiMjtcbiAgICB4QzEgPSBNYXRoLnNxcnQoYTEgKiBhMSArIGIxICogYjEpO1xuICAgIHhDMiA9IE1hdGguc3FydChhMiAqIGEyICsgYjIgKiBiMik7XG4gICAgeERMID0gTDIgLSBMMTtcbiAgICB4REMgPSB4QzIgLSB4QzE7XG4gICAgeERFID0gTWF0aC5zcXJ0KGRMICogZEwgKyBkYSAqIGRhICsgZGIgKiBkYik7XG4gICAgaWYgKE1hdGguc3FydCh4REUpID4gTWF0aC5zcXJ0KE1hdGguYWJzKHhETCkpICsgTWF0aC5zcXJ0KE1hdGguYWJzKHhEQykpKSB7XG4gICAgICB4REggPSBNYXRoLnNxcnQoeERFICogeERFIC0geERMICogeERMIC0geERDICogeERDKTtcbiAgICB9IGVsc2Uge1xuICAgICAgeERIID0gMDtcbiAgICB9XG4gICAgeFNDID0gMSArIDAuMDQ1ICogeEMxO1xuICAgIHhTSCA9IDEgKyAwLjAxNSAqIHhDMTtcbiAgICB4REwgLz0gV0VJR0hUX0w7XG4gICAgeERDIC89IFdFSUdIVF9DICogeFNDO1xuICAgIHhESCAvPSBXRUlHSFRfSCAqIHhTSDtcbiAgICByZXR1cm4gTWF0aC5zcXJ0KHhETCAqIHhETCArIHhEQyAqIHhEQyArIHhESCAqIHhESCk7XG4gIH0sXG4gIHJnYkRpZmY6IGZ1bmN0aW9uKHJnYjEsIHJnYjIpIHtcbiAgICB2YXIgbGFiMSwgbGFiMjtcbiAgICBsYWIxID0gdGhpcy5yZ2JUb0NJRUxhYi5hcHBseSh0aGlzLCByZ2IxKTtcbiAgICBsYWIyID0gdGhpcy5yZ2JUb0NJRUxhYi5hcHBseSh0aGlzLCByZ2IyKTtcbiAgICByZXR1cm4gdGhpcy5kZWx0YUU5NChsYWIxLCBsYWIyKTtcbiAgfSxcbiAgaGV4RGlmZjogZnVuY3Rpb24oaGV4MSwgaGV4Mikge1xuICAgIHZhciByZ2IxLCByZ2IyO1xuICAgIHJnYjEgPSB0aGlzLmhleFRvUmdiKGhleDEpO1xuICAgIHJnYjIgPSB0aGlzLmhleFRvUmdiKGhleDIpO1xuICAgIHJldHVybiB0aGlzLnJnYkRpZmYocmdiMSwgcmdiMik7XG4gIH0sXG4gIERFTFRBRTk0X0RJRkZfU1RBVFVTOiBERUxUQUU5NCxcbiAgZ2V0Q29sb3JEaWZmU3RhdHVzOiBmdW5jdGlvbihkKSB7XG4gICAgaWYgKGQgPCBERUxUQUU5NC5OQSkge1xuICAgICAgcmV0dXJuIFwiTi9BXCI7XG4gICAgfVxuICAgIGlmIChkIDw9IERFTFRBRTk0LlBFUkZFQ1QpIHtcbiAgICAgIHJldHVybiBcIlBlcmZlY3RcIjtcbiAgICB9XG4gICAgaWYgKGQgPD0gREVMVEFFOTQuQ0xPU0UpIHtcbiAgICAgIHJldHVybiBcIkNsb3NlXCI7XG4gICAgfVxuICAgIGlmIChkIDw9IERFTFRBRTk0LkdPT0QpIHtcbiAgICAgIHJldHVybiBcIkdvb2RcIjtcbiAgICB9XG4gICAgaWYgKGQgPCBERUxUQUU5NC5TSU1JTEFSKSB7XG4gICAgICByZXR1cm4gXCJTaW1pbGFyXCI7XG4gICAgfVxuICAgIHJldHVybiBcIldyb25nXCI7XG4gIH0sXG4gIFNJR0JJVFM6IFNJR0JJVFMsXG4gIFJTSElGVDogUlNISUZULFxuICBnZXRDb2xvckluZGV4OiBmdW5jdGlvbihyLCBnLCBiKSB7XG4gICAgcmV0dXJuIChyIDw8ICgyICogU0lHQklUUykpICsgKGcgPDwgU0lHQklUUykgKyBiO1xuICB9XG59O1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12ZFhScGJDNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTkxZEdsc0xtTnZabVpsWlNKZExDSnVZVzFsY3lJNlcxMHNJbTFoY0hCcGJtZHpJam9pUVVGQlFTeEpRVUZCT3p0QlFVRkJMRkZCUVVFc1IwRkRSVHRGUVVGQkxFVkJRVUVzUlVGQlNTeERRVUZLTzBWQlEwRXNUMEZCUVN4RlFVRlRMRU5CUkZRN1JVRkZRU3hMUVVGQkxFVkJRVThzUTBGR1VEdEZRVWRCTEVsQlFVRXNSVUZCVFN4RlFVaE9PMFZCU1VFc1QwRkJRU3hGUVVGVExFVkJTbFE3T3p0QlFVMUdMRTlCUVVFc1IwRkJWVHM3UVVGRFZpeE5RVUZCTEVkQlFWTXNRMEZCUVN4SFFVRkpPenRCUVVsaUxFMUJRVTBzUTBGQlF5eFBRVUZRTEVkQlEwVTdSVUZCUVN4TFFVRkJMRVZCUVU4c1UwRkJReXhEUVVGRU8wRkJRMHdzVVVGQlFUdEpRVUZCTEVsQlFVY3NUMEZCVHl4RFFVRlFMRXRCUVZrc1VVRkJaanROUVVORkxFbEJRVWNzUzBGQlN5eERRVUZETEU5QlFVNHNRMEZCWXl4RFFVRmtMRU5CUVVnN1FVRkRSU3hsUVVGUExFTkJRVU1zUTBGQlF5eEhRVUZHTEVOQlFVMHNRMEZCUVN4VFFVRkJMRXRCUVVFN2FVSkJRVUVzVTBGQlF5eERRVUZFTzIxQ1FVRlBMRXRCUVVrc1EwRkJReXhMUVVGTUxFTkJRVmNzUTBGQldEdFZRVUZRTzFGQlFVRXNRMEZCUVN4RFFVRkJMRU5CUVVFc1NVRkJRU3hEUVVGT0xFVkJSRlE3VDBGQlFTeE5RVUZCTzFGQlIwVXNSVUZCUVN4SFFVRkxPMEZCUTB3c1lVRkJRU3hSUVVGQk96dFZRVU5GTEVWQlFVY3NRMEZCUVN4SFFVRkJMRU5CUVVnc1IwRkJWU3hKUVVGSkxFTkJRVU1zUzBGQlRDeERRVUZYTEV0QlFWZzdRVUZFV2p0QlFVVkJMR1ZCUVU4c1IwRk9WRHRQUVVSR096dFhRVkZCTzBWQlZFc3NRMEZCVUR0RlFWZEJMRkZCUVVFc1JVRkJWU3hUUVVGQk8wRkJRMUlzVVVGQlFUdEpRVUZCTEVOQlFVRXNSMEZCU1R0QlFVTktMRk5CUVVFc01rTkJRVUU3TzBGQlEwVXNWMEZCUVN4VFFVRkJPenRSUVVORkxFbEJRVThzWTBGQlVEdFZRVUZ2UWl4RFFVRkZMRU5CUVVFc1IwRkJRU3hEUVVGR0xFZEJRVk1zU1VGQlNTeERRVUZETEV0QlFVd3NRMEZCVnl4TFFVRllMRVZCUVRkQ096dEJRVVJHTzBGQlJFWTdWMEZKUVR0RlFVNVJMRU5CV0ZZN1JVRnRRa0VzVVVGQlFTeEZRVUZWTEZOQlFVTXNSMEZCUkR0QlFVTlNMRkZCUVVFN1NVRkJRU3hEUVVGQkxFZEJRVWtzTWtOQlFUSkRMRU5CUVVNc1NVRkJOVU1zUTBGQmFVUXNSMEZCYWtRN1NVRkRTaXhKUVVGSExGTkJRVWc3UVVGRFJTeGhRVUZQTEVOQlFVTXNRMEZCUlN4RFFVRkJMRU5CUVVFc1EwRkJTQ3hGUVVGUExFTkJRVVVzUTBGQlFTeERRVUZCTEVOQlFWUXNSVUZCWVN4RFFVRkZMRU5CUVVFc1EwRkJRU3hEUVVGbUxFTkJRV3RDTEVOQlFVTXNSMEZCYmtJc1EwRkJkVUlzVTBGQlF5eERRVUZFTzJWQlFVOHNVVUZCUVN4RFFVRlRMRU5CUVZRc1JVRkJXU3hGUVVGYU8wMUJRVkFzUTBGQmRrSXNSVUZFVkRzN1FVRkZRU3hYUVVGUE8wVkJTa01zUTBGdVFsWTdSVUY1UWtFc1VVRkJRU3hGUVVGVkxGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMWRCUTFJc1IwRkJRU3hIUVVGTkxFTkJRVU1zUTBGQlF5eERRVUZCTEVsQlFVc3NSVUZCVGl4RFFVRkJMRWRCUVZrc1EwRkJReXhEUVVGQkxFbEJRVXNzUlVGQlRpeERRVUZhTEVkQlFYZENMRU5CUVVNc1EwRkJRU3hKUVVGTExFTkJRVTRzUTBGQmVFSXNSMEZCYlVNc1EwRkJjRU1zUTBGQmMwTXNRMEZCUXl4UlFVRjJReXhEUVVGblJDeEZRVUZvUkN4RFFVRnRSQ3hEUVVGRExFdEJRWEJFTEVOQlFUQkVMRU5CUVRGRUxFVkJRVFpFTEVOQlFUZEVPMFZCUkVVc1EwRjZRbFk3UlVFMFFrRXNVVUZCUVN4RlFVRlZMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzBGQlExSXNVVUZCUVR0SlFVRkJMRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVTk1MRWRCUVVFc1IwRkJUU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVOQlFWUXNSVUZCV1N4RFFVRmFMRVZCUVdVc1EwRkJaanRKUVVOT0xFZEJRVUVzUjBGQlRTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRU5CUVZRc1JVRkJXU3hEUVVGYUxFVkJRV1VzUTBGQlpqdEpRVU5PTEVOQlFVRXNSMEZCU1R0SlFVTktMRU5CUVVFc1IwRkJTVHRKUVVOS0xFTkJRVUVzUjBGQlNTeERRVUZETEVkQlFVRXNSMEZCVFN4SFFVRlFMRU5CUVVFc1IwRkJZenRKUVVOc1FpeEpRVUZITEVkQlFVRXNTMEZCVHl4SFFVRldPMDFCUTBVc1EwRkJRU3hIUVVGSkxFTkJRVUVzUjBGQlNTeEZRVVJXTzB0QlFVRXNUVUZCUVR0TlFVbEZMRU5CUVVFc1IwRkJTU3hIUVVGQkxFZEJRVTA3VFVGRFZpeERRVUZCTEVkQlFVOHNRMEZCUVN4SFFVRkpMRWRCUVZBc1IwRkJaMElzUTBGQlFTeEhRVUZKTEVOQlFVTXNRMEZCUVN4SFFVRkpMRWRCUVVvc1IwRkJWU3hIUVVGWUxFTkJRWEJDTEVkQlFYbERMRU5CUVVFc1IwRkJTU3hEUVVGRExFZEJRVUVzUjBGQlRTeEhRVUZRTzBGQlEycEVMR05CUVU4c1IwRkJVRHRCUVVGQkxHRkJRMDhzUTBGRVVEdFZRVVZKTEVOQlFVRXNSMEZCU1N4RFFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGTUxFTkJRVUVzUjBGQlZTeERRVUZXTEVkQlFXTXNRMEZCU1N4RFFVRkJMRWRCUVVrc1EwRkJVQ3hIUVVGakxFTkJRV1FzUjBGQmNVSXNRMEZCZEVJN1FVRkVaanRCUVVSUUxHRkJSMDhzUTBGSVVEdFZRVWxKTEVOQlFVRXNSMEZCU1N4RFFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGTUxFTkJRVUVzUjBGQlZTeERRVUZXTEVkQlFXTTdRVUZFWmp0QlFVaFFMR0ZCUzA4c1EwRk1VRHRWUVUxSkxFTkJRVUVzUjBGQlNTeERRVUZETEVOQlFVRXNSMEZCU1N4RFFVRk1MRU5CUVVFc1IwRkJWU3hEUVVGV0xFZEJRV003UVVGT2RFSTdUVUZQUVN4RFFVRkJMRWxCUVVzc1JVRmlVRHM3VjBGalFTeERRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVRHRGUVhaQ1VTeERRVFZDVmp0RlFYRkVRU3hSUVVGQkxFVkJRVlVzVTBGQlF5eERRVUZFTEVWQlFVa3NRMEZCU2l4RlFVRlBMRU5CUVZBN1FVRkRVaXhSUVVGQk8wbEJRVUVzUTBGQlFTeEhRVUZKTzBsQlEwb3NRMEZCUVN4SFFVRkpPMGxCUTBvc1EwRkJRU3hIUVVGSk8wbEJSVW9zVDBGQlFTeEhRVUZWTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8wMUJRMUlzU1VGQlJ5eERRVUZCTEVkQlFVa3NRMEZCVUR0UlFVTkZMRU5CUVVFc1NVRkJTeXhGUVVSUU96dE5RVVZCTEVsQlFVY3NRMEZCUVN4SFFVRkpMRU5CUVZBN1VVRkRSU3hEUVVGQkxFbEJRVXNzUlVGRVVEczdUVUZGUVN4SlFVRkhMRU5CUVVFc1IwRkJTU3hEUVVGQkxFZEJRVWtzUTBGQldEdEJRVU5GTEdWQlFVOHNRMEZCUVN4SFFVRkpMRU5CUVVNc1EwRkJRU3hIUVVGSkxFTkJRVXdzUTBGQlFTeEhRVUZWTEVOQlFWWXNSMEZCWXl4RlFVUXpRanM3VFVGRlFTeEpRVUZITEVOQlFVRXNSMEZCU1N4RFFVRkJMRWRCUVVrc1EwRkJXRHRCUVVORkxHVkJRVThzUlVGRVZEczdUVUZGUVN4SlFVRkhMRU5CUVVFc1IwRkJTU3hEUVVGQkxFZEJRVWtzUTBGQldEdEJRVU5GTEdWQlFVOHNRMEZCUVN4SFFVRkpMRU5CUVVNc1EwRkJRU3hIUVVGSkxFTkJRVXdzUTBGQlFTeEhRVUZWTEVOQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVVvc1IwRkJVU3hEUVVGVUxFTkJRVllzUjBGQmQwSXNSVUZFY2tNN08yRkJSVUU3U1VGWVVUdEpRV0ZXTEVsQlFVY3NRMEZCUVN4TFFVRkxMRU5CUVZJN1RVRkRSU3hEUVVGQkxFZEJRVWtzUTBGQlFTeEhRVUZKTEVOQlFVRXNSMEZCU1N4RlFVUmtPMHRCUVVFc1RVRkJRVHROUVVsRkxFTkJRVUVzUjBGQlR5eERRVUZCTEVkQlFVa3NSMEZCVUN4SFFVRm5RaXhEUVVGQkxFZEJRVWtzUTBGQlF5eERRVUZCTEVkQlFVa3NRMEZCVEN4RFFVRndRaXhIUVVGcFF5eERRVUZCTEVkQlFVa3NRMEZCU2l4SFFVRlJMRU5CUVVNc1EwRkJRU3hIUVVGSkxFTkJRVXc3VFVGRE4wTXNRMEZCUVN4SFFVRkpMRU5CUVVFc1IwRkJTU3hEUVVGS0xFZEJRVkU3VFVGRFdpeERRVUZCTEVkQlFVa3NUMEZCUVN4RFFVRlJMRU5CUVZJc1JVRkJWeXhEUVVGWUxFVkJRV01zUTBGQlFTeEhRVUZKTEVOQlFVRXNSMEZCU1N4RFFVRjBRanROUVVOS0xFTkJRVUVzUjBGQlNTeFBRVUZCTEVOQlFWRXNRMEZCVWl4RlFVRlhMRU5CUVZnc1JVRkJZeXhEUVVGa08wMUJRMG9zUTBGQlFTeEhRVUZKTEU5QlFVRXNRMEZCVVN4RFFVRlNMRVZCUVZjc1EwRkJXQ3hGUVVGakxFTkJRVUVzUjBGQlNTeERRVUZETEVOQlFVRXNSMEZCU1N4RFFVRk1MRU5CUVd4Q0xFVkJVazQ3TzFkQlUwRXNRMEZEUlN4RFFVRkJMRWRCUVVrc1IwRkVUaXhGUVVWRkxFTkJRVUVzUjBGQlNTeEhRVVpPTEVWQlIwVXNRMEZCUVN4SFFVRkpMRWRCU0U0N1JVRXpRbEVzUTBGeVJGWTdSVUZ6UmtFc1VVRkJRU3hGUVVGVkxGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMEZCUTFJc1VVRkJRVHRKUVVGQkxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzUjBGQlR5eERRVUZCTEVkQlFVa3NUMEZCVUN4SFFVRnZRaXhKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVOQlFVTXNRMEZCUVN4SFFVRkpMRXRCUVV3c1EwRkJRU3hIUVVGakxFdEJRWFpDTEVWQlFUaENMRWRCUVRsQ0xFTkJRWEJDTEVkQlFUUkVMRU5CUVVFc1IwRkJTVHRKUVVOd1JTeERRVUZCTEVkQlFVOHNRMEZCUVN4SFFVRkpMRTlCUVZBc1IwRkJiMElzU1VGQlNTeERRVUZETEVkQlFVd3NRMEZCVXl4RFFVRkRMRU5CUVVFc1IwRkJTU3hMUVVGTUxFTkJRVUVzUjBGQll5eExRVUYyUWl4RlFVRTRRaXhIUVVFNVFpeERRVUZ3UWl4SFFVRTBSQ3hEUVVGQkxFZEJRVWs3U1VGRGNFVXNRMEZCUVN4SFFVRlBMRU5CUVVFc1IwRkJTU3hQUVVGUUxFZEJRVzlDTEVsQlFVa3NRMEZCUXl4SFFVRk1MRU5CUVZNc1EwRkJReXhEUVVGQkxFZEJRVWtzUzBGQlRDeERRVUZCTEVkQlFXTXNTMEZCZGtJc1JVRkJPRUlzUjBGQk9VSXNRMEZCY0VJc1IwRkJORVFzUTBGQlFTeEhRVUZKTzBsQlJYQkZMRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVVk1MRU5CUVVFc1IwRkJTU3hEUVVGQkxFZEJRVWtzVFVGQlNpeEhRVUZoTEVOQlFVRXNSMEZCU1N4TlFVRnFRaXhIUVVFd1FpeERRVUZCTEVkQlFVazdTVUZEYkVNc1EwRkJRU3hIUVVGSkxFTkJRVUVzUjBGQlNTeE5RVUZLTEVkQlFXRXNRMEZCUVN4SFFVRkpMRTFCUVdwQ0xFZEJRVEJDTEVOQlFVRXNSMEZCU1R0SlFVTnNReXhEUVVGQkxFZEJRVWtzUTBGQlFTeEhRVUZKTEUxQlFVb3NSMEZCWVN4RFFVRkJMRWRCUVVrc1RVRkJha0lzUjBGQk1FSXNRMEZCUVN4SFFVRkpPMWRCUld4RExFTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMFZCYUVKUkxFTkJkRVpXTzBWQmQwZEJMRmRCUVVFc1JVRkJZU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUR0QlFVTllMRkZCUVVFN1NVRkJRU3hMUVVGQkxFZEJRVkU3U1VGRFVpeExRVUZCTEVkQlFWRTdTVUZEVWl4TFFVRkJMRWRCUVZFN1NVRkZVaXhEUVVGQkxFbEJRVXM3U1VGRFRDeERRVUZCTEVsQlFVczdTVUZEVEN4RFFVRkJMRWxCUVVzN1NVRkZUQ3hEUVVGQkxFZEJRVThzUTBGQlFTeEhRVUZKTEZGQlFWQXNSMEZCY1VJc1NVRkJTU3hEUVVGRExFZEJRVXdzUTBGQlV5eERRVUZVTEVWQlFWa3NRMEZCUVN4SFFVRkZMRU5CUVdRc1EwRkJja0lzUjBGQk1rTXNTMEZCUVN4SFFVRlJMRU5CUVZJc1IwRkJXU3hGUVVGQkxFZEJRVXM3U1VGRGFFVXNRMEZCUVN4SFFVRlBMRU5CUVVFc1IwRkJTU3hSUVVGUUxFZEJRWEZDTEVsQlFVa3NRMEZCUXl4SFFVRk1MRU5CUVZNc1EwRkJWQ3hGUVVGWkxFTkJRVUVzUjBGQlJTeERRVUZrTEVOQlFYSkNMRWRCUVRKRExFdEJRVUVzUjBGQlVTeERRVUZTTEVkQlFWa3NSVUZCUVN4SFFVRkxPMGxCUTJoRkxFTkJRVUVzUjBGQlR5eERRVUZCTEVkQlFVa3NVVUZCVUN4SFFVRnhRaXhKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVOQlFWUXNSVUZCV1N4RFFVRkJMRWRCUVVVc1EwRkJaQ3hEUVVGeVFpeEhRVUV5UXl4TFFVRkJMRWRCUVZFc1EwRkJVaXhIUVVGWkxFVkJRVUVzUjBGQlN6dEpRVVZvUlN4RFFVRkJMRWRCUVVrc1IwRkJRU3hIUVVGTkxFTkJRVTRzUjBGQlZUdEpRVU5rTEVOQlFVRXNSMEZCU1N4SFFVRkJMRWRCUVUwc1EwRkJReXhEUVVGQkxFZEJRVWtzUTBGQlREdEpRVU5XTEVOQlFVRXNSMEZCU1N4SFFVRkJMRWRCUVUwc1EwRkJReXhEUVVGQkxFZEJRVWtzUTBGQlREdFhRVVZXTEVOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8wVkJha0pYTEVOQmVFZGlPMFZCTWtoQkxGZEJRVUVzUlVGQllTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVRHRCUVVOWUxGRkJRVUU3U1VGQlFTeE5RVUZaTEVsQlFVa3NRMEZCUXl4UlFVRk1MRU5CUVdNc1EwRkJaQ3hGUVVGcFFpeERRVUZxUWl4RlFVRnZRaXhEUVVGd1FpeERRVUZhTEVWQlFVTXNWVUZCUkN4RlFVRkpMRlZCUVVvc1JVRkJUenRYUVVOUUxFbEJRVWtzUTBGQlF5eFhRVUZNTEVOQlFXbENMRU5CUVdwQ0xFVkJRVzlDTEVOQlFYQkNMRVZCUVhWQ0xFTkJRWFpDTzBWQlJsY3NRMEV6U0dJN1JVRXJTRUVzVVVGQlFTeEZRVUZWTEZOQlFVTXNTVUZCUkN4RlFVRlBMRWxCUVZBN1FVRkZVaXhSUVVGQk8wbEJRVUVzVVVGQlFTeEhRVUZYTzBsQlExZ3NVVUZCUVN4SFFVRlhPMGxCUTFnc1VVRkJRU3hIUVVGWE8wbEJSVllzV1VGQlJDeEZRVUZMTEZsQlFVd3NSVUZCVXp0SlFVTlNMRmxCUVVRc1JVRkJTeXhaUVVGTUxFVkJRVk03U1VGRFZDeEZRVUZCTEVkQlFVc3NSVUZCUVN4SFFVRkxPMGxCUTFZc1JVRkJRU3hIUVVGTExFVkJRVUVzUjBGQlN6dEpRVU5XTEVWQlFVRXNSMEZCU3l4RlFVRkJMRWRCUVVzN1NVRkZWaXhIUVVGQkxFZEJRVTBzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4RlFVRkJMRWRCUVVzc1JVRkJUQ3hIUVVGVkxFVkJRVUVzUjBGQlN5eEZRVUY2UWp0SlFVTk9MRWRCUVVFc1IwRkJUU3hKUVVGSkxFTkJRVU1zU1VGQlRDeERRVUZWTEVWQlFVRXNSMEZCU3l4RlFVRk1MRWRCUVZVc1JVRkJRU3hIUVVGTExFVkJRWHBDTzBsQlJVNHNSMEZCUVN4SFFVRk5MRVZCUVVFc1IwRkJTenRKUVVOWUxFZEJRVUVzUjBGQlRTeEhRVUZCTEVkQlFVMDdTVUZEV2l4SFFVRkJMRWRCUVUwc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEZRVUZCTEVkQlFVc3NSVUZCVEN4SFFVRlZMRVZCUVVFc1IwRkJTeXhGUVVGbUxFZEJRVzlDTEVWQlFVRXNSMEZCU3l4RlFVRnVRenRKUVVWT0xFbEJRVWNzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4SFFVRldMRU5CUVVFc1IwRkJhVUlzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFZEJRVlFzUTBGQlZpeERRVUZCTEVkQlFUSkNMRWxCUVVrc1EwRkJReXhKUVVGTUxFTkJRVlVzU1VGQlNTeERRVUZETEVkQlFVd3NRMEZCVXl4SFFVRlVMRU5CUVZZc1EwRkJMME03VFVGRFJTeEhRVUZCTEVkQlFVMHNTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hIUVVGQkxFZEJRVTBzUjBGQlRpeEhRVUZaTEVkQlFVRXNSMEZCVFN4SFFVRnNRaXhIUVVGM1FpeEhRVUZCTEVkQlFVMHNSMEZCZUVNc1JVRkVVanRMUVVGQkxFMUJRVUU3VFVGSFJTeEhRVUZCTEVkQlFVMHNSVUZJVWpzN1NVRkxRU3hIUVVGQkxFZEJRVTBzUTBGQlFTeEhRVUZKTEV0QlFVRXNSMEZCVVR0SlFVTnNRaXhIUVVGQkxFZEJRVTBzUTBGQlFTeEhRVUZKTEV0QlFVRXNSMEZCVVR0SlFVVnNRaXhIUVVGQkxFbEJRVTg3U1VGRFVDeEhRVUZCTEVsQlFVOHNVVUZCUVN4SFFVRlhPMGxCUTJ4Q0xFZEJRVUVzU1VGQlR5eFJRVUZCTEVkQlFWYzdWMEZGYkVJc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEhRVUZCTEVkQlFVMHNSMEZCVGl4SFFVRlpMRWRCUVVFc1IwRkJUU3hIUVVGc1FpeEhRVUYzUWl4SFFVRkJMRWRCUVUwc1IwRkJlRU03UlVFdlFsRXNRMEV2U0ZZN1JVRm5TMEVzVDBGQlFTeEZRVUZUTEZOQlFVTXNTVUZCUkN4RlFVRlBMRWxCUVZBN1FVRkRVQ3hSUVVGQk8wbEJRVUVzU1VGQlFTeEhRVUZQTEVsQlFVTXNRMEZCUVN4WFFVRlhMRU5CUVVNc1MwRkJZaXhEUVVGdFFpeEpRVUZ1UWl4RlFVRnpRaXhKUVVGMFFqdEpRVU5RTEVsQlFVRXNSMEZCVHl4SlFVRkRMRU5CUVVFc1YwRkJWeXhEUVVGRExFdEJRV0lzUTBGQmJVSXNTVUZCYmtJc1JVRkJjMElzU1VGQmRFSTdWMEZEVUN4SlFVRkRMRU5CUVVFc1VVRkJSQ3hEUVVGVkxFbEJRVllzUlVGQlowSXNTVUZCYUVJN1JVRklUeXhEUVdoTFZEdEZRWEZMUVN4UFFVRkJMRVZCUVZNc1UwRkJReXhKUVVGRUxFVkJRVThzU1VGQlVEdEJRVVZRTEZGQlFVRTdTVUZCUVN4SlFVRkJMRWRCUVU4c1NVRkJReXhEUVVGQkxGRkJRVVFzUTBGQlZTeEpRVUZXTzBsQlExQXNTVUZCUVN4SFFVRlBMRWxCUVVNc1EwRkJRU3hSUVVGRUxFTkJRVlVzU1VGQlZqdFhRVWRRTEVsQlFVTXNRMEZCUVN4UFFVRkVMRU5CUVZNc1NVRkJWQ3hGUVVGbExFbEJRV1k3UlVGT1R5eERRWEpMVkR0RlFUWkxRU3h2UWtGQlFTeEZRVUZ6UWl4UlFUZExkRUk3UlVFclMwRXNhMEpCUVVFc1JVRkJiMElzVTBGQlF5eERRVUZFTzBsQlEyeENMRWxCUVVjc1EwRkJRU3hIUVVGSkxGRkJRVkVzUTBGQlF5eEZRVUZvUWp0QlFVTkZMR0ZCUVU4c1RVRkVWRHM3U1VGSFFTeEpRVUZITEVOQlFVRXNTVUZCU3l4UlFVRlJMRU5CUVVNc1QwRkJha0k3UVVGRFJTeGhRVUZQTEZWQlJGUTdPMGxCUjBFc1NVRkJSeXhEUVVGQkxFbEJRVXNzVVVGQlVTeERRVUZETEV0QlFXcENPMEZCUTBVc1lVRkJUeXhSUVVSVU96dEpRVWRCTEVsQlFVY3NRMEZCUVN4SlFVRkxMRkZCUVZFc1EwRkJReXhKUVVGcVFqdEJRVU5GTEdGQlFVOHNUMEZFVkRzN1NVRkhRU3hKUVVGSExFTkJRVUVzUjBGQlNTeFJRVUZSTEVOQlFVTXNUMEZCYUVJN1FVRkRSU3hoUVVGUExGVkJSRlE3TzBGQlJVRXNWMEZCVHp0RlFXWlhMRU5CTDB0d1FqdEZRV2ROUVN4UFFVRkJMRVZCUVZNc1QwRm9UVlE3UlVGcFRVRXNUVUZCUVN4RlFVRlJMRTFCYWsxU08wVkJhMDFCTEdGQlFVRXNSVUZCWlN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVEdFhRVU5pTEVOQlFVTXNRMEZCUVN4SlFVRkhMRU5CUVVNc1EwRkJRU3hIUVVGRkxFOUJRVWdzUTBGQlNpeERRVUZCTEVkQlFXMUNMRU5CUVVNc1EwRkJRU3hKUVVGTExFOUJRVTRzUTBGQmJrSXNSMEZCYjBNN1JVRkVka0lzUTBGc1RXWWlmUT09XG4iLCJcbi8qXG4gIEZyb20gVmlicmFudC5qcyBieSBKYXJpIFp3YXJ0c1xuICBQb3J0ZWQgdG8gbm9kZS5qcyBieSBBS0Zpc2hcblxuICBDb2xvciBhbGdvcml0aG0gY2xhc3MgdGhhdCBmaW5kcyB2YXJpYXRpb25zIG9uIGNvbG9ycyBpbiBhbiBpbWFnZS5cblxuICBDcmVkaXRzXG4gIC0tLS0tLS0tXG4gIExva2VzaCBEaGFrYXIgKGh0dHA6Ly93d3cubG9rZXNoZGhha2FyLmNvbSkgLSBDcmVhdGVkIENvbG9yVGhpZWZcbiAgR29vZ2xlIC0gUGFsZXR0ZSBzdXBwb3J0IGxpYnJhcnkgaW4gQW5kcm9pZFxuICovXG52YXIgQnVpbGRlciwgRGVmYXVsdEdlbmVyYXRvciwgRmlsdGVyLCBTd2F0Y2gsIFZpYnJhbnQsIHV0aWwsXG4gIGJpbmQgPSBmdW5jdGlvbihmbiwgbWUpeyByZXR1cm4gZnVuY3Rpb24oKXsgcmV0dXJuIGZuLmFwcGx5KG1lLCBhcmd1bWVudHMpOyB9OyB9O1xuXG5Td2F0Y2ggPSByZXF1aXJlKCcuL3N3YXRjaCcpO1xuXG51dGlsID0gcmVxdWlyZSgnLi91dGlsJyk7XG5cbkRlZmF1bHRHZW5lcmF0b3IgPSByZXF1aXJlKCcuL2dlbmVyYXRvcicpLkRlZmF1bHQ7XG5cbkZpbHRlciA9IHJlcXVpcmUoJy4vZmlsdGVyJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gVmlicmFudCA9IChmdW5jdGlvbigpIHtcbiAgVmlicmFudC5EZWZhdWx0T3B0cyA9IHtcbiAgICBjb2xvckNvdW50OiAxNixcbiAgICBxdWFsaXR5OiA1LFxuICAgIGdlbmVyYXRvcjogbmV3IERlZmF1bHRHZW5lcmF0b3IoKSxcbiAgICBJbWFnZTogbnVsbCxcbiAgICBRdWFudGl6ZXI6IHJlcXVpcmUoJy4vcXVhbnRpemVyJykuTU1DUSxcbiAgICBmaWx0ZXJzOiBbXVxuICB9O1xuXG4gIFZpYnJhbnQuZnJvbSA9IGZ1bmN0aW9uKHNyYykge1xuICAgIHJldHVybiBuZXcgQnVpbGRlcihzcmMpO1xuICB9O1xuXG4gIFZpYnJhbnQucHJvdG90eXBlLnF1YW50aXplID0gcmVxdWlyZSgncXVhbnRpemUnKTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5fc3dhdGNoZXMgPSBbXTtcblxuICBmdW5jdGlvbiBWaWJyYW50KHNvdXJjZUltYWdlLCBvcHRzKSB7XG4gICAgdGhpcy5zb3VyY2VJbWFnZSA9IHNvdXJjZUltYWdlO1xuICAgIGlmIChvcHRzID09IG51bGwpIHtcbiAgICAgIG9wdHMgPSB7fTtcbiAgICB9XG4gICAgdGhpcy5zd2F0Y2hlcyA9IGJpbmQodGhpcy5zd2F0Y2hlcywgdGhpcyk7XG4gICAgdGhpcy5vcHRzID0gdXRpbC5kZWZhdWx0cyhvcHRzLCB0aGlzLmNvbnN0cnVjdG9yLkRlZmF1bHRPcHRzKTtcbiAgICB0aGlzLmdlbmVyYXRvciA9IHRoaXMub3B0cy5nZW5lcmF0b3I7XG4gIH1cblxuICBWaWJyYW50LnByb3RvdHlwZS5nZXRQYWxldHRlID0gZnVuY3Rpb24oY2IpIHtcbiAgICB2YXIgaW1hZ2U7XG4gICAgcmV0dXJuIGltYWdlID0gbmV3IHRoaXMub3B0cy5JbWFnZSh0aGlzLnNvdXJjZUltYWdlLCAoZnVuY3Rpb24oX3RoaXMpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihlcnIsIGltYWdlKSB7XG4gICAgICAgIHZhciBlcnJvcjtcbiAgICAgICAgaWYgKGVyciAhPSBudWxsKSB7XG4gICAgICAgICAgcmV0dXJuIGNiKGVycik7XG4gICAgICAgIH1cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBfdGhpcy5fcHJvY2VzcyhpbWFnZSwgX3RoaXMub3B0cyk7XG4gICAgICAgICAgcmV0dXJuIGNiKG51bGwsIF90aGlzLnN3YXRjaGVzKCkpO1xuICAgICAgICB9IGNhdGNoIChlcnJvcjEpIHtcbiAgICAgICAgICBlcnJvciA9IGVycm9yMTtcbiAgICAgICAgICByZXR1cm4gY2IoZXJyb3IpO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH0pKHRoaXMpKTtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5nZXRTd2F0Y2hlcyA9IGZ1bmN0aW9uKGNiKSB7XG4gICAgcmV0dXJuIHRoaXMuZ2V0UGFsZXR0ZShjYik7XG4gIH07XG5cbiAgVmlicmFudC5wcm90b3R5cGUuX3Byb2Nlc3MgPSBmdW5jdGlvbihpbWFnZSwgb3B0cykge1xuICAgIHZhciBpbWFnZURhdGEsIHF1YW50aXplcjtcbiAgICBpbWFnZS5zY2FsZURvd24odGhpcy5vcHRzKTtcbiAgICBpbWFnZURhdGEgPSBpbWFnZS5nZXRJbWFnZURhdGEoKTtcbiAgICBxdWFudGl6ZXIgPSBuZXcgdGhpcy5vcHRzLlF1YW50aXplcigpO1xuICAgIHF1YW50aXplci5pbml0aWFsaXplKGltYWdlRGF0YS5kYXRhLCB0aGlzLm9wdHMpO1xuICAgIHRoaXMuYWxsX3N3YXRjaGVzID0gcXVhbnRpemVyLmdldFF1YW50aXplZENvbG9ycygpO1xuICAgIHJldHVybiBpbWFnZS5yZW1vdmVDYW52YXMoKTtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5zd2F0Y2hlcyA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmFsbF9zd2F0Y2hlcztcbiAgfTtcblxuICByZXR1cm4gVmlicmFudDtcblxufSkoKTtcblxubW9kdWxlLmV4cG9ydHMuQnVpbGRlciA9IEJ1aWxkZXIgPSAoZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIEJ1aWxkZXIoc3JjMSwgb3B0czEpIHtcbiAgICB0aGlzLnNyYyA9IHNyYzE7XG4gICAgdGhpcy5vcHRzID0gb3B0czEgIT0gbnVsbCA/IG9wdHMxIDoge307XG4gICAgdGhpcy5vcHRzLmZpbHRlcnMgPSB1dGlsLmNsb25lKFZpYnJhbnQuRGVmYXVsdE9wdHMuZmlsdGVycyk7XG4gIH1cblxuICBCdWlsZGVyLnByb3RvdHlwZS5tYXhDb2xvckNvdW50ID0gZnVuY3Rpb24obikge1xuICAgIHRoaXMub3B0cy5jb2xvckNvdW50ID0gbjtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5tYXhEaW1lbnNpb24gPSBmdW5jdGlvbihkKSB7XG4gICAgdGhpcy5vcHRzLm1heERpbWVuc2lvbiA9IGQ7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuYWRkRmlsdGVyID0gZnVuY3Rpb24oZikge1xuICAgIGlmICh0eXBlb2YgZiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgdGhpcy5vcHRzLmZpbHRlcnMucHVzaChmKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUucmVtb3ZlRmlsdGVyID0gZnVuY3Rpb24oZikge1xuICAgIHZhciBpO1xuICAgIGlmICgoaSA9IHRoaXMub3B0cy5maWx0ZXJzLmluZGV4T2YoZikpID4gMCkge1xuICAgICAgdGhpcy5vcHRzLmZpbHRlcnMuc3BsaWNlKGkpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5jbGVhckZpbHRlcnMgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLm9wdHMuZmlsdGVycyA9IFtdO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLnF1YWxpdHkgPSBmdW5jdGlvbihxKSB7XG4gICAgdGhpcy5vcHRzLnF1YWxpdHkgPSBxO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLnVzZUltYWdlID0gZnVuY3Rpb24oaW1hZ2UpIHtcbiAgICB0aGlzLm9wdHMuSW1hZ2UgPSBpbWFnZTtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS51c2VHZW5lcmF0b3IgPSBmdW5jdGlvbihnZW5lcmF0b3IpIHtcbiAgICB0aGlzLm9wdHMuZ2VuZXJhdG9yID0gZ2VuZXJhdG9yO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLnVzZVF1YW50aXplciA9IGZ1bmN0aW9uKHF1YW50aXplcikge1xuICAgIHRoaXMub3B0cy5RdWFudGl6ZXIgPSBxdWFudGl6ZXI7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuYnVpbGQgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAodGhpcy52ID09IG51bGwpIHtcbiAgICAgIHRoaXMudiA9IG5ldyBWaWJyYW50KHRoaXMuc3JjLCB0aGlzLm9wdHMpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy52O1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmdldFN3YXRjaGVzID0gZnVuY3Rpb24oY2IpIHtcbiAgICByZXR1cm4gdGhpcy5idWlsZCgpLmdldFBhbGV0dGUoY2IpO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmdldFBhbGV0dGUgPSBmdW5jdGlvbihjYikge1xuICAgIHJldHVybiB0aGlzLmJ1aWxkKCkuZ2V0UGFsZXR0ZShjYik7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuZnJvbSA9IGZ1bmN0aW9uKHNyYykge1xuICAgIHJldHVybiBuZXcgVmlicmFudChzcmMsIHRoaXMub3B0cyk7XG4gIH07XG5cbiAgcmV0dXJuIEJ1aWxkZXI7XG5cbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzLlV0aWwgPSB1dGlsO1xuXG5tb2R1bGUuZXhwb3J0cy5Td2F0Y2ggPSBTd2F0Y2g7XG5cbm1vZHVsZS5leHBvcnRzLlF1YW50aXplciA9IHJlcXVpcmUoJy4vcXVhbnRpemVyLycpO1xuXG5tb2R1bGUuZXhwb3J0cy5HZW5lcmF0b3IgPSByZXF1aXJlKCcuL2dlbmVyYXRvci8nKTtcblxubW9kdWxlLmV4cG9ydHMuRmlsdGVyID0gcmVxdWlyZSgnLi9maWx0ZXIvJyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZkbWxpY21GdWRDNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTkyYVdKeVlXNTBMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaU8wRkJRVUU3T3pzN096czdPenM3TzBGQlFVRXNTVUZCUVN4M1JFRkJRVHRGUVVGQk96dEJRVmRCTEUxQlFVRXNSMEZCVXl4UFFVRkJMRU5CUVZFc1ZVRkJVanM3UVVGRFZDeEpRVUZCTEVkQlFVOHNUMEZCUVN4RFFVRlJMRkZCUVZJN08wRkJRMUFzWjBKQlFVRXNSMEZCYlVJc1QwRkJRU3hEUVVGUkxHRkJRVklzUTBGQmMwSXNRMEZCUXpzN1FVRkRNVU1zVFVGQlFTeEhRVUZUTEU5QlFVRXNRMEZCVVN4VlFVRlNPenRCUVVWVUxFMUJRVTBzUTBGQlF5eFBRVUZRTEVkQlEwMDdSVUZEU2l4UFFVRkRMRU5CUVVFc1YwRkJSQ3hIUVVORk8wbEJRVUVzVlVGQlFTeEZRVUZaTEVWQlFWbzdTVUZEUVN4UFFVRkJMRVZCUVZNc1EwRkVWRHRKUVVWQkxGTkJRVUVzUlVGQlZ5eEpRVUZKTEdkQ1FVRktMRU5CUVVFc1EwRkdXRHRKUVVkQkxFdEJRVUVzUlVGQlR5eEpRVWhRTzBsQlNVRXNVMEZCUVN4RlFVRlhMRTlCUVVFc1EwRkJVU3hoUVVGU0xFTkJRWE5DTEVOQlFVTXNTVUZLYkVNN1NVRkxRU3hQUVVGQkxFVkJRVk1zUlVGTVZEczdPMFZCVDBZc1QwRkJReXhEUVVGQkxFbEJRVVFzUjBGQlR5eFRRVUZETEVkQlFVUTdWMEZEVEN4SlFVRkpMRTlCUVVvc1EwRkJXU3hIUVVGYU8wVkJSRXM3TzI5Q1FVZFFMRkZCUVVFc1IwRkJWU3hQUVVGQkxFTkJRVkVzVlVGQlVqczdiMEpCUlZZc1UwRkJRU3hIUVVGWE96dEZRVVZGTEdsQ1FVRkRMRmRCUVVRc1JVRkJaU3hKUVVGbU8wbEJRVU1zU1VGQlF5eERRVUZCTEdOQlFVUTdPMDFCUVdNc1QwRkJUenM3TzBsQlEycERMRWxCUVVNc1EwRkJRU3hKUVVGRUxFZEJRVkVzU1VGQlNTeERRVUZETEZGQlFVd3NRMEZCWXl4SlFVRmtMRVZCUVc5Q0xFbEJRVU1zUTBGQlFTeFhRVUZYTEVOQlFVTXNWMEZCYWtNN1NVRkRVaXhKUVVGRExFTkJRVUVzVTBGQlJDeEhRVUZoTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNN1JVRkdVanM3YjBKQlNXSXNWVUZCUVN4SFFVRlpMRk5CUVVNc1JVRkJSRHRCUVVOV0xGRkJRVUU3VjBGQlFTeExRVUZCTEVkQlFWRXNTVUZCU1N4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExFdEJRVllzUTBGQlowSXNTVUZCUXl4RFFVRkJMRmRCUVdwQ0xFVkJRVGhDTEVOQlFVRXNVMEZCUVN4TFFVRkJPMkZCUVVFc1UwRkJReXhIUVVGRUxFVkJRVTBzUzBGQlRqdEJRVU53UXl4WlFVRkJPMUZCUVVFc1NVRkJSeXhYUVVGSU8wRkJRV0VzYVVKQlFVOHNSVUZCUVN4RFFVRkhMRWRCUVVnc1JVRkJjRUk3TzBGQlEwRTdWVUZEUlN4TFFVRkRMRU5CUVVFc1VVRkJSQ3hEUVVGVkxFdEJRVllzUlVGQmFVSXNTMEZCUXl4RFFVRkJMRWxCUVd4Q08ybENRVU5CTEVWQlFVRXNRMEZCUnl4SlFVRklMRVZCUVZNc1MwRkJReXhEUVVGQkxGRkJRVVFzUTBGQlFTeERRVUZVTEVWQlJrWTdVMEZCUVN4alFVRkJPMVZCUjAwN1FVRkRTaXhwUWtGQlR5eEZRVUZCTEVOQlFVY3NTMEZCU0N4RlFVcFVPenROUVVadlF6dEpRVUZCTEVOQlFVRXNRMEZCUVN4RFFVRkJMRWxCUVVFc1EwRkJPVUk3UlVGRVJUczdiMEpCVTFvc1YwRkJRU3hIUVVGaExGTkJRVU1zUlVGQlJEdFhRVU5ZTEVsQlFVTXNRMEZCUVN4VlFVRkVMRU5CUVZrc1JVRkJXanRGUVVSWE96dHZRa0ZIWWl4UlFVRkJMRWRCUVZVc1UwRkJReXhMUVVGRUxFVkJRVkVzU1VGQlVqdEJRVU5TTEZGQlFVRTdTVUZCUVN4TFFVRkxMRU5CUVVNc1UwRkJUaXhEUVVGblFpeEpRVUZETEVOQlFVRXNTVUZCYWtJN1NVRkRRU3hUUVVGQkxFZEJRVmtzUzBGQlN5eERRVUZETEZsQlFVNHNRMEZCUVR0SlFVVmFMRk5CUVVFc1IwRkJXU3hKUVVGSkxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNVMEZCVml4RFFVRkJPMGxCUTFvc1UwRkJVeXhEUVVGRExGVkJRVllzUTBGQmNVSXNVMEZCVXl4RFFVRkRMRWxCUVM5Q0xFVkJRWEZETEVsQlFVTXNRMEZCUVN4SlFVRjBRenRKUVVWQkxFbEJRVU1zUTBGQlFTeFpRVUZFTEVkQlFXZENMRk5CUVZNc1EwRkJReXhyUWtGQlZpeERRVUZCTzFkQlNXaENMRXRCUVVzc1EwRkJReXhaUVVGT0xFTkJRVUU3UlVGWVVUczdiMEpCWVZZc1VVRkJRU3hIUVVGVkxGTkJRVUU3VjBGRFVpeEpRVUZETEVOQlFVRTdSVUZFVHpzN096czdPMEZCUjFvc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eFBRVUZtTEVkQlEwMDdSVUZEVXl4cFFrRkJReXhKUVVGRUxFVkJRVThzUzBGQlVEdEpRVUZETEVsQlFVTXNRMEZCUVN4TlFVRkVPMGxCUVUwc1NVRkJReXhEUVVGQkxIVkNRVUZFTEZGQlFWRTdTVUZETVVJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eFBRVUZPTEVkQlFXZENMRWxCUVVrc1EwRkJReXhMUVVGTUxFTkJRVmNzVDBGQlR5eERRVUZETEZkQlFWY3NRMEZCUXl4UFFVRXZRanRGUVVSTU96dHZRa0ZIWWl4aFFVRkJMRWRCUVdVc1UwRkJReXhEUVVGRU8wbEJRMklzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4VlFVRk9MRWRCUVcxQ08xZEJRMjVDTzBWQlJtRTdPMjlDUVVsbUxGbEJRVUVzUjBGQll5eFRRVUZETEVOQlFVUTdTVUZEV2l4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGbEJRVTRzUjBGQmNVSTdWMEZEY2tJN1JVRkdXVHM3YjBKQlNXUXNVMEZCUVN4SFFVRlhMRk5CUVVNc1EwRkJSRHRKUVVOVUxFbEJRVWNzVDBGQlR5eERRVUZRTEV0QlFWa3NWVUZCWmp0TlFVTkZMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zVDBGQlR5eERRVUZETEVsQlFXUXNRMEZCYlVJc1EwRkJia0lzUlVGRVJqczdWMEZGUVR0RlFVaFRPenR2UWtGTFdDeFpRVUZCTEVkQlFXTXNVMEZCUXl4RFFVRkVPMEZCUTFvc1VVRkJRVHRKUVVGQkxFbEJRVWNzUTBGQlF5eERRVUZCTEVkQlFVa3NTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhQUVVGUExFTkJRVU1zVDBGQlpDeERRVUZ6UWl4RFFVRjBRaXhEUVVGTUxFTkJRVUVzUjBGQmFVTXNRMEZCY0VNN1RVRkRSU3hKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEU5QlFVOHNRMEZCUXl4TlFVRmtMRU5CUVhGQ0xFTkJRWEpDTEVWQlJFWTdPMWRCUlVFN1JVRklXVHM3YjBKQlMyUXNXVUZCUVN4SFFVRmpMRk5CUVVFN1NVRkRXaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEU5QlFVNHNSMEZCWjBJN1YwRkRhRUk3UlVGR1dUczdiMEpCU1dRc1QwRkJRU3hIUVVGVExGTkJRVU1zUTBGQlJEdEpRVU5RTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1QwRkJUaXhIUVVGblFqdFhRVU5vUWp0RlFVWlBPenR2UWtGSlZDeFJRVUZCTEVkQlFWVXNVMEZCUXl4TFFVRkVPMGxCUTFJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eExRVUZPTEVkQlFXTTdWMEZEWkR0RlFVWlJPenR2UWtGSlZpeFpRVUZCTEVkQlFXTXNVMEZCUXl4VFFVRkVPMGxCUTFvc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eFRRVUZPTEVkQlFXdENPMWRCUTJ4Q08wVkJSbGs3TzI5Q1FVbGtMRmxCUVVFc1IwRkJZeXhUUVVGRExGTkJRVVE3U1VGRFdpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRk5CUVU0c1IwRkJhMEk3VjBGRGJFSTdSVUZHV1RzN2IwSkJTV1FzUzBGQlFTeEhRVUZQTEZOQlFVRTdTVUZEVEN4SlFVRlBMR05CUVZBN1RVRkRSU3hKUVVGRExFTkJRVUVzUTBGQlJDeEhRVUZMTEVsQlFVa3NUMEZCU2l4RFFVRlpMRWxCUVVNc1EwRkJRU3hIUVVGaUxFVkJRV3RDTEVsQlFVTXNRMEZCUVN4SlFVRnVRaXhGUVVSUU96dFhRVVZCTEVsQlFVTXNRMEZCUVR0RlFVaEpPenR2UWtGTFVDeFhRVUZCTEVkQlFXRXNVMEZCUXl4RlFVRkVPMWRCUTFnc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeERRVUZSTEVOQlFVTXNWVUZCVkN4RFFVRnZRaXhGUVVGd1FqdEZRVVJYT3p0dlFrRkhZaXhWUVVGQkxFZEJRVmtzVTBGQlF5eEZRVUZFTzFkQlExWXNTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hEUVVGUkxFTkJRVU1zVlVGQlZDeERRVUZ2UWl4RlFVRndRanRGUVVSVk96dHZRa0ZIV2l4SlFVRkJMRWRCUVUwc1UwRkJReXhIUVVGRU8xZEJRMG9zU1VGQlNTeFBRVUZLTEVOQlFWa3NSMEZCV2l4RlFVRnBRaXhKUVVGRExFTkJRVUVzU1VGQmJFSTdSVUZFU1RzN096czdPMEZCUjFJc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eEpRVUZtTEVkQlFYTkNPenRCUVVOMFFpeE5RVUZOTEVOQlFVTXNUMEZCVHl4RFFVRkRMRTFCUVdZc1IwRkJkMEk3TzBGQlEzaENMRTFCUVUwc1EwRkJReXhQUVVGUExFTkJRVU1zVTBGQlppeEhRVUV5UWl4UFFVRkJMRU5CUVZFc1kwRkJVanM3UVVGRE0wSXNUVUZCVFN4RFFVRkRMRTlCUVU4c1EwRkJReXhUUVVGbUxFZEJRVEpDTEU5QlFVRXNRMEZCVVN4alFVRlNPenRCUVVNelFpeE5RVUZOTEVOQlFVTXNUMEZCVHl4RFFVRkRMRTFCUVdZc1IwRkJkMElzVDBGQlFTeERRVUZSTEZkQlFWSWlmUT09XG4iXX0=
