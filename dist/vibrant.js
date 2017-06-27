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
    filters: [],
    minPopulation: 35,
    minRgbDiff: 15
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
    this.allSwatches = quantizer.getQuantizedColors();
    return image.removeCanvas();
  };

  Vibrant.prototype.swatches = function() {
    var comparingPopulation, finalSwatches, final_swatch, j, k, len, len1, ref, should_be_added, swatch;
    finalSwatches = [];
    this.allSwatches = this.allSwatches.sort(function(a, b) {
      return b.getPopulation() - a.getPopulation();
    });
    comparingPopulation = this.getComparingPopulation(this.allSwatches);
    ref = this.allSwatches;
    for (j = 0, len = ref.length; j < len; j++) {
      swatch = ref[j];
      if (this.populationPercentage(swatch.getPopulation(), comparingPopulation) > this.opts.minPopulation) {
        should_be_added = true;
        for (k = 0, len1 = finalSwatches.length; k < len1; k++) {
          final_swatch = finalSwatches[k];
          if (Vibrant.Util.rgbDiff(final_swatch.rgb, swatch.rgb) < this.opts.minRgbDiff) {
            should_be_added = false;
            break;
          }
        }
        if (should_be_added) {
          finalSwatches.push(swatch);
        }
      }
    }
    return finalSwatches;
  };

  Vibrant.prototype.populationPercentage = function(population, comparingPopulation) {
    return (population / comparingPopulation) * 100;
  };

  Vibrant.prototype.getComparingPopulation = function(swatches) {
    return swatches[1].getPopulation();
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

  Builder.prototype.minPopulation = function(q) {
    this.opts.minPopulation = q;
    return this;
  };

  Builder.prototype.minRgbDiff = function(q) {
    this.opts.minRgbDiff = q;
    return this;
  };

  Builder.prototype.useImage = function(image) {
    this.opts.Image = image;
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
//# sourceMappingURL=data:application/json;charset:utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvdXJsL3VybC5qcyIsIm5vZGVfbW9kdWxlcy9wdW55Y29kZS9wdW55Y29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWFudGl6ZS9xdWFudGl6ZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvZGVjb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9lbmNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2luZGV4LmpzIiwic3JjL2Jyb3dzZXIuY29mZmVlIiwic3JjL2J1bmRsZS5jb2ZmZWUiLCJzcmMvZmlsdGVyL2RlZmF1bHQuY29mZmVlIiwic3JjL2ZpbHRlci9pbmRleC5jb2ZmZWUiLCJzcmMvZ2VuZXJhdG9yL2RlZmF1bHQuY29mZmVlIiwic3JjL2dlbmVyYXRvci9pbmRleC5jb2ZmZWUiLCJzcmMvaW1hZ2UvYnJvd3Nlci5jb2ZmZWUiLCJzcmMvaW1hZ2UvaW5kZXguY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL21tY3EuY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL3BxdWV1ZS5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2ltcGwvdmJveC5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2luZGV4LmNvZmZlZSIsInNyYy9xdWFudGl6ZXIvbW1jcS5jb2ZmZWUiLCJzcmMvc3dhdGNoLmNvZmZlZSIsInNyYy91dGlsLmNvZmZlZSIsInNyYy92aWJyYW50LmNvZmZlZSJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDbnNCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7QUNyaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMWVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3BGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDbktBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzFCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDdkdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzVDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUMvRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3BEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3pQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDakNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDM0VBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDcE9BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uIGUodCxuLHIpe2Z1bmN0aW9uIHMobyx1KXtpZighbltvXSl7aWYoIXRbb10pe3ZhciBhPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7aWYoIXUmJmEpcmV0dXJuIGEobywhMCk7aWYoaSlyZXR1cm4gaShvLCEwKTt2YXIgZj1uZXcgRXJyb3IoXCJDYW5ub3QgZmluZCBtb2R1bGUgJ1wiK28rXCInXCIpO3Rocm93IGYuY29kZT1cIk1PRFVMRV9OT1RfRk9VTkRcIixmfXZhciBsPW5bb109e2V4cG9ydHM6e319O3Rbb11bMF0uY2FsbChsLmV4cG9ydHMsZnVuY3Rpb24oZSl7dmFyIG49dFtvXVsxXVtlXTtyZXR1cm4gcyhuP246ZSl9LGwsbC5leHBvcnRzLGUsdCxuLHIpfXJldHVybiBuW29dLmV4cG9ydHN9dmFyIGk9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtmb3IodmFyIG89MDtvPHIubGVuZ3RoO28rKylzKHJbb10pO3JldHVybiBzfSkiLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxudmFyIHB1bnljb2RlID0gcmVxdWlyZSgncHVueWNvZGUnKTtcblxuZXhwb3J0cy5wYXJzZSA9IHVybFBhcnNlO1xuZXhwb3J0cy5yZXNvbHZlID0gdXJsUmVzb2x2ZTtcbmV4cG9ydHMucmVzb2x2ZU9iamVjdCA9IHVybFJlc29sdmVPYmplY3Q7XG5leHBvcnRzLmZvcm1hdCA9IHVybEZvcm1hdDtcblxuZXhwb3J0cy5VcmwgPSBVcmw7XG5cbmZ1bmN0aW9uIFVybCgpIHtcbiAgdGhpcy5wcm90b2NvbCA9IG51bGw7XG4gIHRoaXMuc2xhc2hlcyA9IG51bGw7XG4gIHRoaXMuYXV0aCA9IG51bGw7XG4gIHRoaXMuaG9zdCA9IG51bGw7XG4gIHRoaXMucG9ydCA9IG51bGw7XG4gIHRoaXMuaG9zdG5hbWUgPSBudWxsO1xuICB0aGlzLmhhc2ggPSBudWxsO1xuICB0aGlzLnNlYXJjaCA9IG51bGw7XG4gIHRoaXMucXVlcnkgPSBudWxsO1xuICB0aGlzLnBhdGhuYW1lID0gbnVsbDtcbiAgdGhpcy5wYXRoID0gbnVsbDtcbiAgdGhpcy5ocmVmID0gbnVsbDtcbn1cblxuLy8gUmVmZXJlbmNlOiBSRkMgMzk4NiwgUkZDIDE4MDgsIFJGQyAyMzk2XG5cbi8vIGRlZmluZSB0aGVzZSBoZXJlIHNvIGF0IGxlYXN0IHRoZXkgb25seSBoYXZlIHRvIGJlXG4vLyBjb21waWxlZCBvbmNlIG9uIHRoZSBmaXJzdCBtb2R1bGUgbG9hZC5cbnZhciBwcm90b2NvbFBhdHRlcm4gPSAvXihbYS16MC05ListXSs6KS9pLFxuICAgIHBvcnRQYXR0ZXJuID0gLzpbMC05XSokLyxcblxuICAgIC8vIFJGQyAyMzk2OiBjaGFyYWN0ZXJzIHJlc2VydmVkIGZvciBkZWxpbWl0aW5nIFVSTHMuXG4gICAgLy8gV2UgYWN0dWFsbHkganVzdCBhdXRvLWVzY2FwZSB0aGVzZS5cbiAgICBkZWxpbXMgPSBbJzwnLCAnPicsICdcIicsICdgJywgJyAnLCAnXFxyJywgJ1xcbicsICdcXHQnXSxcblxuICAgIC8vIFJGQyAyMzk2OiBjaGFyYWN0ZXJzIG5vdCBhbGxvd2VkIGZvciB2YXJpb3VzIHJlYXNvbnMuXG4gICAgdW53aXNlID0gWyd7JywgJ30nLCAnfCcsICdcXFxcJywgJ14nLCAnYCddLmNvbmNhdChkZWxpbXMpLFxuXG4gICAgLy8gQWxsb3dlZCBieSBSRkNzLCBidXQgY2F1c2Ugb2YgWFNTIGF0dGFja3MuICBBbHdheXMgZXNjYXBlIHRoZXNlLlxuICAgIGF1dG9Fc2NhcGUgPSBbJ1xcJyddLmNvbmNhdCh1bndpc2UpLFxuICAgIC8vIENoYXJhY3RlcnMgdGhhdCBhcmUgbmV2ZXIgZXZlciBhbGxvd2VkIGluIGEgaG9zdG5hbWUuXG4gICAgLy8gTm90ZSB0aGF0IGFueSBpbnZhbGlkIGNoYXJzIGFyZSBhbHNvIGhhbmRsZWQsIGJ1dCB0aGVzZVxuICAgIC8vIGFyZSB0aGUgb25lcyB0aGF0IGFyZSAqZXhwZWN0ZWQqIHRvIGJlIHNlZW4sIHNvIHdlIGZhc3QtcGF0aFxuICAgIC8vIHRoZW0uXG4gICAgbm9uSG9zdENoYXJzID0gWyclJywgJy8nLCAnPycsICc7JywgJyMnXS5jb25jYXQoYXV0b0VzY2FwZSksXG4gICAgaG9zdEVuZGluZ0NoYXJzID0gWycvJywgJz8nLCAnIyddLFxuICAgIGhvc3RuYW1lTWF4TGVuID0gMjU1LFxuICAgIGhvc3RuYW1lUGFydFBhdHRlcm4gPSAvXlthLXowLTlBLVpfLV17MCw2M30kLyxcbiAgICBob3N0bmFtZVBhcnRTdGFydCA9IC9eKFthLXowLTlBLVpfLV17MCw2M30pKC4qKSQvLFxuICAgIC8vIHByb3RvY29scyB0aGF0IGNhbiBhbGxvdyBcInVuc2FmZVwiIGFuZCBcInVud2lzZVwiIGNoYXJzLlxuICAgIHVuc2FmZVByb3RvY29sID0ge1xuICAgICAgJ2phdmFzY3JpcHQnOiB0cnVlLFxuICAgICAgJ2phdmFzY3JpcHQ6JzogdHJ1ZVxuICAgIH0sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgbmV2ZXIgaGF2ZSBhIGhvc3RuYW1lLlxuICAgIGhvc3RsZXNzUHJvdG9jb2wgPSB7XG4gICAgICAnamF2YXNjcmlwdCc6IHRydWUsXG4gICAgICAnamF2YXNjcmlwdDonOiB0cnVlXG4gICAgfSxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBhbHdheXMgY29udGFpbiBhIC8vIGJpdC5cbiAgICBzbGFzaGVkUHJvdG9jb2wgPSB7XG4gICAgICAnaHR0cCc6IHRydWUsXG4gICAgICAnaHR0cHMnOiB0cnVlLFxuICAgICAgJ2Z0cCc6IHRydWUsXG4gICAgICAnZ29waGVyJzogdHJ1ZSxcbiAgICAgICdmaWxlJzogdHJ1ZSxcbiAgICAgICdodHRwOic6IHRydWUsXG4gICAgICAnaHR0cHM6JzogdHJ1ZSxcbiAgICAgICdmdHA6JzogdHJ1ZSxcbiAgICAgICdnb3BoZXI6JzogdHJ1ZSxcbiAgICAgICdmaWxlOic6IHRydWVcbiAgICB9LFxuICAgIHF1ZXJ5c3RyaW5nID0gcmVxdWlyZSgncXVlcnlzdHJpbmcnKTtcblxuZnVuY3Rpb24gdXJsUGFyc2UodXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCkge1xuICBpZiAodXJsICYmIGlzT2JqZWN0KHVybCkgJiYgdXJsIGluc3RhbmNlb2YgVXJsKSByZXR1cm4gdXJsO1xuXG4gIHZhciB1ID0gbmV3IFVybDtcbiAgdS5wYXJzZSh1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KTtcbiAgcmV0dXJuIHU7XG59XG5cblVybC5wcm90b3R5cGUucGFyc2UgPSBmdW5jdGlvbih1cmwsIHBhcnNlUXVlcnlTdHJpbmcsIHNsYXNoZXNEZW5vdGVIb3N0KSB7XG4gIGlmICghaXNTdHJpbmcodXJsKSkge1xuICAgIHRocm93IG5ldyBUeXBlRXJyb3IoXCJQYXJhbWV0ZXIgJ3VybCcgbXVzdCBiZSBhIHN0cmluZywgbm90IFwiICsgdHlwZW9mIHVybCk7XG4gIH1cblxuICB2YXIgcmVzdCA9IHVybDtcblxuICAvLyB0cmltIGJlZm9yZSBwcm9jZWVkaW5nLlxuICAvLyBUaGlzIGlzIHRvIHN1cHBvcnQgcGFyc2Ugc3R1ZmYgbGlrZSBcIiAgaHR0cDovL2Zvby5jb20gIFxcblwiXG4gIHJlc3QgPSByZXN0LnRyaW0oKTtcblxuICB2YXIgcHJvdG8gPSBwcm90b2NvbFBhdHRlcm4uZXhlYyhyZXN0KTtcbiAgaWYgKHByb3RvKSB7XG4gICAgcHJvdG8gPSBwcm90b1swXTtcbiAgICB2YXIgbG93ZXJQcm90byA9IHByb3RvLnRvTG93ZXJDYXNlKCk7XG4gICAgdGhpcy5wcm90b2NvbCA9IGxvd2VyUHJvdG87XG4gICAgcmVzdCA9IHJlc3Quc3Vic3RyKHByb3RvLmxlbmd0aCk7XG4gIH1cblxuICAvLyBmaWd1cmUgb3V0IGlmIGl0J3MgZ290IGEgaG9zdFxuICAvLyB1c2VyQHNlcnZlciBpcyAqYWx3YXlzKiBpbnRlcnByZXRlZCBhcyBhIGhvc3RuYW1lLCBhbmQgdXJsXG4gIC8vIHJlc29sdXRpb24gd2lsbCB0cmVhdCAvL2Zvby9iYXIgYXMgaG9zdD1mb28scGF0aD1iYXIgYmVjYXVzZSB0aGF0J3NcbiAgLy8gaG93IHRoZSBicm93c2VyIHJlc29sdmVzIHJlbGF0aXZlIFVSTHMuXG4gIGlmIChzbGFzaGVzRGVub3RlSG9zdCB8fCBwcm90byB8fCByZXN0Lm1hdGNoKC9eXFwvXFwvW15AXFwvXStAW15AXFwvXSsvKSkge1xuICAgIHZhciBzbGFzaGVzID0gcmVzdC5zdWJzdHIoMCwgMikgPT09ICcvLyc7XG4gICAgaWYgKHNsYXNoZXMgJiYgIShwcm90byAmJiBob3N0bGVzc1Byb3RvY29sW3Byb3RvXSkpIHtcbiAgICAgIHJlc3QgPSByZXN0LnN1YnN0cigyKTtcbiAgICAgIHRoaXMuc2xhc2hlcyA9IHRydWU7XG4gICAgfVxuICB9XG5cbiAgaWYgKCFob3N0bGVzc1Byb3RvY29sW3Byb3RvXSAmJlxuICAgICAgKHNsYXNoZXMgfHwgKHByb3RvICYmICFzbGFzaGVkUHJvdG9jb2xbcHJvdG9dKSkpIHtcblxuICAgIC8vIHRoZXJlJ3MgYSBob3N0bmFtZS5cbiAgICAvLyB0aGUgZmlyc3QgaW5zdGFuY2Ugb2YgLywgPywgOywgb3IgIyBlbmRzIHRoZSBob3N0LlxuICAgIC8vXG4gICAgLy8gSWYgdGhlcmUgaXMgYW4gQCBpbiB0aGUgaG9zdG5hbWUsIHRoZW4gbm9uLWhvc3QgY2hhcnMgKmFyZSogYWxsb3dlZFxuICAgIC8vIHRvIHRoZSBsZWZ0IG9mIHRoZSBsYXN0IEAgc2lnbiwgdW5sZXNzIHNvbWUgaG9zdC1lbmRpbmcgY2hhcmFjdGVyXG4gICAgLy8gY29tZXMgKmJlZm9yZSogdGhlIEAtc2lnbi5cbiAgICAvLyBVUkxzIGFyZSBvYm5veGlvdXMuXG4gICAgLy9cbiAgICAvLyBleDpcbiAgICAvLyBodHRwOi8vYUBiQGMvID0+IHVzZXI6YUBiIGhvc3Q6Y1xuICAgIC8vIGh0dHA6Ly9hQGI/QGMgPT4gdXNlcjphIGhvc3Q6YyBwYXRoOi8/QGNcblxuICAgIC8vIHYwLjEyIFRPRE8oaXNhYWNzKTogVGhpcyBpcyBub3QgcXVpdGUgaG93IENocm9tZSBkb2VzIHRoaW5ncy5cbiAgICAvLyBSZXZpZXcgb3VyIHRlc3QgY2FzZSBhZ2FpbnN0IGJyb3dzZXJzIG1vcmUgY29tcHJlaGVuc2l2ZWx5LlxuXG4gICAgLy8gZmluZCB0aGUgZmlyc3QgaW5zdGFuY2Ugb2YgYW55IGhvc3RFbmRpbmdDaGFyc1xuICAgIHZhciBob3N0RW5kID0gLTE7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBob3N0RW5kaW5nQ2hhcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoZWMgPSByZXN0LmluZGV4T2YoaG9zdEVuZGluZ0NoYXJzW2ldKTtcbiAgICAgIGlmIChoZWMgIT09IC0xICYmIChob3N0RW5kID09PSAtMSB8fCBoZWMgPCBob3N0RW5kKSlcbiAgICAgICAgaG9zdEVuZCA9IGhlYztcbiAgICB9XG5cbiAgICAvLyBhdCB0aGlzIHBvaW50LCBlaXRoZXIgd2UgaGF2ZSBhbiBleHBsaWNpdCBwb2ludCB3aGVyZSB0aGVcbiAgICAvLyBhdXRoIHBvcnRpb24gY2Fubm90IGdvIHBhc3QsIG9yIHRoZSBsYXN0IEAgY2hhciBpcyB0aGUgZGVjaWRlci5cbiAgICB2YXIgYXV0aCwgYXRTaWduO1xuICAgIGlmIChob3N0RW5kID09PSAtMSkge1xuICAgICAgLy8gYXRTaWduIGNhbiBiZSBhbnl3aGVyZS5cbiAgICAgIGF0U2lnbiA9IHJlc3QubGFzdEluZGV4T2YoJ0AnKTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gYXRTaWduIG11c3QgYmUgaW4gYXV0aCBwb3J0aW9uLlxuICAgICAgLy8gaHR0cDovL2FAYi9jQGQgPT4gaG9zdDpiIGF1dGg6YSBwYXRoOi9jQGRcbiAgICAgIGF0U2lnbiA9IHJlc3QubGFzdEluZGV4T2YoJ0AnLCBob3N0RW5kKTtcbiAgICB9XG5cbiAgICAvLyBOb3cgd2UgaGF2ZSBhIHBvcnRpb24gd2hpY2ggaXMgZGVmaW5pdGVseSB0aGUgYXV0aC5cbiAgICAvLyBQdWxsIHRoYXQgb2ZmLlxuICAgIGlmIChhdFNpZ24gIT09IC0xKSB7XG4gICAgICBhdXRoID0gcmVzdC5zbGljZSgwLCBhdFNpZ24pO1xuICAgICAgcmVzdCA9IHJlc3Quc2xpY2UoYXRTaWduICsgMSk7XG4gICAgICB0aGlzLmF1dGggPSBkZWNvZGVVUklDb21wb25lbnQoYXV0aCk7XG4gICAgfVxuXG4gICAgLy8gdGhlIGhvc3QgaXMgdGhlIHJlbWFpbmluZyB0byB0aGUgbGVmdCBvZiB0aGUgZmlyc3Qgbm9uLWhvc3QgY2hhclxuICAgIGhvc3RFbmQgPSAtMTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IG5vbkhvc3RDaGFycy5sZW5ndGg7IGkrKykge1xuICAgICAgdmFyIGhlYyA9IHJlc3QuaW5kZXhPZihub25Ib3N0Q2hhcnNbaV0pO1xuICAgICAgaWYgKGhlYyAhPT0gLTEgJiYgKGhvc3RFbmQgPT09IC0xIHx8IGhlYyA8IGhvc3RFbmQpKVxuICAgICAgICBob3N0RW5kID0gaGVjO1xuICAgIH1cbiAgICAvLyBpZiB3ZSBzdGlsbCBoYXZlIG5vdCBoaXQgaXQsIHRoZW4gdGhlIGVudGlyZSB0aGluZyBpcyBhIGhvc3QuXG4gICAgaWYgKGhvc3RFbmQgPT09IC0xKVxuICAgICAgaG9zdEVuZCA9IHJlc3QubGVuZ3RoO1xuXG4gICAgdGhpcy5ob3N0ID0gcmVzdC5zbGljZSgwLCBob3N0RW5kKTtcbiAgICByZXN0ID0gcmVzdC5zbGljZShob3N0RW5kKTtcblxuICAgIC8vIHB1bGwgb3V0IHBvcnQuXG4gICAgdGhpcy5wYXJzZUhvc3QoKTtcblxuICAgIC8vIHdlJ3ZlIGluZGljYXRlZCB0aGF0IHRoZXJlIGlzIGEgaG9zdG5hbWUsXG4gICAgLy8gc28gZXZlbiBpZiBpdCdzIGVtcHR5LCBpdCBoYXMgdG8gYmUgcHJlc2VudC5cbiAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZSB8fCAnJztcblxuICAgIC8vIGlmIGhvc3RuYW1lIGJlZ2lucyB3aXRoIFsgYW5kIGVuZHMgd2l0aCBdXG4gICAgLy8gYXNzdW1lIHRoYXQgaXQncyBhbiBJUHY2IGFkZHJlc3MuXG4gICAgdmFyIGlwdjZIb3N0bmFtZSA9IHRoaXMuaG9zdG5hbWVbMF0gPT09ICdbJyAmJlxuICAgICAgICB0aGlzLmhvc3RuYW1lW3RoaXMuaG9zdG5hbWUubGVuZ3RoIC0gMV0gPT09ICddJztcblxuICAgIC8vIHZhbGlkYXRlIGEgbGl0dGxlLlxuICAgIGlmICghaXB2Nkhvc3RuYW1lKSB7XG4gICAgICB2YXIgaG9zdHBhcnRzID0gdGhpcy5ob3N0bmFtZS5zcGxpdCgvXFwuLyk7XG4gICAgICBmb3IgKHZhciBpID0gMCwgbCA9IGhvc3RwYXJ0cy5sZW5ndGg7IGkgPCBsOyBpKyspIHtcbiAgICAgICAgdmFyIHBhcnQgPSBob3N0cGFydHNbaV07XG4gICAgICAgIGlmICghcGFydCkgY29udGludWU7XG4gICAgICAgIGlmICghcGFydC5tYXRjaChob3N0bmFtZVBhcnRQYXR0ZXJuKSkge1xuICAgICAgICAgIHZhciBuZXdwYXJ0ID0gJyc7XG4gICAgICAgICAgZm9yICh2YXIgaiA9IDAsIGsgPSBwYXJ0Lmxlbmd0aDsgaiA8IGs7IGorKykge1xuICAgICAgICAgICAgaWYgKHBhcnQuY2hhckNvZGVBdChqKSA+IDEyNykge1xuICAgICAgICAgICAgICAvLyB3ZSByZXBsYWNlIG5vbi1BU0NJSSBjaGFyIHdpdGggYSB0ZW1wb3JhcnkgcGxhY2Vob2xkZXJcbiAgICAgICAgICAgICAgLy8gd2UgbmVlZCB0aGlzIHRvIG1ha2Ugc3VyZSBzaXplIG9mIGhvc3RuYW1lIGlzIG5vdFxuICAgICAgICAgICAgICAvLyBicm9rZW4gYnkgcmVwbGFjaW5nIG5vbi1BU0NJSSBieSBub3RoaW5nXG4gICAgICAgICAgICAgIG5ld3BhcnQgKz0gJ3gnO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgbmV3cGFydCArPSBwYXJ0W2pdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICAvLyB3ZSB0ZXN0IGFnYWluIHdpdGggQVNDSUkgY2hhciBvbmx5XG4gICAgICAgICAgaWYgKCFuZXdwYXJ0Lm1hdGNoKGhvc3RuYW1lUGFydFBhdHRlcm4pKSB7XG4gICAgICAgICAgICB2YXIgdmFsaWRQYXJ0cyA9IGhvc3RwYXJ0cy5zbGljZSgwLCBpKTtcbiAgICAgICAgICAgIHZhciBub3RIb3N0ID0gaG9zdHBhcnRzLnNsaWNlKGkgKyAxKTtcbiAgICAgICAgICAgIHZhciBiaXQgPSBwYXJ0Lm1hdGNoKGhvc3RuYW1lUGFydFN0YXJ0KTtcbiAgICAgICAgICAgIGlmIChiaXQpIHtcbiAgICAgICAgICAgICAgdmFsaWRQYXJ0cy5wdXNoKGJpdFsxXSk7XG4gICAgICAgICAgICAgIG5vdEhvc3QudW5zaGlmdChiaXRbMl0pO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgaWYgKG5vdEhvc3QubGVuZ3RoKSB7XG4gICAgICAgICAgICAgIHJlc3QgPSAnLycgKyBub3RIb3N0LmpvaW4oJy4nKSArIHJlc3Q7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0aGlzLmhvc3RuYW1lID0gdmFsaWRQYXJ0cy5qb2luKCcuJyk7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAodGhpcy5ob3N0bmFtZS5sZW5ndGggPiBob3N0bmFtZU1heExlbikge1xuICAgICAgdGhpcy5ob3N0bmFtZSA9ICcnO1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBob3N0bmFtZXMgYXJlIGFsd2F5cyBsb3dlciBjYXNlLlxuICAgICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUudG9Mb3dlckNhc2UoKTtcbiAgICB9XG5cbiAgICBpZiAoIWlwdjZIb3N0bmFtZSkge1xuICAgICAgLy8gSUROQSBTdXBwb3J0OiBSZXR1cm5zIGEgcHVueSBjb2RlZCByZXByZXNlbnRhdGlvbiBvZiBcImRvbWFpblwiLlxuICAgICAgLy8gSXQgb25seSBjb252ZXJ0cyB0aGUgcGFydCBvZiB0aGUgZG9tYWluIG5hbWUgdGhhdFxuICAgICAgLy8gaGFzIG5vbiBBU0NJSSBjaGFyYWN0ZXJzLiBJLmUuIGl0IGRvc2VudCBtYXR0ZXIgaWZcbiAgICAgIC8vIHlvdSBjYWxsIGl0IHdpdGggYSBkb21haW4gdGhhdCBhbHJlYWR5IGlzIGluIEFTQ0lJLlxuICAgICAgdmFyIGRvbWFpbkFycmF5ID0gdGhpcy5ob3N0bmFtZS5zcGxpdCgnLicpO1xuICAgICAgdmFyIG5ld091dCA9IFtdO1xuICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBkb21haW5BcnJheS5sZW5ndGg7ICsraSkge1xuICAgICAgICB2YXIgcyA9IGRvbWFpbkFycmF5W2ldO1xuICAgICAgICBuZXdPdXQucHVzaChzLm1hdGNoKC9bXkEtWmEtejAtOV8tXS8pID9cbiAgICAgICAgICAgICd4bi0tJyArIHB1bnljb2RlLmVuY29kZShzKSA6IHMpO1xuICAgICAgfVxuICAgICAgdGhpcy5ob3N0bmFtZSA9IG5ld091dC5qb2luKCcuJyk7XG4gICAgfVxuXG4gICAgdmFyIHAgPSB0aGlzLnBvcnQgPyAnOicgKyB0aGlzLnBvcnQgOiAnJztcbiAgICB2YXIgaCA9IHRoaXMuaG9zdG5hbWUgfHwgJyc7XG4gICAgdGhpcy5ob3N0ID0gaCArIHA7XG4gICAgdGhpcy5ocmVmICs9IHRoaXMuaG9zdDtcblxuICAgIC8vIHN0cmlwIFsgYW5kIF0gZnJvbSB0aGUgaG9zdG5hbWVcbiAgICAvLyB0aGUgaG9zdCBmaWVsZCBzdGlsbCByZXRhaW5zIHRoZW0sIHRob3VnaFxuICAgIGlmIChpcHY2SG9zdG5hbWUpIHtcbiAgICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lLnN1YnN0cigxLCB0aGlzLmhvc3RuYW1lLmxlbmd0aCAtIDIpO1xuICAgICAgaWYgKHJlc3RbMF0gIT09ICcvJykge1xuICAgICAgICByZXN0ID0gJy8nICsgcmVzdDtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBub3cgcmVzdCBpcyBzZXQgdG8gdGhlIHBvc3QtaG9zdCBzdHVmZi5cbiAgLy8gY2hvcCBvZmYgYW55IGRlbGltIGNoYXJzLlxuICBpZiAoIXVuc2FmZVByb3RvY29sW2xvd2VyUHJvdG9dKSB7XG5cbiAgICAvLyBGaXJzdCwgbWFrZSAxMDAlIHN1cmUgdGhhdCBhbnkgXCJhdXRvRXNjYXBlXCIgY2hhcnMgZ2V0XG4gICAgLy8gZXNjYXBlZCwgZXZlbiBpZiBlbmNvZGVVUklDb21wb25lbnQgZG9lc24ndCB0aGluayB0aGV5XG4gICAgLy8gbmVlZCB0byBiZS5cbiAgICBmb3IgKHZhciBpID0gMCwgbCA9IGF1dG9Fc2NhcGUubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgICB2YXIgYWUgPSBhdXRvRXNjYXBlW2ldO1xuICAgICAgdmFyIGVzYyA9IGVuY29kZVVSSUNvbXBvbmVudChhZSk7XG4gICAgICBpZiAoZXNjID09PSBhZSkge1xuICAgICAgICBlc2MgPSBlc2NhcGUoYWUpO1xuICAgICAgfVxuICAgICAgcmVzdCA9IHJlc3Quc3BsaXQoYWUpLmpvaW4oZXNjKTtcbiAgICB9XG4gIH1cblxuXG4gIC8vIGNob3Agb2ZmIGZyb20gdGhlIHRhaWwgZmlyc3QuXG4gIHZhciBoYXNoID0gcmVzdC5pbmRleE9mKCcjJyk7XG4gIGlmIChoYXNoICE9PSAtMSkge1xuICAgIC8vIGdvdCBhIGZyYWdtZW50IHN0cmluZy5cbiAgICB0aGlzLmhhc2ggPSByZXN0LnN1YnN0cihoYXNoKTtcbiAgICByZXN0ID0gcmVzdC5zbGljZSgwLCBoYXNoKTtcbiAgfVxuICB2YXIgcW0gPSByZXN0LmluZGV4T2YoJz8nKTtcbiAgaWYgKHFtICE9PSAtMSkge1xuICAgIHRoaXMuc2VhcmNoID0gcmVzdC5zdWJzdHIocW0pO1xuICAgIHRoaXMucXVlcnkgPSByZXN0LnN1YnN0cihxbSArIDEpO1xuICAgIGlmIChwYXJzZVF1ZXJ5U3RyaW5nKSB7XG4gICAgICB0aGlzLnF1ZXJ5ID0gcXVlcnlzdHJpbmcucGFyc2UodGhpcy5xdWVyeSk7XG4gICAgfVxuICAgIHJlc3QgPSByZXN0LnNsaWNlKDAsIHFtKTtcbiAgfSBlbHNlIGlmIChwYXJzZVF1ZXJ5U3RyaW5nKSB7XG4gICAgLy8gbm8gcXVlcnkgc3RyaW5nLCBidXQgcGFyc2VRdWVyeVN0cmluZyBzdGlsbCByZXF1ZXN0ZWRcbiAgICB0aGlzLnNlYXJjaCA9ICcnO1xuICAgIHRoaXMucXVlcnkgPSB7fTtcbiAgfVxuICBpZiAocmVzdCkgdGhpcy5wYXRobmFtZSA9IHJlc3Q7XG4gIGlmIChzbGFzaGVkUHJvdG9jb2xbbG93ZXJQcm90b10gJiZcbiAgICAgIHRoaXMuaG9zdG5hbWUgJiYgIXRoaXMucGF0aG5hbWUpIHtcbiAgICB0aGlzLnBhdGhuYW1lID0gJy8nO1xuICB9XG5cbiAgLy90byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICBpZiAodGhpcy5wYXRobmFtZSB8fCB0aGlzLnNlYXJjaCkge1xuICAgIHZhciBwID0gdGhpcy5wYXRobmFtZSB8fCAnJztcbiAgICB2YXIgcyA9IHRoaXMuc2VhcmNoIHx8ICcnO1xuICAgIHRoaXMucGF0aCA9IHAgKyBzO1xuICB9XG5cbiAgLy8gZmluYWxseSwgcmVjb25zdHJ1Y3QgdGhlIGhyZWYgYmFzZWQgb24gd2hhdCBoYXMgYmVlbiB2YWxpZGF0ZWQuXG4gIHRoaXMuaHJlZiA9IHRoaXMuZm9ybWF0KCk7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLy8gZm9ybWF0IGEgcGFyc2VkIG9iamVjdCBpbnRvIGEgdXJsIHN0cmluZ1xuZnVuY3Rpb24gdXJsRm9ybWF0KG9iaikge1xuICAvLyBlbnN1cmUgaXQncyBhbiBvYmplY3QsIGFuZCBub3QgYSBzdHJpbmcgdXJsLlxuICAvLyBJZiBpdCdzIGFuIG9iaiwgdGhpcyBpcyBhIG5vLW9wLlxuICAvLyB0aGlzIHdheSwgeW91IGNhbiBjYWxsIHVybF9mb3JtYXQoKSBvbiBzdHJpbmdzXG4gIC8vIHRvIGNsZWFuIHVwIHBvdGVudGlhbGx5IHdvbmt5IHVybHMuXG4gIGlmIChpc1N0cmluZyhvYmopKSBvYmogPSB1cmxQYXJzZShvYmopO1xuICBpZiAoIShvYmogaW5zdGFuY2VvZiBVcmwpKSByZXR1cm4gVXJsLnByb3RvdHlwZS5mb3JtYXQuY2FsbChvYmopO1xuICByZXR1cm4gb2JqLmZvcm1hdCgpO1xufVxuXG5VcmwucHJvdG90eXBlLmZvcm1hdCA9IGZ1bmN0aW9uKCkge1xuICB2YXIgYXV0aCA9IHRoaXMuYXV0aCB8fCAnJztcbiAgaWYgKGF1dGgpIHtcbiAgICBhdXRoID0gZW5jb2RlVVJJQ29tcG9uZW50KGF1dGgpO1xuICAgIGF1dGggPSBhdXRoLnJlcGxhY2UoLyUzQS9pLCAnOicpO1xuICAgIGF1dGggKz0gJ0AnO1xuICB9XG5cbiAgdmFyIHByb3RvY29sID0gdGhpcy5wcm90b2NvbCB8fCAnJyxcbiAgICAgIHBhdGhuYW1lID0gdGhpcy5wYXRobmFtZSB8fCAnJyxcbiAgICAgIGhhc2ggPSB0aGlzLmhhc2ggfHwgJycsXG4gICAgICBob3N0ID0gZmFsc2UsXG4gICAgICBxdWVyeSA9ICcnO1xuXG4gIGlmICh0aGlzLmhvc3QpIHtcbiAgICBob3N0ID0gYXV0aCArIHRoaXMuaG9zdDtcbiAgfSBlbHNlIGlmICh0aGlzLmhvc3RuYW1lKSB7XG4gICAgaG9zdCA9IGF1dGggKyAodGhpcy5ob3N0bmFtZS5pbmRleE9mKCc6JykgPT09IC0xID9cbiAgICAgICAgdGhpcy5ob3N0bmFtZSA6XG4gICAgICAgICdbJyArIHRoaXMuaG9zdG5hbWUgKyAnXScpO1xuICAgIGlmICh0aGlzLnBvcnQpIHtcbiAgICAgIGhvc3QgKz0gJzonICsgdGhpcy5wb3J0O1xuICAgIH1cbiAgfVxuXG4gIGlmICh0aGlzLnF1ZXJ5ICYmXG4gICAgICBpc09iamVjdCh0aGlzLnF1ZXJ5KSAmJlxuICAgICAgT2JqZWN0LmtleXModGhpcy5xdWVyeSkubGVuZ3RoKSB7XG4gICAgcXVlcnkgPSBxdWVyeXN0cmluZy5zdHJpbmdpZnkodGhpcy5xdWVyeSk7XG4gIH1cblxuICB2YXIgc2VhcmNoID0gdGhpcy5zZWFyY2ggfHwgKHF1ZXJ5ICYmICgnPycgKyBxdWVyeSkpIHx8ICcnO1xuXG4gIGlmIChwcm90b2NvbCAmJiBwcm90b2NvbC5zdWJzdHIoLTEpICE9PSAnOicpIHByb3RvY29sICs9ICc6JztcblxuICAvLyBvbmx5IHRoZSBzbGFzaGVkUHJvdG9jb2xzIGdldCB0aGUgLy8uICBOb3QgbWFpbHRvOiwgeG1wcDosIGV0Yy5cbiAgLy8gdW5sZXNzIHRoZXkgaGFkIHRoZW0gdG8gYmVnaW4gd2l0aC5cbiAgaWYgKHRoaXMuc2xhc2hlcyB8fFxuICAgICAgKCFwcm90b2NvbCB8fCBzbGFzaGVkUHJvdG9jb2xbcHJvdG9jb2xdKSAmJiBob3N0ICE9PSBmYWxzZSkge1xuICAgIGhvc3QgPSAnLy8nICsgKGhvc3QgfHwgJycpO1xuICAgIGlmIChwYXRobmFtZSAmJiBwYXRobmFtZS5jaGFyQXQoMCkgIT09ICcvJykgcGF0aG5hbWUgPSAnLycgKyBwYXRobmFtZTtcbiAgfSBlbHNlIGlmICghaG9zdCkge1xuICAgIGhvc3QgPSAnJztcbiAgfVxuXG4gIGlmIChoYXNoICYmIGhhc2guY2hhckF0KDApICE9PSAnIycpIGhhc2ggPSAnIycgKyBoYXNoO1xuICBpZiAoc2VhcmNoICYmIHNlYXJjaC5jaGFyQXQoMCkgIT09ICc/Jykgc2VhcmNoID0gJz8nICsgc2VhcmNoO1xuXG4gIHBhdGhuYW1lID0gcGF0aG5hbWUucmVwbGFjZSgvWz8jXS9nLCBmdW5jdGlvbihtYXRjaCkge1xuICAgIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQobWF0Y2gpO1xuICB9KTtcbiAgc2VhcmNoID0gc2VhcmNoLnJlcGxhY2UoJyMnLCAnJTIzJyk7XG5cbiAgcmV0dXJuIHByb3RvY29sICsgaG9zdCArIHBhdGhuYW1lICsgc2VhcmNoICsgaGFzaDtcbn07XG5cbmZ1bmN0aW9uIHVybFJlc29sdmUoc291cmNlLCByZWxhdGl2ZSkge1xuICByZXR1cm4gdXJsUGFyc2Uoc291cmNlLCBmYWxzZSwgdHJ1ZSkucmVzb2x2ZShyZWxhdGl2ZSk7XG59XG5cblVybC5wcm90b3R5cGUucmVzb2x2ZSA9IGZ1bmN0aW9uKHJlbGF0aXZlKSB7XG4gIHJldHVybiB0aGlzLnJlc29sdmVPYmplY3QodXJsUGFyc2UocmVsYXRpdmUsIGZhbHNlLCB0cnVlKSkuZm9ybWF0KCk7XG59O1xuXG5mdW5jdGlvbiB1cmxSZXNvbHZlT2JqZWN0KHNvdXJjZSwgcmVsYXRpdmUpIHtcbiAgaWYgKCFzb3VyY2UpIHJldHVybiByZWxhdGl2ZTtcbiAgcmV0dXJuIHVybFBhcnNlKHNvdXJjZSwgZmFsc2UsIHRydWUpLnJlc29sdmVPYmplY3QocmVsYXRpdmUpO1xufVxuXG5VcmwucHJvdG90eXBlLnJlc29sdmVPYmplY3QgPSBmdW5jdGlvbihyZWxhdGl2ZSkge1xuICBpZiAoaXNTdHJpbmcocmVsYXRpdmUpKSB7XG4gICAgdmFyIHJlbCA9IG5ldyBVcmwoKTtcbiAgICByZWwucGFyc2UocmVsYXRpdmUsIGZhbHNlLCB0cnVlKTtcbiAgICByZWxhdGl2ZSA9IHJlbDtcbiAgfVxuXG4gIHZhciByZXN1bHQgPSBuZXcgVXJsKCk7XG4gIE9iamVjdC5rZXlzKHRoaXMpLmZvckVhY2goZnVuY3Rpb24oaykge1xuICAgIHJlc3VsdFtrXSA9IHRoaXNba107XG4gIH0sIHRoaXMpO1xuXG4gIC8vIGhhc2ggaXMgYWx3YXlzIG92ZXJyaWRkZW4sIG5vIG1hdHRlciB3aGF0LlxuICAvLyBldmVuIGhyZWY9XCJcIiB3aWxsIHJlbW92ZSBpdC5cbiAgcmVzdWx0Lmhhc2ggPSByZWxhdGl2ZS5oYXNoO1xuXG4gIC8vIGlmIHRoZSByZWxhdGl2ZSB1cmwgaXMgZW1wdHksIHRoZW4gdGhlcmUncyBub3RoaW5nIGxlZnQgdG8gZG8gaGVyZS5cbiAgaWYgKHJlbGF0aXZlLmhyZWYgPT09ICcnKSB7XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIGhyZWZzIGxpa2UgLy9mb28vYmFyIGFsd2F5cyBjdXQgdG8gdGhlIHByb3RvY29sLlxuICBpZiAocmVsYXRpdmUuc2xhc2hlcyAmJiAhcmVsYXRpdmUucHJvdG9jb2wpIHtcbiAgICAvLyB0YWtlIGV2ZXJ5dGhpbmcgZXhjZXB0IHRoZSBwcm90b2NvbCBmcm9tIHJlbGF0aXZlXG4gICAgT2JqZWN0LmtleXMocmVsYXRpdmUpLmZvckVhY2goZnVuY3Rpb24oaykge1xuICAgICAgaWYgKGsgIT09ICdwcm90b2NvbCcpXG4gICAgICAgIHJlc3VsdFtrXSA9IHJlbGF0aXZlW2tdO1xuICAgIH0pO1xuXG4gICAgLy91cmxQYXJzZSBhcHBlbmRzIHRyYWlsaW5nIC8gdG8gdXJscyBsaWtlIGh0dHA6Ly93d3cuZXhhbXBsZS5jb21cbiAgICBpZiAoc2xhc2hlZFByb3RvY29sW3Jlc3VsdC5wcm90b2NvbF0gJiZcbiAgICAgICAgcmVzdWx0Lmhvc3RuYW1lICYmICFyZXN1bHQucGF0aG5hbWUpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gcmVzdWx0LnBhdGhuYW1lID0gJy8nO1xuICAgIH1cblxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBpZiAocmVsYXRpdmUucHJvdG9jb2wgJiYgcmVsYXRpdmUucHJvdG9jb2wgIT09IHJlc3VsdC5wcm90b2NvbCkge1xuICAgIC8vIGlmIGl0J3MgYSBrbm93biB1cmwgcHJvdG9jb2wsIHRoZW4gY2hhbmdpbmdcbiAgICAvLyB0aGUgcHJvdG9jb2wgZG9lcyB3ZWlyZCB0aGluZ3NcbiAgICAvLyBmaXJzdCwgaWYgaXQncyBub3QgZmlsZTosIHRoZW4gd2UgTVVTVCBoYXZlIGEgaG9zdCxcbiAgICAvLyBhbmQgaWYgdGhlcmUgd2FzIGEgcGF0aFxuICAgIC8vIHRvIGJlZ2luIHdpdGgsIHRoZW4gd2UgTVVTVCBoYXZlIGEgcGF0aC5cbiAgICAvLyBpZiBpdCBpcyBmaWxlOiwgdGhlbiB0aGUgaG9zdCBpcyBkcm9wcGVkLFxuICAgIC8vIGJlY2F1c2UgdGhhdCdzIGtub3duIHRvIGJlIGhvc3RsZXNzLlxuICAgIC8vIGFueXRoaW5nIGVsc2UgaXMgYXNzdW1lZCB0byBiZSBhYnNvbHV0ZS5cbiAgICBpZiAoIXNsYXNoZWRQcm90b2NvbFtyZWxhdGl2ZS5wcm90b2NvbF0pIHtcbiAgICAgIE9iamVjdC5rZXlzKHJlbGF0aXZlKS5mb3JFYWNoKGZ1bmN0aW9uKGspIHtcbiAgICAgICAgcmVzdWx0W2tdID0gcmVsYXRpdmVba107XG4gICAgICB9KTtcbiAgICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICB9XG5cbiAgICByZXN1bHQucHJvdG9jb2wgPSByZWxhdGl2ZS5wcm90b2NvbDtcbiAgICBpZiAoIXJlbGF0aXZlLmhvc3QgJiYgIWhvc3RsZXNzUHJvdG9jb2xbcmVsYXRpdmUucHJvdG9jb2xdKSB7XG4gICAgICB2YXIgcmVsUGF0aCA9IChyZWxhdGl2ZS5wYXRobmFtZSB8fCAnJykuc3BsaXQoJy8nKTtcbiAgICAgIHdoaWxlIChyZWxQYXRoLmxlbmd0aCAmJiAhKHJlbGF0aXZlLmhvc3QgPSByZWxQYXRoLnNoaWZ0KCkpKTtcbiAgICAgIGlmICghcmVsYXRpdmUuaG9zdCkgcmVsYXRpdmUuaG9zdCA9ICcnO1xuICAgICAgaWYgKCFyZWxhdGl2ZS5ob3N0bmFtZSkgcmVsYXRpdmUuaG9zdG5hbWUgPSAnJztcbiAgICAgIGlmIChyZWxQYXRoWzBdICE9PSAnJykgcmVsUGF0aC51bnNoaWZ0KCcnKTtcbiAgICAgIGlmIChyZWxQYXRoLmxlbmd0aCA8IDIpIHJlbFBhdGgudW5zaGlmdCgnJyk7XG4gICAgICByZXN1bHQucGF0aG5hbWUgPSByZWxQYXRoLmpvaW4oJy8nKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0LnBhdGhuYW1lID0gcmVsYXRpdmUucGF0aG5hbWU7XG4gICAgfVxuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gICAgcmVzdWx0Lmhvc3QgPSByZWxhdGl2ZS5ob3N0IHx8ICcnO1xuICAgIHJlc3VsdC5hdXRoID0gcmVsYXRpdmUuYXV0aDtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSByZWxhdGl2ZS5ob3N0bmFtZSB8fCByZWxhdGl2ZS5ob3N0O1xuICAgIHJlc3VsdC5wb3J0ID0gcmVsYXRpdmUucG9ydDtcbiAgICAvLyB0byBzdXBwb3J0IGh0dHAucmVxdWVzdFxuICAgIGlmIChyZXN1bHQucGF0aG5hbWUgfHwgcmVzdWx0LnNlYXJjaCkge1xuICAgICAgdmFyIHAgPSByZXN1bHQucGF0aG5hbWUgfHwgJyc7XG4gICAgICB2YXIgcyA9IHJlc3VsdC5zZWFyY2ggfHwgJyc7XG4gICAgICByZXN1bHQucGF0aCA9IHAgKyBzO1xuICAgIH1cbiAgICByZXN1bHQuc2xhc2hlcyA9IHJlc3VsdC5zbGFzaGVzIHx8IHJlbGF0aXZlLnNsYXNoZXM7XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIHZhciBpc1NvdXJjZUFicyA9IChyZXN1bHQucGF0aG5hbWUgJiYgcmVzdWx0LnBhdGhuYW1lLmNoYXJBdCgwKSA9PT0gJy8nKSxcbiAgICAgIGlzUmVsQWJzID0gKFxuICAgICAgICAgIHJlbGF0aXZlLmhvc3QgfHxcbiAgICAgICAgICByZWxhdGl2ZS5wYXRobmFtZSAmJiByZWxhdGl2ZS5wYXRobmFtZS5jaGFyQXQoMCkgPT09ICcvJ1xuICAgICAgKSxcbiAgICAgIG11c3RFbmRBYnMgPSAoaXNSZWxBYnMgfHwgaXNTb3VyY2VBYnMgfHxcbiAgICAgICAgICAgICAgICAgICAgKHJlc3VsdC5ob3N0ICYmIHJlbGF0aXZlLnBhdGhuYW1lKSksXG4gICAgICByZW1vdmVBbGxEb3RzID0gbXVzdEVuZEFicyxcbiAgICAgIHNyY1BhdGggPSByZXN1bHQucGF0aG5hbWUgJiYgcmVzdWx0LnBhdGhuYW1lLnNwbGl0KCcvJykgfHwgW10sXG4gICAgICByZWxQYXRoID0gcmVsYXRpdmUucGF0aG5hbWUgJiYgcmVsYXRpdmUucGF0aG5hbWUuc3BsaXQoJy8nKSB8fCBbXSxcbiAgICAgIHBzeWNob3RpYyA9IHJlc3VsdC5wcm90b2NvbCAmJiAhc2xhc2hlZFByb3RvY29sW3Jlc3VsdC5wcm90b2NvbF07XG5cbiAgLy8gaWYgdGhlIHVybCBpcyBhIG5vbi1zbGFzaGVkIHVybCwgdGhlbiByZWxhdGl2ZVxuICAvLyBsaW5rcyBsaWtlIC4uLy4uIHNob3VsZCBiZSBhYmxlXG4gIC8vIHRvIGNyYXdsIHVwIHRvIHRoZSBob3N0bmFtZSwgYXMgd2VsbC4gIFRoaXMgaXMgc3RyYW5nZS5cbiAgLy8gcmVzdWx0LnByb3RvY29sIGhhcyBhbHJlYWR5IGJlZW4gc2V0IGJ5IG5vdy5cbiAgLy8gTGF0ZXIgb24sIHB1dCB0aGUgZmlyc3QgcGF0aCBwYXJ0IGludG8gdGhlIGhvc3QgZmllbGQuXG4gIGlmIChwc3ljaG90aWMpIHtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSAnJztcbiAgICByZXN1bHQucG9ydCA9IG51bGw7XG4gICAgaWYgKHJlc3VsdC5ob3N0KSB7XG4gICAgICBpZiAoc3JjUGF0aFswXSA9PT0gJycpIHNyY1BhdGhbMF0gPSByZXN1bHQuaG9zdDtcbiAgICAgIGVsc2Ugc3JjUGF0aC51bnNoaWZ0KHJlc3VsdC5ob3N0KTtcbiAgICB9XG4gICAgcmVzdWx0Lmhvc3QgPSAnJztcbiAgICBpZiAocmVsYXRpdmUucHJvdG9jb2wpIHtcbiAgICAgIHJlbGF0aXZlLmhvc3RuYW1lID0gbnVsbDtcbiAgICAgIHJlbGF0aXZlLnBvcnQgPSBudWxsO1xuICAgICAgaWYgKHJlbGF0aXZlLmhvc3QpIHtcbiAgICAgICAgaWYgKHJlbFBhdGhbMF0gPT09ICcnKSByZWxQYXRoWzBdID0gcmVsYXRpdmUuaG9zdDtcbiAgICAgICAgZWxzZSByZWxQYXRoLnVuc2hpZnQocmVsYXRpdmUuaG9zdCk7XG4gICAgICB9XG4gICAgICByZWxhdGl2ZS5ob3N0ID0gbnVsbDtcbiAgICB9XG4gICAgbXVzdEVuZEFicyA9IG11c3RFbmRBYnMgJiYgKHJlbFBhdGhbMF0gPT09ICcnIHx8IHNyY1BhdGhbMF0gPT09ICcnKTtcbiAgfVxuXG4gIGlmIChpc1JlbEFicykge1xuICAgIC8vIGl0J3MgYWJzb2x1dGUuXG4gICAgcmVzdWx0Lmhvc3QgPSAocmVsYXRpdmUuaG9zdCB8fCByZWxhdGl2ZS5ob3N0ID09PSAnJykgP1xuICAgICAgICAgICAgICAgICAgcmVsYXRpdmUuaG9zdCA6IHJlc3VsdC5ob3N0O1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9IChyZWxhdGl2ZS5ob3N0bmFtZSB8fCByZWxhdGl2ZS5ob3N0bmFtZSA9PT0gJycpID9cbiAgICAgICAgICAgICAgICAgICAgICByZWxhdGl2ZS5ob3N0bmFtZSA6IHJlc3VsdC5ob3N0bmFtZTtcbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIHNyY1BhdGggPSByZWxQYXRoO1xuICAgIC8vIGZhbGwgdGhyb3VnaCB0byB0aGUgZG90LWhhbmRsaW5nIGJlbG93LlxuICB9IGVsc2UgaWYgKHJlbFBhdGgubGVuZ3RoKSB7XG4gICAgLy8gaXQncyByZWxhdGl2ZVxuICAgIC8vIHRocm93IGF3YXkgdGhlIGV4aXN0aW5nIGZpbGUsIGFuZCB0YWtlIHRoZSBuZXcgcGF0aCBpbnN0ZWFkLlxuICAgIGlmICghc3JjUGF0aCkgc3JjUGF0aCA9IFtdO1xuICAgIHNyY1BhdGgucG9wKCk7XG4gICAgc3JjUGF0aCA9IHNyY1BhdGguY29uY2F0KHJlbFBhdGgpO1xuICAgIHJlc3VsdC5zZWFyY2ggPSByZWxhdGl2ZS5zZWFyY2g7XG4gICAgcmVzdWx0LnF1ZXJ5ID0gcmVsYXRpdmUucXVlcnk7XG4gIH0gZWxzZSBpZiAoIWlzTnVsbE9yVW5kZWZpbmVkKHJlbGF0aXZlLnNlYXJjaCkpIHtcbiAgICAvLyBqdXN0IHB1bGwgb3V0IHRoZSBzZWFyY2guXG4gICAgLy8gbGlrZSBocmVmPSc/Zm9vJy5cbiAgICAvLyBQdXQgdGhpcyBhZnRlciB0aGUgb3RoZXIgdHdvIGNhc2VzIGJlY2F1c2UgaXQgc2ltcGxpZmllcyB0aGUgYm9vbGVhbnNcbiAgICBpZiAocHN5Y2hvdGljKSB7XG4gICAgICByZXN1bHQuaG9zdG5hbWUgPSByZXN1bHQuaG9zdCA9IHNyY1BhdGguc2hpZnQoKTtcbiAgICAgIC8vb2NjYXRpb25hbHkgdGhlIGF1dGggY2FuIGdldCBzdHVjayBvbmx5IGluIGhvc3RcbiAgICAgIC8vdGhpcyBlc3BlY2lhbHkgaGFwcGVucyBpbiBjYXNlcyBsaWtlXG4gICAgICAvL3VybC5yZXNvbHZlT2JqZWN0KCdtYWlsdG86bG9jYWwxQGRvbWFpbjEnLCAnbG9jYWwyQGRvbWFpbjInKVxuICAgICAgdmFyIGF1dGhJbkhvc3QgPSByZXN1bHQuaG9zdCAmJiByZXN1bHQuaG9zdC5pbmRleE9mKCdAJykgPiAwID9cbiAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lmhvc3Quc3BsaXQoJ0AnKSA6IGZhbHNlO1xuICAgICAgaWYgKGF1dGhJbkhvc3QpIHtcbiAgICAgICAgcmVzdWx0LmF1dGggPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICAgIHJlc3VsdC5ob3N0ID0gcmVzdWx0Lmhvc3RuYW1lID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAoIWlzTnVsbChyZXN1bHQucGF0aG5hbWUpIHx8ICFpc051bGwocmVzdWx0LnNlYXJjaCkpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gKHJlc3VsdC5wYXRobmFtZSA/IHJlc3VsdC5wYXRobmFtZSA6ICcnKSArXG4gICAgICAgICAgICAgICAgICAgIChyZXN1bHQuc2VhcmNoID8gcmVzdWx0LnNlYXJjaCA6ICcnKTtcbiAgICB9XG4gICAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIGlmICghc3JjUGF0aC5sZW5ndGgpIHtcbiAgICAvLyBubyBwYXRoIGF0IGFsbC4gIGVhc3kuXG4gICAgLy8gd2UndmUgYWxyZWFkeSBoYW5kbGVkIHRoZSBvdGhlciBzdHVmZiBhYm92ZS5cbiAgICByZXN1bHQucGF0aG5hbWUgPSBudWxsO1xuICAgIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAocmVzdWx0LnNlYXJjaCkge1xuICAgICAgcmVzdWx0LnBhdGggPSAnLycgKyByZXN1bHQuc2VhcmNoO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXN1bHQucGF0aCA9IG51bGw7XG4gICAgfVxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBpZiBhIHVybCBFTkRzIGluIC4gb3IgLi4sIHRoZW4gaXQgbXVzdCBnZXQgYSB0cmFpbGluZyBzbGFzaC5cbiAgLy8gaG93ZXZlciwgaWYgaXQgZW5kcyBpbiBhbnl0aGluZyBlbHNlIG5vbi1zbGFzaHksXG4gIC8vIHRoZW4gaXQgbXVzdCBOT1QgZ2V0IGEgdHJhaWxpbmcgc2xhc2guXG4gIHZhciBsYXN0ID0gc3JjUGF0aC5zbGljZSgtMSlbMF07XG4gIHZhciBoYXNUcmFpbGluZ1NsYXNoID0gKFxuICAgICAgKHJlc3VsdC5ob3N0IHx8IHJlbGF0aXZlLmhvc3QpICYmIChsYXN0ID09PSAnLicgfHwgbGFzdCA9PT0gJy4uJykgfHxcbiAgICAgIGxhc3QgPT09ICcnKTtcblxuICAvLyBzdHJpcCBzaW5nbGUgZG90cywgcmVzb2x2ZSBkb3VibGUgZG90cyB0byBwYXJlbnQgZGlyXG4gIC8vIGlmIHRoZSBwYXRoIHRyaWVzIHRvIGdvIGFib3ZlIHRoZSByb290LCBgdXBgIGVuZHMgdXAgPiAwXG4gIHZhciB1cCA9IDA7XG4gIGZvciAodmFyIGkgPSBzcmNQYXRoLmxlbmd0aDsgaSA+PSAwOyBpLS0pIHtcbiAgICBsYXN0ID0gc3JjUGF0aFtpXTtcbiAgICBpZiAobGFzdCA9PSAnLicpIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgIH0gZWxzZSBpZiAobGFzdCA9PT0gJy4uJykge1xuICAgICAgc3JjUGF0aC5zcGxpY2UoaSwgMSk7XG4gICAgICB1cCsrO1xuICAgIH0gZWxzZSBpZiAodXApIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXAtLTtcbiAgICB9XG4gIH1cblxuICAvLyBpZiB0aGUgcGF0aCBpcyBhbGxvd2VkIHRvIGdvIGFib3ZlIHRoZSByb290LCByZXN0b3JlIGxlYWRpbmcgLi5zXG4gIGlmICghbXVzdEVuZEFicyAmJiAhcmVtb3ZlQWxsRG90cykge1xuICAgIGZvciAoOyB1cC0tOyB1cCkge1xuICAgICAgc3JjUGF0aC51bnNoaWZ0KCcuLicpO1xuICAgIH1cbiAgfVxuXG4gIGlmIChtdXN0RW5kQWJzICYmIHNyY1BhdGhbMF0gIT09ICcnICYmXG4gICAgICAoIXNyY1BhdGhbMF0gfHwgc3JjUGF0aFswXS5jaGFyQXQoMCkgIT09ICcvJykpIHtcbiAgICBzcmNQYXRoLnVuc2hpZnQoJycpO1xuICB9XG5cbiAgaWYgKGhhc1RyYWlsaW5nU2xhc2ggJiYgKHNyY1BhdGguam9pbignLycpLnN1YnN0cigtMSkgIT09ICcvJykpIHtcbiAgICBzcmNQYXRoLnB1c2goJycpO1xuICB9XG5cbiAgdmFyIGlzQWJzb2x1dGUgPSBzcmNQYXRoWzBdID09PSAnJyB8fFxuICAgICAgKHNyY1BhdGhbMF0gJiYgc3JjUGF0aFswXS5jaGFyQXQoMCkgPT09ICcvJyk7XG5cbiAgLy8gcHV0IHRoZSBob3N0IGJhY2tcbiAgaWYgKHBzeWNob3RpYykge1xuICAgIHJlc3VsdC5ob3N0bmFtZSA9IHJlc3VsdC5ob3N0ID0gaXNBYnNvbHV0ZSA/ICcnIDpcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNyY1BhdGgubGVuZ3RoID8gc3JjUGF0aC5zaGlmdCgpIDogJyc7XG4gICAgLy9vY2NhdGlvbmFseSB0aGUgYXV0aCBjYW4gZ2V0IHN0dWNrIG9ubHkgaW4gaG9zdFxuICAgIC8vdGhpcyBlc3BlY2lhbHkgaGFwcGVucyBpbiBjYXNlcyBsaWtlXG4gICAgLy91cmwucmVzb2x2ZU9iamVjdCgnbWFpbHRvOmxvY2FsMUBkb21haW4xJywgJ2xvY2FsMkBkb21haW4yJylcbiAgICB2YXIgYXV0aEluSG9zdCA9IHJlc3VsdC5ob3N0ICYmIHJlc3VsdC5ob3N0LmluZGV4T2YoJ0AnKSA+IDAgP1xuICAgICAgICAgICAgICAgICAgICAgcmVzdWx0Lmhvc3Quc3BsaXQoJ0AnKSA6IGZhbHNlO1xuICAgIGlmIChhdXRoSW5Ib3N0KSB7XG4gICAgICByZXN1bHQuYXV0aCA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICAgIHJlc3VsdC5ob3N0ID0gcmVzdWx0Lmhvc3RuYW1lID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgIH1cbiAgfVxuXG4gIG11c3RFbmRBYnMgPSBtdXN0RW5kQWJzIHx8IChyZXN1bHQuaG9zdCAmJiBzcmNQYXRoLmxlbmd0aCk7XG5cbiAgaWYgKG11c3RFbmRBYnMgJiYgIWlzQWJzb2x1dGUpIHtcbiAgICBzcmNQYXRoLnVuc2hpZnQoJycpO1xuICB9XG5cbiAgaWYgKCFzcmNQYXRoLmxlbmd0aCkge1xuICAgIHJlc3VsdC5wYXRobmFtZSA9IG51bGw7XG4gICAgcmVzdWx0LnBhdGggPSBudWxsO1xuICB9IGVsc2Uge1xuICAgIHJlc3VsdC5wYXRobmFtZSA9IHNyY1BhdGguam9pbignLycpO1xuICB9XG5cbiAgLy90byBzdXBwb3J0IHJlcXVlc3QuaHR0cFxuICBpZiAoIWlzTnVsbChyZXN1bHQucGF0aG5hbWUpIHx8ICFpc051bGwocmVzdWx0LnNlYXJjaCkpIHtcbiAgICByZXN1bHQucGF0aCA9IChyZXN1bHQucGF0aG5hbWUgPyByZXN1bHQucGF0aG5hbWUgOiAnJykgK1xuICAgICAgICAgICAgICAgICAgKHJlc3VsdC5zZWFyY2ggPyByZXN1bHQuc2VhcmNoIDogJycpO1xuICB9XG4gIHJlc3VsdC5hdXRoID0gcmVsYXRpdmUuYXV0aCB8fCByZXN1bHQuYXV0aDtcbiAgcmVzdWx0LnNsYXNoZXMgPSByZXN1bHQuc2xhc2hlcyB8fCByZWxhdGl2ZS5zbGFzaGVzO1xuICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cblVybC5wcm90b3R5cGUucGFyc2VIb3N0ID0gZnVuY3Rpb24oKSB7XG4gIHZhciBob3N0ID0gdGhpcy5ob3N0O1xuICB2YXIgcG9ydCA9IHBvcnRQYXR0ZXJuLmV4ZWMoaG9zdCk7XG4gIGlmIChwb3J0KSB7XG4gICAgcG9ydCA9IHBvcnRbMF07XG4gICAgaWYgKHBvcnQgIT09ICc6Jykge1xuICAgICAgdGhpcy5wb3J0ID0gcG9ydC5zdWJzdHIoMSk7XG4gICAgfVxuICAgIGhvc3QgPSBob3N0LnN1YnN0cigwLCBob3N0Lmxlbmd0aCAtIHBvcnQubGVuZ3RoKTtcbiAgfVxuICBpZiAoaG9zdCkgdGhpcy5ob3N0bmFtZSA9IGhvc3Q7XG59O1xuXG5mdW5jdGlvbiBpc1N0cmluZyhhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09IFwic3RyaW5nXCI7XG59XG5cbmZ1bmN0aW9uIGlzT2JqZWN0KGFyZykge1xuICByZXR1cm4gdHlwZW9mIGFyZyA9PT0gJ29iamVjdCcgJiYgYXJnICE9PSBudWxsO1xufVxuXG5mdW5jdGlvbiBpc051bGwoYXJnKSB7XG4gIHJldHVybiBhcmcgPT09IG51bGw7XG59XG5mdW5jdGlvbiBpc051bGxPclVuZGVmaW5lZChhcmcpIHtcbiAgcmV0dXJuICBhcmcgPT0gbnVsbDtcbn1cbiIsIi8qISBodHRwczovL210aHMuYmUvcHVueWNvZGUgdjEuNC4xIGJ5IEBtYXRoaWFzICovXG47KGZ1bmN0aW9uKHJvb3QpIHtcblxuXHQvKiogRGV0ZWN0IGZyZWUgdmFyaWFibGVzICovXG5cdHZhciBmcmVlRXhwb3J0cyA9IHR5cGVvZiBleHBvcnRzID09ICdvYmplY3QnICYmIGV4cG9ydHMgJiZcblx0XHQhZXhwb3J0cy5ub2RlVHlwZSAmJiBleHBvcnRzO1xuXHR2YXIgZnJlZU1vZHVsZSA9IHR5cGVvZiBtb2R1bGUgPT0gJ29iamVjdCcgJiYgbW9kdWxlICYmXG5cdFx0IW1vZHVsZS5ub2RlVHlwZSAmJiBtb2R1bGU7XG5cdHZhciBmcmVlR2xvYmFsID0gdHlwZW9mIGdsb2JhbCA9PSAnb2JqZWN0JyAmJiBnbG9iYWw7XG5cdGlmIChcblx0XHRmcmVlR2xvYmFsLmdsb2JhbCA9PT0gZnJlZUdsb2JhbCB8fFxuXHRcdGZyZWVHbG9iYWwud2luZG93ID09PSBmcmVlR2xvYmFsIHx8XG5cdFx0ZnJlZUdsb2JhbC5zZWxmID09PSBmcmVlR2xvYmFsXG5cdCkge1xuXHRcdHJvb3QgPSBmcmVlR2xvYmFsO1xuXHR9XG5cblx0LyoqXG5cdCAqIFRoZSBgcHVueWNvZGVgIG9iamVjdC5cblx0ICogQG5hbWUgcHVueWNvZGVcblx0ICogQHR5cGUgT2JqZWN0XG5cdCAqL1xuXHR2YXIgcHVueWNvZGUsXG5cblx0LyoqIEhpZ2hlc3QgcG9zaXRpdmUgc2lnbmVkIDMyLWJpdCBmbG9hdCB2YWx1ZSAqL1xuXHRtYXhJbnQgPSAyMTQ3NDgzNjQ3LCAvLyBha2EuIDB4N0ZGRkZGRkYgb3IgMl4zMS0xXG5cblx0LyoqIEJvb3RzdHJpbmcgcGFyYW1ldGVycyAqL1xuXHRiYXNlID0gMzYsXG5cdHRNaW4gPSAxLFxuXHR0TWF4ID0gMjYsXG5cdHNrZXcgPSAzOCxcblx0ZGFtcCA9IDcwMCxcblx0aW5pdGlhbEJpYXMgPSA3Mixcblx0aW5pdGlhbE4gPSAxMjgsIC8vIDB4ODBcblx0ZGVsaW1pdGVyID0gJy0nLCAvLyAnXFx4MkQnXG5cblx0LyoqIFJlZ3VsYXIgZXhwcmVzc2lvbnMgKi9cblx0cmVnZXhQdW55Y29kZSA9IC9eeG4tLS8sXG5cdHJlZ2V4Tm9uQVNDSUkgPSAvW15cXHgyMC1cXHg3RV0vLCAvLyB1bnByaW50YWJsZSBBU0NJSSBjaGFycyArIG5vbi1BU0NJSSBjaGFyc1xuXHRyZWdleFNlcGFyYXRvcnMgPSAvW1xceDJFXFx1MzAwMlxcdUZGMEVcXHVGRjYxXS9nLCAvLyBSRkMgMzQ5MCBzZXBhcmF0b3JzXG5cblx0LyoqIEVycm9yIG1lc3NhZ2VzICovXG5cdGVycm9ycyA9IHtcblx0XHQnb3ZlcmZsb3cnOiAnT3ZlcmZsb3c6IGlucHV0IG5lZWRzIHdpZGVyIGludGVnZXJzIHRvIHByb2Nlc3MnLFxuXHRcdCdub3QtYmFzaWMnOiAnSWxsZWdhbCBpbnB1dCA+PSAweDgwIChub3QgYSBiYXNpYyBjb2RlIHBvaW50KScsXG5cdFx0J2ludmFsaWQtaW5wdXQnOiAnSW52YWxpZCBpbnB1dCdcblx0fSxcblxuXHQvKiogQ29udmVuaWVuY2Ugc2hvcnRjdXRzICovXG5cdGJhc2VNaW51c1RNaW4gPSBiYXNlIC0gdE1pbixcblx0Zmxvb3IgPSBNYXRoLmZsb29yLFxuXHRzdHJpbmdGcm9tQ2hhckNvZGUgPSBTdHJpbmcuZnJvbUNoYXJDb2RlLFxuXG5cdC8qKiBUZW1wb3JhcnkgdmFyaWFibGUgKi9cblx0a2V5O1xuXG5cdC8qLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0qL1xuXG5cdC8qKlxuXHQgKiBBIGdlbmVyaWMgZXJyb3IgdXRpbGl0eSBmdW5jdGlvbi5cblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IHR5cGUgVGhlIGVycm9yIHR5cGUuXG5cdCAqIEByZXR1cm5zIHtFcnJvcn0gVGhyb3dzIGEgYFJhbmdlRXJyb3JgIHdpdGggdGhlIGFwcGxpY2FibGUgZXJyb3IgbWVzc2FnZS5cblx0ICovXG5cdGZ1bmN0aW9uIGVycm9yKHR5cGUpIHtcblx0XHR0aHJvdyBuZXcgUmFuZ2VFcnJvcihlcnJvcnNbdHlwZV0pO1xuXHR9XG5cblx0LyoqXG5cdCAqIEEgZ2VuZXJpYyBgQXJyYXkjbWFwYCB1dGlsaXR5IGZ1bmN0aW9uLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBhcnJheSBUaGUgYXJyYXkgdG8gaXRlcmF0ZSBvdmVyLlxuXHQgKiBAcGFyYW0ge0Z1bmN0aW9ufSBjYWxsYmFjayBUaGUgZnVuY3Rpb24gdGhhdCBnZXRzIGNhbGxlZCBmb3IgZXZlcnkgYXJyYXlcblx0ICogaXRlbS5cblx0ICogQHJldHVybnMge0FycmF5fSBBIG5ldyBhcnJheSBvZiB2YWx1ZXMgcmV0dXJuZWQgYnkgdGhlIGNhbGxiYWNrIGZ1bmN0aW9uLlxuXHQgKi9cblx0ZnVuY3Rpb24gbWFwKGFycmF5LCBmbikge1xuXHRcdHZhciBsZW5ndGggPSBhcnJheS5sZW5ndGg7XG5cdFx0dmFyIHJlc3VsdCA9IFtdO1xuXHRcdHdoaWxlIChsZW5ndGgtLSkge1xuXHRcdFx0cmVzdWx0W2xlbmd0aF0gPSBmbihhcnJheVtsZW5ndGhdKTtcblx0XHR9XG5cdFx0cmV0dXJuIHJlc3VsdDtcblx0fVxuXG5cdC8qKlxuXHQgKiBBIHNpbXBsZSBgQXJyYXkjbWFwYC1saWtlIHdyYXBwZXIgdG8gd29yayB3aXRoIGRvbWFpbiBuYW1lIHN0cmluZ3Mgb3IgZW1haWxcblx0ICogYWRkcmVzc2VzLlxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gZG9tYWluIFRoZSBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzLlxuXHQgKiBAcGFyYW0ge0Z1bmN0aW9ufSBjYWxsYmFjayBUaGUgZnVuY3Rpb24gdGhhdCBnZXRzIGNhbGxlZCBmb3IgZXZlcnlcblx0ICogY2hhcmFjdGVyLlxuXHQgKiBAcmV0dXJucyB7QXJyYXl9IEEgbmV3IHN0cmluZyBvZiBjaGFyYWN0ZXJzIHJldHVybmVkIGJ5IHRoZSBjYWxsYmFja1xuXHQgKiBmdW5jdGlvbi5cblx0ICovXG5cdGZ1bmN0aW9uIG1hcERvbWFpbihzdHJpbmcsIGZuKSB7XG5cdFx0dmFyIHBhcnRzID0gc3RyaW5nLnNwbGl0KCdAJyk7XG5cdFx0dmFyIHJlc3VsdCA9ICcnO1xuXHRcdGlmIChwYXJ0cy5sZW5ndGggPiAxKSB7XG5cdFx0XHQvLyBJbiBlbWFpbCBhZGRyZXNzZXMsIG9ubHkgdGhlIGRvbWFpbiBuYW1lIHNob3VsZCBiZSBwdW55Y29kZWQuIExlYXZlXG5cdFx0XHQvLyB0aGUgbG9jYWwgcGFydCAoaS5lLiBldmVyeXRoaW5nIHVwIHRvIGBAYCkgaW50YWN0LlxuXHRcdFx0cmVzdWx0ID0gcGFydHNbMF0gKyAnQCc7XG5cdFx0XHRzdHJpbmcgPSBwYXJ0c1sxXTtcblx0XHR9XG5cdFx0Ly8gQXZvaWQgYHNwbGl0KHJlZ2V4KWAgZm9yIElFOCBjb21wYXRpYmlsaXR5LiBTZWUgIzE3LlxuXHRcdHN0cmluZyA9IHN0cmluZy5yZXBsYWNlKHJlZ2V4U2VwYXJhdG9ycywgJ1xceDJFJyk7XG5cdFx0dmFyIGxhYmVscyA9IHN0cmluZy5zcGxpdCgnLicpO1xuXHRcdHZhciBlbmNvZGVkID0gbWFwKGxhYmVscywgZm4pLmpvaW4oJy4nKTtcblx0XHRyZXR1cm4gcmVzdWx0ICsgZW5jb2RlZDtcblx0fVxuXG5cdC8qKlxuXHQgKiBDcmVhdGVzIGFuIGFycmF5IGNvbnRhaW5pbmcgdGhlIG51bWVyaWMgY29kZSBwb2ludHMgb2YgZWFjaCBVbmljb2RlXG5cdCAqIGNoYXJhY3RlciBpbiB0aGUgc3RyaW5nLiBXaGlsZSBKYXZhU2NyaXB0IHVzZXMgVUNTLTIgaW50ZXJuYWxseSxcblx0ICogdGhpcyBmdW5jdGlvbiB3aWxsIGNvbnZlcnQgYSBwYWlyIG9mIHN1cnJvZ2F0ZSBoYWx2ZXMgKGVhY2ggb2Ygd2hpY2hcblx0ICogVUNTLTIgZXhwb3NlcyBhcyBzZXBhcmF0ZSBjaGFyYWN0ZXJzKSBpbnRvIGEgc2luZ2xlIGNvZGUgcG9pbnQsXG5cdCAqIG1hdGNoaW5nIFVURi0xNi5cblx0ICogQHNlZSBgcHVueWNvZGUudWNzMi5lbmNvZGVgXG5cdCAqIEBzZWUgPGh0dHBzOi8vbWF0aGlhc2J5bmVucy5iZS9ub3Rlcy9qYXZhc2NyaXB0LWVuY29kaW5nPlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGUudWNzMlxuXHQgKiBAbmFtZSBkZWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IHN0cmluZyBUaGUgVW5pY29kZSBpbnB1dCBzdHJpbmcgKFVDUy0yKS5cblx0ICogQHJldHVybnMge0FycmF5fSBUaGUgbmV3IGFycmF5IG9mIGNvZGUgcG9pbnRzLlxuXHQgKi9cblx0ZnVuY3Rpb24gdWNzMmRlY29kZShzdHJpbmcpIHtcblx0XHR2YXIgb3V0cHV0ID0gW10sXG5cdFx0ICAgIGNvdW50ZXIgPSAwLFxuXHRcdCAgICBsZW5ndGggPSBzdHJpbmcubGVuZ3RoLFxuXHRcdCAgICB2YWx1ZSxcblx0XHQgICAgZXh0cmE7XG5cdFx0d2hpbGUgKGNvdW50ZXIgPCBsZW5ndGgpIHtcblx0XHRcdHZhbHVlID0gc3RyaW5nLmNoYXJDb2RlQXQoY291bnRlcisrKTtcblx0XHRcdGlmICh2YWx1ZSA+PSAweEQ4MDAgJiYgdmFsdWUgPD0gMHhEQkZGICYmIGNvdW50ZXIgPCBsZW5ndGgpIHtcblx0XHRcdFx0Ly8gaGlnaCBzdXJyb2dhdGUsIGFuZCB0aGVyZSBpcyBhIG5leHQgY2hhcmFjdGVyXG5cdFx0XHRcdGV4dHJhID0gc3RyaW5nLmNoYXJDb2RlQXQoY291bnRlcisrKTtcblx0XHRcdFx0aWYgKChleHRyYSAmIDB4RkMwMCkgPT0gMHhEQzAwKSB7IC8vIGxvdyBzdXJyb2dhdGVcblx0XHRcdFx0XHRvdXRwdXQucHVzaCgoKHZhbHVlICYgMHgzRkYpIDw8IDEwKSArIChleHRyYSAmIDB4M0ZGKSArIDB4MTAwMDApO1xuXHRcdFx0XHR9IGVsc2Uge1xuXHRcdFx0XHRcdC8vIHVubWF0Y2hlZCBzdXJyb2dhdGU7IG9ubHkgYXBwZW5kIHRoaXMgY29kZSB1bml0LCBpbiBjYXNlIHRoZSBuZXh0XG5cdFx0XHRcdFx0Ly8gY29kZSB1bml0IGlzIHRoZSBoaWdoIHN1cnJvZ2F0ZSBvZiBhIHN1cnJvZ2F0ZSBwYWlyXG5cdFx0XHRcdFx0b3V0cHV0LnB1c2godmFsdWUpO1xuXHRcdFx0XHRcdGNvdW50ZXItLTtcblx0XHRcdFx0fVxuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0b3V0cHV0LnB1c2godmFsdWUpO1xuXHRcdFx0fVxuXHRcdH1cblx0XHRyZXR1cm4gb3V0cHV0O1xuXHR9XG5cblx0LyoqXG5cdCAqIENyZWF0ZXMgYSBzdHJpbmcgYmFzZWQgb24gYW4gYXJyYXkgb2YgbnVtZXJpYyBjb2RlIHBvaW50cy5cblx0ICogQHNlZSBgcHVueWNvZGUudWNzMi5kZWNvZGVgXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZS51Y3MyXG5cdCAqIEBuYW1lIGVuY29kZVxuXHQgKiBAcGFyYW0ge0FycmF5fSBjb2RlUG9pbnRzIFRoZSBhcnJheSBvZiBudW1lcmljIGNvZGUgcG9pbnRzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgbmV3IFVuaWNvZGUgc3RyaW5nIChVQ1MtMikuXG5cdCAqL1xuXHRmdW5jdGlvbiB1Y3MyZW5jb2RlKGFycmF5KSB7XG5cdFx0cmV0dXJuIG1hcChhcnJheSwgZnVuY3Rpb24odmFsdWUpIHtcblx0XHRcdHZhciBvdXRwdXQgPSAnJztcblx0XHRcdGlmICh2YWx1ZSA+IDB4RkZGRikge1xuXHRcdFx0XHR2YWx1ZSAtPSAweDEwMDAwO1xuXHRcdFx0XHRvdXRwdXQgKz0gc3RyaW5nRnJvbUNoYXJDb2RlKHZhbHVlID4+PiAxMCAmIDB4M0ZGIHwgMHhEODAwKTtcblx0XHRcdFx0dmFsdWUgPSAweERDMDAgfCB2YWx1ZSAmIDB4M0ZGO1xuXHRcdFx0fVxuXHRcdFx0b3V0cHV0ICs9IHN0cmluZ0Zyb21DaGFyQ29kZSh2YWx1ZSk7XG5cdFx0XHRyZXR1cm4gb3V0cHV0O1xuXHRcdH0pLmpvaW4oJycpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgYmFzaWMgY29kZSBwb2ludCBpbnRvIGEgZGlnaXQvaW50ZWdlci5cblx0ICogQHNlZSBgZGlnaXRUb0Jhc2ljKClgXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBjb2RlUG9pbnQgVGhlIGJhc2ljIG51bWVyaWMgY29kZSBwb2ludCB2YWx1ZS5cblx0ICogQHJldHVybnMge051bWJlcn0gVGhlIG51bWVyaWMgdmFsdWUgb2YgYSBiYXNpYyBjb2RlIHBvaW50IChmb3IgdXNlIGluXG5cdCAqIHJlcHJlc2VudGluZyBpbnRlZ2VycykgaW4gdGhlIHJhbmdlIGAwYCB0byBgYmFzZSAtIDFgLCBvciBgYmFzZWAgaWZcblx0ICogdGhlIGNvZGUgcG9pbnQgZG9lcyBub3QgcmVwcmVzZW50IGEgdmFsdWUuXG5cdCAqL1xuXHRmdW5jdGlvbiBiYXNpY1RvRGlnaXQoY29kZVBvaW50KSB7XG5cdFx0aWYgKGNvZGVQb2ludCAtIDQ4IDwgMTApIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSAyMjtcblx0XHR9XG5cdFx0aWYgKGNvZGVQb2ludCAtIDY1IDwgMjYpIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSA2NTtcblx0XHR9XG5cdFx0aWYgKGNvZGVQb2ludCAtIDk3IDwgMjYpIHtcblx0XHRcdHJldHVybiBjb2RlUG9pbnQgLSA5Nztcblx0XHR9XG5cdFx0cmV0dXJuIGJhc2U7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBkaWdpdC9pbnRlZ2VyIGludG8gYSBiYXNpYyBjb2RlIHBvaW50LlxuXHQgKiBAc2VlIGBiYXNpY1RvRGlnaXQoKWBcblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtOdW1iZXJ9IGRpZ2l0IFRoZSBudW1lcmljIHZhbHVlIG9mIGEgYmFzaWMgY29kZSBwb2ludC5cblx0ICogQHJldHVybnMge051bWJlcn0gVGhlIGJhc2ljIGNvZGUgcG9pbnQgd2hvc2UgdmFsdWUgKHdoZW4gdXNlZCBmb3Jcblx0ICogcmVwcmVzZW50aW5nIGludGVnZXJzKSBpcyBgZGlnaXRgLCB3aGljaCBuZWVkcyB0byBiZSBpbiB0aGUgcmFuZ2Vcblx0ICogYDBgIHRvIGBiYXNlIC0gMWAuIElmIGBmbGFnYCBpcyBub24temVybywgdGhlIHVwcGVyY2FzZSBmb3JtIGlzXG5cdCAqIHVzZWQ7IGVsc2UsIHRoZSBsb3dlcmNhc2UgZm9ybSBpcyB1c2VkLiBUaGUgYmVoYXZpb3IgaXMgdW5kZWZpbmVkXG5cdCAqIGlmIGBmbGFnYCBpcyBub24temVybyBhbmQgYGRpZ2l0YCBoYXMgbm8gdXBwZXJjYXNlIGZvcm0uXG5cdCAqL1xuXHRmdW5jdGlvbiBkaWdpdFRvQmFzaWMoZGlnaXQsIGZsYWcpIHtcblx0XHQvLyAgMC4uMjUgbWFwIHRvIEFTQ0lJIGEuLnogb3IgQS4uWlxuXHRcdC8vIDI2Li4zNSBtYXAgdG8gQVNDSUkgMC4uOVxuXHRcdHJldHVybiBkaWdpdCArIDIyICsgNzUgKiAoZGlnaXQgPCAyNikgLSAoKGZsYWcgIT0gMCkgPDwgNSk7XG5cdH1cblxuXHQvKipcblx0ICogQmlhcyBhZGFwdGF0aW9uIGZ1bmN0aW9uIGFzIHBlciBzZWN0aW9uIDMuNCBvZiBSRkMgMzQ5Mi5cblx0ICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzM0OTIjc2VjdGlvbi0zLjRcblx0ICogQHByaXZhdGVcblx0ICovXG5cdGZ1bmN0aW9uIGFkYXB0KGRlbHRhLCBudW1Qb2ludHMsIGZpcnN0VGltZSkge1xuXHRcdHZhciBrID0gMDtcblx0XHRkZWx0YSA9IGZpcnN0VGltZSA/IGZsb29yKGRlbHRhIC8gZGFtcCkgOiBkZWx0YSA+PiAxO1xuXHRcdGRlbHRhICs9IGZsb29yKGRlbHRhIC8gbnVtUG9pbnRzKTtcblx0XHRmb3IgKC8qIG5vIGluaXRpYWxpemF0aW9uICovOyBkZWx0YSA+IGJhc2VNaW51c1RNaW4gKiB0TWF4ID4+IDE7IGsgKz0gYmFzZSkge1xuXHRcdFx0ZGVsdGEgPSBmbG9vcihkZWx0YSAvIGJhc2VNaW51c1RNaW4pO1xuXHRcdH1cblx0XHRyZXR1cm4gZmxvb3IoayArIChiYXNlTWludXNUTWluICsgMSkgKiBkZWx0YSAvIChkZWx0YSArIHNrZXcpKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMgdG8gYSBzdHJpbmcgb2YgVW5pY29kZVxuXHQgKiBzeW1ib2xzLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgcmVzdWx0aW5nIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMuXG5cdCAqL1xuXHRmdW5jdGlvbiBkZWNvZGUoaW5wdXQpIHtcblx0XHQvLyBEb24ndCB1c2UgVUNTLTJcblx0XHR2YXIgb3V0cHV0ID0gW10sXG5cdFx0ICAgIGlucHV0TGVuZ3RoID0gaW5wdXQubGVuZ3RoLFxuXHRcdCAgICBvdXQsXG5cdFx0ICAgIGkgPSAwLFxuXHRcdCAgICBuID0gaW5pdGlhbE4sXG5cdFx0ICAgIGJpYXMgPSBpbml0aWFsQmlhcyxcblx0XHQgICAgYmFzaWMsXG5cdFx0ICAgIGosXG5cdFx0ICAgIGluZGV4LFxuXHRcdCAgICBvbGRpLFxuXHRcdCAgICB3LFxuXHRcdCAgICBrLFxuXHRcdCAgICBkaWdpdCxcblx0XHQgICAgdCxcblx0XHQgICAgLyoqIENhY2hlZCBjYWxjdWxhdGlvbiByZXN1bHRzICovXG5cdFx0ICAgIGJhc2VNaW51c1Q7XG5cblx0XHQvLyBIYW5kbGUgdGhlIGJhc2ljIGNvZGUgcG9pbnRzOiBsZXQgYGJhc2ljYCBiZSB0aGUgbnVtYmVyIG9mIGlucHV0IGNvZGVcblx0XHQvLyBwb2ludHMgYmVmb3JlIHRoZSBsYXN0IGRlbGltaXRlciwgb3IgYDBgIGlmIHRoZXJlIGlzIG5vbmUsIHRoZW4gY29weVxuXHRcdC8vIHRoZSBmaXJzdCBiYXNpYyBjb2RlIHBvaW50cyB0byB0aGUgb3V0cHV0LlxuXG5cdFx0YmFzaWMgPSBpbnB1dC5sYXN0SW5kZXhPZihkZWxpbWl0ZXIpO1xuXHRcdGlmIChiYXNpYyA8IDApIHtcblx0XHRcdGJhc2ljID0gMDtcblx0XHR9XG5cblx0XHRmb3IgKGogPSAwOyBqIDwgYmFzaWM7ICsraikge1xuXHRcdFx0Ly8gaWYgaXQncyBub3QgYSBiYXNpYyBjb2RlIHBvaW50XG5cdFx0XHRpZiAoaW5wdXQuY2hhckNvZGVBdChqKSA+PSAweDgwKSB7XG5cdFx0XHRcdGVycm9yKCdub3QtYmFzaWMnKTtcblx0XHRcdH1cblx0XHRcdG91dHB1dC5wdXNoKGlucHV0LmNoYXJDb2RlQXQoaikpO1xuXHRcdH1cblxuXHRcdC8vIE1haW4gZGVjb2RpbmcgbG9vcDogc3RhcnQganVzdCBhZnRlciB0aGUgbGFzdCBkZWxpbWl0ZXIgaWYgYW55IGJhc2ljIGNvZGVcblx0XHQvLyBwb2ludHMgd2VyZSBjb3BpZWQ7IHN0YXJ0IGF0IHRoZSBiZWdpbm5pbmcgb3RoZXJ3aXNlLlxuXG5cdFx0Zm9yIChpbmRleCA9IGJhc2ljID4gMCA/IGJhc2ljICsgMSA6IDA7IGluZGV4IDwgaW5wdXRMZW5ndGg7IC8qIG5vIGZpbmFsIGV4cHJlc3Npb24gKi8pIHtcblxuXHRcdFx0Ly8gYGluZGV4YCBpcyB0aGUgaW5kZXggb2YgdGhlIG5leHQgY2hhcmFjdGVyIHRvIGJlIGNvbnN1bWVkLlxuXHRcdFx0Ly8gRGVjb2RlIGEgZ2VuZXJhbGl6ZWQgdmFyaWFibGUtbGVuZ3RoIGludGVnZXIgaW50byBgZGVsdGFgLFxuXHRcdFx0Ly8gd2hpY2ggZ2V0cyBhZGRlZCB0byBgaWAuIFRoZSBvdmVyZmxvdyBjaGVja2luZyBpcyBlYXNpZXJcblx0XHRcdC8vIGlmIHdlIGluY3JlYXNlIGBpYCBhcyB3ZSBnbywgdGhlbiBzdWJ0cmFjdCBvZmYgaXRzIHN0YXJ0aW5nXG5cdFx0XHQvLyB2YWx1ZSBhdCB0aGUgZW5kIHRvIG9idGFpbiBgZGVsdGFgLlxuXHRcdFx0Zm9yIChvbGRpID0gaSwgdyA9IDEsIGsgPSBiYXNlOyAvKiBubyBjb25kaXRpb24gKi87IGsgKz0gYmFzZSkge1xuXG5cdFx0XHRcdGlmIChpbmRleCA+PSBpbnB1dExlbmd0aCkge1xuXHRcdFx0XHRcdGVycm9yKCdpbnZhbGlkLWlucHV0Jyk7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRkaWdpdCA9IGJhc2ljVG9EaWdpdChpbnB1dC5jaGFyQ29kZUF0KGluZGV4KyspKTtcblxuXHRcdFx0XHRpZiAoZGlnaXQgPj0gYmFzZSB8fCBkaWdpdCA+IGZsb29yKChtYXhJbnQgLSBpKSAvIHcpKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRpICs9IGRpZ2l0ICogdztcblx0XHRcdFx0dCA9IGsgPD0gYmlhcyA/IHRNaW4gOiAoayA+PSBiaWFzICsgdE1heCA/IHRNYXggOiBrIC0gYmlhcyk7XG5cblx0XHRcdFx0aWYgKGRpZ2l0IDwgdCkge1xuXHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0YmFzZU1pbnVzVCA9IGJhc2UgLSB0O1xuXHRcdFx0XHRpZiAodyA+IGZsb29yKG1heEludCAvIGJhc2VNaW51c1QpKSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHR3ICo9IGJhc2VNaW51c1Q7XG5cblx0XHRcdH1cblxuXHRcdFx0b3V0ID0gb3V0cHV0Lmxlbmd0aCArIDE7XG5cdFx0XHRiaWFzID0gYWRhcHQoaSAtIG9sZGksIG91dCwgb2xkaSA9PSAwKTtcblxuXHRcdFx0Ly8gYGlgIHdhcyBzdXBwb3NlZCB0byB3cmFwIGFyb3VuZCBmcm9tIGBvdXRgIHRvIGAwYCxcblx0XHRcdC8vIGluY3JlbWVudGluZyBgbmAgZWFjaCB0aW1lLCBzbyB3ZSdsbCBmaXggdGhhdCBub3c6XG5cdFx0XHRpZiAoZmxvb3IoaSAvIG91dCkgPiBtYXhJbnQgLSBuKSB7XG5cdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0fVxuXG5cdFx0XHRuICs9IGZsb29yKGkgLyBvdXQpO1xuXHRcdFx0aSAlPSBvdXQ7XG5cblx0XHRcdC8vIEluc2VydCBgbmAgYXQgcG9zaXRpb24gYGlgIG9mIHRoZSBvdXRwdXRcblx0XHRcdG91dHB1dC5zcGxpY2UoaSsrLCAwLCBuKTtcblxuXHRcdH1cblxuXHRcdHJldHVybiB1Y3MyZW5jb2RlKG91dHB1dCk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzIChlLmcuIGEgZG9tYWluIG5hbWUgbGFiZWwpIHRvIGFcblx0ICogUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scy5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scy5cblx0ICogQHJldHVybnMge1N0cmluZ30gVGhlIHJlc3VsdGluZyBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzLlxuXHQgKi9cblx0ZnVuY3Rpb24gZW5jb2RlKGlucHV0KSB7XG5cdFx0dmFyIG4sXG5cdFx0ICAgIGRlbHRhLFxuXHRcdCAgICBoYW5kbGVkQ1BDb3VudCxcblx0XHQgICAgYmFzaWNMZW5ndGgsXG5cdFx0ICAgIGJpYXMsXG5cdFx0ICAgIGosXG5cdFx0ICAgIG0sXG5cdFx0ICAgIHEsXG5cdFx0ICAgIGssXG5cdFx0ICAgIHQsXG5cdFx0ICAgIGN1cnJlbnRWYWx1ZSxcblx0XHQgICAgb3V0cHV0ID0gW10sXG5cdFx0ICAgIC8qKiBgaW5wdXRMZW5ndGhgIHdpbGwgaG9sZCB0aGUgbnVtYmVyIG9mIGNvZGUgcG9pbnRzIGluIGBpbnB1dGAuICovXG5cdFx0ICAgIGlucHV0TGVuZ3RoLFxuXHRcdCAgICAvKiogQ2FjaGVkIGNhbGN1bGF0aW9uIHJlc3VsdHMgKi9cblx0XHQgICAgaGFuZGxlZENQQ291bnRQbHVzT25lLFxuXHRcdCAgICBiYXNlTWludXNULFxuXHRcdCAgICBxTWludXNUO1xuXG5cdFx0Ly8gQ29udmVydCB0aGUgaW5wdXQgaW4gVUNTLTIgdG8gVW5pY29kZVxuXHRcdGlucHV0ID0gdWNzMmRlY29kZShpbnB1dCk7XG5cblx0XHQvLyBDYWNoZSB0aGUgbGVuZ3RoXG5cdFx0aW5wdXRMZW5ndGggPSBpbnB1dC5sZW5ndGg7XG5cblx0XHQvLyBJbml0aWFsaXplIHRoZSBzdGF0ZVxuXHRcdG4gPSBpbml0aWFsTjtcblx0XHRkZWx0YSA9IDA7XG5cdFx0YmlhcyA9IGluaXRpYWxCaWFzO1xuXG5cdFx0Ly8gSGFuZGxlIHRoZSBiYXNpYyBjb2RlIHBvaW50c1xuXHRcdGZvciAoaiA9IDA7IGogPCBpbnB1dExlbmd0aDsgKytqKSB7XG5cdFx0XHRjdXJyZW50VmFsdWUgPSBpbnB1dFtqXTtcblx0XHRcdGlmIChjdXJyZW50VmFsdWUgPCAweDgwKSB7XG5cdFx0XHRcdG91dHB1dC5wdXNoKHN0cmluZ0Zyb21DaGFyQ29kZShjdXJyZW50VmFsdWUpKTtcblx0XHRcdH1cblx0XHR9XG5cblx0XHRoYW5kbGVkQ1BDb3VudCA9IGJhc2ljTGVuZ3RoID0gb3V0cHV0Lmxlbmd0aDtcblxuXHRcdC8vIGBoYW5kbGVkQ1BDb3VudGAgaXMgdGhlIG51bWJlciBvZiBjb2RlIHBvaW50cyB0aGF0IGhhdmUgYmVlbiBoYW5kbGVkO1xuXHRcdC8vIGBiYXNpY0xlbmd0aGAgaXMgdGhlIG51bWJlciBvZiBiYXNpYyBjb2RlIHBvaW50cy5cblxuXHRcdC8vIEZpbmlzaCB0aGUgYmFzaWMgc3RyaW5nIC0gaWYgaXQgaXMgbm90IGVtcHR5IC0gd2l0aCBhIGRlbGltaXRlclxuXHRcdGlmIChiYXNpY0xlbmd0aCkge1xuXHRcdFx0b3V0cHV0LnB1c2goZGVsaW1pdGVyKTtcblx0XHR9XG5cblx0XHQvLyBNYWluIGVuY29kaW5nIGxvb3A6XG5cdFx0d2hpbGUgKGhhbmRsZWRDUENvdW50IDwgaW5wdXRMZW5ndGgpIHtcblxuXHRcdFx0Ly8gQWxsIG5vbi1iYXNpYyBjb2RlIHBvaW50cyA8IG4gaGF2ZSBiZWVuIGhhbmRsZWQgYWxyZWFkeS4gRmluZCB0aGUgbmV4dFxuXHRcdFx0Ly8gbGFyZ2VyIG9uZTpcblx0XHRcdGZvciAobSA9IG1heEludCwgaiA9IDA7IGogPCBpbnB1dExlbmd0aDsgKytqKSB7XG5cdFx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXHRcdFx0XHRpZiAoY3VycmVudFZhbHVlID49IG4gJiYgY3VycmVudFZhbHVlIDwgbSkge1xuXHRcdFx0XHRcdG0gPSBjdXJyZW50VmFsdWU7XG5cdFx0XHRcdH1cblx0XHRcdH1cblxuXHRcdFx0Ly8gSW5jcmVhc2UgYGRlbHRhYCBlbm91Z2ggdG8gYWR2YW5jZSB0aGUgZGVjb2RlcidzIDxuLGk+IHN0YXRlIHRvIDxtLDA+LFxuXHRcdFx0Ly8gYnV0IGd1YXJkIGFnYWluc3Qgb3ZlcmZsb3dcblx0XHRcdGhhbmRsZWRDUENvdW50UGx1c09uZSA9IGhhbmRsZWRDUENvdW50ICsgMTtcblx0XHRcdGlmIChtIC0gbiA+IGZsb29yKChtYXhJbnQgLSBkZWx0YSkgLyBoYW5kbGVkQ1BDb3VudFBsdXNPbmUpKSB7XG5cdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0fVxuXG5cdFx0XHRkZWx0YSArPSAobSAtIG4pICogaGFuZGxlZENQQ291bnRQbHVzT25lO1xuXHRcdFx0biA9IG07XG5cblx0XHRcdGZvciAoaiA9IDA7IGogPCBpbnB1dExlbmd0aDsgKytqKSB7XG5cdFx0XHRcdGN1cnJlbnRWYWx1ZSA9IGlucHV0W2pdO1xuXG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPCBuICYmICsrZGVsdGEgPiBtYXhJbnQpIHtcblx0XHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGlmIChjdXJyZW50VmFsdWUgPT0gbikge1xuXHRcdFx0XHRcdC8vIFJlcHJlc2VudCBkZWx0YSBhcyBhIGdlbmVyYWxpemVkIHZhcmlhYmxlLWxlbmd0aCBpbnRlZ2VyXG5cdFx0XHRcdFx0Zm9yIChxID0gZGVsdGEsIGsgPSBiYXNlOyAvKiBubyBjb25kaXRpb24gKi87IGsgKz0gYmFzZSkge1xuXHRcdFx0XHRcdFx0dCA9IGsgPD0gYmlhcyA/IHRNaW4gOiAoayA+PSBiaWFzICsgdE1heCA/IHRNYXggOiBrIC0gYmlhcyk7XG5cdFx0XHRcdFx0XHRpZiAocSA8IHQpIHtcblx0XHRcdFx0XHRcdFx0YnJlYWs7XG5cdFx0XHRcdFx0XHR9XG5cdFx0XHRcdFx0XHRxTWludXNUID0gcSAtIHQ7XG5cdFx0XHRcdFx0XHRiYXNlTWludXNUID0gYmFzZSAtIHQ7XG5cdFx0XHRcdFx0XHRvdXRwdXQucHVzaChcblx0XHRcdFx0XHRcdFx0c3RyaW5nRnJvbUNoYXJDb2RlKGRpZ2l0VG9CYXNpYyh0ICsgcU1pbnVzVCAlIGJhc2VNaW51c1QsIDApKVxuXHRcdFx0XHRcdFx0KTtcblx0XHRcdFx0XHRcdHEgPSBmbG9vcihxTWludXNUIC8gYmFzZU1pbnVzVCk7XG5cdFx0XHRcdFx0fVxuXG5cdFx0XHRcdFx0b3V0cHV0LnB1c2goc3RyaW5nRnJvbUNoYXJDb2RlKGRpZ2l0VG9CYXNpYyhxLCAwKSkpO1xuXHRcdFx0XHRcdGJpYXMgPSBhZGFwdChkZWx0YSwgaGFuZGxlZENQQ291bnRQbHVzT25lLCBoYW5kbGVkQ1BDb3VudCA9PSBiYXNpY0xlbmd0aCk7XG5cdFx0XHRcdFx0ZGVsdGEgPSAwO1xuXHRcdFx0XHRcdCsraGFuZGxlZENQQ291bnQ7XG5cdFx0XHRcdH1cblx0XHRcdH1cblxuXHRcdFx0KytkZWx0YTtcblx0XHRcdCsrbjtcblxuXHRcdH1cblx0XHRyZXR1cm4gb3V0cHV0LmpvaW4oJycpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgUHVueWNvZGUgc3RyaW5nIHJlcHJlc2VudGluZyBhIGRvbWFpbiBuYW1lIG9yIGFuIGVtYWlsIGFkZHJlc3Ncblx0ICogdG8gVW5pY29kZS4gT25seSB0aGUgUHVueWNvZGVkIHBhcnRzIG9mIHRoZSBpbnB1dCB3aWxsIGJlIGNvbnZlcnRlZCwgaS5lLlxuXHQgKiBpdCBkb2Vzbid0IG1hdHRlciBpZiB5b3UgY2FsbCBpdCBvbiBhIHN0cmluZyB0aGF0IGhhcyBhbHJlYWR5IGJlZW5cblx0ICogY29udmVydGVkIHRvIFVuaWNvZGUuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIFB1bnljb2RlZCBkb21haW4gbmFtZSBvciBlbWFpbCBhZGRyZXNzIHRvXG5cdCAqIGNvbnZlcnQgdG8gVW5pY29kZS5cblx0ICogQHJldHVybnMge1N0cmluZ30gVGhlIFVuaWNvZGUgcmVwcmVzZW50YXRpb24gb2YgdGhlIGdpdmVuIFB1bnljb2RlXG5cdCAqIHN0cmluZy5cblx0ICovXG5cdGZ1bmN0aW9uIHRvVW5pY29kZShpbnB1dCkge1xuXHRcdHJldHVybiBtYXBEb21haW4oaW5wdXQsIGZ1bmN0aW9uKHN0cmluZykge1xuXHRcdFx0cmV0dXJuIHJlZ2V4UHVueWNvZGUudGVzdChzdHJpbmcpXG5cdFx0XHRcdD8gZGVjb2RlKHN0cmluZy5zbGljZSg0KS50b0xvd2VyQ2FzZSgpKVxuXHRcdFx0XHQ6IHN0cmluZztcblx0XHR9KTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIFVuaWNvZGUgc3RyaW5nIHJlcHJlc2VudGluZyBhIGRvbWFpbiBuYW1lIG9yIGFuIGVtYWlsIGFkZHJlc3MgdG9cblx0ICogUHVueWNvZGUuIE9ubHkgdGhlIG5vbi1BU0NJSSBwYXJ0cyBvZiB0aGUgZG9tYWluIG5hbWUgd2lsbCBiZSBjb252ZXJ0ZWQsXG5cdCAqIGkuZS4gaXQgZG9lc24ndCBtYXR0ZXIgaWYgeW91IGNhbGwgaXQgd2l0aCBhIGRvbWFpbiB0aGF0J3MgYWxyZWFkeSBpblxuXHQgKiBBU0NJSS5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgZG9tYWluIG5hbWUgb3IgZW1haWwgYWRkcmVzcyB0byBjb252ZXJ0LCBhcyBhXG5cdCAqIFVuaWNvZGUgc3RyaW5nLlxuXHQgKiBAcmV0dXJucyB7U3RyaW5nfSBUaGUgUHVueWNvZGUgcmVwcmVzZW50YXRpb24gb2YgdGhlIGdpdmVuIGRvbWFpbiBuYW1lIG9yXG5cdCAqIGVtYWlsIGFkZHJlc3MuXG5cdCAqL1xuXHRmdW5jdGlvbiB0b0FTQ0lJKGlucHV0KSB7XG5cdFx0cmV0dXJuIG1hcERvbWFpbihpbnB1dCwgZnVuY3Rpb24oc3RyaW5nKSB7XG5cdFx0XHRyZXR1cm4gcmVnZXhOb25BU0NJSS50ZXN0KHN0cmluZylcblx0XHRcdFx0PyAneG4tLScgKyBlbmNvZGUoc3RyaW5nKVxuXHRcdFx0XHQ6IHN0cmluZztcblx0XHR9KTtcblx0fVxuXG5cdC8qLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0qL1xuXG5cdC8qKiBEZWZpbmUgdGhlIHB1YmxpYyBBUEkgKi9cblx0cHVueWNvZGUgPSB7XG5cdFx0LyoqXG5cdFx0ICogQSBzdHJpbmcgcmVwcmVzZW50aW5nIHRoZSBjdXJyZW50IFB1bnljb2RlLmpzIHZlcnNpb24gbnVtYmVyLlxuXHRcdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHRcdCAqIEB0eXBlIFN0cmluZ1xuXHRcdCAqL1xuXHRcdCd2ZXJzaW9uJzogJzEuNC4xJyxcblx0XHQvKipcblx0XHQgKiBBbiBvYmplY3Qgb2YgbWV0aG9kcyB0byBjb252ZXJ0IGZyb20gSmF2YVNjcmlwdCdzIGludGVybmFsIGNoYXJhY3RlclxuXHRcdCAqIHJlcHJlc2VudGF0aW9uIChVQ1MtMikgdG8gVW5pY29kZSBjb2RlIHBvaW50cywgYW5kIGJhY2suXG5cdFx0ICogQHNlZSA8aHR0cHM6Ly9tYXRoaWFzYnluZW5zLmJlL25vdGVzL2phdmFzY3JpcHQtZW5jb2Rpbmc+XG5cdFx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdFx0ICogQHR5cGUgT2JqZWN0XG5cdFx0ICovXG5cdFx0J3VjczInOiB7XG5cdFx0XHQnZGVjb2RlJzogdWNzMmRlY29kZSxcblx0XHRcdCdlbmNvZGUnOiB1Y3MyZW5jb2RlXG5cdFx0fSxcblx0XHQnZGVjb2RlJzogZGVjb2RlLFxuXHRcdCdlbmNvZGUnOiBlbmNvZGUsXG5cdFx0J3RvQVNDSUknOiB0b0FTQ0lJLFxuXHRcdCd0b1VuaWNvZGUnOiB0b1VuaWNvZGVcblx0fTtcblxuXHQvKiogRXhwb3NlIGBwdW55Y29kZWAgKi9cblx0Ly8gU29tZSBBTUQgYnVpbGQgb3B0aW1pemVycywgbGlrZSByLmpzLCBjaGVjayBmb3Igc3BlY2lmaWMgY29uZGl0aW9uIHBhdHRlcm5zXG5cdC8vIGxpa2UgdGhlIGZvbGxvd2luZzpcblx0aWYgKFxuXHRcdHR5cGVvZiBkZWZpbmUgPT0gJ2Z1bmN0aW9uJyAmJlxuXHRcdHR5cGVvZiBkZWZpbmUuYW1kID09ICdvYmplY3QnICYmXG5cdFx0ZGVmaW5lLmFtZFxuXHQpIHtcblx0XHRkZWZpbmUoJ3B1bnljb2RlJywgZnVuY3Rpb24oKSB7XG5cdFx0XHRyZXR1cm4gcHVueWNvZGU7XG5cdFx0fSk7XG5cdH0gZWxzZSBpZiAoZnJlZUV4cG9ydHMgJiYgZnJlZU1vZHVsZSkge1xuXHRcdGlmIChtb2R1bGUuZXhwb3J0cyA9PSBmcmVlRXhwb3J0cykge1xuXHRcdFx0Ly8gaW4gTm9kZS5qcywgaW8uanMsIG9yIFJpbmdvSlMgdjAuOC4wK1xuXHRcdFx0ZnJlZU1vZHVsZS5leHBvcnRzID0gcHVueWNvZGU7XG5cdFx0fSBlbHNlIHtcblx0XHRcdC8vIGluIE5hcndoYWwgb3IgUmluZ29KUyB2MC43LjAtXG5cdFx0XHRmb3IgKGtleSBpbiBwdW55Y29kZSkge1xuXHRcdFx0XHRwdW55Y29kZS5oYXNPd25Qcm9wZXJ0eShrZXkpICYmIChmcmVlRXhwb3J0c1trZXldID0gcHVueWNvZGVba2V5XSk7XG5cdFx0XHR9XG5cdFx0fVxuXHR9IGVsc2Uge1xuXHRcdC8vIGluIFJoaW5vIG9yIGEgd2ViIGJyb3dzZXJcblx0XHRyb290LnB1bnljb2RlID0gcHVueWNvZGU7XG5cdH1cblxufSh0aGlzKSk7XG4iLCIvKlxuICogcXVhbnRpemUuanMgQ29weXJpZ2h0IDIwMDggTmljayBSYWJpbm93aXR6XG4gKiBQb3J0ZWQgdG8gbm9kZS5qcyBieSBPbGl2aWVyIExlc25pY2tpXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgTUlUIGxpY2Vuc2U6IGh0dHA6Ly93d3cub3BlbnNvdXJjZS5vcmcvbGljZW5zZXMvbWl0LWxpY2Vuc2UucGhwXG4gKi9cblxuLy8gZmlsbCBvdXQgYSBjb3VwbGUgcHJvdG92aXMgZGVwZW5kZW5jaWVzXG4vKlxuICogQmxvY2sgYmVsb3cgY29waWVkIGZyb20gUHJvdG92aXM6IGh0dHA6Ly9tYm9zdG9jay5naXRodWIuY29tL3Byb3RvdmlzL1xuICogQ29weXJpZ2h0IDIwMTAgU3RhbmZvcmQgVmlzdWFsaXphdGlvbiBHcm91cFxuICogTGljZW5zZWQgdW5kZXIgdGhlIEJTRCBMaWNlbnNlOiBodHRwOi8vd3d3Lm9wZW5zb3VyY2Uub3JnL2xpY2Vuc2VzL2JzZC1saWNlbnNlLnBocFxuICovXG5pZiAoIXB2KSB7XG4gICAgdmFyIHB2ID0ge1xuICAgICAgICBtYXA6IGZ1bmN0aW9uKGFycmF5LCBmKSB7XG4gICAgICAgICAgICB2YXIgbyA9IHt9O1xuICAgICAgICAgICAgcmV0dXJuIGYgPyBhcnJheS5tYXAoZnVuY3Rpb24oZCwgaSkge1xuICAgICAgICAgICAgICAgIG8uaW5kZXggPSBpO1xuICAgICAgICAgICAgICAgIHJldHVybiBmLmNhbGwobywgZCk7XG4gICAgICAgICAgICB9KSA6IGFycmF5LnNsaWNlKCk7XG4gICAgICAgIH0sXG4gICAgICAgIG5hdHVyYWxPcmRlcjogZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIChhIDwgYikgPyAtMSA6ICgoYSA+IGIpID8gMSA6IDApO1xuICAgICAgICB9LFxuICAgICAgICBzdW06IGZ1bmN0aW9uKGFycmF5LCBmKSB7XG4gICAgICAgICAgICB2YXIgbyA9IHt9O1xuICAgICAgICAgICAgcmV0dXJuIGFycmF5LnJlZHVjZShmID8gZnVuY3Rpb24ocCwgZCwgaSkge1xuICAgICAgICAgICAgICAgIG8uaW5kZXggPSBpO1xuICAgICAgICAgICAgICAgIHJldHVybiBwICsgZi5jYWxsKG8sIGQpO1xuICAgICAgICAgICAgfSA6IGZ1bmN0aW9uKHAsIGQpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcCArIGQ7XG4gICAgICAgICAgICB9LCAwKTtcbiAgICAgICAgfSxcbiAgICAgICAgbWF4OiBmdW5jdGlvbihhcnJheSwgZikge1xuICAgICAgICAgICAgcmV0dXJuIE1hdGgubWF4LmFwcGx5KG51bGwsIGYgPyBwdi5tYXAoYXJyYXksIGYpIDogYXJyYXkpO1xuICAgICAgICB9XG4gICAgfVxufVxuXG4vKipcbiAqIEJhc2ljIEphdmFzY3JpcHQgcG9ydCBvZiB0aGUgTU1DUSAobW9kaWZpZWQgbWVkaWFuIGN1dCBxdWFudGl6YXRpb24pXG4gKiBhbGdvcml0aG0gZnJvbSB0aGUgTGVwdG9uaWNhIGxpYnJhcnkgKGh0dHA6Ly93d3cubGVwdG9uaWNhLmNvbS8pLlxuICogUmV0dXJucyBhIGNvbG9yIG1hcCB5b3UgY2FuIHVzZSB0byBtYXAgb3JpZ2luYWwgcGl4ZWxzIHRvIHRoZSByZWR1Y2VkXG4gKiBwYWxldHRlLiBTdGlsbCBhIHdvcmsgaW4gcHJvZ3Jlc3MuXG4gKiBcbiAqIEBhdXRob3IgTmljayBSYWJpbm93aXR6XG4gKiBAZXhhbXBsZVxuIFxuLy8gYXJyYXkgb2YgcGl4ZWxzIGFzIFtSLEcsQl0gYXJyYXlzXG52YXIgbXlQaXhlbHMgPSBbWzE5MCwxOTcsMTkwXSwgWzIwMiwyMDQsMjAwXSwgWzIwNywyMTQsMjEwXSwgWzIxMSwyMTQsMjExXSwgWzIwNSwyMDcsMjA3XVxuICAgICAgICAgICAgICAgIC8vIGV0Y1xuICAgICAgICAgICAgICAgIF07XG52YXIgbWF4Q29sb3JzID0gNDtcbiBcbnZhciBjbWFwID0gTU1DUS5xdWFudGl6ZShteVBpeGVscywgbWF4Q29sb3JzKTtcbnZhciBuZXdQYWxldHRlID0gY21hcC5wYWxldHRlKCk7XG52YXIgbmV3UGl4ZWxzID0gbXlQaXhlbHMubWFwKGZ1bmN0aW9uKHApIHsgXG4gICAgcmV0dXJuIGNtYXAubWFwKHApOyBcbn0pO1xuIFxuICovXG52YXIgTU1DUSA9IChmdW5jdGlvbigpIHtcbiAgICAvLyBwcml2YXRlIGNvbnN0YW50c1xuICAgIHZhciBzaWdiaXRzID0gNSxcbiAgICAgICAgcnNoaWZ0ID0gOCAtIHNpZ2JpdHMsXG4gICAgICAgIG1heEl0ZXJhdGlvbnMgPSAxMDAwLFxuICAgICAgICBmcmFjdEJ5UG9wdWxhdGlvbnMgPSAwLjc1O1xuXG4gICAgLy8gZ2V0IHJlZHVjZWQtc3BhY2UgY29sb3IgaW5kZXggZm9yIGEgcGl4ZWxcblxuICAgIGZ1bmN0aW9uIGdldENvbG9ySW5kZXgociwgZywgYikge1xuICAgICAgICByZXR1cm4gKHIgPDwgKDIgKiBzaWdiaXRzKSkgKyAoZyA8PCBzaWdiaXRzKSArIGI7XG4gICAgfVxuXG4gICAgLy8gU2ltcGxlIHByaW9yaXR5IHF1ZXVlXG5cbiAgICBmdW5jdGlvbiBQUXVldWUoY29tcGFyYXRvcikge1xuICAgICAgICB2YXIgY29udGVudHMgPSBbXSxcbiAgICAgICAgICAgIHNvcnRlZCA9IGZhbHNlO1xuXG4gICAgICAgIGZ1bmN0aW9uIHNvcnQoKSB7XG4gICAgICAgICAgICBjb250ZW50cy5zb3J0KGNvbXBhcmF0b3IpO1xuICAgICAgICAgICAgc29ydGVkID0gdHJ1ZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICBwdXNoOiBmdW5jdGlvbihvKSB7XG4gICAgICAgICAgICAgICAgY29udGVudHMucHVzaChvKTtcbiAgICAgICAgICAgICAgICBzb3J0ZWQgPSBmYWxzZTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBwZWVrOiBmdW5jdGlvbihpbmRleCkge1xuICAgICAgICAgICAgICAgIGlmICghc29ydGVkKSBzb3J0KCk7XG4gICAgICAgICAgICAgICAgaWYgKGluZGV4ID09PSB1bmRlZmluZWQpIGluZGV4ID0gY29udGVudHMubGVuZ3RoIC0gMTtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHNbaW5kZXhdO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHBvcDogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgaWYgKCFzb3J0ZWQpIHNvcnQoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHMucG9wKCk7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2l6ZTogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzLmxlbmd0aDtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBtYXA6IGZ1bmN0aW9uKGYpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHMubWFwKGYpO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGRlYnVnOiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNvcnRlZCkgc29ydCgpO1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9XG5cbiAgICAvLyAzZCBjb2xvciBzcGFjZSBib3hcblxuICAgIGZ1bmN0aW9uIFZCb3gocjEsIHIyLCBnMSwgZzIsIGIxLCBiMiwgaGlzdG8pIHtcbiAgICAgICAgdmFyIHZib3ggPSB0aGlzO1xuICAgICAgICB2Ym94LnIxID0gcjE7XG4gICAgICAgIHZib3gucjIgPSByMjtcbiAgICAgICAgdmJveC5nMSA9IGcxO1xuICAgICAgICB2Ym94LmcyID0gZzI7XG4gICAgICAgIHZib3guYjEgPSBiMTtcbiAgICAgICAgdmJveC5iMiA9IGIyO1xuICAgICAgICB2Ym94Lmhpc3RvID0gaGlzdG87XG4gICAgfVxuICAgIFZCb3gucHJvdG90eXBlID0ge1xuICAgICAgICB2b2x1bWU6IGZ1bmN0aW9uKGZvcmNlKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXM7XG4gICAgICAgICAgICBpZiAoIXZib3guX3ZvbHVtZSB8fCBmb3JjZSkge1xuICAgICAgICAgICAgICAgIHZib3guX3ZvbHVtZSA9ICgodmJveC5yMiAtIHZib3gucjEgKyAxKSAqICh2Ym94LmcyIC0gdmJveC5nMSArIDEpICogKHZib3guYjIgLSB2Ym94LmIxICsgMSkpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHZib3guX3ZvbHVtZTtcbiAgICAgICAgfSxcbiAgICAgICAgY291bnQ6IGZ1bmN0aW9uKGZvcmNlKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXMsXG4gICAgICAgICAgICAgICAgaGlzdG8gPSB2Ym94Lmhpc3RvO1xuICAgICAgICAgICAgaWYgKCF2Ym94Ll9jb3VudF9zZXQgfHwgZm9yY2UpIHtcbiAgICAgICAgICAgICAgICB2YXIgbnBpeCA9IDAsXG4gICAgICAgICAgICAgICAgICAgIGksIGosIGssIGluZGV4O1xuICAgICAgICAgICAgICAgIGZvciAoaSA9IHZib3gucjE7IGkgPD0gdmJveC5yMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3guZzE7IGogPD0gdmJveC5nMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmIxOyBrIDw9IHZib3guYjI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChpLCBqLCBrKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBucGl4ICs9IChoaXN0b1tpbmRleF0gfHwgMCk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdmJveC5fY291bnQgPSBucGl4O1xuICAgICAgICAgICAgICAgIHZib3guX2NvdW50X3NldCA9IHRydWU7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdmJveC5fY291bnQ7XG4gICAgICAgIH0sXG4gICAgICAgIGNvcHk6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzO1xuICAgICAgICAgICAgcmV0dXJuIG5ldyBWQm94KHZib3gucjEsIHZib3gucjIsIHZib3guZzEsIHZib3guZzIsIHZib3guYjEsIHZib3guYjIsIHZib3guaGlzdG8pO1xuICAgICAgICB9LFxuICAgICAgICBhdmc6IGZ1bmN0aW9uKGZvcmNlKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXMsXG4gICAgICAgICAgICAgICAgaGlzdG8gPSB2Ym94Lmhpc3RvO1xuICAgICAgICAgICAgaWYgKCF2Ym94Ll9hdmcgfHwgZm9yY2UpIHtcbiAgICAgICAgICAgICAgICB2YXIgbnRvdCA9IDAsXG4gICAgICAgICAgICAgICAgICAgIG11bHQgPSAxIDw8ICg4IC0gc2lnYml0cyksXG4gICAgICAgICAgICAgICAgICAgIHJzdW0gPSAwLFxuICAgICAgICAgICAgICAgICAgICBnc3VtID0gMCxcbiAgICAgICAgICAgICAgICAgICAgYnN1bSA9IDAsXG4gICAgICAgICAgICAgICAgICAgIGh2YWwsXG4gICAgICAgICAgICAgICAgICAgIGksIGosIGssIGhpc3RvaW5kZXg7XG4gICAgICAgICAgICAgICAgZm9yIChpID0gdmJveC5yMTsgaSA8PSB2Ym94LnIyOyBpKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5nMTsgaiA8PSB2Ym94LmcyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaGlzdG9pbmRleCA9IGdldENvbG9ySW5kZXgoaSwgaiwgayk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgaHZhbCA9IGhpc3RvW2hpc3RvaW5kZXhdIHx8IDA7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbnRvdCArPSBodmFsO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJzdW0gKz0gKGh2YWwgKiAoaSArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBnc3VtICs9IChodmFsICogKGogKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgYnN1bSArPSAoaHZhbCAqIChrICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChudG90KSB7XG4gICAgICAgICAgICAgICAgICAgIHZib3guX2F2ZyA9IFt+fihyc3VtIC8gbnRvdCksIH5+IChnc3VtIC8gbnRvdCksIH5+IChic3VtIC8gbnRvdCldO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgIC8vY29uc29sZS5sb2coJ2VtcHR5IGJveCcpO1xuICAgICAgICAgICAgICAgICAgICB2Ym94Ll9hdmcgPSBbfn4obXVsdCAqICh2Ym94LnIxICsgdmJveC5yMiArIDEpIC8gMiksIH5+IChtdWx0ICogKHZib3guZzEgKyB2Ym94LmcyICsgMSkgLyAyKSwgfn4gKG11bHQgKiAodmJveC5iMSArIHZib3guYjIgKyAxKSAvIDIpXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICByZXR1cm4gdmJveC5fYXZnO1xuICAgICAgICB9LFxuICAgICAgICBjb250YWluczogZnVuY3Rpb24ocGl4ZWwpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcyxcbiAgICAgICAgICAgICAgICBydmFsID0gcGl4ZWxbMF0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgZ3ZhbCA9IHBpeGVsWzFdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGJ2YWwgPSBwaXhlbFsyXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICByZXR1cm4gKHJ2YWwgPj0gdmJveC5yMSAmJiBydmFsIDw9IHZib3gucjIgJiZcbiAgICAgICAgICAgICAgICBndmFsID49IHZib3guZzEgJiYgZ3ZhbCA8PSB2Ym94LmcyICYmXG4gICAgICAgICAgICAgICAgYnZhbCA+PSB2Ym94LmIxICYmIGJ2YWwgPD0gdmJveC5iMik7XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gQ29sb3IgbWFwXG5cbiAgICBmdW5jdGlvbiBDTWFwKCkge1xuICAgICAgICB0aGlzLnZib3hlcyA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihcbiAgICAgICAgICAgICAgICBhLnZib3guY291bnQoKSAqIGEudmJveC52b2x1bWUoKSxcbiAgICAgICAgICAgICAgICBiLnZib3guY291bnQoKSAqIGIudmJveC52b2x1bWUoKVxuICAgICAgICAgICAgKVxuICAgICAgICB9KTs7XG4gICAgfVxuICAgIENNYXAucHJvdG90eXBlID0ge1xuICAgICAgICBwdXNoOiBmdW5jdGlvbih2Ym94KSB7XG4gICAgICAgICAgICB0aGlzLnZib3hlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICB2Ym94OiB2Ym94LFxuICAgICAgICAgICAgICAgIGNvbG9yOiB2Ym94LmF2ZygpXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgcGFsZXR0ZTogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy52Ym94ZXMubWFwKGZ1bmN0aW9uKHZiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHZiLmNvbG9yXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSxcbiAgICAgICAgc2l6ZTogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy52Ym94ZXMuc2l6ZSgpO1xuICAgICAgICB9LFxuICAgICAgICBtYXA6IGZ1bmN0aW9uKGNvbG9yKSB7XG4gICAgICAgICAgICB2YXIgdmJveGVzID0gdGhpcy52Ym94ZXM7XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHZib3hlcy5zaXplKCk7IGkrKykge1xuICAgICAgICAgICAgICAgIGlmICh2Ym94ZXMucGVlayhpKS52Ym94LmNvbnRhaW5zKGNvbG9yKSkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdmJveGVzLnBlZWsoaSkuY29sb3I7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHRoaXMubmVhcmVzdChjb2xvcik7XG4gICAgICAgIH0sXG4gICAgICAgIG5lYXJlc3Q6IGZ1bmN0aW9uKGNvbG9yKSB7XG4gICAgICAgICAgICB2YXIgdmJveGVzID0gdGhpcy52Ym94ZXMsXG4gICAgICAgICAgICAgICAgZDEsIGQyLCBwQ29sb3I7XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHZib3hlcy5zaXplKCk7IGkrKykge1xuICAgICAgICAgICAgICAgIGQyID0gTWF0aC5zcXJ0KFxuICAgICAgICAgICAgICAgICAgICBNYXRoLnBvdyhjb2xvclswXSAtIHZib3hlcy5wZWVrKGkpLmNvbG9yWzBdLCAyKSArXG4gICAgICAgICAgICAgICAgICAgIE1hdGgucG93KGNvbG9yWzFdIC0gdmJveGVzLnBlZWsoaSkuY29sb3JbMV0sIDIpICtcbiAgICAgICAgICAgICAgICAgICAgTWF0aC5wb3coY29sb3JbMl0gLSB2Ym94ZXMucGVlayhpKS5jb2xvclsyXSwgMilcbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIGlmIChkMiA8IGQxIHx8IGQxID09PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgZDEgPSBkMjtcbiAgICAgICAgICAgICAgICAgICAgcENvbG9yID0gdmJveGVzLnBlZWsoaSkuY29sb3I7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHBDb2xvcjtcbiAgICAgICAgfSxcbiAgICAgICAgZm9yY2VidzogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAvLyBYWFg6IHdvbid0ICB3b3JrIHlldFxuICAgICAgICAgICAgdmFyIHZib3hlcyA9IHRoaXMudmJveGVzO1xuICAgICAgICAgICAgdmJveGVzLnNvcnQoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgICAgIHJldHVybiBwdi5uYXR1cmFsT3JkZXIocHYuc3VtKGEuY29sb3IpLCBwdi5zdW0oYi5jb2xvcikpXG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8gZm9yY2UgZGFya2VzdCBjb2xvciB0byBibGFjayBpZiBldmVyeXRoaW5nIDwgNVxuICAgICAgICAgICAgdmFyIGxvd2VzdCA9IHZib3hlc1swXS5jb2xvcjtcbiAgICAgICAgICAgIGlmIChsb3dlc3RbMF0gPCA1ICYmIGxvd2VzdFsxXSA8IDUgJiYgbG93ZXN0WzJdIDwgNSlcbiAgICAgICAgICAgICAgICB2Ym94ZXNbMF0uY29sb3IgPSBbMCwgMCwgMF07XG5cbiAgICAgICAgICAgIC8vIGZvcmNlIGxpZ2h0ZXN0IGNvbG9yIHRvIHdoaXRlIGlmIGV2ZXJ5dGhpbmcgPiAyNTFcbiAgICAgICAgICAgIHZhciBpZHggPSB2Ym94ZXMubGVuZ3RoIC0gMSxcbiAgICAgICAgICAgICAgICBoaWdoZXN0ID0gdmJveGVzW2lkeF0uY29sb3I7XG4gICAgICAgICAgICBpZiAoaGlnaGVzdFswXSA+IDI1MSAmJiBoaWdoZXN0WzFdID4gMjUxICYmIGhpZ2hlc3RbMl0gPiAyNTEpXG4gICAgICAgICAgICAgICAgdmJveGVzW2lkeF0uY29sb3IgPSBbMjU1LCAyNTUsIDI1NV07XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgLy8gaGlzdG8gKDEtZCBhcnJheSwgZ2l2aW5nIHRoZSBudW1iZXIgb2YgcGl4ZWxzIGluXG4gICAgLy8gZWFjaCBxdWFudGl6ZWQgcmVnaW9uIG9mIGNvbG9yIHNwYWNlKSwgb3IgbnVsbCBvbiBlcnJvclxuXG4gICAgZnVuY3Rpb24gZ2V0SGlzdG8ocGl4ZWxzKSB7XG4gICAgICAgIHZhciBoaXN0b3NpemUgPSAxIDw8ICgzICogc2lnYml0cyksXG4gICAgICAgICAgICBoaXN0byA9IG5ldyBBcnJheShoaXN0b3NpemUpLFxuICAgICAgICAgICAgaW5kZXgsIHJ2YWwsIGd2YWwsIGJ2YWw7XG4gICAgICAgIHBpeGVscy5mb3JFYWNoKGZ1bmN0aW9uKHBpeGVsKSB7XG4gICAgICAgICAgICBydmFsID0gcGl4ZWxbMF0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgZ3ZhbCA9IHBpeGVsWzFdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGJ2YWwgPSBwaXhlbFsyXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgocnZhbCwgZ3ZhbCwgYnZhbCk7XG4gICAgICAgICAgICBoaXN0b1tpbmRleF0gPSAoaGlzdG9baW5kZXhdIHx8IDApICsgMTtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBoaXN0bztcbiAgICB9XG5cbiAgICBmdW5jdGlvbiB2Ym94RnJvbVBpeGVscyhwaXhlbHMsIGhpc3RvKSB7XG4gICAgICAgIHZhciBybWluID0gMTAwMDAwMCxcbiAgICAgICAgICAgIHJtYXggPSAwLFxuICAgICAgICAgICAgZ21pbiA9IDEwMDAwMDAsXG4gICAgICAgICAgICBnbWF4ID0gMCxcbiAgICAgICAgICAgIGJtaW4gPSAxMDAwMDAwLFxuICAgICAgICAgICAgYm1heCA9IDAsXG4gICAgICAgICAgICBydmFsLCBndmFsLCBidmFsO1xuICAgICAgICAvLyBmaW5kIG1pbi9tYXhcbiAgICAgICAgcGl4ZWxzLmZvckVhY2goZnVuY3Rpb24ocGl4ZWwpIHtcbiAgICAgICAgICAgIHJ2YWwgPSBwaXhlbFswXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBndmFsID0gcGl4ZWxbMV0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgYnZhbCA9IHBpeGVsWzJdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGlmIChydmFsIDwgcm1pbikgcm1pbiA9IHJ2YWw7XG4gICAgICAgICAgICBlbHNlIGlmIChydmFsID4gcm1heCkgcm1heCA9IHJ2YWw7XG4gICAgICAgICAgICBpZiAoZ3ZhbCA8IGdtaW4pIGdtaW4gPSBndmFsO1xuICAgICAgICAgICAgZWxzZSBpZiAoZ3ZhbCA+IGdtYXgpIGdtYXggPSBndmFsO1xuICAgICAgICAgICAgaWYgKGJ2YWwgPCBibWluKSBibWluID0gYnZhbDtcbiAgICAgICAgICAgIGVsc2UgaWYgKGJ2YWwgPiBibWF4KSBibWF4ID0gYnZhbDtcbiAgICAgICAgfSk7XG4gICAgICAgIHJldHVybiBuZXcgVkJveChybWluLCBybWF4LCBnbWluLCBnbWF4LCBibWluLCBibWF4LCBoaXN0byk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gbWVkaWFuQ3V0QXBwbHkoaGlzdG8sIHZib3gpIHtcbiAgICAgICAgaWYgKCF2Ym94LmNvdW50KCkpIHJldHVybjtcblxuICAgICAgICB2YXIgcncgPSB2Ym94LnIyIC0gdmJveC5yMSArIDEsXG4gICAgICAgICAgICBndyA9IHZib3guZzIgLSB2Ym94LmcxICsgMSxcbiAgICAgICAgICAgIGJ3ID0gdmJveC5iMiAtIHZib3guYjEgKyAxLFxuICAgICAgICAgICAgbWF4dyA9IHB2Lm1heChbcncsIGd3LCBid10pO1xuICAgICAgICAvLyBvbmx5IG9uZSBwaXhlbCwgbm8gc3BsaXRcbiAgICAgICAgaWYgKHZib3guY291bnQoKSA9PSAxKSB7XG4gICAgICAgICAgICByZXR1cm4gW3Zib3guY29weSgpXVxuICAgICAgICB9XG4gICAgICAgIC8qIEZpbmQgdGhlIHBhcnRpYWwgc3VtIGFycmF5cyBhbG9uZyB0aGUgc2VsZWN0ZWQgYXhpcy4gKi9cbiAgICAgICAgdmFyIHRvdGFsID0gMCxcbiAgICAgICAgICAgIHBhcnRpYWxzdW0gPSBbXSxcbiAgICAgICAgICAgIGxvb2thaGVhZHN1bSA9IFtdLFxuICAgICAgICAgICAgaSwgaiwgaywgc3VtLCBpbmRleDtcbiAgICAgICAgaWYgKG1heHcgPT0gcncpIHtcbiAgICAgICAgICAgIGZvciAoaSA9IHZib3gucjE7IGkgPD0gdmJveC5yMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgc3VtID0gMDtcbiAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LmcxOyBqIDw9IHZib3guZzI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmIxOyBrIDw9IHZib3guYjI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGksIGosIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgc3VtICs9IChoaXN0b1tpbmRleF0gfHwgMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgICAgICAgIHBhcnRpYWxzdW1baV0gPSB0b3RhbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIGlmIChtYXh3ID09IGd3KSB7XG4gICAgICAgICAgICBmb3IgKGkgPSB2Ym94LmcxOyBpIDw9IHZib3guZzI7IGkrKykge1xuICAgICAgICAgICAgICAgIHN1bSA9IDA7XG4gICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5yMTsgaiA8PSB2Ym94LnIyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5iMTsgayA8PSB2Ym94LmIyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChqLCBpLCBrKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHN1bSArPSAoaGlzdG9baW5kZXhdIHx8IDApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICAgICAgICBwYXJ0aWFsc3VtW2ldID0gdG90YWw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7IC8qIG1heHcgPT0gYncgKi9cbiAgICAgICAgICAgIGZvciAoaSA9IHZib3guYjE7IGkgPD0gdmJveC5iMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgc3VtID0gMDtcbiAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LnIxOyBqIDw9IHZib3gucjI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmcxOyBrIDw9IHZib3guZzI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KGosIGssIGkpO1xuICAgICAgICAgICAgICAgICAgICAgICAgc3VtICs9IChoaXN0b1tpbmRleF0gfHwgMCk7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgICAgICAgIHBhcnRpYWxzdW1baV0gPSB0b3RhbDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICBwYXJ0aWFsc3VtLmZvckVhY2goZnVuY3Rpb24oZCwgaSkge1xuICAgICAgICAgICAgbG9va2FoZWFkc3VtW2ldID0gdG90YWwgLSBkXG4gICAgICAgIH0pO1xuXG4gICAgICAgIGZ1bmN0aW9uIGRvQ3V0KGNvbG9yKSB7XG4gICAgICAgICAgICB2YXIgZGltMSA9IGNvbG9yICsgJzEnLFxuICAgICAgICAgICAgICAgIGRpbTIgPSBjb2xvciArICcyJyxcbiAgICAgICAgICAgICAgICBsZWZ0LCByaWdodCwgdmJveDEsIHZib3gyLCBkMiwgY291bnQyID0gMDtcbiAgICAgICAgICAgIGZvciAoaSA9IHZib3hbZGltMV07IGkgPD0gdmJveFtkaW0yXTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgaWYgKHBhcnRpYWxzdW1baV0gPiB0b3RhbCAvIDIpIHtcbiAgICAgICAgICAgICAgICAgICAgdmJveDEgPSB2Ym94LmNvcHkoKTtcbiAgICAgICAgICAgICAgICAgICAgdmJveDIgPSB2Ym94LmNvcHkoKTtcbiAgICAgICAgICAgICAgICAgICAgbGVmdCA9IGkgLSB2Ym94W2RpbTFdO1xuICAgICAgICAgICAgICAgICAgICByaWdodCA9IHZib3hbZGltMl0gLSBpO1xuICAgICAgICAgICAgICAgICAgICBpZiAobGVmdCA8PSByaWdodClcbiAgICAgICAgICAgICAgICAgICAgICAgIGQyID0gTWF0aC5taW4odmJveFtkaW0yXSAtIDEsIH5+IChpICsgcmlnaHQgLyAyKSk7XG4gICAgICAgICAgICAgICAgICAgIGVsc2UgZDIgPSBNYXRoLm1heCh2Ym94W2RpbTFdLCB+fiAoaSAtIDEgLSBsZWZ0IC8gMikpO1xuICAgICAgICAgICAgICAgICAgICAvLyBhdm9pZCAwLWNvdW50IGJveGVzXG4gICAgICAgICAgICAgICAgICAgIHdoaWxlICghcGFydGlhbHN1bVtkMl0pIGQyKys7XG4gICAgICAgICAgICAgICAgICAgIGNvdW50MiA9IGxvb2thaGVhZHN1bVtkMl07XG4gICAgICAgICAgICAgICAgICAgIHdoaWxlICghY291bnQyICYmIHBhcnRpYWxzdW1bZDIgLSAxXSkgY291bnQyID0gbG9va2FoZWFkc3VtWy0tZDJdO1xuICAgICAgICAgICAgICAgICAgICAvLyBzZXQgZGltZW5zaW9uc1xuICAgICAgICAgICAgICAgICAgICB2Ym94MVtkaW0yXSA9IGQyO1xuICAgICAgICAgICAgICAgICAgICB2Ym94MltkaW0xXSA9IHZib3gxW2RpbTJdICsgMTtcbiAgICAgICAgICAgICAgICAgICAgLy8gY29uc29sZS5sb2coJ3Zib3ggY291bnRzOicsIHZib3guY291bnQoKSwgdmJveDEuY291bnQoKSwgdmJveDIuY291bnQoKSk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiBbdmJveDEsIHZib3gyXTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgfVxuICAgICAgICAvLyBkZXRlcm1pbmUgdGhlIGN1dCBwbGFuZXNcbiAgICAgICAgcmV0dXJuIG1heHcgPT0gcncgPyBkb0N1dCgncicpIDpcbiAgICAgICAgICAgIG1heHcgPT0gZ3cgPyBkb0N1dCgnZycpIDpcbiAgICAgICAgICAgIGRvQ3V0KCdiJyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gcXVhbnRpemUocGl4ZWxzLCBtYXhjb2xvcnMpIHtcbiAgICAgICAgLy8gc2hvcnQtY2lyY3VpdFxuICAgICAgICBpZiAoIXBpeGVscy5sZW5ndGggfHwgbWF4Y29sb3JzIDwgMiB8fCBtYXhjb2xvcnMgPiAyNTYpIHtcbiAgICAgICAgICAgIC8vIGNvbnNvbGUubG9nKCd3cm9uZyBudW1iZXIgb2YgbWF4Y29sb3JzJyk7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBYWFg6IGNoZWNrIGNvbG9yIGNvbnRlbnQgYW5kIGNvbnZlcnQgdG8gZ3JheXNjYWxlIGlmIGluc3VmZmljaWVudFxuXG4gICAgICAgIHZhciBoaXN0byA9IGdldEhpc3RvKHBpeGVscyksXG4gICAgICAgICAgICBoaXN0b3NpemUgPSAxIDw8ICgzICogc2lnYml0cyk7XG5cbiAgICAgICAgLy8gY2hlY2sgdGhhdCB3ZSBhcmVuJ3QgYmVsb3cgbWF4Y29sb3JzIGFscmVhZHlcbiAgICAgICAgdmFyIG5Db2xvcnMgPSAwO1xuICAgICAgICBoaXN0by5mb3JFYWNoKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgbkNvbG9ycysrXG4gICAgICAgIH0pO1xuICAgICAgICBpZiAobkNvbG9ycyA8PSBtYXhjb2xvcnMpIHtcbiAgICAgICAgICAgIC8vIFhYWDogZ2VuZXJhdGUgdGhlIG5ldyBjb2xvcnMgZnJvbSB0aGUgaGlzdG8gYW5kIHJldHVyblxuICAgICAgICB9XG5cbiAgICAgICAgLy8gZ2V0IHRoZSBiZWdpbm5pbmcgdmJveCBmcm9tIHRoZSBjb2xvcnNcbiAgICAgICAgdmFyIHZib3ggPSB2Ym94RnJvbVBpeGVscyhwaXhlbHMsIGhpc3RvKSxcbiAgICAgICAgICAgIHBxID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHB2Lm5hdHVyYWxPcmRlcihhLmNvdW50KCksIGIuY291bnQoKSlcbiAgICAgICAgICAgIH0pO1xuICAgICAgICBwcS5wdXNoKHZib3gpO1xuXG4gICAgICAgIC8vIGlubmVyIGZ1bmN0aW9uIHRvIGRvIHRoZSBpdGVyYXRpb25cblxuICAgICAgICBmdW5jdGlvbiBpdGVyKGxoLCB0YXJnZXQpIHtcbiAgICAgICAgICAgIHZhciBuY29sb3JzID0gMSxcbiAgICAgICAgICAgICAgICBuaXRlcnMgPSAwLFxuICAgICAgICAgICAgICAgIHZib3g7XG4gICAgICAgICAgICB3aGlsZSAobml0ZXJzIDwgbWF4SXRlcmF0aW9ucykge1xuICAgICAgICAgICAgICAgIHZib3ggPSBsaC5wb3AoKTtcbiAgICAgICAgICAgICAgICBpZiAoIXZib3guY291bnQoKSkgeyAvKiBqdXN0IHB1dCBpdCBiYWNrICovXG4gICAgICAgICAgICAgICAgICAgIGxoLnB1c2godmJveCk7XG4gICAgICAgICAgICAgICAgICAgIG5pdGVycysrO1xuICAgICAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gZG8gdGhlIGN1dFxuICAgICAgICAgICAgICAgIHZhciB2Ym94ZXMgPSBtZWRpYW5DdXRBcHBseShoaXN0bywgdmJveCksXG4gICAgICAgICAgICAgICAgICAgIHZib3gxID0gdmJveGVzWzBdLFxuICAgICAgICAgICAgICAgICAgICB2Ym94MiA9IHZib3hlc1sxXTtcblxuICAgICAgICAgICAgICAgIGlmICghdmJveDEpIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gY29uc29sZS5sb2coXCJ2Ym94MSBub3QgZGVmaW5lZDsgc2hvdWxkbid0IGhhcHBlbiFcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgbGgucHVzaCh2Ym94MSk7XG4gICAgICAgICAgICAgICAgaWYgKHZib3gyKSB7IC8qIHZib3gyIGNhbiBiZSBudWxsICovXG4gICAgICAgICAgICAgICAgICAgIGxoLnB1c2godmJveDIpO1xuICAgICAgICAgICAgICAgICAgICBuY29sb3JzKys7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmIChuY29sb3JzID49IHRhcmdldCkgcmV0dXJuO1xuICAgICAgICAgICAgICAgIGlmIChuaXRlcnMrKyA+IG1heEl0ZXJhdGlvbnMpIHtcbiAgICAgICAgICAgICAgICAgICAgLy8gY29uc29sZS5sb2coXCJpbmZpbml0ZSBsb29wOyBwZXJoYXBzIHRvbyBmZXcgcGl4ZWxzIVwiKTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIGZpcnN0IHNldCBvZiBjb2xvcnMsIHNvcnRlZCBieSBwb3B1bGF0aW9uXG4gICAgICAgIGl0ZXIocHEsIGZyYWN0QnlQb3B1bGF0aW9ucyAqIG1heGNvbG9ycyk7XG4gICAgICAgIC8vIGNvbnNvbGUubG9nKHBxLnNpemUoKSwgcHEuZGVidWcoKS5sZW5ndGgsIHBxLmRlYnVnKCkuc2xpY2UoKSk7XG5cbiAgICAgICAgLy8gUmUtc29ydCBieSB0aGUgcHJvZHVjdCBvZiBwaXhlbCBvY2N1cGFuY3kgdGltZXMgdGhlIHNpemUgaW4gY29sb3Igc3BhY2UuXG4gICAgICAgIHZhciBwcTIgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiBwdi5uYXR1cmFsT3JkZXIoYS5jb3VudCgpICogYS52b2x1bWUoKSwgYi5jb3VudCgpICogYi52b2x1bWUoKSlcbiAgICAgICAgfSk7XG4gICAgICAgIHdoaWxlIChwcS5zaXplKCkpIHtcbiAgICAgICAgICAgIHBxMi5wdXNoKHBxLnBvcCgpKTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIG5leHQgc2V0IC0gZ2VuZXJhdGUgdGhlIG1lZGlhbiBjdXRzIHVzaW5nIHRoZSAobnBpeCAqIHZvbCkgc29ydGluZy5cbiAgICAgICAgaXRlcihwcTIsIG1heGNvbG9ycyAtIHBxMi5zaXplKCkpO1xuXG4gICAgICAgIC8vIGNhbGN1bGF0ZSB0aGUgYWN0dWFsIGNvbG9yc1xuICAgICAgICB2YXIgY21hcCA9IG5ldyBDTWFwKCk7XG4gICAgICAgIHdoaWxlIChwcTIuc2l6ZSgpKSB7XG4gICAgICAgICAgICBjbWFwLnB1c2gocHEyLnBvcCgpKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJldHVybiBjbWFwO1xuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICAgIHF1YW50aXplOiBxdWFudGl6ZVxuICAgIH1cbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzID0gTU1DUS5xdWFudGl6ZVxuIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbid1c2Ugc3RyaWN0JztcblxuLy8gSWYgb2JqLmhhc093blByb3BlcnR5IGhhcyBiZWVuIG92ZXJyaWRkZW4sIHRoZW4gY2FsbGluZ1xuLy8gb2JqLmhhc093blByb3BlcnR5KHByb3ApIHdpbGwgYnJlYWsuXG4vLyBTZWU6IGh0dHBzOi8vZ2l0aHViLmNvbS9qb3llbnQvbm9kZS9pc3N1ZXMvMTcwN1xuZnVuY3Rpb24gaGFzT3duUHJvcGVydHkob2JqLCBwcm9wKSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBwcm9wKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihxcywgc2VwLCBlcSwgb3B0aW9ucykge1xuICBzZXAgPSBzZXAgfHwgJyYnO1xuICBlcSA9IGVxIHx8ICc9JztcbiAgdmFyIG9iaiA9IHt9O1xuXG4gIGlmICh0eXBlb2YgcXMgIT09ICdzdHJpbmcnIHx8IHFzLmxlbmd0aCA9PT0gMCkge1xuICAgIHJldHVybiBvYmo7XG4gIH1cblxuICB2YXIgcmVnZXhwID0gL1xcKy9nO1xuICBxcyA9IHFzLnNwbGl0KHNlcCk7XG5cbiAgdmFyIG1heEtleXMgPSAxMDAwO1xuICBpZiAob3B0aW9ucyAmJiB0eXBlb2Ygb3B0aW9ucy5tYXhLZXlzID09PSAnbnVtYmVyJykge1xuICAgIG1heEtleXMgPSBvcHRpb25zLm1heEtleXM7XG4gIH1cblxuICB2YXIgbGVuID0gcXMubGVuZ3RoO1xuICAvLyBtYXhLZXlzIDw9IDAgbWVhbnMgdGhhdCB3ZSBzaG91bGQgbm90IGxpbWl0IGtleXMgY291bnRcbiAgaWYgKG1heEtleXMgPiAwICYmIGxlbiA+IG1heEtleXMpIHtcbiAgICBsZW4gPSBtYXhLZXlzO1xuICB9XG5cbiAgZm9yICh2YXIgaSA9IDA7IGkgPCBsZW47ICsraSkge1xuICAgIHZhciB4ID0gcXNbaV0ucmVwbGFjZShyZWdleHAsICclMjAnKSxcbiAgICAgICAgaWR4ID0geC5pbmRleE9mKGVxKSxcbiAgICAgICAga3N0ciwgdnN0ciwgaywgdjtcblxuICAgIGlmIChpZHggPj0gMCkge1xuICAgICAga3N0ciA9IHguc3Vic3RyKDAsIGlkeCk7XG4gICAgICB2c3RyID0geC5zdWJzdHIoaWR4ICsgMSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGtzdHIgPSB4O1xuICAgICAgdnN0ciA9ICcnO1xuICAgIH1cblxuICAgIGsgPSBkZWNvZGVVUklDb21wb25lbnQoa3N0cik7XG4gICAgdiA9IGRlY29kZVVSSUNvbXBvbmVudCh2c3RyKTtcblxuICAgIGlmICghaGFzT3duUHJvcGVydHkob2JqLCBrKSkge1xuICAgICAgb2JqW2tdID0gdjtcbiAgICB9IGVsc2UgaWYgKGlzQXJyYXkob2JqW2tdKSkge1xuICAgICAgb2JqW2tdLnB1c2godik7XG4gICAgfSBlbHNlIHtcbiAgICAgIG9ialtrXSA9IFtvYmpba10sIHZdO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBvYmo7XG59O1xuXG52YXIgaXNBcnJheSA9IEFycmF5LmlzQXJyYXkgfHwgZnVuY3Rpb24gKHhzKSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoeHMpID09PSAnW29iamVjdCBBcnJheV0nO1xufTtcbiIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG4ndXNlIHN0cmljdCc7XG5cbnZhciBzdHJpbmdpZnlQcmltaXRpdmUgPSBmdW5jdGlvbih2KSB7XG4gIHN3aXRjaCAodHlwZW9mIHYpIHtcbiAgICBjYXNlICdzdHJpbmcnOlxuICAgICAgcmV0dXJuIHY7XG5cbiAgICBjYXNlICdib29sZWFuJzpcbiAgICAgIHJldHVybiB2ID8gJ3RydWUnIDogJ2ZhbHNlJztcblxuICAgIGNhc2UgJ251bWJlcic6XG4gICAgICByZXR1cm4gaXNGaW5pdGUodikgPyB2IDogJyc7XG5cbiAgICBkZWZhdWx0OlxuICAgICAgcmV0dXJuICcnO1xuICB9XG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uKG9iaiwgc2VwLCBlcSwgbmFtZSkge1xuICBzZXAgPSBzZXAgfHwgJyYnO1xuICBlcSA9IGVxIHx8ICc9JztcbiAgaWYgKG9iaiA9PT0gbnVsbCkge1xuICAgIG9iaiA9IHVuZGVmaW5lZDtcbiAgfVxuXG4gIGlmICh0eXBlb2Ygb2JqID09PSAnb2JqZWN0Jykge1xuICAgIHJldHVybiBtYXAob2JqZWN0S2V5cyhvYmopLCBmdW5jdGlvbihrKSB7XG4gICAgICB2YXIga3MgPSBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKGspKSArIGVxO1xuICAgICAgaWYgKGlzQXJyYXkob2JqW2tdKSkge1xuICAgICAgICByZXR1cm4gbWFwKG9ialtrXSwgZnVuY3Rpb24odikge1xuICAgICAgICAgIHJldHVybiBrcyArIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUodikpO1xuICAgICAgICB9KS5qb2luKHNlcCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4ga3MgKyBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKG9ialtrXSkpO1xuICAgICAgfVxuICAgIH0pLmpvaW4oc2VwKTtcblxuICB9XG5cbiAgaWYgKCFuYW1lKSByZXR1cm4gJyc7XG4gIHJldHVybiBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKG5hbWUpKSArIGVxICtcbiAgICAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzdHJpbmdpZnlQcmltaXRpdmUob2JqKSk7XG59O1xuXG52YXIgaXNBcnJheSA9IEFycmF5LmlzQXJyYXkgfHwgZnVuY3Rpb24gKHhzKSB7XG4gIHJldHVybiBPYmplY3QucHJvdG90eXBlLnRvU3RyaW5nLmNhbGwoeHMpID09PSAnW29iamVjdCBBcnJheV0nO1xufTtcblxuZnVuY3Rpb24gbWFwICh4cywgZikge1xuICBpZiAoeHMubWFwKSByZXR1cm4geHMubWFwKGYpO1xuICB2YXIgcmVzID0gW107XG4gIGZvciAodmFyIGkgPSAwOyBpIDwgeHMubGVuZ3RoOyBpKyspIHtcbiAgICByZXMucHVzaChmKHhzW2ldLCBpKSk7XG4gIH1cbiAgcmV0dXJuIHJlcztcbn1cblxudmFyIG9iamVjdEtleXMgPSBPYmplY3Qua2V5cyB8fCBmdW5jdGlvbiAob2JqKSB7XG4gIHZhciByZXMgPSBbXTtcbiAgZm9yICh2YXIga2V5IGluIG9iaikge1xuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqLCBrZXkpKSByZXMucHVzaChrZXkpO1xuICB9XG4gIHJldHVybiByZXM7XG59O1xuIiwiJ3VzZSBzdHJpY3QnO1xuXG5leHBvcnRzLmRlY29kZSA9IGV4cG9ydHMucGFyc2UgPSByZXF1aXJlKCcuL2RlY29kZScpO1xuZXhwb3J0cy5lbmNvZGUgPSBleHBvcnRzLnN0cmluZ2lmeSA9IHJlcXVpcmUoJy4vZW5jb2RlJyk7XG4iLCJ2YXIgVmlicmFudDtcblxuVmlicmFudCA9IHJlcXVpcmUoJy4vdmlicmFudCcpO1xuXG5WaWJyYW50LkRlZmF1bHRPcHRzLkltYWdlID0gcmVxdWlyZSgnLi9pbWFnZS9icm93c2VyJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gVmlicmFudDtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdlluSnZkM05sY2k1amIyWm1aV1VpTENKemIzVnlZMlZTYjI5MElqb2lJaXdpYzI5MWNtTmxjeUk2V3lJdlZYTmxjbk12WXpRdlJHOWpkVzFsYm5SekwxQnliMnBsWTNSekwzTmxiR3hsYnk5dWIyUmxMV3h2WjI4dFkyOXNiM0p6TDNOeVl5OWljbTkzYzJWeUxtTnZabVpsWlNKZExDSnVZVzFsY3lJNlcxMHNJbTFoY0hCcGJtZHpJam9pUVVGQlFTeEpRVUZCT3p0QlFVRkJMRTlCUVVFc1IwRkJWU3hQUVVGQkxFTkJRVkVzVjBGQlVqczdRVUZEVml4UFFVRlBMRU5CUVVNc1YwRkJWeXhEUVVGRExFdEJRWEJDTEVkQlFUUkNMRTlCUVVFc1EwRkJVU3hwUWtGQlVqczdRVUZGTlVJc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGQmFVSWlmUT09XG4iLCJ2YXIgVmlicmFudDtcblxud2luZG93LlZpYnJhbnQgPSBWaWJyYW50ID0gcmVxdWlyZSgnLi9icm93c2VyJyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZZblZ1Wkd4bExtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMMkoxYm1Sc1pTNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNTVUZCUVRzN1FVRkJRU3hOUVVGTkxFTkJRVU1zVDBGQlVDeEhRVUZwUWl4UFFVRkJMRWRCUVZVc1QwRkJRU3hEUVVGUkxGZEJRVklpZlE9PVxuIiwibW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihyLCBnLCBiLCBhKSB7XG4gIHJldHVybiBhID49IDEyNSAmJiAhKHIgPiAyNTAgJiYgZyA+IDI1MCAmJiBiID4gMjUwKTtcbn07XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZabWxzZEdWeUwyUmxabUYxYkhRdVkyOW1abVZsSWl3aWMyOTFjbU5sVW05dmRDSTZJaUlzSW5OdmRYSmpaWE1pT2xzaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZabWxzZEdWeUwyUmxabUYxYkhRdVkyOW1abVZsSWwwc0ltNWhiV1Z6SWpwYlhTd2liV0Z3Y0dsdVozTWlPaUpCUVVGQkxFMUJRVTBzUTBGQlF5eFBRVUZRTEVkQlFXbENMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTEVWQlFWVXNRMEZCVmp0VFFVTm1MRU5CUVVFc1NVRkJTeXhIUVVGTUxFbEJRV0VzUTBGQlNTeERRVUZETEVOQlFVRXNSMEZCU1N4SFFVRktMRWxCUVZrc1EwRkJRU3hIUVVGSkxFZEJRV2hDTEVsQlFYZENMRU5CUVVFc1IwRkJTU3hIUVVFM1FqdEJRVVJHSW4wPVxuIiwibW9kdWxlLmV4cG9ydHMuRGVmYXVsdCA9IHJlcXVpcmUoJy4vZGVmYXVsdCcpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Wm1sc2RHVnlMMmx1WkdWNExtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMMlpwYkhSbGNpOXBibVJsZUM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eFBRVUZtTEVkQlFYbENMRTlCUVVFc1EwRkJVU3hYUVVGU0luMD1cbiIsInZhciBEZWZhdWx0R2VuZXJhdG9yLCBEZWZhdWx0T3B0cywgR2VuZXJhdG9yLCBTd2F0Y2gsIHV0aWwsXG4gIGV4dGVuZCA9IGZ1bmN0aW9uKGNoaWxkLCBwYXJlbnQpIHsgZm9yICh2YXIga2V5IGluIHBhcmVudCkgeyBpZiAoaGFzUHJvcC5jYWxsKHBhcmVudCwga2V5KSkgY2hpbGRba2V5XSA9IHBhcmVudFtrZXldOyB9IGZ1bmN0aW9uIGN0b3IoKSB7IHRoaXMuY29uc3RydWN0b3IgPSBjaGlsZDsgfSBjdG9yLnByb3RvdHlwZSA9IHBhcmVudC5wcm90b3R5cGU7IGNoaWxkLnByb3RvdHlwZSA9IG5ldyBjdG9yKCk7IGNoaWxkLl9fc3VwZXJfXyA9IHBhcmVudC5wcm90b3R5cGU7IHJldHVybiBjaGlsZDsgfSxcbiAgaGFzUHJvcCA9IHt9Lmhhc093blByb3BlcnR5LFxuICBzbGljZSA9IFtdLnNsaWNlO1xuXG5Td2F0Y2ggPSByZXF1aXJlKCcuLi9zd2F0Y2gnKTtcblxudXRpbCA9IHJlcXVpcmUoJy4uL3V0aWwnKTtcblxuR2VuZXJhdG9yID0gcmVxdWlyZSgnLi9pbmRleCcpO1xuXG5EZWZhdWx0T3B0cyA9IHtcbiAgdGFyZ2V0RGFya0x1bWE6IDAuMjYsXG4gIG1heERhcmtMdW1hOiAwLjQ1LFxuICBtaW5MaWdodEx1bWE6IDAuNTUsXG4gIHRhcmdldExpZ2h0THVtYTogMC43NCxcbiAgbWluTm9ybWFsTHVtYTogMC4zLFxuICB0YXJnZXROb3JtYWxMdW1hOiAwLjUsXG4gIG1heE5vcm1hbEx1bWE6IDAuNyxcbiAgdGFyZ2V0TXV0ZXNTYXR1cmF0aW9uOiAwLjMsXG4gIG1heE11dGVzU2F0dXJhdGlvbjogMC40LFxuICB0YXJnZXRWaWJyYW50U2F0dXJhdGlvbjogMS4wLFxuICBtaW5WaWJyYW50U2F0dXJhdGlvbjogMC4zNSxcbiAgd2VpZ2h0U2F0dXJhdGlvbjogMyxcbiAgd2VpZ2h0THVtYTogNixcbiAgd2VpZ2h0UG9wdWxhdGlvbjogMVxufTtcblxubW9kdWxlLmV4cG9ydHMgPSBEZWZhdWx0R2VuZXJhdG9yID0gKGZ1bmN0aW9uKHN1cGVyQ2xhc3MpIHtcbiAgZXh0ZW5kKERlZmF1bHRHZW5lcmF0b3IsIHN1cGVyQ2xhc3MpO1xuXG4gIGZ1bmN0aW9uIERlZmF1bHRHZW5lcmF0b3Iob3B0cykge1xuICAgIHRoaXMub3B0cyA9IHV0aWwuZGVmYXVsdHMob3B0cywgRGVmYXVsdE9wdHMpO1xuICAgIHRoaXMuVmlicmFudFN3YXRjaCA9IG51bGw7XG4gICAgdGhpcy5MaWdodFZpYnJhbnRTd2F0Y2ggPSBudWxsO1xuICAgIHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggPSBudWxsO1xuICAgIHRoaXMuTXV0ZWRTd2F0Y2ggPSBudWxsO1xuICAgIHRoaXMuTGlnaHRNdXRlZFN3YXRjaCA9IG51bGw7XG4gICAgdGhpcy5EYXJrTXV0ZWRTd2F0Y2ggPSBudWxsO1xuICB9XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2VuZXJhdGUgPSBmdW5jdGlvbihzd2F0Y2hlcykge1xuICAgIHRoaXMuc3dhdGNoZXMgPSBzd2F0Y2hlcztcbiAgICB0aGlzLm1heFBvcHVsYXRpb24gPSB0aGlzLmZpbmRNYXhQb3B1bGF0aW9uKCk7XG4gICAgdGhpcy5nZW5lcmF0ZVZhcmF0aW9uQ29sb3JzKCk7XG4gICAgcmV0dXJuIHRoaXMuZ2VuZXJhdGVFbXB0eVN3YXRjaGVzKCk7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0VmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLlZpYnJhbnRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TGlnaHRWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuTGlnaHRWaWJyYW50U3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldERhcmtWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5NdXRlZFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXRMaWdodE11dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuTGlnaHRNdXRlZFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXREYXJrTXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5EYXJrTXV0ZWRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2VuZXJhdGVWYXJhdGlvbkNvbG9ycyA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuVmlicmFudFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXROb3JtYWxMdW1hLCB0aGlzLm9wdHMubWluTm9ybWFsTHVtYSwgdGhpcy5vcHRzLm1heE5vcm1hbEx1bWEsIHRoaXMub3B0cy50YXJnZXRWaWJyYW50U2F0dXJhdGlvbiwgdGhpcy5vcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcbiAgICB0aGlzLkxpZ2h0VmlicmFudFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXRMaWdodEx1bWEsIHRoaXMub3B0cy5taW5MaWdodEx1bWEsIDEsIHRoaXMub3B0cy50YXJnZXRWaWJyYW50U2F0dXJhdGlvbiwgdGhpcy5vcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcbiAgICB0aGlzLkRhcmtWaWJyYW50U3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldERhcmtMdW1hLCAwLCB0aGlzLm9wdHMubWF4RGFya0x1bWEsIHRoaXMub3B0cy50YXJnZXRWaWJyYW50U2F0dXJhdGlvbiwgdGhpcy5vcHRzLm1pblZpYnJhbnRTYXR1cmF0aW9uLCAxKTtcbiAgICB0aGlzLk11dGVkU3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldE5vcm1hbEx1bWEsIHRoaXMub3B0cy5taW5Ob3JtYWxMdW1hLCB0aGlzLm9wdHMubWF4Tm9ybWFsTHVtYSwgdGhpcy5vcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgdGhpcy5vcHRzLm1heE11dGVzU2F0dXJhdGlvbik7XG4gICAgdGhpcy5MaWdodE11dGVkU3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldExpZ2h0THVtYSwgdGhpcy5vcHRzLm1pbkxpZ2h0THVtYSwgMSwgdGhpcy5vcHRzLnRhcmdldE11dGVzU2F0dXJhdGlvbiwgMCwgdGhpcy5vcHRzLm1heE11dGVzU2F0dXJhdGlvbik7XG4gICAgcmV0dXJuIHRoaXMuRGFya011dGVkU3dhdGNoID0gdGhpcy5maW5kQ29sb3JWYXJpYXRpb24odGhpcy5vcHRzLnRhcmdldERhcmtMdW1hLCAwLCB0aGlzLm9wdHMubWF4RGFya0x1bWEsIHRoaXMub3B0cy50YXJnZXRNdXRlc1NhdHVyYXRpb24sIDAsIHRoaXMub3B0cy5tYXhNdXRlc1NhdHVyYXRpb24pO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdlbmVyYXRlRW1wdHlTd2F0Y2hlcyA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBoc2w7XG4gICAgaWYgKHRoaXMuVmlicmFudFN3YXRjaCA9PT0gbnVsbCkge1xuICAgICAgaWYgKHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggIT09IG51bGwpIHtcbiAgICAgICAgaHNsID0gdGhpcy5EYXJrVmlicmFudFN3YXRjaC5nZXRIc2woKTtcbiAgICAgICAgaHNsWzJdID0gdGhpcy5vcHRzLnRhcmdldE5vcm1hbEx1bWE7XG4gICAgICAgIHRoaXMuVmlicmFudFN3YXRjaCA9IG5ldyBTd2F0Y2godXRpbC5oc2xUb1JnYihoc2xbMF0sIGhzbFsxXSwgaHNsWzJdKSwgMCk7XG4gICAgICB9XG4gICAgfVxuICAgIGlmICh0aGlzLkRhcmtWaWJyYW50U3dhdGNoID09PSBudWxsKSB7XG4gICAgICBpZiAodGhpcy5WaWJyYW50U3dhdGNoICE9PSBudWxsKSB7XG4gICAgICAgIGhzbCA9IHRoaXMuVmlicmFudFN3YXRjaC5nZXRIc2woKTtcbiAgICAgICAgaHNsWzJdID0gdGhpcy5vcHRzLnRhcmdldERhcmtMdW1hO1xuICAgICAgICByZXR1cm4gdGhpcy5EYXJrVmlicmFudFN3YXRjaCA9IG5ldyBTd2F0Y2godXRpbC5oc2xUb1JnYihoc2xbMF0sIGhzbFsxXSwgaHNsWzJdKSwgMCk7XG4gICAgICB9XG4gICAgfVxuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmZpbmRNYXhQb3B1bGF0aW9uID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGosIGxlbiwgcG9wdWxhdGlvbiwgcmVmLCBzd2F0Y2g7XG4gICAgcG9wdWxhdGlvbiA9IDA7XG4gICAgcmVmID0gdGhpcy5zd2F0Y2hlcztcbiAgICBmb3IgKGogPSAwLCBsZW4gPSByZWYubGVuZ3RoOyBqIDwgbGVuOyBqKyspIHtcbiAgICAgIHN3YXRjaCA9IHJlZltqXTtcbiAgICAgIHBvcHVsYXRpb24gPSBNYXRoLm1heChwb3B1bGF0aW9uLCBzd2F0Y2guZ2V0UG9wdWxhdGlvbigpKTtcbiAgICB9XG4gICAgcmV0dXJuIHBvcHVsYXRpb247XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZmluZENvbG9yVmFyaWF0aW9uID0gZnVuY3Rpb24odGFyZ2V0THVtYSwgbWluTHVtYSwgbWF4THVtYSwgdGFyZ2V0U2F0dXJhdGlvbiwgbWluU2F0dXJhdGlvbiwgbWF4U2F0dXJhdGlvbikge1xuICAgIHZhciBqLCBsZW4sIGx1bWEsIG1heCwgbWF4VmFsdWUsIHJlZiwgc2F0LCBzd2F0Y2gsIHZhbHVlO1xuICAgIG1heCA9IG51bGw7XG4gICAgbWF4VmFsdWUgPSAwO1xuICAgIHJlZiA9IHRoaXMuc3dhdGNoZXM7XG4gICAgZm9yIChqID0gMCwgbGVuID0gcmVmLmxlbmd0aDsgaiA8IGxlbjsgaisrKSB7XG4gICAgICBzd2F0Y2ggPSByZWZbal07XG4gICAgICBzYXQgPSBzd2F0Y2guZ2V0SHNsKClbMV07XG4gICAgICBsdW1hID0gc3dhdGNoLmdldEhzbCgpWzJdO1xuICAgICAgaWYgKHNhdCA+PSBtaW5TYXR1cmF0aW9uICYmIHNhdCA8PSBtYXhTYXR1cmF0aW9uICYmIGx1bWEgPj0gbWluTHVtYSAmJiBsdW1hIDw9IG1heEx1bWEgJiYgIXRoaXMuaXNBbHJlYWR5U2VsZWN0ZWQoc3dhdGNoKSkge1xuICAgICAgICB2YWx1ZSA9IHRoaXMuY3JlYXRlQ29tcGFyaXNvblZhbHVlKHNhdCwgdGFyZ2V0U2F0dXJhdGlvbiwgbHVtYSwgdGFyZ2V0THVtYSwgc3dhdGNoLmdldFBvcHVsYXRpb24oKSwgdGhpcy5tYXhQb3B1bGF0aW9uKTtcbiAgICAgICAgaWYgKG1heCA9PT0gbnVsbCB8fCB2YWx1ZSA+IG1heFZhbHVlKSB7XG4gICAgICAgICAgbWF4ID0gc3dhdGNoO1xuICAgICAgICAgIG1heFZhbHVlID0gdmFsdWU7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG1heDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5jcmVhdGVDb21wYXJpc29uVmFsdWUgPSBmdW5jdGlvbihzYXR1cmF0aW9uLCB0YXJnZXRTYXR1cmF0aW9uLCBsdW1hLCB0YXJnZXRMdW1hLCBwb3B1bGF0aW9uLCBtYXhQb3B1bGF0aW9uKSB7XG4gICAgcmV0dXJuIHRoaXMud2VpZ2h0ZWRNZWFuKHRoaXMuaW52ZXJ0RGlmZihzYXR1cmF0aW9uLCB0YXJnZXRTYXR1cmF0aW9uKSwgdGhpcy5vcHRzLndlaWdodFNhdHVyYXRpb24sIHRoaXMuaW52ZXJ0RGlmZihsdW1hLCB0YXJnZXRMdW1hKSwgdGhpcy5vcHRzLndlaWdodEx1bWEsIHBvcHVsYXRpb24gLyBtYXhQb3B1bGF0aW9uLCB0aGlzLm9wdHMud2VpZ2h0UG9wdWxhdGlvbik7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuaW52ZXJ0RGlmZiA9IGZ1bmN0aW9uKHZhbHVlLCB0YXJnZXRWYWx1ZSkge1xuICAgIHJldHVybiAxIC0gTWF0aC5hYnModmFsdWUgLSB0YXJnZXRWYWx1ZSk7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUud2VpZ2h0ZWRNZWFuID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGksIHN1bSwgc3VtV2VpZ2h0LCB2YWx1ZSwgdmFsdWVzLCB3ZWlnaHQ7XG4gICAgdmFsdWVzID0gMSA8PSBhcmd1bWVudHMubGVuZ3RoID8gc2xpY2UuY2FsbChhcmd1bWVudHMsIDApIDogW107XG4gICAgc3VtID0gMDtcbiAgICBzdW1XZWlnaHQgPSAwO1xuICAgIGkgPSAwO1xuICAgIHdoaWxlIChpIDwgdmFsdWVzLmxlbmd0aCkge1xuICAgICAgdmFsdWUgPSB2YWx1ZXNbaV07XG4gICAgICB3ZWlnaHQgPSB2YWx1ZXNbaSArIDFdO1xuICAgICAgc3VtICs9IHZhbHVlICogd2VpZ2h0O1xuICAgICAgc3VtV2VpZ2h0ICs9IHdlaWdodDtcbiAgICAgIGkgKz0gMjtcbiAgICB9XG4gICAgcmV0dXJuIHN1bSAvIHN1bVdlaWdodDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5pc0FscmVhZHlTZWxlY3RlZCA9IGZ1bmN0aW9uKHN3YXRjaCkge1xuICAgIHJldHVybiB0aGlzLlZpYnJhbnRTd2F0Y2ggPT09IHN3YXRjaCB8fCB0aGlzLkRhcmtWaWJyYW50U3dhdGNoID09PSBzd2F0Y2ggfHwgdGhpcy5MaWdodFZpYnJhbnRTd2F0Y2ggPT09IHN3YXRjaCB8fCB0aGlzLk11dGVkU3dhdGNoID09PSBzd2F0Y2ggfHwgdGhpcy5EYXJrTXV0ZWRTd2F0Y2ggPT09IHN3YXRjaCB8fCB0aGlzLkxpZ2h0TXV0ZWRTd2F0Y2ggPT09IHN3YXRjaDtcbiAgfTtcblxuICByZXR1cm4gRGVmYXVsdEdlbmVyYXRvcjtcblxufSkoR2VuZXJhdG9yKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdloyVnVaWEpoZEc5eUwyUmxabUYxYkhRdVkyOW1abVZsSWl3aWMyOTFjbU5sVW05dmRDSTZJaUlzSW5OdmRYSmpaWE1pT2xzaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZaMlZ1WlhKaGRHOXlMMlJsWm1GMWJIUXVZMjltWm1WbElsMHNJbTVoYldWeklqcGJYU3dpYldGd2NHbHVaM01pT2lKQlFVRkJMRWxCUVVFc2MwUkJRVUU3UlVGQlFUczdPenRCUVVGQkxFMUJRVUVzUjBGQlV5eFBRVUZCTEVOQlFWRXNWMEZCVWpzN1FVRkRWQ3hKUVVGQkxFZEJRVThzVDBGQlFTeERRVUZSTEZOQlFWSTdPMEZCUTFBc1UwRkJRU3hIUVVGWkxFOUJRVUVzUTBGQlVTeFRRVUZTT3p0QlFVVmFMRmRCUVVFc1IwRkRSVHRGUVVGQkxHTkJRVUVzUlVGQlowSXNTVUZCYUVJN1JVRkRRU3hYUVVGQkxFVkJRV0VzU1VGRVlqdEZRVVZCTEZsQlFVRXNSVUZCWXl4SlFVWmtPMFZCUjBFc1pVRkJRU3hGUVVGcFFpeEpRVWhxUWp0RlFVbEJMR0ZCUVVFc1JVRkJaU3hIUVVwbU8wVkJTMEVzWjBKQlFVRXNSVUZCYTBJc1IwRk1iRUk3UlVGTlFTeGhRVUZCTEVWQlFXVXNSMEZPWmp0RlFVOUJMSEZDUVVGQkxFVkJRWFZDTEVkQlVIWkNPMFZCVVVFc2EwSkJRVUVzUlVGQmIwSXNSMEZTY0VJN1JVRlRRU3gxUWtGQlFTeEZRVUY1UWl4SFFWUjZRanRGUVZWQkxHOUNRVUZCTEVWQlFYTkNMRWxCVm5SQ08wVkJWMEVzWjBKQlFVRXNSVUZCYTBJc1EwRlliRUk3UlVGWlFTeFZRVUZCTEVWQlFWa3NRMEZhV2p0RlFXRkJMR2RDUVVGQkxFVkJRV3RDTEVOQllteENPenM3UVVGbFJpeE5RVUZOTEVOQlFVTXNUMEZCVUN4SFFVTk5PenM3UlVGRFV5d3dRa0ZCUXl4SlFVRkVPMGxCUTFnc1NVRkJReXhEUVVGQkxFbEJRVVFzUjBGQlVTeEpRVUZKTEVOQlFVTXNVVUZCVEN4RFFVRmpMRWxCUVdRc1JVRkJiMElzVjBGQmNFSTdTVUZEVWl4SlFVRkRMRU5CUVVFc1lVRkJSQ3hIUVVGcFFqdEpRVU5xUWl4SlFVRkRMRU5CUVVFc2EwSkJRVVFzUjBGQmMwSTdTVUZEZEVJc1NVRkJReXhEUVVGQkxHbENRVUZFTEVkQlFYRkNPMGxCUTNKQ0xFbEJRVU1zUTBGQlFTeFhRVUZFTEVkQlFXVTdTVUZEWml4SlFVRkRMRU5CUVVFc1owSkJRVVFzUjBGQmIwSTdTVUZEY0VJc1NVRkJReXhEUVVGQkxHVkJRVVFzUjBGQmJVSTdSVUZRVWpzN05rSkJVMklzVVVGQlFTeEhRVUZWTEZOQlFVTXNVVUZCUkR0SlFVRkRMRWxCUVVNc1EwRkJRU3hYUVVGRU8wbEJRMVFzU1VGQlF5eERRVUZCTEdGQlFVUXNSMEZCYVVJc1NVRkJReXhEUVVGQkxHbENRVUZFTEVOQlFVRTdTVUZGYWtJc1NVRkJReXhEUVVGQkxITkNRVUZFTEVOQlFVRTdWMEZEUVN4SlFVRkRMRU5CUVVFc2NVSkJRVVFzUTBGQlFUdEZRVXBST3pzMlFrRk5WaXhuUWtGQlFTeEhRVUZyUWl4VFFVRkJPMWRCUTJoQ0xFbEJRVU1zUTBGQlFUdEZRVVJsT3pzMlFrRkhiRUlzY1VKQlFVRXNSMEZCZFVJc1UwRkJRVHRYUVVOeVFpeEpRVUZETEVOQlFVRTdSVUZFYjBJN096WkNRVWQyUWl4dlFrRkJRU3hIUVVGelFpeFRRVUZCTzFkQlEzQkNMRWxCUVVNc1EwRkJRVHRGUVVSdFFqczdOa0pCUjNSQ0xHTkJRVUVzUjBGQlowSXNVMEZCUVR0WFFVTmtMRWxCUVVNc1EwRkJRVHRGUVVSaE96czJRa0ZIYUVJc2JVSkJRVUVzUjBGQmNVSXNVMEZCUVR0WFFVTnVRaXhKUVVGRExFTkJRVUU3UlVGRWEwSTdPelpDUVVkeVFpeHJRa0ZCUVN4SFFVRnZRaXhUUVVGQk8xZEJRMnhDTEVsQlFVTXNRMEZCUVR0RlFVUnBRanM3TmtKQlIzQkNMSE5DUVVGQkxFZEJRWGRDTEZOQlFVRTdTVUZEZEVJc1NVRkJReXhEUVVGQkxHRkJRVVFzUjBGQmFVSXNTVUZCUXl4RFFVRkJMR3RDUVVGRUxFTkJRVzlDTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1owSkJRVEZDTEVWQlFUUkRMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zWVVGQmJFUXNSVUZCYVVVc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eGhRVUYyUlN4RlFVTm1MRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zZFVKQlJGTXNSVUZEWjBJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eHZRa0ZFZEVJc1JVRkRORU1zUTBGRU5VTTdTVUZIYWtJc1NVRkJReXhEUVVGQkxHdENRVUZFTEVkQlFYTkNMRWxCUVVNc1EwRkJRU3hyUWtGQlJDeERRVUZ2UWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHVkJRVEZDTEVWQlFUSkRMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zV1VGQmFrUXNSVUZCSzBRc1EwRkJMMFFzUlVGRGNFSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXgxUWtGRVl5eEZRVU5YTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2IwSkJSR3BDTEVWQlEzVkRMRU5CUkhaRE8wbEJSM1JDTEVsQlFVTXNRMEZCUVN4cFFrRkJSQ3hIUVVGeFFpeEpRVUZETEVOQlFVRXNhMEpCUVVRc1EwRkJiMElzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4alFVRXhRaXhGUVVFd1F5eERRVUV4UXl4RlFVRTJReXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEZkQlFXNUVMRVZCUTI1Q0xFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNkVUpCUkdFc1JVRkRXU3hKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEc5Q1FVUnNRaXhGUVVOM1F5eERRVVI0UXp0SlFVZHlRaXhKUVVGRExFTkJRVUVzVjBGQlJDeEhRVUZsTEVsQlFVTXNRMEZCUVN4clFrRkJSQ3hEUVVGdlFpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR2RDUVVFeFFpeEZRVUUwUXl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHRkJRV3hFTEVWQlFXbEZMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zWVVGQmRrVXNSVUZEWWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExIRkNRVVJQTEVWQlEyZENMRU5CUkdoQ0xFVkJRMjFDTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2EwSkJSSHBDTzBsQlIyWXNTVUZCUXl4RFFVRkJMR2RDUVVGRUxFZEJRVzlDTEVsQlFVTXNRMEZCUVN4clFrRkJSQ3hEUVVGdlFpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR1ZCUVRGQ0xFVkJRVEpETEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1dVRkJha1FzUlVGQkswUXNRMEZCTDBRc1JVRkRiRUlzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4eFFrRkVXU3hGUVVOWExFTkJSRmdzUlVGRFl5eEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR3RDUVVSd1FqdFhRVWR3UWl4SlFVRkRMRU5CUVVFc1pVRkJSQ3hIUVVGdFFpeEpRVUZETEVOQlFVRXNhMEpCUVVRc1EwRkJiMElzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4alFVRXhRaXhGUVVFd1F5eERRVUV4UXl4RlFVRTJReXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEZkQlFXNUVMRVZCUTJwQ0xFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNjVUpCUkZjc1JVRkRXU3hEUVVSYUxFVkJRMlVzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4clFrRkVja0k3UlVGb1FrYzdPelpDUVcxQ2VFSXNjVUpCUVVFc1IwRkJkVUlzVTBGQlFUdEJRVU55UWl4UlFVRkJPMGxCUVVFc1NVRkJSeXhKUVVGRExFTkJRVUVzWVVGQlJDeExRVUZyUWl4SlFVRnlRanROUVVWRkxFbEJRVWNzU1VGQlF5eERRVUZCTEdsQ1FVRkVMRXRCUVhkQ0xFbEJRVE5DTzFGQlJVVXNSMEZCUVN4SFFVRk5MRWxCUVVNc1EwRkJRU3hwUWtGQmFVSXNRMEZCUXl4TlFVRnVRaXhEUVVGQk8xRkJRMDRzUjBGQlNTeERRVUZCTEVOQlFVRXNRMEZCU2l4SFFVRlRMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU03VVVGRFppeEpRVUZETEVOQlFVRXNZVUZCUkN4SFFVRnBRaXhKUVVGSkxFMUJRVW9zUTBGQlZ5eEpRVUZKTEVOQlFVTXNVVUZCVEN4RFFVRmpMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRV3hDTEVWQlFYTkNMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRVEZDTEVWQlFUaENMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRV3hETEVOQlFWZ3NSVUZCYTBRc1EwRkJiRVFzUlVGS2JrSTdUMEZHUmpzN1NVRlJRU3hKUVVGSExFbEJRVU1zUTBGQlFTeHBRa0ZCUkN4TFFVRnpRaXhKUVVGNlFqdE5RVVZGTEVsQlFVY3NTVUZCUXl4RFFVRkJMR0ZCUVVRc1MwRkJiMElzU1VGQmRrSTdVVUZGUlN4SFFVRkJMRWRCUVUwc1NVRkJReXhEUVVGQkxHRkJRV0VzUTBGQlF5eE5RVUZtTEVOQlFVRTdVVUZEVGl4SFFVRkpMRU5CUVVFc1EwRkJRU3hEUVVGS0xFZEJRVk1zU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXp0bFFVTm1MRWxCUVVNc1EwRkJRU3hwUWtGQlJDeEhRVUZ4UWl4SlFVRkpMRTFCUVVvc1EwRkJWeXhKUVVGSkxFTkJRVU1zVVVGQlRDeERRVUZqTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVd4Q0xFVkJRWE5DTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVRGQ0xFVkJRVGhDTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVd4RExFTkJRVmdzUlVGQmEwUXNRMEZCYkVRc1JVRktka0k3VDBGR1JqczdSVUZVY1VJN096WkNRV2xDZGtJc2FVSkJRVUVzUjBGQmJVSXNVMEZCUVR0QlFVTnFRaXhSUVVGQk8wbEJRVUVzVlVGQlFTeEhRVUZoTzBGQlEySTdRVUZCUVN4VFFVRkJMSEZEUVVGQk96dE5RVUZCTEZWQlFVRXNSMEZCWVN4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExGVkJRVlFzUlVGQmNVSXNUVUZCVFN4RFFVRkRMR0ZCUVZBc1EwRkJRU3hEUVVGeVFqdEJRVUZpTzFkQlEwRTdSVUZJYVVJN096WkNRVXR1UWl4clFrRkJRU3hIUVVGdlFpeFRRVUZETEZWQlFVUXNSVUZCWVN4UFFVRmlMRVZCUVhOQ0xFOUJRWFJDTEVWQlFTdENMR2RDUVVFdlFpeEZRVUZwUkN4aFFVRnFSQ3hGUVVGblJTeGhRVUZvUlR0QlFVTnNRaXhSUVVGQk8wbEJRVUVzUjBGQlFTeEhRVUZOTzBsQlEwNHNVVUZCUVN4SFFVRlhPMEZCUlZnN1FVRkJRU3hUUVVGQkxIRkRRVUZCT3p0TlFVTkZMRWRCUVVFc1IwRkJUU3hOUVVGTkxFTkJRVU1zVFVGQlVDeERRVUZCTEVOQlFXZENMRU5CUVVFc1EwRkJRVHROUVVOMFFpeEpRVUZCTEVkQlFVOHNUVUZCVFN4RFFVRkRMRTFCUVZBc1EwRkJRU3hEUVVGblFpeERRVUZCTEVOQlFVRTdUVUZGZGtJc1NVRkJSeXhIUVVGQkxFbEJRVThzWVVGQlVDeEpRVUY1UWl4SFFVRkJMRWxCUVU4c1lVRkJhRU1zU1VGRFJDeEpRVUZCTEVsQlFWRXNUMEZFVUN4SlFVTnRRaXhKUVVGQkxFbEJRVkVzVDBGRU0wSXNTVUZGUkN4RFFVRkpMRWxCUVVNc1EwRkJRU3hwUWtGQlJDeERRVUZ0UWl4TlFVRnVRaXhEUVVaT08xRkJSMGtzUzBGQlFTeEhRVUZSTEVsQlFVTXNRMEZCUVN4eFFrRkJSQ3hEUVVGMVFpeEhRVUYyUWl4RlFVRTBRaXhuUWtGQk5VSXNSVUZCT0VNc1NVRkJPVU1zUlVGQmIwUXNWVUZCY0VRc1JVRkRUaXhOUVVGTkxFTkJRVU1zWVVGQlVDeERRVUZCTEVOQlJFMHNSVUZEYTBJc1NVRkJReXhEUVVGQkxHRkJSRzVDTzFGQlJWSXNTVUZCUnl4SFFVRkJMRXRCUVU4c1NVRkJVQ3hKUVVGbExFdEJRVUVzUjBGQlVTeFJRVUV4UWp0VlFVTkZMRWRCUVVFc1IwRkJUVHRWUVVOT0xGRkJRVUVzUjBGQlZ5eE5RVVppTzFOQlRFbzdPMEZCU2tZN1YwRmhRVHRGUVdwQ2EwSTdPelpDUVcxQ2NFSXNjVUpCUVVFc1IwRkJkVUlzVTBGQlF5eFZRVUZFTEVWQlFXRXNaMEpCUVdJc1JVRkRia0lzU1VGRWJVSXNSVUZEWWl4VlFVUmhMRVZCUTBRc1ZVRkVReXhGUVVOWExHRkJSRmc3VjBGRmNrSXNTVUZCUXl4RFFVRkJMRmxCUVVRc1EwRkRSU3hKUVVGRExFTkJRVUVzVlVGQlJDeERRVUZaTEZWQlFWb3NSVUZCZDBJc1owSkJRWGhDTEVOQlJFWXNSVUZETmtNc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eG5Ra0ZFYmtRc1JVRkZSU3hKUVVGRExFTkJRVUVzVlVGQlJDeERRVUZaTEVsQlFWb3NSVUZCYTBJc1ZVRkJiRUlzUTBGR1JpeEZRVVZwUXl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGVkJSblpETEVWQlIwVXNWVUZCUVN4SFFVRmhMR0ZCU0dZc1JVRkhPRUlzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4blFrRkljRU03UlVGR2NVSTdPelpDUVZGMlFpeFZRVUZCTEVkQlFWa3NVMEZCUXl4TFFVRkVMRVZCUVZFc1YwRkJVanRYUVVOV0xFTkJRVUVzUjBGQlNTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRXRCUVVFc1IwRkJVU3hYUVVGcVFqdEZRVVJOT3pzMlFrRkhXaXhaUVVGQkxFZEJRV01zVTBGQlFUdEJRVU5hTEZGQlFVRTdTVUZFWVR0SlFVTmlMRWRCUVVFc1IwRkJUVHRKUVVOT0xGTkJRVUVzUjBGQldUdEpRVU5hTEVOQlFVRXNSMEZCU1R0QlFVTktMRmRCUVUwc1EwRkJRU3hIUVVGSkxFMUJRVTBzUTBGQlF5eE5RVUZxUWp0TlFVTkZMRXRCUVVFc1IwRkJVU3hOUVVGUExFTkJRVUVzUTBGQlFUdE5RVU5tTEUxQlFVRXNSMEZCVXl4TlFVRlBMRU5CUVVFc1EwRkJRU3hIUVVGSkxFTkJRVW83VFVGRGFFSXNSMEZCUVN4SlFVRlBMRXRCUVVFc1IwRkJVVHROUVVObUxGTkJRVUVzU1VGQllUdE5RVU5pTEVOQlFVRXNTVUZCU3p0SlFVeFFPMWRCVFVFc1IwRkJRU3hIUVVGTk8wVkJWazA3T3paQ1FWbGtMR2xDUVVGQkxFZEJRVzFDTEZOQlFVTXNUVUZCUkR0WFFVTnFRaXhKUVVGRExFTkJRVUVzWVVGQlJDeExRVUZyUWl4TlFVRnNRaXhKUVVFMFFpeEpRVUZETEVOQlFVRXNhVUpCUVVRc1MwRkJjMElzVFVGQmJFUXNTVUZEUlN4SlFVRkRMRU5CUVVFc2EwSkJRVVFzUzBGQmRVSXNUVUZFZWtJc1NVRkRiVU1zU1VGQlF5eERRVUZCTEZkQlFVUXNTMEZCWjBJc1RVRkVia1FzU1VGRlJTeEpRVUZETEVOQlFVRXNaVUZCUkN4TFFVRnZRaXhOUVVaMFFpeEpRVVZuUXl4SlFVRkRMRU5CUVVFc1owSkJRVVFzUzBGQmNVSTdSVUZJY0VNN096czdSMEZ5U0ZVaWZRPT1cbiIsInZhciBHZW5lcmF0b3I7XG5cbm1vZHVsZS5leHBvcnRzID0gR2VuZXJhdG9yID0gKGZ1bmN0aW9uKCkge1xuICBmdW5jdGlvbiBHZW5lcmF0b3IoKSB7fVxuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2VuZXJhdGUgPSBmdW5jdGlvbihzd2F0Y2hlcykge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXRWaWJyYW50U3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldExpZ2h0VmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXREYXJrVmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXRNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXRMaWdodE11dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7fTtcblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdldERhcmtNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgcmV0dXJuIEdlbmVyYXRvcjtcblxufSkoKTtcblxubW9kdWxlLmV4cG9ydHMuRGVmYXVsdCA9IHJlcXVpcmUoJy4vZGVmYXVsdCcpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12WjJWdVpYSmhkRzl5TDJsdVpHVjRMbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDJkbGJtVnlZWFJ2Y2k5cGJtUmxlQzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzU1VGQlFUczdRVUZCUVN4TlFVRk5MRU5CUVVNc1QwRkJVQ3hIUVVOTk96czdjMEpCUTBvc1VVRkJRU3hIUVVGVkxGTkJRVU1zVVVGQlJDeEhRVUZCT3p0elFrRkZWaXhuUWtGQlFTeEhRVUZyUWl4VFFVRkJMRWRCUVVFN08zTkNRVVZzUWl4eFFrRkJRU3hIUVVGMVFpeFRRVUZCTEVkQlFVRTdPM05DUVVWMlFpeHZRa0ZCUVN4SFFVRnpRaXhUUVVGQkxFZEJRVUU3TzNOQ1FVVjBRaXhqUVVGQkxFZEJRV2RDTEZOQlFVRXNSMEZCUVRzN2MwSkJSV2hDTEcxQ1FVRkJMRWRCUVhGQ0xGTkJRVUVzUjBGQlFUczdjMEpCUlhKQ0xHdENRVUZCTEVkQlFXOUNMRk5CUVVFc1IwRkJRVHM3T3pzN08wRkJSWFJDTEUxQlFVMHNRMEZCUXl4UFFVRlBMRU5CUVVNc1QwRkJaaXhIUVVGNVFpeFBRVUZCTEVOQlFWRXNWMEZCVWlKOVxuIiwidmFyIEJyb3dzZXJJbWFnZSwgSW1hZ2UsIFVybCwgaXNSZWxhdGl2ZVVybCwgaXNTYW1lT3JpZ2luLFxuICBleHRlbmQgPSBmdW5jdGlvbihjaGlsZCwgcGFyZW50KSB7IGZvciAodmFyIGtleSBpbiBwYXJlbnQpIHsgaWYgKGhhc1Byb3AuY2FsbChwYXJlbnQsIGtleSkpIGNoaWxkW2tleV0gPSBwYXJlbnRba2V5XTsgfSBmdW5jdGlvbiBjdG9yKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gY2hpbGQ7IH0gY3Rvci5wcm90b3R5cGUgPSBwYXJlbnQucHJvdG90eXBlOyBjaGlsZC5wcm90b3R5cGUgPSBuZXcgY3RvcigpOyBjaGlsZC5fX3N1cGVyX18gPSBwYXJlbnQucHJvdG90eXBlOyByZXR1cm4gY2hpbGQ7IH0sXG4gIGhhc1Byb3AgPSB7fS5oYXNPd25Qcm9wZXJ0eTtcblxuSW1hZ2UgPSByZXF1aXJlKCcuL2luZGV4Jyk7XG5cblVybCA9IHJlcXVpcmUoJ3VybCcpO1xuXG5pc1JlbGF0aXZlVXJsID0gZnVuY3Rpb24odXJsKSB7XG4gIHZhciB1O1xuICB1ID0gVXJsLnBhcnNlKHVybCk7XG4gIHJldHVybiB1LnByb3RvY29sID09PSBudWxsICYmIHUuaG9zdCA9PT0gbnVsbCAmJiB1LnBvcnQgPT09IG51bGw7XG59O1xuXG5pc1NhbWVPcmlnaW4gPSBmdW5jdGlvbihhLCBiKSB7XG4gIHZhciB1YSwgdWI7XG4gIHVhID0gVXJsLnBhcnNlKGEpO1xuICB1YiA9IFVybC5wYXJzZShiKTtcbiAgcmV0dXJuIHVhLnByb3RvY29sID09PSB1Yi5wcm90b2NvbCAmJiB1YS5ob3N0bmFtZSA9PT0gdWIuaG9zdG5hbWUgJiYgdWEucG9ydCA9PT0gdWIucG9ydDtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gQnJvd3NlckltYWdlID0gKGZ1bmN0aW9uKHN1cGVyQ2xhc3MpIHtcbiAgZXh0ZW5kKEJyb3dzZXJJbWFnZSwgc3VwZXJDbGFzcyk7XG5cbiAgZnVuY3Rpb24gQnJvd3NlckltYWdlKHBhdGgsIGNiKSB7XG4gICAgaWYgKHR5cGVvZiBwYXRoID09PSAnb2JqZWN0JyAmJiBwYXRoIGluc3RhbmNlb2YgSFRNTEltYWdlRWxlbWVudCkge1xuICAgICAgdGhpcy5pbWcgPSBwYXRoO1xuICAgICAgcGF0aCA9IHRoaXMuaW1nLnNyYztcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5pbWcgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpbWcnKTtcbiAgICAgIHRoaXMuaW1nLnNyYyA9IHBhdGg7XG4gICAgfVxuICAgIGlmICghaXNSZWxhdGl2ZVVybChwYXRoKSAmJiAhaXNTYW1lT3JpZ2luKHdpbmRvdy5sb2NhdGlvbi5ocmVmLCBwYXRoKSkge1xuICAgICAgdGhpcy5pbWcuY3Jvc3NPcmlnaW4gPSAnYW5vbnltb3VzJztcbiAgICB9XG4gICAgdGhpcy5pbWcub25sb2FkID0gKGZ1bmN0aW9uKF90aGlzKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oKSB7XG4gICAgICAgIF90aGlzLl9pbml0Q2FudmFzKCk7XG4gICAgICAgIHJldHVybiB0eXBlb2YgY2IgPT09IFwiZnVuY3Rpb25cIiA/IGNiKG51bGwsIF90aGlzKSA6IHZvaWQgMDtcbiAgICAgIH07XG4gICAgfSkodGhpcyk7XG4gICAgaWYgKHRoaXMuaW1nLmNvbXBsZXRlKSB7XG4gICAgICB0aGlzLmltZy5vbmxvYWQoKTtcbiAgICB9XG4gICAgdGhpcy5pbWcub25lcnJvciA9IChmdW5jdGlvbihfdGhpcykge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKGUpIHtcbiAgICAgICAgdmFyIGVycjtcbiAgICAgICAgZXJyID0gbmV3IEVycm9yKFwiRmFpbCB0byBsb2FkIGltYWdlOiBcIiArIHBhdGgpO1xuICAgICAgICBlcnIucmF3ID0gZTtcbiAgICAgICAgcmV0dXJuIHR5cGVvZiBjYiA9PT0gXCJmdW5jdGlvblwiID8gY2IoZXJyKSA6IHZvaWQgMDtcbiAgICAgIH07XG4gICAgfSkodGhpcyk7XG4gIH1cblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLl9pbml0Q2FudmFzID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5jYW52YXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdjYW52YXMnKTtcbiAgICB0aGlzLmNvbnRleHQgPSB0aGlzLmNhbnZhcy5nZXRDb250ZXh0KCcyZCcpO1xuICAgIGRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQodGhpcy5jYW52YXMpO1xuICAgIHRoaXMud2lkdGggPSB0aGlzLmNhbnZhcy53aWR0aCA9IHRoaXMuaW1nLndpZHRoO1xuICAgIHRoaXMuaGVpZ2h0ID0gdGhpcy5jYW52YXMuaGVpZ2h0ID0gdGhpcy5pbWcuaGVpZ2h0O1xuICAgIHJldHVybiB0aGlzLmNvbnRleHQuZHJhd0ltYWdlKHRoaXMuaW1nLCAwLCAwLCB0aGlzLndpZHRoLCB0aGlzLmhlaWdodCk7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5jbGVhciA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmNvbnRleHQuY2xlYXJSZWN0KDAsIDAsIHRoaXMud2lkdGgsIHRoaXMuaGVpZ2h0KTtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLmdldFdpZHRoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMud2lkdGg7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5nZXRIZWlnaHQgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5oZWlnaHQ7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5yZXNpemUgPSBmdW5jdGlvbih3LCBoLCByKSB7XG4gICAgdGhpcy53aWR0aCA9IHRoaXMuY2FudmFzLndpZHRoID0gdztcbiAgICB0aGlzLmhlaWdodCA9IHRoaXMuY2FudmFzLmhlaWdodCA9IGg7XG4gICAgdGhpcy5jb250ZXh0LnNjYWxlKHIsIHIpO1xuICAgIHJldHVybiB0aGlzLmNvbnRleHQuZHJhd0ltYWdlKHRoaXMuaW1nLCAwLCAwKTtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLnVwZGF0ZSA9IGZ1bmN0aW9uKGltYWdlRGF0YSkge1xuICAgIHJldHVybiB0aGlzLmNvbnRleHQucHV0SW1hZ2VEYXRhKGltYWdlRGF0YSwgMCwgMCk7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5nZXRQaXhlbENvdW50ID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMud2lkdGggKiB0aGlzLmhlaWdodDtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLmdldEltYWdlRGF0YSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmNvbnRleHQuZ2V0SW1hZ2VEYXRhKDAsIDAsIHRoaXMud2lkdGgsIHRoaXMuaGVpZ2h0KTtcbiAgfTtcblxuICBCcm93c2VySW1hZ2UucHJvdG90eXBlLnJlbW92ZUNhbnZhcyA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmNhbnZhcy5wYXJlbnROb2RlLnJlbW92ZUNoaWxkKHRoaXMuY2FudmFzKTtcbiAgfTtcblxuICByZXR1cm4gQnJvd3NlckltYWdlO1xuXG59KShJbWFnZSk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZhVzFoWjJVdlluSnZkM05sY2k1amIyWm1aV1VpTENKemIzVnlZMlZTYjI5MElqb2lJaXdpYzI5MWNtTmxjeUk2V3lJdlZYTmxjbk12WXpRdlJHOWpkVzFsYm5SekwxQnliMnBsWTNSekwzTmxiR3hsYnk5dWIyUmxMV3h2WjI4dFkyOXNiM0p6TDNOeVl5OXBiV0ZuWlM5aWNtOTNjMlZ5TG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lRVUZCUVN4SlFVRkJMSEZFUVVGQk8wVkJRVUU3T3p0QlFVRkJMRXRCUVVFc1IwRkJVU3hQUVVGQkxFTkJRVkVzVTBGQlVqczdRVUZEVWl4SFFVRkJMRWRCUVUwc1QwRkJRU3hEUVVGUkxFdEJRVkk3TzBGQlJVNHNZVUZCUVN4SFFVRm5RaXhUUVVGRExFZEJRVVE3UVVGRFpDeE5RVUZCTzBWQlFVRXNRMEZCUVN4SFFVRkpMRWRCUVVjc1EwRkJReXhMUVVGS0xFTkJRVlVzUjBGQlZqdFRRVVZLTEVOQlFVTXNRMEZCUXl4UlFVRkdMRXRCUVdNc1NVRkJaQ3hKUVVGelFpeERRVUZETEVOQlFVTXNTVUZCUml4TFFVRlZMRWxCUVdoRExFbEJRWGRETEVOQlFVTXNRMEZCUXl4SlFVRkdMRXRCUVZVN1FVRkljRU03TzBGQlMyaENMRmxCUVVFc1IwRkJaU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTzBGQlEySXNUVUZCUVR0RlFVRkJMRVZCUVVFc1IwRkJTeXhIUVVGSExFTkJRVU1zUzBGQlNpeERRVUZWTEVOQlFWWTdSVUZEVEN4RlFVRkJMRWRCUVVzc1IwRkJSeXhEUVVGRExFdEJRVW9zUTBGQlZTeERRVUZXTzFOQlIwd3NSVUZCUlN4RFFVRkRMRkZCUVVnc1MwRkJaU3hGUVVGRkxFTkJRVU1zVVVGQmJFSXNTVUZCT0VJc1JVRkJSU3hEUVVGRExGRkJRVWdzUzBGQlpTeEZRVUZGTEVOQlFVTXNVVUZCYUVRc1NVRkJORVFzUlVGQlJTeERRVUZETEVsQlFVZ3NTMEZCVnl4RlFVRkZMRU5CUVVNN1FVRk1OMFE3TzBGQlQyWXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHM3TzBWQlJWTXNjMEpCUVVNc1NVRkJSQ3hGUVVGUExFVkJRVkE3U1VGRFdDeEpRVUZITEU5QlFVOHNTVUZCVUN4TFFVRmxMRkZCUVdZc1NVRkJORUlzU1VGQlFTeFpRVUZuUWl4blFrRkJMME03VFVGRFJTeEpRVUZETEVOQlFVRXNSMEZCUkN4SFFVRlBPMDFCUTFBc1NVRkJRU3hIUVVGUExFbEJRVU1zUTBGQlFTeEhRVUZITEVOQlFVTXNTVUZHWkR0TFFVRkJMRTFCUVVFN1RVRkpSU3hKUVVGRExFTkJRVUVzUjBGQlJDeEhRVUZQTEZGQlFWRXNRMEZCUXl4aFFVRlVMRU5CUVhWQ0xFdEJRWFpDTzAxQlExQXNTVUZCUXl4RFFVRkJMRWRCUVVjc1EwRkJReXhIUVVGTUxFZEJRVmNzUzBGTVlqczdTVUZQUVN4SlFVRkhMRU5CUVVrc1lVRkJRU3hEUVVGakxFbEJRV1FzUTBGQlNpeEpRVUV5UWl4RFFVRkpMRmxCUVVFc1EwRkJZU3hOUVVGTkxFTkJRVU1zVVVGQlVTeERRVUZETEVsQlFUZENMRVZCUVcxRExFbEJRVzVETEVOQlFXeERPMDFCUTBVc1NVRkJReXhEUVVGQkxFZEJRVWNzUTBGQlF5eFhRVUZNTEVkQlFXMUNMRmxCUkhKQ096dEpRVWRCTEVsQlFVTXNRMEZCUVN4SFFVRkhMRU5CUVVNc1RVRkJUQ3hIUVVGakxFTkJRVUVzVTBGQlFTeExRVUZCTzJGQlFVRXNVMEZCUVR0UlFVTmFMRXRCUVVNc1EwRkJRU3hYUVVGRUxFTkJRVUU3TUVOQlEwRXNSMEZCU1N4TlFVRk5PMDFCUmtVN1NVRkJRU3hEUVVGQkxFTkJRVUVzUTBGQlFTeEpRVUZCTzBsQlMyUXNTVUZCUnl4SlFVRkRMRU5CUVVFc1IwRkJSeXhEUVVGRExGRkJRVkk3VFVGRFJTeEpRVUZETEVOQlFVRXNSMEZCUnl4RFFVRkRMRTFCUVV3c1EwRkJRU3hGUVVSR096dEpRVWRCTEVsQlFVTXNRMEZCUVN4SFFVRkhMRU5CUVVNc1QwRkJUQ3hIUVVGbExFTkJRVUVzVTBGQlFTeExRVUZCTzJGQlFVRXNVMEZCUXl4RFFVRkVPMEZCUTJJc1dVRkJRVHRSUVVGQkxFZEJRVUVzUjBGQlRTeEpRVUZKTEV0QlFVb3NRMEZCVlN4elFrRkJRU3hIUVVGNVFpeEpRVUZ1UXp0UlFVTk9MRWRCUVVjc1EwRkJReXhIUVVGS0xFZEJRVlU3TUVOQlExWXNSMEZCU1R0TlFVaFRPMGxCUVVFc1EwRkJRU3hEUVVGQkxFTkJRVUVzU1VGQlFUdEZRVzVDU2pzN2VVSkJlVUppTEZkQlFVRXNSMEZCWVN4VFFVRkJPMGxCUTFnc1NVRkJReXhEUVVGQkxFMUJRVVFzUjBGQlZTeFJRVUZSTEVOQlFVTXNZVUZCVkN4RFFVRjFRaXhSUVVGMlFqdEpRVU5XTEVsQlFVTXNRMEZCUVN4UFFVRkVMRWRCUVZjc1NVRkJReXhEUVVGQkxFMUJRVTBzUTBGQlF5eFZRVUZTTEVOQlFXMUNMRWxCUVc1Q08wbEJRMWdzVVVGQlVTeERRVUZETEVsQlFVa3NRMEZCUXl4WFFVRmtMRU5CUVRCQ0xFbEJRVU1zUTBGQlFTeE5RVUV6UWp0SlFVTkJMRWxCUVVNc1EwRkJRU3hMUVVGRUxFZEJRVk1zU1VGQlF5eERRVUZCTEUxQlFVMHNRMEZCUXl4TFFVRlNMRWRCUVdkQ0xFbEJRVU1zUTBGQlFTeEhRVUZITEVOQlFVTTdTVUZET1VJc1NVRkJReXhEUVVGQkxFMUJRVVFzUjBGQlZTeEpRVUZETEVOQlFVRXNUVUZCVFN4RFFVRkRMRTFCUVZJc1IwRkJhVUlzU1VGQlF5eERRVUZCTEVkQlFVY3NRMEZCUXp0WFFVTm9ReXhKUVVGRExFTkJRVUVzVDBGQlR5eERRVUZETEZOQlFWUXNRMEZCYlVJc1NVRkJReXhEUVVGQkxFZEJRWEJDTEVWQlFYbENMRU5CUVhwQ0xFVkJRVFJDTEVOQlFUVkNMRVZCUVN0Q0xFbEJRVU1zUTBGQlFTeExRVUZvUXl4RlFVRjFReXhKUVVGRExFTkJRVUVzVFVGQmVFTTdSVUZPVnpzN2VVSkJVV0lzUzBGQlFTeEhRVUZQTEZOQlFVRTdWMEZEVEN4SlFVRkRMRU5CUVVFc1QwRkJUeXhEUVVGRExGTkJRVlFzUTBGQmJVSXNRMEZCYmtJc1JVRkJjMElzUTBGQmRFSXNSVUZCZVVJc1NVRkJReXhEUVVGQkxFdEJRVEZDTEVWQlFXbERMRWxCUVVNc1EwRkJRU3hOUVVGc1F6dEZRVVJMT3p0NVFrRkhVQ3hSUVVGQkxFZEJRVlVzVTBGQlFUdFhRVU5TTEVsQlFVTXNRMEZCUVR0RlFVUlBPenQ1UWtGSFZpeFRRVUZCTEVkQlFWY3NVMEZCUVR0WFFVTlVMRWxCUVVNc1EwRkJRVHRGUVVSUk96dDVRa0ZIV0N4TlFVRkJMRWRCUVZFc1UwRkJReXhEUVVGRUxFVkJRVWtzUTBGQlNpeEZRVUZQTEVOQlFWQTdTVUZEVGl4SlFVRkRMRU5CUVVFc1MwRkJSQ3hIUVVGVExFbEJRVU1zUTBGQlFTeE5RVUZOTEVOQlFVTXNTMEZCVWl4SFFVRm5RanRKUVVONlFpeEpRVUZETEVOQlFVRXNUVUZCUkN4SFFVRlZMRWxCUVVNc1EwRkJRU3hOUVVGTkxFTkJRVU1zVFVGQlVpeEhRVUZwUWp0SlFVTXpRaXhKUVVGRExFTkJRVUVzVDBGQlR5eERRVUZETEV0QlFWUXNRMEZCWlN4RFFVRm1MRVZCUVd0Q0xFTkJRV3hDTzFkQlEwRXNTVUZCUXl4RFFVRkJMRTlCUVU4c1EwRkJReXhUUVVGVUxFTkJRVzFDTEVsQlFVTXNRMEZCUVN4SFFVRndRaXhGUVVGNVFpeERRVUY2UWl4RlFVRTBRaXhEUVVFMVFqdEZRVXBOT3p0NVFrRk5VaXhOUVVGQkxFZEJRVkVzVTBGQlF5eFRRVUZFTzFkQlEwNHNTVUZCUXl4RFFVRkJMRTlCUVU4c1EwRkJReXhaUVVGVUxFTkJRWE5DTEZOQlFYUkNMRVZCUVdsRExFTkJRV3BETEVWQlFXOURMRU5CUVhCRE8wVkJSRTA3TzNsQ1FVZFNMR0ZCUVVFc1IwRkJaU3hUUVVGQk8xZEJRMklzU1VGQlF5eERRVUZCTEV0QlFVUXNSMEZCVXl4SlFVRkRMRU5CUVVFN1JVRkVSenM3ZVVKQlIyWXNXVUZCUVN4SFFVRmpMRk5CUVVFN1YwRkRXaXhKUVVGRExFTkJRVUVzVDBGQlR5eERRVUZETEZsQlFWUXNRMEZCYzBJc1EwRkJkRUlzUlVGQmVVSXNRMEZCZWtJc1JVRkJORUlzU1VGQlF5eERRVUZCTEV0QlFUZENMRVZCUVc5RExFbEJRVU1zUTBGQlFTeE5RVUZ5UXp0RlFVUlpPenQ1UWtGSFpDeFpRVUZCTEVkQlFXTXNVMEZCUVR0WFFVTmFMRWxCUVVNc1EwRkJRU3hOUVVGTkxFTkJRVU1zVlVGQlZTeERRVUZETEZkQlFXNUNMRU5CUVN0Q0xFbEJRVU1zUTBGQlFTeE5RVUZvUXp0RlFVUlpPenM3TzBkQk0wUlhJbjA9XG4iLCJ2YXIgSW1hZ2U7XG5cbm1vZHVsZS5leHBvcnRzID0gSW1hZ2UgPSAoZnVuY3Rpb24oKSB7XG4gIGZ1bmN0aW9uIEltYWdlKCkge31cblxuICBJbWFnZS5wcm90b3R5cGUuY2xlYXIgPSBmdW5jdGlvbigpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS51cGRhdGUgPSBmdW5jdGlvbihpbWFnZURhdGEpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5nZXRXaWR0aCA9IGZ1bmN0aW9uKCkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLmdldEhlaWdodCA9IGZ1bmN0aW9uKCkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLnNjYWxlRG93biA9IGZ1bmN0aW9uKG9wdHMpIHtcbiAgICB2YXIgaGVpZ2h0LCBtYXhTaWRlLCByYXRpbywgd2lkdGg7XG4gICAgd2lkdGggPSB0aGlzLmdldFdpZHRoKCk7XG4gICAgaGVpZ2h0ID0gdGhpcy5nZXRIZWlnaHQoKTtcbiAgICByYXRpbyA9IDE7XG4gICAgaWYgKG9wdHMubWF4RGltZW5zaW9uICE9IG51bGwpIHtcbiAgICAgIG1heFNpZGUgPSBNYXRoLm1heCh3aWR0aCwgaGVpZ2h0KTtcbiAgICAgIGlmIChtYXhTaWRlID4gb3B0cy5tYXhEaW1lbnNpb24pIHtcbiAgICAgICAgcmF0aW8gPSBvcHRzLm1heERpbWVuc2lvbiAvIG1heFNpZGU7XG4gICAgICB9XG4gICAgfSBlbHNlIHtcbiAgICAgIHJhdGlvID0gMSAvIG9wdHMucXVhbGl0eTtcbiAgICB9XG4gICAgaWYgKHJhdGlvIDwgMSkge1xuICAgICAgcmV0dXJuIHRoaXMucmVzaXplKHdpZHRoICogcmF0aW8sIGhlaWdodCAqIHJhdGlvLCByYXRpbyk7XG4gICAgfVxuICB9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5yZXNpemUgPSBmdW5jdGlvbih3LCBoLCByKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUuZ2V0UGl4ZWxDb3VudCA9IGZ1bmN0aW9uKCkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLmdldEltYWdlRGF0YSA9IGZ1bmN0aW9uKCkge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLnJlbW92ZUNhbnZhcyA9IGZ1bmN0aW9uKCkge307XG5cbiAgcmV0dXJuIEltYWdlO1xuXG59KSgpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12YVcxaFoyVXZhVzVrWlhndVkyOW1abVZsSWl3aWMyOTFjbU5sVW05dmRDSTZJaUlzSW5OdmRYSmpaWE1pT2xzaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZhVzFoWjJVdmFXNWtaWGd1WTI5bVptVmxJbDBzSW01aGJXVnpJanBiWFN3aWJXRndjR2x1WjNNaU9pSkJRVUZCTEVsQlFVRTdPMEZCUVVFc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUczdPMnRDUVVOS0xFdEJRVUVzUjBGQlR5eFRRVUZCTEVkQlFVRTdPMnRDUVVWUUxFMUJRVUVzUjBGQlVTeFRRVUZETEZOQlFVUXNSMEZCUVRzN2EwSkJSVklzVVVGQlFTeEhRVUZWTEZOQlFVRXNSMEZCUVRzN2EwSkJSVllzVTBGQlFTeEhRVUZYTEZOQlFVRXNSMEZCUVRzN2EwSkJSVmdzVTBGQlFTeEhRVUZYTEZOQlFVTXNTVUZCUkR0QlFVTlVMRkZCUVVFN1NVRkJRU3hMUVVGQkxFZEJRVkVzU1VGQlF5eERRVUZCTEZGQlFVUXNRMEZCUVR0SlFVTlNMRTFCUVVFc1IwRkJVeXhKUVVGRExFTkJRVUVzVTBGQlJDeERRVUZCTzBsQlJWUXNTMEZCUVN4SFFVRlJPMGxCUTFJc1NVRkJSeXg1UWtGQlNEdE5RVU5GTEU5QlFVRXNSMEZCVlN4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFdEJRVlFzUlVGQlowSXNUVUZCYUVJN1RVRkRWaXhKUVVGSExFOUJRVUVzUjBGQlZTeEpRVUZKTEVOQlFVTXNXVUZCYkVJN1VVRkRSU3hMUVVGQkxFZEJRVkVzU1VGQlNTeERRVUZETEZsQlFVd3NSMEZCYjBJc1VVRkVPVUk3VDBGR1JqdExRVUZCTEUxQlFVRTdUVUZMUlN4TFFVRkJMRWRCUVZFc1EwRkJRU3hIUVVGSkxFbEJRVWtzUTBGQlF5eFJRVXh1UWpzN1NVRlBRU3hKUVVGSExFdEJRVUVzUjBGQlVTeERRVUZZTzJGQlEwVXNTVUZCUXl4RFFVRkJMRTFCUVVRc1EwRkJVU3hMUVVGQkxFZEJRVkVzUzBGQmFFSXNSVUZCZFVJc1RVRkJRU3hIUVVGVExFdEJRV2hETEVWQlFYVkRMRXRCUVhaRExFVkJSRVk3TzBWQldsTTdPMnRDUVdWWUxFMUJRVUVzUjBGQlVTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVQ3hIUVVGQk96dHJRa0ZIVWl4aFFVRkJMRWRCUVdVc1UwRkJRU3hIUVVGQk96dHJRa0ZGWml4WlFVRkJMRWRCUVdNc1UwRkJRU3hIUVVGQk96dHJRa0ZGWkN4WlFVRkJMRWRCUVdNc1UwRkJRU3hIUVVGQkluMD1cbiIsInZhciBNTUNRLCBQUXVldWUsIFJTSElGVCwgU0lHQklUUywgU3dhdGNoLCBWQm94LCBnZXRDb2xvckluZGV4LCByZWYsIHV0aWw7XG5cbnJlZiA9IHV0aWwgPSByZXF1aXJlKCcuLi8uLi91dGlsJyksIGdldENvbG9ySW5kZXggPSByZWYuZ2V0Q29sb3JJbmRleCwgU0lHQklUUyA9IHJlZi5TSUdCSVRTLCBSU0hJRlQgPSByZWYuUlNISUZUO1xuXG5Td2F0Y2ggPSByZXF1aXJlKCcuLi8uLi9zd2F0Y2gnKTtcblxuVkJveCA9IHJlcXVpcmUoJy4vdmJveCcpO1xuXG5QUXVldWUgPSByZXF1aXJlKCcuL3BxdWV1ZScpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IE1NQ1EgPSAoZnVuY3Rpb24oKSB7XG4gIE1NQ1EuRGVmYXVsdE9wdHMgPSB7XG4gICAgbWF4SXRlcmF0aW9uczogMTAwMCxcbiAgICBmcmFjdEJ5UG9wdWxhdGlvbnM6IDAuNzVcbiAgfTtcblxuICBmdW5jdGlvbiBNTUNRKG9wdHMpIHtcbiAgICB0aGlzLm9wdHMgPSB1dGlsLmRlZmF1bHRzKG9wdHMsIHRoaXMuY29uc3RydWN0b3IuRGVmYXVsdE9wdHMpO1xuICB9XG5cbiAgTU1DUS5wcm90b3R5cGUucXVhbnRpemUgPSBmdW5jdGlvbihwaXhlbHMsIG9wdHMpIHtcbiAgICB2YXIgY29sb3IsIGNvbG9yQ291bnQsIGhpc3QsIHBxLCBwcTIsIHNob3VsZElnbm9yZSwgc3dhdGNoZXMsIHYsIHZib3g7XG4gICAgaWYgKHBpeGVscy5sZW5ndGggPT09IDAgfHwgb3B0cy5jb2xvckNvdW50IDwgMiB8fCBvcHRzLmNvbG9yQ291bnQgPiAyNTYpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIldyb25nIE1NQ1EgcGFyYW1ldGVyc1wiKTtcbiAgICB9XG4gICAgc2hvdWxkSWdub3JlID0gZnVuY3Rpb24oKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfTtcbiAgICBpZiAoQXJyYXkuaXNBcnJheShvcHRzLmZpbHRlcnMpICYmIG9wdHMuZmlsdGVycy5sZW5ndGggPiAwKSB7XG4gICAgICBzaG91bGRJZ25vcmUgPSBmdW5jdGlvbihyLCBnLCBiLCBhKSB7XG4gICAgICAgIHZhciBmLCBpLCBsZW4sIHJlZjE7XG4gICAgICAgIHJlZjEgPSBvcHRzLmZpbHRlcnM7XG4gICAgICAgIGZvciAoaSA9IDAsIGxlbiA9IHJlZjEubGVuZ3RoOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgICAgICBmID0gcmVmMVtpXTtcbiAgICAgICAgICBpZiAoIWYociwgZywgYiwgYSkpIHtcbiAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9O1xuICAgIH1cbiAgICB2Ym94ID0gVkJveC5idWlsZChwaXhlbHMsIHNob3VsZElnbm9yZSk7XG4gICAgaGlzdCA9IHZib3guaGlzdDtcbiAgICBjb2xvckNvdW50ID0gT2JqZWN0LmtleXMoaGlzdCkubGVuZ3RoO1xuICAgIHBxID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICByZXR1cm4gYS5jb3VudCgpIC0gYi5jb3VudCgpO1xuICAgIH0pO1xuICAgIHBxLnB1c2godmJveCk7XG4gICAgdGhpcy5fc3BsaXRCb3hlcyhwcSwgdGhpcy5vcHRzLmZyYWN0QnlQb3B1bGF0aW9ucyAqIG9wdHMuY29sb3JDb3VudCk7XG4gICAgcHEyID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICByZXR1cm4gYS5jb3VudCgpICogYS52b2x1bWUoKSAtIGIuY291bnQoKSAqIGIudm9sdW1lKCk7XG4gICAgfSk7XG4gICAgcHEyLmNvbnRlbnRzID0gcHEuY29udGVudHM7XG4gICAgdGhpcy5fc3BsaXRCb3hlcyhwcTIsIG9wdHMuY29sb3JDb3VudCAtIHBxMi5zaXplKCkpO1xuICAgIHN3YXRjaGVzID0gW107XG4gICAgdGhpcy52Ym94ZXMgPSBbXTtcbiAgICB3aGlsZSAocHEyLnNpemUoKSkge1xuICAgICAgdiA9IHBxMi5wb3AoKTtcbiAgICAgIGNvbG9yID0gdi5hdmcoKTtcbiAgICAgIGlmICghKHR5cGVvZiBzaG91bGRJZ25vcmUgPT09IFwiZnVuY3Rpb25cIiA/IHNob3VsZElnbm9yZShjb2xvclswXSwgY29sb3JbMV0sIGNvbG9yWzJdLCAyNTUpIDogdm9pZCAwKSkge1xuICAgICAgICB0aGlzLnZib3hlcy5wdXNoKHYpO1xuICAgICAgICBzd2F0Y2hlcy5wdXNoKG5ldyBTd2F0Y2goY29sb3IsIHYuY291bnQoKSkpO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gc3dhdGNoZXM7XG4gIH07XG5cbiAgTU1DUS5wcm90b3R5cGUuX3NwbGl0Qm94ZXMgPSBmdW5jdGlvbihwcSwgdGFyZ2V0KSB7XG4gICAgdmFyIGNvbG9yQ291bnQsIGl0ZXJhdGlvbiwgbWF4SXRlcmF0aW9ucywgcmVmMSwgdmJveCwgdmJveDEsIHZib3gyO1xuICAgIGNvbG9yQ291bnQgPSAxO1xuICAgIGl0ZXJhdGlvbiA9IDA7XG4gICAgbWF4SXRlcmF0aW9ucyA9IHRoaXMub3B0cy5tYXhJdGVyYXRpb25zO1xuICAgIHdoaWxlIChpdGVyYXRpb24gPCBtYXhJdGVyYXRpb25zKSB7XG4gICAgICBpdGVyYXRpb24rKztcbiAgICAgIHZib3ggPSBwcS5wb3AoKTtcbiAgICAgIGlmICghdmJveC5jb3VudCgpKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgcmVmMSA9IHZib3guc3BsaXQoKSwgdmJveDEgPSByZWYxWzBdLCB2Ym94MiA9IHJlZjFbMV07XG4gICAgICBwcS5wdXNoKHZib3gxKTtcbiAgICAgIGlmICh2Ym94Mikge1xuICAgICAgICBwcS5wdXNoKHZib3gyKTtcbiAgICAgICAgY29sb3JDb3VudCsrO1xuICAgICAgfVxuICAgICAgaWYgKGNvbG9yQ291bnQgPj0gdGFyZ2V0IHx8IGl0ZXJhdGlvbiA+IG1heEl0ZXJhdGlvbnMpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICByZXR1cm4gTU1DUTtcblxufSkoKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwybHRjR3d2YlcxamNTNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTl4ZFdGdWRHbDZaWEl2YVcxd2JDOXRiV054TG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lRVUZOUVN4SlFVRkJPenRCUVVGQkxFMUJRVzFETEVsQlFVRXNSMEZCVHl4UFFVRkJMRU5CUVZFc1dVRkJVaXhEUVVFeFF5eEZRVUZETEdsRFFVRkVMRVZCUVdkQ0xIRkNRVUZvUWl4RlFVRjVRanM3UVVGRGVrSXNUVUZCUVN4SFFVRlRMRTlCUVVFc1EwRkJVU3hqUVVGU096dEJRVU5VTEVsQlFVRXNSMEZCVHl4UFFVRkJMRU5CUVZFc1VVRkJVanM3UVVGRFVDeE5RVUZCTEVkQlFWTXNUMEZCUVN4RFFVRlJMRlZCUVZJN08wRkJSVlFzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFR0RlFVTktMRWxCUVVNc1EwRkJRU3hYUVVGRUxFZEJRMFU3U1VGQlFTeGhRVUZCTEVWQlFXVXNTVUZCWmp0SlFVTkJMR3RDUVVGQkxFVkJRVzlDTEVsQlJIQkNPenM3UlVGSFZ5eGpRVUZETEVsQlFVUTdTVUZEV0N4SlFVRkRMRU5CUVVFc1NVRkJSQ3hIUVVGUkxFbEJRVWtzUTBGQlF5eFJRVUZNTEVOQlFXTXNTVUZCWkN4RlFVRnZRaXhKUVVGRExFTkJRVUVzVjBGQlZ5eERRVUZETEZkQlFXcERPMFZCUkVjN08ybENRVVZpTEZGQlFVRXNSMEZCVlN4VFFVRkRMRTFCUVVRc1JVRkJVeXhKUVVGVU8wRkJRMUlzVVVGQlFUdEpRVUZCTEVsQlFVY3NUVUZCVFN4RFFVRkRMRTFCUVZBc1MwRkJhVUlzUTBGQmFrSXNTVUZCYzBJc1NVRkJTU3hEUVVGRExGVkJRVXdzUjBGQmEwSXNRMEZCZUVNc1NVRkJOa01zU1VGQlNTeERRVUZETEZWQlFVd3NSMEZCYTBJc1IwRkJiRVU3UVVGRFJTeFpRVUZOTEVsQlFVa3NTMEZCU2l4RFFVRlZMSFZDUVVGV0xFVkJSRkk3TzBsQlIwRXNXVUZCUVN4SFFVRmxMRk5CUVVFN1lVRkJSenRKUVVGSU8wbEJSV1lzU1VGQlJ5eExRVUZMTEVOQlFVTXNUMEZCVGl4RFFVRmpMRWxCUVVrc1EwRkJReXhQUVVGdVFpeERRVUZCTEVsQlFXZERMRWxCUVVrc1EwRkJReXhQUVVGUExFTkJRVU1zVFVGQllpeEhRVUZ6UWl4RFFVRjZSRHROUVVORkxGbEJRVUVzUjBGQlpTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVQ3hGUVVGVkxFTkJRVlk3UVVGRFlpeFpRVUZCTzBGQlFVRTdRVUZCUVN4aFFVRkJMSE5EUVVGQk96dFZRVU5GTEVsQlFVY3NRMEZCU1N4RFFVRkJMRU5CUVVVc1EwRkJSaXhGUVVGTExFTkJRVXdzUlVGQlVTeERRVUZTTEVWQlFWY3NRMEZCV0N4RFFVRlFPMEZCUVRCQ0xHMUNRVUZQTEV0QlFXcERPenRCUVVSR08wRkJSVUVzWlVGQlR6dE5RVWhOTEVWQlJHcENPenRKUVU5QkxFbEJRVUVzUjBGQlR5eEpRVUZKTEVOQlFVTXNTMEZCVEN4RFFVRlhMRTFCUVZnc1JVRkJiVUlzV1VGQmJrSTdTVUZEVUN4SlFVRkJMRWRCUVU4c1NVRkJTU3hEUVVGRE8wbEJRMW9zVlVGQlFTeEhRVUZoTEUxQlFVMHNRMEZCUXl4SlFVRlFMRU5CUVZrc1NVRkJXaXhEUVVGcFFpeERRVUZETzBsQlF5OUNMRVZCUVVFc1IwRkJTeXhKUVVGSkxFMUJRVW9zUTBGQlZ5eFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktPMkZCUVZVc1EwRkJReXhEUVVGRExFdEJRVVlzUTBGQlFTeERRVUZCTEVkQlFWa3NRMEZCUXl4RFFVRkRMRXRCUVVZc1EwRkJRVHRKUVVGMFFpeERRVUZZTzBsQlJVd3NSVUZCUlN4RFFVRkRMRWxCUVVnc1EwRkJVU3hKUVVGU08wbEJSMEVzU1VGQlF5eERRVUZCTEZkQlFVUXNRMEZCWVN4RlFVRmlMRVZCUVdsQ0xFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNhMEpCUVU0c1IwRkJNa0lzU1VGQlNTeERRVUZETEZWQlFXcEVPMGxCUjBFc1IwRkJRU3hIUVVGTkxFbEJRVWtzVFVGQlNpeERRVUZYTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvN1lVRkJWU3hEUVVGRExFTkJRVU1zUzBGQlJpeERRVUZCTEVOQlFVRXNSMEZCV1N4RFFVRkRMRU5CUVVNc1RVRkJSaXhEUVVGQkxFTkJRVm9zUjBGQmVVSXNRMEZCUXl4RFFVRkRMRXRCUVVZc1EwRkJRU3hEUVVGQkxFZEJRVmtzUTBGQlF5eERRVUZETEUxQlFVWXNRMEZCUVR0SlFVRXZReXhEUVVGWU8wbEJRMDRzUjBGQlJ5eERRVUZETEZGQlFVb3NSMEZCWlN4RlFVRkZMRU5CUVVNN1NVRkhiRUlzU1VGQlF5eERRVUZCTEZkQlFVUXNRMEZCWVN4SFFVRmlMRVZCUVd0Q0xFbEJRVWtzUTBGQlF5eFZRVUZNTEVkQlFXdENMRWRCUVVjc1EwRkJReXhKUVVGS0xFTkJRVUVzUTBGQmNFTTdTVUZIUVN4UlFVRkJMRWRCUVZjN1NVRkRXQ3hKUVVGRExFTkJRVUVzVFVGQlJDeEhRVUZWTzBGQlExWXNWMEZCVFN4SFFVRkhMRU5CUVVNc1NVRkJTaXhEUVVGQkxFTkJRVTQ3VFVGRFJTeERRVUZCTEVkQlFVa3NSMEZCUnl4RFFVRkRMRWRCUVVvc1EwRkJRVHROUVVOS0xFdEJRVUVzUjBGQlVTeERRVUZETEVOQlFVTXNSMEZCUml4RFFVRkJPMDFCUTFJc1NVRkJSeXgxUTBGQlNTeGhRVUZqTEV0QlFVMHNRMEZCUVN4RFFVRkJMRWRCUVVrc1MwRkJUU3hEUVVGQkxFTkJRVUVzUjBGQlNTeExRVUZOTEVOQlFVRXNRMEZCUVN4SFFVRkpMR05CUVc1RU8xRkJRMFVzU1VGQlF5eERRVUZCTEUxQlFVMHNRMEZCUXl4SlFVRlNMRU5CUVdFc1EwRkJZanRSUVVOQkxGRkJRVkVzUTBGQlF5eEpRVUZVTEVOQlFXTXNTVUZCU1N4TlFVRktMRU5CUVZjc1MwRkJXQ3hGUVVGclFpeERRVUZETEVOQlFVTXNTMEZCUml4RFFVRkJMRU5CUVd4Q0xFTkJRV1FzUlVGR1JqczdTVUZJUmp0WFFVOUJPMFZCZUVOUk96dHBRa0V3UTFZc1YwRkJRU3hIUVVGaExGTkJRVU1zUlVGQlJDeEZRVUZMTEUxQlFVdzdRVUZEV0N4UlFVRkJPMGxCUVVFc1ZVRkJRU3hIUVVGaE8wbEJRMklzVTBGQlFTeEhRVUZaTzBsQlExb3NZVUZCUVN4SFFVRm5RaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETzBGQlEzUkNMRmRCUVUwc1UwRkJRU3hIUVVGWkxHRkJRV3hDTzAxQlEwVXNVMEZCUVR0TlFVTkJMRWxCUVVFc1IwRkJUeXhGUVVGRkxFTkJRVU1zUjBGQlNDeERRVUZCTzAxQlExQXNTVUZCUnl4RFFVRkRMRWxCUVVrc1EwRkJReXhMUVVGTUxFTkJRVUVzUTBGQlNqdEJRVU5GTEdsQ1FVUkdPenROUVVkQkxFOUJRV2xDTEVsQlFVa3NRMEZCUXl4TFFVRk1MRU5CUVVFc1EwRkJha0lzUlVGQlF5eGxRVUZFTEVWQlFWRTdUVUZGVWl4RlFVRkZMRU5CUVVNc1NVRkJTQ3hEUVVGUkxFdEJRVkk3VFVGRFFTeEpRVUZITEV0QlFVZzdVVUZEUlN4RlFVRkZMRU5CUVVNc1NVRkJTQ3hEUVVGUkxFdEJRVkk3VVVGRFFTeFZRVUZCTEVkQlJrWTdPMDFCUjBFc1NVRkJSeXhWUVVGQkxFbEJRV01zVFVGQlpDeEpRVUYzUWl4VFFVRkJMRWRCUVZrc1lVRkJka003UVVGRFJTeGxRVVJHT3p0SlFWcEdPMFZCU2xjaWZRPT1cbiIsInZhciBQUXVldWU7XG5cbm1vZHVsZS5leHBvcnRzID0gUFF1ZXVlID0gKGZ1bmN0aW9uKCkge1xuICBmdW5jdGlvbiBQUXVldWUoY29tcGFyYXRvcikge1xuICAgIHRoaXMuY29tcGFyYXRvciA9IGNvbXBhcmF0b3I7XG4gICAgdGhpcy5jb250ZW50cyA9IFtdO1xuICAgIHRoaXMuc29ydGVkID0gZmFsc2U7XG4gIH1cblxuICBQUXVldWUucHJvdG90eXBlLl9zb3J0ID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5jb250ZW50cy5zb3J0KHRoaXMuY29tcGFyYXRvcik7XG4gICAgcmV0dXJuIHRoaXMuc29ydGVkID0gdHJ1ZTtcbiAgfTtcblxuICBQUXVldWUucHJvdG90eXBlLnB1c2ggPSBmdW5jdGlvbihvKSB7XG4gICAgdGhpcy5jb250ZW50cy5wdXNoKG8pO1xuICAgIHJldHVybiB0aGlzLnNvcnRlZCA9IGZhbHNlO1xuICB9O1xuXG4gIFBRdWV1ZS5wcm90b3R5cGUucGVlayA9IGZ1bmN0aW9uKGluZGV4KSB7XG4gICAgaWYgKCF0aGlzLnNvcnRlZCkge1xuICAgICAgdGhpcy5fc29ydCgpO1xuICAgIH1cbiAgICBpZiAoaW5kZXggPT0gbnVsbCkge1xuICAgICAgaW5kZXggPSB0aGlzLmNvbnRlbnRzLmxlbmd0aCAtIDE7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmNvbnRlbnRzW2luZGV4XTtcbiAgfTtcblxuICBQUXVldWUucHJvdG90eXBlLnBvcCA9IGZ1bmN0aW9uKCkge1xuICAgIGlmICghdGhpcy5zb3J0ZWQpIHtcbiAgICAgIHRoaXMuX3NvcnQoKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuY29udGVudHMucG9wKCk7XG4gIH07XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5zaXplID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuY29udGVudHMubGVuZ3RoO1xuICB9O1xuXG4gIFBRdWV1ZS5wcm90b3R5cGUubWFwID0gZnVuY3Rpb24oZikge1xuICAgIGlmICghdGhpcy5zb3J0ZWQpIHtcbiAgICAgIHRoaXMuX3NvcnQoKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuY29udGVudHMubWFwKGYpO1xuICB9O1xuXG4gIHJldHVybiBQUXVldWU7XG5cbn0pKCk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMmx0Y0d3dmNIRjFaWFZsTG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwzRjFZVzUwYVhwbGNpOXBiWEJzTDNCeGRXVjFaUzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzU1VGQlFUczdRVUZCUVN4TlFVRk5MRU5CUVVNc1QwRkJVQ3hIUVVOTk8wVkJRMU1zWjBKQlFVTXNWVUZCUkR0SlFVRkRMRWxCUVVNc1EwRkJRU3hoUVVGRU8wbEJRMW9zU1VGQlF5eERRVUZCTEZGQlFVUXNSMEZCV1R0SlFVTmFMRWxCUVVNc1EwRkJRU3hOUVVGRUxFZEJRVlU3UlVGR1F6czdiVUpCU1dJc1MwRkJRU3hIUVVGUExGTkJRVUU3U1VGRFRDeEpRVUZETEVOQlFVRXNVVUZCVVN4RFFVRkRMRWxCUVZZc1EwRkJaU3hKUVVGRExFTkJRVUVzVlVGQmFFSTdWMEZEUVN4SlFVRkRMRU5CUVVFc1RVRkJSQ3hIUVVGVk8wVkJSa3c3TzIxQ1FVbFFMRWxCUVVFc1IwRkJUU3hUUVVGRExFTkJRVVE3U1VGRFNpeEpRVUZETEVOQlFVRXNVVUZCVVN4RFFVRkRMRWxCUVZZc1EwRkJaU3hEUVVGbU8xZEJRMEVzU1VGQlF5eERRVUZCTEUxQlFVUXNSMEZCVlR0RlFVWk9PenR0UWtGSlRpeEpRVUZCTEVkQlFVMHNVMEZCUXl4TFFVRkVPMGxCUTBvc1NVRkJSeXhEUVVGSkxFbEJRVU1zUTBGQlFTeE5RVUZTTzAxQlEwVXNTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hGUVVSR096czdUVUZGUVN4UlFVRlRMRWxCUVVNc1EwRkJRU3hSUVVGUkxFTkJRVU1zVFVGQlZpeEhRVUZ0UWpzN1YwRkROVUlzU1VGQlF5eERRVUZCTEZGQlFWTXNRMEZCUVN4TFFVRkJPMFZCU2s0N08yMUNRVTFPTEVkQlFVRXNSMEZCU3l4VFFVRkJPMGxCUTBnc1NVRkJSeXhEUVVGSkxFbEJRVU1zUTBGQlFTeE5RVUZTTzAxQlEwVXNTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hGUVVSR096dFhRVVZCTEVsQlFVTXNRMEZCUVN4UlFVRlJMRU5CUVVNc1IwRkJWaXhEUVVGQk8wVkJTRWM3TzIxQ1FVdE1MRWxCUVVFc1IwRkJUU3hUUVVGQk8xZEJRMG9zU1VGQlF5eERRVUZCTEZGQlFWRXNRMEZCUXp0RlFVUk9PenR0UWtGSFRpeEhRVUZCTEVkQlFVc3NVMEZCUXl4RFFVRkVPMGxCUTBnc1NVRkJSeXhEUVVGSkxFbEJRVU1zUTBGQlFTeE5RVUZTTzAxQlEwVXNTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hGUVVSR096dFhRVVZCTEVsQlFVTXNRMEZCUVN4UlFVRlJMRU5CUVVNc1IwRkJWaXhEUVVGakxFTkJRV1E3UlVGSVJ5SjlcbiIsInZhciBSU0hJRlQsIFNJR0JJVFMsIFZCb3gsIGdldENvbG9ySW5kZXgsIHJlZiwgdXRpbDtcblxucmVmID0gdXRpbCA9IHJlcXVpcmUoJy4uLy4uL3V0aWwnKSwgZ2V0Q29sb3JJbmRleCA9IHJlZi5nZXRDb2xvckluZGV4LCBTSUdCSVRTID0gcmVmLlNJR0JJVFMsIFJTSElGVCA9IHJlZi5SU0hJRlQ7XG5cbm1vZHVsZS5leHBvcnRzID0gVkJveCA9IChmdW5jdGlvbigpIHtcbiAgVkJveC5idWlsZCA9IGZ1bmN0aW9uKHBpeGVscywgc2hvdWxkSWdub3JlKSB7XG4gICAgdmFyIGEsIGIsIGJtYXgsIGJtaW4sIGcsIGdtYXgsIGdtaW4sIGhpc3QsIGhuLCBpLCBpbmRleCwgbiwgb2Zmc2V0LCByLCBybWF4LCBybWluO1xuICAgIGhuID0gMSA8PCAoMyAqIFNJR0JJVFMpO1xuICAgIGhpc3QgPSBuZXcgVWludDMyQXJyYXkoaG4pO1xuICAgIHJtYXggPSBnbWF4ID0gYm1heCA9IDA7XG4gICAgcm1pbiA9IGdtaW4gPSBibWluID0gTnVtYmVyLk1BWF9WQUxVRTtcbiAgICBuID0gcGl4ZWxzLmxlbmd0aCAvIDQ7XG4gICAgaSA9IDA7XG4gICAgd2hpbGUgKGkgPCBuKSB7XG4gICAgICBvZmZzZXQgPSBpICogNDtcbiAgICAgIGkrKztcbiAgICAgIHIgPSBwaXhlbHNbb2Zmc2V0ICsgMF07XG4gICAgICBnID0gcGl4ZWxzW29mZnNldCArIDFdO1xuICAgICAgYiA9IHBpeGVsc1tvZmZzZXQgKyAyXTtcbiAgICAgIGEgPSBwaXhlbHNbb2Zmc2V0ICsgM107XG4gICAgICBpZiAoc2hvdWxkSWdub3JlKHIsIGcsIGIsIGEpKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuICAgICAgciA9IHIgPj4gUlNISUZUO1xuICAgICAgZyA9IGcgPj4gUlNISUZUO1xuICAgICAgYiA9IGIgPj4gUlNISUZUO1xuICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgaGlzdFtpbmRleF0gKz0gMTtcbiAgICAgIGlmIChyID4gcm1heCkge1xuICAgICAgICBybWF4ID0gcjtcbiAgICAgIH1cbiAgICAgIGlmIChyIDwgcm1pbikge1xuICAgICAgICBybWluID0gcjtcbiAgICAgIH1cbiAgICAgIGlmIChnID4gZ21heCkge1xuICAgICAgICBnbWF4ID0gZztcbiAgICAgIH1cbiAgICAgIGlmIChnIDwgZ21pbikge1xuICAgICAgICBnbWluID0gZztcbiAgICAgIH1cbiAgICAgIGlmIChiID4gYm1heCkge1xuICAgICAgICBibWF4ID0gYjtcbiAgICAgIH1cbiAgICAgIGlmIChiIDwgYm1pbikge1xuICAgICAgICBibWluID0gYjtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIG5ldyBWQm94KHJtaW4sIHJtYXgsIGdtaW4sIGdtYXgsIGJtaW4sIGJtYXgsIGhpc3QpO1xuICB9O1xuXG4gIGZ1bmN0aW9uIFZCb3gocjEsIHIyLCBnMSwgZzIsIGIxLCBiMiwgaGlzdDEpIHtcbiAgICB0aGlzLnIxID0gcjE7XG4gICAgdGhpcy5yMiA9IHIyO1xuICAgIHRoaXMuZzEgPSBnMTtcbiAgICB0aGlzLmcyID0gZzI7XG4gICAgdGhpcy5iMSA9IGIxO1xuICAgIHRoaXMuYjIgPSBiMjtcbiAgICB0aGlzLmhpc3QgPSBoaXN0MTtcbiAgfVxuXG4gIFZCb3gucHJvdG90eXBlLmludmFsaWRhdGUgPSBmdW5jdGlvbigpIHtcbiAgICBkZWxldGUgdGhpcy5fY291bnQ7XG4gICAgZGVsZXRlIHRoaXMuX2F2ZztcbiAgICByZXR1cm4gZGVsZXRlIHRoaXMuX3ZvbHVtZTtcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS52b2x1bWUgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAodGhpcy5fdm9sdW1lID09IG51bGwpIHtcbiAgICAgIHRoaXMuX3ZvbHVtZSA9ICh0aGlzLnIyIC0gdGhpcy5yMSArIDEpICogKHRoaXMuZzIgLSB0aGlzLmcxICsgMSkgKiAodGhpcy5iMiAtIHRoaXMuYjEgKyAxKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX3ZvbHVtZTtcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS5jb3VudCA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBjLCBoaXN0O1xuICAgIGlmICh0aGlzLl9jb3VudCA9PSBudWxsKSB7XG4gICAgICBoaXN0ID0gdGhpcy5oaXN0O1xuICAgICAgYyA9IDA7XG4gICAgICBcbiAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICBjICs9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgO1xuICAgICAgdGhpcy5fY291bnQgPSBjO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5fY291bnQ7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUuY2xvbmUgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gbmV3IFZCb3godGhpcy5yMSwgdGhpcy5yMiwgdGhpcy5nMSwgdGhpcy5nMiwgdGhpcy5iMSwgdGhpcy5iMiwgdGhpcy5oaXN0KTtcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS5hdmcgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgYnN1bSwgZ3N1bSwgaGlzdCwgbXVsdCwgbnRvdCwgcnN1bTtcbiAgICBpZiAodGhpcy5fYXZnID09IG51bGwpIHtcbiAgICAgIGhpc3QgPSB0aGlzLmhpc3Q7XG4gICAgICBudG90ID0gMDtcbiAgICAgIG11bHQgPSAxIDw8ICg4IC0gU0lHQklUUyk7XG4gICAgICByc3VtID0gZ3N1bSA9IGJzdW0gPSAwO1xuICAgICAgXG4gICAgICBmb3IgKHZhciByID0gdGhpcy5yMTsgciA8PSB0aGlzLnIyOyByKyspIHtcbiAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgdmFyIGggPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICAgIG50b3QgKz0gaDtcbiAgICAgICAgICAgIHJzdW0gKz0gKGggKiAociArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgIGdzdW0gKz0gKGggKiAoZyArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgIGJzdW0gKz0gKGggKiAoYiArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIDtcbiAgICAgIGlmIChudG90KSB7XG4gICAgICAgIHRoaXMuX2F2ZyA9IFt+fihyc3VtIC8gbnRvdCksIH5+KGdzdW0gLyBudG90KSwgfn4oYnN1bSAvIG50b3QpXTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHRoaXMuX2F2ZyA9IFt+fihtdWx0ICogKHRoaXMucjEgKyB0aGlzLnIyICsgMSkgLyAyKSwgfn4obXVsdCAqICh0aGlzLmcxICsgdGhpcy5nMiArIDEpIC8gMiksIH5+KG11bHQgKiAodGhpcy5iMSArIHRoaXMuYjIgKyAxKSAvIDIpXTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX2F2ZztcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS5zcGxpdCA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBhY2NTdW0sIGJ3LCBkLCBkb0N1dCwgZ3csIGhpc3QsIGksIGosIG1heGQsIG1heHcsIHJlZjEsIHJldmVyc2VTdW0sIHJ3LCBzcGxpdFBvaW50LCBzdW0sIHRvdGFsLCB2Ym94O1xuICAgIGhpc3QgPSB0aGlzLmhpc3Q7XG4gICAgaWYgKCF0aGlzLmNvdW50KCkpIHtcbiAgICAgIHJldHVybiBudWxsO1xuICAgIH1cbiAgICBpZiAodGhpcy5jb3VudCgpID09PSAxKSB7XG4gICAgICByZXR1cm4gW3RoaXMuY2xvbmUoKV07XG4gICAgfVxuICAgIHJ3ID0gdGhpcy5yMiAtIHRoaXMucjEgKyAxO1xuICAgIGd3ID0gdGhpcy5nMiAtIHRoaXMuZzEgKyAxO1xuICAgIGJ3ID0gdGhpcy5iMiAtIHRoaXMuYjEgKyAxO1xuICAgIG1heHcgPSBNYXRoLm1heChydywgZ3csIGJ3KTtcbiAgICBhY2NTdW0gPSBudWxsO1xuICAgIHN1bSA9IHRvdGFsID0gMDtcbiAgICBtYXhkID0gbnVsbDtcbiAgICBzd2l0Y2ggKG1heHcpIHtcbiAgICAgIGNhc2Ugcnc6XG4gICAgICAgIG1heGQgPSAncic7XG4gICAgICAgIGFjY1N1bSA9IG5ldyBVaW50MzJBcnJheSh0aGlzLnIyICsgMSk7XG4gICAgICAgIFxuICAgICAgICBmb3IgKHZhciByID0gdGhpcy5yMTsgciA8PSB0aGlzLnIyOyByKyspIHtcbiAgICAgICAgICBzdW0gPSAwXG4gICAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgICAgc3VtICs9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgYWNjU3VtW3JdID0gdG90YWw7XG4gICAgICAgIH1cbiAgICAgICAgO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgZ3c6XG4gICAgICAgIG1heGQgPSAnZyc7XG4gICAgICAgIGFjY1N1bSA9IG5ldyBVaW50MzJBcnJheSh0aGlzLmcyICsgMSk7XG4gICAgICAgIFxuICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICBzdW0gPSAwXG4gICAgICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgICAgc3VtICs9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgYWNjU3VtW2ddID0gdG90YWw7XG4gICAgICAgIH1cbiAgICAgICAgO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgYnc6XG4gICAgICAgIG1heGQgPSAnYic7XG4gICAgICAgIGFjY1N1bSA9IG5ldyBVaW50MzJBcnJheSh0aGlzLmIyICsgMSk7XG4gICAgICAgIFxuICAgICAgICBmb3IgKHZhciBiID0gdGhpcy5iMTsgYiA8PSB0aGlzLmIyOyBiKyspIHtcbiAgICAgICAgICBzdW0gPSAwXG4gICAgICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgICAgICBmb3IgKHZhciBnID0gdGhpcy5nMTsgZyA8PSB0aGlzLmcyOyBnKyspIHtcbiAgICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgICAgc3VtICs9IGhpc3RbaW5kZXhdO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgYWNjU3VtW2JdID0gdG90YWw7XG4gICAgICAgIH1cbiAgICAgICAgO1xuICAgIH1cbiAgICBzcGxpdFBvaW50ID0gLTE7XG4gICAgcmV2ZXJzZVN1bSA9IG5ldyBVaW50MzJBcnJheShhY2NTdW0ubGVuZ3RoKTtcbiAgICBmb3IgKGkgPSBqID0gMCwgcmVmMSA9IGFjY1N1bS5sZW5ndGggLSAxOyAwIDw9IHJlZjEgPyBqIDw9IHJlZjEgOiBqID49IHJlZjE7IGkgPSAwIDw9IHJlZjEgPyArK2ogOiAtLWopIHtcbiAgICAgIGQgPSBhY2NTdW1baV07XG4gICAgICBpZiAoc3BsaXRQb2ludCA8IDAgJiYgZCA+IHRvdGFsIC8gMikge1xuICAgICAgICBzcGxpdFBvaW50ID0gaTtcbiAgICAgIH1cbiAgICAgIHJldmVyc2VTdW1baV0gPSB0b3RhbCAtIGQ7XG4gICAgfVxuICAgIHZib3ggPSB0aGlzO1xuICAgIGRvQ3V0ID0gZnVuY3Rpb24oZCkge1xuICAgICAgdmFyIGMyLCBkMSwgZDIsIGRpbTEsIGRpbTIsIGxlZnQsIHJpZ2h0LCB2Ym94MSwgdmJveDI7XG4gICAgICBkaW0xID0gZCArIFwiMVwiO1xuICAgICAgZGltMiA9IGQgKyBcIjJcIjtcbiAgICAgIGQxID0gdmJveFtkaW0xXTtcbiAgICAgIGQyID0gdmJveFtkaW0yXTtcbiAgICAgIHZib3gxID0gdmJveC5jbG9uZSgpO1xuICAgICAgdmJveDIgPSB2Ym94LmNsb25lKCk7XG4gICAgICBsZWZ0ID0gc3BsaXRQb2ludCAtIGQxO1xuICAgICAgcmlnaHQgPSBkMiAtIHNwbGl0UG9pbnQ7XG4gICAgICBpZiAobGVmdCA8PSByaWdodCkge1xuICAgICAgICBkMiA9IE1hdGgubWluKGQyIC0gMSwgfn4oc3BsaXRQb2ludCArIHJpZ2h0IC8gMikpO1xuICAgICAgICBkMiA9IE1hdGgubWF4KDAsIGQyKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGQyID0gTWF0aC5tYXgoZDEsIH5+KHNwbGl0UG9pbnQgLSAxIC0gbGVmdCAvIDIpKTtcbiAgICAgICAgZDIgPSBNYXRoLm1pbih2Ym94W2RpbTJdLCBkMik7XG4gICAgICB9XG4gICAgICB3aGlsZSAoIWFjY1N1bVtkMl0pIHtcbiAgICAgICAgZDIrKztcbiAgICAgIH1cbiAgICAgIGMyID0gcmV2ZXJzZVN1bVtkMl07XG4gICAgICB3aGlsZSAoIWMyICYmIGFjY1N1bVtkMiAtIDFdKSB7XG4gICAgICAgIGMyID0gcmV2ZXJzZVN1bVstLWQyXTtcbiAgICAgIH1cbiAgICAgIHZib3gxW2RpbTJdID0gZDI7XG4gICAgICB2Ym94MltkaW0xXSA9IGQyICsgMTtcbiAgICAgIHJldHVybiBbdmJveDEsIHZib3gyXTtcbiAgICB9O1xuICAgIHJldHVybiBkb0N1dChtYXhkKTtcbiAgfTtcblxuICBWQm94LnByb3RvdHlwZS5jb250YWlucyA9IGZ1bmN0aW9uKHApIHtcbiAgICB2YXIgYiwgZywgcjtcbiAgICByID0gcFswXSA+PiBSU0hJRlQ7XG4gICAgZyA9IHBbMV0gPj4gUlNISUZUO1xuICAgIGIgPSBwWzJdID4+IFJTSElGVDtcbiAgICByZXR1cm4gciA+PSB0aGlzLnIxICYmIHIgPD0gdGhpcy5yMiAmJiBnID49IHRoaXMuZzEgJiYgZyA8PSB0aGlzLmcyICYmIGIgPj0gdGhpcy5iMSAmJiBiIDw9IHRoaXMuYjI7XG4gIH07XG5cbiAgcmV0dXJuIFZCb3g7XG5cbn0pKCk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMmx0Y0d3dmRtSnZlQzVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5eGRXRnVkR2w2WlhJdmFXMXdiQzkyWW05NExtTnZabVpsWlNKZExDSnVZVzFsY3lJNlcxMHNJbTFoY0hCcGJtZHpJam9pUVVGQlFTeEpRVUZCT3p0QlFVRkJMRTFCUVcxRExFbEJRVUVzUjBGQlR5eFBRVUZCTEVOQlFWRXNXVUZCVWl4RFFVRXhReXhGUVVGRExHbERRVUZFTEVWQlFXZENMSEZDUVVGb1FpeEZRVUY1UWpzN1FVRkZla0lzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFR0RlFVTktMRWxCUVVNc1EwRkJRU3hMUVVGRUxFZEJRVkVzVTBGQlF5eE5RVUZFTEVWQlFWTXNXVUZCVkR0QlFVTk9MRkZCUVVFN1NVRkJRU3hGUVVGQkxFZEJRVXNzUTBGQlFTeEpRVUZITEVOQlFVTXNRMEZCUVN4SFFVRkZMRTlCUVVnN1NVRkRVaXhKUVVGQkxFZEJRVThzU1VGQlNTeFhRVUZLTEVOQlFXZENMRVZCUVdoQ08wbEJRMUFzU1VGQlFTeEhRVUZQTEVsQlFVRXNSMEZCVHl4SlFVRkJMRWRCUVU4N1NVRkRja0lzU1VGQlFTeEhRVUZQTEVsQlFVRXNSMEZCVHl4SlFVRkJMRWRCUVU4c1RVRkJUU3hEUVVGRE8wbEJRelZDTEVOQlFVRXNSMEZCU1N4TlFVRk5MRU5CUVVNc1RVRkJVQ3hIUVVGblFqdEpRVU53UWl4RFFVRkJMRWRCUVVrN1FVRkZTaXhYUVVGTkxFTkJRVUVzUjBGQlNTeERRVUZXTzAxQlEwVXNUVUZCUVN4SFFVRlRMRU5CUVVFc1IwRkJTVHROUVVOaUxFTkJRVUU3VFVGRFFTeERRVUZCTEVkQlFVa3NUVUZCVHl4RFFVRkJMRTFCUVVFc1IwRkJVeXhEUVVGVU8wMUJRMWdzUTBGQlFTeEhRVUZKTEUxQlFVOHNRMEZCUVN4TlFVRkJMRWRCUVZNc1EwRkJWRHROUVVOWUxFTkJRVUVzUjBGQlNTeE5RVUZQTEVOQlFVRXNUVUZCUVN4SFFVRlRMRU5CUVZRN1RVRkRXQ3hEUVVGQkxFZEJRVWtzVFVGQlR5eERRVUZCTEUxQlFVRXNSMEZCVXl4RFFVRlVPMDFCUlZnc1NVRkJSeXhaUVVGQkxFTkJRV0VzUTBGQllpeEZRVUZuUWl4RFFVRm9RaXhGUVVGdFFpeERRVUZ1UWl4RlFVRnpRaXhEUVVGMFFpeERRVUZJTzBGQlFXbERMR2xDUVVGcVF6czdUVUZGUVN4RFFVRkJMRWRCUVVrc1EwRkJRU3hKUVVGTE8wMUJRMVFzUTBGQlFTeEhRVUZKTEVOQlFVRXNTVUZCU3p0TlFVTlVMRU5CUVVFc1IwRkJTU3hEUVVGQkxFbEJRVXM3VFVGSFZDeExRVUZCTEVkQlFWRXNZVUZCUVN4RFFVRmpMRU5CUVdRc1JVRkJhVUlzUTBGQmFrSXNSVUZCYjBJc1EwRkJjRUk3VFVGRFVpeEpRVUZMTEVOQlFVRXNTMEZCUVN4RFFVRk1MRWxCUVdVN1RVRkZaaXhKUVVGSExFTkJRVUVzUjBGQlNTeEpRVUZRTzFGQlEwVXNTVUZCUVN4SFFVRlBMRVZCUkZRN08wMUJSVUVzU1VGQlJ5eERRVUZCTEVkQlFVa3NTVUZCVUR0UlFVTkZMRWxCUVVFc1IwRkJUeXhGUVVSVU96dE5RVVZCTEVsQlFVY3NRMEZCUVN4SFFVRkpMRWxCUVZBN1VVRkRSU3hKUVVGQkxFZEJRVThzUlVGRVZEczdUVUZGUVN4SlFVRkhMRU5CUVVFc1IwRkJTU3hKUVVGUU8xRkJRMFVzU1VGQlFTeEhRVUZQTEVWQlJGUTdPMDFCUlVFc1NVRkJSeXhEUVVGQkxFZEJRVWtzU1VGQlVEdFJRVU5GTEVsQlFVRXNSMEZCVHl4RlFVUlVPenROUVVWQkxFbEJRVWNzUTBGQlFTeEhRVUZKTEVsQlFWQTdVVUZEUlN4SlFVRkJMRWRCUVU4c1JVRkVWRHM3U1VFMVFrWTdWMEVyUWtFc1NVRkJTU3hKUVVGS0xFTkJRVk1zU1VGQlZDeEZRVUZsTEVsQlFXWXNSVUZCY1VJc1NVRkJja0lzUlVGQk1rSXNTVUZCTTBJc1JVRkJhVU1zU1VGQmFrTXNSVUZCZFVNc1NVRkJka01zUlVGQk5rTXNTVUZCTjBNN1JVRjJRMDA3TzBWQmVVTkxMR05CUVVNc1JVRkJSQ3hGUVVGTkxFVkJRVTRzUlVGQlZ5eEZRVUZZTEVWQlFXZENMRVZCUVdoQ0xFVkJRWEZDTEVWQlFYSkNMRVZCUVRCQ0xFVkJRVEZDTEVWQlFTdENMRXRCUVM5Q08wbEJRVU1zU1VGQlF5eERRVUZCTEV0QlFVUTdTVUZCU3l4SlFVRkRMRU5CUVVFc1MwRkJSRHRKUVVGTExFbEJRVU1zUTBGQlFTeExRVUZFTzBsQlFVc3NTVUZCUXl4RFFVRkJMRXRCUVVRN1NVRkJTeXhKUVVGRExFTkJRVUVzUzBGQlJEdEpRVUZMTEVsQlFVTXNRMEZCUVN4TFFVRkVPMGxCUVVzc1NVRkJReXhEUVVGQkxFOUJRVVE3UlVGQkwwSTdPMmxDUVVkaUxGVkJRVUVzUjBGQldTeFRRVUZCTzBsQlExWXNUMEZCVHl4SlFVRkRMRU5CUVVFN1NVRkRVaXhQUVVGUExFbEJRVU1zUTBGQlFUdFhRVU5TTEU5QlFVOHNTVUZCUXl4RFFVRkJPMFZCU0VVN08ybENRVXRhTEUxQlFVRXNSMEZCVVN4VFFVRkJPMGxCUTA0c1NVRkJUeXh2UWtGQlVEdE5RVU5GTEVsQlFVTXNRMEZCUVN4UFFVRkVMRWRCUVZjc1EwRkJReXhKUVVGRExFTkJRVUVzUlVGQlJDeEhRVUZOTEVsQlFVTXNRMEZCUVN4RlFVRlFMRWRCUVZrc1EwRkJZaXhEUVVGQkxFZEJRV3RDTEVOQlFVTXNTVUZCUXl4RFFVRkJMRVZCUVVRc1IwRkJUU3hKUVVGRExFTkJRVUVzUlVGQlVDeEhRVUZaTEVOQlFXSXNRMEZCYkVJc1IwRkJiME1zUTBGQlF5eEpRVUZETEVOQlFVRXNSVUZCUkN4SFFVRk5MRWxCUVVNc1EwRkJRU3hGUVVGUUxFZEJRVmtzUTBGQllpeEZRVVJxUkRzN1YwRkZRU3hKUVVGRExFTkJRVUU3UlVGSVN6czdhVUpCUzFJc1MwRkJRU3hIUVVGUExGTkJRVUU3UVVGRFRDeFJRVUZCTzBsQlFVRXNTVUZCVHl4dFFrRkJVRHROUVVORkxFbEJRVUVzUjBGQlR5eEpRVUZETEVOQlFVRTdUVUZEVWl4RFFVRkJMRWRCUVVrN1RVRkRTanM3T3pzN096czdPenROUVdWQkxFbEJRVU1zUTBGQlFTeE5RVUZFTEVkQlFWVXNSVUZzUWxvN08xZEJiVUpCTEVsQlFVTXNRMEZCUVR0RlFYQkNTVHM3YVVKQmMwSlFMRXRCUVVFc1IwRkJUeXhUUVVGQk8xZEJRMHdzU1VGQlNTeEpRVUZLTEVOQlFWTXNTVUZCUXl4RFFVRkJMRVZCUVZZc1JVRkJZeXhKUVVGRExFTkJRVUVzUlVGQlppeEZRVUZ0UWl4SlFVRkRMRU5CUVVFc1JVRkJjRUlzUlVGQmQwSXNTVUZCUXl4RFFVRkJMRVZCUVhwQ0xFVkJRVFpDTEVsQlFVTXNRMEZCUVN4RlFVRTVRaXhGUVVGclF5eEpRVUZETEVOQlFVRXNSVUZCYmtNc1JVRkJkVU1zU1VGQlF5eERRVUZCTEVsQlFYaERPMFZCUkVzN08ybENRVWRRTEVkQlFVRXNSMEZCU3l4VFFVRkJPMEZCUTBnc1VVRkJRVHRKUVVGQkxFbEJRVThzYVVKQlFWQTdUVUZEUlN4SlFVRkJMRWRCUVU4c1NVRkJReXhEUVVGQk8wMUJRMUlzU1VGQlFTeEhRVUZQTzAxQlExQXNTVUZCUVN4SFFVRlBMRU5CUVVFc1NVRkJTeXhEUVVGRExFTkJRVUVzUjBGQlNTeFBRVUZNTzAxQlExb3NTVUZCUVN4SFFVRlBMRWxCUVVFc1IwRkJUeXhKUVVGQkxFZEJRVTg3VFVGRGNrSTdPenM3T3pzN096czdPenM3TzAxQmVVSkJMRWxCUVVjc1NVRkJTRHRSUVVORkxFbEJRVU1zUTBGQlFTeEpRVUZFTEVkQlFWRXNRMEZEVGl4RFFVRkRMRU5CUVVNc1EwRkJReXhKUVVGQkxFZEJRVThzU1VGQlVpeERRVVJKTEVWQlJVNHNRMEZCUXl4RFFVRkRMRU5CUVVNc1NVRkJRU3hIUVVGUExFbEJRVklzUTBGR1NTeEZRVWRPTEVOQlFVTXNRMEZCUXl4RFFVRkRMRWxCUVVFc1IwRkJUeXhKUVVGU0xFTkJTRWtzUlVGRVZqdFBRVUZCTEUxQlFVRTdVVUZQUlN4SlFVRkRMRU5CUVVFc1NVRkJSQ3hIUVVGUkxFTkJRMDRzUTBGQlF5eERRVUZETEVOQlFVTXNTVUZCUVN4SFFVRlBMRU5CUVVNc1NVRkJReXhEUVVGQkxFVkJRVVFzUjBGQlRTeEpRVUZETEVOQlFVRXNSVUZCVUN4SFFVRlpMRU5CUVdJc1EwRkJVQ3hIUVVGNVFpeERRVUV4UWl4RFFVUkpMRVZCUlU0c1EwRkJReXhEUVVGRExFTkJRVU1zU1VGQlFTeEhRVUZQTEVOQlFVTXNTVUZCUXl4RFFVRkJMRVZCUVVRc1IwRkJUU3hKUVVGRExFTkJRVUVzUlVGQlVDeEhRVUZaTEVOQlFXSXNRMEZCVUN4SFFVRjVRaXhEUVVFeFFpeERRVVpKTEVWQlIwNHNRMEZCUXl4RFFVRkRMRU5CUVVNc1NVRkJRU3hIUVVGUExFTkJRVU1zU1VGQlF5eERRVUZCTEVWQlFVUXNSMEZCVFN4SlFVRkRMRU5CUVVFc1JVRkJVQ3hIUVVGWkxFTkJRV0lzUTBGQlVDeEhRVUY1UWl4RFFVRXhRaXhEUVVoSkxFVkJVRlk3VDBFNVFrWTdPMWRCTUVOQkxFbEJRVU1zUTBGQlFUdEZRVE5EUlRzN2FVSkJOa05NTEV0QlFVRXNSMEZCVHl4VFFVRkJPMEZCUTB3c1VVRkJRVHRKUVVGQkxFbEJRVUVzUjBGQlR5eEpRVUZETEVOQlFVRTdTVUZEVWl4SlFVRkhMRU5CUVVNc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeERRVUZLTzBGQlEwVXNZVUZCVHl4TFFVUlVPenRKUVVWQkxFbEJRVWNzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RFFVRkJMRXRCUVZrc1EwRkJaanRCUVVORkxHRkJRVThzUTBGQlF5eEpRVUZETEVOQlFVRXNTMEZCUkN4RFFVRkJMRU5CUVVRc1JVRkVWRHM3U1VGSFFTeEZRVUZCTEVkQlFVc3NTVUZCUXl4RFFVRkJMRVZCUVVRc1IwRkJUU3hKUVVGRExFTkJRVUVzUlVGQlVDeEhRVUZaTzBsQlEycENMRVZCUVVFc1IwRkJTeXhKUVVGRExFTkJRVUVzUlVGQlJDeEhRVUZOTEVsQlFVTXNRMEZCUVN4RlFVRlFMRWRCUVZrN1NVRkRha0lzUlVGQlFTeEhRVUZMTEVsQlFVTXNRMEZCUVN4RlFVRkVMRWRCUVUwc1NVRkJReXhEUVVGQkxFVkJRVkFzUjBGQldUdEpRVVZxUWl4SlFVRkJMRWRCUVU4c1NVRkJTU3hEUVVGRExFZEJRVXdzUTBGQlV5eEZRVUZVTEVWQlFXRXNSVUZCWWl4RlFVRnBRaXhGUVVGcVFqdEpRVU5RTEUxQlFVRXNSMEZCVXp0SlFVTlVMRWRCUVVFc1IwRkJUU3hMUVVGQkxFZEJRVkU3U1VGRlpDeEpRVUZCTEVkQlFVODdRVUZEVUN4WlFVRlBMRWxCUVZBN1FVRkJRU3hYUVVOUExFVkJSRkE3VVVGRlNTeEpRVUZCTEVkQlFVODdVVUZEVUN4TlFVRkJMRWRCUVZNc1NVRkJTU3hYUVVGS0xFTkJRV2RDTEVsQlFVTXNRMEZCUVN4RlFVRkVMRWRCUVUwc1EwRkJkRUk3VVVGRFZEczdPenM3T3pzN096czdPenRCUVVoSE8wRkJSRkFzVjBGNVFrOHNSVUY2UWxBN1VVRXdRa2tzU1VGQlFTeEhRVUZQTzFGQlExQXNUVUZCUVN4SFFVRlRMRWxCUVVrc1YwRkJTaXhEUVVGblFpeEpRVUZETEVOQlFVRXNSVUZCUkN4SFFVRk5MRU5CUVhSQ08xRkJRMVE3T3pzN096czdPenM3T3pzN1FVRklSenRCUVhwQ1VDeFhRV2xFVHl4RlFXcEVVRHRSUVd0RVNTeEpRVUZCTEVkQlFVODdVVUZEVUN4TlFVRkJMRWRCUVZNc1NVRkJTU3hYUVVGS0xFTkJRV2RDTEVsQlFVTXNRMEZCUVN4RlFVRkVMRWRCUVUwc1EwRkJkRUk3VVVGRFZEczdPenM3T3pzN096czdPenRCUVhCRVNqdEpRVEJGUVN4VlFVRkJMRWRCUVdFc1EwRkJRenRKUVVOa0xGVkJRVUVzUjBGQllTeEpRVUZKTEZkQlFVb3NRMEZCWjBJc1RVRkJUU3hEUVVGRExFMUJRWFpDTzBGQlEySXNVMEZCVXl4cFIwRkJWRHROUVVORkxFTkJRVUVzUjBGQlNTeE5RVUZQTEVOQlFVRXNRMEZCUVR0TlFVTllMRWxCUVVjc1ZVRkJRU3hIUVVGaExFTkJRV0lzU1VGQmEwSXNRMEZCUVN4SFFVRkpMRXRCUVVFc1IwRkJVU3hEUVVGcVF6dFJRVU5GTEZWQlFVRXNSMEZCWVN4RlFVUm1PenROUVVWQkxGVkJRVmNzUTBGQlFTeERRVUZCTEVOQlFWZ3NSMEZCWjBJc1MwRkJRU3hIUVVGUk8wRkJTakZDTzBsQlRVRXNTVUZCUVN4SFFVRlBPMGxCUTFBc1MwRkJRU3hIUVVGUkxGTkJRVU1zUTBGQlJEdEJRVU5PTEZWQlFVRTdUVUZCUVN4SlFVRkJMRWRCUVU4c1EwRkJRU3hIUVVGSk8wMUJRMWdzU1VGQlFTeEhRVUZQTEVOQlFVRXNSMEZCU1R0TlFVTllMRVZCUVVFc1IwRkJTeXhKUVVGTExFTkJRVUVzU1VGQlFUdE5RVU5XTEVWQlFVRXNSMEZCU3l4SlFVRkxMRU5CUVVFc1NVRkJRVHROUVVOV0xFdEJRVUVzUjBGQlVTeEpRVUZKTEVOQlFVTXNTMEZCVEN4RFFVRkJPMDFCUTFJc1MwRkJRU3hIUVVGUkxFbEJRVWtzUTBGQlF5eExRVUZNTEVOQlFVRTdUVUZEVWl4SlFVRkJMRWRCUVU4c1ZVRkJRU3hIUVVGaE8wMUJRM0JDTEV0QlFVRXNSMEZCVVN4RlFVRkJMRWRCUVVzN1RVRkRZaXhKUVVGSExFbEJRVUVzU1VGQlVTeExRVUZZTzFGQlEwVXNSVUZCUVN4SFFVRkxMRWxCUVVrc1EwRkJReXhIUVVGTUxFTkJRVk1zUlVGQlFTeEhRVUZMTEVOQlFXUXNSVUZCYVVJc1EwRkJReXhEUVVGRkxFTkJRVU1zVlVGQlFTeEhRVUZoTEV0QlFVRXNSMEZCVVN4RFFVRjBRaXhEUVVGd1FqdFJRVU5NTEVWQlFVRXNSMEZCU3l4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFTkJRVlFzUlVGQldTeEZRVUZhTEVWQlJsQTdUMEZCUVN4TlFVRkJPMUZCU1VVc1JVRkJRU3hIUVVGTExFbEJRVWtzUTBGQlF5eEhRVUZNTEVOQlFWTXNSVUZCVkN4RlFVRmhMRU5CUVVNc1EwRkJSU3hEUVVGRExGVkJRVUVzUjBGQllTeERRVUZpTEVkQlFXbENMRWxCUVVFc1IwRkJUeXhEUVVGNlFpeERRVUZvUWp0UlFVTk1MRVZCUVVFc1IwRkJTeXhKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVsQlFVc3NRMEZCUVN4SlFVRkJMRU5CUVdRc1JVRkJjVUlzUlVGQmNrSXNSVUZNVURzN1FVRlJRU3hoUVVGTkxFTkJRVU1zVFVGQlR5eERRVUZCTEVWQlFVRXNRMEZCWkR0UlFVTkZMRVZCUVVFN1RVRkVSanROUVVsQkxFVkJRVUVzUjBGQlN5eFZRVUZYTEVOQlFVRXNSVUZCUVR0QlFVTm9RaXhoUVVGTkxFTkJRVU1zUlVGQlJDeEpRVUZSTEUxQlFVOHNRMEZCUVN4RlFVRkJMRWRCUVVzc1EwRkJUQ3hEUVVGeVFqdFJRVU5GTEVWQlFVRXNSMEZCU3l4VlFVRlhMRU5CUVVFc1JVRkJSU3hGUVVGR08wMUJSR3hDTzAxQlIwRXNTMEZCVFN4RFFVRkJMRWxCUVVFc1EwRkJUaXhIUVVGak8wMUJRMlFzUzBGQlRTeERRVUZCTEVsQlFVRXNRMEZCVGl4SFFVRmpMRVZCUVVFc1IwRkJTenRCUVVkdVFpeGhRVUZQTEVOQlFVTXNTMEZCUkN4RlFVRlJMRXRCUVZJN1NVRTNRa1E3VjBFclFsSXNTMEZCUVN4RFFVRk5MRWxCUVU0N1JVRnNTVXM3TzJsQ1FXOUpVQ3hSUVVGQkxFZEJRVlVzVTBGQlF5eERRVUZFTzBGQlExSXNVVUZCUVR0SlFVRkJMRU5CUVVFc1IwRkJTU3hEUVVGRkxFTkJRVUVzUTBGQlFTeERRVUZHTEVsQlFVMDdTVUZEVml4RFFVRkJMRWRCUVVrc1EwRkJSU3hEUVVGQkxFTkJRVUVzUTBGQlJpeEpRVUZOTzBsQlExWXNRMEZCUVN4SFFVRkpMRU5CUVVVc1EwRkJRU3hEUVVGQkxFTkJRVVlzU1VGQlRUdFhRVVZXTEVOQlFVRXNTVUZCU3l4SlFVRkRMRU5CUVVFc1JVRkJUaXhKUVVGaExFTkJRVUVzU1VGQlN5eEpRVUZETEVOQlFVRXNSVUZCYmtJc1NVRkJNRUlzUTBGQlFTeEpRVUZMTEVsQlFVTXNRMEZCUVN4RlFVRm9ReXhKUVVGMVF5eERRVUZCTEVsQlFVc3NTVUZCUXl4RFFVRkJMRVZCUVRkRExFbEJRVzlFTEVOQlFVRXNTVUZCU3l4SlFVRkRMRU5CUVVFc1JVRkJNVVFzU1VGQmFVVXNRMEZCUVN4SlFVRkxMRWxCUVVNc1EwRkJRVHRGUVV3dlJDSjlcbiIsInZhciBRdWFudGl6ZXI7XG5cbm1vZHVsZS5leHBvcnRzID0gUXVhbnRpemVyID0gKGZ1bmN0aW9uKCkge1xuICBmdW5jdGlvbiBRdWFudGl6ZXIoKSB7fVxuXG4gIFF1YW50aXplci5wcm90b3R5cGUuaW5pdGlhbGl6ZSA9IGZ1bmN0aW9uKHBpeGVscywgb3B0cykge307XG5cbiAgUXVhbnRpemVyLnByb3RvdHlwZS5nZXRRdWFudGl6ZWRDb2xvcnMgPSBmdW5jdGlvbigpIHt9O1xuXG4gIHJldHVybiBRdWFudGl6ZXI7XG5cbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzLk1NQ1EgPSByZXF1aXJlKCcuL21tY3EnKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwybHVaR1Y0TG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwzRjFZVzUwYVhwbGNpOXBibVJsZUM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1NVRkJRVHM3UVVGQlFTeE5RVUZOTEVOQlFVTXNUMEZCVUN4SFFVTk5PenM3YzBKQlEwb3NWVUZCUVN4SFFVRlpMRk5CUVVNc1RVRkJSQ3hGUVVGVExFbEJRVlFzUjBGQlFUczdjMEpCUlZvc2EwSkJRVUVzUjBGQmIwSXNVMEZCUVN4SFFVRkJPenM3T3pzN1FVRkZkRUlzVFVGQlRTeERRVUZETEU5QlFVOHNRMEZCUXl4SlFVRm1MRWRCUVhOQ0xFOUJRVUVzUTBGQlVTeFJRVUZTSW4wPVxuIiwidmFyIE1NQ1EsIE1NQ1FJbXBsLCBRdWFudGl6ZXIsIFN3YXRjaCxcbiAgZXh0ZW5kID0gZnVuY3Rpb24oY2hpbGQsIHBhcmVudCkgeyBmb3IgKHZhciBrZXkgaW4gcGFyZW50KSB7IGlmIChoYXNQcm9wLmNhbGwocGFyZW50LCBrZXkpKSBjaGlsZFtrZXldID0gcGFyZW50W2tleV07IH0gZnVuY3Rpb24gY3RvcigpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGNoaWxkOyB9IGN0b3IucHJvdG90eXBlID0gcGFyZW50LnByb3RvdHlwZTsgY2hpbGQucHJvdG90eXBlID0gbmV3IGN0b3IoKTsgY2hpbGQuX19zdXBlcl9fID0gcGFyZW50LnByb3RvdHlwZTsgcmV0dXJuIGNoaWxkOyB9LFxuICBoYXNQcm9wID0ge30uaGFzT3duUHJvcGVydHk7XG5cblN3YXRjaCA9IHJlcXVpcmUoJy4uL3N3YXRjaCcpO1xuXG5RdWFudGl6ZXIgPSByZXF1aXJlKCcuL2luZGV4Jyk7XG5cbk1NQ1FJbXBsID0gcmVxdWlyZSgnLi9pbXBsL21tY3EnKTtcblxubW9kdWxlLmV4cG9ydHMgPSBNTUNRID0gKGZ1bmN0aW9uKHN1cGVyQ2xhc3MpIHtcbiAgZXh0ZW5kKE1NQ1EsIHN1cGVyQ2xhc3MpO1xuXG4gIGZ1bmN0aW9uIE1NQ1EoKSB7XG4gICAgcmV0dXJuIE1NQ1EuX19zdXBlcl9fLmNvbnN0cnVjdG9yLmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG4gIH1cblxuICBNTUNRLnByb3RvdHlwZS5pbml0aWFsaXplID0gZnVuY3Rpb24ocGl4ZWxzLCBvcHRzKSB7XG4gICAgdmFyIG1tY3E7XG4gICAgdGhpcy5vcHRzID0gb3B0cztcbiAgICBtbWNxID0gbmV3IE1NQ1FJbXBsKCk7XG4gICAgcmV0dXJuIHRoaXMuc3dhdGNoZXMgPSBtbWNxLnF1YW50aXplKHBpeGVscywgdGhpcy5vcHRzKTtcbiAgfTtcblxuICBNTUNRLnByb3RvdHlwZS5nZXRRdWFudGl6ZWRDb2xvcnMgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5zd2F0Y2hlcztcbiAgfTtcblxuICByZXR1cm4gTU1DUTtcblxufSkoUXVhbnRpemVyKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwyMXRZM0V1WTI5bVptVmxJaXdpYzI5MWNtTmxVbTl2ZENJNklpSXNJbk52ZFhKalpYTWlPbHNpTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmNYVmhiblJwZW1WeUwyMXRZM0V1WTI5bVptVmxJbDBzSW01aGJXVnpJanBiWFN3aWJXRndjR2x1WjNNaU9pSkJRVUZCTEVsQlFVRXNhVU5CUVVFN1JVRkJRVHM3TzBGQlFVRXNUVUZCUVN4SFFVRlRMRTlCUVVFc1EwRkJVU3hYUVVGU096dEJRVU5VTEZOQlFVRXNSMEZCV1N4UFFVRkJMRU5CUVZFc1UwRkJVanM3UVVGRFdpeFJRVUZCTEVkQlFWY3NUMEZCUVN4RFFVRlJMR0ZCUVZJN08wRkJSVmdzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFRzN096czdPenRwUWtGRFNpeFZRVUZCTEVkQlFWa3NVMEZCUXl4TlFVRkVMRVZCUVZNc1NVRkJWRHRCUVVOV0xGRkJRVUU3U1VGRWJVSXNTVUZCUXl4RFFVRkJMRTlCUVVRN1NVRkRia0lzU1VGQlFTeEhRVUZQTEVsQlFVa3NVVUZCU2l4RFFVRkJPMWRCUTFBc1NVRkJReXhEUVVGQkxGRkJRVVFzUjBGQldTeEpRVUZKTEVOQlFVTXNVVUZCVEN4RFFVRmpMRTFCUVdRc1JVRkJjMElzU1VGQlF5eERRVUZCTEVsQlFYWkNPMFZCUmtZN08ybENRVWxhTEd0Q1FVRkJMRWRCUVc5Q0xGTkJRVUU3VjBGRGJFSXNTVUZCUXl4RFFVRkJPMFZCUkdsQ096czdPMGRCVEVnaWZRPT1cbiIsInZhciBTd2F0Y2gsIHV0aWw7XG5cbnV0aWwgPSByZXF1aXJlKCcuL3V0aWwnKTtcblxuXG4vKlxuICBGcm9tIFZpYnJhbnQuanMgYnkgSmFyaSBad2FydHNcbiAgUG9ydGVkIHRvIG5vZGUuanMgYnkgQUtGaXNoXG5cbiAgU3dhdGNoIGNsYXNzXG4gKi9cblxubW9kdWxlLmV4cG9ydHMgPSBTd2F0Y2ggPSAoZnVuY3Rpb24oKSB7XG4gIFN3YXRjaC5wcm90b3R5cGUuaHNsID0gdm9pZCAwO1xuXG4gIFN3YXRjaC5wcm90b3R5cGUucmdiID0gdm9pZCAwO1xuXG4gIFN3YXRjaC5wcm90b3R5cGUucG9wdWxhdGlvbiA9IDE7XG5cbiAgU3dhdGNoLnByb3RvdHlwZS55aXEgPSAwO1xuXG4gIGZ1bmN0aW9uIFN3YXRjaChyZ2IsIHBvcHVsYXRpb24pIHtcbiAgICB0aGlzLnJnYiA9IHJnYjtcbiAgICB0aGlzLnBvcHVsYXRpb24gPSBwb3B1bGF0aW9uO1xuICB9XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRIc2wgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAoIXRoaXMuaHNsKSB7XG4gICAgICByZXR1cm4gdGhpcy5oc2wgPSB1dGlsLnJnYlRvSHNsKHRoaXMucmdiWzBdLCB0aGlzLnJnYlsxXSwgdGhpcy5yZ2JbMl0pO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gdGhpcy5oc2w7XG4gICAgfVxuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0UG9wdWxhdGlvbiA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLnBvcHVsYXRpb247XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRSZ2IgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5yZ2I7XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRIZXggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdXRpbC5yZ2JUb0hleCh0aGlzLnJnYlswXSwgdGhpcy5yZ2JbMV0sIHRoaXMucmdiWzJdKTtcbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLmdldFRpdGxlVGV4dENvbG9yID0gZnVuY3Rpb24oKSB7XG4gICAgdGhpcy5fZW5zdXJlVGV4dENvbG9ycygpO1xuICAgIGlmICh0aGlzLnlpcSA8IDIwMCkge1xuICAgICAgcmV0dXJuIFwiI2ZmZlwiO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXR1cm4gXCIjMDAwXCI7XG4gICAgfVxuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0Qm9keVRleHRDb2xvciA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX2Vuc3VyZVRleHRDb2xvcnMoKTtcbiAgICBpZiAodGhpcy55aXEgPCAxNTApIHtcbiAgICAgIHJldHVybiBcIiNmZmZcIjtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIFwiIzAwMFwiO1xuICAgIH1cbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLl9lbnN1cmVUZXh0Q29sb3JzID0gZnVuY3Rpb24oKSB7XG4gICAgaWYgKCF0aGlzLnlpcSkge1xuICAgICAgcmV0dXJuIHRoaXMueWlxID0gKHRoaXMucmdiWzBdICogMjk5ICsgdGhpcy5yZ2JbMV0gKiA1ODcgKyB0aGlzLnJnYlsyXSAqIDExNCkgLyAxMDAwO1xuICAgIH1cbiAgfTtcblxuICByZXR1cm4gU3dhdGNoO1xuXG59KSgpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12YzNkaGRHTm9MbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDNOM1lYUmphQzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzU1VGQlFUczdRVUZCUVN4SlFVRkJMRWRCUVU4c1QwRkJRU3hEUVVGUkxGRkJRVkk3T3p0QlFVTlFPenM3T3pzN08wRkJUVUVzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFR0dFFrRkRTaXhIUVVGQkxFZEJRVXM3TzIxQ1FVTk1MRWRCUVVFc1IwRkJTenM3YlVKQlEwd3NWVUZCUVN4SFFVRlpPenR0UWtGRFdpeEhRVUZCTEVkQlFVczdPMFZCUlZFc1owSkJRVU1zUjBGQlJDeEZRVUZOTEZWQlFVNDdTVUZEV0N4SlFVRkRMRU5CUVVFc1IwRkJSQ3hIUVVGUE8wbEJRMUFzU1VGQlF5eERRVUZCTEZWQlFVUXNSMEZCWXp0RlFVWklPenR0UWtGSllpeE5RVUZCTEVkQlFWRXNVMEZCUVR0SlFVTk9MRWxCUVVjc1EwRkJTU3hKUVVGRExFTkJRVUVzUjBGQlVqdGhRVU5GTEVsQlFVTXNRMEZCUVN4SFFVRkVMRWRCUVU4c1NVRkJTU3hEUVVGRExGRkJRVXdzUTBGQll5eEpRVUZETEVOQlFVRXNSMEZCU1N4RFFVRkJMRU5CUVVFc1EwRkJia0lzUlVGQmRVSXNTVUZCUXl4RFFVRkJMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRVFZDTEVWQlFXZERMRWxCUVVNc1EwRkJRU3hIUVVGSkxFTkJRVUVzUTBGQlFTeERRVUZ5UXl4RlFVUlVPMHRCUVVFc1RVRkJRVHRoUVVWTExFbEJRVU1zUTBGQlFTeEpRVVpPT3p0RlFVUk5PenR0UWtGTFVpeGhRVUZCTEVkQlFXVXNVMEZCUVR0WFFVTmlMRWxCUVVNc1EwRkJRVHRGUVVSWk96dHRRa0ZIWml4TlFVRkJMRWRCUVZFc1UwRkJRVHRYUVVOT0xFbEJRVU1zUTBGQlFUdEZRVVJMT3p0dFFrRkhVaXhOUVVGQkxFZEJRVkVzVTBGQlFUdFhRVU5PTEVsQlFVa3NRMEZCUXl4UlFVRk1MRU5CUVdNc1NVRkJReXhEUVVGQkxFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFXNUNMRVZCUVhWQ0xFbEJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVRXNRMEZCUVN4RFFVRTFRaXhGUVVGblF5eEpRVUZETEVOQlFVRXNSMEZCU1N4RFFVRkJMRU5CUVVFc1EwRkJja003UlVGRVRUczdiVUpCUjFJc2FVSkJRVUVzUjBGQmJVSXNVMEZCUVR0SlFVTnFRaXhKUVVGRExFTkJRVUVzYVVKQlFVUXNRMEZCUVR0SlFVTkJMRWxCUVVjc1NVRkJReXhEUVVGQkxFZEJRVVFzUjBGQlR5eEhRVUZXTzJGQlFXMUNMRTlCUVc1Q08wdEJRVUVzVFVGQlFUdGhRVUVyUWl4UFFVRXZRanM3UlVGR2FVSTdPMjFDUVVsdVFpeG5Ra0ZCUVN4SFFVRnJRaXhUUVVGQk8wbEJRMmhDTEVsQlFVTXNRMEZCUVN4cFFrRkJSQ3hEUVVGQk8wbEJRMEVzU1VGQlJ5eEpRVUZETEVOQlFVRXNSMEZCUkN4SFFVRlBMRWRCUVZZN1lVRkJiVUlzVDBGQmJrSTdTMEZCUVN4TlFVRkJPMkZCUVN0Q0xFOUJRUzlDT3p0RlFVWm5RanM3YlVKQlNXeENMR2xDUVVGQkxFZEJRVzFDTEZOQlFVRTdTVUZEYWtJc1NVRkJSeXhEUVVGSkxFbEJRVU1zUTBGQlFTeEhRVUZTTzJGQlFXbENMRWxCUVVNc1EwRkJRU3hIUVVGRUxFZEJRVThzUTBGQlF5eEpRVUZETEVOQlFVRXNSMEZCU1N4RFFVRkJMRU5CUVVFc1EwRkJUQ3hIUVVGVkxFZEJRVllzUjBGQlowSXNTVUZCUXl4RFFVRkJMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRVXdzUjBGQlZTeEhRVUV4UWl4SFFVRm5ReXhKUVVGRExFTkJRVUVzUjBGQlNTeERRVUZCTEVOQlFVRXNRMEZCVEN4SFFVRlZMRWRCUVRORExFTkJRVUVzUjBGQmEwUXNTMEZCTVVVN08wVkJSR2xDSW4wPVxuIiwidmFyIERFTFRBRTk0LCBSU0hJRlQsIFNJR0JJVFM7XG5cbkRFTFRBRTk0ID0ge1xuICBOQTogMCxcbiAgUEVSRkVDVDogMSxcbiAgQ0xPU0U6IDIsXG4gIEdPT0Q6IDEwLFxuICBTSU1JTEFSOiA1MFxufTtcblxuU0lHQklUUyA9IDU7XG5cblJTSElGVCA9IDggLSBTSUdCSVRTO1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgY2xvbmU6IGZ1bmN0aW9uKG8pIHtcbiAgICB2YXIgX28sIGtleSwgdmFsdWU7XG4gICAgaWYgKHR5cGVvZiBvID09PSAnb2JqZWN0Jykge1xuICAgICAgaWYgKEFycmF5LmlzQXJyYXkobykpIHtcbiAgICAgICAgcmV0dXJuIG8ubWFwKChmdW5jdGlvbihfdGhpcykge1xuICAgICAgICAgIHJldHVybiBmdW5jdGlvbih2KSB7XG4gICAgICAgICAgICByZXR1cm4gX3RoaXMuY2xvbmUodik7XG4gICAgICAgICAgfTtcbiAgICAgICAgfSkodGhpcykpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgX28gPSB7fTtcbiAgICAgICAgZm9yIChrZXkgaW4gbykge1xuICAgICAgICAgIHZhbHVlID0gb1trZXldO1xuICAgICAgICAgIF9vW2tleV0gPSB0aGlzLmNsb25lKHZhbHVlKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gX287XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBvO1xuICB9LFxuICBkZWZhdWx0czogZnVuY3Rpb24oKSB7XG4gICAgdmFyIF9vLCBpLCBrZXksIGxlbiwgbywgdmFsdWU7XG4gICAgbyA9IHt9O1xuICAgIGZvciAoaSA9IDAsIGxlbiA9IGFyZ3VtZW50cy5sZW5ndGg7IGkgPCBsZW47IGkrKykge1xuICAgICAgX28gPSBhcmd1bWVudHNbaV07XG4gICAgICBmb3IgKGtleSBpbiBfbykge1xuICAgICAgICB2YWx1ZSA9IF9vW2tleV07XG4gICAgICAgIGlmIChvW2tleV0gPT0gbnVsbCkge1xuICAgICAgICAgIG9ba2V5XSA9IHRoaXMuY2xvbmUodmFsdWUpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBvO1xuICB9LFxuICBoZXhUb1JnYjogZnVuY3Rpb24oaGV4KSB7XG4gICAgdmFyIG07XG4gICAgbSA9IC9eIz8oW2EtZlxcZF17Mn0pKFthLWZcXGRdezJ9KShbYS1mXFxkXXsyfSkkL2kuZXhlYyhoZXgpO1xuICAgIGlmIChtICE9IG51bGwpIHtcbiAgICAgIHJldHVybiBbbVsxXSwgbVsyXSwgbVszXV0ubWFwKGZ1bmN0aW9uKHMpIHtcbiAgICAgICAgcmV0dXJuIHBhcnNlSW50KHMsIDE2KTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICByZXR1cm4gbnVsbDtcbiAgfSxcbiAgcmdiVG9IZXg6IGZ1bmN0aW9uKHIsIGcsIGIpIHtcbiAgICByZXR1cm4gXCIjXCIgKyAoKDEgPDwgMjQpICsgKHIgPDwgMTYpICsgKGcgPDwgOCkgKyBiKS50b1N0cmluZygxNikuc2xpY2UoMSwgNyk7XG4gIH0sXG4gIHJnYlRvSHNsOiBmdW5jdGlvbihyLCBnLCBiKSB7XG4gICAgdmFyIGQsIGgsIGwsIG1heCwgbWluLCBzO1xuICAgIHIgLz0gMjU1O1xuICAgIGcgLz0gMjU1O1xuICAgIGIgLz0gMjU1O1xuICAgIG1heCA9IE1hdGgubWF4KHIsIGcsIGIpO1xuICAgIG1pbiA9IE1hdGgubWluKHIsIGcsIGIpO1xuICAgIGggPSB2b2lkIDA7XG4gICAgcyA9IHZvaWQgMDtcbiAgICBsID0gKG1heCArIG1pbikgLyAyO1xuICAgIGlmIChtYXggPT09IG1pbikge1xuICAgICAgaCA9IHMgPSAwO1xuICAgIH0gZWxzZSB7XG4gICAgICBkID0gbWF4IC0gbWluO1xuICAgICAgcyA9IGwgPiAwLjUgPyBkIC8gKDIgLSBtYXggLSBtaW4pIDogZCAvIChtYXggKyBtaW4pO1xuICAgICAgc3dpdGNoIChtYXgpIHtcbiAgICAgICAgY2FzZSByOlxuICAgICAgICAgIGggPSAoZyAtIGIpIC8gZCArIChnIDwgYiA/IDYgOiAwKTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgY2FzZSBnOlxuICAgICAgICAgIGggPSAoYiAtIHIpIC8gZCArIDI7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgYjpcbiAgICAgICAgICBoID0gKHIgLSBnKSAvIGQgKyA0O1xuICAgICAgfVxuICAgICAgaCAvPSA2O1xuICAgIH1cbiAgICByZXR1cm4gW2gsIHMsIGxdO1xuICB9LFxuICBoc2xUb1JnYjogZnVuY3Rpb24oaCwgcywgbCkge1xuICAgIHZhciBiLCBnLCBodWUycmdiLCBwLCBxLCByO1xuICAgIHIgPSB2b2lkIDA7XG4gICAgZyA9IHZvaWQgMDtcbiAgICBiID0gdm9pZCAwO1xuICAgIGh1ZTJyZ2IgPSBmdW5jdGlvbihwLCBxLCB0KSB7XG4gICAgICBpZiAodCA8IDApIHtcbiAgICAgICAgdCArPSAxO1xuICAgICAgfVxuICAgICAgaWYgKHQgPiAxKSB7XG4gICAgICAgIHQgLT0gMTtcbiAgICAgIH1cbiAgICAgIGlmICh0IDwgMSAvIDYpIHtcbiAgICAgICAgcmV0dXJuIHAgKyAocSAtIHApICogNiAqIHQ7XG4gICAgICB9XG4gICAgICBpZiAodCA8IDEgLyAyKSB7XG4gICAgICAgIHJldHVybiBxO1xuICAgICAgfVxuICAgICAgaWYgKHQgPCAyIC8gMykge1xuICAgICAgICByZXR1cm4gcCArIChxIC0gcCkgKiAoMiAvIDMgLSB0KSAqIDY7XG4gICAgICB9XG4gICAgICByZXR1cm4gcDtcbiAgICB9O1xuICAgIGlmIChzID09PSAwKSB7XG4gICAgICByID0gZyA9IGIgPSBsO1xuICAgIH0gZWxzZSB7XG4gICAgICBxID0gbCA8IDAuNSA/IGwgKiAoMSArIHMpIDogbCArIHMgLSAobCAqIHMpO1xuICAgICAgcCA9IDIgKiBsIC0gcTtcbiAgICAgIHIgPSBodWUycmdiKHAsIHEsIGggKyAxIC8gMyk7XG4gICAgICBnID0gaHVlMnJnYihwLCBxLCBoKTtcbiAgICAgIGIgPSBodWUycmdiKHAsIHEsIGggLSAoMSAvIDMpKTtcbiAgICB9XG4gICAgcmV0dXJuIFtyICogMjU1LCBnICogMjU1LCBiICogMjU1XTtcbiAgfSxcbiAgcmdiVG9YeXo6IGZ1bmN0aW9uKHIsIGcsIGIpIHtcbiAgICB2YXIgeCwgeSwgejtcbiAgICByIC89IDI1NTtcbiAgICBnIC89IDI1NTtcbiAgICBiIC89IDI1NTtcbiAgICByID0gciA+IDAuMDQwNDUgPyBNYXRoLnBvdygociArIDAuMDA1KSAvIDEuMDU1LCAyLjQpIDogciAvIDEyLjkyO1xuICAgIGcgPSBnID4gMC4wNDA0NSA/IE1hdGgucG93KChnICsgMC4wMDUpIC8gMS4wNTUsIDIuNCkgOiBnIC8gMTIuOTI7XG4gICAgYiA9IGIgPiAwLjA0MDQ1ID8gTWF0aC5wb3coKGIgKyAwLjAwNSkgLyAxLjA1NSwgMi40KSA6IGIgLyAxMi45MjtcbiAgICByICo9IDEwMDtcbiAgICBnICo9IDEwMDtcbiAgICBiICo9IDEwMDtcbiAgICB4ID0gciAqIDAuNDEyNCArIGcgKiAwLjM1NzYgKyBiICogMC4xODA1O1xuICAgIHkgPSByICogMC4yMTI2ICsgZyAqIDAuNzE1MiArIGIgKiAwLjA3MjI7XG4gICAgeiA9IHIgKiAwLjAxOTMgKyBnICogMC4xMTkyICsgYiAqIDAuOTUwNTtcbiAgICByZXR1cm4gW3gsIHksIHpdO1xuICB9LFxuICB4eXpUb0NJRUxhYjogZnVuY3Rpb24oeCwgeSwgeikge1xuICAgIHZhciBMLCBSRUZfWCwgUkVGX1ksIFJFRl9aLCBhLCBiO1xuICAgIFJFRl9YID0gOTUuMDQ3O1xuICAgIFJFRl9ZID0gMTAwO1xuICAgIFJFRl9aID0gMTA4Ljg4MztcbiAgICB4IC89IFJFRl9YO1xuICAgIHkgLz0gUkVGX1k7XG4gICAgeiAvPSBSRUZfWjtcbiAgICB4ID0geCA+IDAuMDA4ODU2ID8gTWF0aC5wb3coeCwgMSAvIDMpIDogNy43ODcgKiB4ICsgMTYgLyAxMTY7XG4gICAgeSA9IHkgPiAwLjAwODg1NiA/IE1hdGgucG93KHksIDEgLyAzKSA6IDcuNzg3ICogeSArIDE2IC8gMTE2O1xuICAgIHogPSB6ID4gMC4wMDg4NTYgPyBNYXRoLnBvdyh6LCAxIC8gMykgOiA3Ljc4NyAqIHogKyAxNiAvIDExNjtcbiAgICBMID0gMTE2ICogeSAtIDE2O1xuICAgIGEgPSA1MDAgKiAoeCAtIHkpO1xuICAgIGIgPSAyMDAgKiAoeSAtIHopO1xuICAgIHJldHVybiBbTCwgYSwgYl07XG4gIH0sXG4gIHJnYlRvQ0lFTGFiOiBmdW5jdGlvbihyLCBnLCBiKSB7XG4gICAgdmFyIHJlZiwgeCwgeSwgejtcbiAgICByZWYgPSB0aGlzLnJnYlRvWHl6KHIsIGcsIGIpLCB4ID0gcmVmWzBdLCB5ID0gcmVmWzFdLCB6ID0gcmVmWzJdO1xuICAgIHJldHVybiB0aGlzLnh5elRvQ0lFTGFiKHgsIHksIHopO1xuICB9LFxuICBkZWx0YUU5NDogZnVuY3Rpb24obGFiMSwgbGFiMikge1xuICAgIHZhciBMMSwgTDIsIFdFSUdIVF9DLCBXRUlHSFRfSCwgV0VJR0hUX0wsIGExLCBhMiwgYjEsIGIyLCBkTCwgZGEsIGRiLCB4QzEsIHhDMiwgeERDLCB4REUsIHhESCwgeERMLCB4U0MsIHhTSDtcbiAgICBXRUlHSFRfTCA9IDE7XG4gICAgV0VJR0hUX0MgPSAxO1xuICAgIFdFSUdIVF9IID0gMTtcbiAgICBMMSA9IGxhYjFbMF0sIGExID0gbGFiMVsxXSwgYjEgPSBsYWIxWzJdO1xuICAgIEwyID0gbGFiMlswXSwgYTIgPSBsYWIyWzFdLCBiMiA9IGxhYjJbMl07XG4gICAgZEwgPSBMMSAtIEwyO1xuICAgIGRhID0gYTEgLSBhMjtcbiAgICBkYiA9IGIxIC0gYjI7XG4gICAgeEMxID0gTWF0aC5zcXJ0KGExICogYTEgKyBiMSAqIGIxKTtcbiAgICB4QzIgPSBNYXRoLnNxcnQoYTIgKiBhMiArIGIyICogYjIpO1xuICAgIHhETCA9IEwyIC0gTDE7XG4gICAgeERDID0geEMyIC0geEMxO1xuICAgIHhERSA9IE1hdGguc3FydChkTCAqIGRMICsgZGEgKiBkYSArIGRiICogZGIpO1xuICAgIGlmIChNYXRoLnNxcnQoeERFKSA+IE1hdGguc3FydChNYXRoLmFicyh4REwpKSArIE1hdGguc3FydChNYXRoLmFicyh4REMpKSkge1xuICAgICAgeERIID0gTWF0aC5zcXJ0KHhERSAqIHhERSAtIHhETCAqIHhETCAtIHhEQyAqIHhEQyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHhESCA9IDA7XG4gICAgfVxuICAgIHhTQyA9IDEgKyAwLjA0NSAqIHhDMTtcbiAgICB4U0ggPSAxICsgMC4wMTUgKiB4QzE7XG4gICAgeERMIC89IFdFSUdIVF9MO1xuICAgIHhEQyAvPSBXRUlHSFRfQyAqIHhTQztcbiAgICB4REggLz0gV0VJR0hUX0ggKiB4U0g7XG4gICAgcmV0dXJuIE1hdGguc3FydCh4REwgKiB4REwgKyB4REMgKiB4REMgKyB4REggKiB4REgpO1xuICB9LFxuICByZ2JEaWZmOiBmdW5jdGlvbihyZ2IxLCByZ2IyKSB7XG4gICAgdmFyIGxhYjEsIGxhYjI7XG4gICAgbGFiMSA9IHRoaXMucmdiVG9DSUVMYWIuYXBwbHkodGhpcywgcmdiMSk7XG4gICAgbGFiMiA9IHRoaXMucmdiVG9DSUVMYWIuYXBwbHkodGhpcywgcmdiMik7XG4gICAgcmV0dXJuIHRoaXMuZGVsdGFFOTQobGFiMSwgbGFiMik7XG4gIH0sXG4gIGhleERpZmY6IGZ1bmN0aW9uKGhleDEsIGhleDIpIHtcbiAgICB2YXIgcmdiMSwgcmdiMjtcbiAgICByZ2IxID0gdGhpcy5oZXhUb1JnYihoZXgxKTtcbiAgICByZ2IyID0gdGhpcy5oZXhUb1JnYihoZXgyKTtcbiAgICByZXR1cm4gdGhpcy5yZ2JEaWZmKHJnYjEsIHJnYjIpO1xuICB9LFxuICBERUxUQUU5NF9ESUZGX1NUQVRVUzogREVMVEFFOTQsXG4gIGdldENvbG9yRGlmZlN0YXR1czogZnVuY3Rpb24oZCkge1xuICAgIGlmIChkIDwgREVMVEFFOTQuTkEpIHtcbiAgICAgIHJldHVybiBcIk4vQVwiO1xuICAgIH1cbiAgICBpZiAoZCA8PSBERUxUQUU5NC5QRVJGRUNUKSB7XG4gICAgICByZXR1cm4gXCJQZXJmZWN0XCI7XG4gICAgfVxuICAgIGlmIChkIDw9IERFTFRBRTk0LkNMT1NFKSB7XG4gICAgICByZXR1cm4gXCJDbG9zZVwiO1xuICAgIH1cbiAgICBpZiAoZCA8PSBERUxUQUU5NC5HT09EKSB7XG4gICAgICByZXR1cm4gXCJHb29kXCI7XG4gICAgfVxuICAgIGlmIChkIDwgREVMVEFFOTQuU0lNSUxBUikge1xuICAgICAgcmV0dXJuIFwiU2ltaWxhclwiO1xuICAgIH1cbiAgICByZXR1cm4gXCJXcm9uZ1wiO1xuICB9LFxuICBTSUdCSVRTOiBTSUdCSVRTLFxuICBSU0hJRlQ6IFJTSElGVCxcbiAgZ2V0Q29sb3JJbmRleDogZnVuY3Rpb24ociwgZywgYikge1xuICAgIHJldHVybiAociA8PCAoMiAqIFNJR0JJVFMpKSArIChnIDw8IFNJR0JJVFMpICsgYjtcbiAgfVxufTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmRYUnBiQzVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5MWRHbHNMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaVFVRkJRU3hKUVVGQk96dEJRVUZCTEZGQlFVRXNSMEZEUlR0RlFVRkJMRVZCUVVFc1JVRkJTU3hEUVVGS08wVkJRMEVzVDBGQlFTeEZRVUZUTEVOQlJGUTdSVUZGUVN4TFFVRkJMRVZCUVU4c1EwRkdVRHRGUVVkQkxFbEJRVUVzUlVGQlRTeEZRVWhPTzBWQlNVRXNUMEZCUVN4RlFVRlRMRVZCU2xRN096dEJRVTFHTEU5QlFVRXNSMEZCVlRzN1FVRkRWaXhOUVVGQkxFZEJRVk1zUTBGQlFTeEhRVUZKT3p0QlFVbGlMRTFCUVUwc1EwRkJReXhQUVVGUUxFZEJRMFU3UlVGQlFTeExRVUZCTEVWQlFVOHNVMEZCUXl4RFFVRkVPMEZCUTB3c1VVRkJRVHRKUVVGQkxFbEJRVWNzVDBGQlR5eERRVUZRTEV0QlFWa3NVVUZCWmp0TlFVTkZMRWxCUVVjc1MwRkJTeXhEUVVGRExFOUJRVTRzUTBGQll5eERRVUZrTEVOQlFVZzdRVUZEUlN4bFFVRlBMRU5CUVVNc1EwRkJReXhIUVVGR0xFTkJRVTBzUTBGQlFTeFRRVUZCTEV0QlFVRTdhVUpCUVVFc1UwRkJReXhEUVVGRU8yMUNRVUZQTEV0QlFVa3NRMEZCUXl4TFFVRk1MRU5CUVZjc1EwRkJXRHRWUVVGUU8xRkJRVUVzUTBGQlFTeERRVUZCTEVOQlFVRXNTVUZCUVN4RFFVRk9MRVZCUkZRN1QwRkJRU3hOUVVGQk8xRkJSMFVzUlVGQlFTeEhRVUZMTzBGQlEwd3NZVUZCUVN4UlFVRkJPenRWUVVORkxFVkJRVWNzUTBGQlFTeEhRVUZCTEVOQlFVZ3NSMEZCVlN4SlFVRkpMRU5CUVVNc1MwRkJUQ3hEUVVGWExFdEJRVmc3UVVGRVdqdEJRVVZCTEdWQlFVOHNSMEZPVkR0UFFVUkdPenRYUVZGQk8wVkJWRXNzUTBGQlVEdEZRVmRCTEZGQlFVRXNSVUZCVlN4VFFVRkJPMEZCUTFJc1VVRkJRVHRKUVVGQkxFTkJRVUVzUjBGQlNUdEJRVU5LTEZOQlFVRXNNa05CUVVFN08wRkJRMFVzVjBGQlFTeFRRVUZCT3p0UlFVTkZMRWxCUVU4c1kwRkJVRHRWUVVGdlFpeERRVUZGTEVOQlFVRXNSMEZCUVN4RFFVRkdMRWRCUVZNc1NVRkJTU3hEUVVGRExFdEJRVXdzUTBGQlZ5eExRVUZZTEVWQlFUZENPenRCUVVSR08wRkJSRVk3VjBGSlFUdEZRVTVSTEVOQldGWTdSVUZ0UWtFc1VVRkJRU3hGUVVGVkxGTkJRVU1zUjBGQlJEdEJRVU5TTEZGQlFVRTdTVUZCUVN4RFFVRkJMRWRCUVVrc01rTkJRVEpETEVOQlFVTXNTVUZCTlVNc1EwRkJhVVFzUjBGQmFrUTdTVUZEU2l4SlFVRkhMRk5CUVVnN1FVRkRSU3hoUVVGUExFTkJRVU1zUTBGQlJTeERRVUZCTEVOQlFVRXNRMEZCU0N4RlFVRlBMRU5CUVVVc1EwRkJRU3hEUVVGQkxFTkJRVlFzUlVGQllTeERRVUZGTEVOQlFVRXNRMEZCUVN4RFFVRm1MRU5CUVd0Q0xFTkJRVU1zUjBGQmJrSXNRMEZCZFVJc1UwRkJReXhEUVVGRU8yVkJRVThzVVVGQlFTeERRVUZUTEVOQlFWUXNSVUZCV1N4RlFVRmFPMDFCUVZBc1EwRkJka0lzUlVGRVZEczdRVUZGUVN4WFFVRlBPMFZCU2tNc1EwRnVRbFk3UlVGNVFrRXNVVUZCUVN4RlFVRlZMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzFkQlExSXNSMEZCUVN4SFFVRk5MRU5CUVVNc1EwRkJReXhEUVVGQkxFbEJRVXNzUlVGQlRpeERRVUZCTEVkQlFWa3NRMEZCUXl4RFFVRkJMRWxCUVVzc1JVRkJUaXhEUVVGYUxFZEJRWGRDTEVOQlFVTXNRMEZCUVN4SlFVRkxMRU5CUVU0c1EwRkJlRUlzUjBGQmJVTXNRMEZCY0VNc1EwRkJjME1zUTBGQlF5eFJRVUYyUXl4RFFVRm5SQ3hGUVVGb1JDeERRVUZ0UkN4RFFVRkRMRXRCUVhCRUxFTkJRVEJFTEVOQlFURkVMRVZCUVRaRUxFTkJRVGRFTzBWQlJFVXNRMEY2UWxZN1JVRTBRa0VzVVVGQlFTeEZRVUZWTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8wRkJRMUlzVVVGQlFUdEpRVUZCTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVU5NTEVkQlFVRXNSMEZCVFN4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFTkJRVlFzUlVGQldTeERRVUZhTEVWQlFXVXNRMEZCWmp0SlFVTk9MRWRCUVVFc1IwRkJUU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVOQlFWUXNSVUZCV1N4RFFVRmFMRVZCUVdVc1EwRkJaanRKUVVOT0xFTkJRVUVzUjBGQlNUdEpRVU5LTEVOQlFVRXNSMEZCU1R0SlFVTktMRU5CUVVFc1IwRkJTU3hEUVVGRExFZEJRVUVzUjBGQlRTeEhRVUZRTEVOQlFVRXNSMEZCWXp0SlFVTnNRaXhKUVVGSExFZEJRVUVzUzBGQlR5eEhRVUZXTzAxQlEwVXNRMEZCUVN4SFFVRkpMRU5CUVVFc1IwRkJTU3hGUVVSV08wdEJRVUVzVFVGQlFUdE5RVWxGTEVOQlFVRXNSMEZCU1N4SFFVRkJMRWRCUVUwN1RVRkRWaXhEUVVGQkxFZEJRVThzUTBGQlFTeEhRVUZKTEVkQlFWQXNSMEZCWjBJc1EwRkJRU3hIUVVGSkxFTkJRVU1zUTBGQlFTeEhRVUZKTEVkQlFVb3NSMEZCVlN4SFFVRllMRU5CUVhCQ0xFZEJRWGxETEVOQlFVRXNSMEZCU1N4RFFVRkRMRWRCUVVFc1IwRkJUU3hIUVVGUU8wRkJRMnBFTEdOQlFVOHNSMEZCVUR0QlFVRkJMR0ZCUTA4c1EwRkVVRHRWUVVWSkxFTkJRVUVzUjBGQlNTeERRVUZETEVOQlFVRXNSMEZCU1N4RFFVRk1MRU5CUVVFc1IwRkJWU3hEUVVGV0xFZEJRV01zUTBGQlNTeERRVUZCTEVkQlFVa3NRMEZCVUN4SFFVRmpMRU5CUVdRc1IwRkJjVUlzUTBGQmRFSTdRVUZFWmp0QlFVUlFMR0ZCUjA4c1EwRklVRHRWUVVsSkxFTkJRVUVzUjBGQlNTeERRVUZETEVOQlFVRXNSMEZCU1N4RFFVRk1MRU5CUVVFc1IwRkJWU3hEUVVGV0xFZEJRV003UVVGRVpqdEJRVWhRTEdGQlMwOHNRMEZNVUR0VlFVMUpMRU5CUVVFc1IwRkJTU3hEUVVGRExFTkJRVUVzUjBGQlNTeERRVUZNTEVOQlFVRXNSMEZCVlN4RFFVRldMRWRCUVdNN1FVRk9kRUk3VFVGUFFTeERRVUZCTEVsQlFVc3NSVUZpVURzN1YwRmpRU3hEUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUR0RlFYWkNVU3hEUVRWQ1ZqdEZRWEZFUVN4UlFVRkJMRVZCUVZVc1UwRkJReXhEUVVGRUxFVkJRVWtzUTBGQlNpeEZRVUZQTEVOQlFWQTdRVUZEVWl4UlFVRkJPMGxCUVVFc1EwRkJRU3hIUVVGSk8wbEJRMG9zUTBGQlFTeEhRVUZKTzBsQlEwb3NRMEZCUVN4SFFVRkpPMGxCUlVvc1QwRkJRU3hIUVVGVkxGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMDFCUTFJc1NVRkJSeXhEUVVGQkxFZEJRVWtzUTBGQlVEdFJRVU5GTEVOQlFVRXNTVUZCU3l4RlFVUlFPenROUVVWQkxFbEJRVWNzUTBGQlFTeEhRVUZKTEVOQlFWQTdVVUZEUlN4RFFVRkJMRWxCUVVzc1JVRkVVRHM3VFVGRlFTeEpRVUZITEVOQlFVRXNSMEZCU1N4RFFVRkJMRWRCUVVrc1EwRkJXRHRCUVVORkxHVkJRVThzUTBGQlFTeEhRVUZKTEVOQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVV3c1EwRkJRU3hIUVVGVkxFTkJRVllzUjBGQll5eEZRVVF6UWpzN1RVRkZRU3hKUVVGSExFTkJRVUVzUjBGQlNTeERRVUZCTEVkQlFVa3NRMEZCV0R0QlFVTkZMR1ZCUVU4c1JVRkVWRHM3VFVGRlFTeEpRVUZITEVOQlFVRXNSMEZCU1N4RFFVRkJMRWRCUVVrc1EwRkJXRHRCUVVORkxHVkJRVThzUTBGQlFTeEhRVUZKTEVOQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVV3c1EwRkJRU3hIUVVGVkxFTkJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVb3NSMEZCVVN4RFFVRlVMRU5CUVZZc1IwRkJkMElzUlVGRWNrTTdPMkZCUlVFN1NVRllVVHRKUVdGV0xFbEJRVWNzUTBGQlFTeExRVUZMTEVOQlFWSTdUVUZEUlN4RFFVRkJMRWRCUVVrc1EwRkJRU3hIUVVGSkxFTkJRVUVzUjBGQlNTeEZRVVJrTzB0QlFVRXNUVUZCUVR0TlFVbEZMRU5CUVVFc1IwRkJUeXhEUVVGQkxFZEJRVWtzUjBGQlVDeEhRVUZuUWl4RFFVRkJMRWRCUVVrc1EwRkJReXhEUVVGQkxFZEJRVWtzUTBGQlRDeERRVUZ3UWl4SFFVRnBReXhEUVVGQkxFZEJRVWtzUTBGQlNpeEhRVUZSTEVOQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVV3N1RVRkROME1zUTBGQlFTeEhRVUZKTEVOQlFVRXNSMEZCU1N4RFFVRktMRWRCUVZFN1RVRkRXaXhEUVVGQkxFZEJRVWtzVDBGQlFTeERRVUZSTEVOQlFWSXNSVUZCVnl4RFFVRllMRVZCUVdNc1EwRkJRU3hIUVVGSkxFTkJRVUVzUjBGQlNTeERRVUYwUWp0TlFVTktMRU5CUVVFc1IwRkJTU3hQUVVGQkxFTkJRVkVzUTBGQlVpeEZRVUZYTEVOQlFWZ3NSVUZCWXl4RFFVRmtPMDFCUTBvc1EwRkJRU3hIUVVGSkxFOUJRVUVzUTBGQlVTeERRVUZTTEVWQlFWY3NRMEZCV0N4RlFVRmpMRU5CUVVFc1IwRkJTU3hEUVVGRExFTkJRVUVzUjBGQlNTeERRVUZNTEVOQlFXeENMRVZCVWs0N08xZEJVMEVzUTBGRFJTeERRVUZCTEVkQlFVa3NSMEZFVGl4RlFVVkZMRU5CUVVFc1IwRkJTU3hIUVVaT0xFVkJSMFVzUTBGQlFTeEhRVUZKTEVkQlNFNDdSVUV6UWxFc1EwRnlSRlk3UlVGelJrRXNVVUZCUVN4RlFVRlZMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzBGQlExSXNVVUZCUVR0SlFVRkJMRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1IwRkJUeXhEUVVGQkxFZEJRVWtzVDBGQlVDeEhRVUZ2UWl4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFTkJRVU1zUTBGQlFTeEhRVUZKTEV0QlFVd3NRMEZCUVN4SFFVRmpMRXRCUVhaQ0xFVkJRVGhDTEVkQlFUbENMRU5CUVhCQ0xFZEJRVFJFTEVOQlFVRXNSMEZCU1R0SlFVTndSU3hEUVVGQkxFZEJRVThzUTBGQlFTeEhRVUZKTEU5QlFWQXNSMEZCYjBJc1NVRkJTU3hEUVVGRExFZEJRVXdzUTBGQlV5eERRVUZETEVOQlFVRXNSMEZCU1N4TFFVRk1MRU5CUVVFc1IwRkJZeXhMUVVGMlFpeEZRVUU0UWl4SFFVRTVRaXhEUVVGd1FpeEhRVUUwUkN4RFFVRkJMRWRCUVVrN1NVRkRjRVVzUTBGQlFTeEhRVUZQTEVOQlFVRXNSMEZCU1N4UFFVRlFMRWRCUVc5Q0xFbEJRVWtzUTBGQlF5eEhRVUZNTEVOQlFWTXNRMEZCUXl4RFFVRkJMRWRCUVVrc1MwRkJUQ3hEUVVGQkxFZEJRV01zUzBGQmRrSXNSVUZCT0VJc1IwRkJPVUlzUTBGQmNFSXNSMEZCTkVRc1EwRkJRU3hIUVVGSk8wbEJSWEJGTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVVZNTEVOQlFVRXNSMEZCU1N4RFFVRkJMRWRCUVVrc1RVRkJTaXhIUVVGaExFTkJRVUVzUjBGQlNTeE5RVUZxUWl4SFFVRXdRaXhEUVVGQkxFZEJRVWs3U1VGRGJFTXNRMEZCUVN4SFFVRkpMRU5CUVVFc1IwRkJTU3hOUVVGS0xFZEJRV0VzUTBGQlFTeEhRVUZKTEUxQlFXcENMRWRCUVRCQ0xFTkJRVUVzUjBGQlNUdEpRVU5zUXl4RFFVRkJMRWRCUVVrc1EwRkJRU3hIUVVGSkxFMUJRVW9zUjBGQllTeERRVUZCTEVkQlFVa3NUVUZCYWtJc1IwRkJNRUlzUTBGQlFTeEhRVUZKTzFkQlJXeERMRU5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzBWQmFFSlJMRU5CZEVaV08wVkJkMGRCTEZkQlFVRXNSVUZCWVN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVEdEJRVU5ZTEZGQlFVRTdTVUZCUVN4TFFVRkJMRWRCUVZFN1NVRkRVaXhMUVVGQkxFZEJRVkU3U1VGRFVpeExRVUZCTEVkQlFWRTdTVUZGVWl4RFFVRkJMRWxCUVVzN1NVRkRUQ3hEUVVGQkxFbEJRVXM3U1VGRFRDeERRVUZCTEVsQlFVczdTVUZGVEN4RFFVRkJMRWRCUVU4c1EwRkJRU3hIUVVGSkxGRkJRVkFzUjBGQmNVSXNTVUZCU1N4RFFVRkRMRWRCUVV3c1EwRkJVeXhEUVVGVUxFVkJRVmtzUTBGQlFTeEhRVUZGTEVOQlFXUXNRMEZCY2tJc1IwRkJNa01zUzBGQlFTeEhRVUZSTEVOQlFWSXNSMEZCV1N4RlFVRkJMRWRCUVVzN1NVRkRhRVVzUTBGQlFTeEhRVUZQTEVOQlFVRXNSMEZCU1N4UlFVRlFMRWRCUVhGQ0xFbEJRVWtzUTBGQlF5eEhRVUZNTEVOQlFWTXNRMEZCVkN4RlFVRlpMRU5CUVVFc1IwRkJSU3hEUVVGa0xFTkJRWEpDTEVkQlFUSkRMRXRCUVVFc1IwRkJVU3hEUVVGU0xFZEJRVmtzUlVGQlFTeEhRVUZMTzBsQlEyaEZMRU5CUVVFc1IwRkJUeXhEUVVGQkxFZEJRVWtzVVVGQlVDeEhRVUZ4UWl4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFTkJRVlFzUlVGQldTeERRVUZCTEVkQlFVVXNRMEZCWkN4RFFVRnlRaXhIUVVFeVF5eExRVUZCTEVkQlFWRXNRMEZCVWl4SFFVRlpMRVZCUVVFc1IwRkJTenRKUVVWb1JTeERRVUZCTEVkQlFVa3NSMEZCUVN4SFFVRk5MRU5CUVU0c1IwRkJWVHRKUVVOa0xFTkJRVUVzUjBGQlNTeEhRVUZCTEVkQlFVMHNRMEZCUXl4RFFVRkJMRWRCUVVrc1EwRkJURHRKUVVOV0xFTkJRVUVzUjBGQlNTeEhRVUZCTEVkQlFVMHNRMEZCUXl4RFFVRkJMRWRCUVVrc1EwRkJURHRYUVVWV0xFTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMFZCYWtKWExFTkJlRWRpTzBWQk1raEJMRmRCUVVFc1JVRkJZU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUR0QlFVTllMRkZCUVVFN1NVRkJRU3hOUVVGWkxFbEJRVWtzUTBGQlF5eFJRVUZNTEVOQlFXTXNRMEZCWkN4RlFVRnBRaXhEUVVGcVFpeEZRVUZ2UWl4RFFVRndRaXhEUVVGYUxFVkJRVU1zVlVGQlJDeEZRVUZKTEZWQlFVb3NSVUZCVHp0WFFVTlFMRWxCUVVrc1EwRkJReXhYUVVGTUxFTkJRV2xDTEVOQlFXcENMRVZCUVc5Q0xFTkJRWEJDTEVWQlFYVkNMRU5CUVhaQ08wVkJSbGNzUTBFelNHSTdSVUVyU0VFc1VVRkJRU3hGUVVGVkxGTkJRVU1zU1VGQlJDeEZRVUZQTEVsQlFWQTdRVUZGVWl4UlFVRkJPMGxCUVVFc1VVRkJRU3hIUVVGWE8wbEJRMWdzVVVGQlFTeEhRVUZYTzBsQlExZ3NVVUZCUVN4SFFVRlhPMGxCUlZZc1dVRkJSQ3hGUVVGTExGbEJRVXdzUlVGQlV6dEpRVU5TTEZsQlFVUXNSVUZCU3l4WlFVRk1MRVZCUVZNN1NVRkRWQ3hGUVVGQkxFZEJRVXNzUlVGQlFTeEhRVUZMTzBsQlExWXNSVUZCUVN4SFFVRkxMRVZCUVVFc1IwRkJTenRKUVVOV0xFVkJRVUVzUjBGQlN5eEZRVUZCTEVkQlFVczdTVUZGVml4SFFVRkJMRWRCUVUwc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEZRVUZCTEVkQlFVc3NSVUZCVEN4SFFVRlZMRVZCUVVFc1IwRkJTeXhGUVVGNlFqdEpRVU5PTEVkQlFVRXNSMEZCVFN4SlFVRkpMRU5CUVVNc1NVRkJUQ3hEUVVGVkxFVkJRVUVzUjBGQlN5eEZRVUZNTEVkQlFWVXNSVUZCUVN4SFFVRkxMRVZCUVhwQ08wbEJSVTRzUjBGQlFTeEhRVUZOTEVWQlFVRXNSMEZCU3p0SlFVTllMRWRCUVVFc1IwRkJUU3hIUVVGQkxFZEJRVTA3U1VGRFdpeEhRVUZCTEVkQlFVMHNTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hGUVVGQkxFZEJRVXNzUlVGQlRDeEhRVUZWTEVWQlFVRXNSMEZCU3l4RlFVRm1MRWRCUVc5Q0xFVkJRVUVzUjBGQlN5eEZRVUZ1UXp0SlFVVk9MRWxCUVVjc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEhRVUZXTEVOQlFVRXNSMEZCYVVJc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRWRCUVZRc1EwRkJWaXhEUVVGQkxFZEJRVEpDTEVsQlFVa3NRMEZCUXl4SlFVRk1MRU5CUVZVc1NVRkJTU3hEUVVGRExFZEJRVXdzUTBGQlV5eEhRVUZVTEVOQlFWWXNRMEZCTDBNN1RVRkRSU3hIUVVGQkxFZEJRVTBzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4SFFVRkJMRWRCUVUwc1IwRkJUaXhIUVVGWkxFZEJRVUVzUjBGQlRTeEhRVUZzUWl4SFFVRjNRaXhIUVVGQkxFZEJRVTBzUjBGQmVFTXNSVUZFVWp0TFFVRkJMRTFCUVVFN1RVRkhSU3hIUVVGQkxFZEJRVTBzUlVGSVVqczdTVUZMUVN4SFFVRkJMRWRCUVUwc1EwRkJRU3hIUVVGSkxFdEJRVUVzUjBGQlVUdEpRVU5zUWl4SFFVRkJMRWRCUVUwc1EwRkJRU3hIUVVGSkxFdEJRVUVzUjBGQlVUdEpRVVZzUWl4SFFVRkJMRWxCUVU4N1NVRkRVQ3hIUVVGQkxFbEJRVThzVVVGQlFTeEhRVUZYTzBsQlEyeENMRWRCUVVFc1NVRkJUeXhSUVVGQkxFZEJRVmM3VjBGRmJFSXNTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hIUVVGQkxFZEJRVTBzUjBGQlRpeEhRVUZaTEVkQlFVRXNSMEZCVFN4SFFVRnNRaXhIUVVGM1FpeEhRVUZCTEVkQlFVMHNSMEZCZUVNN1JVRXZRbEVzUTBFdlNGWTdSVUZuUzBFc1QwRkJRU3hGUVVGVExGTkJRVU1zU1VGQlJDeEZRVUZQTEVsQlFWQTdRVUZEVUN4UlFVRkJPMGxCUVVFc1NVRkJRU3hIUVVGUExFbEJRVU1zUTBGQlFTeFhRVUZYTEVOQlFVTXNTMEZCWWl4RFFVRnRRaXhKUVVGdVFpeEZRVUZ6UWl4SlFVRjBRanRKUVVOUUxFbEJRVUVzUjBGQlR5eEpRVUZETEVOQlFVRXNWMEZCVnl4RFFVRkRMRXRCUVdJc1EwRkJiVUlzU1VGQmJrSXNSVUZCYzBJc1NVRkJkRUk3VjBGRFVDeEpRVUZETEVOQlFVRXNVVUZCUkN4RFFVRlZMRWxCUVZZc1JVRkJaMElzU1VGQmFFSTdSVUZJVHl4RFFXaExWRHRGUVhGTFFTeFBRVUZCTEVWQlFWTXNVMEZCUXl4SlFVRkVMRVZCUVU4c1NVRkJVRHRCUVVWUUxGRkJRVUU3U1VGQlFTeEpRVUZCTEVkQlFVOHNTVUZCUXl4RFFVRkJMRkZCUVVRc1EwRkJWU3hKUVVGV08wbEJRMUFzU1VGQlFTeEhRVUZQTEVsQlFVTXNRMEZCUVN4UlFVRkVMRU5CUVZVc1NVRkJWanRYUVVkUUxFbEJRVU1zUTBGQlFTeFBRVUZFTEVOQlFWTXNTVUZCVkN4RlFVRmxMRWxCUVdZN1JVRk9UeXhEUVhKTFZEdEZRVFpMUVN4dlFrRkJRU3hGUVVGelFpeFJRVGRMZEVJN1JVRXJTMEVzYTBKQlFVRXNSVUZCYjBJc1UwRkJReXhEUVVGRU8wbEJRMnhDTEVsQlFVY3NRMEZCUVN4SFFVRkpMRkZCUVZFc1EwRkJReXhGUVVGb1FqdEJRVU5GTEdGQlFVOHNUVUZFVkRzN1NVRkhRU3hKUVVGSExFTkJRVUVzU1VGQlN5eFJRVUZSTEVOQlFVTXNUMEZCYWtJN1FVRkRSU3hoUVVGUExGVkJSRlE3TzBsQlIwRXNTVUZCUnl4RFFVRkJMRWxCUVVzc1VVRkJVU3hEUVVGRExFdEJRV3BDTzBGQlEwVXNZVUZCVHl4UlFVUlVPenRKUVVkQkxFbEJRVWNzUTBGQlFTeEpRVUZMTEZGQlFWRXNRMEZCUXl4SlFVRnFRanRCUVVORkxHRkJRVThzVDBGRVZEczdTVUZIUVN4SlFVRkhMRU5CUVVFc1IwRkJTU3hSUVVGUkxFTkJRVU1zVDBGQmFFSTdRVUZEUlN4aFFVRlBMRlZCUkZRN08wRkJSVUVzVjBGQlR6dEZRV1pYTEVOQkwwdHdRanRGUVdkTlFTeFBRVUZCTEVWQlFWTXNUMEZvVFZRN1JVRnBUVUVzVFVGQlFTeEZRVUZSTEUxQmFrMVNPMFZCYTAxQkxHRkJRVUVzUlVGQlpTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVRHRYUVVOaUxFTkJRVU1zUTBGQlFTeEpRVUZITEVOQlFVTXNRMEZCUVN4SFFVRkZMRTlCUVVnc1EwRkJTaXhEUVVGQkxFZEJRVzFDTEVOQlFVTXNRMEZCUVN4SlFVRkxMRTlCUVU0c1EwRkJia0lzUjBGQmIwTTdSVUZFZGtJc1EwRnNUV1lpZlE9PVxuIiwiXG4vKlxuICBGcm9tIFZpYnJhbnQuanMgYnkgSmFyaSBad2FydHNcbiAgUG9ydGVkIHRvIG5vZGUuanMgYnkgQUtGaXNoXG5cbiAgQ29sb3IgYWxnb3JpdGhtIGNsYXNzIHRoYXQgZmluZHMgdmFyaWF0aW9ucyBvbiBjb2xvcnMgaW4gYW4gaW1hZ2UuXG5cbiAgQ3JlZGl0c1xuICAtLS0tLS0tLVxuICBMb2tlc2ggRGhha2FyIChodHRwOi8vd3d3Lmxva2VzaGRoYWthci5jb20pIC0gQ3JlYXRlZCBDb2xvclRoaWVmXG4gIEdvb2dsZSAtIFBhbGV0dGUgc3VwcG9ydCBsaWJyYXJ5IGluIEFuZHJvaWRcbiAqL1xudmFyIEJ1aWxkZXIsIERlZmF1bHRHZW5lcmF0b3IsIEZpbHRlciwgU3dhdGNoLCBWaWJyYW50LCB1dGlsLFxuICBiaW5kID0gZnVuY3Rpb24oZm4sIG1lKXsgcmV0dXJuIGZ1bmN0aW9uKCl7IHJldHVybiBmbi5hcHBseShtZSwgYXJndW1lbnRzKTsgfTsgfTtcblxuU3dhdGNoID0gcmVxdWlyZSgnLi9zd2F0Y2gnKTtcblxudXRpbCA9IHJlcXVpcmUoJy4vdXRpbCcpO1xuXG5EZWZhdWx0R2VuZXJhdG9yID0gcmVxdWlyZSgnLi9nZW5lcmF0b3InKS5EZWZhdWx0O1xuXG5GaWx0ZXIgPSByZXF1aXJlKCcuL2ZpbHRlcicpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFZpYnJhbnQgPSAoZnVuY3Rpb24oKSB7XG4gIFZpYnJhbnQuRGVmYXVsdE9wdHMgPSB7XG4gICAgY29sb3JDb3VudDogMTYsXG4gICAgcXVhbGl0eTogNSxcbiAgICBnZW5lcmF0b3I6IG5ldyBEZWZhdWx0R2VuZXJhdG9yKCksXG4gICAgSW1hZ2U6IG51bGwsXG4gICAgUXVhbnRpemVyOiByZXF1aXJlKCcuL3F1YW50aXplcicpLk1NQ1EsXG4gICAgZmlsdGVyczogW10sXG4gICAgbWluUG9wdWxhdGlvbjogMzUsXG4gICAgbWluUmdiRGlmZjogMTVcbiAgfTtcblxuICBWaWJyYW50LmZyb20gPSBmdW5jdGlvbihzcmMpIHtcbiAgICByZXR1cm4gbmV3IEJ1aWxkZXIoc3JjKTtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5xdWFudGl6ZSA9IHJlcXVpcmUoJ3F1YW50aXplJyk7XG5cbiAgVmlicmFudC5wcm90b3R5cGUuX3N3YXRjaGVzID0gW107XG5cbiAgZnVuY3Rpb24gVmlicmFudChzb3VyY2VJbWFnZSwgb3B0cykge1xuICAgIHRoaXMuc291cmNlSW1hZ2UgPSBzb3VyY2VJbWFnZTtcbiAgICBpZiAob3B0cyA9PSBudWxsKSB7XG4gICAgICBvcHRzID0ge307XG4gICAgfVxuICAgIHRoaXMuc3dhdGNoZXMgPSBiaW5kKHRoaXMuc3dhdGNoZXMsIHRoaXMpO1xuICAgIHRoaXMub3B0cyA9IHV0aWwuZGVmYXVsdHMob3B0cywgdGhpcy5jb25zdHJ1Y3Rvci5EZWZhdWx0T3B0cyk7XG4gICAgdGhpcy5nZW5lcmF0b3IgPSB0aGlzLm9wdHMuZ2VuZXJhdG9yO1xuICB9XG5cbiAgVmlicmFudC5wcm90b3R5cGUuZ2V0UGFsZXR0ZSA9IGZ1bmN0aW9uKGNiKSB7XG4gICAgdmFyIGltYWdlO1xuICAgIHJldHVybiBpbWFnZSA9IG5ldyB0aGlzLm9wdHMuSW1hZ2UodGhpcy5zb3VyY2VJbWFnZSwgKGZ1bmN0aW9uKF90aGlzKSB7XG4gICAgICByZXR1cm4gZnVuY3Rpb24oZXJyLCBpbWFnZSkge1xuICAgICAgICB2YXIgZXJyb3I7XG4gICAgICAgIGlmIChlcnIgIT0gbnVsbCkge1xuICAgICAgICAgIHJldHVybiBjYihlcnIpO1xuICAgICAgICB9XG4gICAgICAgIHRyeSB7XG4gICAgICAgICAgX3RoaXMuX3Byb2Nlc3MoaW1hZ2UsIF90aGlzLm9wdHMpO1xuICAgICAgICAgIHJldHVybiBjYihudWxsLCBfdGhpcy5zd2F0Y2hlcygpKTtcbiAgICAgICAgfSBjYXRjaCAoZXJyb3IxKSB7XG4gICAgICAgICAgZXJyb3IgPSBlcnJvcjE7XG4gICAgICAgICAgcmV0dXJuIGNiKGVycm9yKTtcbiAgICAgICAgfVxuICAgICAgfTtcbiAgICB9KSh0aGlzKSk7XG4gIH07XG5cbiAgVmlicmFudC5wcm90b3R5cGUuZ2V0U3dhdGNoZXMgPSBmdW5jdGlvbihjYikge1xuICAgIHJldHVybiB0aGlzLmdldFBhbGV0dGUoY2IpO1xuICB9O1xuXG4gIFZpYnJhbnQucHJvdG90eXBlLl9wcm9jZXNzID0gZnVuY3Rpb24oaW1hZ2UsIG9wdHMpIHtcbiAgICB2YXIgaW1hZ2VEYXRhLCBxdWFudGl6ZXI7XG4gICAgaW1hZ2Uuc2NhbGVEb3duKHRoaXMub3B0cyk7XG4gICAgaW1hZ2VEYXRhID0gaW1hZ2UuZ2V0SW1hZ2VEYXRhKCk7XG4gICAgcXVhbnRpemVyID0gbmV3IHRoaXMub3B0cy5RdWFudGl6ZXIoKTtcbiAgICBxdWFudGl6ZXIuaW5pdGlhbGl6ZShpbWFnZURhdGEuZGF0YSwgdGhpcy5vcHRzKTtcbiAgICB0aGlzLmFsbFN3YXRjaGVzID0gcXVhbnRpemVyLmdldFF1YW50aXplZENvbG9ycygpO1xuICAgIHJldHVybiBpbWFnZS5yZW1vdmVDYW52YXMoKTtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5zd2F0Y2hlcyA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBjb21wYXJpbmdQb3B1bGF0aW9uLCBmaW5hbFN3YXRjaGVzLCBmaW5hbF9zd2F0Y2gsIGosIGssIGxlbiwgbGVuMSwgcmVmLCBzaG91bGRfYmVfYWRkZWQsIHN3YXRjaDtcbiAgICBmaW5hbFN3YXRjaGVzID0gW107XG4gICAgdGhpcy5hbGxTd2F0Y2hlcyA9IHRoaXMuYWxsU3dhdGNoZXMuc29ydChmdW5jdGlvbihhLCBiKSB7XG4gICAgICByZXR1cm4gYi5nZXRQb3B1bGF0aW9uKCkgLSBhLmdldFBvcHVsYXRpb24oKTtcbiAgICB9KTtcbiAgICBjb21wYXJpbmdQb3B1bGF0aW9uID0gdGhpcy5nZXRDb21wYXJpbmdQb3B1bGF0aW9uKHRoaXMuYWxsU3dhdGNoZXMpO1xuICAgIHJlZiA9IHRoaXMuYWxsU3dhdGNoZXM7XG4gICAgZm9yIChqID0gMCwgbGVuID0gcmVmLmxlbmd0aDsgaiA8IGxlbjsgaisrKSB7XG4gICAgICBzd2F0Y2ggPSByZWZbal07XG4gICAgICBpZiAodGhpcy5wb3B1bGF0aW9uUGVyY2VudGFnZShzd2F0Y2guZ2V0UG9wdWxhdGlvbigpLCBjb21wYXJpbmdQb3B1bGF0aW9uKSA+IHRoaXMub3B0cy5taW5Qb3B1bGF0aW9uKSB7XG4gICAgICAgIHNob3VsZF9iZV9hZGRlZCA9IHRydWU7XG4gICAgICAgIGZvciAoayA9IDAsIGxlbjEgPSBmaW5hbFN3YXRjaGVzLmxlbmd0aDsgayA8IGxlbjE7IGsrKykge1xuICAgICAgICAgIGZpbmFsX3N3YXRjaCA9IGZpbmFsU3dhdGNoZXNba107XG4gICAgICAgICAgaWYgKFZpYnJhbnQuVXRpbC5yZ2JEaWZmKGZpbmFsX3N3YXRjaC5yZ2IsIHN3YXRjaC5yZ2IpIDwgdGhpcy5vcHRzLm1pblJnYkRpZmYpIHtcbiAgICAgICAgICAgIHNob3VsZF9iZV9hZGRlZCA9IGZhbHNlO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICAgIGlmIChzaG91bGRfYmVfYWRkZWQpIHtcbiAgICAgICAgICBmaW5hbFN3YXRjaGVzLnB1c2goc3dhdGNoKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gZmluYWxTd2F0Y2hlcztcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5wb3B1bGF0aW9uUGVyY2VudGFnZSA9IGZ1bmN0aW9uKHBvcHVsYXRpb24sIGNvbXBhcmluZ1BvcHVsYXRpb24pIHtcbiAgICByZXR1cm4gKHBvcHVsYXRpb24gLyBjb21wYXJpbmdQb3B1bGF0aW9uKSAqIDEwMDtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5nZXRDb21wYXJpbmdQb3B1bGF0aW9uID0gZnVuY3Rpb24oc3dhdGNoZXMpIHtcbiAgICByZXR1cm4gc3dhdGNoZXNbMV0uZ2V0UG9wdWxhdGlvbigpO1xuICB9O1xuXG4gIHJldHVybiBWaWJyYW50O1xuXG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cy5CdWlsZGVyID0gQnVpbGRlciA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gQnVpbGRlcihzcmMxLCBvcHRzMSkge1xuICAgIHRoaXMuc3JjID0gc3JjMTtcbiAgICB0aGlzLm9wdHMgPSBvcHRzMSAhPSBudWxsID8gb3B0czEgOiB7fTtcbiAgICB0aGlzLm9wdHMuZmlsdGVycyA9IHV0aWwuY2xvbmUoVmlicmFudC5EZWZhdWx0T3B0cy5maWx0ZXJzKTtcbiAgfVxuXG4gIEJ1aWxkZXIucHJvdG90eXBlLm1heENvbG9yQ291bnQgPSBmdW5jdGlvbihuKSB7XG4gICAgdGhpcy5vcHRzLmNvbG9yQ291bnQgPSBuO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLm1heERpbWVuc2lvbiA9IGZ1bmN0aW9uKGQpIHtcbiAgICB0aGlzLm9wdHMubWF4RGltZW5zaW9uID0gZDtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5hZGRGaWx0ZXIgPSBmdW5jdGlvbihmKSB7XG4gICAgaWYgKHR5cGVvZiBmID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICB0aGlzLm9wdHMuZmlsdGVycy5wdXNoKGYpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5yZW1vdmVGaWx0ZXIgPSBmdW5jdGlvbihmKSB7XG4gICAgdmFyIGk7XG4gICAgaWYgKChpID0gdGhpcy5vcHRzLmZpbHRlcnMuaW5kZXhPZihmKSkgPiAwKSB7XG4gICAgICB0aGlzLm9wdHMuZmlsdGVycy5zcGxpY2UoaSk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmNsZWFyRmlsdGVycyA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMub3B0cy5maWx0ZXJzID0gW107XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUucXVhbGl0eSA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMucXVhbGl0eSA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUubWluUG9wdWxhdGlvbiA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMubWluUG9wdWxhdGlvbiA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUubWluUmdiRGlmZiA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMubWluUmdiRGlmZiA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUudXNlSW1hZ2UgPSBmdW5jdGlvbihpbWFnZSkge1xuICAgIHRoaXMub3B0cy5JbWFnZSA9IGltYWdlO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLnVzZVF1YW50aXplciA9IGZ1bmN0aW9uKHF1YW50aXplcikge1xuICAgIHRoaXMub3B0cy5RdWFudGl6ZXIgPSBxdWFudGl6ZXI7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuYnVpbGQgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAodGhpcy52ID09IG51bGwpIHtcbiAgICAgIHRoaXMudiA9IG5ldyBWaWJyYW50KHRoaXMuc3JjLCB0aGlzLm9wdHMpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy52O1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmdldFN3YXRjaGVzID0gZnVuY3Rpb24oY2IpIHtcbiAgICByZXR1cm4gdGhpcy5idWlsZCgpLmdldFBhbGV0dGUoY2IpO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmdldFBhbGV0dGUgPSBmdW5jdGlvbihjYikge1xuICAgIHJldHVybiB0aGlzLmJ1aWxkKCkuZ2V0UGFsZXR0ZShjYik7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuZnJvbSA9IGZ1bmN0aW9uKHNyYykge1xuICAgIHJldHVybiBuZXcgVmlicmFudChzcmMsIHRoaXMub3B0cyk7XG4gIH07XG5cbiAgcmV0dXJuIEJ1aWxkZXI7XG5cbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzLlV0aWwgPSB1dGlsO1xuXG5tb2R1bGUuZXhwb3J0cy5Td2F0Y2ggPSBTd2F0Y2g7XG5cbm1vZHVsZS5leHBvcnRzLlF1YW50aXplciA9IHJlcXVpcmUoJy4vcXVhbnRpemVyLycpO1xuXG5tb2R1bGUuZXhwb3J0cy5HZW5lcmF0b3IgPSByZXF1aXJlKCcuL2dlbmVyYXRvci8nKTtcblxubW9kdWxlLmV4cG9ydHMuRmlsdGVyID0gcmVxdWlyZSgnLi9maWx0ZXIvJyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZkbWxpY21GdWRDNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTkyYVdKeVlXNTBMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaU8wRkJRVUU3T3pzN096czdPenM3TzBGQlFVRXNTVUZCUVN4M1JFRkJRVHRGUVVGQk96dEJRVmRCTEUxQlFVRXNSMEZCVXl4UFFVRkJMRU5CUVZFc1ZVRkJVanM3UVVGRFZDeEpRVUZCTEVkQlFVOHNUMEZCUVN4RFFVRlJMRkZCUVZJN08wRkJRMUFzWjBKQlFVRXNSMEZCYlVJc1QwRkJRU3hEUVVGUkxHRkJRVklzUTBGQmMwSXNRMEZCUXpzN1FVRkRNVU1zVFVGQlFTeEhRVUZUTEU5QlFVRXNRMEZCVVN4VlFVRlNPenRCUVVWVUxFMUJRVTBzUTBGQlF5eFBRVUZRTEVkQlEwMDdSVUZEU2l4UFFVRkRMRU5CUVVFc1YwRkJSQ3hIUVVORk8wbEJRVUVzVlVGQlFTeEZRVUZaTEVWQlFWbzdTVUZEUVN4UFFVRkJMRVZCUVZNc1EwRkVWRHRKUVVWQkxGTkJRVUVzUlVGQlZ5eEpRVUZKTEdkQ1FVRktMRU5CUVVFc1EwRkdXRHRKUVVkQkxFdEJRVUVzUlVGQlR5eEpRVWhRTzBsQlNVRXNVMEZCUVN4RlFVRlhMRTlCUVVFc1EwRkJVU3hoUVVGU0xFTkJRWE5DTEVOQlFVTXNTVUZLYkVNN1NVRkxRU3hQUVVGQkxFVkJRVk1zUlVGTVZEdEpRVTFCTEdGQlFVRXNSVUZCWlN4RlFVNW1PMGxCVDBFc1ZVRkJRU3hGUVVGWkxFVkJVRm83T3p0RlFWTkdMRTlCUVVNc1EwRkJRU3hKUVVGRUxFZEJRVThzVTBGQlF5eEhRVUZFTzFkQlEwd3NTVUZCU1N4UFFVRktMRU5CUVZrc1IwRkJXanRGUVVSTE96dHZRa0ZIVUN4UlFVRkJMRWRCUVZVc1QwRkJRU3hEUVVGUkxGVkJRVkk3TzI5Q1FVVldMRk5CUVVFc1IwRkJWenM3UlVGRlJTeHBRa0ZCUXl4WFFVRkVMRVZCUVdVc1NVRkJaanRKUVVGRExFbEJRVU1zUTBGQlFTeGpRVUZFT3p0TlFVRmpMRTlCUVU4N096dEpRVU5xUXl4SlFVRkRMRU5CUVVFc1NVRkJSQ3hIUVVGUkxFbEJRVWtzUTBGQlF5eFJRVUZNTEVOQlFXTXNTVUZCWkN4RlFVRnZRaXhKUVVGRExFTkJRVUVzVjBGQlZ5eERRVUZETEZkQlFXcERPMGxCUTFJc1NVRkJReXhEUVVGQkxGTkJRVVFzUjBGQllTeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRPMFZCUmxJN08yOUNRVWxpTEZWQlFVRXNSMEZCV1N4VFFVRkRMRVZCUVVRN1FVRkRWaXhSUVVGQk8xZEJRVUVzUzBGQlFTeEhRVUZSTEVsQlFVa3NTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhMUVVGV0xFTkJRV2RDTEVsQlFVTXNRMEZCUVN4WFFVRnFRaXhGUVVFNFFpeERRVUZCTEZOQlFVRXNTMEZCUVR0aFFVRkJMRk5CUVVNc1IwRkJSQ3hGUVVGTkxFdEJRVTQ3UVVGRGNFTXNXVUZCUVR0UlFVRkJMRWxCUVVjc1YwRkJTRHRCUVVGaExHbENRVUZQTEVWQlFVRXNRMEZCUnl4SFFVRklMRVZCUVhCQ096dEJRVU5CTzFWQlEwVXNTMEZCUXl4RFFVRkJMRkZCUVVRc1EwRkJWU3hMUVVGV0xFVkJRV2xDTEV0QlFVTXNRMEZCUVN4SlFVRnNRanRwUWtGRFFTeEZRVUZCTEVOQlFVY3NTVUZCU0N4RlFVRlRMRXRCUVVNc1EwRkJRU3hSUVVGRUxFTkJRVUVzUTBGQlZDeEZRVVpHTzFOQlFVRXNZMEZCUVR0VlFVZE5PMEZCUTBvc2FVSkJRVThzUlVGQlFTeERRVUZITEV0QlFVZ3NSVUZLVkRzN1RVRkdiME03U1VGQlFTeERRVUZCTEVOQlFVRXNRMEZCUVN4SlFVRkJMRU5CUVRsQ08wVkJSRVU3TzI5Q1FWTmFMRmRCUVVFc1IwRkJZU3hUUVVGRExFVkJRVVE3VjBGRFdDeEpRVUZETEVOQlFVRXNWVUZCUkN4RFFVRlpMRVZCUVZvN1JVRkVWenM3YjBKQlIySXNVVUZCUVN4SFFVRlZMRk5CUVVNc1MwRkJSQ3hGUVVGUkxFbEJRVkk3UVVGRFVpeFJRVUZCTzBsQlFVRXNTMEZCU3l4RFFVRkRMRk5CUVU0c1EwRkJaMElzU1VGQlF5eERRVUZCTEVsQlFXcENPMGxCUTBFc1UwRkJRU3hIUVVGWkxFdEJRVXNzUTBGQlF5eFpRVUZPTEVOQlFVRTdTVUZGV2l4VFFVRkJMRWRCUVZrc1NVRkJTU3hKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEZOQlFWWXNRMEZCUVR0SlFVTmFMRk5CUVZNc1EwRkJReXhWUVVGV0xFTkJRWEZDTEZOQlFWTXNRMEZCUXl4SlFVRXZRaXhGUVVGeFF5eEpRVUZETEVOQlFVRXNTVUZCZEVNN1NVRkZRU3hKUVVGRExFTkJRVUVzVjBGQlJDeEhRVUZsTEZOQlFWTXNRMEZCUXl4clFrRkJWaXhEUVVGQk8xZEJSV1lzUzBGQlN5eERRVUZETEZsQlFVNHNRMEZCUVR0RlFWUlJPenR2UWtGWFZpeFJRVUZCTEVkQlFWVXNVMEZCUVR0QlFVTlNMRkZCUVVFN1NVRkJRU3hoUVVGQkxFZEJRV2RDTzBsQlJXaENMRWxCUVVNc1EwRkJRU3hYUVVGRUxFZEJRV1VzU1VGQlF5eERRVUZCTEZkQlFWY3NRMEZCUXl4SlFVRmlMRU5CUVd0Q0xGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVbzdZVUZETDBJc1EwRkJReXhEUVVGRExHRkJRVVlzUTBGQlFTeERRVUZCTEVkQlFXOUNMRU5CUVVNc1EwRkJReXhoUVVGR0xFTkJRVUU3U1VGRVZ5eERRVUZzUWp0SlFVZG1MRzFDUVVGQkxFZEJRWE5DTEVsQlFVTXNRMEZCUVN4elFrRkJSQ3hEUVVGM1FpeEpRVUZETEVOQlFVRXNWMEZCZWtJN1FVRkZkRUk3UVVGQlFTeFRRVUZCTEhGRFFVRkJPenROUVVORkxFbEJRVWNzU1VGQlF5eERRVUZCTEc5Q1FVRkVMRU5CUVhOQ0xFMUJRVTBzUTBGQlF5eGhRVUZRTEVOQlFVRXNRMEZCZEVJc1JVRkJPRU1zYlVKQlFUbERMRU5CUVVFc1IwRkJjVVVzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4aFFVRTVSVHRSUVVORkxHVkJRVUVzUjBGQmEwSTdRVUZGYkVJc1lVRkJRU3hwUkVGQlFUczdWVUZEUlN4SlFVRkhMRTlCUVU4c1EwRkJReXhKUVVGSkxFTkJRVU1zVDBGQllpeERRVUZ4UWl4WlFVRlpMRU5CUVVNc1IwRkJiRU1zUlVGQmRVTXNUVUZCVFN4RFFVRkRMRWRCUVRsRExFTkJRVUVzUjBGQmNVUXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhWUVVFNVJEdFpRVU5GTEdWQlFVRXNSMEZCYTBJN1FVRkRiRUlzYTBKQlJrWTdPMEZCUkVZN1VVRkxRU3hKUVVGSExHVkJRVWc3VlVGRFJTeGhRVUZoTEVOQlFVTXNTVUZCWkN4RFFVRnRRaXhOUVVGdVFpeEZRVVJHTzFOQlVrWTdPMEZCUkVZN1YwRlpRVHRGUVhCQ1VUczdiMEpCYzBKV0xHOUNRVUZCTEVkQlFYTkNMRk5CUVVNc1ZVRkJSQ3hGUVVGaExHMUNRVUZpTzFkQlEzQkNMRU5CUVVNc1ZVRkJRU3hIUVVGaExHMUNRVUZrTEVOQlFVRXNSMEZCY1VNN1JVRkVha0k3TzI5Q1FVZDBRaXh6UWtGQlFTeEhRVUYzUWl4VFFVRkRMRkZCUVVRN1YwRkRkRUlzVVVGQlV5eERRVUZCTEVOQlFVRXNRMEZCUlN4RFFVRkRMR0ZCUVZvc1EwRkJRVHRGUVVSelFqczdPenM3TzBGQlJ6RkNMRTFCUVUwc1EwRkJReXhQUVVGUExFTkJRVU1zVDBGQlppeEhRVU5OTzBWQlExTXNhVUpCUVVNc1NVRkJSQ3hGUVVGUExFdEJRVkE3U1VGQlF5eEpRVUZETEVOQlFVRXNUVUZCUkR0SlFVRk5MRWxCUVVNc1EwRkJRU3gxUWtGQlJDeFJRVUZSTzBsQlF6RkNMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zVDBGQlRpeEhRVUZuUWl4SlFVRkpMRU5CUVVNc1MwRkJUQ3hEUVVGWExFOUJRVThzUTBGQlF5eFhRVUZYTEVOQlFVTXNUMEZCTDBJN1JVRkVURHM3YjBKQlIySXNZVUZCUVN4SFFVRmxMRk5CUVVNc1EwRkJSRHRKUVVOaUxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNWVUZCVGl4SFFVRnRRanRYUVVOdVFqdEZRVVpoT3p0dlFrRkpaaXhaUVVGQkxFZEJRV01zVTBGQlF5eERRVUZFTzBsQlExb3NTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhaUVVGT0xFZEJRWEZDTzFkQlEzSkNPMFZCUmxrN08yOUNRVWxrTEZOQlFVRXNSMEZCVnl4VFFVRkRMRU5CUVVRN1NVRkRWQ3hKUVVGSExFOUJRVThzUTBGQlVDeExRVUZaTEZWQlFXWTdUVUZEUlN4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExFOUJRVThzUTBGQlF5eEpRVUZrTEVOQlFXMUNMRU5CUVc1Q0xFVkJSRVk3TzFkQlJVRTdSVUZJVXpzN2IwSkJTMWdzV1VGQlFTeEhRVUZqTEZOQlFVTXNRMEZCUkR0QlFVTmFMRkZCUVVFN1NVRkJRU3hKUVVGSExFTkJRVU1zUTBGQlFTeEhRVUZKTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1QwRkJUeXhEUVVGRExFOUJRV1FzUTBGQmMwSXNRMEZCZEVJc1EwRkJUQ3hEUVVGQkxFZEJRV2xETEVOQlFYQkRPMDFCUTBVc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eFBRVUZQTEVOQlFVTXNUVUZCWkN4RFFVRnhRaXhEUVVGeVFpeEZRVVJHT3p0WFFVVkJPMFZCU0ZrN08yOUNRVXRrTEZsQlFVRXNSMEZCWXl4VFFVRkJPMGxCUTFvc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eFBRVUZPTEVkQlFXZENPMWRCUTJoQ08wVkJSbGs3TzI5Q1FVbGtMRTlCUVVFc1IwRkJVeXhUUVVGRExFTkJRVVE3U1VGRFVDeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRTlCUVU0c1IwRkJaMEk3VjBGRGFFSTdSVUZHVHpzN2IwSkJTVlFzWVVGQlFTeEhRVUZsTEZOQlFVTXNRMEZCUkR0SlFVTmlMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zWVVGQlRpeEhRVUZ6UWp0WFFVTjBRanRGUVVaaE96dHZRa0ZKWml4VlFVRkJMRWRCUVZrc1UwRkJReXhEUVVGRU8wbEJRMVlzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4VlFVRk9MRWRCUVcxQ08xZEJRMjVDTzBWQlJsVTdPMjlDUVVsYUxGRkJRVUVzUjBGQlZTeFRRVUZETEV0QlFVUTdTVUZEVWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExFdEJRVTRzUjBGQll6dFhRVU5rTzBWQlJsRTdPMjlDUVVsV0xGbEJRVUVzUjBGQll5eFRRVUZETEZOQlFVUTdTVUZEV2l4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGTkJRVTRzUjBGQmEwSTdWMEZEYkVJN1JVRkdXVHM3YjBKQlNXUXNTMEZCUVN4SFFVRlBMRk5CUVVFN1NVRkRUQ3hKUVVGUExHTkJRVkE3VFVGRFJTeEpRVUZETEVOQlFVRXNRMEZCUkN4SFFVRkxMRWxCUVVrc1QwRkJTaXhEUVVGWkxFbEJRVU1zUTBGQlFTeEhRVUZpTEVWQlFXdENMRWxCUVVNc1EwRkJRU3hKUVVGdVFpeEZRVVJRT3p0WFFVVkJMRWxCUVVNc1EwRkJRVHRGUVVoSk96dHZRa0ZMVUN4WFFVRkJMRWRCUVdFc1UwRkJReXhGUVVGRU8xZEJRMWdzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RFFVRlJMRU5CUVVNc1ZVRkJWQ3hEUVVGdlFpeEZRVUZ3UWp0RlFVUlhPenR2UWtGSFlpeFZRVUZCTEVkQlFWa3NVMEZCUXl4RlFVRkVPMWRCUTFZc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeERRVUZSTEVOQlFVTXNWVUZCVkN4RFFVRnZRaXhGUVVGd1FqdEZRVVJWT3p0dlFrRkhXaXhKUVVGQkxFZEJRVTBzVTBGQlF5eEhRVUZFTzFkQlEwb3NTVUZCU1N4UFFVRktMRU5CUVZrc1IwRkJXaXhGUVVGcFFpeEpRVUZETEVOQlFVRXNTVUZCYkVJN1JVRkVTVHM3T3pzN08wRkJSMUlzVFVGQlRTeERRVUZETEU5QlFVOHNRMEZCUXl4SlFVRm1MRWRCUVhOQ096dEJRVU4wUWl4TlFVRk5MRU5CUVVNc1QwRkJUeXhEUVVGRExFMUJRV1lzUjBGQmQwSTdPMEZCUTNoQ0xFMUJRVTBzUTBGQlF5eFBRVUZQTEVOQlFVTXNVMEZCWml4SFFVRXlRaXhQUVVGQkxFTkJRVkVzWTBGQlVqczdRVUZETTBJc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eFRRVUZtTEVkQlFUSkNMRTlCUVVFc1EwRkJVU3hqUVVGU096dEJRVU16UWl4TlFVRk5MRU5CUVVNc1QwRkJUeXhEUVVGRExFMUJRV1lzUjBGQmQwSXNUMEZCUVN4RFFVRlJMRmRCUVZJaWZRPT1cbiJdfQ==
