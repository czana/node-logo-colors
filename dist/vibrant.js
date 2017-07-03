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
    minRgbDiff: 15,
    comparingPopulationIndex: 1
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
    comparingPopulation = this.getComparingPopulation(this.allSwatches, this.opts.comparingPopulationIndex);
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
    if (comparingPopulation === 0) {
      console.log('comparing population equals 0!');
      return 0;
    }
    return (population / comparingPopulation) * 100;
  };

  Vibrant.prototype.getComparingPopulation = function(swatches, index) {
    if (swatches.length > index) {
      return swatches[index].getPopulation();
    } else {
      return 100;
    }
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

  Builder.prototype.comparingPopulationIndex = function(q) {
    this.opts.comparingPopulationIndex = q;
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
//# sourceMappingURL=data:application/json;charset:utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJub2RlX21vZHVsZXMvYnJvd3NlcmlmeS9ub2RlX21vZHVsZXMvdXJsL3VybC5qcyIsIm5vZGVfbW9kdWxlcy9wdW55Y29kZS9wdW55Y29kZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWFudGl6ZS9xdWFudGl6ZS5qcyIsIm5vZGVfbW9kdWxlcy9xdWVyeXN0cmluZy1lczMvZGVjb2RlLmpzIiwibm9kZV9tb2R1bGVzL3F1ZXJ5c3RyaW5nLWVzMy9lbmNvZGUuanMiLCJub2RlX21vZHVsZXMvcXVlcnlzdHJpbmctZXMzL2luZGV4LmpzIiwic3JjL2Jyb3dzZXIuY29mZmVlIiwic3JjL2J1bmRsZS5jb2ZmZWUiLCJzcmMvZmlsdGVyL2RlZmF1bHQuY29mZmVlIiwic3JjL2ZpbHRlci9pbmRleC5jb2ZmZWUiLCJzcmMvZ2VuZXJhdG9yL2RlZmF1bHQuY29mZmVlIiwic3JjL2dlbmVyYXRvci9pbmRleC5jb2ZmZWUiLCJzcmMvaW1hZ2UvYnJvd3Nlci5jb2ZmZWUiLCJzcmMvaW1hZ2UvaW5kZXguY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL21tY3EuY29mZmVlIiwic3JjL3F1YW50aXplci9pbXBsL3BxdWV1ZS5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2ltcGwvdmJveC5jb2ZmZWUiLCJzcmMvcXVhbnRpemVyL2luZGV4LmNvZmZlZSIsInNyYy9xdWFudGl6ZXIvbW1jcS5jb2ZmZWUiLCJzcmMvc3dhdGNoLmNvZmZlZSIsInNyYy91dGlsLmNvZmZlZSIsInNyYy92aWJyYW50LmNvZmZlZSJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDbnNCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7Ozs7QUNyaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDMWVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3BGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDbktBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzFCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDdkdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQzVDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUMvRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3BEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQ3pQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDaEJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDakNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDM0VBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FDcE9BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbiBlKHQsbixyKXtmdW5jdGlvbiBzKG8sdSl7aWYoIW5bb10pe2lmKCF0W29dKXt2YXIgYT10eXBlb2YgcmVxdWlyZT09XCJmdW5jdGlvblwiJiZyZXF1aXJlO2lmKCF1JiZhKXJldHVybiBhKG8sITApO2lmKGkpcmV0dXJuIGkobywhMCk7dmFyIGY9bmV3IEVycm9yKFwiQ2Fubm90IGZpbmQgbW9kdWxlICdcIitvK1wiJ1wiKTt0aHJvdyBmLmNvZGU9XCJNT0RVTEVfTk9UX0ZPVU5EXCIsZn12YXIgbD1uW29dPXtleHBvcnRzOnt9fTt0W29dWzBdLmNhbGwobC5leHBvcnRzLGZ1bmN0aW9uKGUpe3ZhciBuPXRbb11bMV1bZV07cmV0dXJuIHMobj9uOmUpfSxsLGwuZXhwb3J0cyxlLHQsbixyKX1yZXR1cm4gbltvXS5leHBvcnRzfXZhciBpPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7Zm9yKHZhciBvPTA7bzxyLmxlbmd0aDtvKyspcyhyW29dKTtyZXR1cm4gc30pIiwiLy8gQ29weXJpZ2h0IEpveWVudCwgSW5jLiBhbmQgb3RoZXIgTm9kZSBjb250cmlidXRvcnMuXG4vL1xuLy8gUGVybWlzc2lvbiBpcyBoZXJlYnkgZ3JhbnRlZCwgZnJlZSBvZiBjaGFyZ2UsIHRvIGFueSBwZXJzb24gb2J0YWluaW5nIGFcbi8vIGNvcHkgb2YgdGhpcyBzb2Z0d2FyZSBhbmQgYXNzb2NpYXRlZCBkb2N1bWVudGF0aW9uIGZpbGVzICh0aGVcbi8vIFwiU29mdHdhcmVcIiksIHRvIGRlYWwgaW4gdGhlIFNvZnR3YXJlIHdpdGhvdXQgcmVzdHJpY3Rpb24sIGluY2x1ZGluZ1xuLy8gd2l0aG91dCBsaW1pdGF0aW9uIHRoZSByaWdodHMgdG8gdXNlLCBjb3B5LCBtb2RpZnksIG1lcmdlLCBwdWJsaXNoLFxuLy8gZGlzdHJpYnV0ZSwgc3VibGljZW5zZSwgYW5kL29yIHNlbGwgY29waWVzIG9mIHRoZSBTb2Z0d2FyZSwgYW5kIHRvIHBlcm1pdFxuLy8gcGVyc29ucyB0byB3aG9tIHRoZSBTb2Z0d2FyZSBpcyBmdXJuaXNoZWQgdG8gZG8gc28sIHN1YmplY3QgdG8gdGhlXG4vLyBmb2xsb3dpbmcgY29uZGl0aW9uczpcbi8vXG4vLyBUaGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSBhbmQgdGhpcyBwZXJtaXNzaW9uIG5vdGljZSBzaGFsbCBiZSBpbmNsdWRlZFxuLy8gaW4gYWxsIGNvcGllcyBvciBzdWJzdGFudGlhbCBwb3J0aW9ucyBvZiB0aGUgU29mdHdhcmUuXG4vL1xuLy8gVEhFIFNPRlRXQVJFIElTIFBST1ZJREVEIFwiQVMgSVNcIiwgV0lUSE9VVCBXQVJSQU5UWSBPRiBBTlkgS0lORCwgRVhQUkVTU1xuLy8gT1IgSU1QTElFRCwgSU5DTFVESU5HIEJVVCBOT1QgTElNSVRFRCBUTyBUSEUgV0FSUkFOVElFUyBPRlxuLy8gTUVSQ0hBTlRBQklMSVRZLCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBTkQgTk9OSU5GUklOR0VNRU5ULiBJTlxuLy8gTk8gRVZFTlQgU0hBTEwgVEhFIEFVVEhPUlMgT1IgQ09QWVJJR0hUIEhPTERFUlMgQkUgTElBQkxFIEZPUiBBTlkgQ0xBSU0sXG4vLyBEQU1BR0VTIE9SIE9USEVSIExJQUJJTElUWSwgV0hFVEhFUiBJTiBBTiBBQ1RJT04gT0YgQ09OVFJBQ1QsIFRPUlQgT1Jcbi8vIE9USEVSV0lTRSwgQVJJU0lORyBGUk9NLCBPVVQgT0YgT1IgSU4gQ09OTkVDVElPTiBXSVRIIFRIRSBTT0ZUV0FSRSBPUiBUSEVcbi8vIFVTRSBPUiBPVEhFUiBERUFMSU5HUyBJTiBUSEUgU09GVFdBUkUuXG5cbnZhciBwdW55Y29kZSA9IHJlcXVpcmUoJ3B1bnljb2RlJyk7XG5cbmV4cG9ydHMucGFyc2UgPSB1cmxQYXJzZTtcbmV4cG9ydHMucmVzb2x2ZSA9IHVybFJlc29sdmU7XG5leHBvcnRzLnJlc29sdmVPYmplY3QgPSB1cmxSZXNvbHZlT2JqZWN0O1xuZXhwb3J0cy5mb3JtYXQgPSB1cmxGb3JtYXQ7XG5cbmV4cG9ydHMuVXJsID0gVXJsO1xuXG5mdW5jdGlvbiBVcmwoKSB7XG4gIHRoaXMucHJvdG9jb2wgPSBudWxsO1xuICB0aGlzLnNsYXNoZXMgPSBudWxsO1xuICB0aGlzLmF1dGggPSBudWxsO1xuICB0aGlzLmhvc3QgPSBudWxsO1xuICB0aGlzLnBvcnQgPSBudWxsO1xuICB0aGlzLmhvc3RuYW1lID0gbnVsbDtcbiAgdGhpcy5oYXNoID0gbnVsbDtcbiAgdGhpcy5zZWFyY2ggPSBudWxsO1xuICB0aGlzLnF1ZXJ5ID0gbnVsbDtcbiAgdGhpcy5wYXRobmFtZSA9IG51bGw7XG4gIHRoaXMucGF0aCA9IG51bGw7XG4gIHRoaXMuaHJlZiA9IG51bGw7XG59XG5cbi8vIFJlZmVyZW5jZTogUkZDIDM5ODYsIFJGQyAxODA4LCBSRkMgMjM5NlxuXG4vLyBkZWZpbmUgdGhlc2UgaGVyZSBzbyBhdCBsZWFzdCB0aGV5IG9ubHkgaGF2ZSB0byBiZVxuLy8gY29tcGlsZWQgb25jZSBvbiB0aGUgZmlyc3QgbW9kdWxlIGxvYWQuXG52YXIgcHJvdG9jb2xQYXR0ZXJuID0gL14oW2EtejAtOS4rLV0rOikvaSxcbiAgICBwb3J0UGF0dGVybiA9IC86WzAtOV0qJC8sXG5cbiAgICAvLyBSRkMgMjM5NjogY2hhcmFjdGVycyByZXNlcnZlZCBmb3IgZGVsaW1pdGluZyBVUkxzLlxuICAgIC8vIFdlIGFjdHVhbGx5IGp1c3QgYXV0by1lc2NhcGUgdGhlc2UuXG4gICAgZGVsaW1zID0gWyc8JywgJz4nLCAnXCInLCAnYCcsICcgJywgJ1xccicsICdcXG4nLCAnXFx0J10sXG5cbiAgICAvLyBSRkMgMjM5NjogY2hhcmFjdGVycyBub3QgYWxsb3dlZCBmb3IgdmFyaW91cyByZWFzb25zLlxuICAgIHVud2lzZSA9IFsneycsICd9JywgJ3wnLCAnXFxcXCcsICdeJywgJ2AnXS5jb25jYXQoZGVsaW1zKSxcblxuICAgIC8vIEFsbG93ZWQgYnkgUkZDcywgYnV0IGNhdXNlIG9mIFhTUyBhdHRhY2tzLiAgQWx3YXlzIGVzY2FwZSB0aGVzZS5cbiAgICBhdXRvRXNjYXBlID0gWydcXCcnXS5jb25jYXQodW53aXNlKSxcbiAgICAvLyBDaGFyYWN0ZXJzIHRoYXQgYXJlIG5ldmVyIGV2ZXIgYWxsb3dlZCBpbiBhIGhvc3RuYW1lLlxuICAgIC8vIE5vdGUgdGhhdCBhbnkgaW52YWxpZCBjaGFycyBhcmUgYWxzbyBoYW5kbGVkLCBidXQgdGhlc2VcbiAgICAvLyBhcmUgdGhlIG9uZXMgdGhhdCBhcmUgKmV4cGVjdGVkKiB0byBiZSBzZWVuLCBzbyB3ZSBmYXN0LXBhdGhcbiAgICAvLyB0aGVtLlxuICAgIG5vbkhvc3RDaGFycyA9IFsnJScsICcvJywgJz8nLCAnOycsICcjJ10uY29uY2F0KGF1dG9Fc2NhcGUpLFxuICAgIGhvc3RFbmRpbmdDaGFycyA9IFsnLycsICc/JywgJyMnXSxcbiAgICBob3N0bmFtZU1heExlbiA9IDI1NSxcbiAgICBob3N0bmFtZVBhcnRQYXR0ZXJuID0gL15bYS16MC05QS1aXy1dezAsNjN9JC8sXG4gICAgaG9zdG5hbWVQYXJ0U3RhcnQgPSAvXihbYS16MC05QS1aXy1dezAsNjN9KSguKikkLyxcbiAgICAvLyBwcm90b2NvbHMgdGhhdCBjYW4gYWxsb3cgXCJ1bnNhZmVcIiBhbmQgXCJ1bndpc2VcIiBjaGFycy5cbiAgICB1bnNhZmVQcm90b2NvbCA9IHtcbiAgICAgICdqYXZhc2NyaXB0JzogdHJ1ZSxcbiAgICAgICdqYXZhc2NyaXB0Oic6IHRydWVcbiAgICB9LFxuICAgIC8vIHByb3RvY29scyB0aGF0IG5ldmVyIGhhdmUgYSBob3N0bmFtZS5cbiAgICBob3N0bGVzc1Byb3RvY29sID0ge1xuICAgICAgJ2phdmFzY3JpcHQnOiB0cnVlLFxuICAgICAgJ2phdmFzY3JpcHQ6JzogdHJ1ZVxuICAgIH0sXG4gICAgLy8gcHJvdG9jb2xzIHRoYXQgYWx3YXlzIGNvbnRhaW4gYSAvLyBiaXQuXG4gICAgc2xhc2hlZFByb3RvY29sID0ge1xuICAgICAgJ2h0dHAnOiB0cnVlLFxuICAgICAgJ2h0dHBzJzogdHJ1ZSxcbiAgICAgICdmdHAnOiB0cnVlLFxuICAgICAgJ2dvcGhlcic6IHRydWUsXG4gICAgICAnZmlsZSc6IHRydWUsXG4gICAgICAnaHR0cDonOiB0cnVlLFxuICAgICAgJ2h0dHBzOic6IHRydWUsXG4gICAgICAnZnRwOic6IHRydWUsXG4gICAgICAnZ29waGVyOic6IHRydWUsXG4gICAgICAnZmlsZTonOiB0cnVlXG4gICAgfSxcbiAgICBxdWVyeXN0cmluZyA9IHJlcXVpcmUoJ3F1ZXJ5c3RyaW5nJyk7XG5cbmZ1bmN0aW9uIHVybFBhcnNlKHVybCwgcGFyc2VRdWVyeVN0cmluZywgc2xhc2hlc0Rlbm90ZUhvc3QpIHtcbiAgaWYgKHVybCAmJiBpc09iamVjdCh1cmwpICYmIHVybCBpbnN0YW5jZW9mIFVybCkgcmV0dXJuIHVybDtcblxuICB2YXIgdSA9IG5ldyBVcmw7XG4gIHUucGFyc2UodXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCk7XG4gIHJldHVybiB1O1xufVxuXG5VcmwucHJvdG90eXBlLnBhcnNlID0gZnVuY3Rpb24odXJsLCBwYXJzZVF1ZXJ5U3RyaW5nLCBzbGFzaGVzRGVub3RlSG9zdCkge1xuICBpZiAoIWlzU3RyaW5nKHVybCkpIHtcbiAgICB0aHJvdyBuZXcgVHlwZUVycm9yKFwiUGFyYW1ldGVyICd1cmwnIG11c3QgYmUgYSBzdHJpbmcsIG5vdCBcIiArIHR5cGVvZiB1cmwpO1xuICB9XG5cbiAgdmFyIHJlc3QgPSB1cmw7XG5cbiAgLy8gdHJpbSBiZWZvcmUgcHJvY2VlZGluZy5cbiAgLy8gVGhpcyBpcyB0byBzdXBwb3J0IHBhcnNlIHN0dWZmIGxpa2UgXCIgIGh0dHA6Ly9mb28uY29tICBcXG5cIlxuICByZXN0ID0gcmVzdC50cmltKCk7XG5cbiAgdmFyIHByb3RvID0gcHJvdG9jb2xQYXR0ZXJuLmV4ZWMocmVzdCk7XG4gIGlmIChwcm90bykge1xuICAgIHByb3RvID0gcHJvdG9bMF07XG4gICAgdmFyIGxvd2VyUHJvdG8gPSBwcm90by50b0xvd2VyQ2FzZSgpO1xuICAgIHRoaXMucHJvdG9jb2wgPSBsb3dlclByb3RvO1xuICAgIHJlc3QgPSByZXN0LnN1YnN0cihwcm90by5sZW5ndGgpO1xuICB9XG5cbiAgLy8gZmlndXJlIG91dCBpZiBpdCdzIGdvdCBhIGhvc3RcbiAgLy8gdXNlckBzZXJ2ZXIgaXMgKmFsd2F5cyogaW50ZXJwcmV0ZWQgYXMgYSBob3N0bmFtZSwgYW5kIHVybFxuICAvLyByZXNvbHV0aW9uIHdpbGwgdHJlYXQgLy9mb28vYmFyIGFzIGhvc3Q9Zm9vLHBhdGg9YmFyIGJlY2F1c2UgdGhhdCdzXG4gIC8vIGhvdyB0aGUgYnJvd3NlciByZXNvbHZlcyByZWxhdGl2ZSBVUkxzLlxuICBpZiAoc2xhc2hlc0Rlbm90ZUhvc3QgfHwgcHJvdG8gfHwgcmVzdC5tYXRjaCgvXlxcL1xcL1teQFxcL10rQFteQFxcL10rLykpIHtcbiAgICB2YXIgc2xhc2hlcyA9IHJlc3Quc3Vic3RyKDAsIDIpID09PSAnLy8nO1xuICAgIGlmIChzbGFzaGVzICYmICEocHJvdG8gJiYgaG9zdGxlc3NQcm90b2NvbFtwcm90b10pKSB7XG4gICAgICByZXN0ID0gcmVzdC5zdWJzdHIoMik7XG4gICAgICB0aGlzLnNsYXNoZXMgPSB0cnVlO1xuICAgIH1cbiAgfVxuXG4gIGlmICghaG9zdGxlc3NQcm90b2NvbFtwcm90b10gJiZcbiAgICAgIChzbGFzaGVzIHx8IChwcm90byAmJiAhc2xhc2hlZFByb3RvY29sW3Byb3RvXSkpKSB7XG5cbiAgICAvLyB0aGVyZSdzIGEgaG9zdG5hbWUuXG4gICAgLy8gdGhlIGZpcnN0IGluc3RhbmNlIG9mIC8sID8sIDssIG9yICMgZW5kcyB0aGUgaG9zdC5cbiAgICAvL1xuICAgIC8vIElmIHRoZXJlIGlzIGFuIEAgaW4gdGhlIGhvc3RuYW1lLCB0aGVuIG5vbi1ob3N0IGNoYXJzICphcmUqIGFsbG93ZWRcbiAgICAvLyB0byB0aGUgbGVmdCBvZiB0aGUgbGFzdCBAIHNpZ24sIHVubGVzcyBzb21lIGhvc3QtZW5kaW5nIGNoYXJhY3RlclxuICAgIC8vIGNvbWVzICpiZWZvcmUqIHRoZSBALXNpZ24uXG4gICAgLy8gVVJMcyBhcmUgb2Jub3hpb3VzLlxuICAgIC8vXG4gICAgLy8gZXg6XG4gICAgLy8gaHR0cDovL2FAYkBjLyA9PiB1c2VyOmFAYiBob3N0OmNcbiAgICAvLyBodHRwOi8vYUBiP0BjID0+IHVzZXI6YSBob3N0OmMgcGF0aDovP0BjXG5cbiAgICAvLyB2MC4xMiBUT0RPKGlzYWFjcyk6IFRoaXMgaXMgbm90IHF1aXRlIGhvdyBDaHJvbWUgZG9lcyB0aGluZ3MuXG4gICAgLy8gUmV2aWV3IG91ciB0ZXN0IGNhc2UgYWdhaW5zdCBicm93c2VycyBtb3JlIGNvbXByZWhlbnNpdmVseS5cblxuICAgIC8vIGZpbmQgdGhlIGZpcnN0IGluc3RhbmNlIG9mIGFueSBob3N0RW5kaW5nQ2hhcnNcbiAgICB2YXIgaG9zdEVuZCA9IC0xO1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaG9zdEVuZGluZ0NoYXJzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB2YXIgaGVjID0gcmVzdC5pbmRleE9mKGhvc3RFbmRpbmdDaGFyc1tpXSk7XG4gICAgICBpZiAoaGVjICE9PSAtMSAmJiAoaG9zdEVuZCA9PT0gLTEgfHwgaGVjIDwgaG9zdEVuZCkpXG4gICAgICAgIGhvc3RFbmQgPSBoZWM7XG4gICAgfVxuXG4gICAgLy8gYXQgdGhpcyBwb2ludCwgZWl0aGVyIHdlIGhhdmUgYW4gZXhwbGljaXQgcG9pbnQgd2hlcmUgdGhlXG4gICAgLy8gYXV0aCBwb3J0aW9uIGNhbm5vdCBnbyBwYXN0LCBvciB0aGUgbGFzdCBAIGNoYXIgaXMgdGhlIGRlY2lkZXIuXG4gICAgdmFyIGF1dGgsIGF0U2lnbjtcbiAgICBpZiAoaG9zdEVuZCA9PT0gLTEpIHtcbiAgICAgIC8vIGF0U2lnbiBjYW4gYmUgYW55d2hlcmUuXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIC8vIGF0U2lnbiBtdXN0IGJlIGluIGF1dGggcG9ydGlvbi5cbiAgICAgIC8vIGh0dHA6Ly9hQGIvY0BkID0+IGhvc3Q6YiBhdXRoOmEgcGF0aDovY0BkXG4gICAgICBhdFNpZ24gPSByZXN0Lmxhc3RJbmRleE9mKCdAJywgaG9zdEVuZCk7XG4gICAgfVxuXG4gICAgLy8gTm93IHdlIGhhdmUgYSBwb3J0aW9uIHdoaWNoIGlzIGRlZmluaXRlbHkgdGhlIGF1dGguXG4gICAgLy8gUHVsbCB0aGF0IG9mZi5cbiAgICBpZiAoYXRTaWduICE9PSAtMSkge1xuICAgICAgYXV0aCA9IHJlc3Quc2xpY2UoMCwgYXRTaWduKTtcbiAgICAgIHJlc3QgPSByZXN0LnNsaWNlKGF0U2lnbiArIDEpO1xuICAgICAgdGhpcy5hdXRoID0gZGVjb2RlVVJJQ29tcG9uZW50KGF1dGgpO1xuICAgIH1cblxuICAgIC8vIHRoZSBob3N0IGlzIHRoZSByZW1haW5pbmcgdG8gdGhlIGxlZnQgb2YgdGhlIGZpcnN0IG5vbi1ob3N0IGNoYXJcbiAgICBob3N0RW5kID0gLTE7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBub25Ib3N0Q2hhcnMubGVuZ3RoOyBpKyspIHtcbiAgICAgIHZhciBoZWMgPSByZXN0LmluZGV4T2Yobm9uSG9zdENoYXJzW2ldKTtcbiAgICAgIGlmIChoZWMgIT09IC0xICYmIChob3N0RW5kID09PSAtMSB8fCBoZWMgPCBob3N0RW5kKSlcbiAgICAgICAgaG9zdEVuZCA9IGhlYztcbiAgICB9XG4gICAgLy8gaWYgd2Ugc3RpbGwgaGF2ZSBub3QgaGl0IGl0LCB0aGVuIHRoZSBlbnRpcmUgdGhpbmcgaXMgYSBob3N0LlxuICAgIGlmIChob3N0RW5kID09PSAtMSlcbiAgICAgIGhvc3RFbmQgPSByZXN0Lmxlbmd0aDtcblxuICAgIHRoaXMuaG9zdCA9IHJlc3Quc2xpY2UoMCwgaG9zdEVuZCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoaG9zdEVuZCk7XG5cbiAgICAvLyBwdWxsIG91dCBwb3J0LlxuICAgIHRoaXMucGFyc2VIb3N0KCk7XG5cbiAgICAvLyB3ZSd2ZSBpbmRpY2F0ZWQgdGhhdCB0aGVyZSBpcyBhIGhvc3RuYW1lLFxuICAgIC8vIHNvIGV2ZW4gaWYgaXQncyBlbXB0eSwgaXQgaGFzIHRvIGJlIHByZXNlbnQuXG4gICAgdGhpcy5ob3N0bmFtZSA9IHRoaXMuaG9zdG5hbWUgfHwgJyc7XG5cbiAgICAvLyBpZiBob3N0bmFtZSBiZWdpbnMgd2l0aCBbIGFuZCBlbmRzIHdpdGggXVxuICAgIC8vIGFzc3VtZSB0aGF0IGl0J3MgYW4gSVB2NiBhZGRyZXNzLlxuICAgIHZhciBpcHY2SG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lWzBdID09PSAnWycgJiZcbiAgICAgICAgdGhpcy5ob3N0bmFtZVt0aGlzLmhvc3RuYW1lLmxlbmd0aCAtIDFdID09PSAnXSc7XG5cbiAgICAvLyB2YWxpZGF0ZSBhIGxpdHRsZS5cbiAgICBpZiAoIWlwdjZIb3N0bmFtZSkge1xuICAgICAgdmFyIGhvc3RwYXJ0cyA9IHRoaXMuaG9zdG5hbWUuc3BsaXQoL1xcLi8pO1xuICAgICAgZm9yICh2YXIgaSA9IDAsIGwgPSBob3N0cGFydHMubGVuZ3RoOyBpIDwgbDsgaSsrKSB7XG4gICAgICAgIHZhciBwYXJ0ID0gaG9zdHBhcnRzW2ldO1xuICAgICAgICBpZiAoIXBhcnQpIGNvbnRpbnVlO1xuICAgICAgICBpZiAoIXBhcnQubWF0Y2goaG9zdG5hbWVQYXJ0UGF0dGVybikpIHtcbiAgICAgICAgICB2YXIgbmV3cGFydCA9ICcnO1xuICAgICAgICAgIGZvciAodmFyIGogPSAwLCBrID0gcGFydC5sZW5ndGg7IGogPCBrOyBqKyspIHtcbiAgICAgICAgICAgIGlmIChwYXJ0LmNoYXJDb2RlQXQoaikgPiAxMjcpIHtcbiAgICAgICAgICAgICAgLy8gd2UgcmVwbGFjZSBub24tQVNDSUkgY2hhciB3aXRoIGEgdGVtcG9yYXJ5IHBsYWNlaG9sZGVyXG4gICAgICAgICAgICAgIC8vIHdlIG5lZWQgdGhpcyB0byBtYWtlIHN1cmUgc2l6ZSBvZiBob3N0bmFtZSBpcyBub3RcbiAgICAgICAgICAgICAgLy8gYnJva2VuIGJ5IHJlcGxhY2luZyBub24tQVNDSUkgYnkgbm90aGluZ1xuICAgICAgICAgICAgICBuZXdwYXJ0ICs9ICd4JztcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIG5ld3BhcnQgKz0gcGFydFtqXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgLy8gd2UgdGVzdCBhZ2FpbiB3aXRoIEFTQ0lJIGNoYXIgb25seVxuICAgICAgICAgIGlmICghbmV3cGFydC5tYXRjaChob3N0bmFtZVBhcnRQYXR0ZXJuKSkge1xuICAgICAgICAgICAgdmFyIHZhbGlkUGFydHMgPSBob3N0cGFydHMuc2xpY2UoMCwgaSk7XG4gICAgICAgICAgICB2YXIgbm90SG9zdCA9IGhvc3RwYXJ0cy5zbGljZShpICsgMSk7XG4gICAgICAgICAgICB2YXIgYml0ID0gcGFydC5tYXRjaChob3N0bmFtZVBhcnRTdGFydCk7XG4gICAgICAgICAgICBpZiAoYml0KSB7XG4gICAgICAgICAgICAgIHZhbGlkUGFydHMucHVzaChiaXRbMV0pO1xuICAgICAgICAgICAgICBub3RIb3N0LnVuc2hpZnQoYml0WzJdKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIGlmIChub3RIb3N0Lmxlbmd0aCkge1xuICAgICAgICAgICAgICByZXN0ID0gJy8nICsgbm90SG9zdC5qb2luKCcuJykgKyByZXN0O1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgdGhpcy5ob3N0bmFtZSA9IHZhbGlkUGFydHMuam9pbignLicpO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHRoaXMuaG9zdG5hbWUubGVuZ3RoID4gaG9zdG5hbWVNYXhMZW4pIHtcbiAgICAgIHRoaXMuaG9zdG5hbWUgPSAnJztcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gaG9zdG5hbWVzIGFyZSBhbHdheXMgbG93ZXIgY2FzZS5cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSB0aGlzLmhvc3RuYW1lLnRvTG93ZXJDYXNlKCk7XG4gICAgfVxuXG4gICAgaWYgKCFpcHY2SG9zdG5hbWUpIHtcbiAgICAgIC8vIElETkEgU3VwcG9ydDogUmV0dXJucyBhIHB1bnkgY29kZWQgcmVwcmVzZW50YXRpb24gb2YgXCJkb21haW5cIi5cbiAgICAgIC8vIEl0IG9ubHkgY29udmVydHMgdGhlIHBhcnQgb2YgdGhlIGRvbWFpbiBuYW1lIHRoYXRcbiAgICAgIC8vIGhhcyBub24gQVNDSUkgY2hhcmFjdGVycy4gSS5lLiBpdCBkb3NlbnQgbWF0dGVyIGlmXG4gICAgICAvLyB5b3UgY2FsbCBpdCB3aXRoIGEgZG9tYWluIHRoYXQgYWxyZWFkeSBpcyBpbiBBU0NJSS5cbiAgICAgIHZhciBkb21haW5BcnJheSA9IHRoaXMuaG9zdG5hbWUuc3BsaXQoJy4nKTtcbiAgICAgIHZhciBuZXdPdXQgPSBbXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgZG9tYWluQXJyYXkubGVuZ3RoOyArK2kpIHtcbiAgICAgICAgdmFyIHMgPSBkb21haW5BcnJheVtpXTtcbiAgICAgICAgbmV3T3V0LnB1c2gocy5tYXRjaCgvW15BLVphLXowLTlfLV0vKSA/XG4gICAgICAgICAgICAneG4tLScgKyBwdW55Y29kZS5lbmNvZGUocykgOiBzKTtcbiAgICAgIH1cbiAgICAgIHRoaXMuaG9zdG5hbWUgPSBuZXdPdXQuam9pbignLicpO1xuICAgIH1cblxuICAgIHZhciBwID0gdGhpcy5wb3J0ID8gJzonICsgdGhpcy5wb3J0IDogJyc7XG4gICAgdmFyIGggPSB0aGlzLmhvc3RuYW1lIHx8ICcnO1xuICAgIHRoaXMuaG9zdCA9IGggKyBwO1xuICAgIHRoaXMuaHJlZiArPSB0aGlzLmhvc3Q7XG5cbiAgICAvLyBzdHJpcCBbIGFuZCBdIGZyb20gdGhlIGhvc3RuYW1lXG4gICAgLy8gdGhlIGhvc3QgZmllbGQgc3RpbGwgcmV0YWlucyB0aGVtLCB0aG91Z2hcbiAgICBpZiAoaXB2Nkhvc3RuYW1lKSB7XG4gICAgICB0aGlzLmhvc3RuYW1lID0gdGhpcy5ob3N0bmFtZS5zdWJzdHIoMSwgdGhpcy5ob3N0bmFtZS5sZW5ndGggLSAyKTtcbiAgICAgIGlmIChyZXN0WzBdICE9PSAnLycpIHtcbiAgICAgICAgcmVzdCA9ICcvJyArIHJlc3Q7XG4gICAgICB9XG4gICAgfVxuICB9XG5cbiAgLy8gbm93IHJlc3QgaXMgc2V0IHRvIHRoZSBwb3N0LWhvc3Qgc3R1ZmYuXG4gIC8vIGNob3Agb2ZmIGFueSBkZWxpbSBjaGFycy5cbiAgaWYgKCF1bnNhZmVQcm90b2NvbFtsb3dlclByb3RvXSkge1xuXG4gICAgLy8gRmlyc3QsIG1ha2UgMTAwJSBzdXJlIHRoYXQgYW55IFwiYXV0b0VzY2FwZVwiIGNoYXJzIGdldFxuICAgIC8vIGVzY2FwZWQsIGV2ZW4gaWYgZW5jb2RlVVJJQ29tcG9uZW50IGRvZXNuJ3QgdGhpbmsgdGhleVxuICAgIC8vIG5lZWQgdG8gYmUuXG4gICAgZm9yICh2YXIgaSA9IDAsIGwgPSBhdXRvRXNjYXBlLmxlbmd0aDsgaSA8IGw7IGkrKykge1xuICAgICAgdmFyIGFlID0gYXV0b0VzY2FwZVtpXTtcbiAgICAgIHZhciBlc2MgPSBlbmNvZGVVUklDb21wb25lbnQoYWUpO1xuICAgICAgaWYgKGVzYyA9PT0gYWUpIHtcbiAgICAgICAgZXNjID0gZXNjYXBlKGFlKTtcbiAgICAgIH1cbiAgICAgIHJlc3QgPSByZXN0LnNwbGl0KGFlKS5qb2luKGVzYyk7XG4gICAgfVxuICB9XG5cblxuICAvLyBjaG9wIG9mZiBmcm9tIHRoZSB0YWlsIGZpcnN0LlxuICB2YXIgaGFzaCA9IHJlc3QuaW5kZXhPZignIycpO1xuICBpZiAoaGFzaCAhPT0gLTEpIHtcbiAgICAvLyBnb3QgYSBmcmFnbWVudCBzdHJpbmcuXG4gICAgdGhpcy5oYXNoID0gcmVzdC5zdWJzdHIoaGFzaCk7XG4gICAgcmVzdCA9IHJlc3Quc2xpY2UoMCwgaGFzaCk7XG4gIH1cbiAgdmFyIHFtID0gcmVzdC5pbmRleE9mKCc/Jyk7XG4gIGlmIChxbSAhPT0gLTEpIHtcbiAgICB0aGlzLnNlYXJjaCA9IHJlc3Quc3Vic3RyKHFtKTtcbiAgICB0aGlzLnF1ZXJ5ID0gcmVzdC5zdWJzdHIocW0gKyAxKTtcbiAgICBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgICAgdGhpcy5xdWVyeSA9IHF1ZXJ5c3RyaW5nLnBhcnNlKHRoaXMucXVlcnkpO1xuICAgIH1cbiAgICByZXN0ID0gcmVzdC5zbGljZSgwLCBxbSk7XG4gIH0gZWxzZSBpZiAocGFyc2VRdWVyeVN0cmluZykge1xuICAgIC8vIG5vIHF1ZXJ5IHN0cmluZywgYnV0IHBhcnNlUXVlcnlTdHJpbmcgc3RpbGwgcmVxdWVzdGVkXG4gICAgdGhpcy5zZWFyY2ggPSAnJztcbiAgICB0aGlzLnF1ZXJ5ID0ge307XG4gIH1cbiAgaWYgKHJlc3QpIHRoaXMucGF0aG5hbWUgPSByZXN0O1xuICBpZiAoc2xhc2hlZFByb3RvY29sW2xvd2VyUHJvdG9dICYmXG4gICAgICB0aGlzLmhvc3RuYW1lICYmICF0aGlzLnBhdGhuYW1lKSB7XG4gICAgdGhpcy5wYXRobmFtZSA9ICcvJztcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgaWYgKHRoaXMucGF0aG5hbWUgfHwgdGhpcy5zZWFyY2gpIHtcbiAgICB2YXIgcCA9IHRoaXMucGF0aG5hbWUgfHwgJyc7XG4gICAgdmFyIHMgPSB0aGlzLnNlYXJjaCB8fCAnJztcbiAgICB0aGlzLnBhdGggPSBwICsgcztcbiAgfVxuXG4gIC8vIGZpbmFsbHksIHJlY29uc3RydWN0IHRoZSBocmVmIGJhc2VkIG9uIHdoYXQgaGFzIGJlZW4gdmFsaWRhdGVkLlxuICB0aGlzLmhyZWYgPSB0aGlzLmZvcm1hdCgpO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8vIGZvcm1hdCBhIHBhcnNlZCBvYmplY3QgaW50byBhIHVybCBzdHJpbmdcbmZ1bmN0aW9uIHVybEZvcm1hdChvYmopIHtcbiAgLy8gZW5zdXJlIGl0J3MgYW4gb2JqZWN0LCBhbmQgbm90IGEgc3RyaW5nIHVybC5cbiAgLy8gSWYgaXQncyBhbiBvYmosIHRoaXMgaXMgYSBuby1vcC5cbiAgLy8gdGhpcyB3YXksIHlvdSBjYW4gY2FsbCB1cmxfZm9ybWF0KCkgb24gc3RyaW5nc1xuICAvLyB0byBjbGVhbiB1cCBwb3RlbnRpYWxseSB3b25reSB1cmxzLlxuICBpZiAoaXNTdHJpbmcob2JqKSkgb2JqID0gdXJsUGFyc2Uob2JqKTtcbiAgaWYgKCEob2JqIGluc3RhbmNlb2YgVXJsKSkgcmV0dXJuIFVybC5wcm90b3R5cGUuZm9ybWF0LmNhbGwob2JqKTtcbiAgcmV0dXJuIG9iai5mb3JtYXQoKTtcbn1cblxuVXJsLnByb3RvdHlwZS5mb3JtYXQgPSBmdW5jdGlvbigpIHtcbiAgdmFyIGF1dGggPSB0aGlzLmF1dGggfHwgJyc7XG4gIGlmIChhdXRoKSB7XG4gICAgYXV0aCA9IGVuY29kZVVSSUNvbXBvbmVudChhdXRoKTtcbiAgICBhdXRoID0gYXV0aC5yZXBsYWNlKC8lM0EvaSwgJzonKTtcbiAgICBhdXRoICs9ICdAJztcbiAgfVxuXG4gIHZhciBwcm90b2NvbCA9IHRoaXMucHJvdG9jb2wgfHwgJycsXG4gICAgICBwYXRobmFtZSA9IHRoaXMucGF0aG5hbWUgfHwgJycsXG4gICAgICBoYXNoID0gdGhpcy5oYXNoIHx8ICcnLFxuICAgICAgaG9zdCA9IGZhbHNlLFxuICAgICAgcXVlcnkgPSAnJztcblxuICBpZiAodGhpcy5ob3N0KSB7XG4gICAgaG9zdCA9IGF1dGggKyB0aGlzLmhvc3Q7XG4gIH0gZWxzZSBpZiAodGhpcy5ob3N0bmFtZSkge1xuICAgIGhvc3QgPSBhdXRoICsgKHRoaXMuaG9zdG5hbWUuaW5kZXhPZignOicpID09PSAtMSA/XG4gICAgICAgIHRoaXMuaG9zdG5hbWUgOlxuICAgICAgICAnWycgKyB0aGlzLmhvc3RuYW1lICsgJ10nKTtcbiAgICBpZiAodGhpcy5wb3J0KSB7XG4gICAgICBob3N0ICs9ICc6JyArIHRoaXMucG9ydDtcbiAgICB9XG4gIH1cblxuICBpZiAodGhpcy5xdWVyeSAmJlxuICAgICAgaXNPYmplY3QodGhpcy5xdWVyeSkgJiZcbiAgICAgIE9iamVjdC5rZXlzKHRoaXMucXVlcnkpLmxlbmd0aCkge1xuICAgIHF1ZXJ5ID0gcXVlcnlzdHJpbmcuc3RyaW5naWZ5KHRoaXMucXVlcnkpO1xuICB9XG5cbiAgdmFyIHNlYXJjaCA9IHRoaXMuc2VhcmNoIHx8IChxdWVyeSAmJiAoJz8nICsgcXVlcnkpKSB8fCAnJztcblxuICBpZiAocHJvdG9jb2wgJiYgcHJvdG9jb2wuc3Vic3RyKC0xKSAhPT0gJzonKSBwcm90b2NvbCArPSAnOic7XG5cbiAgLy8gb25seSB0aGUgc2xhc2hlZFByb3RvY29scyBnZXQgdGhlIC8vLiAgTm90IG1haWx0bzosIHhtcHA6LCBldGMuXG4gIC8vIHVubGVzcyB0aGV5IGhhZCB0aGVtIHRvIGJlZ2luIHdpdGguXG4gIGlmICh0aGlzLnNsYXNoZXMgfHxcbiAgICAgICghcHJvdG9jb2wgfHwgc2xhc2hlZFByb3RvY29sW3Byb3RvY29sXSkgJiYgaG9zdCAhPT0gZmFsc2UpIHtcbiAgICBob3N0ID0gJy8vJyArIChob3N0IHx8ICcnKTtcbiAgICBpZiAocGF0aG5hbWUgJiYgcGF0aG5hbWUuY2hhckF0KDApICE9PSAnLycpIHBhdGhuYW1lID0gJy8nICsgcGF0aG5hbWU7XG4gIH0gZWxzZSBpZiAoIWhvc3QpIHtcbiAgICBob3N0ID0gJyc7XG4gIH1cblxuICBpZiAoaGFzaCAmJiBoYXNoLmNoYXJBdCgwKSAhPT0gJyMnKSBoYXNoID0gJyMnICsgaGFzaDtcbiAgaWYgKHNlYXJjaCAmJiBzZWFyY2guY2hhckF0KDApICE9PSAnPycpIHNlYXJjaCA9ICc/JyArIHNlYXJjaDtcblxuICBwYXRobmFtZSA9IHBhdGhuYW1lLnJlcGxhY2UoL1s/I10vZywgZnVuY3Rpb24obWF0Y2gpIHtcbiAgICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KG1hdGNoKTtcbiAgfSk7XG4gIHNlYXJjaCA9IHNlYXJjaC5yZXBsYWNlKCcjJywgJyUyMycpO1xuXG4gIHJldHVybiBwcm90b2NvbCArIGhvc3QgKyBwYXRobmFtZSArIHNlYXJjaCArIGhhc2g7XG59O1xuXG5mdW5jdGlvbiB1cmxSZXNvbHZlKHNvdXJjZSwgcmVsYXRpdmUpIHtcbiAgcmV0dXJuIHVybFBhcnNlKHNvdXJjZSwgZmFsc2UsIHRydWUpLnJlc29sdmUocmVsYXRpdmUpO1xufVxuXG5VcmwucHJvdG90eXBlLnJlc29sdmUgPSBmdW5jdGlvbihyZWxhdGl2ZSkge1xuICByZXR1cm4gdGhpcy5yZXNvbHZlT2JqZWN0KHVybFBhcnNlKHJlbGF0aXZlLCBmYWxzZSwgdHJ1ZSkpLmZvcm1hdCgpO1xufTtcblxuZnVuY3Rpb24gdXJsUmVzb2x2ZU9iamVjdChzb3VyY2UsIHJlbGF0aXZlKSB7XG4gIGlmICghc291cmNlKSByZXR1cm4gcmVsYXRpdmU7XG4gIHJldHVybiB1cmxQYXJzZShzb3VyY2UsIGZhbHNlLCB0cnVlKS5yZXNvbHZlT2JqZWN0KHJlbGF0aXZlKTtcbn1cblxuVXJsLnByb3RvdHlwZS5yZXNvbHZlT2JqZWN0ID0gZnVuY3Rpb24ocmVsYXRpdmUpIHtcbiAgaWYgKGlzU3RyaW5nKHJlbGF0aXZlKSkge1xuICAgIHZhciByZWwgPSBuZXcgVXJsKCk7XG4gICAgcmVsLnBhcnNlKHJlbGF0aXZlLCBmYWxzZSwgdHJ1ZSk7XG4gICAgcmVsYXRpdmUgPSByZWw7XG4gIH1cblxuICB2YXIgcmVzdWx0ID0gbmV3IFVybCgpO1xuICBPYmplY3Qua2V5cyh0aGlzKS5mb3JFYWNoKGZ1bmN0aW9uKGspIHtcbiAgICByZXN1bHRba10gPSB0aGlzW2tdO1xuICB9LCB0aGlzKTtcblxuICAvLyBoYXNoIGlzIGFsd2F5cyBvdmVycmlkZGVuLCBubyBtYXR0ZXIgd2hhdC5cbiAgLy8gZXZlbiBocmVmPVwiXCIgd2lsbCByZW1vdmUgaXQuXG4gIHJlc3VsdC5oYXNoID0gcmVsYXRpdmUuaGFzaDtcblxuICAvLyBpZiB0aGUgcmVsYXRpdmUgdXJsIGlzIGVtcHR5LCB0aGVuIHRoZXJlJ3Mgbm90aGluZyBsZWZ0IHRvIGRvIGhlcmUuXG4gIGlmIChyZWxhdGl2ZS5ocmVmID09PSAnJykge1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICAvLyBocmVmcyBsaWtlIC8vZm9vL2JhciBhbHdheXMgY3V0IHRvIHRoZSBwcm90b2NvbC5cbiAgaWYgKHJlbGF0aXZlLnNsYXNoZXMgJiYgIXJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgLy8gdGFrZSBldmVyeXRoaW5nIGV4Y2VwdCB0aGUgcHJvdG9jb2wgZnJvbSByZWxhdGl2ZVxuICAgIE9iamVjdC5rZXlzKHJlbGF0aXZlKS5mb3JFYWNoKGZ1bmN0aW9uKGspIHtcbiAgICAgIGlmIChrICE9PSAncHJvdG9jb2wnKVxuICAgICAgICByZXN1bHRba10gPSByZWxhdGl2ZVtrXTtcbiAgICB9KTtcblxuICAgIC8vdXJsUGFyc2UgYXBwZW5kcyB0cmFpbGluZyAvIHRvIHVybHMgbGlrZSBodHRwOi8vd3d3LmV4YW1wbGUuY29tXG4gICAgaWYgKHNsYXNoZWRQcm90b2NvbFtyZXN1bHQucHJvdG9jb2xdICYmXG4gICAgICAgIHJlc3VsdC5ob3N0bmFtZSAmJiAhcmVzdWx0LnBhdGhuYW1lKSB7XG4gICAgICByZXN1bHQucGF0aCA9IHJlc3VsdC5wYXRobmFtZSA9ICcvJztcbiAgICB9XG5cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgaWYgKHJlbGF0aXZlLnByb3RvY29sICYmIHJlbGF0aXZlLnByb3RvY29sICE9PSByZXN1bHQucHJvdG9jb2wpIHtcbiAgICAvLyBpZiBpdCdzIGEga25vd24gdXJsIHByb3RvY29sLCB0aGVuIGNoYW5naW5nXG4gICAgLy8gdGhlIHByb3RvY29sIGRvZXMgd2VpcmQgdGhpbmdzXG4gICAgLy8gZmlyc3QsIGlmIGl0J3Mgbm90IGZpbGU6LCB0aGVuIHdlIE1VU1QgaGF2ZSBhIGhvc3QsXG4gICAgLy8gYW5kIGlmIHRoZXJlIHdhcyBhIHBhdGhcbiAgICAvLyB0byBiZWdpbiB3aXRoLCB0aGVuIHdlIE1VU1QgaGF2ZSBhIHBhdGguXG4gICAgLy8gaWYgaXQgaXMgZmlsZTosIHRoZW4gdGhlIGhvc3QgaXMgZHJvcHBlZCxcbiAgICAvLyBiZWNhdXNlIHRoYXQncyBrbm93biB0byBiZSBob3N0bGVzcy5cbiAgICAvLyBhbnl0aGluZyBlbHNlIGlzIGFzc3VtZWQgdG8gYmUgYWJzb2x1dGUuXG4gICAgaWYgKCFzbGFzaGVkUHJvdG9jb2xbcmVsYXRpdmUucHJvdG9jb2xdKSB7XG4gICAgICBPYmplY3Qua2V5cyhyZWxhdGl2ZSkuZm9yRWFjaChmdW5jdGlvbihrKSB7XG4gICAgICAgIHJlc3VsdFtrXSA9IHJlbGF0aXZlW2tdO1xuICAgICAgfSk7XG4gICAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgfVxuXG4gICAgcmVzdWx0LnByb3RvY29sID0gcmVsYXRpdmUucHJvdG9jb2w7XG4gICAgaWYgKCFyZWxhdGl2ZS5ob3N0ICYmICFob3N0bGVzc1Byb3RvY29sW3JlbGF0aXZlLnByb3RvY29sXSkge1xuICAgICAgdmFyIHJlbFBhdGggPSAocmVsYXRpdmUucGF0aG5hbWUgfHwgJycpLnNwbGl0KCcvJyk7XG4gICAgICB3aGlsZSAocmVsUGF0aC5sZW5ndGggJiYgIShyZWxhdGl2ZS5ob3N0ID0gcmVsUGF0aC5zaGlmdCgpKSk7XG4gICAgICBpZiAoIXJlbGF0aXZlLmhvc3QpIHJlbGF0aXZlLmhvc3QgPSAnJztcbiAgICAgIGlmICghcmVsYXRpdmUuaG9zdG5hbWUpIHJlbGF0aXZlLmhvc3RuYW1lID0gJyc7XG4gICAgICBpZiAocmVsUGF0aFswXSAhPT0gJycpIHJlbFBhdGgudW5zaGlmdCgnJyk7XG4gICAgICBpZiAocmVsUGF0aC5sZW5ndGggPCAyKSByZWxQYXRoLnVuc2hpZnQoJycpO1xuICAgICAgcmVzdWx0LnBhdGhuYW1lID0gcmVsUGF0aC5qb2luKCcvJyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlc3VsdC5wYXRobmFtZSA9IHJlbGF0aXZlLnBhdGhuYW1lO1xuICAgIH1cbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICAgIHJlc3VsdC5ob3N0ID0gcmVsYXRpdmUuaG9zdCB8fCAnJztcbiAgICByZXN1bHQuYXV0aCA9IHJlbGF0aXZlLmF1dGg7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdDtcbiAgICByZXN1bHQucG9ydCA9IHJlbGF0aXZlLnBvcnQ7XG4gICAgLy8gdG8gc3VwcG9ydCBodHRwLnJlcXVlc3RcbiAgICBpZiAocmVzdWx0LnBhdGhuYW1lIHx8IHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHZhciBwID0gcmVzdWx0LnBhdGhuYW1lIHx8ICcnO1xuICAgICAgdmFyIHMgPSByZXN1bHQuc2VhcmNoIHx8ICcnO1xuICAgICAgcmVzdWx0LnBhdGggPSBwICsgcztcbiAgICB9XG4gICAgcmVzdWx0LnNsYXNoZXMgPSByZXN1bHQuc2xhc2hlcyB8fCByZWxhdGl2ZS5zbGFzaGVzO1xuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICB2YXIgaXNTb3VyY2VBYnMgPSAocmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5jaGFyQXQoMCkgPT09ICcvJyksXG4gICAgICBpc1JlbEFicyA9IChcbiAgICAgICAgICByZWxhdGl2ZS5ob3N0IHx8XG4gICAgICAgICAgcmVsYXRpdmUucGF0aG5hbWUgJiYgcmVsYXRpdmUucGF0aG5hbWUuY2hhckF0KDApID09PSAnLydcbiAgICAgICksXG4gICAgICBtdXN0RW5kQWJzID0gKGlzUmVsQWJzIHx8IGlzU291cmNlQWJzIHx8XG4gICAgICAgICAgICAgICAgICAgIChyZXN1bHQuaG9zdCAmJiByZWxhdGl2ZS5wYXRobmFtZSkpLFxuICAgICAgcmVtb3ZlQWxsRG90cyA9IG11c3RFbmRBYnMsXG4gICAgICBzcmNQYXRoID0gcmVzdWx0LnBhdGhuYW1lICYmIHJlc3VsdC5wYXRobmFtZS5zcGxpdCgnLycpIHx8IFtdLFxuICAgICAgcmVsUGF0aCA9IHJlbGF0aXZlLnBhdGhuYW1lICYmIHJlbGF0aXZlLnBhdGhuYW1lLnNwbGl0KCcvJykgfHwgW10sXG4gICAgICBwc3ljaG90aWMgPSByZXN1bHQucHJvdG9jb2wgJiYgIXNsYXNoZWRQcm90b2NvbFtyZXN1bHQucHJvdG9jb2xdO1xuXG4gIC8vIGlmIHRoZSB1cmwgaXMgYSBub24tc2xhc2hlZCB1cmwsIHRoZW4gcmVsYXRpdmVcbiAgLy8gbGlua3MgbGlrZSAuLi8uLiBzaG91bGQgYmUgYWJsZVxuICAvLyB0byBjcmF3bCB1cCB0byB0aGUgaG9zdG5hbWUsIGFzIHdlbGwuICBUaGlzIGlzIHN0cmFuZ2UuXG4gIC8vIHJlc3VsdC5wcm90b2NvbCBoYXMgYWxyZWFkeSBiZWVuIHNldCBieSBub3cuXG4gIC8vIExhdGVyIG9uLCBwdXQgdGhlIGZpcnN0IHBhdGggcGFydCBpbnRvIHRoZSBob3N0IGZpZWxkLlxuICBpZiAocHN5Y2hvdGljKSB7XG4gICAgcmVzdWx0Lmhvc3RuYW1lID0gJyc7XG4gICAgcmVzdWx0LnBvcnQgPSBudWxsO1xuICAgIGlmIChyZXN1bHQuaG9zdCkge1xuICAgICAgaWYgKHNyY1BhdGhbMF0gPT09ICcnKSBzcmNQYXRoWzBdID0gcmVzdWx0Lmhvc3Q7XG4gICAgICBlbHNlIHNyY1BhdGgudW5zaGlmdChyZXN1bHQuaG9zdCk7XG4gICAgfVxuICAgIHJlc3VsdC5ob3N0ID0gJyc7XG4gICAgaWYgKHJlbGF0aXZlLnByb3RvY29sKSB7XG4gICAgICByZWxhdGl2ZS5ob3N0bmFtZSA9IG51bGw7XG4gICAgICByZWxhdGl2ZS5wb3J0ID0gbnVsbDtcbiAgICAgIGlmIChyZWxhdGl2ZS5ob3N0KSB7XG4gICAgICAgIGlmIChyZWxQYXRoWzBdID09PSAnJykgcmVsUGF0aFswXSA9IHJlbGF0aXZlLmhvc3Q7XG4gICAgICAgIGVsc2UgcmVsUGF0aC51bnNoaWZ0KHJlbGF0aXZlLmhvc3QpO1xuICAgICAgfVxuICAgICAgcmVsYXRpdmUuaG9zdCA9IG51bGw7XG4gICAgfVxuICAgIG11c3RFbmRBYnMgPSBtdXN0RW5kQWJzICYmIChyZWxQYXRoWzBdID09PSAnJyB8fCBzcmNQYXRoWzBdID09PSAnJyk7XG4gIH1cblxuICBpZiAoaXNSZWxBYnMpIHtcbiAgICAvLyBpdCdzIGFic29sdXRlLlxuICAgIHJlc3VsdC5ob3N0ID0gKHJlbGF0aXZlLmhvc3QgfHwgcmVsYXRpdmUuaG9zdCA9PT0gJycpID9cbiAgICAgICAgICAgICAgICAgIHJlbGF0aXZlLmhvc3QgOiByZXN1bHQuaG9zdDtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSAocmVsYXRpdmUuaG9zdG5hbWUgfHwgcmVsYXRpdmUuaG9zdG5hbWUgPT09ICcnKSA/XG4gICAgICAgICAgICAgICAgICAgICAgcmVsYXRpdmUuaG9zdG5hbWUgOiByZXN1bHQuaG9zdG5hbWU7XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICBzcmNQYXRoID0gcmVsUGF0aDtcbiAgICAvLyBmYWxsIHRocm91Z2ggdG8gdGhlIGRvdC1oYW5kbGluZyBiZWxvdy5cbiAgfSBlbHNlIGlmIChyZWxQYXRoLmxlbmd0aCkge1xuICAgIC8vIGl0J3MgcmVsYXRpdmVcbiAgICAvLyB0aHJvdyBhd2F5IHRoZSBleGlzdGluZyBmaWxlLCBhbmQgdGFrZSB0aGUgbmV3IHBhdGggaW5zdGVhZC5cbiAgICBpZiAoIXNyY1BhdGgpIHNyY1BhdGggPSBbXTtcbiAgICBzcmNQYXRoLnBvcCgpO1xuICAgIHNyY1BhdGggPSBzcmNQYXRoLmNvbmNhdChyZWxQYXRoKTtcbiAgICByZXN1bHQuc2VhcmNoID0gcmVsYXRpdmUuc2VhcmNoO1xuICAgIHJlc3VsdC5xdWVyeSA9IHJlbGF0aXZlLnF1ZXJ5O1xuICB9IGVsc2UgaWYgKCFpc051bGxPclVuZGVmaW5lZChyZWxhdGl2ZS5zZWFyY2gpKSB7XG4gICAgLy8ganVzdCBwdWxsIG91dCB0aGUgc2VhcmNoLlxuICAgIC8vIGxpa2UgaHJlZj0nP2ZvbycuXG4gICAgLy8gUHV0IHRoaXMgYWZ0ZXIgdGhlIG90aGVyIHR3byBjYXNlcyBiZWNhdXNlIGl0IHNpbXBsaWZpZXMgdGhlIGJvb2xlYW5zXG4gICAgaWYgKHBzeWNob3RpYykge1xuICAgICAgcmVzdWx0Lmhvc3RuYW1lID0gcmVzdWx0Lmhvc3QgPSBzcmNQYXRoLnNoaWZ0KCk7XG4gICAgICAvL29jY2F0aW9uYWx5IHRoZSBhdXRoIGNhbiBnZXQgc3R1Y2sgb25seSBpbiBob3N0XG4gICAgICAvL3RoaXMgZXNwZWNpYWx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgICAgLy91cmwucmVzb2x2ZU9iamVjdCgnbWFpbHRvOmxvY2FsMUBkb21haW4xJywgJ2xvY2FsMkBkb21haW4yJylcbiAgICAgIHZhciBhdXRoSW5Ib3N0ID0gcmVzdWx0Lmhvc3QgJiYgcmVzdWx0Lmhvc3QuaW5kZXhPZignQCcpID4gMCA/XG4gICAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICAgIGlmIChhdXRoSW5Ib3N0KSB7XG4gICAgICAgIHJlc3VsdC5hdXRoID0gYXV0aEluSG9zdC5zaGlmdCgpO1xuICAgICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmVzdWx0LnNlYXJjaCA9IHJlbGF0aXZlLnNlYXJjaDtcbiAgICByZXN1bHQucXVlcnkgPSByZWxhdGl2ZS5xdWVyeTtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKCFpc051bGwocmVzdWx0LnBhdGhuYW1lKSB8fCAhaXNOdWxsKHJlc3VsdC5zZWFyY2gpKSB7XG4gICAgICByZXN1bHQucGF0aCA9IChyZXN1bHQucGF0aG5hbWUgPyByZXN1bHQucGF0aG5hbWUgOiAnJykgK1xuICAgICAgICAgICAgICAgICAgICAocmVzdWx0LnNlYXJjaCA/IHJlc3VsdC5zZWFyY2ggOiAnJyk7XG4gICAgfVxuICAgIHJlc3VsdC5ocmVmID0gcmVzdWx0LmZvcm1hdCgpO1xuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBpZiAoIXNyY1BhdGgubGVuZ3RoKSB7XG4gICAgLy8gbm8gcGF0aCBhdCBhbGwuICBlYXN5LlxuICAgIC8vIHdlJ3ZlIGFscmVhZHkgaGFuZGxlZCB0aGUgb3RoZXIgc3R1ZmYgYWJvdmUuXG4gICAgcmVzdWx0LnBhdGhuYW1lID0gbnVsbDtcbiAgICAvL3RvIHN1cHBvcnQgaHR0cC5yZXF1ZXN0XG4gICAgaWYgKHJlc3VsdC5zZWFyY2gpIHtcbiAgICAgIHJlc3VsdC5wYXRoID0gJy8nICsgcmVzdWx0LnNlYXJjaDtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzdWx0LnBhdGggPSBudWxsO1xuICAgIH1cbiAgICByZXN1bHQuaHJlZiA9IHJlc3VsdC5mb3JtYXQoKTtcbiAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gaWYgYSB1cmwgRU5EcyBpbiAuIG9yIC4uLCB0aGVuIGl0IG11c3QgZ2V0IGEgdHJhaWxpbmcgc2xhc2guXG4gIC8vIGhvd2V2ZXIsIGlmIGl0IGVuZHMgaW4gYW55dGhpbmcgZWxzZSBub24tc2xhc2h5LFxuICAvLyB0aGVuIGl0IG11c3QgTk9UIGdldCBhIHRyYWlsaW5nIHNsYXNoLlxuICB2YXIgbGFzdCA9IHNyY1BhdGguc2xpY2UoLTEpWzBdO1xuICB2YXIgaGFzVHJhaWxpbmdTbGFzaCA9IChcbiAgICAgIChyZXN1bHQuaG9zdCB8fCByZWxhdGl2ZS5ob3N0KSAmJiAobGFzdCA9PT0gJy4nIHx8IGxhc3QgPT09ICcuLicpIHx8XG4gICAgICBsYXN0ID09PSAnJyk7XG5cbiAgLy8gc3RyaXAgc2luZ2xlIGRvdHMsIHJlc29sdmUgZG91YmxlIGRvdHMgdG8gcGFyZW50IGRpclxuICAvLyBpZiB0aGUgcGF0aCB0cmllcyB0byBnbyBhYm92ZSB0aGUgcm9vdCwgYHVwYCBlbmRzIHVwID4gMFxuICB2YXIgdXAgPSAwO1xuICBmb3IgKHZhciBpID0gc3JjUGF0aC5sZW5ndGg7IGkgPj0gMDsgaS0tKSB7XG4gICAgbGFzdCA9IHNyY1BhdGhbaV07XG4gICAgaWYgKGxhc3QgPT0gJy4nKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICB9IGVsc2UgaWYgKGxhc3QgPT09ICcuLicpIHtcbiAgICAgIHNyY1BhdGguc3BsaWNlKGksIDEpO1xuICAgICAgdXArKztcbiAgICB9IGVsc2UgaWYgKHVwKSB7XG4gICAgICBzcmNQYXRoLnNwbGljZShpLCAxKTtcbiAgICAgIHVwLS07XG4gICAgfVxuICB9XG5cbiAgLy8gaWYgdGhlIHBhdGggaXMgYWxsb3dlZCB0byBnbyBhYm92ZSB0aGUgcm9vdCwgcmVzdG9yZSBsZWFkaW5nIC4uc1xuICBpZiAoIW11c3RFbmRBYnMgJiYgIXJlbW92ZUFsbERvdHMpIHtcbiAgICBmb3IgKDsgdXAtLTsgdXApIHtcbiAgICAgIHNyY1BhdGgudW5zaGlmdCgnLi4nKTtcbiAgICB9XG4gIH1cblxuICBpZiAobXVzdEVuZEFicyAmJiBzcmNQYXRoWzBdICE9PSAnJyAmJlxuICAgICAgKCFzcmNQYXRoWzBdIHx8IHNyY1BhdGhbMF0uY2hhckF0KDApICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmIChoYXNUcmFpbGluZ1NsYXNoICYmIChzcmNQYXRoLmpvaW4oJy8nKS5zdWJzdHIoLTEpICE9PSAnLycpKSB7XG4gICAgc3JjUGF0aC5wdXNoKCcnKTtcbiAgfVxuXG4gIHZhciBpc0Fic29sdXRlID0gc3JjUGF0aFswXSA9PT0gJycgfHxcbiAgICAgIChzcmNQYXRoWzBdICYmIHNyY1BhdGhbMF0uY2hhckF0KDApID09PSAnLycpO1xuXG4gIC8vIHB1dCB0aGUgaG9zdCBiYWNrXG4gIGlmIChwc3ljaG90aWMpIHtcbiAgICByZXN1bHQuaG9zdG5hbWUgPSByZXN1bHQuaG9zdCA9IGlzQWJzb2x1dGUgPyAnJyA6XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBzcmNQYXRoLmxlbmd0aCA/IHNyY1BhdGguc2hpZnQoKSA6ICcnO1xuICAgIC8vb2NjYXRpb25hbHkgdGhlIGF1dGggY2FuIGdldCBzdHVjayBvbmx5IGluIGhvc3RcbiAgICAvL3RoaXMgZXNwZWNpYWx5IGhhcHBlbnMgaW4gY2FzZXMgbGlrZVxuICAgIC8vdXJsLnJlc29sdmVPYmplY3QoJ21haWx0bzpsb2NhbDFAZG9tYWluMScsICdsb2NhbDJAZG9tYWluMicpXG4gICAgdmFyIGF1dGhJbkhvc3QgPSByZXN1bHQuaG9zdCAmJiByZXN1bHQuaG9zdC5pbmRleE9mKCdAJykgPiAwID9cbiAgICAgICAgICAgICAgICAgICAgIHJlc3VsdC5ob3N0LnNwbGl0KCdAJykgOiBmYWxzZTtcbiAgICBpZiAoYXV0aEluSG9zdCkge1xuICAgICAgcmVzdWx0LmF1dGggPSBhdXRoSW5Ib3N0LnNoaWZ0KCk7XG4gICAgICByZXN1bHQuaG9zdCA9IHJlc3VsdC5ob3N0bmFtZSA9IGF1dGhJbkhvc3Quc2hpZnQoKTtcbiAgICB9XG4gIH1cblxuICBtdXN0RW5kQWJzID0gbXVzdEVuZEFicyB8fCAocmVzdWx0Lmhvc3QgJiYgc3JjUGF0aC5sZW5ndGgpO1xuXG4gIGlmIChtdXN0RW5kQWJzICYmICFpc0Fic29sdXRlKSB7XG4gICAgc3JjUGF0aC51bnNoaWZ0KCcnKTtcbiAgfVxuXG4gIGlmICghc3JjUGF0aC5sZW5ndGgpIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBudWxsO1xuICAgIHJlc3VsdC5wYXRoID0gbnVsbDtcbiAgfSBlbHNlIHtcbiAgICByZXN1bHQucGF0aG5hbWUgPSBzcmNQYXRoLmpvaW4oJy8nKTtcbiAgfVxuXG4gIC8vdG8gc3VwcG9ydCByZXF1ZXN0Lmh0dHBcbiAgaWYgKCFpc051bGwocmVzdWx0LnBhdGhuYW1lKSB8fCAhaXNOdWxsKHJlc3VsdC5zZWFyY2gpKSB7XG4gICAgcmVzdWx0LnBhdGggPSAocmVzdWx0LnBhdGhuYW1lID8gcmVzdWx0LnBhdGhuYW1lIDogJycpICtcbiAgICAgICAgICAgICAgICAgIChyZXN1bHQuc2VhcmNoID8gcmVzdWx0LnNlYXJjaCA6ICcnKTtcbiAgfVxuICByZXN1bHQuYXV0aCA9IHJlbGF0aXZlLmF1dGggfHwgcmVzdWx0LmF1dGg7XG4gIHJlc3VsdC5zbGFzaGVzID0gcmVzdWx0LnNsYXNoZXMgfHwgcmVsYXRpdmUuc2xhc2hlcztcbiAgcmVzdWx0LmhyZWYgPSByZXN1bHQuZm9ybWF0KCk7XG4gIHJldHVybiByZXN1bHQ7XG59O1xuXG5VcmwucHJvdG90eXBlLnBhcnNlSG9zdCA9IGZ1bmN0aW9uKCkge1xuICB2YXIgaG9zdCA9IHRoaXMuaG9zdDtcbiAgdmFyIHBvcnQgPSBwb3J0UGF0dGVybi5leGVjKGhvc3QpO1xuICBpZiAocG9ydCkge1xuICAgIHBvcnQgPSBwb3J0WzBdO1xuICAgIGlmIChwb3J0ICE9PSAnOicpIHtcbiAgICAgIHRoaXMucG9ydCA9IHBvcnQuc3Vic3RyKDEpO1xuICAgIH1cbiAgICBob3N0ID0gaG9zdC5zdWJzdHIoMCwgaG9zdC5sZW5ndGggLSBwb3J0Lmxlbmd0aCk7XG4gIH1cbiAgaWYgKGhvc3QpIHRoaXMuaG9zdG5hbWUgPSBob3N0O1xufTtcblxuZnVuY3Rpb24gaXNTdHJpbmcoYXJnKSB7XG4gIHJldHVybiB0eXBlb2YgYXJnID09PSBcInN0cmluZ1wiO1xufVxuXG5mdW5jdGlvbiBpc09iamVjdChhcmcpIHtcbiAgcmV0dXJuIHR5cGVvZiBhcmcgPT09ICdvYmplY3QnICYmIGFyZyAhPT0gbnVsbDtcbn1cblxuZnVuY3Rpb24gaXNOdWxsKGFyZykge1xuICByZXR1cm4gYXJnID09PSBudWxsO1xufVxuZnVuY3Rpb24gaXNOdWxsT3JVbmRlZmluZWQoYXJnKSB7XG4gIHJldHVybiAgYXJnID09IG51bGw7XG59XG4iLCIvKiEgaHR0cHM6Ly9tdGhzLmJlL3B1bnljb2RlIHYxLjQuMSBieSBAbWF0aGlhcyAqL1xuOyhmdW5jdGlvbihyb290KSB7XG5cblx0LyoqIERldGVjdCBmcmVlIHZhcmlhYmxlcyAqL1xuXHR2YXIgZnJlZUV4cG9ydHMgPSB0eXBlb2YgZXhwb3J0cyA9PSAnb2JqZWN0JyAmJiBleHBvcnRzICYmXG5cdFx0IWV4cG9ydHMubm9kZVR5cGUgJiYgZXhwb3J0cztcblx0dmFyIGZyZWVNb2R1bGUgPSB0eXBlb2YgbW9kdWxlID09ICdvYmplY3QnICYmIG1vZHVsZSAmJlxuXHRcdCFtb2R1bGUubm9kZVR5cGUgJiYgbW9kdWxlO1xuXHR2YXIgZnJlZUdsb2JhbCA9IHR5cGVvZiBnbG9iYWwgPT0gJ29iamVjdCcgJiYgZ2xvYmFsO1xuXHRpZiAoXG5cdFx0ZnJlZUdsb2JhbC5nbG9iYWwgPT09IGZyZWVHbG9iYWwgfHxcblx0XHRmcmVlR2xvYmFsLndpbmRvdyA9PT0gZnJlZUdsb2JhbCB8fFxuXHRcdGZyZWVHbG9iYWwuc2VsZiA9PT0gZnJlZUdsb2JhbFxuXHQpIHtcblx0XHRyb290ID0gZnJlZUdsb2JhbDtcblx0fVxuXG5cdC8qKlxuXHQgKiBUaGUgYHB1bnljb2RlYCBvYmplY3QuXG5cdCAqIEBuYW1lIHB1bnljb2RlXG5cdCAqIEB0eXBlIE9iamVjdFxuXHQgKi9cblx0dmFyIHB1bnljb2RlLFxuXG5cdC8qKiBIaWdoZXN0IHBvc2l0aXZlIHNpZ25lZCAzMi1iaXQgZmxvYXQgdmFsdWUgKi9cblx0bWF4SW50ID0gMjE0NzQ4MzY0NywgLy8gYWthLiAweDdGRkZGRkZGIG9yIDJeMzEtMVxuXG5cdC8qKiBCb290c3RyaW5nIHBhcmFtZXRlcnMgKi9cblx0YmFzZSA9IDM2LFxuXHR0TWluID0gMSxcblx0dE1heCA9IDI2LFxuXHRza2V3ID0gMzgsXG5cdGRhbXAgPSA3MDAsXG5cdGluaXRpYWxCaWFzID0gNzIsXG5cdGluaXRpYWxOID0gMTI4LCAvLyAweDgwXG5cdGRlbGltaXRlciA9ICctJywgLy8gJ1xceDJEJ1xuXG5cdC8qKiBSZWd1bGFyIGV4cHJlc3Npb25zICovXG5cdHJlZ2V4UHVueWNvZGUgPSAvXnhuLS0vLFxuXHRyZWdleE5vbkFTQ0lJID0gL1teXFx4MjAtXFx4N0VdLywgLy8gdW5wcmludGFibGUgQVNDSUkgY2hhcnMgKyBub24tQVNDSUkgY2hhcnNcblx0cmVnZXhTZXBhcmF0b3JzID0gL1tcXHgyRVxcdTMwMDJcXHVGRjBFXFx1RkY2MV0vZywgLy8gUkZDIDM0OTAgc2VwYXJhdG9yc1xuXG5cdC8qKiBFcnJvciBtZXNzYWdlcyAqL1xuXHRlcnJvcnMgPSB7XG5cdFx0J292ZXJmbG93JzogJ092ZXJmbG93OiBpbnB1dCBuZWVkcyB3aWRlciBpbnRlZ2VycyB0byBwcm9jZXNzJyxcblx0XHQnbm90LWJhc2ljJzogJ0lsbGVnYWwgaW5wdXQgPj0gMHg4MCAobm90IGEgYmFzaWMgY29kZSBwb2ludCknLFxuXHRcdCdpbnZhbGlkLWlucHV0JzogJ0ludmFsaWQgaW5wdXQnXG5cdH0sXG5cblx0LyoqIENvbnZlbmllbmNlIHNob3J0Y3V0cyAqL1xuXHRiYXNlTWludXNUTWluID0gYmFzZSAtIHRNaW4sXG5cdGZsb29yID0gTWF0aC5mbG9vcixcblx0c3RyaW5nRnJvbUNoYXJDb2RlID0gU3RyaW5nLmZyb21DaGFyQ29kZSxcblxuXHQvKiogVGVtcG9yYXJ5IHZhcmlhYmxlICovXG5cdGtleTtcblxuXHQvKi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKi9cblxuXHQvKipcblx0ICogQSBnZW5lcmljIGVycm9yIHV0aWxpdHkgZnVuY3Rpb24uXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSB0eXBlIFRoZSBlcnJvciB0eXBlLlxuXHQgKiBAcmV0dXJucyB7RXJyb3J9IFRocm93cyBhIGBSYW5nZUVycm9yYCB3aXRoIHRoZSBhcHBsaWNhYmxlIGVycm9yIG1lc3NhZ2UuXG5cdCAqL1xuXHRmdW5jdGlvbiBlcnJvcih0eXBlKSB7XG5cdFx0dGhyb3cgbmV3IFJhbmdlRXJyb3IoZXJyb3JzW3R5cGVdKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBBIGdlbmVyaWMgYEFycmF5I21hcGAgdXRpbGl0eSBmdW5jdGlvbi5cblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtBcnJheX0gYXJyYXkgVGhlIGFycmF5IHRvIGl0ZXJhdGUgb3Zlci5cblx0ICogQHBhcmFtIHtGdW5jdGlvbn0gY2FsbGJhY2sgVGhlIGZ1bmN0aW9uIHRoYXQgZ2V0cyBjYWxsZWQgZm9yIGV2ZXJ5IGFycmF5XG5cdCAqIGl0ZW0uXG5cdCAqIEByZXR1cm5zIHtBcnJheX0gQSBuZXcgYXJyYXkgb2YgdmFsdWVzIHJldHVybmVkIGJ5IHRoZSBjYWxsYmFjayBmdW5jdGlvbi5cblx0ICovXG5cdGZ1bmN0aW9uIG1hcChhcnJheSwgZm4pIHtcblx0XHR2YXIgbGVuZ3RoID0gYXJyYXkubGVuZ3RoO1xuXHRcdHZhciByZXN1bHQgPSBbXTtcblx0XHR3aGlsZSAobGVuZ3RoLS0pIHtcblx0XHRcdHJlc3VsdFtsZW5ndGhdID0gZm4oYXJyYXlbbGVuZ3RoXSk7XG5cdFx0fVxuXHRcdHJldHVybiByZXN1bHQ7XG5cdH1cblxuXHQvKipcblx0ICogQSBzaW1wbGUgYEFycmF5I21hcGAtbGlrZSB3cmFwcGVyIHRvIHdvcmsgd2l0aCBkb21haW4gbmFtZSBzdHJpbmdzIG9yIGVtYWlsXG5cdCAqIGFkZHJlc3Nlcy5cblx0ICogQHByaXZhdGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGRvbWFpbiBUaGUgZG9tYWluIG5hbWUgb3IgZW1haWwgYWRkcmVzcy5cblx0ICogQHBhcmFtIHtGdW5jdGlvbn0gY2FsbGJhY2sgVGhlIGZ1bmN0aW9uIHRoYXQgZ2V0cyBjYWxsZWQgZm9yIGV2ZXJ5XG5cdCAqIGNoYXJhY3Rlci5cblx0ICogQHJldHVybnMge0FycmF5fSBBIG5ldyBzdHJpbmcgb2YgY2hhcmFjdGVycyByZXR1cm5lZCBieSB0aGUgY2FsbGJhY2tcblx0ICogZnVuY3Rpb24uXG5cdCAqL1xuXHRmdW5jdGlvbiBtYXBEb21haW4oc3RyaW5nLCBmbikge1xuXHRcdHZhciBwYXJ0cyA9IHN0cmluZy5zcGxpdCgnQCcpO1xuXHRcdHZhciByZXN1bHQgPSAnJztcblx0XHRpZiAocGFydHMubGVuZ3RoID4gMSkge1xuXHRcdFx0Ly8gSW4gZW1haWwgYWRkcmVzc2VzLCBvbmx5IHRoZSBkb21haW4gbmFtZSBzaG91bGQgYmUgcHVueWNvZGVkLiBMZWF2ZVxuXHRcdFx0Ly8gdGhlIGxvY2FsIHBhcnQgKGkuZS4gZXZlcnl0aGluZyB1cCB0byBgQGApIGludGFjdC5cblx0XHRcdHJlc3VsdCA9IHBhcnRzWzBdICsgJ0AnO1xuXHRcdFx0c3RyaW5nID0gcGFydHNbMV07XG5cdFx0fVxuXHRcdC8vIEF2b2lkIGBzcGxpdChyZWdleClgIGZvciBJRTggY29tcGF0aWJpbGl0eS4gU2VlICMxNy5cblx0XHRzdHJpbmcgPSBzdHJpbmcucmVwbGFjZShyZWdleFNlcGFyYXRvcnMsICdcXHgyRScpO1xuXHRcdHZhciBsYWJlbHMgPSBzdHJpbmcuc3BsaXQoJy4nKTtcblx0XHR2YXIgZW5jb2RlZCA9IG1hcChsYWJlbHMsIGZuKS5qb2luKCcuJyk7XG5cdFx0cmV0dXJuIHJlc3VsdCArIGVuY29kZWQ7XG5cdH1cblxuXHQvKipcblx0ICogQ3JlYXRlcyBhbiBhcnJheSBjb250YWluaW5nIHRoZSBudW1lcmljIGNvZGUgcG9pbnRzIG9mIGVhY2ggVW5pY29kZVxuXHQgKiBjaGFyYWN0ZXIgaW4gdGhlIHN0cmluZy4gV2hpbGUgSmF2YVNjcmlwdCB1c2VzIFVDUy0yIGludGVybmFsbHksXG5cdCAqIHRoaXMgZnVuY3Rpb24gd2lsbCBjb252ZXJ0IGEgcGFpciBvZiBzdXJyb2dhdGUgaGFsdmVzIChlYWNoIG9mIHdoaWNoXG5cdCAqIFVDUy0yIGV4cG9zZXMgYXMgc2VwYXJhdGUgY2hhcmFjdGVycykgaW50byBhIHNpbmdsZSBjb2RlIHBvaW50LFxuXHQgKiBtYXRjaGluZyBVVEYtMTYuXG5cdCAqIEBzZWUgYHB1bnljb2RlLnVjczIuZW5jb2RlYFxuXHQgKiBAc2VlIDxodHRwczovL21hdGhpYXNieW5lbnMuYmUvbm90ZXMvamF2YXNjcmlwdC1lbmNvZGluZz5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlLnVjczJcblx0ICogQG5hbWUgZGVjb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBzdHJpbmcgVGhlIFVuaWNvZGUgaW5wdXQgc3RyaW5nIChVQ1MtMikuXG5cdCAqIEByZXR1cm5zIHtBcnJheX0gVGhlIG5ldyBhcnJheSBvZiBjb2RlIHBvaW50cy5cblx0ICovXG5cdGZ1bmN0aW9uIHVjczJkZWNvZGUoc3RyaW5nKSB7XG5cdFx0dmFyIG91dHB1dCA9IFtdLFxuXHRcdCAgICBjb3VudGVyID0gMCxcblx0XHQgICAgbGVuZ3RoID0gc3RyaW5nLmxlbmd0aCxcblx0XHQgICAgdmFsdWUsXG5cdFx0ICAgIGV4dHJhO1xuXHRcdHdoaWxlIChjb3VudGVyIDwgbGVuZ3RoKSB7XG5cdFx0XHR2YWx1ZSA9IHN0cmluZy5jaGFyQ29kZUF0KGNvdW50ZXIrKyk7XG5cdFx0XHRpZiAodmFsdWUgPj0gMHhEODAwICYmIHZhbHVlIDw9IDB4REJGRiAmJiBjb3VudGVyIDwgbGVuZ3RoKSB7XG5cdFx0XHRcdC8vIGhpZ2ggc3Vycm9nYXRlLCBhbmQgdGhlcmUgaXMgYSBuZXh0IGNoYXJhY3RlclxuXHRcdFx0XHRleHRyYSA9IHN0cmluZy5jaGFyQ29kZUF0KGNvdW50ZXIrKyk7XG5cdFx0XHRcdGlmICgoZXh0cmEgJiAweEZDMDApID09IDB4REMwMCkgeyAvLyBsb3cgc3Vycm9nYXRlXG5cdFx0XHRcdFx0b3V0cHV0LnB1c2goKCh2YWx1ZSAmIDB4M0ZGKSA8PCAxMCkgKyAoZXh0cmEgJiAweDNGRikgKyAweDEwMDAwKTtcblx0XHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0XHQvLyB1bm1hdGNoZWQgc3Vycm9nYXRlOyBvbmx5IGFwcGVuZCB0aGlzIGNvZGUgdW5pdCwgaW4gY2FzZSB0aGUgbmV4dFxuXHRcdFx0XHRcdC8vIGNvZGUgdW5pdCBpcyB0aGUgaGlnaCBzdXJyb2dhdGUgb2YgYSBzdXJyb2dhdGUgcGFpclxuXHRcdFx0XHRcdG91dHB1dC5wdXNoKHZhbHVlKTtcblx0XHRcdFx0XHRjb3VudGVyLS07XG5cdFx0XHRcdH1cblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdG91dHB1dC5wdXNoKHZhbHVlKTtcblx0XHRcdH1cblx0XHR9XG5cdFx0cmV0dXJuIG91dHB1dDtcblx0fVxuXG5cdC8qKlxuXHQgKiBDcmVhdGVzIGEgc3RyaW5nIGJhc2VkIG9uIGFuIGFycmF5IG9mIG51bWVyaWMgY29kZSBwb2ludHMuXG5cdCAqIEBzZWUgYHB1bnljb2RlLnVjczIuZGVjb2RlYFxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGUudWNzMlxuXHQgKiBAbmFtZSBlbmNvZGVcblx0ICogQHBhcmFtIHtBcnJheX0gY29kZVBvaW50cyBUaGUgYXJyYXkgb2YgbnVtZXJpYyBjb2RlIHBvaW50cy5cblx0ICogQHJldHVybnMge1N0cmluZ30gVGhlIG5ldyBVbmljb2RlIHN0cmluZyAoVUNTLTIpLlxuXHQgKi9cblx0ZnVuY3Rpb24gdWNzMmVuY29kZShhcnJheSkge1xuXHRcdHJldHVybiBtYXAoYXJyYXksIGZ1bmN0aW9uKHZhbHVlKSB7XG5cdFx0XHR2YXIgb3V0cHV0ID0gJyc7XG5cdFx0XHRpZiAodmFsdWUgPiAweEZGRkYpIHtcblx0XHRcdFx0dmFsdWUgLT0gMHgxMDAwMDtcblx0XHRcdFx0b3V0cHV0ICs9IHN0cmluZ0Zyb21DaGFyQ29kZSh2YWx1ZSA+Pj4gMTAgJiAweDNGRiB8IDB4RDgwMCk7XG5cdFx0XHRcdHZhbHVlID0gMHhEQzAwIHwgdmFsdWUgJiAweDNGRjtcblx0XHRcdH1cblx0XHRcdG91dHB1dCArPSBzdHJpbmdGcm9tQ2hhckNvZGUodmFsdWUpO1xuXHRcdFx0cmV0dXJuIG91dHB1dDtcblx0XHR9KS5qb2luKCcnKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIGJhc2ljIGNvZGUgcG9pbnQgaW50byBhIGRpZ2l0L2ludGVnZXIuXG5cdCAqIEBzZWUgYGRpZ2l0VG9CYXNpYygpYFxuXHQgKiBAcHJpdmF0ZVxuXHQgKiBAcGFyYW0ge051bWJlcn0gY29kZVBvaW50IFRoZSBiYXNpYyBudW1lcmljIGNvZGUgcG9pbnQgdmFsdWUuXG5cdCAqIEByZXR1cm5zIHtOdW1iZXJ9IFRoZSBudW1lcmljIHZhbHVlIG9mIGEgYmFzaWMgY29kZSBwb2ludCAoZm9yIHVzZSBpblxuXHQgKiByZXByZXNlbnRpbmcgaW50ZWdlcnMpIGluIHRoZSByYW5nZSBgMGAgdG8gYGJhc2UgLSAxYCwgb3IgYGJhc2VgIGlmXG5cdCAqIHRoZSBjb2RlIHBvaW50IGRvZXMgbm90IHJlcHJlc2VudCBhIHZhbHVlLlxuXHQgKi9cblx0ZnVuY3Rpb24gYmFzaWNUb0RpZ2l0KGNvZGVQb2ludCkge1xuXHRcdGlmIChjb2RlUG9pbnQgLSA0OCA8IDEwKSB7XG5cdFx0XHRyZXR1cm4gY29kZVBvaW50IC0gMjI7XG5cdFx0fVxuXHRcdGlmIChjb2RlUG9pbnQgLSA2NSA8IDI2KSB7XG5cdFx0XHRyZXR1cm4gY29kZVBvaW50IC0gNjU7XG5cdFx0fVxuXHRcdGlmIChjb2RlUG9pbnQgLSA5NyA8IDI2KSB7XG5cdFx0XHRyZXR1cm4gY29kZVBvaW50IC0gOTc7XG5cdFx0fVxuXHRcdHJldHVybiBiYXNlO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgZGlnaXQvaW50ZWdlciBpbnRvIGEgYmFzaWMgY29kZSBwb2ludC5cblx0ICogQHNlZSBgYmFzaWNUb0RpZ2l0KClgXG5cdCAqIEBwcml2YXRlXG5cdCAqIEBwYXJhbSB7TnVtYmVyfSBkaWdpdCBUaGUgbnVtZXJpYyB2YWx1ZSBvZiBhIGJhc2ljIGNvZGUgcG9pbnQuXG5cdCAqIEByZXR1cm5zIHtOdW1iZXJ9IFRoZSBiYXNpYyBjb2RlIHBvaW50IHdob3NlIHZhbHVlICh3aGVuIHVzZWQgZm9yXG5cdCAqIHJlcHJlc2VudGluZyBpbnRlZ2VycykgaXMgYGRpZ2l0YCwgd2hpY2ggbmVlZHMgdG8gYmUgaW4gdGhlIHJhbmdlXG5cdCAqIGAwYCB0byBgYmFzZSAtIDFgLiBJZiBgZmxhZ2AgaXMgbm9uLXplcm8sIHRoZSB1cHBlcmNhc2UgZm9ybSBpc1xuXHQgKiB1c2VkOyBlbHNlLCB0aGUgbG93ZXJjYXNlIGZvcm0gaXMgdXNlZC4gVGhlIGJlaGF2aW9yIGlzIHVuZGVmaW5lZFxuXHQgKiBpZiBgZmxhZ2AgaXMgbm9uLXplcm8gYW5kIGBkaWdpdGAgaGFzIG5vIHVwcGVyY2FzZSBmb3JtLlxuXHQgKi9cblx0ZnVuY3Rpb24gZGlnaXRUb0Jhc2ljKGRpZ2l0LCBmbGFnKSB7XG5cdFx0Ly8gIDAuLjI1IG1hcCB0byBBU0NJSSBhLi56IG9yIEEuLlpcblx0XHQvLyAyNi4uMzUgbWFwIHRvIEFTQ0lJIDAuLjlcblx0XHRyZXR1cm4gZGlnaXQgKyAyMiArIDc1ICogKGRpZ2l0IDwgMjYpIC0gKChmbGFnICE9IDApIDw8IDUpO1xuXHR9XG5cblx0LyoqXG5cdCAqIEJpYXMgYWRhcHRhdGlvbiBmdW5jdGlvbiBhcyBwZXIgc2VjdGlvbiAzLjQgb2YgUkZDIDM0OTIuXG5cdCAqIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmMzNDkyI3NlY3Rpb24tMy40XG5cdCAqIEBwcml2YXRlXG5cdCAqL1xuXHRmdW5jdGlvbiBhZGFwdChkZWx0YSwgbnVtUG9pbnRzLCBmaXJzdFRpbWUpIHtcblx0XHR2YXIgayA9IDA7XG5cdFx0ZGVsdGEgPSBmaXJzdFRpbWUgPyBmbG9vcihkZWx0YSAvIGRhbXApIDogZGVsdGEgPj4gMTtcblx0XHRkZWx0YSArPSBmbG9vcihkZWx0YSAvIG51bVBvaW50cyk7XG5cdFx0Zm9yICgvKiBubyBpbml0aWFsaXphdGlvbiAqLzsgZGVsdGEgPiBiYXNlTWludXNUTWluICogdE1heCA+PiAxOyBrICs9IGJhc2UpIHtcblx0XHRcdGRlbHRhID0gZmxvb3IoZGVsdGEgLyBiYXNlTWludXNUTWluKTtcblx0XHR9XG5cdFx0cmV0dXJuIGZsb29yKGsgKyAoYmFzZU1pbnVzVE1pbiArIDEpICogZGVsdGEgLyAoZGVsdGEgKyBza2V3KSk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBQdW55Y29kZSBzdHJpbmcgb2YgQVNDSUktb25seSBzeW1ib2xzIHRvIGEgc3RyaW5nIG9mIFVuaWNvZGVcblx0ICogc3ltYm9scy5cblx0ICogQG1lbWJlck9mIHB1bnljb2RlXG5cdCAqIEBwYXJhbSB7U3RyaW5nfSBpbnB1dCBUaGUgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scy5cblx0ICogQHJldHVybnMge1N0cmluZ30gVGhlIHJlc3VsdGluZyBzdHJpbmcgb2YgVW5pY29kZSBzeW1ib2xzLlxuXHQgKi9cblx0ZnVuY3Rpb24gZGVjb2RlKGlucHV0KSB7XG5cdFx0Ly8gRG9uJ3QgdXNlIFVDUy0yXG5cdFx0dmFyIG91dHB1dCA9IFtdLFxuXHRcdCAgICBpbnB1dExlbmd0aCA9IGlucHV0Lmxlbmd0aCxcblx0XHQgICAgb3V0LFxuXHRcdCAgICBpID0gMCxcblx0XHQgICAgbiA9IGluaXRpYWxOLFxuXHRcdCAgICBiaWFzID0gaW5pdGlhbEJpYXMsXG5cdFx0ICAgIGJhc2ljLFxuXHRcdCAgICBqLFxuXHRcdCAgICBpbmRleCxcblx0XHQgICAgb2xkaSxcblx0XHQgICAgdyxcblx0XHQgICAgayxcblx0XHQgICAgZGlnaXQsXG5cdFx0ICAgIHQsXG5cdFx0ICAgIC8qKiBDYWNoZWQgY2FsY3VsYXRpb24gcmVzdWx0cyAqL1xuXHRcdCAgICBiYXNlTWludXNUO1xuXG5cdFx0Ly8gSGFuZGxlIHRoZSBiYXNpYyBjb2RlIHBvaW50czogbGV0IGBiYXNpY2AgYmUgdGhlIG51bWJlciBvZiBpbnB1dCBjb2RlXG5cdFx0Ly8gcG9pbnRzIGJlZm9yZSB0aGUgbGFzdCBkZWxpbWl0ZXIsIG9yIGAwYCBpZiB0aGVyZSBpcyBub25lLCB0aGVuIGNvcHlcblx0XHQvLyB0aGUgZmlyc3QgYmFzaWMgY29kZSBwb2ludHMgdG8gdGhlIG91dHB1dC5cblxuXHRcdGJhc2ljID0gaW5wdXQubGFzdEluZGV4T2YoZGVsaW1pdGVyKTtcblx0XHRpZiAoYmFzaWMgPCAwKSB7XG5cdFx0XHRiYXNpYyA9IDA7XG5cdFx0fVxuXG5cdFx0Zm9yIChqID0gMDsgaiA8IGJhc2ljOyArK2opIHtcblx0XHRcdC8vIGlmIGl0J3Mgbm90IGEgYmFzaWMgY29kZSBwb2ludFxuXHRcdFx0aWYgKGlucHV0LmNoYXJDb2RlQXQoaikgPj0gMHg4MCkge1xuXHRcdFx0XHRlcnJvcignbm90LWJhc2ljJyk7XG5cdFx0XHR9XG5cdFx0XHRvdXRwdXQucHVzaChpbnB1dC5jaGFyQ29kZUF0KGopKTtcblx0XHR9XG5cblx0XHQvLyBNYWluIGRlY29kaW5nIGxvb3A6IHN0YXJ0IGp1c3QgYWZ0ZXIgdGhlIGxhc3QgZGVsaW1pdGVyIGlmIGFueSBiYXNpYyBjb2RlXG5cdFx0Ly8gcG9pbnRzIHdlcmUgY29waWVkOyBzdGFydCBhdCB0aGUgYmVnaW5uaW5nIG90aGVyd2lzZS5cblxuXHRcdGZvciAoaW5kZXggPSBiYXNpYyA+IDAgPyBiYXNpYyArIDEgOiAwOyBpbmRleCA8IGlucHV0TGVuZ3RoOyAvKiBubyBmaW5hbCBleHByZXNzaW9uICovKSB7XG5cblx0XHRcdC8vIGBpbmRleGAgaXMgdGhlIGluZGV4IG9mIHRoZSBuZXh0IGNoYXJhY3RlciB0byBiZSBjb25zdW1lZC5cblx0XHRcdC8vIERlY29kZSBhIGdlbmVyYWxpemVkIHZhcmlhYmxlLWxlbmd0aCBpbnRlZ2VyIGludG8gYGRlbHRhYCxcblx0XHRcdC8vIHdoaWNoIGdldHMgYWRkZWQgdG8gYGlgLiBUaGUgb3ZlcmZsb3cgY2hlY2tpbmcgaXMgZWFzaWVyXG5cdFx0XHQvLyBpZiB3ZSBpbmNyZWFzZSBgaWAgYXMgd2UgZ28sIHRoZW4gc3VidHJhY3Qgb2ZmIGl0cyBzdGFydGluZ1xuXHRcdFx0Ly8gdmFsdWUgYXQgdGhlIGVuZCB0byBvYnRhaW4gYGRlbHRhYC5cblx0XHRcdGZvciAob2xkaSA9IGksIHcgPSAxLCBrID0gYmFzZTsgLyogbm8gY29uZGl0aW9uICovOyBrICs9IGJhc2UpIHtcblxuXHRcdFx0XHRpZiAoaW5kZXggPj0gaW5wdXRMZW5ndGgpIHtcblx0XHRcdFx0XHRlcnJvcignaW52YWxpZC1pbnB1dCcpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0ZGlnaXQgPSBiYXNpY1RvRGlnaXQoaW5wdXQuY2hhckNvZGVBdChpbmRleCsrKSk7XG5cblx0XHRcdFx0aWYgKGRpZ2l0ID49IGJhc2UgfHwgZGlnaXQgPiBmbG9vcigobWF4SW50IC0gaSkgLyB3KSkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0aSArPSBkaWdpdCAqIHc7XG5cdFx0XHRcdHQgPSBrIDw9IGJpYXMgPyB0TWluIDogKGsgPj0gYmlhcyArIHRNYXggPyB0TWF4IDogayAtIGJpYXMpO1xuXG5cdFx0XHRcdGlmIChkaWdpdCA8IHQpIHtcblx0XHRcdFx0XHRicmVhaztcblx0XHRcdFx0fVxuXG5cdFx0XHRcdGJhc2VNaW51c1QgPSBiYXNlIC0gdDtcblx0XHRcdFx0aWYgKHcgPiBmbG9vcihtYXhJbnQgLyBiYXNlTWludXNUKSkge1xuXHRcdFx0XHRcdGVycm9yKCdvdmVyZmxvdycpO1xuXHRcdFx0XHR9XG5cblx0XHRcdFx0dyAqPSBiYXNlTWludXNUO1xuXG5cdFx0XHR9XG5cblx0XHRcdG91dCA9IG91dHB1dC5sZW5ndGggKyAxO1xuXHRcdFx0YmlhcyA9IGFkYXB0KGkgLSBvbGRpLCBvdXQsIG9sZGkgPT0gMCk7XG5cblx0XHRcdC8vIGBpYCB3YXMgc3VwcG9zZWQgdG8gd3JhcCBhcm91bmQgZnJvbSBgb3V0YCB0byBgMGAsXG5cdFx0XHQvLyBpbmNyZW1lbnRpbmcgYG5gIGVhY2ggdGltZSwgc28gd2UnbGwgZml4IHRoYXQgbm93OlxuXHRcdFx0aWYgKGZsb29yKGkgLyBvdXQpID4gbWF4SW50IC0gbikge1xuXHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdH1cblxuXHRcdFx0biArPSBmbG9vcihpIC8gb3V0KTtcblx0XHRcdGkgJT0gb3V0O1xuXG5cdFx0XHQvLyBJbnNlcnQgYG5gIGF0IHBvc2l0aW9uIGBpYCBvZiB0aGUgb3V0cHV0XG5cdFx0XHRvdXRwdXQuc3BsaWNlKGkrKywgMCwgbik7XG5cblx0XHR9XG5cblx0XHRyZXR1cm4gdWNzMmVuY29kZShvdXRwdXQpO1xuXHR9XG5cblx0LyoqXG5cdCAqIENvbnZlcnRzIGEgc3RyaW5nIG9mIFVuaWNvZGUgc3ltYm9scyAoZS5nLiBhIGRvbWFpbiBuYW1lIGxhYmVsKSB0byBhXG5cdCAqIFB1bnljb2RlIHN0cmluZyBvZiBBU0NJSS1vbmx5IHN5bWJvbHMuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIHN0cmluZyBvZiBVbmljb2RlIHN5bWJvbHMuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSByZXN1bHRpbmcgUHVueWNvZGUgc3RyaW5nIG9mIEFTQ0lJLW9ubHkgc3ltYm9scy5cblx0ICovXG5cdGZ1bmN0aW9uIGVuY29kZShpbnB1dCkge1xuXHRcdHZhciBuLFxuXHRcdCAgICBkZWx0YSxcblx0XHQgICAgaGFuZGxlZENQQ291bnQsXG5cdFx0ICAgIGJhc2ljTGVuZ3RoLFxuXHRcdCAgICBiaWFzLFxuXHRcdCAgICBqLFxuXHRcdCAgICBtLFxuXHRcdCAgICBxLFxuXHRcdCAgICBrLFxuXHRcdCAgICB0LFxuXHRcdCAgICBjdXJyZW50VmFsdWUsXG5cdFx0ICAgIG91dHB1dCA9IFtdLFxuXHRcdCAgICAvKiogYGlucHV0TGVuZ3RoYCB3aWxsIGhvbGQgdGhlIG51bWJlciBvZiBjb2RlIHBvaW50cyBpbiBgaW5wdXRgLiAqL1xuXHRcdCAgICBpbnB1dExlbmd0aCxcblx0XHQgICAgLyoqIENhY2hlZCBjYWxjdWxhdGlvbiByZXN1bHRzICovXG5cdFx0ICAgIGhhbmRsZWRDUENvdW50UGx1c09uZSxcblx0XHQgICAgYmFzZU1pbnVzVCxcblx0XHQgICAgcU1pbnVzVDtcblxuXHRcdC8vIENvbnZlcnQgdGhlIGlucHV0IGluIFVDUy0yIHRvIFVuaWNvZGVcblx0XHRpbnB1dCA9IHVjczJkZWNvZGUoaW5wdXQpO1xuXG5cdFx0Ly8gQ2FjaGUgdGhlIGxlbmd0aFxuXHRcdGlucHV0TGVuZ3RoID0gaW5wdXQubGVuZ3RoO1xuXG5cdFx0Ly8gSW5pdGlhbGl6ZSB0aGUgc3RhdGVcblx0XHRuID0gaW5pdGlhbE47XG5cdFx0ZGVsdGEgPSAwO1xuXHRcdGJpYXMgPSBpbml0aWFsQmlhcztcblxuXHRcdC8vIEhhbmRsZSB0aGUgYmFzaWMgY29kZSBwb2ludHNcblx0XHRmb3IgKGogPSAwOyBqIDwgaW5wdXRMZW5ndGg7ICsraikge1xuXHRcdFx0Y3VycmVudFZhbHVlID0gaW5wdXRbal07XG5cdFx0XHRpZiAoY3VycmVudFZhbHVlIDwgMHg4MCkge1xuXHRcdFx0XHRvdXRwdXQucHVzaChzdHJpbmdGcm9tQ2hhckNvZGUoY3VycmVudFZhbHVlKSk7XG5cdFx0XHR9XG5cdFx0fVxuXG5cdFx0aGFuZGxlZENQQ291bnQgPSBiYXNpY0xlbmd0aCA9IG91dHB1dC5sZW5ndGg7XG5cblx0XHQvLyBgaGFuZGxlZENQQ291bnRgIGlzIHRoZSBudW1iZXIgb2YgY29kZSBwb2ludHMgdGhhdCBoYXZlIGJlZW4gaGFuZGxlZDtcblx0XHQvLyBgYmFzaWNMZW5ndGhgIGlzIHRoZSBudW1iZXIgb2YgYmFzaWMgY29kZSBwb2ludHMuXG5cblx0XHQvLyBGaW5pc2ggdGhlIGJhc2ljIHN0cmluZyAtIGlmIGl0IGlzIG5vdCBlbXB0eSAtIHdpdGggYSBkZWxpbWl0ZXJcblx0XHRpZiAoYmFzaWNMZW5ndGgpIHtcblx0XHRcdG91dHB1dC5wdXNoKGRlbGltaXRlcik7XG5cdFx0fVxuXG5cdFx0Ly8gTWFpbiBlbmNvZGluZyBsb29wOlxuXHRcdHdoaWxlIChoYW5kbGVkQ1BDb3VudCA8IGlucHV0TGVuZ3RoKSB7XG5cblx0XHRcdC8vIEFsbCBub24tYmFzaWMgY29kZSBwb2ludHMgPCBuIGhhdmUgYmVlbiBoYW5kbGVkIGFscmVhZHkuIEZpbmQgdGhlIG5leHRcblx0XHRcdC8vIGxhcmdlciBvbmU6XG5cdFx0XHRmb3IgKG0gPSBtYXhJbnQsIGogPSAwOyBqIDwgaW5wdXRMZW5ndGg7ICsraikge1xuXHRcdFx0XHRjdXJyZW50VmFsdWUgPSBpbnB1dFtqXTtcblx0XHRcdFx0aWYgKGN1cnJlbnRWYWx1ZSA+PSBuICYmIGN1cnJlbnRWYWx1ZSA8IG0pIHtcblx0XHRcdFx0XHRtID0gY3VycmVudFZhbHVlO1xuXHRcdFx0XHR9XG5cdFx0XHR9XG5cblx0XHRcdC8vIEluY3JlYXNlIGBkZWx0YWAgZW5vdWdoIHRvIGFkdmFuY2UgdGhlIGRlY29kZXIncyA8bixpPiBzdGF0ZSB0byA8bSwwPixcblx0XHRcdC8vIGJ1dCBndWFyZCBhZ2FpbnN0IG92ZXJmbG93XG5cdFx0XHRoYW5kbGVkQ1BDb3VudFBsdXNPbmUgPSBoYW5kbGVkQ1BDb3VudCArIDE7XG5cdFx0XHRpZiAobSAtIG4gPiBmbG9vcigobWF4SW50IC0gZGVsdGEpIC8gaGFuZGxlZENQQ291bnRQbHVzT25lKSkge1xuXHRcdFx0XHRlcnJvcignb3ZlcmZsb3cnKTtcblx0XHRcdH1cblxuXHRcdFx0ZGVsdGEgKz0gKG0gLSBuKSAqIGhhbmRsZWRDUENvdW50UGx1c09uZTtcblx0XHRcdG4gPSBtO1xuXG5cdFx0XHRmb3IgKGogPSAwOyBqIDwgaW5wdXRMZW5ndGg7ICsraikge1xuXHRcdFx0XHRjdXJyZW50VmFsdWUgPSBpbnB1dFtqXTtcblxuXHRcdFx0XHRpZiAoY3VycmVudFZhbHVlIDwgbiAmJiArK2RlbHRhID4gbWF4SW50KSB7XG5cdFx0XHRcdFx0ZXJyb3IoJ292ZXJmbG93Jyk7XG5cdFx0XHRcdH1cblxuXHRcdFx0XHRpZiAoY3VycmVudFZhbHVlID09IG4pIHtcblx0XHRcdFx0XHQvLyBSZXByZXNlbnQgZGVsdGEgYXMgYSBnZW5lcmFsaXplZCB2YXJpYWJsZS1sZW5ndGggaW50ZWdlclxuXHRcdFx0XHRcdGZvciAocSA9IGRlbHRhLCBrID0gYmFzZTsgLyogbm8gY29uZGl0aW9uICovOyBrICs9IGJhc2UpIHtcblx0XHRcdFx0XHRcdHQgPSBrIDw9IGJpYXMgPyB0TWluIDogKGsgPj0gYmlhcyArIHRNYXggPyB0TWF4IDogayAtIGJpYXMpO1xuXHRcdFx0XHRcdFx0aWYgKHEgPCB0KSB7XG5cdFx0XHRcdFx0XHRcdGJyZWFrO1xuXHRcdFx0XHRcdFx0fVxuXHRcdFx0XHRcdFx0cU1pbnVzVCA9IHEgLSB0O1xuXHRcdFx0XHRcdFx0YmFzZU1pbnVzVCA9IGJhc2UgLSB0O1xuXHRcdFx0XHRcdFx0b3V0cHV0LnB1c2goXG5cdFx0XHRcdFx0XHRcdHN0cmluZ0Zyb21DaGFyQ29kZShkaWdpdFRvQmFzaWModCArIHFNaW51c1QgJSBiYXNlTWludXNULCAwKSlcblx0XHRcdFx0XHRcdCk7XG5cdFx0XHRcdFx0XHRxID0gZmxvb3IocU1pbnVzVCAvIGJhc2VNaW51c1QpO1xuXHRcdFx0XHRcdH1cblxuXHRcdFx0XHRcdG91dHB1dC5wdXNoKHN0cmluZ0Zyb21DaGFyQ29kZShkaWdpdFRvQmFzaWMocSwgMCkpKTtcblx0XHRcdFx0XHRiaWFzID0gYWRhcHQoZGVsdGEsIGhhbmRsZWRDUENvdW50UGx1c09uZSwgaGFuZGxlZENQQ291bnQgPT0gYmFzaWNMZW5ndGgpO1xuXHRcdFx0XHRcdGRlbHRhID0gMDtcblx0XHRcdFx0XHQrK2hhbmRsZWRDUENvdW50O1xuXHRcdFx0XHR9XG5cdFx0XHR9XG5cblx0XHRcdCsrZGVsdGE7XG5cdFx0XHQrK247XG5cblx0XHR9XG5cdFx0cmV0dXJuIG91dHB1dC5qb2luKCcnKTtcblx0fVxuXG5cdC8qKlxuXHQgKiBDb252ZXJ0cyBhIFB1bnljb2RlIHN0cmluZyByZXByZXNlbnRpbmcgYSBkb21haW4gbmFtZSBvciBhbiBlbWFpbCBhZGRyZXNzXG5cdCAqIHRvIFVuaWNvZGUuIE9ubHkgdGhlIFB1bnljb2RlZCBwYXJ0cyBvZiB0aGUgaW5wdXQgd2lsbCBiZSBjb252ZXJ0ZWQsIGkuZS5cblx0ICogaXQgZG9lc24ndCBtYXR0ZXIgaWYgeW91IGNhbGwgaXQgb24gYSBzdHJpbmcgdGhhdCBoYXMgYWxyZWFkeSBiZWVuXG5cdCAqIGNvbnZlcnRlZCB0byBVbmljb2RlLlxuXHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0ICogQHBhcmFtIHtTdHJpbmd9IGlucHV0IFRoZSBQdW55Y29kZWQgZG9tYWluIG5hbWUgb3IgZW1haWwgYWRkcmVzcyB0b1xuXHQgKiBjb252ZXJ0IHRvIFVuaWNvZGUuXG5cdCAqIEByZXR1cm5zIHtTdHJpbmd9IFRoZSBVbmljb2RlIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBnaXZlbiBQdW55Y29kZVxuXHQgKiBzdHJpbmcuXG5cdCAqL1xuXHRmdW5jdGlvbiB0b1VuaWNvZGUoaW5wdXQpIHtcblx0XHRyZXR1cm4gbWFwRG9tYWluKGlucHV0LCBmdW5jdGlvbihzdHJpbmcpIHtcblx0XHRcdHJldHVybiByZWdleFB1bnljb2RlLnRlc3Qoc3RyaW5nKVxuXHRcdFx0XHQ/IGRlY29kZShzdHJpbmcuc2xpY2UoNCkudG9Mb3dlckNhc2UoKSlcblx0XHRcdFx0OiBzdHJpbmc7XG5cdFx0fSk7XG5cdH1cblxuXHQvKipcblx0ICogQ29udmVydHMgYSBVbmljb2RlIHN0cmluZyByZXByZXNlbnRpbmcgYSBkb21haW4gbmFtZSBvciBhbiBlbWFpbCBhZGRyZXNzIHRvXG5cdCAqIFB1bnljb2RlLiBPbmx5IHRoZSBub24tQVNDSUkgcGFydHMgb2YgdGhlIGRvbWFpbiBuYW1lIHdpbGwgYmUgY29udmVydGVkLFxuXHQgKiBpLmUuIGl0IGRvZXNuJ3QgbWF0dGVyIGlmIHlvdSBjYWxsIGl0IHdpdGggYSBkb21haW4gdGhhdCdzIGFscmVhZHkgaW5cblx0ICogQVNDSUkuXG5cdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHQgKiBAcGFyYW0ge1N0cmluZ30gaW5wdXQgVGhlIGRvbWFpbiBuYW1lIG9yIGVtYWlsIGFkZHJlc3MgdG8gY29udmVydCwgYXMgYVxuXHQgKiBVbmljb2RlIHN0cmluZy5cblx0ICogQHJldHVybnMge1N0cmluZ30gVGhlIFB1bnljb2RlIHJlcHJlc2VudGF0aW9uIG9mIHRoZSBnaXZlbiBkb21haW4gbmFtZSBvclxuXHQgKiBlbWFpbCBhZGRyZXNzLlxuXHQgKi9cblx0ZnVuY3Rpb24gdG9BU0NJSShpbnB1dCkge1xuXHRcdHJldHVybiBtYXBEb21haW4oaW5wdXQsIGZ1bmN0aW9uKHN0cmluZykge1xuXHRcdFx0cmV0dXJuIHJlZ2V4Tm9uQVNDSUkudGVzdChzdHJpbmcpXG5cdFx0XHRcdD8gJ3huLS0nICsgZW5jb2RlKHN0cmluZylcblx0XHRcdFx0OiBzdHJpbmc7XG5cdFx0fSk7XG5cdH1cblxuXHQvKi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tKi9cblxuXHQvKiogRGVmaW5lIHRoZSBwdWJsaWMgQVBJICovXG5cdHB1bnljb2RlID0ge1xuXHRcdC8qKlxuXHRcdCAqIEEgc3RyaW5nIHJlcHJlc2VudGluZyB0aGUgY3VycmVudCBQdW55Y29kZS5qcyB2ZXJzaW9uIG51bWJlci5cblx0XHQgKiBAbWVtYmVyT2YgcHVueWNvZGVcblx0XHQgKiBAdHlwZSBTdHJpbmdcblx0XHQgKi9cblx0XHQndmVyc2lvbic6ICcxLjQuMScsXG5cdFx0LyoqXG5cdFx0ICogQW4gb2JqZWN0IG9mIG1ldGhvZHMgdG8gY29udmVydCBmcm9tIEphdmFTY3JpcHQncyBpbnRlcm5hbCBjaGFyYWN0ZXJcblx0XHQgKiByZXByZXNlbnRhdGlvbiAoVUNTLTIpIHRvIFVuaWNvZGUgY29kZSBwb2ludHMsIGFuZCBiYWNrLlxuXHRcdCAqIEBzZWUgPGh0dHBzOi8vbWF0aGlhc2J5bmVucy5iZS9ub3Rlcy9qYXZhc2NyaXB0LWVuY29kaW5nPlxuXHRcdCAqIEBtZW1iZXJPZiBwdW55Y29kZVxuXHRcdCAqIEB0eXBlIE9iamVjdFxuXHRcdCAqL1xuXHRcdCd1Y3MyJzoge1xuXHRcdFx0J2RlY29kZSc6IHVjczJkZWNvZGUsXG5cdFx0XHQnZW5jb2RlJzogdWNzMmVuY29kZVxuXHRcdH0sXG5cdFx0J2RlY29kZSc6IGRlY29kZSxcblx0XHQnZW5jb2RlJzogZW5jb2RlLFxuXHRcdCd0b0FTQ0lJJzogdG9BU0NJSSxcblx0XHQndG9Vbmljb2RlJzogdG9Vbmljb2RlXG5cdH07XG5cblx0LyoqIEV4cG9zZSBgcHVueWNvZGVgICovXG5cdC8vIFNvbWUgQU1EIGJ1aWxkIG9wdGltaXplcnMsIGxpa2Ugci5qcywgY2hlY2sgZm9yIHNwZWNpZmljIGNvbmRpdGlvbiBwYXR0ZXJuc1xuXHQvLyBsaWtlIHRoZSBmb2xsb3dpbmc6XG5cdGlmIChcblx0XHR0eXBlb2YgZGVmaW5lID09ICdmdW5jdGlvbicgJiZcblx0XHR0eXBlb2YgZGVmaW5lLmFtZCA9PSAnb2JqZWN0JyAmJlxuXHRcdGRlZmluZS5hbWRcblx0KSB7XG5cdFx0ZGVmaW5lKCdwdW55Y29kZScsIGZ1bmN0aW9uKCkge1xuXHRcdFx0cmV0dXJuIHB1bnljb2RlO1xuXHRcdH0pO1xuXHR9IGVsc2UgaWYgKGZyZWVFeHBvcnRzICYmIGZyZWVNb2R1bGUpIHtcblx0XHRpZiAobW9kdWxlLmV4cG9ydHMgPT0gZnJlZUV4cG9ydHMpIHtcblx0XHRcdC8vIGluIE5vZGUuanMsIGlvLmpzLCBvciBSaW5nb0pTIHYwLjguMCtcblx0XHRcdGZyZWVNb2R1bGUuZXhwb3J0cyA9IHB1bnljb2RlO1xuXHRcdH0gZWxzZSB7XG5cdFx0XHQvLyBpbiBOYXJ3aGFsIG9yIFJpbmdvSlMgdjAuNy4wLVxuXHRcdFx0Zm9yIChrZXkgaW4gcHVueWNvZGUpIHtcblx0XHRcdFx0cHVueWNvZGUuaGFzT3duUHJvcGVydHkoa2V5KSAmJiAoZnJlZUV4cG9ydHNba2V5XSA9IHB1bnljb2RlW2tleV0pO1xuXHRcdFx0fVxuXHRcdH1cblx0fSBlbHNlIHtcblx0XHQvLyBpbiBSaGlubyBvciBhIHdlYiBicm93c2VyXG5cdFx0cm9vdC5wdW55Y29kZSA9IHB1bnljb2RlO1xuXHR9XG5cbn0odGhpcykpO1xuIiwiLypcbiAqIHF1YW50aXplLmpzIENvcHlyaWdodCAyMDA4IE5pY2sgUmFiaW5vd2l0elxuICogUG9ydGVkIHRvIG5vZGUuanMgYnkgT2xpdmllciBMZXNuaWNraVxuICogTGljZW5zZWQgdW5kZXIgdGhlIE1JVCBsaWNlbnNlOiBodHRwOi8vd3d3Lm9wZW5zb3VyY2Uub3JnL2xpY2Vuc2VzL21pdC1saWNlbnNlLnBocFxuICovXG5cbi8vIGZpbGwgb3V0IGEgY291cGxlIHByb3RvdmlzIGRlcGVuZGVuY2llc1xuLypcbiAqIEJsb2NrIGJlbG93IGNvcGllZCBmcm9tIFByb3RvdmlzOiBodHRwOi8vbWJvc3RvY2suZ2l0aHViLmNvbS9wcm90b3Zpcy9cbiAqIENvcHlyaWdodCAyMDEwIFN0YW5mb3JkIFZpc3VhbGl6YXRpb24gR3JvdXBcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBCU0QgTGljZW5zZTogaHR0cDovL3d3dy5vcGVuc291cmNlLm9yZy9saWNlbnNlcy9ic2QtbGljZW5zZS5waHBcbiAqL1xuaWYgKCFwdikge1xuICAgIHZhciBwdiA9IHtcbiAgICAgICAgbWFwOiBmdW5jdGlvbihhcnJheSwgZikge1xuICAgICAgICAgICAgdmFyIG8gPSB7fTtcbiAgICAgICAgICAgIHJldHVybiBmID8gYXJyYXkubWFwKGZ1bmN0aW9uKGQsIGkpIHtcbiAgICAgICAgICAgICAgICBvLmluZGV4ID0gaTtcbiAgICAgICAgICAgICAgICByZXR1cm4gZi5jYWxsKG8sIGQpO1xuICAgICAgICAgICAgfSkgOiBhcnJheS5zbGljZSgpO1xuICAgICAgICB9LFxuICAgICAgICBuYXR1cmFsT3JkZXI6IGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiAoYSA8IGIpID8gLTEgOiAoKGEgPiBiKSA/IDEgOiAwKTtcbiAgICAgICAgfSxcbiAgICAgICAgc3VtOiBmdW5jdGlvbihhcnJheSwgZikge1xuICAgICAgICAgICAgdmFyIG8gPSB7fTtcbiAgICAgICAgICAgIHJldHVybiBhcnJheS5yZWR1Y2UoZiA/IGZ1bmN0aW9uKHAsIGQsIGkpIHtcbiAgICAgICAgICAgICAgICBvLmluZGV4ID0gaTtcbiAgICAgICAgICAgICAgICByZXR1cm4gcCArIGYuY2FsbChvLCBkKTtcbiAgICAgICAgICAgIH0gOiBmdW5jdGlvbihwLCBkKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIHAgKyBkO1xuICAgICAgICAgICAgfSwgMCk7XG4gICAgICAgIH0sXG4gICAgICAgIG1heDogZnVuY3Rpb24oYXJyYXksIGYpIHtcbiAgICAgICAgICAgIHJldHVybiBNYXRoLm1heC5hcHBseShudWxsLCBmID8gcHYubWFwKGFycmF5LCBmKSA6IGFycmF5KTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLyoqXG4gKiBCYXNpYyBKYXZhc2NyaXB0IHBvcnQgb2YgdGhlIE1NQ1EgKG1vZGlmaWVkIG1lZGlhbiBjdXQgcXVhbnRpemF0aW9uKVxuICogYWxnb3JpdGhtIGZyb20gdGhlIExlcHRvbmljYSBsaWJyYXJ5IChodHRwOi8vd3d3LmxlcHRvbmljYS5jb20vKS5cbiAqIFJldHVybnMgYSBjb2xvciBtYXAgeW91IGNhbiB1c2UgdG8gbWFwIG9yaWdpbmFsIHBpeGVscyB0byB0aGUgcmVkdWNlZFxuICogcGFsZXR0ZS4gU3RpbGwgYSB3b3JrIGluIHByb2dyZXNzLlxuICogXG4gKiBAYXV0aG9yIE5pY2sgUmFiaW5vd2l0elxuICogQGV4YW1wbGVcbiBcbi8vIGFycmF5IG9mIHBpeGVscyBhcyBbUixHLEJdIGFycmF5c1xudmFyIG15UGl4ZWxzID0gW1sxOTAsMTk3LDE5MF0sIFsyMDIsMjA0LDIwMF0sIFsyMDcsMjE0LDIxMF0sIFsyMTEsMjE0LDIxMV0sIFsyMDUsMjA3LDIwN11cbiAgICAgICAgICAgICAgICAvLyBldGNcbiAgICAgICAgICAgICAgICBdO1xudmFyIG1heENvbG9ycyA9IDQ7XG4gXG52YXIgY21hcCA9IE1NQ1EucXVhbnRpemUobXlQaXhlbHMsIG1heENvbG9ycyk7XG52YXIgbmV3UGFsZXR0ZSA9IGNtYXAucGFsZXR0ZSgpO1xudmFyIG5ld1BpeGVscyA9IG15UGl4ZWxzLm1hcChmdW5jdGlvbihwKSB7IFxuICAgIHJldHVybiBjbWFwLm1hcChwKTsgXG59KTtcbiBcbiAqL1xudmFyIE1NQ1EgPSAoZnVuY3Rpb24oKSB7XG4gICAgLy8gcHJpdmF0ZSBjb25zdGFudHNcbiAgICB2YXIgc2lnYml0cyA9IDUsXG4gICAgICAgIHJzaGlmdCA9IDggLSBzaWdiaXRzLFxuICAgICAgICBtYXhJdGVyYXRpb25zID0gMTAwMCxcbiAgICAgICAgZnJhY3RCeVBvcHVsYXRpb25zID0gMC43NTtcblxuICAgIC8vIGdldCByZWR1Y2VkLXNwYWNlIGNvbG9yIGluZGV4IGZvciBhIHBpeGVsXG5cbiAgICBmdW5jdGlvbiBnZXRDb2xvckluZGV4KHIsIGcsIGIpIHtcbiAgICAgICAgcmV0dXJuIChyIDw8ICgyICogc2lnYml0cykpICsgKGcgPDwgc2lnYml0cykgKyBiO1xuICAgIH1cblxuICAgIC8vIFNpbXBsZSBwcmlvcml0eSBxdWV1ZVxuXG4gICAgZnVuY3Rpb24gUFF1ZXVlKGNvbXBhcmF0b3IpIHtcbiAgICAgICAgdmFyIGNvbnRlbnRzID0gW10sXG4gICAgICAgICAgICBzb3J0ZWQgPSBmYWxzZTtcblxuICAgICAgICBmdW5jdGlvbiBzb3J0KCkge1xuICAgICAgICAgICAgY29udGVudHMuc29ydChjb21wYXJhdG9yKTtcbiAgICAgICAgICAgIHNvcnRlZCA9IHRydWU7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcHVzaDogZnVuY3Rpb24obykge1xuICAgICAgICAgICAgICAgIGNvbnRlbnRzLnB1c2gobyk7XG4gICAgICAgICAgICAgICAgc29ydGVkID0gZmFsc2U7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgcGVlazogZnVuY3Rpb24oaW5kZXgpIHtcbiAgICAgICAgICAgICAgICBpZiAoIXNvcnRlZCkgc29ydCgpO1xuICAgICAgICAgICAgICAgIGlmIChpbmRleCA9PT0gdW5kZWZpbmVkKSBpbmRleCA9IGNvbnRlbnRzLmxlbmd0aCAtIDE7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzW2luZGV4XTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBwb3A6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIGlmICghc29ydGVkKSBzb3J0KCk7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzLnBvcCgpO1xuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNpemU6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBjb250ZW50cy5sZW5ndGg7XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgbWFwOiBmdW5jdGlvbihmKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNvbnRlbnRzLm1hcChmKTtcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBkZWJ1ZzogZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAgICAgaWYgKCFzb3J0ZWQpIHNvcnQoKTtcbiAgICAgICAgICAgICAgICByZXR1cm4gY29udGVudHM7XG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfVxuXG4gICAgLy8gM2QgY29sb3Igc3BhY2UgYm94XG5cbiAgICBmdW5jdGlvbiBWQm94KHIxLCByMiwgZzEsIGcyLCBiMSwgYjIsIGhpc3RvKSB7XG4gICAgICAgIHZhciB2Ym94ID0gdGhpcztcbiAgICAgICAgdmJveC5yMSA9IHIxO1xuICAgICAgICB2Ym94LnIyID0gcjI7XG4gICAgICAgIHZib3guZzEgPSBnMTtcbiAgICAgICAgdmJveC5nMiA9IGcyO1xuICAgICAgICB2Ym94LmIxID0gYjE7XG4gICAgICAgIHZib3guYjIgPSBiMjtcbiAgICAgICAgdmJveC5oaXN0byA9IGhpc3RvO1xuICAgIH1cbiAgICBWQm94LnByb3RvdHlwZSA9IHtcbiAgICAgICAgdm9sdW1lOiBmdW5jdGlvbihmb3JjZSkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzO1xuICAgICAgICAgICAgaWYgKCF2Ym94Ll92b2x1bWUgfHwgZm9yY2UpIHtcbiAgICAgICAgICAgICAgICB2Ym94Ll92b2x1bWUgPSAoKHZib3gucjIgLSB2Ym94LnIxICsgMSkgKiAodmJveC5nMiAtIHZib3guZzEgKyAxKSAqICh2Ym94LmIyIC0gdmJveC5iMSArIDEpKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB2Ym94Ll92b2x1bWU7XG4gICAgICAgIH0sXG4gICAgICAgIGNvdW50OiBmdW5jdGlvbihmb3JjZSkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzLFxuICAgICAgICAgICAgICAgIGhpc3RvID0gdmJveC5oaXN0bztcbiAgICAgICAgICAgIGlmICghdmJveC5fY291bnRfc2V0IHx8IGZvcmNlKSB7XG4gICAgICAgICAgICAgICAgdmFyIG5waXggPSAwLFxuICAgICAgICAgICAgICAgICAgICBpLCBqLCBrLCBpbmRleDtcbiAgICAgICAgICAgICAgICBmb3IgKGkgPSB2Ym94LnIxOyBpIDw9IHZib3gucjI7IGkrKykge1xuICAgICAgICAgICAgICAgICAgICBmb3IgKGogPSB2Ym94LmcxOyBqIDw9IHZib3guZzI7IGorKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5iMTsgayA8PSB2Ym94LmIyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaSwgaiwgayk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbnBpeCArPSAoaGlzdG9baW5kZXhdIHx8IDApO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHZib3guX2NvdW50ID0gbnBpeDtcbiAgICAgICAgICAgICAgICB2Ym94Ll9jb3VudF9zZXQgPSB0cnVlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHZib3guX2NvdW50O1xuICAgICAgICB9LFxuICAgICAgICBjb3B5OiBmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIHZhciB2Ym94ID0gdGhpcztcbiAgICAgICAgICAgIHJldHVybiBuZXcgVkJveCh2Ym94LnIxLCB2Ym94LnIyLCB2Ym94LmcxLCB2Ym94LmcyLCB2Ym94LmIxLCB2Ym94LmIyLCB2Ym94Lmhpc3RvKTtcbiAgICAgICAgfSxcbiAgICAgICAgYXZnOiBmdW5jdGlvbihmb3JjZSkge1xuICAgICAgICAgICAgdmFyIHZib3ggPSB0aGlzLFxuICAgICAgICAgICAgICAgIGhpc3RvID0gdmJveC5oaXN0bztcbiAgICAgICAgICAgIGlmICghdmJveC5fYXZnIHx8IGZvcmNlKSB7XG4gICAgICAgICAgICAgICAgdmFyIG50b3QgPSAwLFxuICAgICAgICAgICAgICAgICAgICBtdWx0ID0gMSA8PCAoOCAtIHNpZ2JpdHMpLFxuICAgICAgICAgICAgICAgICAgICByc3VtID0gMCxcbiAgICAgICAgICAgICAgICAgICAgZ3N1bSA9IDAsXG4gICAgICAgICAgICAgICAgICAgIGJzdW0gPSAwLFxuICAgICAgICAgICAgICAgICAgICBodmFsLFxuICAgICAgICAgICAgICAgICAgICBpLCBqLCBrLCBoaXN0b2luZGV4O1xuICAgICAgICAgICAgICAgIGZvciAoaSA9IHZib3gucjE7IGkgPD0gdmJveC5yMjsgaSsrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3guZzE7IGogPD0gdmJveC5nMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGsgPSB2Ym94LmIxOyBrIDw9IHZib3guYjI7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGhpc3RvaW5kZXggPSBnZXRDb2xvckluZGV4KGksIGosIGspO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGh2YWwgPSBoaXN0b1toaXN0b2luZGV4XSB8fCAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIG50b3QgKz0gaHZhbDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByc3VtICs9IChodmFsICogKGkgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgZ3N1bSArPSAoaHZhbCAqIChqICsgMC41KSAqIG11bHQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGJzdW0gKz0gKGh2YWwgKiAoayArIDAuNSkgKiBtdWx0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAobnRvdCkge1xuICAgICAgICAgICAgICAgICAgICB2Ym94Ll9hdmcgPSBbfn4ocnN1bSAvIG50b3QpLCB+fiAoZ3N1bSAvIG50b3QpLCB+fiAoYnN1bSAvIG50b3QpXTtcbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAvL2NvbnNvbGUubG9nKCdlbXB0eSBib3gnKTtcbiAgICAgICAgICAgICAgICAgICAgdmJveC5fYXZnID0gW35+KG11bHQgKiAodmJveC5yMSArIHZib3gucjIgKyAxKSAvIDIpLCB+fiAobXVsdCAqICh2Ym94LmcxICsgdmJveC5nMiArIDEpIC8gMiksIH5+IChtdWx0ICogKHZib3guYjEgKyB2Ym94LmIyICsgMSkgLyAyKV07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcmV0dXJuIHZib3guX2F2ZztcbiAgICAgICAgfSxcbiAgICAgICAgY29udGFpbnM6IGZ1bmN0aW9uKHBpeGVsKSB7XG4gICAgICAgICAgICB2YXIgdmJveCA9IHRoaXMsXG4gICAgICAgICAgICAgICAgcnZhbCA9IHBpeGVsWzBdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGd2YWwgPSBwaXhlbFsxXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBidmFsID0gcGl4ZWxbMl0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgcmV0dXJuIChydmFsID49IHZib3gucjEgJiYgcnZhbCA8PSB2Ym94LnIyICYmXG4gICAgICAgICAgICAgICAgZ3ZhbCA+PSB2Ym94LmcxICYmIGd2YWwgPD0gdmJveC5nMiAmJlxuICAgICAgICAgICAgICAgIGJ2YWwgPj0gdmJveC5iMSAmJiBidmFsIDw9IHZib3guYjIpO1xuICAgICAgICB9XG4gICAgfTtcblxuICAgIC8vIENvbG9yIG1hcFxuXG4gICAgZnVuY3Rpb24gQ01hcCgpIHtcbiAgICAgICAgdGhpcy52Ym94ZXMgPSBuZXcgUFF1ZXVlKGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgIHJldHVybiBwdi5uYXR1cmFsT3JkZXIoXG4gICAgICAgICAgICAgICAgYS52Ym94LmNvdW50KCkgKiBhLnZib3gudm9sdW1lKCksXG4gICAgICAgICAgICAgICAgYi52Ym94LmNvdW50KCkgKiBiLnZib3gudm9sdW1lKClcbiAgICAgICAgICAgIClcbiAgICAgICAgfSk7O1xuICAgIH1cbiAgICBDTWFwLnByb3RvdHlwZSA9IHtcbiAgICAgICAgcHVzaDogZnVuY3Rpb24odmJveCkge1xuICAgICAgICAgICAgdGhpcy52Ym94ZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgdmJveDogdmJveCxcbiAgICAgICAgICAgICAgICBjb2xvcjogdmJveC5hdmcoKVxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0sXG4gICAgICAgIHBhbGV0dGU6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudmJveGVzLm1hcChmdW5jdGlvbih2Yikge1xuICAgICAgICAgICAgICAgIHJldHVybiB2Yi5jb2xvclxuICAgICAgICAgICAgfSk7XG4gICAgICAgIH0sXG4gICAgICAgIHNpemU6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMudmJveGVzLnNpemUoKTtcbiAgICAgICAgfSxcbiAgICAgICAgbWFwOiBmdW5jdGlvbihjb2xvcikge1xuICAgICAgICAgICAgdmFyIHZib3hlcyA9IHRoaXMudmJveGVzO1xuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB2Ym94ZXMuc2l6ZSgpOyBpKyspIHtcbiAgICAgICAgICAgICAgICBpZiAodmJveGVzLnBlZWsoaSkudmJveC5jb250YWlucyhjb2xvcikpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHZib3hlcy5wZWVrKGkpLmNvbG9yO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiB0aGlzLm5lYXJlc3QoY29sb3IpO1xuICAgICAgICB9LFxuICAgICAgICBuZWFyZXN0OiBmdW5jdGlvbihjb2xvcikge1xuICAgICAgICAgICAgdmFyIHZib3hlcyA9IHRoaXMudmJveGVzLFxuICAgICAgICAgICAgICAgIGQxLCBkMiwgcENvbG9yO1xuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB2Ym94ZXMuc2l6ZSgpOyBpKyspIHtcbiAgICAgICAgICAgICAgICBkMiA9IE1hdGguc3FydChcbiAgICAgICAgICAgICAgICAgICAgTWF0aC5wb3coY29sb3JbMF0gLSB2Ym94ZXMucGVlayhpKS5jb2xvclswXSwgMikgK1xuICAgICAgICAgICAgICAgICAgICBNYXRoLnBvdyhjb2xvclsxXSAtIHZib3hlcy5wZWVrKGkpLmNvbG9yWzFdLCAyKSArXG4gICAgICAgICAgICAgICAgICAgIE1hdGgucG93KGNvbG9yWzJdIC0gdmJveGVzLnBlZWsoaSkuY29sb3JbMl0sIDIpXG4gICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICBpZiAoZDIgPCBkMSB8fCBkMSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICAgIGQxID0gZDI7XG4gICAgICAgICAgICAgICAgICAgIHBDb2xvciA9IHZib3hlcy5wZWVrKGkpLmNvbG9yO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHJldHVybiBwQ29sb3I7XG4gICAgICAgIH0sXG4gICAgICAgIGZvcmNlYnc6IGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgLy8gWFhYOiB3b24ndCAgd29yayB5ZXRcbiAgICAgICAgICAgIHZhciB2Ym94ZXMgPSB0aGlzLnZib3hlcztcbiAgICAgICAgICAgIHZib3hlcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKHB2LnN1bShhLmNvbG9yKSwgcHYuc3VtKGIuY29sb3IpKVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vIGZvcmNlIGRhcmtlc3QgY29sb3IgdG8gYmxhY2sgaWYgZXZlcnl0aGluZyA8IDVcbiAgICAgICAgICAgIHZhciBsb3dlc3QgPSB2Ym94ZXNbMF0uY29sb3I7XG4gICAgICAgICAgICBpZiAobG93ZXN0WzBdIDwgNSAmJiBsb3dlc3RbMV0gPCA1ICYmIGxvd2VzdFsyXSA8IDUpXG4gICAgICAgICAgICAgICAgdmJveGVzWzBdLmNvbG9yID0gWzAsIDAsIDBdO1xuXG4gICAgICAgICAgICAvLyBmb3JjZSBsaWdodGVzdCBjb2xvciB0byB3aGl0ZSBpZiBldmVyeXRoaW5nID4gMjUxXG4gICAgICAgICAgICB2YXIgaWR4ID0gdmJveGVzLmxlbmd0aCAtIDEsXG4gICAgICAgICAgICAgICAgaGlnaGVzdCA9IHZib3hlc1tpZHhdLmNvbG9yO1xuICAgICAgICAgICAgaWYgKGhpZ2hlc3RbMF0gPiAyNTEgJiYgaGlnaGVzdFsxXSA+IDI1MSAmJiBoaWdoZXN0WzJdID4gMjUxKVxuICAgICAgICAgICAgICAgIHZib3hlc1tpZHhdLmNvbG9yID0gWzI1NSwgMjU1LCAyNTVdO1xuICAgICAgICB9XG4gICAgfTtcblxuICAgIC8vIGhpc3RvICgxLWQgYXJyYXksIGdpdmluZyB0aGUgbnVtYmVyIG9mIHBpeGVscyBpblxuICAgIC8vIGVhY2ggcXVhbnRpemVkIHJlZ2lvbiBvZiBjb2xvciBzcGFjZSksIG9yIG51bGwgb24gZXJyb3JcblxuICAgIGZ1bmN0aW9uIGdldEhpc3RvKHBpeGVscykge1xuICAgICAgICB2YXIgaGlzdG9zaXplID0gMSA8PCAoMyAqIHNpZ2JpdHMpLFxuICAgICAgICAgICAgaGlzdG8gPSBuZXcgQXJyYXkoaGlzdG9zaXplKSxcbiAgICAgICAgICAgIGluZGV4LCBydmFsLCBndmFsLCBidmFsO1xuICAgICAgICBwaXhlbHMuZm9yRWFjaChmdW5jdGlvbihwaXhlbCkge1xuICAgICAgICAgICAgcnZhbCA9IHBpeGVsWzBdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGd2YWwgPSBwaXhlbFsxXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBidmFsID0gcGl4ZWxbMl0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgaW5kZXggPSBnZXRDb2xvckluZGV4KHJ2YWwsIGd2YWwsIGJ2YWwpO1xuICAgICAgICAgICAgaGlzdG9baW5kZXhdID0gKGhpc3RvW2luZGV4XSB8fCAwKSArIDE7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gaGlzdG87XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gdmJveEZyb21QaXhlbHMocGl4ZWxzLCBoaXN0bykge1xuICAgICAgICB2YXIgcm1pbiA9IDEwMDAwMDAsXG4gICAgICAgICAgICBybWF4ID0gMCxcbiAgICAgICAgICAgIGdtaW4gPSAxMDAwMDAwLFxuICAgICAgICAgICAgZ21heCA9IDAsXG4gICAgICAgICAgICBibWluID0gMTAwMDAwMCxcbiAgICAgICAgICAgIGJtYXggPSAwLFxuICAgICAgICAgICAgcnZhbCwgZ3ZhbCwgYnZhbDtcbiAgICAgICAgLy8gZmluZCBtaW4vbWF4XG4gICAgICAgIHBpeGVscy5mb3JFYWNoKGZ1bmN0aW9uKHBpeGVsKSB7XG4gICAgICAgICAgICBydmFsID0gcGl4ZWxbMF0gPj4gcnNoaWZ0O1xuICAgICAgICAgICAgZ3ZhbCA9IHBpeGVsWzFdID4+IHJzaGlmdDtcbiAgICAgICAgICAgIGJ2YWwgPSBwaXhlbFsyXSA+PiByc2hpZnQ7XG4gICAgICAgICAgICBpZiAocnZhbCA8IHJtaW4pIHJtaW4gPSBydmFsO1xuICAgICAgICAgICAgZWxzZSBpZiAocnZhbCA+IHJtYXgpIHJtYXggPSBydmFsO1xuICAgICAgICAgICAgaWYgKGd2YWwgPCBnbWluKSBnbWluID0gZ3ZhbDtcbiAgICAgICAgICAgIGVsc2UgaWYgKGd2YWwgPiBnbWF4KSBnbWF4ID0gZ3ZhbDtcbiAgICAgICAgICAgIGlmIChidmFsIDwgYm1pbikgYm1pbiA9IGJ2YWw7XG4gICAgICAgICAgICBlbHNlIGlmIChidmFsID4gYm1heCkgYm1heCA9IGJ2YWw7XG4gICAgICAgIH0pO1xuICAgICAgICByZXR1cm4gbmV3IFZCb3gocm1pbiwgcm1heCwgZ21pbiwgZ21heCwgYm1pbiwgYm1heCwgaGlzdG8pO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIG1lZGlhbkN1dEFwcGx5KGhpc3RvLCB2Ym94KSB7XG4gICAgICAgIGlmICghdmJveC5jb3VudCgpKSByZXR1cm47XG5cbiAgICAgICAgdmFyIHJ3ID0gdmJveC5yMiAtIHZib3gucjEgKyAxLFxuICAgICAgICAgICAgZ3cgPSB2Ym94LmcyIC0gdmJveC5nMSArIDEsXG4gICAgICAgICAgICBidyA9IHZib3guYjIgLSB2Ym94LmIxICsgMSxcbiAgICAgICAgICAgIG1heHcgPSBwdi5tYXgoW3J3LCBndywgYnddKTtcbiAgICAgICAgLy8gb25seSBvbmUgcGl4ZWwsIG5vIHNwbGl0XG4gICAgICAgIGlmICh2Ym94LmNvdW50KCkgPT0gMSkge1xuICAgICAgICAgICAgcmV0dXJuIFt2Ym94LmNvcHkoKV1cbiAgICAgICAgfVxuICAgICAgICAvKiBGaW5kIHRoZSBwYXJ0aWFsIHN1bSBhcnJheXMgYWxvbmcgdGhlIHNlbGVjdGVkIGF4aXMuICovXG4gICAgICAgIHZhciB0b3RhbCA9IDAsXG4gICAgICAgICAgICBwYXJ0aWFsc3VtID0gW10sXG4gICAgICAgICAgICBsb29rYWhlYWRzdW0gPSBbXSxcbiAgICAgICAgICAgIGksIGosIGssIHN1bSwgaW5kZXg7XG4gICAgICAgIGlmIChtYXh3ID09IHJ3KSB7XG4gICAgICAgICAgICBmb3IgKGkgPSB2Ym94LnIxOyBpIDw9IHZib3gucjI7IGkrKykge1xuICAgICAgICAgICAgICAgIHN1bSA9IDA7XG4gICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5nMTsgaiA8PSB2Ym94LmcyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5iMTsgayA8PSB2Ym94LmIyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChpLCBqLCBrKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHN1bSArPSAoaGlzdG9baW5kZXhdIHx8IDApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICAgICAgICBwYXJ0aWFsc3VtW2ldID0gdG90YWw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSBpZiAobWF4dyA9PSBndykge1xuICAgICAgICAgICAgZm9yIChpID0gdmJveC5nMTsgaSA8PSB2Ym94LmcyOyBpKyspIHtcbiAgICAgICAgICAgICAgICBzdW0gPSAwO1xuICAgICAgICAgICAgICAgIGZvciAoaiA9IHZib3gucjE7IGogPD0gdmJveC5yMjsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZvciAoayA9IHZib3guYjE7IGsgPD0gdmJveC5iMjsgaysrKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBpbmRleCA9IGdldENvbG9ySW5kZXgoaiwgaSwgayk7XG4gICAgICAgICAgICAgICAgICAgICAgICBzdW0gKz0gKGhpc3RvW2luZGV4XSB8fCAwKTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB0b3RhbCArPSBzdW07XG4gICAgICAgICAgICAgICAgcGFydGlhbHN1bVtpXSA9IHRvdGFsO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2UgeyAvKiBtYXh3ID09IGJ3ICovXG4gICAgICAgICAgICBmb3IgKGkgPSB2Ym94LmIxOyBpIDw9IHZib3guYjI7IGkrKykge1xuICAgICAgICAgICAgICAgIHN1bSA9IDA7XG4gICAgICAgICAgICAgICAgZm9yIChqID0gdmJveC5yMTsgaiA8PSB2Ym94LnIyOyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZm9yIChrID0gdmJveC5nMTsgayA8PSB2Ym94LmcyOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChqLCBrLCBpKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHN1bSArPSAoaGlzdG9baW5kZXhdIHx8IDApO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIHRvdGFsICs9IHN1bTtcbiAgICAgICAgICAgICAgICBwYXJ0aWFsc3VtW2ldID0gdG90YWw7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcGFydGlhbHN1bS5mb3JFYWNoKGZ1bmN0aW9uKGQsIGkpIHtcbiAgICAgICAgICAgIGxvb2thaGVhZHN1bVtpXSA9IHRvdGFsIC0gZFxuICAgICAgICB9KTtcblxuICAgICAgICBmdW5jdGlvbiBkb0N1dChjb2xvcikge1xuICAgICAgICAgICAgdmFyIGRpbTEgPSBjb2xvciArICcxJyxcbiAgICAgICAgICAgICAgICBkaW0yID0gY29sb3IgKyAnMicsXG4gICAgICAgICAgICAgICAgbGVmdCwgcmlnaHQsIHZib3gxLCB2Ym94MiwgZDIsIGNvdW50MiA9IDA7XG4gICAgICAgICAgICBmb3IgKGkgPSB2Ym94W2RpbTFdOyBpIDw9IHZib3hbZGltMl07IGkrKykge1xuICAgICAgICAgICAgICAgIGlmIChwYXJ0aWFsc3VtW2ldID4gdG90YWwgLyAyKSB7XG4gICAgICAgICAgICAgICAgICAgIHZib3gxID0gdmJveC5jb3B5KCk7XG4gICAgICAgICAgICAgICAgICAgIHZib3gyID0gdmJveC5jb3B5KCk7XG4gICAgICAgICAgICAgICAgICAgIGxlZnQgPSBpIC0gdmJveFtkaW0xXTtcbiAgICAgICAgICAgICAgICAgICAgcmlnaHQgPSB2Ym94W2RpbTJdIC0gaTtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGxlZnQgPD0gcmlnaHQpXG4gICAgICAgICAgICAgICAgICAgICAgICBkMiA9IE1hdGgubWluKHZib3hbZGltMl0gLSAxLCB+fiAoaSArIHJpZ2h0IC8gMikpO1xuICAgICAgICAgICAgICAgICAgICBlbHNlIGQyID0gTWF0aC5tYXgodmJveFtkaW0xXSwgfn4gKGkgLSAxIC0gbGVmdCAvIDIpKTtcbiAgICAgICAgICAgICAgICAgICAgLy8gYXZvaWQgMC1jb3VudCBib3hlc1xuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoIXBhcnRpYWxzdW1bZDJdKSBkMisrO1xuICAgICAgICAgICAgICAgICAgICBjb3VudDIgPSBsb29rYWhlYWRzdW1bZDJdO1xuICAgICAgICAgICAgICAgICAgICB3aGlsZSAoIWNvdW50MiAmJiBwYXJ0aWFsc3VtW2QyIC0gMV0pIGNvdW50MiA9IGxvb2thaGVhZHN1bVstLWQyXTtcbiAgICAgICAgICAgICAgICAgICAgLy8gc2V0IGRpbWVuc2lvbnNcbiAgICAgICAgICAgICAgICAgICAgdmJveDFbZGltMl0gPSBkMjtcbiAgICAgICAgICAgICAgICAgICAgdmJveDJbZGltMV0gPSB2Ym94MVtkaW0yXSArIDE7XG4gICAgICAgICAgICAgICAgICAgIC8vIGNvbnNvbGUubG9nKCd2Ym94IGNvdW50czonLCB2Ym94LmNvdW50KCksIHZib3gxLmNvdW50KCksIHZib3gyLmNvdW50KCkpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gW3Zib3gxLCB2Ym94Ml07XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cbiAgICAgICAgLy8gZGV0ZXJtaW5lIHRoZSBjdXQgcGxhbmVzXG4gICAgICAgIHJldHVybiBtYXh3ID09IHJ3ID8gZG9DdXQoJ3InKSA6XG4gICAgICAgICAgICBtYXh3ID09IGd3ID8gZG9DdXQoJ2cnKSA6XG4gICAgICAgICAgICBkb0N1dCgnYicpO1xuICAgIH1cblxuICAgIGZ1bmN0aW9uIHF1YW50aXplKHBpeGVscywgbWF4Y29sb3JzKSB7XG4gICAgICAgIC8vIHNob3J0LWNpcmN1aXRcbiAgICAgICAgaWYgKCFwaXhlbHMubGVuZ3RoIHx8IG1heGNvbG9ycyA8IDIgfHwgbWF4Y29sb3JzID4gMjU2KSB7XG4gICAgICAgICAgICAvLyBjb25zb2xlLmxvZygnd3JvbmcgbnVtYmVyIG9mIG1heGNvbG9ycycpO1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gWFhYOiBjaGVjayBjb2xvciBjb250ZW50IGFuZCBjb252ZXJ0IHRvIGdyYXlzY2FsZSBpZiBpbnN1ZmZpY2llbnRcblxuICAgICAgICB2YXIgaGlzdG8gPSBnZXRIaXN0byhwaXhlbHMpLFxuICAgICAgICAgICAgaGlzdG9zaXplID0gMSA8PCAoMyAqIHNpZ2JpdHMpO1xuXG4gICAgICAgIC8vIGNoZWNrIHRoYXQgd2UgYXJlbid0IGJlbG93IG1heGNvbG9ycyBhbHJlYWR5XG4gICAgICAgIHZhciBuQ29sb3JzID0gMDtcbiAgICAgICAgaGlzdG8uZm9yRWFjaChmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIG5Db2xvcnMrK1xuICAgICAgICB9KTtcbiAgICAgICAgaWYgKG5Db2xvcnMgPD0gbWF4Y29sb3JzKSB7XG4gICAgICAgICAgICAvLyBYWFg6IGdlbmVyYXRlIHRoZSBuZXcgY29sb3JzIGZyb20gdGhlIGhpc3RvIGFuZCByZXR1cm5cbiAgICAgICAgfVxuXG4gICAgICAgIC8vIGdldCB0aGUgYmVnaW5uaW5nIHZib3ggZnJvbSB0aGUgY29sb3JzXG4gICAgICAgIHZhciB2Ym94ID0gdmJveEZyb21QaXhlbHMocGl4ZWxzLCBoaXN0byksXG4gICAgICAgICAgICBwcSA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgICAgICAgICAgIHJldHVybiBwdi5uYXR1cmFsT3JkZXIoYS5jb3VudCgpLCBiLmNvdW50KCkpXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgcHEucHVzaCh2Ym94KTtcblxuICAgICAgICAvLyBpbm5lciBmdW5jdGlvbiB0byBkbyB0aGUgaXRlcmF0aW9uXG5cbiAgICAgICAgZnVuY3Rpb24gaXRlcihsaCwgdGFyZ2V0KSB7XG4gICAgICAgICAgICB2YXIgbmNvbG9ycyA9IDEsXG4gICAgICAgICAgICAgICAgbml0ZXJzID0gMCxcbiAgICAgICAgICAgICAgICB2Ym94O1xuICAgICAgICAgICAgd2hpbGUgKG5pdGVycyA8IG1heEl0ZXJhdGlvbnMpIHtcbiAgICAgICAgICAgICAgICB2Ym94ID0gbGgucG9wKCk7XG4gICAgICAgICAgICAgICAgaWYgKCF2Ym94LmNvdW50KCkpIHsgLyoganVzdCBwdXQgaXQgYmFjayAqL1xuICAgICAgICAgICAgICAgICAgICBsaC5wdXNoKHZib3gpO1xuICAgICAgICAgICAgICAgICAgICBuaXRlcnMrKztcbiAgICAgICAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIGRvIHRoZSBjdXRcbiAgICAgICAgICAgICAgICB2YXIgdmJveGVzID0gbWVkaWFuQ3V0QXBwbHkoaGlzdG8sIHZib3gpLFxuICAgICAgICAgICAgICAgICAgICB2Ym94MSA9IHZib3hlc1swXSxcbiAgICAgICAgICAgICAgICAgICAgdmJveDIgPSB2Ym94ZXNbMV07XG5cbiAgICAgICAgICAgICAgICBpZiAoIXZib3gxKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIGNvbnNvbGUubG9nKFwidmJveDEgbm90IGRlZmluZWQ7IHNob3VsZG4ndCBoYXBwZW4hXCIpO1xuICAgICAgICAgICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGxoLnB1c2godmJveDEpO1xuICAgICAgICAgICAgICAgIGlmICh2Ym94MikgeyAvKiB2Ym94MiBjYW4gYmUgbnVsbCAqL1xuICAgICAgICAgICAgICAgICAgICBsaC5wdXNoKHZib3gyKTtcbiAgICAgICAgICAgICAgICAgICAgbmNvbG9ycysrO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAobmNvbG9ycyA+PSB0YXJnZXQpIHJldHVybjtcbiAgICAgICAgICAgICAgICBpZiAobml0ZXJzKysgPiBtYXhJdGVyYXRpb25zKSB7XG4gICAgICAgICAgICAgICAgICAgIC8vIGNvbnNvbGUubG9nKFwiaW5maW5pdGUgbG9vcDsgcGVyaGFwcyB0b28gZmV3IHBpeGVscyFcIik7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybjtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICAvLyBmaXJzdCBzZXQgb2YgY29sb3JzLCBzb3J0ZWQgYnkgcG9wdWxhdGlvblxuICAgICAgICBpdGVyKHBxLCBmcmFjdEJ5UG9wdWxhdGlvbnMgKiBtYXhjb2xvcnMpO1xuICAgICAgICAvLyBjb25zb2xlLmxvZyhwcS5zaXplKCksIHBxLmRlYnVnKCkubGVuZ3RoLCBwcS5kZWJ1ZygpLnNsaWNlKCkpO1xuXG4gICAgICAgIC8vIFJlLXNvcnQgYnkgdGhlIHByb2R1Y3Qgb2YgcGl4ZWwgb2NjdXBhbmN5IHRpbWVzIHRoZSBzaXplIGluIGNvbG9yIHNwYWNlLlxuICAgICAgICB2YXIgcHEyID0gbmV3IFBRdWV1ZShmdW5jdGlvbihhLCBiKSB7XG4gICAgICAgICAgICByZXR1cm4gcHYubmF0dXJhbE9yZGVyKGEuY291bnQoKSAqIGEudm9sdW1lKCksIGIuY291bnQoKSAqIGIudm9sdW1lKCkpXG4gICAgICAgIH0pO1xuICAgICAgICB3aGlsZSAocHEuc2l6ZSgpKSB7XG4gICAgICAgICAgICBwcTIucHVzaChwcS5wb3AoKSk7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBuZXh0IHNldCAtIGdlbmVyYXRlIHRoZSBtZWRpYW4gY3V0cyB1c2luZyB0aGUgKG5waXggKiB2b2wpIHNvcnRpbmcuXG4gICAgICAgIGl0ZXIocHEyLCBtYXhjb2xvcnMgLSBwcTIuc2l6ZSgpKTtcblxuICAgICAgICAvLyBjYWxjdWxhdGUgdGhlIGFjdHVhbCBjb2xvcnNcbiAgICAgICAgdmFyIGNtYXAgPSBuZXcgQ01hcCgpO1xuICAgICAgICB3aGlsZSAocHEyLnNpemUoKSkge1xuICAgICAgICAgICAgY21hcC5wdXNoKHBxMi5wb3AoKSk7XG4gICAgICAgIH1cblxuICAgICAgICByZXR1cm4gY21hcDtcbiAgICB9XG5cbiAgICByZXR1cm4ge1xuICAgICAgICBxdWFudGl6ZTogcXVhbnRpemVcbiAgICB9XG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IE1NQ1EucXVhbnRpemVcbiIsIi8vIENvcHlyaWdodCBKb3llbnQsIEluYy4gYW5kIG90aGVyIE5vZGUgY29udHJpYnV0b3JzLlxuLy9cbi8vIFBlcm1pc3Npb24gaXMgaGVyZWJ5IGdyYW50ZWQsIGZyZWUgb2YgY2hhcmdlLCB0byBhbnkgcGVyc29uIG9idGFpbmluZyBhXG4vLyBjb3B5IG9mIHRoaXMgc29mdHdhcmUgYW5kIGFzc29jaWF0ZWQgZG9jdW1lbnRhdGlvbiBmaWxlcyAodGhlXG4vLyBcIlNvZnR3YXJlXCIpLCB0byBkZWFsIGluIHRoZSBTb2Z0d2FyZSB3aXRob3V0IHJlc3RyaWN0aW9uLCBpbmNsdWRpbmdcbi8vIHdpdGhvdXQgbGltaXRhdGlvbiB0aGUgcmlnaHRzIHRvIHVzZSwgY29weSwgbW9kaWZ5LCBtZXJnZSwgcHVibGlzaCxcbi8vIGRpc3RyaWJ1dGUsIHN1YmxpY2Vuc2UsIGFuZC9vciBzZWxsIGNvcGllcyBvZiB0aGUgU29mdHdhcmUsIGFuZCB0byBwZXJtaXRcbi8vIHBlcnNvbnMgdG8gd2hvbSB0aGUgU29mdHdhcmUgaXMgZnVybmlzaGVkIHRvIGRvIHNvLCBzdWJqZWN0IHRvIHRoZVxuLy8gZm9sbG93aW5nIGNvbmRpdGlvbnM6XG4vL1xuLy8gVGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UgYW5kIHRoaXMgcGVybWlzc2lvbiBub3RpY2Ugc2hhbGwgYmUgaW5jbHVkZWRcbi8vIGluIGFsbCBjb3BpZXMgb3Igc3Vic3RhbnRpYWwgcG9ydGlvbnMgb2YgdGhlIFNvZnR3YXJlLlxuLy9cbi8vIFRIRSBTT0ZUV0FSRSBJUyBQUk9WSURFRCBcIkFTIElTXCIsIFdJVEhPVVQgV0FSUkFOVFkgT0YgQU5ZIEtJTkQsIEVYUFJFU1Ncbi8vIE9SIElNUExJRUQsIElOQ0xVRElORyBCVVQgTk9UIExJTUlURUQgVE8gVEhFIFdBUlJBTlRJRVMgT0Zcbi8vIE1FUkNIQU5UQUJJTElUWSwgRklUTkVTUyBGT1IgQSBQQVJUSUNVTEFSIFBVUlBPU0UgQU5EIE5PTklORlJJTkdFTUVOVC4gSU5cbi8vIE5PIEVWRU5UIFNIQUxMIFRIRSBBVVRIT1JTIE9SIENPUFlSSUdIVCBIT0xERVJTIEJFIExJQUJMRSBGT1IgQU5ZIENMQUlNLFxuLy8gREFNQUdFUyBPUiBPVEhFUiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQU4gQUNUSU9OIE9GIENPTlRSQUNULCBUT1JUIE9SXG4vLyBPVEhFUldJU0UsIEFSSVNJTkcgRlJPTSwgT1VUIE9GIE9SIElOIENPTk5FQ1RJT04gV0lUSCBUSEUgU09GVFdBUkUgT1IgVEhFXG4vLyBVU0UgT1IgT1RIRVIgREVBTElOR1MgSU4gVEhFIFNPRlRXQVJFLlxuXG4ndXNlIHN0cmljdCc7XG5cbi8vIElmIG9iai5oYXNPd25Qcm9wZXJ0eSBoYXMgYmVlbiBvdmVycmlkZGVuLCB0aGVuIGNhbGxpbmdcbi8vIG9iai5oYXNPd25Qcm9wZXJ0eShwcm9wKSB3aWxsIGJyZWFrLlxuLy8gU2VlOiBodHRwczovL2dpdGh1Yi5jb20vam95ZW50L25vZGUvaXNzdWVzLzE3MDdcbmZ1bmN0aW9uIGhhc093blByb3BlcnR5KG9iaiwgcHJvcCkge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwgcHJvcCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ocXMsIHNlcCwgZXEsIG9wdGlvbnMpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIHZhciBvYmogPSB7fTtcblxuICBpZiAodHlwZW9mIHFzICE9PSAnc3RyaW5nJyB8fCBxcy5sZW5ndGggPT09IDApIHtcbiAgICByZXR1cm4gb2JqO1xuICB9XG5cbiAgdmFyIHJlZ2V4cCA9IC9cXCsvZztcbiAgcXMgPSBxcy5zcGxpdChzZXApO1xuXG4gIHZhciBtYXhLZXlzID0gMTAwMDtcbiAgaWYgKG9wdGlvbnMgJiYgdHlwZW9mIG9wdGlvbnMubWF4S2V5cyA9PT0gJ251bWJlcicpIHtcbiAgICBtYXhLZXlzID0gb3B0aW9ucy5tYXhLZXlzO1xuICB9XG5cbiAgdmFyIGxlbiA9IHFzLmxlbmd0aDtcbiAgLy8gbWF4S2V5cyA8PSAwIG1lYW5zIHRoYXQgd2Ugc2hvdWxkIG5vdCBsaW1pdCBrZXlzIGNvdW50XG4gIGlmIChtYXhLZXlzID4gMCAmJiBsZW4gPiBtYXhLZXlzKSB7XG4gICAgbGVuID0gbWF4S2V5cztcbiAgfVxuXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyArK2kpIHtcbiAgICB2YXIgeCA9IHFzW2ldLnJlcGxhY2UocmVnZXhwLCAnJTIwJyksXG4gICAgICAgIGlkeCA9IHguaW5kZXhPZihlcSksXG4gICAgICAgIGtzdHIsIHZzdHIsIGssIHY7XG5cbiAgICBpZiAoaWR4ID49IDApIHtcbiAgICAgIGtzdHIgPSB4LnN1YnN0cigwLCBpZHgpO1xuICAgICAgdnN0ciA9IHguc3Vic3RyKGlkeCArIDEpO1xuICAgIH0gZWxzZSB7XG4gICAgICBrc3RyID0geDtcbiAgICAgIHZzdHIgPSAnJztcbiAgICB9XG5cbiAgICBrID0gZGVjb2RlVVJJQ29tcG9uZW50KGtzdHIpO1xuICAgIHYgPSBkZWNvZGVVUklDb21wb25lbnQodnN0cik7XG5cbiAgICBpZiAoIWhhc093blByb3BlcnR5KG9iaiwgaykpIHtcbiAgICAgIG9ialtrXSA9IHY7XG4gICAgfSBlbHNlIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgIG9ialtrXS5wdXNoKHYpO1xuICAgIH0gZWxzZSB7XG4gICAgICBvYmpba10gPSBbb2JqW2tdLCB2XTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gb2JqO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG4iLCIvLyBDb3B5cmlnaHQgSm95ZW50LCBJbmMuIGFuZCBvdGhlciBOb2RlIGNvbnRyaWJ1dG9ycy5cbi8vXG4vLyBQZXJtaXNzaW9uIGlzIGhlcmVieSBncmFudGVkLCBmcmVlIG9mIGNoYXJnZSwgdG8gYW55IHBlcnNvbiBvYnRhaW5pbmcgYVxuLy8gY29weSBvZiB0aGlzIHNvZnR3YXJlIGFuZCBhc3NvY2lhdGVkIGRvY3VtZW50YXRpb24gZmlsZXMgKHRoZVxuLy8gXCJTb2Z0d2FyZVwiKSwgdG8gZGVhbCBpbiB0aGUgU29mdHdhcmUgd2l0aG91dCByZXN0cmljdGlvbiwgaW5jbHVkaW5nXG4vLyB3aXRob3V0IGxpbWl0YXRpb24gdGhlIHJpZ2h0cyB0byB1c2UsIGNvcHksIG1vZGlmeSwgbWVyZ2UsIHB1Ymxpc2gsXG4vLyBkaXN0cmlidXRlLCBzdWJsaWNlbnNlLCBhbmQvb3Igc2VsbCBjb3BpZXMgb2YgdGhlIFNvZnR3YXJlLCBhbmQgdG8gcGVybWl0XG4vLyBwZXJzb25zIHRvIHdob20gdGhlIFNvZnR3YXJlIGlzIGZ1cm5pc2hlZCB0byBkbyBzbywgc3ViamVjdCB0byB0aGVcbi8vIGZvbGxvd2luZyBjb25kaXRpb25zOlxuLy9cbi8vIFRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlIGFuZCB0aGlzIHBlcm1pc3Npb24gbm90aWNlIHNoYWxsIGJlIGluY2x1ZGVkXG4vLyBpbiBhbGwgY29waWVzIG9yIHN1YnN0YW50aWFsIHBvcnRpb25zIG9mIHRoZSBTb2Z0d2FyZS5cbi8vXG4vLyBUSEUgU09GVFdBUkUgSVMgUFJPVklERUQgXCJBUyBJU1wiLCBXSVRIT1VUIFdBUlJBTlRZIE9GIEFOWSBLSU5ELCBFWFBSRVNTXG4vLyBPUiBJTVBMSUVELCBJTkNMVURJTkcgQlVUIE5PVCBMSU1JVEVEIFRPIFRIRSBXQVJSQU5USUVTIE9GXG4vLyBNRVJDSEFOVEFCSUxJVFksIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFORCBOT05JTkZSSU5HRU1FTlQuIElOXG4vLyBOTyBFVkVOVCBTSEFMTCBUSEUgQVVUSE9SUyBPUiBDT1BZUklHSFQgSE9MREVSUyBCRSBMSUFCTEUgRk9SIEFOWSBDTEFJTSxcbi8vIERBTUFHRVMgT1IgT1RIRVIgTElBQklMSVRZLCBXSEVUSEVSIElOIEFOIEFDVElPTiBPRiBDT05UUkFDVCwgVE9SVCBPUlxuLy8gT1RIRVJXSVNFLCBBUklTSU5HIEZST00sIE9VVCBPRiBPUiBJTiBDT05ORUNUSU9OIFdJVEggVEhFIFNPRlRXQVJFIE9SIFRIRVxuLy8gVVNFIE9SIE9USEVSIERFQUxJTkdTIElOIFRIRSBTT0ZUV0FSRS5cblxuJ3VzZSBzdHJpY3QnO1xuXG52YXIgc3RyaW5naWZ5UHJpbWl0aXZlID0gZnVuY3Rpb24odikge1xuICBzd2l0Y2ggKHR5cGVvZiB2KSB7XG4gICAgY2FzZSAnc3RyaW5nJzpcbiAgICAgIHJldHVybiB2O1xuXG4gICAgY2FzZSAnYm9vbGVhbic6XG4gICAgICByZXR1cm4gdiA/ICd0cnVlJyA6ICdmYWxzZSc7XG5cbiAgICBjYXNlICdudW1iZXInOlxuICAgICAgcmV0dXJuIGlzRmluaXRlKHYpID8gdiA6ICcnO1xuXG4gICAgZGVmYXVsdDpcbiAgICAgIHJldHVybiAnJztcbiAgfVxufTtcblxubW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbihvYmosIHNlcCwgZXEsIG5hbWUpIHtcbiAgc2VwID0gc2VwIHx8ICcmJztcbiAgZXEgPSBlcSB8fCAnPSc7XG4gIGlmIChvYmogPT09IG51bGwpIHtcbiAgICBvYmogPSB1bmRlZmluZWQ7XG4gIH1cblxuICBpZiAodHlwZW9mIG9iaiA9PT0gJ29iamVjdCcpIHtcbiAgICByZXR1cm4gbWFwKG9iamVjdEtleXMob2JqKSwgZnVuY3Rpb24oaykge1xuICAgICAgdmFyIGtzID0gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShrKSkgKyBlcTtcbiAgICAgIGlmIChpc0FycmF5KG9ialtrXSkpIHtcbiAgICAgICAgcmV0dXJuIG1hcChvYmpba10sIGZ1bmN0aW9uKHYpIHtcbiAgICAgICAgICByZXR1cm4ga3MgKyBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKHYpKTtcbiAgICAgICAgfSkuam9pbihzZXApO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuIGtzICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShvYmpba10pKTtcbiAgICAgIH1cbiAgICB9KS5qb2luKHNlcCk7XG5cbiAgfVxuXG4gIGlmICghbmFtZSkgcmV0dXJuICcnO1xuICByZXR1cm4gZW5jb2RlVVJJQ29tcG9uZW50KHN0cmluZ2lmeVByaW1pdGl2ZShuYW1lKSkgKyBlcSArXG4gICAgICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RyaW5naWZ5UHJpbWl0aXZlKG9iaikpO1xufTtcblxudmFyIGlzQXJyYXkgPSBBcnJheS5pc0FycmF5IHx8IGZ1bmN0aW9uICh4cykge1xuICByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKHhzKSA9PT0gJ1tvYmplY3QgQXJyYXldJztcbn07XG5cbmZ1bmN0aW9uIG1hcCAoeHMsIGYpIHtcbiAgaWYgKHhzLm1hcCkgcmV0dXJuIHhzLm1hcChmKTtcbiAgdmFyIHJlcyA9IFtdO1xuICBmb3IgKHZhciBpID0gMDsgaSA8IHhzLmxlbmd0aDsgaSsrKSB7XG4gICAgcmVzLnB1c2goZih4c1tpXSwgaSkpO1xuICB9XG4gIHJldHVybiByZXM7XG59XG5cbnZhciBvYmplY3RLZXlzID0gT2JqZWN0LmtleXMgfHwgZnVuY3Rpb24gKG9iaikge1xuICB2YXIgcmVzID0gW107XG4gIGZvciAodmFyIGtleSBpbiBvYmopIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSkgcmVzLnB1c2goa2V5KTtcbiAgfVxuICByZXR1cm4gcmVzO1xufTtcbiIsIid1c2Ugc3RyaWN0JztcblxuZXhwb3J0cy5kZWNvZGUgPSBleHBvcnRzLnBhcnNlID0gcmVxdWlyZSgnLi9kZWNvZGUnKTtcbmV4cG9ydHMuZW5jb2RlID0gZXhwb3J0cy5zdHJpbmdpZnkgPSByZXF1aXJlKCcuL2VuY29kZScpO1xuIiwidmFyIFZpYnJhbnQ7XG5cblZpYnJhbnQgPSByZXF1aXJlKCcuL3ZpYnJhbnQnKTtcblxuVmlicmFudC5EZWZhdWx0T3B0cy5JbWFnZSA9IHJlcXVpcmUoJy4vaW1hZ2UvYnJvd3NlcicpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFZpYnJhbnQ7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZZbkp2ZDNObGNpNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTlpY205M2MyVnlMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaVFVRkJRU3hKUVVGQk96dEJRVUZCTEU5QlFVRXNSMEZCVlN4UFFVRkJMRU5CUVZFc1YwRkJVanM3UVVGRFZpeFBRVUZQTEVOQlFVTXNWMEZCVnl4RFFVRkRMRXRCUVhCQ0xFZEJRVFJDTEU5QlFVRXNRMEZCVVN4cFFrRkJVanM3UVVGRk5VSXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkJhVUlpZlE9PVxuIiwidmFyIFZpYnJhbnQ7XG5cbndpbmRvdy5WaWJyYW50ID0gVmlicmFudCA9IHJlcXVpcmUoJy4vYnJvd3NlcicpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12WW5WdVpHeGxMbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDJKMWJtUnNaUzVqYjJabVpXVWlYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklrRkJRVUVzU1VGQlFUczdRVUZCUVN4TlFVRk5MRU5CUVVNc1QwRkJVQ3hIUVVGcFFpeFBRVUZCTEVkQlFWVXNUMEZCUVN4RFFVRlJMRmRCUVZJaWZRPT1cbiIsIm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24ociwgZywgYiwgYSkge1xuICByZXR1cm4gYSA+PSAxMjUgJiYgIShyID4gMjUwICYmIGcgPiAyNTAgJiYgYiA+IDI1MCk7XG59O1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Wm1sc2RHVnlMMlJsWm1GMWJIUXVZMjltWm1WbElpd2ljMjkxY21ObFVtOXZkQ0k2SWlJc0luTnZkWEpqWlhNaU9sc2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Wm1sc2RHVnlMMlJsWm1GMWJIUXVZMjltWm1WbElsMHNJbTVoYldWeklqcGJYU3dpYldGd2NHbHVaM01pT2lKQlFVRkJMRTFCUVUwc1EwRkJReXhQUVVGUUxFZEJRV2xDTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUUxFVkJRVlVzUTBGQlZqdFRRVU5tTEVOQlFVRXNTVUZCU3l4SFFVRk1MRWxCUVdFc1EwRkJTU3hEUVVGRExFTkJRVUVzUjBGQlNTeEhRVUZLTEVsQlFWa3NRMEZCUVN4SFFVRkpMRWRCUVdoQ0xFbEJRWGRDTEVOQlFVRXNSMEZCU1N4SFFVRTNRanRCUVVSR0luMD1cbiIsIm1vZHVsZS5leHBvcnRzLkRlZmF1bHQgPSByZXF1aXJlKCcuL2RlZmF1bHQnKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdlptbHNkR1Z5TDJsdVpHVjRMbU52Wm1abFpTSXNJbk52ZFhKalpWSnZiM1FpT2lJaUxDSnpiM1Z5WTJWeklqcGJJaTlWYzJWeWN5OWpOQzlFYjJOMWJXVnVkSE12VUhKdmFtVmpkSE12YzJWc2JHVnZMMjV2WkdVdGJHOW5ieTFqYjJ4dmNuTXZjM0pqTDJacGJIUmxjaTlwYm1SbGVDNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNUVUZCVFN4RFFVRkRMRTlCUVU4c1EwRkJReXhQUVVGbUxFZEJRWGxDTEU5QlFVRXNRMEZCVVN4WFFVRlNJbjA9XG4iLCJ2YXIgRGVmYXVsdEdlbmVyYXRvciwgRGVmYXVsdE9wdHMsIEdlbmVyYXRvciwgU3dhdGNoLCB1dGlsLFxuICBleHRlbmQgPSBmdW5jdGlvbihjaGlsZCwgcGFyZW50KSB7IGZvciAodmFyIGtleSBpbiBwYXJlbnQpIHsgaWYgKGhhc1Byb3AuY2FsbChwYXJlbnQsIGtleSkpIGNoaWxkW2tleV0gPSBwYXJlbnRba2V5XTsgfSBmdW5jdGlvbiBjdG9yKCkgeyB0aGlzLmNvbnN0cnVjdG9yID0gY2hpbGQ7IH0gY3Rvci5wcm90b3R5cGUgPSBwYXJlbnQucHJvdG90eXBlOyBjaGlsZC5wcm90b3R5cGUgPSBuZXcgY3RvcigpOyBjaGlsZC5fX3N1cGVyX18gPSBwYXJlbnQucHJvdG90eXBlOyByZXR1cm4gY2hpbGQ7IH0sXG4gIGhhc1Byb3AgPSB7fS5oYXNPd25Qcm9wZXJ0eSxcbiAgc2xpY2UgPSBbXS5zbGljZTtcblxuU3dhdGNoID0gcmVxdWlyZSgnLi4vc3dhdGNoJyk7XG5cbnV0aWwgPSByZXF1aXJlKCcuLi91dGlsJyk7XG5cbkdlbmVyYXRvciA9IHJlcXVpcmUoJy4vaW5kZXgnKTtcblxuRGVmYXVsdE9wdHMgPSB7XG4gIHRhcmdldERhcmtMdW1hOiAwLjI2LFxuICBtYXhEYXJrTHVtYTogMC40NSxcbiAgbWluTGlnaHRMdW1hOiAwLjU1LFxuICB0YXJnZXRMaWdodEx1bWE6IDAuNzQsXG4gIG1pbk5vcm1hbEx1bWE6IDAuMyxcbiAgdGFyZ2V0Tm9ybWFsTHVtYTogMC41LFxuICBtYXhOb3JtYWxMdW1hOiAwLjcsXG4gIHRhcmdldE11dGVzU2F0dXJhdGlvbjogMC4zLFxuICBtYXhNdXRlc1NhdHVyYXRpb246IDAuNCxcbiAgdGFyZ2V0VmlicmFudFNhdHVyYXRpb246IDEuMCxcbiAgbWluVmlicmFudFNhdHVyYXRpb246IDAuMzUsXG4gIHdlaWdodFNhdHVyYXRpb246IDMsXG4gIHdlaWdodEx1bWE6IDYsXG4gIHdlaWdodFBvcHVsYXRpb246IDFcbn07XG5cbm1vZHVsZS5leHBvcnRzID0gRGVmYXVsdEdlbmVyYXRvciA9IChmdW5jdGlvbihzdXBlckNsYXNzKSB7XG4gIGV4dGVuZChEZWZhdWx0R2VuZXJhdG9yLCBzdXBlckNsYXNzKTtcblxuICBmdW5jdGlvbiBEZWZhdWx0R2VuZXJhdG9yKG9wdHMpIHtcbiAgICB0aGlzLm9wdHMgPSB1dGlsLmRlZmF1bHRzKG9wdHMsIERlZmF1bHRPcHRzKTtcbiAgICB0aGlzLlZpYnJhbnRTd2F0Y2ggPSBudWxsO1xuICAgIHRoaXMuTGlnaHRWaWJyYW50U3dhdGNoID0gbnVsbDtcbiAgICB0aGlzLkRhcmtWaWJyYW50U3dhdGNoID0gbnVsbDtcbiAgICB0aGlzLk11dGVkU3dhdGNoID0gbnVsbDtcbiAgICB0aGlzLkxpZ2h0TXV0ZWRTd2F0Y2ggPSBudWxsO1xuICAgIHRoaXMuRGFya011dGVkU3dhdGNoID0gbnVsbDtcbiAgfVxuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdlbmVyYXRlID0gZnVuY3Rpb24oc3dhdGNoZXMpIHtcbiAgICB0aGlzLnN3YXRjaGVzID0gc3dhdGNoZXM7XG4gICAgdGhpcy5tYXhQb3B1bGF0aW9uID0gdGhpcy5maW5kTWF4UG9wdWxhdGlvbigpO1xuICAgIHRoaXMuZ2VuZXJhdGVWYXJhdGlvbkNvbG9ycygpO1xuICAgIHJldHVybiB0aGlzLmdlbmVyYXRlRW1wdHlTd2F0Y2hlcygpO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldFZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5WaWJyYW50U3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldExpZ2h0VmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLkxpZ2h0VmlicmFudFN3YXRjaDtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZXREYXJrVmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLkRhcmtWaWJyYW50U3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdldE11dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuTXV0ZWRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TGlnaHRNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLkxpZ2h0TXV0ZWRTd2F0Y2g7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0RGFya011dGVkU3dhdGNoID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuRGFya011dGVkU3dhdGNoO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmdlbmVyYXRlVmFyYXRpb25Db2xvcnMgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLlZpYnJhbnRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0Tm9ybWFsTHVtYSwgdGhpcy5vcHRzLm1pbk5vcm1hbEx1bWEsIHRoaXMub3B0cy5tYXhOb3JtYWxMdW1hLCB0aGlzLm9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIHRoaXMub3B0cy5taW5WaWJyYW50U2F0dXJhdGlvbiwgMSk7XG4gICAgdGhpcy5MaWdodFZpYnJhbnRTd2F0Y2ggPSB0aGlzLmZpbmRDb2xvclZhcmlhdGlvbih0aGlzLm9wdHMudGFyZ2V0TGlnaHRMdW1hLCB0aGlzLm9wdHMubWluTGlnaHRMdW1hLCAxLCB0aGlzLm9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIHRoaXMub3B0cy5taW5WaWJyYW50U2F0dXJhdGlvbiwgMSk7XG4gICAgdGhpcy5EYXJrVmlicmFudFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXREYXJrTHVtYSwgMCwgdGhpcy5vcHRzLm1heERhcmtMdW1hLCB0aGlzLm9wdHMudGFyZ2V0VmlicmFudFNhdHVyYXRpb24sIHRoaXMub3B0cy5taW5WaWJyYW50U2F0dXJhdGlvbiwgMSk7XG4gICAgdGhpcy5NdXRlZFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXROb3JtYWxMdW1hLCB0aGlzLm9wdHMubWluTm9ybWFsTHVtYSwgdGhpcy5vcHRzLm1heE5vcm1hbEx1bWEsIHRoaXMub3B0cy50YXJnZXRNdXRlc1NhdHVyYXRpb24sIDAsIHRoaXMub3B0cy5tYXhNdXRlc1NhdHVyYXRpb24pO1xuICAgIHRoaXMuTGlnaHRNdXRlZFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXRMaWdodEx1bWEsIHRoaXMub3B0cy5taW5MaWdodEx1bWEsIDEsIHRoaXMub3B0cy50YXJnZXRNdXRlc1NhdHVyYXRpb24sIDAsIHRoaXMub3B0cy5tYXhNdXRlc1NhdHVyYXRpb24pO1xuICAgIHJldHVybiB0aGlzLkRhcmtNdXRlZFN3YXRjaCA9IHRoaXMuZmluZENvbG9yVmFyaWF0aW9uKHRoaXMub3B0cy50YXJnZXREYXJrTHVtYSwgMCwgdGhpcy5vcHRzLm1heERhcmtMdW1hLCB0aGlzLm9wdHMudGFyZ2V0TXV0ZXNTYXR1cmF0aW9uLCAwLCB0aGlzLm9wdHMubWF4TXV0ZXNTYXR1cmF0aW9uKTtcbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5nZW5lcmF0ZUVtcHR5U3dhdGNoZXMgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgaHNsO1xuICAgIGlmICh0aGlzLlZpYnJhbnRTd2F0Y2ggPT09IG51bGwpIHtcbiAgICAgIGlmICh0aGlzLkRhcmtWaWJyYW50U3dhdGNoICE9PSBudWxsKSB7XG4gICAgICAgIGhzbCA9IHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2guZ2V0SHNsKCk7XG4gICAgICAgIGhzbFsyXSA9IHRoaXMub3B0cy50YXJnZXROb3JtYWxMdW1hO1xuICAgICAgICB0aGlzLlZpYnJhbnRTd2F0Y2ggPSBuZXcgU3dhdGNoKHV0aWwuaHNsVG9SZ2IoaHNsWzBdLCBoc2xbMV0sIGhzbFsyXSksIDApO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAodGhpcy5EYXJrVmlicmFudFN3YXRjaCA9PT0gbnVsbCkge1xuICAgICAgaWYgKHRoaXMuVmlicmFudFN3YXRjaCAhPT0gbnVsbCkge1xuICAgICAgICBoc2wgPSB0aGlzLlZpYnJhbnRTd2F0Y2guZ2V0SHNsKCk7XG4gICAgICAgIGhzbFsyXSA9IHRoaXMub3B0cy50YXJnZXREYXJrTHVtYTtcbiAgICAgICAgcmV0dXJuIHRoaXMuRGFya1ZpYnJhbnRTd2F0Y2ggPSBuZXcgU3dhdGNoKHV0aWwuaHNsVG9SZ2IoaHNsWzBdLCBoc2xbMV0sIGhzbFsyXSksIDApO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICBEZWZhdWx0R2VuZXJhdG9yLnByb3RvdHlwZS5maW5kTWF4UG9wdWxhdGlvbiA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBqLCBsZW4sIHBvcHVsYXRpb24sIHJlZiwgc3dhdGNoO1xuICAgIHBvcHVsYXRpb24gPSAwO1xuICAgIHJlZiA9IHRoaXMuc3dhdGNoZXM7XG4gICAgZm9yIChqID0gMCwgbGVuID0gcmVmLmxlbmd0aDsgaiA8IGxlbjsgaisrKSB7XG4gICAgICBzd2F0Y2ggPSByZWZbal07XG4gICAgICBwb3B1bGF0aW9uID0gTWF0aC5tYXgocG9wdWxhdGlvbiwgc3dhdGNoLmdldFBvcHVsYXRpb24oKSk7XG4gICAgfVxuICAgIHJldHVybiBwb3B1bGF0aW9uO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmZpbmRDb2xvclZhcmlhdGlvbiA9IGZ1bmN0aW9uKHRhcmdldEx1bWEsIG1pbkx1bWEsIG1heEx1bWEsIHRhcmdldFNhdHVyYXRpb24sIG1pblNhdHVyYXRpb24sIG1heFNhdHVyYXRpb24pIHtcbiAgICB2YXIgaiwgbGVuLCBsdW1hLCBtYXgsIG1heFZhbHVlLCByZWYsIHNhdCwgc3dhdGNoLCB2YWx1ZTtcbiAgICBtYXggPSBudWxsO1xuICAgIG1heFZhbHVlID0gMDtcbiAgICByZWYgPSB0aGlzLnN3YXRjaGVzO1xuICAgIGZvciAoaiA9IDAsIGxlbiA9IHJlZi5sZW5ndGg7IGogPCBsZW47IGorKykge1xuICAgICAgc3dhdGNoID0gcmVmW2pdO1xuICAgICAgc2F0ID0gc3dhdGNoLmdldEhzbCgpWzFdO1xuICAgICAgbHVtYSA9IHN3YXRjaC5nZXRIc2woKVsyXTtcbiAgICAgIGlmIChzYXQgPj0gbWluU2F0dXJhdGlvbiAmJiBzYXQgPD0gbWF4U2F0dXJhdGlvbiAmJiBsdW1hID49IG1pbkx1bWEgJiYgbHVtYSA8PSBtYXhMdW1hICYmICF0aGlzLmlzQWxyZWFkeVNlbGVjdGVkKHN3YXRjaCkpIHtcbiAgICAgICAgdmFsdWUgPSB0aGlzLmNyZWF0ZUNvbXBhcmlzb25WYWx1ZShzYXQsIHRhcmdldFNhdHVyYXRpb24sIGx1bWEsIHRhcmdldEx1bWEsIHN3YXRjaC5nZXRQb3B1bGF0aW9uKCksIHRoaXMubWF4UG9wdWxhdGlvbik7XG4gICAgICAgIGlmIChtYXggPT09IG51bGwgfHwgdmFsdWUgPiBtYXhWYWx1ZSkge1xuICAgICAgICAgIG1heCA9IHN3YXRjaDtcbiAgICAgICAgICBtYXhWYWx1ZSA9IHZhbHVlO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBtYXg7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuY3JlYXRlQ29tcGFyaXNvblZhbHVlID0gZnVuY3Rpb24oc2F0dXJhdGlvbiwgdGFyZ2V0U2F0dXJhdGlvbiwgbHVtYSwgdGFyZ2V0THVtYSwgcG9wdWxhdGlvbiwgbWF4UG9wdWxhdGlvbikge1xuICAgIHJldHVybiB0aGlzLndlaWdodGVkTWVhbih0aGlzLmludmVydERpZmYoc2F0dXJhdGlvbiwgdGFyZ2V0U2F0dXJhdGlvbiksIHRoaXMub3B0cy53ZWlnaHRTYXR1cmF0aW9uLCB0aGlzLmludmVydERpZmYobHVtYSwgdGFyZ2V0THVtYSksIHRoaXMub3B0cy53ZWlnaHRMdW1hLCBwb3B1bGF0aW9uIC8gbWF4UG9wdWxhdGlvbiwgdGhpcy5vcHRzLndlaWdodFBvcHVsYXRpb24pO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLmludmVydERpZmYgPSBmdW5jdGlvbih2YWx1ZSwgdGFyZ2V0VmFsdWUpIHtcbiAgICByZXR1cm4gMSAtIE1hdGguYWJzKHZhbHVlIC0gdGFyZ2V0VmFsdWUpO1xuICB9O1xuXG4gIERlZmF1bHRHZW5lcmF0b3IucHJvdG90eXBlLndlaWdodGVkTWVhbiA9IGZ1bmN0aW9uKCkge1xuICAgIHZhciBpLCBzdW0sIHN1bVdlaWdodCwgdmFsdWUsIHZhbHVlcywgd2VpZ2h0O1xuICAgIHZhbHVlcyA9IDEgPD0gYXJndW1lbnRzLmxlbmd0aCA/IHNsaWNlLmNhbGwoYXJndW1lbnRzLCAwKSA6IFtdO1xuICAgIHN1bSA9IDA7XG4gICAgc3VtV2VpZ2h0ID0gMDtcbiAgICBpID0gMDtcbiAgICB3aGlsZSAoaSA8IHZhbHVlcy5sZW5ndGgpIHtcbiAgICAgIHZhbHVlID0gdmFsdWVzW2ldO1xuICAgICAgd2VpZ2h0ID0gdmFsdWVzW2kgKyAxXTtcbiAgICAgIHN1bSArPSB2YWx1ZSAqIHdlaWdodDtcbiAgICAgIHN1bVdlaWdodCArPSB3ZWlnaHQ7XG4gICAgICBpICs9IDI7XG4gICAgfVxuICAgIHJldHVybiBzdW0gLyBzdW1XZWlnaHQ7XG4gIH07XG5cbiAgRGVmYXVsdEdlbmVyYXRvci5wcm90b3R5cGUuaXNBbHJlYWR5U2VsZWN0ZWQgPSBmdW5jdGlvbihzd2F0Y2gpIHtcbiAgICByZXR1cm4gdGhpcy5WaWJyYW50U3dhdGNoID09PSBzd2F0Y2ggfHwgdGhpcy5EYXJrVmlicmFudFN3YXRjaCA9PT0gc3dhdGNoIHx8IHRoaXMuTGlnaHRWaWJyYW50U3dhdGNoID09PSBzd2F0Y2ggfHwgdGhpcy5NdXRlZFN3YXRjaCA9PT0gc3dhdGNoIHx8IHRoaXMuRGFya011dGVkU3dhdGNoID09PSBzd2F0Y2ggfHwgdGhpcy5MaWdodE11dGVkU3dhdGNoID09PSBzd2F0Y2g7XG4gIH07XG5cbiAgcmV0dXJuIERlZmF1bHRHZW5lcmF0b3I7XG5cbn0pKEdlbmVyYXRvcik7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZaMlZ1WlhKaGRHOXlMMlJsWm1GMWJIUXVZMjltWm1WbElpd2ljMjkxY21ObFVtOXZkQ0k2SWlJc0luTnZkWEpqWlhNaU9sc2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12WjJWdVpYSmhkRzl5TDJSbFptRjFiSFF1WTI5bVptVmxJbDBzSW01aGJXVnpJanBiWFN3aWJXRndjR2x1WjNNaU9pSkJRVUZCTEVsQlFVRXNjMFJCUVVFN1JVRkJRVHM3T3p0QlFVRkJMRTFCUVVFc1IwRkJVeXhQUVVGQkxFTkJRVkVzVjBGQlVqczdRVUZEVkN4SlFVRkJMRWRCUVU4c1QwRkJRU3hEUVVGUkxGTkJRVkk3TzBGQlExQXNVMEZCUVN4SFFVRlpMRTlCUVVFc1EwRkJVU3hUUVVGU096dEJRVVZhTEZkQlFVRXNSMEZEUlR0RlFVRkJMR05CUVVFc1JVRkJaMElzU1VGQmFFSTdSVUZEUVN4WFFVRkJMRVZCUVdFc1NVRkVZanRGUVVWQkxGbEJRVUVzUlVGQll5eEpRVVprTzBWQlIwRXNaVUZCUVN4RlFVRnBRaXhKUVVocVFqdEZRVWxCTEdGQlFVRXNSVUZCWlN4SFFVcG1PMFZCUzBFc1owSkJRVUVzUlVGQmEwSXNSMEZNYkVJN1JVRk5RU3hoUVVGQkxFVkJRV1VzUjBGT1pqdEZRVTlCTEhGQ1FVRkJMRVZCUVhWQ0xFZEJVSFpDTzBWQlVVRXNhMEpCUVVFc1JVRkJiMElzUjBGU2NFSTdSVUZUUVN4MVFrRkJRU3hGUVVGNVFpeEhRVlI2UWp0RlFWVkJMRzlDUVVGQkxFVkJRWE5DTEVsQlZuUkNPMFZCVjBFc1owSkJRVUVzUlVGQmEwSXNRMEZZYkVJN1JVRlpRU3hWUVVGQkxFVkJRVmtzUTBGYVdqdEZRV0ZCTEdkQ1FVRkJMRVZCUVd0Q0xFTkJZbXhDT3pzN1FVRmxSaXhOUVVGTkxFTkJRVU1zVDBGQlVDeEhRVU5OT3pzN1JVRkRVeXd3UWtGQlF5eEpRVUZFTzBsQlExZ3NTVUZCUXl4RFFVRkJMRWxCUVVRc1IwRkJVU3hKUVVGSkxFTkJRVU1zVVVGQlRDeERRVUZqTEVsQlFXUXNSVUZCYjBJc1YwRkJjRUk3U1VGRFVpeEpRVUZETEVOQlFVRXNZVUZCUkN4SFFVRnBRanRKUVVOcVFpeEpRVUZETEVOQlFVRXNhMEpCUVVRc1IwRkJjMEk3U1VGRGRFSXNTVUZCUXl4RFFVRkJMR2xDUVVGRUxFZEJRWEZDTzBsQlEzSkNMRWxCUVVNc1EwRkJRU3hYUVVGRUxFZEJRV1U3U1VGRFppeEpRVUZETEVOQlFVRXNaMEpCUVVRc1IwRkJiMEk3U1VGRGNFSXNTVUZCUXl4RFFVRkJMR1ZCUVVRc1IwRkJiVUk3UlVGUVVqczdOa0pCVTJJc1VVRkJRU3hIUVVGVkxGTkJRVU1zVVVGQlJEdEpRVUZETEVsQlFVTXNRMEZCUVN4WFFVRkVPMGxCUTFRc1NVRkJReXhEUVVGQkxHRkJRVVFzUjBGQmFVSXNTVUZCUXl4RFFVRkJMR2xDUVVGRUxFTkJRVUU3U1VGRmFrSXNTVUZCUXl4RFFVRkJMSE5DUVVGRUxFTkJRVUU3VjBGRFFTeEpRVUZETEVOQlFVRXNjVUpCUVVRc1EwRkJRVHRGUVVwUk96czJRa0ZOVml4blFrRkJRU3hIUVVGclFpeFRRVUZCTzFkQlEyaENMRWxCUVVNc1EwRkJRVHRGUVVSbE96czJRa0ZIYkVJc2NVSkJRVUVzUjBGQmRVSXNVMEZCUVR0WFFVTnlRaXhKUVVGRExFTkJRVUU3UlVGRWIwSTdPelpDUVVkMlFpeHZRa0ZCUVN4SFFVRnpRaXhUUVVGQk8xZEJRM0JDTEVsQlFVTXNRMEZCUVR0RlFVUnRRanM3TmtKQlIzUkNMR05CUVVFc1IwRkJaMElzVTBGQlFUdFhRVU5rTEVsQlFVTXNRMEZCUVR0RlFVUmhPenMyUWtGSGFFSXNiVUpCUVVFc1IwRkJjVUlzVTBGQlFUdFhRVU51UWl4SlFVRkRMRU5CUVVFN1JVRkVhMEk3T3paQ1FVZHlRaXhyUWtGQlFTeEhRVUZ2UWl4VFFVRkJPMWRCUTJ4Q0xFbEJRVU1zUTBGQlFUdEZRVVJwUWpzN05rSkJSM0JDTEhOQ1FVRkJMRWRCUVhkQ0xGTkJRVUU3U1VGRGRFSXNTVUZCUXl4RFFVRkJMR0ZCUVVRc1IwRkJhVUlzU1VGQlF5eERRVUZCTEd0Q1FVRkVMRU5CUVc5Q0xFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNaMEpCUVRGQ0xFVkJRVFJETEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1lVRkJiRVFzUlVGQmFVVXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhoUVVGMlJTeEZRVU5tTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc2RVSkJSRk1zUlVGRFowSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXh2UWtGRWRFSXNSVUZETkVNc1EwRkVOVU03U1VGSGFrSXNTVUZCUXl4RFFVRkJMR3RDUVVGRUxFZEJRWE5DTEVsQlFVTXNRMEZCUVN4clFrRkJSQ3hEUVVGdlFpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR1ZCUVRGQ0xFVkJRVEpETEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1dVRkJha1FzUlVGQkswUXNRMEZCTDBRc1JVRkRjRUlzU1VGQlF5eERRVUZCTEVsQlFVa3NRMEZCUXl4MVFrRkVZeXhGUVVOWExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNiMEpCUkdwQ0xFVkJRM1ZETEVOQlJIWkRPMGxCUjNSQ0xFbEJRVU1zUTBGQlFTeHBRa0ZCUkN4SFFVRnhRaXhKUVVGRExFTkJRVUVzYTBKQlFVUXNRMEZCYjBJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eGpRVUV4UWl4RlFVRXdReXhEUVVFeFF5eEZRVUUyUXl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGZEJRVzVFTEVWQlEyNUNMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zZFVKQlJHRXNSVUZEV1N4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExHOUNRVVJzUWl4RlFVTjNReXhEUVVSNFF6dEpRVWR5UWl4SlFVRkRMRU5CUVVFc1YwRkJSQ3hIUVVGbExFbEJRVU1zUTBGQlFTeHJRa0ZCUkN4RFFVRnZRaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEdkQ1FVRXhRaXhGUVVFMFF5eEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR0ZCUVd4RUxFVkJRV2xGTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1lVRkJka1VzUlVGRFlpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMSEZDUVVSUExFVkJRMmRDTEVOQlJHaENMRVZCUTIxQ0xFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNhMEpCUkhwQ08wbEJSMllzU1VGQlF5eERRVUZCTEdkQ1FVRkVMRWRCUVc5Q0xFbEJRVU1zUTBGQlFTeHJRa0ZCUkN4RFFVRnZRaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEdWQlFURkNMRVZCUVRKRExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNXVUZCYWtRc1JVRkJLMFFzUTBGQkwwUXNSVUZEYkVJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eHhRa0ZFV1N4RlFVTlhMRU5CUkZnc1JVRkRZeXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEd0Q1FVUndRanRYUVVkd1FpeEpRVUZETEVOQlFVRXNaVUZCUkN4SFFVRnRRaXhKUVVGRExFTkJRVUVzYTBKQlFVUXNRMEZCYjBJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eGpRVUV4UWl4RlFVRXdReXhEUVVFeFF5eEZRVUUyUXl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGZEJRVzVFTEVWQlEycENMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zY1VKQlJGY3NSVUZEV1N4RFFVUmFMRVZCUTJVc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eHJRa0ZFY2tJN1JVRm9Ra2M3T3paQ1FXMUNlRUlzY1VKQlFVRXNSMEZCZFVJc1UwRkJRVHRCUVVOeVFpeFJRVUZCTzBsQlFVRXNTVUZCUnl4SlFVRkRMRU5CUVVFc1lVRkJSQ3hMUVVGclFpeEpRVUZ5UWp0TlFVVkZMRWxCUVVjc1NVRkJReXhEUVVGQkxHbENRVUZFTEV0QlFYZENMRWxCUVROQ08xRkJSVVVzUjBGQlFTeEhRVUZOTEVsQlFVTXNRMEZCUVN4cFFrRkJhVUlzUTBGQlF5eE5RVUZ1UWl4RFFVRkJPMUZCUTA0c1IwRkJTU3hEUVVGQkxFTkJRVUVzUTBGQlNpeEhRVUZUTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNN1VVRkRaaXhKUVVGRExFTkJRVUVzWVVGQlJDeEhRVUZwUWl4SlFVRkpMRTFCUVVvc1EwRkJWeXhKUVVGSkxFTkJRVU1zVVVGQlRDeERRVUZqTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVd4Q0xFVkJRWE5DTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVRGQ0xFVkJRVGhDTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVd4RExFTkJRVmdzUlVGQmEwUXNRMEZCYkVRc1JVRktia0k3VDBGR1JqczdTVUZSUVN4SlFVRkhMRWxCUVVNc1EwRkJRU3hwUWtGQlJDeExRVUZ6UWl4SlFVRjZRanROUVVWRkxFbEJRVWNzU1VGQlF5eERRVUZCTEdGQlFVUXNTMEZCYjBJc1NVRkJka0k3VVVGRlJTeEhRVUZCTEVkQlFVMHNTVUZCUXl4RFFVRkJMR0ZCUVdFc1EwRkJReXhOUVVGbUxFTkJRVUU3VVVGRFRpeEhRVUZKTEVOQlFVRXNRMEZCUVN4RFFVRktMRWRCUVZNc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF6dGxRVU5tTEVsQlFVTXNRMEZCUVN4cFFrRkJSQ3hIUVVGeFFpeEpRVUZKTEUxQlFVb3NRMEZCVnl4SlFVRkpMRU5CUVVNc1VVRkJUQ3hEUVVGakxFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFXeENMRVZCUVhOQ0xFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFURkNMRVZCUVRoQ0xFZEJRVWtzUTBGQlFTeERRVUZCTEVOQlFXeERMRU5CUVZnc1JVRkJhMFFzUTBGQmJFUXNSVUZLZGtJN1QwRkdSanM3UlVGVWNVSTdPelpDUVdsQ2RrSXNhVUpCUVVFc1IwRkJiVUlzVTBGQlFUdEJRVU5xUWl4UlFVRkJPMGxCUVVFc1ZVRkJRU3hIUVVGaE8wRkJRMkk3UVVGQlFTeFRRVUZCTEhGRFFVRkJPenROUVVGQkxGVkJRVUVzUjBGQllTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRlZCUVZRc1JVRkJjVUlzVFVGQlRTeERRVUZETEdGQlFWQXNRMEZCUVN4RFFVRnlRanRCUVVGaU8xZEJRMEU3UlVGSWFVSTdPelpDUVV0dVFpeHJRa0ZCUVN4SFFVRnZRaXhUUVVGRExGVkJRVVFzUlVGQllTeFBRVUZpTEVWQlFYTkNMRTlCUVhSQ0xFVkJRU3RDTEdkQ1FVRXZRaXhGUVVGcFJDeGhRVUZxUkN4RlFVRm5SU3hoUVVGb1JUdEJRVU5zUWl4UlFVRkJPMGxCUVVFc1IwRkJRU3hIUVVGTk8wbEJRMDRzVVVGQlFTeEhRVUZYTzBGQlJWZzdRVUZCUVN4VFFVRkJMSEZEUVVGQk96dE5RVU5GTEVkQlFVRXNSMEZCVFN4TlFVRk5MRU5CUVVNc1RVRkJVQ3hEUVVGQkxFTkJRV2RDTEVOQlFVRXNRMEZCUVR0TlFVTjBRaXhKUVVGQkxFZEJRVThzVFVGQlRTeERRVUZETEUxQlFWQXNRMEZCUVN4RFFVRm5RaXhEUVVGQkxFTkJRVUU3VFVGRmRrSXNTVUZCUnl4SFFVRkJMRWxCUVU4c1lVRkJVQ3hKUVVGNVFpeEhRVUZCTEVsQlFVOHNZVUZCYUVNc1NVRkRSQ3hKUVVGQkxFbEJRVkVzVDBGRVVDeEpRVU50UWl4SlFVRkJMRWxCUVZFc1QwRkVNMElzU1VGRlJDeERRVUZKTEVsQlFVTXNRMEZCUVN4cFFrRkJSQ3hEUVVGdFFpeE5RVUZ1UWl4RFFVWk9PMUZCUjBrc1MwRkJRU3hIUVVGUkxFbEJRVU1zUTBGQlFTeHhRa0ZCUkN4RFFVRjFRaXhIUVVGMlFpeEZRVUUwUWl4blFrRkJOVUlzUlVGQk9FTXNTVUZCT1VNc1JVRkJiMFFzVlVGQmNFUXNSVUZEVGl4TlFVRk5MRU5CUVVNc1lVRkJVQ3hEUVVGQkxFTkJSRTBzUlVGRGEwSXNTVUZCUXl4RFFVRkJMR0ZCUkc1Q08xRkJSVklzU1VGQlJ5eEhRVUZCTEV0QlFVOHNTVUZCVUN4SlFVRmxMRXRCUVVFc1IwRkJVU3hSUVVFeFFqdFZRVU5GTEVkQlFVRXNSMEZCVFR0VlFVTk9MRkZCUVVFc1IwRkJWeXhOUVVaaU8xTkJURW83TzBGQlNrWTdWMEZoUVR0RlFXcENhMEk3T3paQ1FXMUNjRUlzY1VKQlFVRXNSMEZCZFVJc1UwRkJReXhWUVVGRUxFVkJRV0VzWjBKQlFXSXNSVUZEYmtJc1NVRkViVUlzUlVGRFlpeFZRVVJoTEVWQlEwUXNWVUZFUXl4RlFVTlhMR0ZCUkZnN1YwRkZja0lzU1VGQlF5eERRVUZCTEZsQlFVUXNRMEZEUlN4SlFVRkRMRU5CUVVFc1ZVRkJSQ3hEUVVGWkxGVkJRVm9zUlVGQmQwSXNaMEpCUVhoQ0xFTkJSRVlzUlVGRE5rTXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhuUWtGRWJrUXNSVUZGUlN4SlFVRkRMRU5CUVVFc1ZVRkJSQ3hEUVVGWkxFbEJRVm9zUlVGQmEwSXNWVUZCYkVJc1EwRkdSaXhGUVVWcFF5eEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRlZCUm5aRExFVkJSMFVzVlVGQlFTeEhRVUZoTEdGQlNHWXNSVUZIT0VJc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eG5Ra0ZJY0VNN1JVRkdjVUk3T3paQ1FWRjJRaXhWUVVGQkxFZEJRVmtzVTBGQlF5eExRVUZFTEVWQlFWRXNWMEZCVWp0WFFVTldMRU5CUVVFc1IwRkJTU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEV0QlFVRXNSMEZCVVN4WFFVRnFRanRGUVVSTk96czJRa0ZIV2l4WlFVRkJMRWRCUVdNc1UwRkJRVHRCUVVOYUxGRkJRVUU3U1VGRVlUdEpRVU5pTEVkQlFVRXNSMEZCVFR0SlFVTk9MRk5CUVVFc1IwRkJXVHRKUVVOYUxFTkJRVUVzUjBGQlNUdEJRVU5LTEZkQlFVMHNRMEZCUVN4SFFVRkpMRTFCUVUwc1EwRkJReXhOUVVGcVFqdE5RVU5GTEV0QlFVRXNSMEZCVVN4TlFVRlBMRU5CUVVFc1EwRkJRVHROUVVObUxFMUJRVUVzUjBGQlV5eE5RVUZQTEVOQlFVRXNRMEZCUVN4SFFVRkpMRU5CUVVvN1RVRkRhRUlzUjBGQlFTeEpRVUZQTEV0QlFVRXNSMEZCVVR0TlFVTm1MRk5CUVVFc1NVRkJZVHROUVVOaUxFTkJRVUVzU1VGQlN6dEpRVXhRTzFkQlRVRXNSMEZCUVN4SFFVRk5PMFZCVmswN096WkNRVmxrTEdsQ1FVRkJMRWRCUVcxQ0xGTkJRVU1zVFVGQlJEdFhRVU5xUWl4SlFVRkRMRU5CUVVFc1lVRkJSQ3hMUVVGclFpeE5RVUZzUWl4SlFVRTBRaXhKUVVGRExFTkJRVUVzYVVKQlFVUXNTMEZCYzBJc1RVRkJiRVFzU1VGRFJTeEpRVUZETEVOQlFVRXNhMEpCUVVRc1MwRkJkVUlzVFVGRWVrSXNTVUZEYlVNc1NVRkJReXhEUVVGQkxGZEJRVVFzUzBGQlowSXNUVUZFYmtRc1NVRkZSU3hKUVVGRExFTkJRVUVzWlVGQlJDeExRVUZ2UWl4TlFVWjBRaXhKUVVWblF5eEpRVUZETEVOQlFVRXNaMEpCUVVRc1MwRkJjVUk3UlVGSWNFTTdPenM3UjBGeVNGVWlmUT09XG4iLCJ2YXIgR2VuZXJhdG9yO1xuXG5tb2R1bGUuZXhwb3J0cyA9IEdlbmVyYXRvciA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gR2VuZXJhdG9yKCkge31cblxuICBHZW5lcmF0b3IucHJvdG90eXBlLmdlbmVyYXRlID0gZnVuY3Rpb24oc3dhdGNoZXMpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0VmlicmFudFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXRMaWdodFZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0RGFya1ZpYnJhbnRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEdlbmVyYXRvci5wcm90b3R5cGUuZ2V0TGlnaHRNdXRlZFN3YXRjaCA9IGZ1bmN0aW9uKCkge307XG5cbiAgR2VuZXJhdG9yLnByb3RvdHlwZS5nZXREYXJrTXV0ZWRTd2F0Y2ggPSBmdW5jdGlvbigpIHt9O1xuXG4gIHJldHVybiBHZW5lcmF0b3I7XG5cbn0pKCk7XG5cbm1vZHVsZS5leHBvcnRzLkRlZmF1bHQgPSByZXF1aXJlKCcuL2RlZmF1bHQnKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdloyVnVaWEpoZEc5eUwybHVaR1Y0TG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwyZGxibVZ5WVhSdmNpOXBibVJsZUM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1NVRkJRVHM3UVVGQlFTeE5RVUZOTEVOQlFVTXNUMEZCVUN4SFFVTk5PenM3YzBKQlEwb3NVVUZCUVN4SFFVRlZMRk5CUVVNc1VVRkJSQ3hIUVVGQk96dHpRa0ZGVml4blFrRkJRU3hIUVVGclFpeFRRVUZCTEVkQlFVRTdPM05DUVVWc1FpeHhRa0ZCUVN4SFFVRjFRaXhUUVVGQkxFZEJRVUU3TzNOQ1FVVjJRaXh2UWtGQlFTeEhRVUZ6UWl4VFFVRkJMRWRCUVVFN08zTkNRVVYwUWl4alFVRkJMRWRCUVdkQ0xGTkJRVUVzUjBGQlFUczdjMEpCUldoQ0xHMUNRVUZCTEVkQlFYRkNMRk5CUVVFc1IwRkJRVHM3YzBKQlJYSkNMR3RDUVVGQkxFZEJRVzlDTEZOQlFVRXNSMEZCUVRzN096czdPMEZCUlhSQ0xFMUJRVTBzUTBGQlF5eFBRVUZQTEVOQlFVTXNUMEZCWml4SFFVRjVRaXhQUVVGQkxFTkJRVkVzVjBGQlVpSjlcbiIsInZhciBCcm93c2VySW1hZ2UsIEltYWdlLCBVcmwsIGlzUmVsYXRpdmVVcmwsIGlzU2FtZU9yaWdpbixcbiAgZXh0ZW5kID0gZnVuY3Rpb24oY2hpbGQsIHBhcmVudCkgeyBmb3IgKHZhciBrZXkgaW4gcGFyZW50KSB7IGlmIChoYXNQcm9wLmNhbGwocGFyZW50LCBrZXkpKSBjaGlsZFtrZXldID0gcGFyZW50W2tleV07IH0gZnVuY3Rpb24gY3RvcigpIHsgdGhpcy5jb25zdHJ1Y3RvciA9IGNoaWxkOyB9IGN0b3IucHJvdG90eXBlID0gcGFyZW50LnByb3RvdHlwZTsgY2hpbGQucHJvdG90eXBlID0gbmV3IGN0b3IoKTsgY2hpbGQuX19zdXBlcl9fID0gcGFyZW50LnByb3RvdHlwZTsgcmV0dXJuIGNoaWxkOyB9LFxuICBoYXNQcm9wID0ge30uaGFzT3duUHJvcGVydHk7XG5cbkltYWdlID0gcmVxdWlyZSgnLi9pbmRleCcpO1xuXG5VcmwgPSByZXF1aXJlKCd1cmwnKTtcblxuaXNSZWxhdGl2ZVVybCA9IGZ1bmN0aW9uKHVybCkge1xuICB2YXIgdTtcbiAgdSA9IFVybC5wYXJzZSh1cmwpO1xuICByZXR1cm4gdS5wcm90b2NvbCA9PT0gbnVsbCAmJiB1Lmhvc3QgPT09IG51bGwgJiYgdS5wb3J0ID09PSBudWxsO1xufTtcblxuaXNTYW1lT3JpZ2luID0gZnVuY3Rpb24oYSwgYikge1xuICB2YXIgdWEsIHViO1xuICB1YSA9IFVybC5wYXJzZShhKTtcbiAgdWIgPSBVcmwucGFyc2UoYik7XG4gIHJldHVybiB1YS5wcm90b2NvbCA9PT0gdWIucHJvdG9jb2wgJiYgdWEuaG9zdG5hbWUgPT09IHViLmhvc3RuYW1lICYmIHVhLnBvcnQgPT09IHViLnBvcnQ7XG59O1xuXG5tb2R1bGUuZXhwb3J0cyA9IEJyb3dzZXJJbWFnZSA9IChmdW5jdGlvbihzdXBlckNsYXNzKSB7XG4gIGV4dGVuZChCcm93c2VySW1hZ2UsIHN1cGVyQ2xhc3MpO1xuXG4gIGZ1bmN0aW9uIEJyb3dzZXJJbWFnZShwYXRoLCBjYikge1xuICAgIGlmICh0eXBlb2YgcGF0aCA9PT0gJ29iamVjdCcgJiYgcGF0aCBpbnN0YW5jZW9mIEhUTUxJbWFnZUVsZW1lbnQpIHtcbiAgICAgIHRoaXMuaW1nID0gcGF0aDtcbiAgICAgIHBhdGggPSB0aGlzLmltZy5zcmM7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMuaW1nID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaW1nJyk7XG4gICAgICB0aGlzLmltZy5zcmMgPSBwYXRoO1xuICAgIH1cbiAgICBpZiAoIWlzUmVsYXRpdmVVcmwocGF0aCkgJiYgIWlzU2FtZU9yaWdpbih3aW5kb3cubG9jYXRpb24uaHJlZiwgcGF0aCkpIHtcbiAgICAgIHRoaXMuaW1nLmNyb3NzT3JpZ2luID0gJ2Fub255bW91cyc7XG4gICAgfVxuICAgIHRoaXMuaW1nLm9ubG9hZCA9IChmdW5jdGlvbihfdGhpcykge1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uKCkge1xuICAgICAgICBfdGhpcy5faW5pdENhbnZhcygpO1xuICAgICAgICByZXR1cm4gdHlwZW9mIGNiID09PSBcImZ1bmN0aW9uXCIgPyBjYihudWxsLCBfdGhpcykgOiB2b2lkIDA7XG4gICAgICB9O1xuICAgIH0pKHRoaXMpO1xuICAgIGlmICh0aGlzLmltZy5jb21wbGV0ZSkge1xuICAgICAgdGhpcy5pbWcub25sb2FkKCk7XG4gICAgfVxuICAgIHRoaXMuaW1nLm9uZXJyb3IgPSAoZnVuY3Rpb24oX3RoaXMpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihlKSB7XG4gICAgICAgIHZhciBlcnI7XG4gICAgICAgIGVyciA9IG5ldyBFcnJvcihcIkZhaWwgdG8gbG9hZCBpbWFnZTogXCIgKyBwYXRoKTtcbiAgICAgICAgZXJyLnJhdyA9IGU7XG4gICAgICAgIHJldHVybiB0eXBlb2YgY2IgPT09IFwiZnVuY3Rpb25cIiA/IGNiKGVycikgOiB2b2lkIDA7XG4gICAgICB9O1xuICAgIH0pKHRoaXMpO1xuICB9XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5faW5pdENhbnZhcyA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuY2FudmFzID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnY2FudmFzJyk7XG4gICAgdGhpcy5jb250ZXh0ID0gdGhpcy5jYW52YXMuZ2V0Q29udGV4dCgnMmQnKTtcbiAgICBkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKHRoaXMuY2FudmFzKTtcbiAgICB0aGlzLndpZHRoID0gdGhpcy5jYW52YXMud2lkdGggPSB0aGlzLmltZy53aWR0aDtcbiAgICB0aGlzLmhlaWdodCA9IHRoaXMuY2FudmFzLmhlaWdodCA9IHRoaXMuaW1nLmhlaWdodDtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0LmRyYXdJbWFnZSh0aGlzLmltZywgMCwgMCwgdGhpcy53aWR0aCwgdGhpcy5oZWlnaHQpO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuY2xlYXIgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0LmNsZWFyUmVjdCgwLCAwLCB0aGlzLndpZHRoLCB0aGlzLmhlaWdodCk7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5nZXRXaWR0aCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLndpZHRoO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuZ2V0SGVpZ2h0ID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuaGVpZ2h0O1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUucmVzaXplID0gZnVuY3Rpb24odywgaCwgcikge1xuICAgIHRoaXMud2lkdGggPSB0aGlzLmNhbnZhcy53aWR0aCA9IHc7XG4gICAgdGhpcy5oZWlnaHQgPSB0aGlzLmNhbnZhcy5oZWlnaHQgPSBoO1xuICAgIHRoaXMuY29udGV4dC5zY2FsZShyLCByKTtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0LmRyYXdJbWFnZSh0aGlzLmltZywgMCwgMCk7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS51cGRhdGUgPSBmdW5jdGlvbihpbWFnZURhdGEpIHtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0LnB1dEltYWdlRGF0YShpbWFnZURhdGEsIDAsIDApO1xuICB9O1xuXG4gIEJyb3dzZXJJbWFnZS5wcm90b3R5cGUuZ2V0UGl4ZWxDb3VudCA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLndpZHRoICogdGhpcy5oZWlnaHQ7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5nZXRJbWFnZURhdGEgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5jb250ZXh0LmdldEltYWdlRGF0YSgwLCAwLCB0aGlzLndpZHRoLCB0aGlzLmhlaWdodCk7XG4gIH07XG5cbiAgQnJvd3NlckltYWdlLnByb3RvdHlwZS5yZW1vdmVDYW52YXMgPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5jYW52YXMucGFyZW50Tm9kZS5yZW1vdmVDaGlsZCh0aGlzLmNhbnZhcyk7XG4gIH07XG5cbiAgcmV0dXJuIEJyb3dzZXJJbWFnZTtcblxufSkoSW1hZ2UpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12YVcxaFoyVXZZbkp2ZDNObGNpNWpiMlptWldVaUxDSnpiM1Z5WTJWU2IyOTBJam9pSWl3aWMyOTFjbU5sY3lJNld5SXZWWE5sY25Ndll6UXZSRzlqZFcxbGJuUnpMMUJ5YjJwbFkzUnpMM05sYkd4bGJ5OXViMlJsTFd4dloyOHRZMjlzYjNKekwzTnlZeTlwYldGblpTOWljbTkzYzJWeUxtTnZabVpsWlNKZExDSnVZVzFsY3lJNlcxMHNJbTFoY0hCcGJtZHpJam9pUVVGQlFTeEpRVUZCTEhGRVFVRkJPMFZCUVVFN096dEJRVUZCTEV0QlFVRXNSMEZCVVN4UFFVRkJMRU5CUVZFc1UwRkJVanM3UVVGRFVpeEhRVUZCTEVkQlFVMHNUMEZCUVN4RFFVRlJMRXRCUVZJN08wRkJSVTRzWVVGQlFTeEhRVUZuUWl4VFFVRkRMRWRCUVVRN1FVRkRaQ3hOUVVGQk8wVkJRVUVzUTBGQlFTeEhRVUZKTEVkQlFVY3NRMEZCUXl4TFFVRktMRU5CUVZVc1IwRkJWanRUUVVWS0xFTkJRVU1zUTBGQlF5eFJRVUZHTEV0QlFXTXNTVUZCWkN4SlFVRnpRaXhEUVVGRExFTkJRVU1zU1VGQlJpeExRVUZWTEVsQlFXaERMRWxCUVhkRExFTkJRVU1zUTBGQlF5eEpRVUZHTEV0QlFWVTdRVUZJY0VNN08wRkJTMmhDTEZsQlFVRXNSMEZCWlN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS08wRkJRMklzVFVGQlFUdEZRVUZCTEVWQlFVRXNSMEZCU3l4SFFVRkhMRU5CUVVNc1MwRkJTaXhEUVVGVkxFTkJRVlk3UlVGRFRDeEZRVUZCTEVkQlFVc3NSMEZCUnl4RFFVRkRMRXRCUVVvc1EwRkJWU3hEUVVGV08xTkJSMHdzUlVGQlJTeERRVUZETEZGQlFVZ3NTMEZCWlN4RlFVRkZMRU5CUVVNc1VVRkJiRUlzU1VGQk9FSXNSVUZCUlN4RFFVRkRMRkZCUVVnc1MwRkJaU3hGUVVGRkxFTkJRVU1zVVVGQmFFUXNTVUZCTkVRc1JVRkJSU3hEUVVGRExFbEJRVWdzUzBGQlZ5eEZRVUZGTEVOQlFVTTdRVUZNTjBRN08wRkJUMllzVFVGQlRTeERRVUZETEU5QlFWQXNSMEZEVFRzN08wVkJSVk1zYzBKQlFVTXNTVUZCUkN4RlFVRlBMRVZCUVZBN1NVRkRXQ3hKUVVGSExFOUJRVThzU1VGQlVDeExRVUZsTEZGQlFXWXNTVUZCTkVJc1NVRkJRU3haUVVGblFpeG5Ra0ZCTDBNN1RVRkRSU3hKUVVGRExFTkJRVUVzUjBGQlJDeEhRVUZQTzAxQlExQXNTVUZCUVN4SFFVRlBMRWxCUVVNc1EwRkJRU3hIUVVGSExFTkJRVU1zU1VGR1pEdExRVUZCTEUxQlFVRTdUVUZKUlN4SlFVRkRMRU5CUVVFc1IwRkJSQ3hIUVVGUExGRkJRVkVzUTBGQlF5eGhRVUZVTEVOQlFYVkNMRXRCUVhaQ08wMUJRMUFzU1VGQlF5eERRVUZCTEVkQlFVY3NRMEZCUXl4SFFVRk1MRWRCUVZjc1MwRk1ZanM3U1VGUFFTeEpRVUZITEVOQlFVa3NZVUZCUVN4RFFVRmpMRWxCUVdRc1EwRkJTaXhKUVVFeVFpeERRVUZKTEZsQlFVRXNRMEZCWVN4TlFVRk5MRU5CUVVNc1VVRkJVU3hEUVVGRExFbEJRVGRDTEVWQlFXMURMRWxCUVc1RExFTkJRV3hETzAxQlEwVXNTVUZCUXl4RFFVRkJMRWRCUVVjc1EwRkJReXhYUVVGTUxFZEJRVzFDTEZsQlJISkNPenRKUVVkQkxFbEJRVU1zUTBGQlFTeEhRVUZITEVOQlFVTXNUVUZCVEN4SFFVRmpMRU5CUVVFc1UwRkJRU3hMUVVGQk8yRkJRVUVzVTBGQlFUdFJRVU5hTEV0QlFVTXNRMEZCUVN4WFFVRkVMRU5CUVVFN01FTkJRMEVzUjBGQlNTeE5RVUZOTzAxQlJrVTdTVUZCUVN4RFFVRkJMRU5CUVVFc1EwRkJRU3hKUVVGQk8wbEJTMlFzU1VGQlJ5eEpRVUZETEVOQlFVRXNSMEZCUnl4RFFVRkRMRkZCUVZJN1RVRkRSU3hKUVVGRExFTkJRVUVzUjBGQlJ5eERRVUZETEUxQlFVd3NRMEZCUVN4RlFVUkdPenRKUVVkQkxFbEJRVU1zUTBGQlFTeEhRVUZITEVOQlFVTXNUMEZCVEN4SFFVRmxMRU5CUVVFc1UwRkJRU3hMUVVGQk8yRkJRVUVzVTBGQlF5eERRVUZFTzBGQlEySXNXVUZCUVR0UlFVRkJMRWRCUVVFc1IwRkJUU3hKUVVGSkxFdEJRVW9zUTBGQlZTeHpRa0ZCUVN4SFFVRjVRaXhKUVVGdVF6dFJRVU5PTEVkQlFVY3NRMEZCUXl4SFFVRktMRWRCUVZVN01FTkJRMVlzUjBGQlNUdE5RVWhUTzBsQlFVRXNRMEZCUVN4RFFVRkJMRU5CUVVFc1NVRkJRVHRGUVc1Q1NqczdlVUpCZVVKaUxGZEJRVUVzUjBGQllTeFRRVUZCTzBsQlExZ3NTVUZCUXl4RFFVRkJMRTFCUVVRc1IwRkJWU3hSUVVGUkxFTkJRVU1zWVVGQlZDeERRVUYxUWl4UlFVRjJRanRKUVVOV0xFbEJRVU1zUTBGQlFTeFBRVUZFTEVkQlFWY3NTVUZCUXl4RFFVRkJMRTFCUVUwc1EwRkJReXhWUVVGU0xFTkJRVzFDTEVsQlFXNUNPMGxCUTFnc1VVRkJVU3hEUVVGRExFbEJRVWtzUTBGQlF5eFhRVUZrTEVOQlFUQkNMRWxCUVVNc1EwRkJRU3hOUVVFelFqdEpRVU5CTEVsQlFVTXNRMEZCUVN4TFFVRkVMRWRCUVZNc1NVRkJReXhEUVVGQkxFMUJRVTBzUTBGQlF5eExRVUZTTEVkQlFXZENMRWxCUVVNc1EwRkJRU3hIUVVGSExFTkJRVU03U1VGRE9VSXNTVUZCUXl4RFFVRkJMRTFCUVVRc1IwRkJWU3hKUVVGRExFTkJRVUVzVFVGQlRTeERRVUZETEUxQlFWSXNSMEZCYVVJc1NVRkJReXhEUVVGQkxFZEJRVWNzUTBGQlF6dFhRVU5vUXl4SlFVRkRMRU5CUVVFc1QwRkJUeXhEUVVGRExGTkJRVlFzUTBGQmJVSXNTVUZCUXl4RFFVRkJMRWRCUVhCQ0xFVkJRWGxDTEVOQlFYcENMRVZCUVRSQ0xFTkJRVFZDTEVWQlFTdENMRWxCUVVNc1EwRkJRU3hMUVVGb1F5eEZRVUYxUXl4SlFVRkRMRU5CUVVFc1RVRkJlRU03UlVGT1Z6czdlVUpCVVdJc1MwRkJRU3hIUVVGUExGTkJRVUU3VjBGRFRDeEpRVUZETEVOQlFVRXNUMEZCVHl4RFFVRkRMRk5CUVZRc1EwRkJiVUlzUTBGQmJrSXNSVUZCYzBJc1EwRkJkRUlzUlVGQmVVSXNTVUZCUXl4RFFVRkJMRXRCUVRGQ0xFVkJRV2xETEVsQlFVTXNRMEZCUVN4TlFVRnNRenRGUVVSTE96dDVRa0ZIVUN4UlFVRkJMRWRCUVZVc1UwRkJRVHRYUVVOU0xFbEJRVU1zUTBGQlFUdEZRVVJQT3p0NVFrRkhWaXhUUVVGQkxFZEJRVmNzVTBGQlFUdFhRVU5VTEVsQlFVTXNRMEZCUVR0RlFVUlJPenQ1UWtGSFdDeE5RVUZCTEVkQlFWRXNVMEZCUXl4RFFVRkVMRVZCUVVrc1EwRkJTaXhGUVVGUExFTkJRVkE3U1VGRFRpeEpRVUZETEVOQlFVRXNTMEZCUkN4SFFVRlRMRWxCUVVNc1EwRkJRU3hOUVVGTkxFTkJRVU1zUzBGQlVpeEhRVUZuUWp0SlFVTjZRaXhKUVVGRExFTkJRVUVzVFVGQlJDeEhRVUZWTEVsQlFVTXNRMEZCUVN4TlFVRk5MRU5CUVVNc1RVRkJVaXhIUVVGcFFqdEpRVU16UWl4SlFVRkRMRU5CUVVFc1QwRkJUeXhEUVVGRExFdEJRVlFzUTBGQlpTeERRVUZtTEVWQlFXdENMRU5CUVd4Q08xZEJRMEVzU1VGQlF5eERRVUZCTEU5QlFVOHNRMEZCUXl4VFFVRlVMRU5CUVcxQ0xFbEJRVU1zUTBGQlFTeEhRVUZ3UWl4RlFVRjVRaXhEUVVGNlFpeEZRVUUwUWl4RFFVRTFRanRGUVVwTk96dDVRa0ZOVWl4TlFVRkJMRWRCUVZFc1UwRkJReXhUUVVGRU8xZEJRMDRzU1VGQlF5eERRVUZCTEU5QlFVOHNRMEZCUXl4WlFVRlVMRU5CUVhOQ0xGTkJRWFJDTEVWQlFXbERMRU5CUVdwRExFVkJRVzlETEVOQlFYQkRPMFZCUkUwN08zbENRVWRTTEdGQlFVRXNSMEZCWlN4VFFVRkJPMWRCUTJJc1NVRkJReXhEUVVGQkxFdEJRVVFzUjBGQlV5eEpRVUZETEVOQlFVRTdSVUZFUnpzN2VVSkJSMllzV1VGQlFTeEhRVUZqTEZOQlFVRTdWMEZEV2l4SlFVRkRMRU5CUVVFc1QwRkJUeXhEUVVGRExGbEJRVlFzUTBGQmMwSXNRMEZCZEVJc1JVRkJlVUlzUTBGQmVrSXNSVUZCTkVJc1NVRkJReXhEUVVGQkxFdEJRVGRDTEVWQlFXOURMRWxCUVVNc1EwRkJRU3hOUVVGeVF6dEZRVVJaT3p0NVFrRkhaQ3haUVVGQkxFZEJRV01zVTBGQlFUdFhRVU5hTEVsQlFVTXNRMEZCUVN4TlFVRk5MRU5CUVVNc1ZVRkJWU3hEUVVGRExGZEJRVzVDTEVOQlFTdENMRWxCUVVNc1EwRkJRU3hOUVVGb1F6dEZRVVJaT3pzN08wZEJNMFJYSW4wPVxuIiwidmFyIEltYWdlO1xuXG5tb2R1bGUuZXhwb3J0cyA9IEltYWdlID0gKGZ1bmN0aW9uKCkge1xuICBmdW5jdGlvbiBJbWFnZSgpIHt9XG5cbiAgSW1hZ2UucHJvdG90eXBlLmNsZWFyID0gZnVuY3Rpb24oKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUudXBkYXRlID0gZnVuY3Rpb24oaW1hZ2VEYXRhKSB7fTtcblxuICBJbWFnZS5wcm90b3R5cGUuZ2V0V2lkdGggPSBmdW5jdGlvbigpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5nZXRIZWlnaHQgPSBmdW5jdGlvbigpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5zY2FsZURvd24gPSBmdW5jdGlvbihvcHRzKSB7XG4gICAgdmFyIGhlaWdodCwgbWF4U2lkZSwgcmF0aW8sIHdpZHRoO1xuICAgIHdpZHRoID0gdGhpcy5nZXRXaWR0aCgpO1xuICAgIGhlaWdodCA9IHRoaXMuZ2V0SGVpZ2h0KCk7XG4gICAgcmF0aW8gPSAxO1xuICAgIGlmIChvcHRzLm1heERpbWVuc2lvbiAhPSBudWxsKSB7XG4gICAgICBtYXhTaWRlID0gTWF0aC5tYXgod2lkdGgsIGhlaWdodCk7XG4gICAgICBpZiAobWF4U2lkZSA+IG9wdHMubWF4RGltZW5zaW9uKSB7XG4gICAgICAgIHJhdGlvID0gb3B0cy5tYXhEaW1lbnNpb24gLyBtYXhTaWRlO1xuICAgICAgfVxuICAgIH0gZWxzZSB7XG4gICAgICByYXRpbyA9IDEgLyBvcHRzLnF1YWxpdHk7XG4gICAgfVxuICAgIGlmIChyYXRpbyA8IDEpIHtcbiAgICAgIHJldHVybiB0aGlzLnJlc2l6ZSh3aWR0aCAqIHJhdGlvLCBoZWlnaHQgKiByYXRpbywgcmF0aW8pO1xuICAgIH1cbiAgfTtcblxuICBJbWFnZS5wcm90b3R5cGUucmVzaXplID0gZnVuY3Rpb24odywgaCwgcikge307XG5cbiAgSW1hZ2UucHJvdG90eXBlLmdldFBpeGVsQ291bnQgPSBmdW5jdGlvbigpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5nZXRJbWFnZURhdGEgPSBmdW5jdGlvbigpIHt9O1xuXG4gIEltYWdlLnByb3RvdHlwZS5yZW1vdmVDYW52YXMgPSBmdW5jdGlvbigpIHt9O1xuXG4gIHJldHVybiBJbWFnZTtcblxufSkoKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmFXMWhaMlV2YVc1a1pYZ3VZMjltWm1WbElpd2ljMjkxY21ObFVtOXZkQ0k2SWlJc0luTnZkWEpqWlhNaU9sc2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12YVcxaFoyVXZhVzVrWlhndVkyOW1abVZsSWwwc0ltNWhiV1Z6SWpwYlhTd2liV0Z3Y0dsdVozTWlPaUpCUVVGQkxFbEJRVUU3TzBGQlFVRXNUVUZCVFN4RFFVRkRMRTlCUVZBc1IwRkRUVHM3TzJ0Q1FVTktMRXRCUVVFc1IwRkJUeXhUUVVGQkxFZEJRVUU3TzJ0Q1FVVlFMRTFCUVVFc1IwRkJVU3hUUVVGRExGTkJRVVFzUjBGQlFUczdhMEpCUlZJc1VVRkJRU3hIUVVGVkxGTkJRVUVzUjBGQlFUczdhMEpCUlZZc1UwRkJRU3hIUVVGWExGTkJRVUVzUjBGQlFUczdhMEpCUlZnc1UwRkJRU3hIUVVGWExGTkJRVU1zU1VGQlJEdEJRVU5VTEZGQlFVRTdTVUZCUVN4TFFVRkJMRWRCUVZFc1NVRkJReXhEUVVGQkxGRkJRVVFzUTBGQlFUdEpRVU5TTEUxQlFVRXNSMEZCVXl4SlFVRkRMRU5CUVVFc1UwRkJSQ3hEUVVGQk8wbEJSVlFzUzBGQlFTeEhRVUZSTzBsQlExSXNTVUZCUnl4NVFrRkJTRHROUVVORkxFOUJRVUVzUjBGQlZTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRXRCUVZRc1JVRkJaMElzVFVGQmFFSTdUVUZEVml4SlFVRkhMRTlCUVVFc1IwRkJWU3hKUVVGSkxFTkJRVU1zV1VGQmJFSTdVVUZEUlN4TFFVRkJMRWRCUVZFc1NVRkJTU3hEUVVGRExGbEJRVXdzUjBGQmIwSXNVVUZFT1VJN1QwRkdSanRMUVVGQkxFMUJRVUU3VFVGTFJTeExRVUZCTEVkQlFWRXNRMEZCUVN4SFFVRkpMRWxCUVVrc1EwRkJReXhSUVV4dVFqczdTVUZQUVN4SlFVRkhMRXRCUVVFc1IwRkJVU3hEUVVGWU8yRkJRMFVzU1VGQlF5eERRVUZCTEUxQlFVUXNRMEZCVVN4TFFVRkJMRWRCUVZFc1MwRkJhRUlzUlVGQmRVSXNUVUZCUVN4SFFVRlRMRXRCUVdoRExFVkJRWFZETEV0QlFYWkRMRVZCUkVZN08wVkJXbE03TzJ0Q1FXVllMRTFCUVVFc1IwRkJVU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUN4SFFVRkJPenRyUWtGSFVpeGhRVUZCTEVkQlFXVXNVMEZCUVN4SFFVRkJPenRyUWtGRlppeFpRVUZCTEVkQlFXTXNVMEZCUVN4SFFVRkJPenRyUWtGRlpDeFpRVUZCTEVkQlFXTXNVMEZCUVN4SFFVRkJJbjA9XG4iLCJ2YXIgTU1DUSwgUFF1ZXVlLCBSU0hJRlQsIFNJR0JJVFMsIFN3YXRjaCwgVkJveCwgZ2V0Q29sb3JJbmRleCwgcmVmLCB1dGlsO1xuXG5yZWYgPSB1dGlsID0gcmVxdWlyZSgnLi4vLi4vdXRpbCcpLCBnZXRDb2xvckluZGV4ID0gcmVmLmdldENvbG9ySW5kZXgsIFNJR0JJVFMgPSByZWYuU0lHQklUUywgUlNISUZUID0gcmVmLlJTSElGVDtcblxuU3dhdGNoID0gcmVxdWlyZSgnLi4vLi4vc3dhdGNoJyk7XG5cblZCb3ggPSByZXF1aXJlKCcuL3Zib3gnKTtcblxuUFF1ZXVlID0gcmVxdWlyZSgnLi9wcXVldWUnKTtcblxubW9kdWxlLmV4cG9ydHMgPSBNTUNRID0gKGZ1bmN0aW9uKCkge1xuICBNTUNRLkRlZmF1bHRPcHRzID0ge1xuICAgIG1heEl0ZXJhdGlvbnM6IDEwMDAsXG4gICAgZnJhY3RCeVBvcHVsYXRpb25zOiAwLjc1XG4gIH07XG5cbiAgZnVuY3Rpb24gTU1DUShvcHRzKSB7XG4gICAgdGhpcy5vcHRzID0gdXRpbC5kZWZhdWx0cyhvcHRzLCB0aGlzLmNvbnN0cnVjdG9yLkRlZmF1bHRPcHRzKTtcbiAgfVxuXG4gIE1NQ1EucHJvdG90eXBlLnF1YW50aXplID0gZnVuY3Rpb24ocGl4ZWxzLCBvcHRzKSB7XG4gICAgdmFyIGNvbG9yLCBjb2xvckNvdW50LCBoaXN0LCBwcSwgcHEyLCBzaG91bGRJZ25vcmUsIHN3YXRjaGVzLCB2LCB2Ym94O1xuICAgIGlmIChwaXhlbHMubGVuZ3RoID09PSAwIHx8IG9wdHMuY29sb3JDb3VudCA8IDIgfHwgb3B0cy5jb2xvckNvdW50ID4gMjU2KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJXcm9uZyBNTUNRIHBhcmFtZXRlcnNcIik7XG4gICAgfVxuICAgIHNob3VsZElnbm9yZSA9IGZ1bmN0aW9uKCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH07XG4gICAgaWYgKEFycmF5LmlzQXJyYXkob3B0cy5maWx0ZXJzKSAmJiBvcHRzLmZpbHRlcnMubGVuZ3RoID4gMCkge1xuICAgICAgc2hvdWxkSWdub3JlID0gZnVuY3Rpb24ociwgZywgYiwgYSkge1xuICAgICAgICB2YXIgZiwgaSwgbGVuLCByZWYxO1xuICAgICAgICByZWYxID0gb3B0cy5maWx0ZXJzO1xuICAgICAgICBmb3IgKGkgPSAwLCBsZW4gPSByZWYxLmxlbmd0aDsgaSA8IGxlbjsgaSsrKSB7XG4gICAgICAgICAgZiA9IHJlZjFbaV07XG4gICAgICAgICAgaWYgKCFmKHIsIGcsIGIsIGEpKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfTtcbiAgICB9XG4gICAgdmJveCA9IFZCb3guYnVpbGQocGl4ZWxzLCBzaG91bGRJZ25vcmUpO1xuICAgIGhpc3QgPSB2Ym94Lmhpc3Q7XG4gICAgY29sb3JDb3VudCA9IE9iamVjdC5rZXlzKGhpc3QpLmxlbmd0aDtcbiAgICBwcSA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgcmV0dXJuIGEuY291bnQoKSAtIGIuY291bnQoKTtcbiAgICB9KTtcbiAgICBwcS5wdXNoKHZib3gpO1xuICAgIHRoaXMuX3NwbGl0Qm94ZXMocHEsIHRoaXMub3B0cy5mcmFjdEJ5UG9wdWxhdGlvbnMgKiBvcHRzLmNvbG9yQ291bnQpO1xuICAgIHBxMiA9IG5ldyBQUXVldWUoZnVuY3Rpb24oYSwgYikge1xuICAgICAgcmV0dXJuIGEuY291bnQoKSAqIGEudm9sdW1lKCkgLSBiLmNvdW50KCkgKiBiLnZvbHVtZSgpO1xuICAgIH0pO1xuICAgIHBxMi5jb250ZW50cyA9IHBxLmNvbnRlbnRzO1xuICAgIHRoaXMuX3NwbGl0Qm94ZXMocHEyLCBvcHRzLmNvbG9yQ291bnQgLSBwcTIuc2l6ZSgpKTtcbiAgICBzd2F0Y2hlcyA9IFtdO1xuICAgIHRoaXMudmJveGVzID0gW107XG4gICAgd2hpbGUgKHBxMi5zaXplKCkpIHtcbiAgICAgIHYgPSBwcTIucG9wKCk7XG4gICAgICBjb2xvciA9IHYuYXZnKCk7XG4gICAgICBpZiAoISh0eXBlb2Ygc2hvdWxkSWdub3JlID09PSBcImZ1bmN0aW9uXCIgPyBzaG91bGRJZ25vcmUoY29sb3JbMF0sIGNvbG9yWzFdLCBjb2xvclsyXSwgMjU1KSA6IHZvaWQgMCkpIHtcbiAgICAgICAgdGhpcy52Ym94ZXMucHVzaCh2KTtcbiAgICAgICAgc3dhdGNoZXMucHVzaChuZXcgU3dhdGNoKGNvbG9yLCB2LmNvdW50KCkpKTtcbiAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHN3YXRjaGVzO1xuICB9O1xuXG4gIE1NQ1EucHJvdG90eXBlLl9zcGxpdEJveGVzID0gZnVuY3Rpb24ocHEsIHRhcmdldCkge1xuICAgIHZhciBjb2xvckNvdW50LCBpdGVyYXRpb24sIG1heEl0ZXJhdGlvbnMsIHJlZjEsIHZib3gsIHZib3gxLCB2Ym94MjtcbiAgICBjb2xvckNvdW50ID0gMTtcbiAgICBpdGVyYXRpb24gPSAwO1xuICAgIG1heEl0ZXJhdGlvbnMgPSB0aGlzLm9wdHMubWF4SXRlcmF0aW9ucztcbiAgICB3aGlsZSAoaXRlcmF0aW9uIDwgbWF4SXRlcmF0aW9ucykge1xuICAgICAgaXRlcmF0aW9uKys7XG4gICAgICB2Ym94ID0gcHEucG9wKCk7XG4gICAgICBpZiAoIXZib3guY291bnQoKSkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIHJlZjEgPSB2Ym94LnNwbGl0KCksIHZib3gxID0gcmVmMVswXSwgdmJveDIgPSByZWYxWzFdO1xuICAgICAgcHEucHVzaCh2Ym94MSk7XG4gICAgICBpZiAodmJveDIpIHtcbiAgICAgICAgcHEucHVzaCh2Ym94Mik7XG4gICAgICAgIGNvbG9yQ291bnQrKztcbiAgICAgIH1cbiAgICAgIGlmIChjb2xvckNvdW50ID49IHRhcmdldCB8fCBpdGVyYXRpb24gPiBtYXhJdGVyYXRpb25zKSB7XG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgcmV0dXJuIE1NQ1E7XG5cbn0pKCk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMmx0Y0d3dmJXMWpjUzVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5eGRXRnVkR2w2WlhJdmFXMXdiQzl0YldOeExtTnZabVpsWlNKZExDSnVZVzFsY3lJNlcxMHNJbTFoY0hCcGJtZHpJam9pUVVGTlFTeEpRVUZCT3p0QlFVRkJMRTFCUVcxRExFbEJRVUVzUjBGQlR5eFBRVUZCTEVOQlFWRXNXVUZCVWl4RFFVRXhReXhGUVVGRExHbERRVUZFTEVWQlFXZENMSEZDUVVGb1FpeEZRVUY1UWpzN1FVRkRla0lzVFVGQlFTeEhRVUZUTEU5QlFVRXNRMEZCVVN4alFVRlNPenRCUVVOVUxFbEJRVUVzUjBGQlR5eFBRVUZCTEVOQlFWRXNVVUZCVWpzN1FVRkRVQ3hOUVVGQkxFZEJRVk1zVDBGQlFTeERRVUZSTEZWQlFWSTdPMEZCUlZRc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUdEZRVU5LTEVsQlFVTXNRMEZCUVN4WFFVRkVMRWRCUTBVN1NVRkJRU3hoUVVGQkxFVkJRV1VzU1VGQlpqdEpRVU5CTEd0Q1FVRkJMRVZCUVc5Q0xFbEJSSEJDT3pzN1JVRkhWeXhqUVVGRExFbEJRVVE3U1VGRFdDeEpRVUZETEVOQlFVRXNTVUZCUkN4SFFVRlJMRWxCUVVrc1EwRkJReXhSUVVGTUxFTkJRV01zU1VGQlpDeEZRVUZ2UWl4SlFVRkRMRU5CUVVFc1YwRkJWeXhEUVVGRExGZEJRV3BETzBWQlJFYzdPMmxDUVVWaUxGRkJRVUVzUjBGQlZTeFRRVUZETEUxQlFVUXNSVUZCVXl4SlFVRlVPMEZCUTFJc1VVRkJRVHRKUVVGQkxFbEJRVWNzVFVGQlRTeERRVUZETEUxQlFWQXNTMEZCYVVJc1EwRkJha0lzU1VGQmMwSXNTVUZCU1N4RFFVRkRMRlZCUVV3c1IwRkJhMElzUTBGQmVFTXNTVUZCTmtNc1NVRkJTU3hEUVVGRExGVkJRVXdzUjBGQmEwSXNSMEZCYkVVN1FVRkRSU3haUVVGTkxFbEJRVWtzUzBGQlNpeERRVUZWTEhWQ1FVRldMRVZCUkZJN08wbEJSMEVzV1VGQlFTeEhRVUZsTEZOQlFVRTdZVUZCUnp0SlFVRklPMGxCUldZc1NVRkJSeXhMUVVGTExFTkJRVU1zVDBGQlRpeERRVUZqTEVsQlFVa3NRMEZCUXl4UFFVRnVRaXhEUVVGQkxFbEJRV2RETEVsQlFVa3NRMEZCUXl4UFFVRlBMRU5CUVVNc1RVRkJZaXhIUVVGelFpeERRVUY2UkR0TlFVTkZMRmxCUVVFc1IwRkJaU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUN4RlFVRlZMRU5CUVZZN1FVRkRZaXhaUVVGQk8wRkJRVUU3UVVGQlFTeGhRVUZCTEhORFFVRkJPenRWUVVORkxFbEJRVWNzUTBGQlNTeERRVUZCTEVOQlFVVXNRMEZCUml4RlFVRkxMRU5CUVV3c1JVRkJVU3hEUVVGU0xFVkJRVmNzUTBGQldDeERRVUZRTzBGQlFUQkNMRzFDUVVGUExFdEJRV3BET3p0QlFVUkdPMEZCUlVFc1pVRkJUenROUVVoTkxFVkJSR3BDT3p0SlFVOUJMRWxCUVVFc1IwRkJUeXhKUVVGSkxFTkJRVU1zUzBGQlRDeERRVUZYTEUxQlFWZ3NSVUZCYlVJc1dVRkJia0k3U1VGRFVDeEpRVUZCTEVkQlFVOHNTVUZCU1N4RFFVRkRPMGxCUTFvc1ZVRkJRU3hIUVVGaExFMUJRVTBzUTBGQlF5eEpRVUZRTEVOQlFWa3NTVUZCV2l4RFFVRnBRaXhEUVVGRE8wbEJReTlDTEVWQlFVRXNSMEZCU3l4SlFVRkpMRTFCUVVvc1EwRkJWeXhUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTzJGQlFWVXNRMEZCUXl4RFFVRkRMRXRCUVVZc1EwRkJRU3hEUVVGQkxFZEJRVmtzUTBGQlF5eERRVUZETEV0QlFVWXNRMEZCUVR0SlFVRjBRaXhEUVVGWU8wbEJSVXdzUlVGQlJTeERRVUZETEVsQlFVZ3NRMEZCVVN4SlFVRlNPMGxCUjBFc1NVRkJReXhEUVVGQkxGZEJRVVFzUTBGQllTeEZRVUZpTEVWQlFXbENMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zYTBKQlFVNHNSMEZCTWtJc1NVRkJTU3hEUVVGRExGVkJRV3BFTzBsQlIwRXNSMEZCUVN4SFFVRk5MRWxCUVVrc1RVRkJTaXhEUVVGWExGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVbzdZVUZCVlN4RFFVRkRMRU5CUVVNc1MwRkJSaXhEUVVGQkxFTkJRVUVzUjBGQldTeERRVUZETEVOQlFVTXNUVUZCUml4RFFVRkJMRU5CUVZvc1IwRkJlVUlzUTBGQlF5eERRVUZETEV0QlFVWXNRMEZCUVN4RFFVRkJMRWRCUVZrc1EwRkJReXhEUVVGRExFMUJRVVlzUTBGQlFUdEpRVUV2UXl4RFFVRllPMGxCUTA0c1IwRkJSeXhEUVVGRExGRkJRVW9zUjBGQlpTeEZRVUZGTEVOQlFVTTdTVUZIYkVJc1NVRkJReXhEUVVGQkxGZEJRVVFzUTBGQllTeEhRVUZpTEVWQlFXdENMRWxCUVVrc1EwRkJReXhWUVVGTUxFZEJRV3RDTEVkQlFVY3NRMEZCUXl4SlFVRktMRU5CUVVFc1EwRkJjRU03U1VGSFFTeFJRVUZCTEVkQlFWYzdTVUZEV0N4SlFVRkRMRU5CUVVFc1RVRkJSQ3hIUVVGVk8wRkJRMVlzVjBGQlRTeEhRVUZITEVOQlFVTXNTVUZCU2l4RFFVRkJMRU5CUVU0N1RVRkRSU3hEUVVGQkxFZEJRVWtzUjBGQlJ5eERRVUZETEVkQlFVb3NRMEZCUVR0TlFVTktMRXRCUVVFc1IwRkJVU3hEUVVGRExFTkJRVU1zUjBGQlJpeERRVUZCTzAxQlExSXNTVUZCUnl4MVEwRkJTU3hoUVVGakxFdEJRVTBzUTBGQlFTeERRVUZCTEVkQlFVa3NTMEZCVFN4RFFVRkJMRU5CUVVFc1IwRkJTU3hMUVVGTkxFTkJRVUVzUTBGQlFTeEhRVUZKTEdOQlFXNUVPMUZCUTBVc1NVRkJReXhEUVVGQkxFMUJRVTBzUTBGQlF5eEpRVUZTTEVOQlFXRXNRMEZCWWp0UlFVTkJMRkZCUVZFc1EwRkJReXhKUVVGVUxFTkJRV01zU1VGQlNTeE5RVUZLTEVOQlFWY3NTMEZCV0N4RlFVRnJRaXhEUVVGRExFTkJRVU1zUzBGQlJpeERRVUZCTEVOQlFXeENMRU5CUVdRc1JVRkdSanM3U1VGSVJqdFhRVTlCTzBWQmVFTlJPenRwUWtFd1ExWXNWMEZCUVN4SFFVRmhMRk5CUVVNc1JVRkJSQ3hGUVVGTExFMUJRVXc3UVVGRFdDeFJRVUZCTzBsQlFVRXNWVUZCUVN4SFFVRmhPMGxCUTJJc1UwRkJRU3hIUVVGWk8wbEJRMW9zWVVGQlFTeEhRVUZuUWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRE8wRkJRM1JDTEZkQlFVMHNVMEZCUVN4SFFVRlpMR0ZCUVd4Q08wMUJRMFVzVTBGQlFUdE5RVU5CTEVsQlFVRXNSMEZCVHl4RlFVRkZMRU5CUVVNc1IwRkJTQ3hEUVVGQk8wMUJRMUFzU1VGQlJ5eERRVUZETEVsQlFVa3NRMEZCUXl4TFFVRk1MRU5CUVVFc1EwRkJTanRCUVVORkxHbENRVVJHT3p0TlFVZEJMRTlCUVdsQ0xFbEJRVWtzUTBGQlF5eExRVUZNTEVOQlFVRXNRMEZCYWtJc1JVRkJReXhsUVVGRUxFVkJRVkU3VFVGRlVpeEZRVUZGTEVOQlFVTXNTVUZCU0N4RFFVRlJMRXRCUVZJN1RVRkRRU3hKUVVGSExFdEJRVWc3VVVGRFJTeEZRVUZGTEVOQlFVTXNTVUZCU0N4RFFVRlJMRXRCUVZJN1VVRkRRU3hWUVVGQkxFZEJSa1k3TzAxQlIwRXNTVUZCUnl4VlFVRkJMRWxCUVdNc1RVRkJaQ3hKUVVGM1FpeFRRVUZCTEVkQlFWa3NZVUZCZGtNN1FVRkRSU3hsUVVSR096dEpRVnBHTzBWQlNsY2lmUT09XG4iLCJ2YXIgUFF1ZXVlO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFBRdWV1ZSA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gUFF1ZXVlKGNvbXBhcmF0b3IpIHtcbiAgICB0aGlzLmNvbXBhcmF0b3IgPSBjb21wYXJhdG9yO1xuICAgIHRoaXMuY29udGVudHMgPSBbXTtcbiAgICB0aGlzLnNvcnRlZCA9IGZhbHNlO1xuICB9XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5fc29ydCA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuY29udGVudHMuc29ydCh0aGlzLmNvbXBhcmF0b3IpO1xuICAgIHJldHVybiB0aGlzLnNvcnRlZCA9IHRydWU7XG4gIH07XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5wdXNoID0gZnVuY3Rpb24obykge1xuICAgIHRoaXMuY29udGVudHMucHVzaChvKTtcbiAgICByZXR1cm4gdGhpcy5zb3J0ZWQgPSBmYWxzZTtcbiAgfTtcblxuICBQUXVldWUucHJvdG90eXBlLnBlZWsgPSBmdW5jdGlvbihpbmRleCkge1xuICAgIGlmICghdGhpcy5zb3J0ZWQpIHtcbiAgICAgIHRoaXMuX3NvcnQoKTtcbiAgICB9XG4gICAgaWYgKGluZGV4ID09IG51bGwpIHtcbiAgICAgIGluZGV4ID0gdGhpcy5jb250ZW50cy5sZW5ndGggLSAxO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5jb250ZW50c1tpbmRleF07XG4gIH07XG5cbiAgUFF1ZXVlLnByb3RvdHlwZS5wb3AgPSBmdW5jdGlvbigpIHtcbiAgICBpZiAoIXRoaXMuc29ydGVkKSB7XG4gICAgICB0aGlzLl9zb3J0KCk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmNvbnRlbnRzLnBvcCgpO1xuICB9O1xuXG4gIFBRdWV1ZS5wcm90b3R5cGUuc2l6ZSA9IGZ1bmN0aW9uKCkge1xuICAgIHJldHVybiB0aGlzLmNvbnRlbnRzLmxlbmd0aDtcbiAgfTtcblxuICBQUXVldWUucHJvdG90eXBlLm1hcCA9IGZ1bmN0aW9uKGYpIHtcbiAgICBpZiAoIXRoaXMuc29ydGVkKSB7XG4gICAgICB0aGlzLl9zb3J0KCk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLmNvbnRlbnRzLm1hcChmKTtcbiAgfTtcblxuICByZXR1cm4gUFF1ZXVlO1xuXG59KSgpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDJsdGNHd3ZjSEYxWlhWbExtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMM0YxWVc1MGFYcGxjaTlwYlhCc0wzQnhkV1YxWlM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1NVRkJRVHM3UVVGQlFTeE5RVUZOTEVOQlFVTXNUMEZCVUN4SFFVTk5PMFZCUTFNc1owSkJRVU1zVlVGQlJEdEpRVUZETEVsQlFVTXNRMEZCUVN4aFFVRkVPMGxCUTFvc1NVRkJReXhEUVVGQkxGRkJRVVFzUjBGQldUdEpRVU5hTEVsQlFVTXNRMEZCUVN4TlFVRkVMRWRCUVZVN1JVRkdRenM3YlVKQlNXSXNTMEZCUVN4SFFVRlBMRk5CUVVFN1NVRkRUQ3hKUVVGRExFTkJRVUVzVVVGQlVTeERRVUZETEVsQlFWWXNRMEZCWlN4SlFVRkRMRU5CUVVFc1ZVRkJhRUk3VjBGRFFTeEpRVUZETEVOQlFVRXNUVUZCUkN4SFFVRlZPMFZCUmt3N08yMUNRVWxRTEVsQlFVRXNSMEZCVFN4VFFVRkRMRU5CUVVRN1NVRkRTaXhKUVVGRExFTkJRVUVzVVVGQlVTeERRVUZETEVsQlFWWXNRMEZCWlN4RFFVRm1PMWRCUTBFc1NVRkJReXhEUVVGQkxFMUJRVVFzUjBGQlZUdEZRVVpPT3p0dFFrRkpUaXhKUVVGQkxFZEJRVTBzVTBGQlF5eExRVUZFTzBsQlEwb3NTVUZCUnl4RFFVRkpMRWxCUVVNc1EwRkJRU3hOUVVGU08wMUJRMFVzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RlFVUkdPenM3VFVGRlFTeFJRVUZUTEVsQlFVTXNRMEZCUVN4UlFVRlJMRU5CUVVNc1RVRkJWaXhIUVVGdFFqczdWMEZETlVJc1NVRkJReXhEUVVGQkxGRkJRVk1zUTBGQlFTeExRVUZCTzBWQlNrNDdPMjFDUVUxT0xFZEJRVUVzUjBGQlN5eFRRVUZCTzBsQlEwZ3NTVUZCUnl4RFFVRkpMRWxCUVVNc1EwRkJRU3hOUVVGU08wMUJRMFVzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RlFVUkdPenRYUVVWQkxFbEJRVU1zUTBGQlFTeFJRVUZSTEVOQlFVTXNSMEZCVml4RFFVRkJPMFZCU0VjN08yMUNRVXRNTEVsQlFVRXNSMEZCVFN4VFFVRkJPMWRCUTBvc1NVRkJReXhEUVVGQkxGRkJRVkVzUTBGQlF6dEZRVVJPT3p0dFFrRkhUaXhIUVVGQkxFZEJRVXNzVTBGQlF5eERRVUZFTzBsQlEwZ3NTVUZCUnl4RFFVRkpMRWxCUVVNc1EwRkJRU3hOUVVGU08wMUJRMFVzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RlFVUkdPenRYUVVWQkxFbEJRVU1zUTBGQlFTeFJRVUZSTEVOQlFVTXNSMEZCVml4RFFVRmpMRU5CUVdRN1JVRklSeUo5XG4iLCJ2YXIgUlNISUZULCBTSUdCSVRTLCBWQm94LCBnZXRDb2xvckluZGV4LCByZWYsIHV0aWw7XG5cbnJlZiA9IHV0aWwgPSByZXF1aXJlKCcuLi8uLi91dGlsJyksIGdldENvbG9ySW5kZXggPSByZWYuZ2V0Q29sb3JJbmRleCwgU0lHQklUUyA9IHJlZi5TSUdCSVRTLCBSU0hJRlQgPSByZWYuUlNISUZUO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFZCb3ggPSAoZnVuY3Rpb24oKSB7XG4gIFZCb3guYnVpbGQgPSBmdW5jdGlvbihwaXhlbHMsIHNob3VsZElnbm9yZSkge1xuICAgIHZhciBhLCBiLCBibWF4LCBibWluLCBnLCBnbWF4LCBnbWluLCBoaXN0LCBobiwgaSwgaW5kZXgsIG4sIG9mZnNldCwgciwgcm1heCwgcm1pbjtcbiAgICBobiA9IDEgPDwgKDMgKiBTSUdCSVRTKTtcbiAgICBoaXN0ID0gbmV3IFVpbnQzMkFycmF5KGhuKTtcbiAgICBybWF4ID0gZ21heCA9IGJtYXggPSAwO1xuICAgIHJtaW4gPSBnbWluID0gYm1pbiA9IE51bWJlci5NQVhfVkFMVUU7XG4gICAgbiA9IHBpeGVscy5sZW5ndGggLyA0O1xuICAgIGkgPSAwO1xuICAgIHdoaWxlIChpIDwgbikge1xuICAgICAgb2Zmc2V0ID0gaSAqIDQ7XG4gICAgICBpKys7XG4gICAgICByID0gcGl4ZWxzW29mZnNldCArIDBdO1xuICAgICAgZyA9IHBpeGVsc1tvZmZzZXQgKyAxXTtcbiAgICAgIGIgPSBwaXhlbHNbb2Zmc2V0ICsgMl07XG4gICAgICBhID0gcGl4ZWxzW29mZnNldCArIDNdO1xuICAgICAgaWYgKHNob3VsZElnbm9yZShyLCBnLCBiLCBhKSkge1xuICAgICAgICBjb250aW51ZTtcbiAgICAgIH1cbiAgICAgIHIgPSByID4+IFJTSElGVDtcbiAgICAgIGcgPSBnID4+IFJTSElGVDtcbiAgICAgIGIgPSBiID4+IFJTSElGVDtcbiAgICAgIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgIGhpc3RbaW5kZXhdICs9IDE7XG4gICAgICBpZiAociA+IHJtYXgpIHtcbiAgICAgICAgcm1heCA9IHI7XG4gICAgICB9XG4gICAgICBpZiAociA8IHJtaW4pIHtcbiAgICAgICAgcm1pbiA9IHI7XG4gICAgICB9XG4gICAgICBpZiAoZyA+IGdtYXgpIHtcbiAgICAgICAgZ21heCA9IGc7XG4gICAgICB9XG4gICAgICBpZiAoZyA8IGdtaW4pIHtcbiAgICAgICAgZ21pbiA9IGc7XG4gICAgICB9XG4gICAgICBpZiAoYiA+IGJtYXgpIHtcbiAgICAgICAgYm1heCA9IGI7XG4gICAgICB9XG4gICAgICBpZiAoYiA8IGJtaW4pIHtcbiAgICAgICAgYm1pbiA9IGI7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBuZXcgVkJveChybWluLCBybWF4LCBnbWluLCBnbWF4LCBibWluLCBibWF4LCBoaXN0KTtcbiAgfTtcblxuICBmdW5jdGlvbiBWQm94KHIxLCByMiwgZzEsIGcyLCBiMSwgYjIsIGhpc3QxKSB7XG4gICAgdGhpcy5yMSA9IHIxO1xuICAgIHRoaXMucjIgPSByMjtcbiAgICB0aGlzLmcxID0gZzE7XG4gICAgdGhpcy5nMiA9IGcyO1xuICAgIHRoaXMuYjEgPSBiMTtcbiAgICB0aGlzLmIyID0gYjI7XG4gICAgdGhpcy5oaXN0ID0gaGlzdDE7XG4gIH1cblxuICBWQm94LnByb3RvdHlwZS5pbnZhbGlkYXRlID0gZnVuY3Rpb24oKSB7XG4gICAgZGVsZXRlIHRoaXMuX2NvdW50O1xuICAgIGRlbGV0ZSB0aGlzLl9hdmc7XG4gICAgcmV0dXJuIGRlbGV0ZSB0aGlzLl92b2x1bWU7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUudm9sdW1lID0gZnVuY3Rpb24oKSB7XG4gICAgaWYgKHRoaXMuX3ZvbHVtZSA9PSBudWxsKSB7XG4gICAgICB0aGlzLl92b2x1bWUgPSAodGhpcy5yMiAtIHRoaXMucjEgKyAxKSAqICh0aGlzLmcyIC0gdGhpcy5nMSArIDEpICogKHRoaXMuYjIgLSB0aGlzLmIxICsgMSk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl92b2x1bWU7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUuY291bnQgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgYywgaGlzdDtcbiAgICBpZiAodGhpcy5fY291bnQgPT0gbnVsbCkge1xuICAgICAgaGlzdCA9IHRoaXMuaGlzdDtcbiAgICAgIGMgPSAwO1xuICAgICAgXG4gICAgICBmb3IgKHZhciByID0gdGhpcy5yMTsgciA8PSB0aGlzLnIyOyByKyspIHtcbiAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgICB2YXIgaW5kZXggPSBnZXRDb2xvckluZGV4KHIsIGcsIGIpO1xuICAgICAgICAgICAgYyArPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIDtcbiAgICAgIHRoaXMuX2NvdW50ID0gYztcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMuX2NvdW50O1xuICB9O1xuXG4gIFZCb3gucHJvdG90eXBlLmNsb25lID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIG5ldyBWQm94KHRoaXMucjEsIHRoaXMucjIsIHRoaXMuZzEsIHRoaXMuZzIsIHRoaXMuYjEsIHRoaXMuYjIsIHRoaXMuaGlzdCk7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUuYXZnID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGJzdW0sIGdzdW0sIGhpc3QsIG11bHQsIG50b3QsIHJzdW07XG4gICAgaWYgKHRoaXMuX2F2ZyA9PSBudWxsKSB7XG4gICAgICBoaXN0ID0gdGhpcy5oaXN0O1xuICAgICAgbnRvdCA9IDA7XG4gICAgICBtdWx0ID0gMSA8PCAoOCAtIFNJR0JJVFMpO1xuICAgICAgcnN1bSA9IGdzdW0gPSBic3VtID0gMDtcbiAgICAgIFxuICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgIGZvciAodmFyIGIgPSB0aGlzLmIxOyBiIDw9IHRoaXMuYjI7IGIrKykge1xuICAgICAgICAgICAgdmFyIGluZGV4ID0gZ2V0Q29sb3JJbmRleChyLCBnLCBiKTtcbiAgICAgICAgICAgIHZhciBoID0gaGlzdFtpbmRleF07XG4gICAgICAgICAgICBudG90ICs9IGg7XG4gICAgICAgICAgICByc3VtICs9IChoICogKHIgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICBnc3VtICs9IChoICogKGcgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgICBic3VtICs9IChoICogKGIgKyAwLjUpICogbXVsdCk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgICA7XG4gICAgICBpZiAobnRvdCkge1xuICAgICAgICB0aGlzLl9hdmcgPSBbfn4ocnN1bSAvIG50b3QpLCB+fihnc3VtIC8gbnRvdCksIH5+KGJzdW0gLyBudG90KV07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aGlzLl9hdmcgPSBbfn4obXVsdCAqICh0aGlzLnIxICsgdGhpcy5yMiArIDEpIC8gMiksIH5+KG11bHQgKiAodGhpcy5nMSArIHRoaXMuZzIgKyAxKSAvIDIpLCB+fihtdWx0ICogKHRoaXMuYjEgKyB0aGlzLmIyICsgMSkgLyAyKV07XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0aGlzLl9hdmc7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUuc3BsaXQgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgYWNjU3VtLCBidywgZCwgZG9DdXQsIGd3LCBoaXN0LCBpLCBqLCBtYXhkLCBtYXh3LCByZWYxLCByZXZlcnNlU3VtLCBydywgc3BsaXRQb2ludCwgc3VtLCB0b3RhbCwgdmJveDtcbiAgICBoaXN0ID0gdGhpcy5oaXN0O1xuICAgIGlmICghdGhpcy5jb3VudCgpKSB7XG4gICAgICByZXR1cm4gbnVsbDtcbiAgICB9XG4gICAgaWYgKHRoaXMuY291bnQoKSA9PT0gMSkge1xuICAgICAgcmV0dXJuIFt0aGlzLmNsb25lKCldO1xuICAgIH1cbiAgICBydyA9IHRoaXMucjIgLSB0aGlzLnIxICsgMTtcbiAgICBndyA9IHRoaXMuZzIgLSB0aGlzLmcxICsgMTtcbiAgICBidyA9IHRoaXMuYjIgLSB0aGlzLmIxICsgMTtcbiAgICBtYXh3ID0gTWF0aC5tYXgocncsIGd3LCBidyk7XG4gICAgYWNjU3VtID0gbnVsbDtcbiAgICBzdW0gPSB0b3RhbCA9IDA7XG4gICAgbWF4ZCA9IG51bGw7XG4gICAgc3dpdGNoIChtYXh3KSB7XG4gICAgICBjYXNlIHJ3OlxuICAgICAgICBtYXhkID0gJ3InO1xuICAgICAgICBhY2NTdW0gPSBuZXcgVWludDMyQXJyYXkodGhpcy5yMiArIDEpO1xuICAgICAgICBcbiAgICAgICAgZm9yICh2YXIgciA9IHRoaXMucjE7IHIgPD0gdGhpcy5yMjsgcisrKSB7XG4gICAgICAgICAgc3VtID0gMFxuICAgICAgICAgIGZvciAodmFyIGcgPSB0aGlzLmcxOyBnIDw9IHRoaXMuZzI7IGcrKykge1xuICAgICAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICAgIHN1bSArPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgIGFjY1N1bVtyXSA9IHRvdGFsO1xuICAgICAgICB9XG4gICAgICAgIDtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlIGd3OlxuICAgICAgICBtYXhkID0gJ2cnO1xuICAgICAgICBhY2NTdW0gPSBuZXcgVWludDMyQXJyYXkodGhpcy5nMiArIDEpO1xuICAgICAgICBcbiAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgc3VtID0gMFxuICAgICAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICAgIHN1bSArPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgIGFjY1N1bVtnXSA9IHRvdGFsO1xuICAgICAgICB9XG4gICAgICAgIDtcbiAgICAgICAgYnJlYWs7XG4gICAgICBjYXNlIGJ3OlxuICAgICAgICBtYXhkID0gJ2InO1xuICAgICAgICBhY2NTdW0gPSBuZXcgVWludDMyQXJyYXkodGhpcy5iMiArIDEpO1xuICAgICAgICBcbiAgICAgICAgZm9yICh2YXIgYiA9IHRoaXMuYjE7IGIgPD0gdGhpcy5iMjsgYisrKSB7XG4gICAgICAgICAgc3VtID0gMFxuICAgICAgICAgIGZvciAodmFyIHIgPSB0aGlzLnIxOyByIDw9IHRoaXMucjI7IHIrKykge1xuICAgICAgICAgICAgZm9yICh2YXIgZyA9IHRoaXMuZzE7IGcgPD0gdGhpcy5nMjsgZysrKSB7XG4gICAgICAgICAgICAgIHZhciBpbmRleCA9IGdldENvbG9ySW5kZXgociwgZywgYik7XG4gICAgICAgICAgICAgIHN1bSArPSBoaXN0W2luZGV4XTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICAgdG90YWwgKz0gc3VtO1xuICAgICAgICAgIGFjY1N1bVtiXSA9IHRvdGFsO1xuICAgICAgICB9XG4gICAgICAgIDtcbiAgICB9XG4gICAgc3BsaXRQb2ludCA9IC0xO1xuICAgIHJldmVyc2VTdW0gPSBuZXcgVWludDMyQXJyYXkoYWNjU3VtLmxlbmd0aCk7XG4gICAgZm9yIChpID0gaiA9IDAsIHJlZjEgPSBhY2NTdW0ubGVuZ3RoIC0gMTsgMCA8PSByZWYxID8gaiA8PSByZWYxIDogaiA+PSByZWYxOyBpID0gMCA8PSByZWYxID8gKytqIDogLS1qKSB7XG4gICAgICBkID0gYWNjU3VtW2ldO1xuICAgICAgaWYgKHNwbGl0UG9pbnQgPCAwICYmIGQgPiB0b3RhbCAvIDIpIHtcbiAgICAgICAgc3BsaXRQb2ludCA9IGk7XG4gICAgICB9XG4gICAgICByZXZlcnNlU3VtW2ldID0gdG90YWwgLSBkO1xuICAgIH1cbiAgICB2Ym94ID0gdGhpcztcbiAgICBkb0N1dCA9IGZ1bmN0aW9uKGQpIHtcbiAgICAgIHZhciBjMiwgZDEsIGQyLCBkaW0xLCBkaW0yLCBsZWZ0LCByaWdodCwgdmJveDEsIHZib3gyO1xuICAgICAgZGltMSA9IGQgKyBcIjFcIjtcbiAgICAgIGRpbTIgPSBkICsgXCIyXCI7XG4gICAgICBkMSA9IHZib3hbZGltMV07XG4gICAgICBkMiA9IHZib3hbZGltMl07XG4gICAgICB2Ym94MSA9IHZib3guY2xvbmUoKTtcbiAgICAgIHZib3gyID0gdmJveC5jbG9uZSgpO1xuICAgICAgbGVmdCA9IHNwbGl0UG9pbnQgLSBkMTtcbiAgICAgIHJpZ2h0ID0gZDIgLSBzcGxpdFBvaW50O1xuICAgICAgaWYgKGxlZnQgPD0gcmlnaHQpIHtcbiAgICAgICAgZDIgPSBNYXRoLm1pbihkMiAtIDEsIH5+KHNwbGl0UG9pbnQgKyByaWdodCAvIDIpKTtcbiAgICAgICAgZDIgPSBNYXRoLm1heCgwLCBkMik7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBkMiA9IE1hdGgubWF4KGQxLCB+fihzcGxpdFBvaW50IC0gMSAtIGxlZnQgLyAyKSk7XG4gICAgICAgIGQyID0gTWF0aC5taW4odmJveFtkaW0yXSwgZDIpO1xuICAgICAgfVxuICAgICAgd2hpbGUgKCFhY2NTdW1bZDJdKSB7XG4gICAgICAgIGQyKys7XG4gICAgICB9XG4gICAgICBjMiA9IHJldmVyc2VTdW1bZDJdO1xuICAgICAgd2hpbGUgKCFjMiAmJiBhY2NTdW1bZDIgLSAxXSkge1xuICAgICAgICBjMiA9IHJldmVyc2VTdW1bLS1kMl07XG4gICAgICB9XG4gICAgICB2Ym94MVtkaW0yXSA9IGQyO1xuICAgICAgdmJveDJbZGltMV0gPSBkMiArIDE7XG4gICAgICByZXR1cm4gW3Zib3gxLCB2Ym94Ml07XG4gICAgfTtcbiAgICByZXR1cm4gZG9DdXQobWF4ZCk7XG4gIH07XG5cbiAgVkJveC5wcm90b3R5cGUuY29udGFpbnMgPSBmdW5jdGlvbihwKSB7XG4gICAgdmFyIGIsIGcsIHI7XG4gICAgciA9IHBbMF0gPj4gUlNISUZUO1xuICAgIGcgPSBwWzFdID4+IFJTSElGVDtcbiAgICBiID0gcFsyXSA+PiBSU0hJRlQ7XG4gICAgcmV0dXJuIHIgPj0gdGhpcy5yMSAmJiByIDw9IHRoaXMucjIgJiYgZyA+PSB0aGlzLmcxICYmIGcgPD0gdGhpcy5nMiAmJiBiID49IHRoaXMuYjEgJiYgYiA8PSB0aGlzLmIyO1xuICB9O1xuXG4gIHJldHVybiBWQm94O1xuXG59KSgpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12Y1hWaGJuUnBlbVZ5TDJsdGNHd3ZkbUp2ZUM1amIyWm1aV1VpTENKemIzVnlZMlZTYjI5MElqb2lJaXdpYzI5MWNtTmxjeUk2V3lJdlZYTmxjbk12WXpRdlJHOWpkVzFsYm5SekwxQnliMnBsWTNSekwzTmxiR3hsYnk5dWIyUmxMV3h2WjI4dFkyOXNiM0p6TDNOeVl5OXhkV0Z1ZEdsNlpYSXZhVzF3YkM5MlltOTRMbU52Wm1abFpTSmRMQ0p1WVcxbGN5STZXMTBzSW0xaGNIQnBibWR6SWpvaVFVRkJRU3hKUVVGQk96dEJRVUZCTEUxQlFXMURMRWxCUVVFc1IwRkJUeXhQUVVGQkxFTkJRVkVzV1VGQlVpeERRVUV4UXl4RlFVRkRMR2xEUVVGRUxFVkJRV2RDTEhGQ1FVRm9RaXhGUVVGNVFqczdRVUZGZWtJc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUdEZRVU5LTEVsQlFVTXNRMEZCUVN4TFFVRkVMRWRCUVZFc1UwRkJReXhOUVVGRUxFVkJRVk1zV1VGQlZEdEJRVU5PTEZGQlFVRTdTVUZCUVN4RlFVRkJMRWRCUVVzc1EwRkJRU3hKUVVGSExFTkJRVU1zUTBGQlFTeEhRVUZGTEU5QlFVZzdTVUZEVWl4SlFVRkJMRWRCUVU4c1NVRkJTU3hYUVVGS0xFTkJRV2RDTEVWQlFXaENPMGxCUTFBc1NVRkJRU3hIUVVGUExFbEJRVUVzUjBGQlR5eEpRVUZCTEVkQlFVODdTVUZEY2tJc1NVRkJRU3hIUVVGUExFbEJRVUVzUjBGQlR5eEpRVUZCTEVkQlFVOHNUVUZCVFN4RFFVRkRPMGxCUXpWQ0xFTkJRVUVzUjBGQlNTeE5RVUZOTEVOQlFVTXNUVUZCVUN4SFFVRm5RanRKUVVOd1FpeERRVUZCTEVkQlFVazdRVUZGU2l4WFFVRk5MRU5CUVVFc1IwRkJTU3hEUVVGV08wMUJRMFVzVFVGQlFTeEhRVUZUTEVOQlFVRXNSMEZCU1R0TlFVTmlMRU5CUVVFN1RVRkRRU3hEUVVGQkxFZEJRVWtzVFVGQlR5eERRVUZCTEUxQlFVRXNSMEZCVXl4RFFVRlVPMDFCUTFnc1EwRkJRU3hIUVVGSkxFMUJRVThzUTBGQlFTeE5RVUZCTEVkQlFWTXNRMEZCVkR0TlFVTllMRU5CUVVFc1IwRkJTU3hOUVVGUExFTkJRVUVzVFVGQlFTeEhRVUZUTEVOQlFWUTdUVUZEV0N4RFFVRkJMRWRCUVVrc1RVRkJUeXhEUVVGQkxFMUJRVUVzUjBGQlV5eERRVUZVTzAxQlJWZ3NTVUZCUnl4WlFVRkJMRU5CUVdFc1EwRkJZaXhGUVVGblFpeERRVUZvUWl4RlFVRnRRaXhEUVVGdVFpeEZRVUZ6UWl4RFFVRjBRaXhEUVVGSU8wRkJRV2xETEdsQ1FVRnFRenM3VFVGRlFTeERRVUZCTEVkQlFVa3NRMEZCUVN4SlFVRkxPMDFCUTFRc1EwRkJRU3hIUVVGSkxFTkJRVUVzU1VGQlN6dE5RVU5VTEVOQlFVRXNSMEZCU1N4RFFVRkJMRWxCUVVzN1RVRkhWQ3hMUVVGQkxFZEJRVkVzWVVGQlFTeERRVUZqTEVOQlFXUXNSVUZCYVVJc1EwRkJha0lzUlVGQmIwSXNRMEZCY0VJN1RVRkRVaXhKUVVGTExFTkJRVUVzUzBGQlFTeERRVUZNTEVsQlFXVTdUVUZGWml4SlFVRkhMRU5CUVVFc1IwRkJTU3hKUVVGUU8xRkJRMFVzU1VGQlFTeEhRVUZQTEVWQlJGUTdPMDFCUlVFc1NVRkJSeXhEUVVGQkxFZEJRVWtzU1VGQlVEdFJRVU5GTEVsQlFVRXNSMEZCVHl4RlFVUlVPenROUVVWQkxFbEJRVWNzUTBGQlFTeEhRVUZKTEVsQlFWQTdVVUZEUlN4SlFVRkJMRWRCUVU4c1JVRkVWRHM3VFVGRlFTeEpRVUZITEVOQlFVRXNSMEZCU1N4SlFVRlFPMUZCUTBVc1NVRkJRU3hIUVVGUExFVkJSRlE3TzAxQlJVRXNTVUZCUnl4RFFVRkJMRWRCUVVrc1NVRkJVRHRSUVVORkxFbEJRVUVzUjBGQlR5eEZRVVJVT3p0TlFVVkJMRWxCUVVjc1EwRkJRU3hIUVVGSkxFbEJRVkE3VVVGRFJTeEpRVUZCTEVkQlFVOHNSVUZFVkRzN1NVRTFRa1k3VjBFclFrRXNTVUZCU1N4SlFVRktMRU5CUVZNc1NVRkJWQ3hGUVVGbExFbEJRV1lzUlVGQmNVSXNTVUZCY2tJc1JVRkJNa0lzU1VGQk0wSXNSVUZCYVVNc1NVRkJha01zUlVGQmRVTXNTVUZCZGtNc1JVRkJOa01zU1VGQk4wTTdSVUYyUTAwN08wVkJlVU5MTEdOQlFVTXNSVUZCUkN4RlFVRk5MRVZCUVU0c1JVRkJWeXhGUVVGWUxFVkJRV2RDTEVWQlFXaENMRVZCUVhGQ0xFVkJRWEpDTEVWQlFUQkNMRVZCUVRGQ0xFVkJRU3RDTEV0QlFTOUNPMGxCUVVNc1NVRkJReXhEUVVGQkxFdEJRVVE3U1VGQlN5eEpRVUZETEVOQlFVRXNTMEZCUkR0SlFVRkxMRWxCUVVNc1EwRkJRU3hMUVVGRU8wbEJRVXNzU1VGQlF5eERRVUZCTEV0QlFVUTdTVUZCU3l4SlFVRkRMRU5CUVVFc1MwRkJSRHRKUVVGTExFbEJRVU1zUTBGQlFTeExRVUZFTzBsQlFVc3NTVUZCUXl4RFFVRkJMRTlCUVVRN1JVRkJMMEk3TzJsQ1FVZGlMRlZCUVVFc1IwRkJXU3hUUVVGQk8wbEJRMVlzVDBGQlR5eEpRVUZETEVOQlFVRTdTVUZEVWl4UFFVRlBMRWxCUVVNc1EwRkJRVHRYUVVOU0xFOUJRVThzU1VGQlF5eERRVUZCTzBWQlNFVTdPMmxDUVV0YUxFMUJRVUVzUjBGQlVTeFRRVUZCTzBsQlEwNHNTVUZCVHl4dlFrRkJVRHROUVVORkxFbEJRVU1zUTBGQlFTeFBRVUZFTEVkQlFWY3NRMEZCUXl4SlFVRkRMRU5CUVVFc1JVRkJSQ3hIUVVGTkxFbEJRVU1zUTBGQlFTeEZRVUZRTEVkQlFWa3NRMEZCWWl4RFFVRkJMRWRCUVd0Q0xFTkJRVU1zU1VGQlF5eERRVUZCTEVWQlFVUXNSMEZCVFN4SlFVRkRMRU5CUVVFc1JVRkJVQ3hIUVVGWkxFTkJRV0lzUTBGQmJFSXNSMEZCYjBNc1EwRkJReXhKUVVGRExFTkJRVUVzUlVGQlJDeEhRVUZOTEVsQlFVTXNRMEZCUVN4RlFVRlFMRWRCUVZrc1EwRkJZaXhGUVVScVJEczdWMEZGUVN4SlFVRkRMRU5CUVVFN1JVRklTenM3YVVKQlMxSXNTMEZCUVN4SFFVRlBMRk5CUVVFN1FVRkRUQ3hSUVVGQk8wbEJRVUVzU1VGQlR5eHRRa0ZCVUR0TlFVTkZMRWxCUVVFc1IwRkJUeXhKUVVGRExFTkJRVUU3VFVGRFVpeERRVUZCTEVkQlFVazdUVUZEU2pzN096czdPenM3T3p0TlFXVkJMRWxCUVVNc1EwRkJRU3hOUVVGRUxFZEJRVlVzUlVGc1FsbzdPMWRCYlVKQkxFbEJRVU1zUTBGQlFUdEZRWEJDU1RzN2FVSkJjMEpRTEV0QlFVRXNSMEZCVHl4VFFVRkJPMWRCUTB3c1NVRkJTU3hKUVVGS0xFTkJRVk1zU1VGQlF5eERRVUZCTEVWQlFWWXNSVUZCWXl4SlFVRkRMRU5CUVVFc1JVRkJaaXhGUVVGdFFpeEpRVUZETEVOQlFVRXNSVUZCY0VJc1JVRkJkMElzU1VGQlF5eERRVUZCTEVWQlFYcENMRVZCUVRaQ0xFbEJRVU1zUTBGQlFTeEZRVUU1UWl4RlFVRnJReXhKUVVGRExFTkJRVUVzUlVGQmJrTXNSVUZCZFVNc1NVRkJReXhEUVVGQkxFbEJRWGhETzBWQlJFczdPMmxDUVVkUUxFZEJRVUVzUjBGQlN5eFRRVUZCTzBGQlEwZ3NVVUZCUVR0SlFVRkJMRWxCUVU4c2FVSkJRVkE3VFVGRFJTeEpRVUZCTEVkQlFVOHNTVUZCUXl4RFFVRkJPMDFCUTFJc1NVRkJRU3hIUVVGUE8wMUJRMUFzU1VGQlFTeEhRVUZQTEVOQlFVRXNTVUZCU3l4RFFVRkRMRU5CUVVFc1IwRkJTU3hQUVVGTU8wMUJRMW9zU1VGQlFTeEhRVUZQTEVsQlFVRXNSMEZCVHl4SlFVRkJMRWRCUVU4N1RVRkRja0k3T3pzN096czdPenM3T3pzN08wMUJlVUpCTEVsQlFVY3NTVUZCU0R0UlFVTkZMRWxCUVVNc1EwRkJRU3hKUVVGRUxFZEJRVkVzUTBGRFRpeERRVUZETEVOQlFVTXNRMEZCUXl4SlFVRkJMRWRCUVU4c1NVRkJVaXhEUVVSSkxFVkJSVTRzUTBGQlF5eERRVUZETEVOQlFVTXNTVUZCUVN4SFFVRlBMRWxCUVZJc1EwRkdTU3hGUVVkT0xFTkJRVU1zUTBGQlF5eERRVUZETEVsQlFVRXNSMEZCVHl4SlFVRlNMRU5CU0Vrc1JVRkVWanRQUVVGQkxFMUJRVUU3VVVGUFJTeEpRVUZETEVOQlFVRXNTVUZCUkN4SFFVRlJMRU5CUTA0c1EwRkJReXhEUVVGRExFTkJRVU1zU1VGQlFTeEhRVUZQTEVOQlFVTXNTVUZCUXl4RFFVRkJMRVZCUVVRc1IwRkJUU3hKUVVGRExFTkJRVUVzUlVGQlVDeEhRVUZaTEVOQlFXSXNRMEZCVUN4SFFVRjVRaXhEUVVFeFFpeERRVVJKTEVWQlJVNHNRMEZCUXl4RFFVRkRMRU5CUVVNc1NVRkJRU3hIUVVGUExFTkJRVU1zU1VGQlF5eERRVUZCTEVWQlFVUXNSMEZCVFN4SlFVRkRMRU5CUVVFc1JVRkJVQ3hIUVVGWkxFTkJRV0lzUTBGQlVDeEhRVUY1UWl4RFFVRXhRaXhEUVVaSkxFVkJSMDRzUTBGQlF5eERRVUZETEVOQlFVTXNTVUZCUVN4SFFVRlBMRU5CUVVNc1NVRkJReXhEUVVGQkxFVkJRVVFzUjBGQlRTeEpRVUZETEVOQlFVRXNSVUZCVUN4SFFVRlpMRU5CUVdJc1EwRkJVQ3hIUVVGNVFpeERRVUV4UWl4RFFVaEpMRVZCVUZZN1QwRTVRa1k3TzFkQk1FTkJMRWxCUVVNc1EwRkJRVHRGUVRORFJUczdhVUpCTmtOTUxFdEJRVUVzUjBGQlR5eFRRVUZCTzBGQlEwd3NVVUZCUVR0SlFVRkJMRWxCUVVFc1IwRkJUeXhKUVVGRExFTkJRVUU3U1VGRFVpeEpRVUZITEVOQlFVTXNTVUZCUXl4RFFVRkJMRXRCUVVRc1EwRkJRU3hEUVVGS08wRkJRMFVzWVVGQlR5eExRVVJVT3p0SlFVVkJMRWxCUVVjc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeERRVUZCTEV0QlFWa3NRMEZCWmp0QlFVTkZMR0ZCUVU4c1EwRkJReXhKUVVGRExFTkJRVUVzUzBGQlJDeERRVUZCTEVOQlFVUXNSVUZFVkRzN1NVRkhRU3hGUVVGQkxFZEJRVXNzU1VGQlF5eERRVUZCTEVWQlFVUXNSMEZCVFN4SlFVRkRMRU5CUVVFc1JVRkJVQ3hIUVVGWk8wbEJRMnBDTEVWQlFVRXNSMEZCU3l4SlFVRkRMRU5CUVVFc1JVRkJSQ3hIUVVGTkxFbEJRVU1zUTBGQlFTeEZRVUZRTEVkQlFWazdTVUZEYWtJc1JVRkJRU3hIUVVGTExFbEJRVU1zUTBGQlFTeEZRVUZFTEVkQlFVMHNTVUZCUXl4RFFVRkJMRVZCUVZBc1IwRkJXVHRKUVVWcVFpeEpRVUZCTEVkQlFVOHNTVUZCU1N4RFFVRkRMRWRCUVV3c1EwRkJVeXhGUVVGVUxFVkJRV0VzUlVGQllpeEZRVUZwUWl4RlFVRnFRanRKUVVOUUxFMUJRVUVzUjBGQlV6dEpRVU5VTEVkQlFVRXNSMEZCVFN4TFFVRkJMRWRCUVZFN1NVRkZaQ3hKUVVGQkxFZEJRVTg3UVVGRFVDeFpRVUZQTEVsQlFWQTdRVUZCUVN4WFFVTlBMRVZCUkZBN1VVRkZTU3hKUVVGQkxFZEJRVTg3VVVGRFVDeE5RVUZCTEVkQlFWTXNTVUZCU1N4WFFVRktMRU5CUVdkQ0xFbEJRVU1zUTBGQlFTeEZRVUZFTEVkQlFVMHNRMEZCZEVJN1VVRkRWRHM3T3pzN096czdPenM3T3p0QlFVaEhPMEZCUkZBc1YwRjVRazhzUlVGNlFsQTdVVUV3UWtrc1NVRkJRU3hIUVVGUE8xRkJRMUFzVFVGQlFTeEhRVUZUTEVsQlFVa3NWMEZCU2l4RFFVRm5RaXhKUVVGRExFTkJRVUVzUlVGQlJDeEhRVUZOTEVOQlFYUkNPMUZCUTFRN096czdPenM3T3pzN096czdRVUZJUnp0QlFYcENVQ3hYUVdsRVR5eEZRV3BFVUR0UlFXdEVTU3hKUVVGQkxFZEJRVTg3VVVGRFVDeE5RVUZCTEVkQlFWTXNTVUZCU1N4WFFVRktMRU5CUVdkQ0xFbEJRVU1zUTBGQlFTeEZRVUZFTEVkQlFVMHNRMEZCZEVJN1VVRkRWRHM3T3pzN096czdPenM3T3p0QlFYQkVTanRKUVRCRlFTeFZRVUZCTEVkQlFXRXNRMEZCUXp0SlFVTmtMRlZCUVVFc1IwRkJZU3hKUVVGSkxGZEJRVW9zUTBGQlowSXNUVUZCVFN4RFFVRkRMRTFCUVhaQ08wRkJRMklzVTBGQlV5eHBSMEZCVkR0TlFVTkZMRU5CUVVFc1IwRkJTU3hOUVVGUExFTkJRVUVzUTBGQlFUdE5RVU5ZTEVsQlFVY3NWVUZCUVN4SFFVRmhMRU5CUVdJc1NVRkJhMElzUTBGQlFTeEhRVUZKTEV0QlFVRXNSMEZCVVN4RFFVRnFRenRSUVVORkxGVkJRVUVzUjBGQllTeEZRVVJtT3p0TlFVVkJMRlZCUVZjc1EwRkJRU3hEUVVGQkxFTkJRVmdzUjBGQlowSXNTMEZCUVN4SFFVRlJPMEZCU2pGQ08wbEJUVUVzU1VGQlFTeEhRVUZQTzBsQlExQXNTMEZCUVN4SFFVRlJMRk5CUVVNc1EwRkJSRHRCUVVOT0xGVkJRVUU3VFVGQlFTeEpRVUZCTEVkQlFVOHNRMEZCUVN4SFFVRkpPMDFCUTFnc1NVRkJRU3hIUVVGUExFTkJRVUVzUjBGQlNUdE5RVU5ZTEVWQlFVRXNSMEZCU3l4SlFVRkxMRU5CUVVFc1NVRkJRVHROUVVOV0xFVkJRVUVzUjBGQlN5eEpRVUZMTEVOQlFVRXNTVUZCUVR0TlFVTldMRXRCUVVFc1IwRkJVU3hKUVVGSkxFTkJRVU1zUzBGQlRDeERRVUZCTzAxQlExSXNTMEZCUVN4SFFVRlJMRWxCUVVrc1EwRkJReXhMUVVGTUxFTkJRVUU3VFVGRFVpeEpRVUZCTEVkQlFVOHNWVUZCUVN4SFFVRmhPMDFCUTNCQ0xFdEJRVUVzUjBGQlVTeEZRVUZCTEVkQlFVczdUVUZEWWl4SlFVRkhMRWxCUVVFc1NVRkJVU3hMUVVGWU8xRkJRMFVzUlVGQlFTeEhRVUZMTEVsQlFVa3NRMEZCUXl4SFFVRk1MRU5CUVZNc1JVRkJRU3hIUVVGTExFTkJRV1FzUlVGQmFVSXNRMEZCUXl4RFFVRkZMRU5CUVVNc1ZVRkJRU3hIUVVGaExFdEJRVUVzUjBGQlVTeERRVUYwUWl4RFFVRndRanRSUVVOTUxFVkJRVUVzUjBGQlN5eEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRU5CUVZRc1JVRkJXU3hGUVVGYUxFVkJSbEE3VDBGQlFTeE5RVUZCTzFGQlNVVXNSVUZCUVN4SFFVRkxMRWxCUVVrc1EwRkJReXhIUVVGTUxFTkJRVk1zUlVGQlZDeEZRVUZoTEVOQlFVTXNRMEZCUlN4RFFVRkRMRlZCUVVFc1IwRkJZU3hEUVVGaUxFZEJRV2xDTEVsQlFVRXNSMEZCVHl4RFFVRjZRaXhEUVVGb1FqdFJRVU5NTEVWQlFVRXNSMEZCU3l4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFbEJRVXNzUTBGQlFTeEpRVUZCTEVOQlFXUXNSVUZCY1VJc1JVRkJja0lzUlVGTVVEczdRVUZSUVN4aFFVRk5MRU5CUVVNc1RVRkJUeXhEUVVGQkxFVkJRVUVzUTBGQlpEdFJRVU5GTEVWQlFVRTdUVUZFUmp0TlFVbEJMRVZCUVVFc1IwRkJTeXhWUVVGWExFTkJRVUVzUlVGQlFUdEJRVU5vUWl4aFFVRk5MRU5CUVVNc1JVRkJSQ3hKUVVGUkxFMUJRVThzUTBGQlFTeEZRVUZCTEVkQlFVc3NRMEZCVEN4RFFVRnlRanRSUVVORkxFVkJRVUVzUjBGQlN5eFZRVUZYTEVOQlFVRXNSVUZCUlN4RlFVRkdPMDFCUkd4Q08wMUJSMEVzUzBGQlRTeERRVUZCTEVsQlFVRXNRMEZCVGl4SFFVRmpPMDFCUTJRc1MwRkJUU3hEUVVGQkxFbEJRVUVzUTBGQlRpeEhRVUZqTEVWQlFVRXNSMEZCU3p0QlFVZHVRaXhoUVVGUExFTkJRVU1zUzBGQlJDeEZRVUZSTEV0QlFWSTdTVUUzUWtRN1YwRXJRbElzUzBGQlFTeERRVUZOTEVsQlFVNDdSVUZzU1VzN08ybENRVzlKVUN4UlFVRkJMRWRCUVZVc1UwRkJReXhEUVVGRU8wRkJRMUlzVVVGQlFUdEpRVUZCTEVOQlFVRXNSMEZCU1N4RFFVRkZMRU5CUVVFc1EwRkJRU3hEUVVGR0xFbEJRVTA3U1VGRFZpeERRVUZCTEVkQlFVa3NRMEZCUlN4RFFVRkJMRU5CUVVFc1EwRkJSaXhKUVVGTk8wbEJRMVlzUTBGQlFTeEhRVUZKTEVOQlFVVXNRMEZCUVN4RFFVRkJMRU5CUVVZc1NVRkJUVHRYUVVWV0xFTkJRVUVzU1VGQlN5eEpRVUZETEVOQlFVRXNSVUZCVGl4SlFVRmhMRU5CUVVFc1NVRkJTeXhKUVVGRExFTkJRVUVzUlVGQmJrSXNTVUZCTUVJc1EwRkJRU3hKUVVGTExFbEJRVU1zUTBGQlFTeEZRVUZvUXl4SlFVRjFReXhEUVVGQkxFbEJRVXNzU1VGQlF5eERRVUZCTEVWQlFUZERMRWxCUVc5RUxFTkJRVUVzU1VGQlN5eEpRVUZETEVOQlFVRXNSVUZCTVVRc1NVRkJhVVVzUTBGQlFTeEpRVUZMTEVsQlFVTXNRMEZCUVR0RlFVd3ZSQ0o5XG4iLCJ2YXIgUXVhbnRpemVyO1xuXG5tb2R1bGUuZXhwb3J0cyA9IFF1YW50aXplciA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gUXVhbnRpemVyKCkge31cblxuICBRdWFudGl6ZXIucHJvdG90eXBlLmluaXRpYWxpemUgPSBmdW5jdGlvbihwaXhlbHMsIG9wdHMpIHt9O1xuXG4gIFF1YW50aXplci5wcm90b3R5cGUuZ2V0UXVhbnRpemVkQ29sb3JzID0gZnVuY3Rpb24oKSB7fTtcblxuICByZXR1cm4gUXVhbnRpemVyO1xuXG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cy5NTUNRID0gcmVxdWlyZSgnLi9tbWNxJyk7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMmx1WkdWNExtTnZabVpsWlNJc0luTnZkWEpqWlZKdmIzUWlPaUlpTENKemIzVnlZMlZ6SWpwYklpOVZjMlZ5Y3k5ak5DOUViMk4xYldWdWRITXZVSEp2YW1WamRITXZjMlZzYkdWdkwyNXZaR1V0Ykc5bmJ5MWpiMnh2Y25NdmMzSmpMM0YxWVc1MGFYcGxjaTlwYm1SbGVDNWpiMlptWldVaVhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWtGQlFVRXNTVUZCUVRzN1FVRkJRU3hOUVVGTkxFTkJRVU1zVDBGQlVDeEhRVU5OT3pzN2MwSkJRMG9zVlVGQlFTeEhRVUZaTEZOQlFVTXNUVUZCUkN4RlFVRlRMRWxCUVZRc1IwRkJRVHM3YzBKQlJWb3NhMEpCUVVFc1IwRkJiMElzVTBGQlFTeEhRVUZCT3pzN096czdRVUZGZEVJc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eEpRVUZtTEVkQlFYTkNMRTlCUVVFc1EwRkJVU3hSUVVGU0luMD1cbiIsInZhciBNTUNRLCBNTUNRSW1wbCwgUXVhbnRpemVyLCBTd2F0Y2gsXG4gIGV4dGVuZCA9IGZ1bmN0aW9uKGNoaWxkLCBwYXJlbnQpIHsgZm9yICh2YXIga2V5IGluIHBhcmVudCkgeyBpZiAoaGFzUHJvcC5jYWxsKHBhcmVudCwga2V5KSkgY2hpbGRba2V5XSA9IHBhcmVudFtrZXldOyB9IGZ1bmN0aW9uIGN0b3IoKSB7IHRoaXMuY29uc3RydWN0b3IgPSBjaGlsZDsgfSBjdG9yLnByb3RvdHlwZSA9IHBhcmVudC5wcm90b3R5cGU7IGNoaWxkLnByb3RvdHlwZSA9IG5ldyBjdG9yKCk7IGNoaWxkLl9fc3VwZXJfXyA9IHBhcmVudC5wcm90b3R5cGU7IHJldHVybiBjaGlsZDsgfSxcbiAgaGFzUHJvcCA9IHt9Lmhhc093blByb3BlcnR5O1xuXG5Td2F0Y2ggPSByZXF1aXJlKCcuLi9zd2F0Y2gnKTtcblxuUXVhbnRpemVyID0gcmVxdWlyZSgnLi9pbmRleCcpO1xuXG5NTUNRSW1wbCA9IHJlcXVpcmUoJy4vaW1wbC9tbWNxJyk7XG5cbm1vZHVsZS5leHBvcnRzID0gTU1DUSA9IChmdW5jdGlvbihzdXBlckNsYXNzKSB7XG4gIGV4dGVuZChNTUNRLCBzdXBlckNsYXNzKTtcblxuICBmdW5jdGlvbiBNTUNRKCkge1xuICAgIHJldHVybiBNTUNRLl9fc3VwZXJfXy5jb25zdHJ1Y3Rvci5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuICB9XG5cbiAgTU1DUS5wcm90b3R5cGUuaW5pdGlhbGl6ZSA9IGZ1bmN0aW9uKHBpeGVscywgb3B0cykge1xuICAgIHZhciBtbWNxO1xuICAgIHRoaXMub3B0cyA9IG9wdHM7XG4gICAgbW1jcSA9IG5ldyBNTUNRSW1wbCgpO1xuICAgIHJldHVybiB0aGlzLnN3YXRjaGVzID0gbW1jcS5xdWFudGl6ZShwaXhlbHMsIHRoaXMub3B0cyk7XG4gIH07XG5cbiAgTU1DUS5wcm90b3R5cGUuZ2V0UXVhbnRpemVkQ29sb3JzID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMuc3dhdGNoZXM7XG4gIH07XG5cbiAgcmV0dXJuIE1NQ1E7XG5cbn0pKFF1YW50aXplcik7XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMjF0WTNFdVkyOW1abVZsSWl3aWMyOTFjbU5sVW05dmRDSTZJaUlzSW5OdmRYSmpaWE1pT2xzaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZjWFZoYm5ScGVtVnlMMjF0WTNFdVkyOW1abVZsSWwwc0ltNWhiV1Z6SWpwYlhTd2liV0Z3Y0dsdVozTWlPaUpCUVVGQkxFbEJRVUVzYVVOQlFVRTdSVUZCUVRzN08wRkJRVUVzVFVGQlFTeEhRVUZUTEU5QlFVRXNRMEZCVVN4WFFVRlNPenRCUVVOVUxGTkJRVUVzUjBGQldTeFBRVUZCTEVOQlFWRXNVMEZCVWpzN1FVRkRXaXhSUVVGQkxFZEJRVmNzVDBGQlFTeERRVUZSTEdGQlFWSTdPMEZCUlZnc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUczdPenM3T3p0cFFrRkRTaXhWUVVGQkxFZEJRVmtzVTBGQlF5eE5RVUZFTEVWQlFWTXNTVUZCVkR0QlFVTldMRkZCUVVFN1NVRkViVUlzU1VGQlF5eERRVUZCTEU5QlFVUTdTVUZEYmtJc1NVRkJRU3hIUVVGUExFbEJRVWtzVVVGQlNpeERRVUZCTzFkQlExQXNTVUZCUXl4RFFVRkJMRkZCUVVRc1IwRkJXU3hKUVVGSkxFTkJRVU1zVVVGQlRDeERRVUZqTEUxQlFXUXNSVUZCYzBJc1NVRkJReXhEUVVGQkxFbEJRWFpDTzBWQlJrWTdPMmxDUVVsYUxHdENRVUZCTEVkQlFXOUNMRk5CUVVFN1YwRkRiRUlzU1VGQlF5eERRVUZCTzBWQlJHbENPenM3TzBkQlRFZ2lmUT09XG4iLCJ2YXIgU3dhdGNoLCB1dGlsO1xuXG51dGlsID0gcmVxdWlyZSgnLi91dGlsJyk7XG5cblxuLypcbiAgRnJvbSBWaWJyYW50LmpzIGJ5IEphcmkgWndhcnRzXG4gIFBvcnRlZCB0byBub2RlLmpzIGJ5IEFLRmlzaFxuXG4gIFN3YXRjaCBjbGFzc1xuICovXG5cbm1vZHVsZS5leHBvcnRzID0gU3dhdGNoID0gKGZ1bmN0aW9uKCkge1xuICBTd2F0Y2gucHJvdG90eXBlLmhzbCA9IHZvaWQgMDtcblxuICBTd2F0Y2gucHJvdG90eXBlLnJnYiA9IHZvaWQgMDtcblxuICBTd2F0Y2gucHJvdG90eXBlLnBvcHVsYXRpb24gPSAxO1xuXG4gIFN3YXRjaC5wcm90b3R5cGUueWlxID0gMDtcblxuICBmdW5jdGlvbiBTd2F0Y2gocmdiLCBwb3B1bGF0aW9uKSB7XG4gICAgdGhpcy5yZ2IgPSByZ2I7XG4gICAgdGhpcy5wb3B1bGF0aW9uID0gcG9wdWxhdGlvbjtcbiAgfVxuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0SHNsID0gZnVuY3Rpb24oKSB7XG4gICAgaWYgKCF0aGlzLmhzbCkge1xuICAgICAgcmV0dXJuIHRoaXMuaHNsID0gdXRpbC5yZ2JUb0hzbCh0aGlzLnJnYlswXSwgdGhpcy5yZ2JbMV0sIHRoaXMucmdiWzJdKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHRoaXMuaHNsO1xuICAgIH1cbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLmdldFBvcHVsYXRpb24gPSBmdW5jdGlvbigpIHtcbiAgICByZXR1cm4gdGhpcy5wb3B1bGF0aW9uO1xuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0UmdiID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHRoaXMucmdiO1xuICB9O1xuXG4gIFN3YXRjaC5wcm90b3R5cGUuZ2V0SGV4ID0gZnVuY3Rpb24oKSB7XG4gICAgcmV0dXJuIHV0aWwucmdiVG9IZXgodGhpcy5yZ2JbMF0sIHRoaXMucmdiWzFdLCB0aGlzLnJnYlsyXSk7XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5nZXRUaXRsZVRleHRDb2xvciA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMuX2Vuc3VyZVRleHRDb2xvcnMoKTtcbiAgICBpZiAodGhpcy55aXEgPCAyMDApIHtcbiAgICAgIHJldHVybiBcIiNmZmZcIjtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIFwiIzAwMFwiO1xuICAgIH1cbiAgfTtcblxuICBTd2F0Y2gucHJvdG90eXBlLmdldEJvZHlUZXh0Q29sb3IgPSBmdW5jdGlvbigpIHtcbiAgICB0aGlzLl9lbnN1cmVUZXh0Q29sb3JzKCk7XG4gICAgaWYgKHRoaXMueWlxIDwgMTUwKSB7XG4gICAgICByZXR1cm4gXCIjZmZmXCI7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiBcIiMwMDBcIjtcbiAgICB9XG4gIH07XG5cbiAgU3dhdGNoLnByb3RvdHlwZS5fZW5zdXJlVGV4dENvbG9ycyA9IGZ1bmN0aW9uKCkge1xuICAgIGlmICghdGhpcy55aXEpIHtcbiAgICAgIHJldHVybiB0aGlzLnlpcSA9ICh0aGlzLnJnYlswXSAqIDI5OSArIHRoaXMucmdiWzFdICogNTg3ICsgdGhpcy5yZ2JbMl0gKiAxMTQpIC8gMTAwMDtcbiAgICB9XG4gIH07XG5cbiAgcmV0dXJuIFN3YXRjaDtcblxufSkoKTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKbWFXeGxJam9pTDFWelpYSnpMMk0wTDBSdlkzVnRaVzUwY3k5UWNtOXFaV04wY3k5elpXeHNaVzh2Ym05a1pTMXNiMmR2TFdOdmJHOXljeTl6Y21NdmMzZGhkR05vTG1OdlptWmxaU0lzSW5OdmRYSmpaVkp2YjNRaU9pSWlMQ0p6YjNWeVkyVnpJanBiSWk5VmMyVnljeTlqTkM5RWIyTjFiV1Z1ZEhNdlVISnZhbVZqZEhNdmMyVnNiR1Z2TDI1dlpHVXRiRzluYnkxamIyeHZjbk12YzNKakwzTjNZWFJqYUM1amIyWm1aV1VpWFN3aWJtRnRaWE1pT2x0ZExDSnRZWEJ3YVc1bmN5STZJa0ZCUVVFc1NVRkJRVHM3UVVGQlFTeEpRVUZCTEVkQlFVOHNUMEZCUVN4RFFVRlJMRkZCUVZJN096dEJRVU5RT3pzN096czdPMEZCVFVFc1RVRkJUU3hEUVVGRExFOUJRVkFzUjBGRFRUdHRRa0ZEU2l4SFFVRkJMRWRCUVVzN08yMUNRVU5NTEVkQlFVRXNSMEZCU3pzN2JVSkJRMHdzVlVGQlFTeEhRVUZaT3p0dFFrRkRXaXhIUVVGQkxFZEJRVXM3TzBWQlJWRXNaMEpCUVVNc1IwRkJSQ3hGUVVGTkxGVkJRVTQ3U1VGRFdDeEpRVUZETEVOQlFVRXNSMEZCUkN4SFFVRlBPMGxCUTFBc1NVRkJReXhEUVVGQkxGVkJRVVFzUjBGQll6dEZRVVpJT3p0dFFrRkpZaXhOUVVGQkxFZEJRVkVzVTBGQlFUdEpRVU5PTEVsQlFVY3NRMEZCU1N4SlFVRkRMRU5CUVVFc1IwRkJVanRoUVVORkxFbEJRVU1zUTBGQlFTeEhRVUZFTEVkQlFVOHNTVUZCU1N4RFFVRkRMRkZCUVV3c1EwRkJZeXhKUVVGRExFTkJRVUVzUjBGQlNTeERRVUZCTEVOQlFVRXNRMEZCYmtJc1JVRkJkVUlzU1VGQlF5eERRVUZCTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVRWQ0xFVkJRV2RETEVsQlFVTXNRMEZCUVN4SFFVRkpMRU5CUVVFc1EwRkJRU3hEUVVGeVF5eEZRVVJVTzB0QlFVRXNUVUZCUVR0aFFVVkxMRWxCUVVNc1EwRkJRU3hKUVVaT096dEZRVVJOT3p0dFFrRkxVaXhoUVVGQkxFZEJRV1VzVTBGQlFUdFhRVU5pTEVsQlFVTXNRMEZCUVR0RlFVUlpPenR0UWtGSFppeE5RVUZCTEVkQlFWRXNVMEZCUVR0WFFVTk9MRWxCUVVNc1EwRkJRVHRGUVVSTE96dHRRa0ZIVWl4TlFVRkJMRWRCUVZFc1UwRkJRVHRYUVVOT0xFbEJRVWtzUTBGQlF5eFJRVUZNTEVOQlFXTXNTVUZCUXl4RFFVRkJMRWRCUVVrc1EwRkJRU3hEUVVGQkxFTkJRVzVDTEVWQlFYVkNMRWxCUVVNc1EwRkJRU3hIUVVGSkxFTkJRVUVzUTBGQlFTeERRVUUxUWl4RlFVRm5ReXhKUVVGRExFTkJRVUVzUjBGQlNTeERRVUZCTEVOQlFVRXNRMEZCY2tNN1JVRkVUVHM3YlVKQlIxSXNhVUpCUVVFc1IwRkJiVUlzVTBGQlFUdEpRVU5xUWl4SlFVRkRMRU5CUVVFc2FVSkJRVVFzUTBGQlFUdEpRVU5CTEVsQlFVY3NTVUZCUXl4RFFVRkJMRWRCUVVRc1IwRkJUeXhIUVVGV08yRkJRVzFDTEU5QlFXNUNPMHRCUVVFc1RVRkJRVHRoUVVFclFpeFBRVUV2UWpzN1JVRkdhVUk3TzIxQ1FVbHVRaXhuUWtGQlFTeEhRVUZyUWl4VFFVRkJPMGxCUTJoQ0xFbEJRVU1zUTBGQlFTeHBRa0ZCUkN4RFFVRkJPMGxCUTBFc1NVRkJSeXhKUVVGRExFTkJRVUVzUjBGQlJDeEhRVUZQTEVkQlFWWTdZVUZCYlVJc1QwRkJia0k3UzBGQlFTeE5RVUZCTzJGQlFTdENMRTlCUVM5Q096dEZRVVpuUWpzN2JVSkJTV3hDTEdsQ1FVRkJMRWRCUVcxQ0xGTkJRVUU3U1VGRGFrSXNTVUZCUnl4RFFVRkpMRWxCUVVNc1EwRkJRU3hIUVVGU08yRkJRV2xDTEVsQlFVTXNRMEZCUVN4SFFVRkVMRWRCUVU4c1EwRkJReXhKUVVGRExFTkJRVUVzUjBGQlNTeERRVUZCTEVOQlFVRXNRMEZCVEN4SFFVRlZMRWRCUVZZc1IwRkJaMElzU1VGQlF5eERRVUZCTEVkQlFVa3NRMEZCUVN4RFFVRkJMRU5CUVV3c1IwRkJWU3hIUVVFeFFpeEhRVUZuUXl4SlFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGQkxFTkJRVUVzUTBGQlRDeEhRVUZWTEVkQlFUTkRMRU5CUVVFc1IwRkJhMFFzUzBGQk1VVTdPMFZCUkdsQ0luMD1cbiIsInZhciBERUxUQUU5NCwgUlNISUZULCBTSUdCSVRTO1xuXG5ERUxUQUU5NCA9IHtcbiAgTkE6IDAsXG4gIFBFUkZFQ1Q6IDEsXG4gIENMT1NFOiAyLFxuICBHT09EOiAxMCxcbiAgU0lNSUxBUjogNTBcbn07XG5cblNJR0JJVFMgPSA1O1xuXG5SU0hJRlQgPSA4IC0gU0lHQklUUztcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIGNsb25lOiBmdW5jdGlvbihvKSB7XG4gICAgdmFyIF9vLCBrZXksIHZhbHVlO1xuICAgIGlmICh0eXBlb2YgbyA9PT0gJ29iamVjdCcpIHtcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KG8pKSB7XG4gICAgICAgIHJldHVybiBvLm1hcCgoZnVuY3Rpb24oX3RoaXMpIHtcbiAgICAgICAgICByZXR1cm4gZnVuY3Rpb24odikge1xuICAgICAgICAgICAgcmV0dXJuIF90aGlzLmNsb25lKHYpO1xuICAgICAgICAgIH07XG4gICAgICAgIH0pKHRoaXMpKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIF9vID0ge307XG4gICAgICAgIGZvciAoa2V5IGluIG8pIHtcbiAgICAgICAgICB2YWx1ZSA9IG9ba2V5XTtcbiAgICAgICAgICBfb1trZXldID0gdGhpcy5jbG9uZSh2YWx1ZSk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIF9vO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbztcbiAgfSxcbiAgZGVmYXVsdHM6IGZ1bmN0aW9uKCkge1xuICAgIHZhciBfbywgaSwga2V5LCBsZW4sIG8sIHZhbHVlO1xuICAgIG8gPSB7fTtcbiAgICBmb3IgKGkgPSAwLCBsZW4gPSBhcmd1bWVudHMubGVuZ3RoOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIF9vID0gYXJndW1lbnRzW2ldO1xuICAgICAgZm9yIChrZXkgaW4gX28pIHtcbiAgICAgICAgdmFsdWUgPSBfb1trZXldO1xuICAgICAgICBpZiAob1trZXldID09IG51bGwpIHtcbiAgICAgICAgICBvW2tleV0gPSB0aGlzLmNsb25lKHZhbHVlKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbztcbiAgfSxcbiAgaGV4VG9SZ2I6IGZ1bmN0aW9uKGhleCkge1xuICAgIHZhciBtO1xuICAgIG0gPSAvXiM/KFthLWZcXGRdezJ9KShbYS1mXFxkXXsyfSkoW2EtZlxcZF17Mn0pJC9pLmV4ZWMoaGV4KTtcbiAgICBpZiAobSAhPSBudWxsKSB7XG4gICAgICByZXR1cm4gW21bMV0sIG1bMl0sIG1bM11dLm1hcChmdW5jdGlvbihzKSB7XG4gICAgICAgIHJldHVybiBwYXJzZUludChzLCAxNik7XG4gICAgICB9KTtcbiAgICB9XG4gICAgcmV0dXJuIG51bGw7XG4gIH0sXG4gIHJnYlRvSGV4OiBmdW5jdGlvbihyLCBnLCBiKSB7XG4gICAgcmV0dXJuIFwiI1wiICsgKCgxIDw8IDI0KSArIChyIDw8IDE2KSArIChnIDw8IDgpICsgYikudG9TdHJpbmcoMTYpLnNsaWNlKDEsIDcpO1xuICB9LFxuICByZ2JUb0hzbDogZnVuY3Rpb24ociwgZywgYikge1xuICAgIHZhciBkLCBoLCBsLCBtYXgsIG1pbiwgcztcbiAgICByIC89IDI1NTtcbiAgICBnIC89IDI1NTtcbiAgICBiIC89IDI1NTtcbiAgICBtYXggPSBNYXRoLm1heChyLCBnLCBiKTtcbiAgICBtaW4gPSBNYXRoLm1pbihyLCBnLCBiKTtcbiAgICBoID0gdm9pZCAwO1xuICAgIHMgPSB2b2lkIDA7XG4gICAgbCA9IChtYXggKyBtaW4pIC8gMjtcbiAgICBpZiAobWF4ID09PSBtaW4pIHtcbiAgICAgIGggPSBzID0gMDtcbiAgICB9IGVsc2Uge1xuICAgICAgZCA9IG1heCAtIG1pbjtcbiAgICAgIHMgPSBsID4gMC41ID8gZCAvICgyIC0gbWF4IC0gbWluKSA6IGQgLyAobWF4ICsgbWluKTtcbiAgICAgIHN3aXRjaCAobWF4KSB7XG4gICAgICAgIGNhc2UgcjpcbiAgICAgICAgICBoID0gKGcgLSBiKSAvIGQgKyAoZyA8IGIgPyA2IDogMCk7XG4gICAgICAgICAgYnJlYWs7XG4gICAgICAgIGNhc2UgZzpcbiAgICAgICAgICBoID0gKGIgLSByKSAvIGQgKyAyO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICBjYXNlIGI6XG4gICAgICAgICAgaCA9IChyIC0gZykgLyBkICsgNDtcbiAgICAgIH1cbiAgICAgIGggLz0gNjtcbiAgICB9XG4gICAgcmV0dXJuIFtoLCBzLCBsXTtcbiAgfSxcbiAgaHNsVG9SZ2I6IGZ1bmN0aW9uKGgsIHMsIGwpIHtcbiAgICB2YXIgYiwgZywgaHVlMnJnYiwgcCwgcSwgcjtcbiAgICByID0gdm9pZCAwO1xuICAgIGcgPSB2b2lkIDA7XG4gICAgYiA9IHZvaWQgMDtcbiAgICBodWUycmdiID0gZnVuY3Rpb24ocCwgcSwgdCkge1xuICAgICAgaWYgKHQgPCAwKSB7XG4gICAgICAgIHQgKz0gMTtcbiAgICAgIH1cbiAgICAgIGlmICh0ID4gMSkge1xuICAgICAgICB0IC09IDE7XG4gICAgICB9XG4gICAgICBpZiAodCA8IDEgLyA2KSB7XG4gICAgICAgIHJldHVybiBwICsgKHEgLSBwKSAqIDYgKiB0O1xuICAgICAgfVxuICAgICAgaWYgKHQgPCAxIC8gMikge1xuICAgICAgICByZXR1cm4gcTtcbiAgICAgIH1cbiAgICAgIGlmICh0IDwgMiAvIDMpIHtcbiAgICAgICAgcmV0dXJuIHAgKyAocSAtIHApICogKDIgLyAzIC0gdCkgKiA2O1xuICAgICAgfVxuICAgICAgcmV0dXJuIHA7XG4gICAgfTtcbiAgICBpZiAocyA9PT0gMCkge1xuICAgICAgciA9IGcgPSBiID0gbDtcbiAgICB9IGVsc2Uge1xuICAgICAgcSA9IGwgPCAwLjUgPyBsICogKDEgKyBzKSA6IGwgKyBzIC0gKGwgKiBzKTtcbiAgICAgIHAgPSAyICogbCAtIHE7XG4gICAgICByID0gaHVlMnJnYihwLCBxLCBoICsgMSAvIDMpO1xuICAgICAgZyA9IGh1ZTJyZ2IocCwgcSwgaCk7XG4gICAgICBiID0gaHVlMnJnYihwLCBxLCBoIC0gKDEgLyAzKSk7XG4gICAgfVxuICAgIHJldHVybiBbciAqIDI1NSwgZyAqIDI1NSwgYiAqIDI1NV07XG4gIH0sXG4gIHJnYlRvWHl6OiBmdW5jdGlvbihyLCBnLCBiKSB7XG4gICAgdmFyIHgsIHksIHo7XG4gICAgciAvPSAyNTU7XG4gICAgZyAvPSAyNTU7XG4gICAgYiAvPSAyNTU7XG4gICAgciA9IHIgPiAwLjA0MDQ1ID8gTWF0aC5wb3coKHIgKyAwLjAwNSkgLyAxLjA1NSwgMi40KSA6IHIgLyAxMi45MjtcbiAgICBnID0gZyA+IDAuMDQwNDUgPyBNYXRoLnBvdygoZyArIDAuMDA1KSAvIDEuMDU1LCAyLjQpIDogZyAvIDEyLjkyO1xuICAgIGIgPSBiID4gMC4wNDA0NSA/IE1hdGgucG93KChiICsgMC4wMDUpIC8gMS4wNTUsIDIuNCkgOiBiIC8gMTIuOTI7XG4gICAgciAqPSAxMDA7XG4gICAgZyAqPSAxMDA7XG4gICAgYiAqPSAxMDA7XG4gICAgeCA9IHIgKiAwLjQxMjQgKyBnICogMC4zNTc2ICsgYiAqIDAuMTgwNTtcbiAgICB5ID0gciAqIDAuMjEyNiArIGcgKiAwLjcxNTIgKyBiICogMC4wNzIyO1xuICAgIHogPSByICogMC4wMTkzICsgZyAqIDAuMTE5MiArIGIgKiAwLjk1MDU7XG4gICAgcmV0dXJuIFt4LCB5LCB6XTtcbiAgfSxcbiAgeHl6VG9DSUVMYWI6IGZ1bmN0aW9uKHgsIHksIHopIHtcbiAgICB2YXIgTCwgUkVGX1gsIFJFRl9ZLCBSRUZfWiwgYSwgYjtcbiAgICBSRUZfWCA9IDk1LjA0NztcbiAgICBSRUZfWSA9IDEwMDtcbiAgICBSRUZfWiA9IDEwOC44ODM7XG4gICAgeCAvPSBSRUZfWDtcbiAgICB5IC89IFJFRl9ZO1xuICAgIHogLz0gUkVGX1o7XG4gICAgeCA9IHggPiAwLjAwODg1NiA/IE1hdGgucG93KHgsIDEgLyAzKSA6IDcuNzg3ICogeCArIDE2IC8gMTE2O1xuICAgIHkgPSB5ID4gMC4wMDg4NTYgPyBNYXRoLnBvdyh5LCAxIC8gMykgOiA3Ljc4NyAqIHkgKyAxNiAvIDExNjtcbiAgICB6ID0geiA+IDAuMDA4ODU2ID8gTWF0aC5wb3coeiwgMSAvIDMpIDogNy43ODcgKiB6ICsgMTYgLyAxMTY7XG4gICAgTCA9IDExNiAqIHkgLSAxNjtcbiAgICBhID0gNTAwICogKHggLSB5KTtcbiAgICBiID0gMjAwICogKHkgLSB6KTtcbiAgICByZXR1cm4gW0wsIGEsIGJdO1xuICB9LFxuICByZ2JUb0NJRUxhYjogZnVuY3Rpb24ociwgZywgYikge1xuICAgIHZhciByZWYsIHgsIHksIHo7XG4gICAgcmVmID0gdGhpcy5yZ2JUb1h5eihyLCBnLCBiKSwgeCA9IHJlZlswXSwgeSA9IHJlZlsxXSwgeiA9IHJlZlsyXTtcbiAgICByZXR1cm4gdGhpcy54eXpUb0NJRUxhYih4LCB5LCB6KTtcbiAgfSxcbiAgZGVsdGFFOTQ6IGZ1bmN0aW9uKGxhYjEsIGxhYjIpIHtcbiAgICB2YXIgTDEsIEwyLCBXRUlHSFRfQywgV0VJR0hUX0gsIFdFSUdIVF9MLCBhMSwgYTIsIGIxLCBiMiwgZEwsIGRhLCBkYiwgeEMxLCB4QzIsIHhEQywgeERFLCB4REgsIHhETCwgeFNDLCB4U0g7XG4gICAgV0VJR0hUX0wgPSAxO1xuICAgIFdFSUdIVF9DID0gMTtcbiAgICBXRUlHSFRfSCA9IDE7XG4gICAgTDEgPSBsYWIxWzBdLCBhMSA9IGxhYjFbMV0sIGIxID0gbGFiMVsyXTtcbiAgICBMMiA9IGxhYjJbMF0sIGEyID0gbGFiMlsxXSwgYjIgPSBsYWIyWzJdO1xuICAgIGRMID0gTDEgLSBMMjtcbiAgICBkYSA9IGExIC0gYTI7XG4gICAgZGIgPSBiMSAtIGIyO1xuICAgIHhDMSA9IE1hdGguc3FydChhMSAqIGExICsgYjEgKiBiMSk7XG4gICAgeEMyID0gTWF0aC5zcXJ0KGEyICogYTIgKyBiMiAqIGIyKTtcbiAgICB4REwgPSBMMiAtIEwxO1xuICAgIHhEQyA9IHhDMiAtIHhDMTtcbiAgICB4REUgPSBNYXRoLnNxcnQoZEwgKiBkTCArIGRhICogZGEgKyBkYiAqIGRiKTtcbiAgICBpZiAoTWF0aC5zcXJ0KHhERSkgPiBNYXRoLnNxcnQoTWF0aC5hYnMoeERMKSkgKyBNYXRoLnNxcnQoTWF0aC5hYnMoeERDKSkpIHtcbiAgICAgIHhESCA9IE1hdGguc3FydCh4REUgKiB4REUgLSB4REwgKiB4REwgLSB4REMgKiB4REMpO1xuICAgIH0gZWxzZSB7XG4gICAgICB4REggPSAwO1xuICAgIH1cbiAgICB4U0MgPSAxICsgMC4wNDUgKiB4QzE7XG4gICAgeFNIID0gMSArIDAuMDE1ICogeEMxO1xuICAgIHhETCAvPSBXRUlHSFRfTDtcbiAgICB4REMgLz0gV0VJR0hUX0MgKiB4U0M7XG4gICAgeERIIC89IFdFSUdIVF9IICogeFNIO1xuICAgIHJldHVybiBNYXRoLnNxcnQoeERMICogeERMICsgeERDICogeERDICsgeERIICogeERIKTtcbiAgfSxcbiAgcmdiRGlmZjogZnVuY3Rpb24ocmdiMSwgcmdiMikge1xuICAgIHZhciBsYWIxLCBsYWIyO1xuICAgIGxhYjEgPSB0aGlzLnJnYlRvQ0lFTGFiLmFwcGx5KHRoaXMsIHJnYjEpO1xuICAgIGxhYjIgPSB0aGlzLnJnYlRvQ0lFTGFiLmFwcGx5KHRoaXMsIHJnYjIpO1xuICAgIHJldHVybiB0aGlzLmRlbHRhRTk0KGxhYjEsIGxhYjIpO1xuICB9LFxuICBoZXhEaWZmOiBmdW5jdGlvbihoZXgxLCBoZXgyKSB7XG4gICAgdmFyIHJnYjEsIHJnYjI7XG4gICAgcmdiMSA9IHRoaXMuaGV4VG9SZ2IoaGV4MSk7XG4gICAgcmdiMiA9IHRoaXMuaGV4VG9SZ2IoaGV4Mik7XG4gICAgcmV0dXJuIHRoaXMucmdiRGlmZihyZ2IxLCByZ2IyKTtcbiAgfSxcbiAgREVMVEFFOTRfRElGRl9TVEFUVVM6IERFTFRBRTk0LFxuICBnZXRDb2xvckRpZmZTdGF0dXM6IGZ1bmN0aW9uKGQpIHtcbiAgICBpZiAoZCA8IERFTFRBRTk0Lk5BKSB7XG4gICAgICByZXR1cm4gXCJOL0FcIjtcbiAgICB9XG4gICAgaWYgKGQgPD0gREVMVEFFOTQuUEVSRkVDVCkge1xuICAgICAgcmV0dXJuIFwiUGVyZmVjdFwiO1xuICAgIH1cbiAgICBpZiAoZCA8PSBERUxUQUU5NC5DTE9TRSkge1xuICAgICAgcmV0dXJuIFwiQ2xvc2VcIjtcbiAgICB9XG4gICAgaWYgKGQgPD0gREVMVEFFOTQuR09PRCkge1xuICAgICAgcmV0dXJuIFwiR29vZFwiO1xuICAgIH1cbiAgICBpZiAoZCA8IERFTFRBRTk0LlNJTUlMQVIpIHtcbiAgICAgIHJldHVybiBcIlNpbWlsYXJcIjtcbiAgICB9XG4gICAgcmV0dXJuIFwiV3JvbmdcIjtcbiAgfSxcbiAgU0lHQklUUzogU0lHQklUUyxcbiAgUlNISUZUOiBSU0hJRlQsXG4gIGdldENvbG9ySW5kZXg6IGZ1bmN0aW9uKHIsIGcsIGIpIHtcbiAgICByZXR1cm4gKHIgPDwgKDIgKiBTSUdCSVRTKSkgKyAoZyA8PCBTSUdCSVRTKSArIGI7XG4gIH1cbn07XG5cbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSm1hV3hsSWpvaUwxVnpaWEp6TDJNMEwwUnZZM1Z0Wlc1MGN5OVFjbTlxWldOMGN5OXpaV3hzWlc4dmJtOWtaUzFzYjJkdkxXTnZiRzl5Y3k5emNtTXZkWFJwYkM1amIyWm1aV1VpTENKemIzVnlZMlZTYjI5MElqb2lJaXdpYzI5MWNtTmxjeUk2V3lJdlZYTmxjbk12WXpRdlJHOWpkVzFsYm5SekwxQnliMnBsWTNSekwzTmxiR3hsYnk5dWIyUmxMV3h2WjI4dFkyOXNiM0p6TDNOeVl5OTFkR2xzTG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lRVUZCUVN4SlFVRkJPenRCUVVGQkxGRkJRVUVzUjBGRFJUdEZRVUZCTEVWQlFVRXNSVUZCU1N4RFFVRktPMFZCUTBFc1QwRkJRU3hGUVVGVExFTkJSRlE3UlVGRlFTeExRVUZCTEVWQlFVOHNRMEZHVUR0RlFVZEJMRWxCUVVFc1JVRkJUU3hGUVVoT08wVkJTVUVzVDBGQlFTeEZRVUZUTEVWQlNsUTdPenRCUVUxR0xFOUJRVUVzUjBGQlZUczdRVUZEVml4TlFVRkJMRWRCUVZNc1EwRkJRU3hIUVVGSk96dEJRVWxpTEUxQlFVMHNRMEZCUXl4UFFVRlFMRWRCUTBVN1JVRkJRU3hMUVVGQkxFVkJRVThzVTBGQlF5eERRVUZFTzBGQlEwd3NVVUZCUVR0SlFVRkJMRWxCUVVjc1QwRkJUeXhEUVVGUUxFdEJRVmtzVVVGQlpqdE5RVU5GTEVsQlFVY3NTMEZCU3l4RFFVRkRMRTlCUVU0c1EwRkJZeXhEUVVGa0xFTkJRVWc3UVVGRFJTeGxRVUZQTEVOQlFVTXNRMEZCUXl4SFFVRkdMRU5CUVUwc1EwRkJRU3hUUVVGQkxFdEJRVUU3YVVKQlFVRXNVMEZCUXl4RFFVRkVPMjFDUVVGUExFdEJRVWtzUTBGQlF5eExRVUZNTEVOQlFWY3NRMEZCV0R0VlFVRlFPMUZCUVVFc1EwRkJRU3hEUVVGQkxFTkJRVUVzU1VGQlFTeERRVUZPTEVWQlJGUTdUMEZCUVN4TlFVRkJPMUZCUjBVc1JVRkJRU3hIUVVGTE8wRkJRMHdzWVVGQlFTeFJRVUZCT3p0VlFVTkZMRVZCUVVjc1EwRkJRU3hIUVVGQkxFTkJRVWdzUjBGQlZTeEpRVUZKTEVOQlFVTXNTMEZCVEN4RFFVRlhMRXRCUVZnN1FVRkVXanRCUVVWQkxHVkJRVThzUjBGT1ZEdFBRVVJHT3p0WFFWRkJPMFZCVkVzc1EwRkJVRHRGUVZkQkxGRkJRVUVzUlVGQlZTeFRRVUZCTzBGQlExSXNVVUZCUVR0SlFVRkJMRU5CUVVFc1IwRkJTVHRCUVVOS0xGTkJRVUVzTWtOQlFVRTdPMEZCUTBVc1YwRkJRU3hUUVVGQk96dFJRVU5GTEVsQlFVOHNZMEZCVUR0VlFVRnZRaXhEUVVGRkxFTkJRVUVzUjBGQlFTeERRVUZHTEVkQlFWTXNTVUZCU1N4RFFVRkRMRXRCUVV3c1EwRkJWeXhMUVVGWUxFVkJRVGRDT3p0QlFVUkdPMEZCUkVZN1YwRkpRVHRGUVU1UkxFTkJXRlk3UlVGdFFrRXNVVUZCUVN4RlFVRlZMRk5CUVVNc1IwRkJSRHRCUVVOU0xGRkJRVUU3U1VGQlFTeERRVUZCTEVkQlFVa3NNa05CUVRKRExFTkJRVU1zU1VGQk5VTXNRMEZCYVVRc1IwRkJha1E3U1VGRFNpeEpRVUZITEZOQlFVZzdRVUZEUlN4aFFVRlBMRU5CUVVNc1EwRkJSU3hEUVVGQkxFTkJRVUVzUTBGQlNDeEZRVUZQTEVOQlFVVXNRMEZCUVN4RFFVRkJMRU5CUVZRc1JVRkJZU3hEUVVGRkxFTkJRVUVzUTBGQlFTeERRVUZtTEVOQlFXdENMRU5CUVVNc1IwRkJia0lzUTBGQmRVSXNVMEZCUXl4RFFVRkVPMlZCUVU4c1VVRkJRU3hEUVVGVExFTkJRVlFzUlVGQldTeEZRVUZhTzAxQlFWQXNRMEZCZGtJc1JVRkVWRHM3UVVGRlFTeFhRVUZQTzBWQlNrTXNRMEZ1UWxZN1JVRjVRa0VzVVVGQlFTeEZRVUZWTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8xZEJRMUlzUjBGQlFTeEhRVUZOTEVOQlFVTXNRMEZCUXl4RFFVRkJMRWxCUVVzc1JVRkJUaXhEUVVGQkxFZEJRVmtzUTBGQlF5eERRVUZCTEVsQlFVc3NSVUZCVGl4RFFVRmFMRWRCUVhkQ0xFTkJRVU1zUTBGQlFTeEpRVUZMTEVOQlFVNHNRMEZCZUVJc1IwRkJiVU1zUTBGQmNFTXNRMEZCYzBNc1EwRkJReXhSUVVGMlF5eERRVUZuUkN4RlFVRm9SQ3hEUVVGdFJDeERRVUZETEV0QlFYQkVMRU5CUVRCRUxFTkJRVEZFTEVWQlFUWkVMRU5CUVRkRU8wVkJSRVVzUTBGNlFsWTdSVUUwUWtFc1VVRkJRU3hGUVVGVkxGTkJRVU1zUTBGQlJDeEZRVUZKTEVOQlFVb3NSVUZCVHl4RFFVRlFPMEZCUTFJc1VVRkJRVHRKUVVGQkxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVOTUxFZEJRVUVzUjBGQlRTeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRU5CUVZRc1JVRkJXU3hEUVVGYUxFVkJRV1VzUTBGQlpqdEpRVU5PTEVkQlFVRXNSMEZCVFN4SlFVRkpMRU5CUVVNc1IwRkJUQ3hEUVVGVExFTkJRVlFzUlVGQldTeERRVUZhTEVWQlFXVXNRMEZCWmp0SlFVTk9MRU5CUVVFc1IwRkJTVHRKUVVOS0xFTkJRVUVzUjBGQlNUdEpRVU5LTEVOQlFVRXNSMEZCU1N4RFFVRkRMRWRCUVVFc1IwRkJUU3hIUVVGUUxFTkJRVUVzUjBGQll6dEpRVU5zUWl4SlFVRkhMRWRCUVVFc1MwRkJUeXhIUVVGV08wMUJRMFVzUTBGQlFTeEhRVUZKTEVOQlFVRXNSMEZCU1N4RlFVUldPMHRCUVVFc1RVRkJRVHROUVVsRkxFTkJRVUVzUjBGQlNTeEhRVUZCTEVkQlFVMDdUVUZEVml4RFFVRkJMRWRCUVU4c1EwRkJRU3hIUVVGSkxFZEJRVkFzUjBGQlowSXNRMEZCUVN4SFFVRkpMRU5CUVVNc1EwRkJRU3hIUVVGSkxFZEJRVW9zUjBGQlZTeEhRVUZZTEVOQlFYQkNMRWRCUVhsRExFTkJRVUVzUjBGQlNTeERRVUZETEVkQlFVRXNSMEZCVFN4SFFVRlFPMEZCUTJwRUxHTkJRVThzUjBGQlVEdEJRVUZCTEdGQlEwOHNRMEZFVUR0VlFVVkpMRU5CUVVFc1IwRkJTU3hEUVVGRExFTkJRVUVzUjBGQlNTeERRVUZNTEVOQlFVRXNSMEZCVlN4RFFVRldMRWRCUVdNc1EwRkJTU3hEUVVGQkxFZEJRVWtzUTBGQlVDeEhRVUZqTEVOQlFXUXNSMEZCY1VJc1EwRkJkRUk3UVVGRVpqdEJRVVJRTEdGQlIwOHNRMEZJVUR0VlFVbEpMRU5CUVVFc1IwRkJTU3hEUVVGRExFTkJRVUVzUjBGQlNTeERRVUZNTEVOQlFVRXNSMEZCVlN4RFFVRldMRWRCUVdNN1FVRkVaanRCUVVoUUxHRkJTMDhzUTBGTVVEdFZRVTFKTEVOQlFVRXNSMEZCU1N4RFFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGTUxFTkJRVUVzUjBGQlZTeERRVUZXTEVkQlFXTTdRVUZPZEVJN1RVRlBRU3hEUVVGQkxFbEJRVXNzUlVGaVVEczdWMEZqUVN4RFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVEdEZRWFpDVVN4RFFUVkNWanRGUVhGRVFTeFJRVUZCTEVWQlFWVXNVMEZCUXl4RFFVRkVMRVZCUVVrc1EwRkJTaXhGUVVGUExFTkJRVkE3UVVGRFVpeFJRVUZCTzBsQlFVRXNRMEZCUVN4SFFVRkpPMGxCUTBvc1EwRkJRU3hIUVVGSk8wbEJRMG9zUTBGQlFTeEhRVUZKTzBsQlJVb3NUMEZCUVN4SFFVRlZMRk5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzAxQlExSXNTVUZCUnl4RFFVRkJMRWRCUVVrc1EwRkJVRHRSUVVORkxFTkJRVUVzU1VGQlN5eEZRVVJRT3p0TlFVVkJMRWxCUVVjc1EwRkJRU3hIUVVGSkxFTkJRVkE3VVVGRFJTeERRVUZCTEVsQlFVc3NSVUZFVURzN1RVRkZRU3hKUVVGSExFTkJRVUVzUjBGQlNTeERRVUZCTEVkQlFVa3NRMEZCV0R0QlFVTkZMR1ZCUVU4c1EwRkJRU3hIUVVGSkxFTkJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVd3NRMEZCUVN4SFFVRlZMRU5CUVZZc1IwRkJZeXhGUVVRelFqczdUVUZGUVN4SlFVRkhMRU5CUVVFc1IwRkJTU3hEUVVGQkxFZEJRVWtzUTBGQldEdEJRVU5GTEdWQlFVOHNSVUZFVkRzN1RVRkZRU3hKUVVGSExFTkJRVUVzUjBGQlNTeERRVUZCTEVkQlFVa3NRMEZCV0R0QlFVTkZMR1ZCUVU4c1EwRkJRU3hIUVVGSkxFTkJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVd3NRMEZCUVN4SFFVRlZMRU5CUVVNc1EwRkJRU3hIUVVGSkxFTkJRVW9zUjBGQlVTeERRVUZVTEVOQlFWWXNSMEZCZDBJc1JVRkVja003TzJGQlJVRTdTVUZZVVR0SlFXRldMRWxCUVVjc1EwRkJRU3hMUVVGTExFTkJRVkk3VFVGRFJTeERRVUZCTEVkQlFVa3NRMEZCUVN4SFFVRkpMRU5CUVVFc1IwRkJTU3hGUVVSa08wdEJRVUVzVFVGQlFUdE5RVWxGTEVOQlFVRXNSMEZCVHl4RFFVRkJMRWRCUVVrc1IwRkJVQ3hIUVVGblFpeERRVUZCTEVkQlFVa3NRMEZCUXl4RFFVRkJMRWRCUVVrc1EwRkJUQ3hEUVVGd1FpeEhRVUZwUXl4RFFVRkJMRWRCUVVrc1EwRkJTaXhIUVVGUkxFTkJRVU1zUTBGQlFTeEhRVUZKTEVOQlFVdzdUVUZETjBNc1EwRkJRU3hIUVVGSkxFTkJRVUVzUjBGQlNTeERRVUZLTEVkQlFWRTdUVUZEV2l4RFFVRkJMRWRCUVVrc1QwRkJRU3hEUVVGUkxFTkJRVklzUlVGQlZ5eERRVUZZTEVWQlFXTXNRMEZCUVN4SFFVRkpMRU5CUVVFc1IwRkJTU3hEUVVGMFFqdE5RVU5LTEVOQlFVRXNSMEZCU1N4UFFVRkJMRU5CUVZFc1EwRkJVaXhGUVVGWExFTkJRVmdzUlVGQll5eERRVUZrTzAxQlEwb3NRMEZCUVN4SFFVRkpMRTlCUVVFc1EwRkJVU3hEUVVGU0xFVkJRVmNzUTBGQldDeEZRVUZqTEVOQlFVRXNSMEZCU1N4RFFVRkRMRU5CUVVFc1IwRkJTU3hEUVVGTUxFTkJRV3hDTEVWQlVrNDdPMWRCVTBFc1EwRkRSU3hEUVVGQkxFZEJRVWtzUjBGRVRpeEZRVVZGTEVOQlFVRXNSMEZCU1N4SFFVWk9MRVZCUjBVc1EwRkJRU3hIUVVGSkxFZEJTRTQ3UlVFelFsRXNRMEZ5UkZZN1JVRnpSa0VzVVVGQlFTeEZRVUZWTEZOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8wRkJRMUlzVVVGQlFUdEpRVUZCTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVOTUxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNSMEZCVHl4RFFVRkJMRWRCUVVrc1QwRkJVQ3hIUVVGdlFpeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRU5CUVVNc1EwRkJRU3hIUVVGSkxFdEJRVXdzUTBGQlFTeEhRVUZqTEV0QlFYWkNMRVZCUVRoQ0xFZEJRVGxDTEVOQlFYQkNMRWRCUVRSRUxFTkJRVUVzUjBGQlNUdEpRVU53UlN4RFFVRkJMRWRCUVU4c1EwRkJRU3hIUVVGSkxFOUJRVkFzUjBGQmIwSXNTVUZCU1N4RFFVRkRMRWRCUVV3c1EwRkJVeXhEUVVGRExFTkJRVUVzUjBGQlNTeExRVUZNTEVOQlFVRXNSMEZCWXl4TFFVRjJRaXhGUVVFNFFpeEhRVUU1UWl4RFFVRndRaXhIUVVFMFJDeERRVUZCTEVkQlFVazdTVUZEY0VVc1EwRkJRU3hIUVVGUExFTkJRVUVzUjBGQlNTeFBRVUZRTEVkQlFXOUNMRWxCUVVrc1EwRkJReXhIUVVGTUxFTkJRVk1zUTBGQlF5eERRVUZCTEVkQlFVa3NTMEZCVEN4RFFVRkJMRWRCUVdNc1MwRkJka0lzUlVGQk9FSXNSMEZCT1VJc1EwRkJjRUlzUjBGQk5FUXNRMEZCUVN4SFFVRkpPMGxCUlhCRkxFTkJRVUVzU1VGQlN6dEpRVU5NTEVOQlFVRXNTVUZCU3p0SlFVTk1MRU5CUVVFc1NVRkJTenRKUVVWTUxFTkJRVUVzUjBGQlNTeERRVUZCTEVkQlFVa3NUVUZCU2l4SFFVRmhMRU5CUVVFc1IwRkJTU3hOUVVGcVFpeEhRVUV3UWl4RFFVRkJMRWRCUVVrN1NVRkRiRU1zUTBGQlFTeEhRVUZKTEVOQlFVRXNSMEZCU1N4TlFVRktMRWRCUVdFc1EwRkJRU3hIUVVGSkxFMUJRV3BDTEVkQlFUQkNMRU5CUVVFc1IwRkJTVHRKUVVOc1F5eERRVUZCTEVkQlFVa3NRMEZCUVN4SFFVRkpMRTFCUVVvc1IwRkJZU3hEUVVGQkxFZEJRVWtzVFVGQmFrSXNSMEZCTUVJc1EwRkJRU3hIUVVGSk8xZEJSV3hETEVOQlFVTXNRMEZCUkN4RlFVRkpMRU5CUVVvc1JVRkJUeXhEUVVGUU8wVkJhRUpSTEVOQmRFWldPMFZCZDBkQkxGZEJRVUVzUlVGQllTeFRRVUZETEVOQlFVUXNSVUZCU1N4RFFVRktMRVZCUVU4c1EwRkJVRHRCUVVOWUxGRkJRVUU3U1VGQlFTeExRVUZCTEVkQlFWRTdTVUZEVWl4TFFVRkJMRWRCUVZFN1NVRkRVaXhMUVVGQkxFZEJRVkU3U1VGRlVpeERRVUZCTEVsQlFVczdTVUZEVEN4RFFVRkJMRWxCUVVzN1NVRkRUQ3hEUVVGQkxFbEJRVXM3U1VGRlRDeERRVUZCTEVkQlFVOHNRMEZCUVN4SFFVRkpMRkZCUVZBc1IwRkJjVUlzU1VGQlNTeERRVUZETEVkQlFVd3NRMEZCVXl4RFFVRlVMRVZCUVZrc1EwRkJRU3hIUVVGRkxFTkJRV1FzUTBGQmNrSXNSMEZCTWtNc1MwRkJRU3hIUVVGUkxFTkJRVklzUjBGQldTeEZRVUZCTEVkQlFVczdTVUZEYUVVc1EwRkJRU3hIUVVGUExFTkJRVUVzUjBGQlNTeFJRVUZRTEVkQlFYRkNMRWxCUVVrc1EwRkJReXhIUVVGTUxFTkJRVk1zUTBGQlZDeEZRVUZaTEVOQlFVRXNSMEZCUlN4RFFVRmtMRU5CUVhKQ0xFZEJRVEpETEV0QlFVRXNSMEZCVVN4RFFVRlNMRWRCUVZrc1JVRkJRU3hIUVVGTE8wbEJRMmhGTEVOQlFVRXNSMEZCVHl4RFFVRkJMRWRCUVVrc1VVRkJVQ3hIUVVGeFFpeEpRVUZKTEVOQlFVTXNSMEZCVEN4RFFVRlRMRU5CUVZRc1JVRkJXU3hEUVVGQkxFZEJRVVVzUTBGQlpDeERRVUZ5UWl4SFFVRXlReXhMUVVGQkxFZEJRVkVzUTBGQlVpeEhRVUZaTEVWQlFVRXNSMEZCU3p0SlFVVm9SU3hEUVVGQkxFZEJRVWtzUjBGQlFTeEhRVUZOTEVOQlFVNHNSMEZCVlR0SlFVTmtMRU5CUVVFc1IwRkJTU3hIUVVGQkxFZEJRVTBzUTBGQlF5eERRVUZCTEVkQlFVa3NRMEZCVER0SlFVTldMRU5CUVVFc1IwRkJTU3hIUVVGQkxFZEJRVTBzUTBGQlF5eERRVUZCTEVkQlFVa3NRMEZCVER0WFFVVldMRU5CUVVNc1EwRkJSQ3hGUVVGSkxFTkJRVW9zUlVGQlR5eERRVUZRTzBWQmFrSlhMRU5CZUVkaU8wVkJNa2hCTEZkQlFVRXNSVUZCWVN4VFFVRkRMRU5CUVVRc1JVRkJTU3hEUVVGS0xFVkJRVThzUTBGQlVEdEJRVU5ZTEZGQlFVRTdTVUZCUVN4TlFVRlpMRWxCUVVrc1EwRkJReXhSUVVGTUxFTkJRV01zUTBGQlpDeEZRVUZwUWl4RFFVRnFRaXhGUVVGdlFpeERRVUZ3UWl4RFFVRmFMRVZCUVVNc1ZVRkJSQ3hGUVVGSkxGVkJRVW9zUlVGQlR6dFhRVU5RTEVsQlFVa3NRMEZCUXl4WFFVRk1MRU5CUVdsQ0xFTkJRV3BDTEVWQlFXOUNMRU5CUVhCQ0xFVkJRWFZDTEVOQlFYWkNPMFZCUmxjc1EwRXpTR0k3UlVFclNFRXNVVUZCUVN4RlFVRlZMRk5CUVVNc1NVRkJSQ3hGUVVGUExFbEJRVkE3UVVGRlVpeFJRVUZCTzBsQlFVRXNVVUZCUVN4SFFVRlhPMGxCUTFnc1VVRkJRU3hIUVVGWE8wbEJRMWdzVVVGQlFTeEhRVUZYTzBsQlJWWXNXVUZCUkN4RlFVRkxMRmxCUVV3c1JVRkJVenRKUVVOU0xGbEJRVVFzUlVGQlN5eFpRVUZNTEVWQlFWTTdTVUZEVkN4RlFVRkJMRWRCUVVzc1JVRkJRU3hIUVVGTE8wbEJRMVlzUlVGQlFTeEhRVUZMTEVWQlFVRXNSMEZCU3p0SlFVTldMRVZCUVVFc1IwRkJTeXhGUVVGQkxFZEJRVXM3U1VGRlZpeEhRVUZCTEVkQlFVMHNTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hGUVVGQkxFZEJRVXNzUlVGQlRDeEhRVUZWTEVWQlFVRXNSMEZCU3l4RlFVRjZRanRKUVVOT0xFZEJRVUVzUjBGQlRTeEpRVUZKTEVOQlFVTXNTVUZCVEN4RFFVRlZMRVZCUVVFc1IwRkJTeXhGUVVGTUxFZEJRVlVzUlVGQlFTeEhRVUZMTEVWQlFYcENPMGxCUlU0c1IwRkJRU3hIUVVGTkxFVkJRVUVzUjBGQlN6dEpRVU5ZTEVkQlFVRXNSMEZCVFN4SFFVRkJMRWRCUVUwN1NVRkRXaXhIUVVGQkxFZEJRVTBzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4RlFVRkJMRWRCUVVzc1JVRkJUQ3hIUVVGVkxFVkJRVUVzUjBGQlN5eEZRVUZtTEVkQlFXOUNMRVZCUVVFc1IwRkJTeXhGUVVGdVF6dEpRVVZPTEVsQlFVY3NTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hIUVVGV0xFTkJRVUVzUjBGQmFVSXNTVUZCU1N4RFFVRkRMRWxCUVV3c1EwRkJWU3hKUVVGSkxFTkJRVU1zUjBGQlRDeERRVUZUTEVkQlFWUXNRMEZCVml4RFFVRkJMRWRCUVRKQ0xFbEJRVWtzUTBGQlF5eEpRVUZNTEVOQlFWVXNTVUZCU1N4RFFVRkRMRWRCUVV3c1EwRkJVeXhIUVVGVUxFTkJRVllzUTBGQkwwTTdUVUZEUlN4SFFVRkJMRWRCUVUwc1NVRkJTU3hEUVVGRExFbEJRVXdzUTBGQlZTeEhRVUZCTEVkQlFVMHNSMEZCVGl4SFFVRlpMRWRCUVVFc1IwRkJUU3hIUVVGc1FpeEhRVUYzUWl4SFFVRkJMRWRCUVUwc1IwRkJlRU1zUlVGRVVqdExRVUZCTEUxQlFVRTdUVUZIUlN4SFFVRkJMRWRCUVUwc1JVRklVanM3U1VGTFFTeEhRVUZCTEVkQlFVMHNRMEZCUVN4SFFVRkpMRXRCUVVFc1IwRkJVVHRKUVVOc1FpeEhRVUZCTEVkQlFVMHNRMEZCUVN4SFFVRkpMRXRCUVVFc1IwRkJVVHRKUVVWc1FpeEhRVUZCTEVsQlFVODdTVUZEVUN4SFFVRkJMRWxCUVU4c1VVRkJRU3hIUVVGWE8wbEJRMnhDTEVkQlFVRXNTVUZCVHl4UlFVRkJMRWRCUVZjN1YwRkZiRUlzU1VGQlNTeERRVUZETEVsQlFVd3NRMEZCVlN4SFFVRkJMRWRCUVUwc1IwRkJUaXhIUVVGWkxFZEJRVUVzUjBGQlRTeEhRVUZzUWl4SFFVRjNRaXhIUVVGQkxFZEJRVTBzUjBGQmVFTTdSVUV2UWxFc1EwRXZTRlk3UlVGblMwRXNUMEZCUVN4RlFVRlRMRk5CUVVNc1NVRkJSQ3hGUVVGUExFbEJRVkE3UVVGRFVDeFJRVUZCTzBsQlFVRXNTVUZCUVN4SFFVRlBMRWxCUVVNc1EwRkJRU3hYUVVGWExFTkJRVU1zUzBGQllpeERRVUZ0UWl4SlFVRnVRaXhGUVVGelFpeEpRVUYwUWp0SlFVTlFMRWxCUVVFc1IwRkJUeXhKUVVGRExFTkJRVUVzVjBGQlZ5eERRVUZETEV0QlFXSXNRMEZCYlVJc1NVRkJia0lzUlVGQmMwSXNTVUZCZEVJN1YwRkRVQ3hKUVVGRExFTkJRVUVzVVVGQlJDeERRVUZWTEVsQlFWWXNSVUZCWjBJc1NVRkJhRUk3UlVGSVR5eERRV2hMVkR0RlFYRkxRU3hQUVVGQkxFVkJRVk1zVTBGQlF5eEpRVUZFTEVWQlFVOHNTVUZCVUR0QlFVVlFMRkZCUVVFN1NVRkJRU3hKUVVGQkxFZEJRVThzU1VGQlF5eERRVUZCTEZGQlFVUXNRMEZCVlN4SlFVRldPMGxCUTFBc1NVRkJRU3hIUVVGUExFbEJRVU1zUTBGQlFTeFJRVUZFTEVOQlFWVXNTVUZCVmp0WFFVZFFMRWxCUVVNc1EwRkJRU3hQUVVGRUxFTkJRVk1zU1VGQlZDeEZRVUZsTEVsQlFXWTdSVUZPVHl4RFFYSkxWRHRGUVRaTFFTeHZRa0ZCUVN4RlFVRnpRaXhSUVRkTGRFSTdSVUVyUzBFc2EwSkJRVUVzUlVGQmIwSXNVMEZCUXl4RFFVRkVPMGxCUTJ4Q0xFbEJRVWNzUTBGQlFTeEhRVUZKTEZGQlFWRXNRMEZCUXl4RlFVRm9RanRCUVVORkxHRkJRVThzVFVGRVZEczdTVUZIUVN4SlFVRkhMRU5CUVVFc1NVRkJTeXhSUVVGUkxFTkJRVU1zVDBGQmFrSTdRVUZEUlN4aFFVRlBMRlZCUkZRN08wbEJSMEVzU1VGQlJ5eERRVUZCTEVsQlFVc3NVVUZCVVN4RFFVRkRMRXRCUVdwQ08wRkJRMFVzWVVGQlR5eFJRVVJVT3p0SlFVZEJMRWxCUVVjc1EwRkJRU3hKUVVGTExGRkJRVkVzUTBGQlF5eEpRVUZxUWp0QlFVTkZMR0ZCUVU4c1QwRkVWRHM3U1VGSFFTeEpRVUZITEVOQlFVRXNSMEZCU1N4UlFVRlJMRU5CUVVNc1QwRkJhRUk3UVVGRFJTeGhRVUZQTEZWQlJGUTdPMEZCUlVFc1YwRkJUenRGUVdaWExFTkJMMHR3UWp0RlFXZE5RU3hQUVVGQkxFVkJRVk1zVDBGb1RWUTdSVUZwVFVFc1RVRkJRU3hGUVVGUkxFMUJhazFTTzBWQmEwMUJMR0ZCUVVFc1JVRkJaU3hUUVVGRExFTkJRVVFzUlVGQlNTeERRVUZLTEVWQlFVOHNRMEZCVUR0WFFVTmlMRU5CUVVNc1EwRkJRU3hKUVVGSExFTkJRVU1zUTBGQlFTeEhRVUZGTEU5QlFVZ3NRMEZCU2l4RFFVRkJMRWRCUVcxQ0xFTkJRVU1zUTBGQlFTeEpRVUZMTEU5QlFVNHNRMEZCYmtJc1IwRkJiME03UlVGRWRrSXNRMEZzVFdZaWZRPT1cbiIsIlxuLypcbiAgRnJvbSBWaWJyYW50LmpzIGJ5IEphcmkgWndhcnRzXG4gIFBvcnRlZCB0byBub2RlLmpzIGJ5IEFLRmlzaFxuXG4gIENvbG9yIGFsZ29yaXRobSBjbGFzcyB0aGF0IGZpbmRzIHZhcmlhdGlvbnMgb24gY29sb3JzIGluIGFuIGltYWdlLlxuXG4gIENyZWRpdHNcbiAgLS0tLS0tLS1cbiAgTG9rZXNoIERoYWthciAoaHR0cDovL3d3dy5sb2tlc2hkaGFrYXIuY29tKSAtIENyZWF0ZWQgQ29sb3JUaGllZlxuICBHb29nbGUgLSBQYWxldHRlIHN1cHBvcnQgbGlicmFyeSBpbiBBbmRyb2lkXG4gKi9cbnZhciBCdWlsZGVyLCBEZWZhdWx0R2VuZXJhdG9yLCBGaWx0ZXIsIFN3YXRjaCwgVmlicmFudCwgdXRpbCxcbiAgYmluZCA9IGZ1bmN0aW9uKGZuLCBtZSl7IHJldHVybiBmdW5jdGlvbigpeyByZXR1cm4gZm4uYXBwbHkobWUsIGFyZ3VtZW50cyk7IH07IH07XG5cblN3YXRjaCA9IHJlcXVpcmUoJy4vc3dhdGNoJyk7XG5cbnV0aWwgPSByZXF1aXJlKCcuL3V0aWwnKTtcblxuRGVmYXVsdEdlbmVyYXRvciA9IHJlcXVpcmUoJy4vZ2VuZXJhdG9yJykuRGVmYXVsdDtcblxuRmlsdGVyID0gcmVxdWlyZSgnLi9maWx0ZXInKTtcblxubW9kdWxlLmV4cG9ydHMgPSBWaWJyYW50ID0gKGZ1bmN0aW9uKCkge1xuICBWaWJyYW50LkRlZmF1bHRPcHRzID0ge1xuICAgIGNvbG9yQ291bnQ6IDE2LFxuICAgIHF1YWxpdHk6IDUsXG4gICAgZ2VuZXJhdG9yOiBuZXcgRGVmYXVsdEdlbmVyYXRvcigpLFxuICAgIEltYWdlOiBudWxsLFxuICAgIFF1YW50aXplcjogcmVxdWlyZSgnLi9xdWFudGl6ZXInKS5NTUNRLFxuICAgIGZpbHRlcnM6IFtdLFxuICAgIG1pblBvcHVsYXRpb246IDM1LFxuICAgIG1pblJnYkRpZmY6IDE1LFxuICAgIGNvbXBhcmluZ1BvcHVsYXRpb25JbmRleDogMVxuICB9O1xuXG4gIFZpYnJhbnQuZnJvbSA9IGZ1bmN0aW9uKHNyYykge1xuICAgIHJldHVybiBuZXcgQnVpbGRlcihzcmMpO1xuICB9O1xuXG4gIFZpYnJhbnQucHJvdG90eXBlLnF1YW50aXplID0gcmVxdWlyZSgncXVhbnRpemUnKTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5fc3dhdGNoZXMgPSBbXTtcblxuICBmdW5jdGlvbiBWaWJyYW50KHNvdXJjZUltYWdlLCBvcHRzKSB7XG4gICAgdGhpcy5zb3VyY2VJbWFnZSA9IHNvdXJjZUltYWdlO1xuICAgIGlmIChvcHRzID09IG51bGwpIHtcbiAgICAgIG9wdHMgPSB7fTtcbiAgICB9XG4gICAgdGhpcy5zd2F0Y2hlcyA9IGJpbmQodGhpcy5zd2F0Y2hlcywgdGhpcyk7XG4gICAgdGhpcy5vcHRzID0gdXRpbC5kZWZhdWx0cyhvcHRzLCB0aGlzLmNvbnN0cnVjdG9yLkRlZmF1bHRPcHRzKTtcbiAgICB0aGlzLmdlbmVyYXRvciA9IHRoaXMub3B0cy5nZW5lcmF0b3I7XG4gIH1cblxuICBWaWJyYW50LnByb3RvdHlwZS5nZXRQYWxldHRlID0gZnVuY3Rpb24oY2IpIHtcbiAgICB2YXIgaW1hZ2U7XG4gICAgcmV0dXJuIGltYWdlID0gbmV3IHRoaXMub3B0cy5JbWFnZSh0aGlzLnNvdXJjZUltYWdlLCAoZnVuY3Rpb24oX3RoaXMpIHtcbiAgICAgIHJldHVybiBmdW5jdGlvbihlcnIsIGltYWdlKSB7XG4gICAgICAgIHZhciBlcnJvcjtcbiAgICAgICAgaWYgKGVyciAhPSBudWxsKSB7XG4gICAgICAgICAgcmV0dXJuIGNiKGVycik7XG4gICAgICAgIH1cbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBfdGhpcy5fcHJvY2VzcyhpbWFnZSwgX3RoaXMub3B0cyk7XG4gICAgICAgICAgcmV0dXJuIGNiKG51bGwsIF90aGlzLnN3YXRjaGVzKCkpO1xuICAgICAgICB9IGNhdGNoIChlcnJvcjEpIHtcbiAgICAgICAgICBlcnJvciA9IGVycm9yMTtcbiAgICAgICAgICByZXR1cm4gY2IoZXJyb3IpO1xuICAgICAgICB9XG4gICAgICB9O1xuICAgIH0pKHRoaXMpKTtcbiAgfTtcblxuICBWaWJyYW50LnByb3RvdHlwZS5nZXRTd2F0Y2hlcyA9IGZ1bmN0aW9uKGNiKSB7XG4gICAgcmV0dXJuIHRoaXMuZ2V0UGFsZXR0ZShjYik7XG4gIH07XG5cbiAgVmlicmFudC5wcm90b3R5cGUuX3Byb2Nlc3MgPSBmdW5jdGlvbihpbWFnZSwgb3B0cykge1xuICAgIHZhciBpbWFnZURhdGEsIHF1YW50aXplcjtcbiAgICBpbWFnZS5zY2FsZURvd24odGhpcy5vcHRzKTtcbiAgICBpbWFnZURhdGEgPSBpbWFnZS5nZXRJbWFnZURhdGEoKTtcbiAgICBxdWFudGl6ZXIgPSBuZXcgdGhpcy5vcHRzLlF1YW50aXplcigpO1xuICAgIHF1YW50aXplci5pbml0aWFsaXplKGltYWdlRGF0YS5kYXRhLCB0aGlzLm9wdHMpO1xuICAgIHRoaXMuYWxsU3dhdGNoZXMgPSBxdWFudGl6ZXIuZ2V0UXVhbnRpemVkQ29sb3JzKCk7XG4gICAgcmV0dXJuIGltYWdlLnJlbW92ZUNhbnZhcygpO1xuICB9O1xuXG4gIFZpYnJhbnQucHJvdG90eXBlLnN3YXRjaGVzID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIGNvbXBhcmluZ1BvcHVsYXRpb24sIGZpbmFsU3dhdGNoZXMsIGZpbmFsX3N3YXRjaCwgaiwgaywgbGVuLCBsZW4xLCByZWYsIHNob3VsZF9iZV9hZGRlZCwgc3dhdGNoO1xuICAgIGZpbmFsU3dhdGNoZXMgPSBbXTtcbiAgICB0aGlzLmFsbFN3YXRjaGVzID0gdGhpcy5hbGxTd2F0Y2hlcy5zb3J0KGZ1bmN0aW9uKGEsIGIpIHtcbiAgICAgIHJldHVybiBiLmdldFBvcHVsYXRpb24oKSAtIGEuZ2V0UG9wdWxhdGlvbigpO1xuICAgIH0pO1xuICAgIGNvbXBhcmluZ1BvcHVsYXRpb24gPSB0aGlzLmdldENvbXBhcmluZ1BvcHVsYXRpb24odGhpcy5hbGxTd2F0Y2hlcywgdGhpcy5vcHRzLmNvbXBhcmluZ1BvcHVsYXRpb25JbmRleCk7XG4gICAgcmVmID0gdGhpcy5hbGxTd2F0Y2hlcztcbiAgICBmb3IgKGogPSAwLCBsZW4gPSByZWYubGVuZ3RoOyBqIDwgbGVuOyBqKyspIHtcbiAgICAgIHN3YXRjaCA9IHJlZltqXTtcbiAgICAgIGlmICh0aGlzLnBvcHVsYXRpb25QZXJjZW50YWdlKHN3YXRjaC5nZXRQb3B1bGF0aW9uKCksIGNvbXBhcmluZ1BvcHVsYXRpb24pID4gdGhpcy5vcHRzLm1pblBvcHVsYXRpb24pIHtcbiAgICAgICAgc2hvdWxkX2JlX2FkZGVkID0gdHJ1ZTtcbiAgICAgICAgZm9yIChrID0gMCwgbGVuMSA9IGZpbmFsU3dhdGNoZXMubGVuZ3RoOyBrIDwgbGVuMTsgaysrKSB7XG4gICAgICAgICAgZmluYWxfc3dhdGNoID0gZmluYWxTd2F0Y2hlc1trXTtcbiAgICAgICAgICBpZiAoVmlicmFudC5VdGlsLnJnYkRpZmYoZmluYWxfc3dhdGNoLnJnYiwgc3dhdGNoLnJnYikgPCB0aGlzLm9wdHMubWluUmdiRGlmZikge1xuICAgICAgICAgICAgc2hvdWxkX2JlX2FkZGVkID0gZmFsc2U7XG4gICAgICAgICAgICBicmVhaztcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgICAgaWYgKHNob3VsZF9iZV9hZGRlZCkge1xuICAgICAgICAgIGZpbmFsU3dhdGNoZXMucHVzaChzd2F0Y2gpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiBmaW5hbFN3YXRjaGVzO1xuICB9O1xuXG4gIFZpYnJhbnQucHJvdG90eXBlLnBvcHVsYXRpb25QZXJjZW50YWdlID0gZnVuY3Rpb24ocG9wdWxhdGlvbiwgY29tcGFyaW5nUG9wdWxhdGlvbikge1xuICAgIGlmIChjb21wYXJpbmdQb3B1bGF0aW9uID09PSAwKSB7XG4gICAgICBjb25zb2xlLmxvZygnY29tcGFyaW5nIHBvcHVsYXRpb24gZXF1YWxzIDAhJyk7XG4gICAgICByZXR1cm4gMDtcbiAgICB9XG4gICAgcmV0dXJuIChwb3B1bGF0aW9uIC8gY29tcGFyaW5nUG9wdWxhdGlvbikgKiAxMDA7XG4gIH07XG5cbiAgVmlicmFudC5wcm90b3R5cGUuZ2V0Q29tcGFyaW5nUG9wdWxhdGlvbiA9IGZ1bmN0aW9uKHN3YXRjaGVzLCBpbmRleCkge1xuICAgIGlmIChzd2F0Y2hlcy5sZW5ndGggPiBpbmRleCkge1xuICAgICAgcmV0dXJuIHN3YXRjaGVzW2luZGV4XS5nZXRQb3B1bGF0aW9uKCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJldHVybiAxMDA7XG4gICAgfVxuICB9O1xuXG4gIHJldHVybiBWaWJyYW50O1xuXG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cy5CdWlsZGVyID0gQnVpbGRlciA9IChmdW5jdGlvbigpIHtcbiAgZnVuY3Rpb24gQnVpbGRlcihzcmMxLCBvcHRzMSkge1xuICAgIHRoaXMuc3JjID0gc3JjMTtcbiAgICB0aGlzLm9wdHMgPSBvcHRzMSAhPSBudWxsID8gb3B0czEgOiB7fTtcbiAgICB0aGlzLm9wdHMuZmlsdGVycyA9IHV0aWwuY2xvbmUoVmlicmFudC5EZWZhdWx0T3B0cy5maWx0ZXJzKTtcbiAgfVxuXG4gIEJ1aWxkZXIucHJvdG90eXBlLm1heENvbG9yQ291bnQgPSBmdW5jdGlvbihuKSB7XG4gICAgdGhpcy5vcHRzLmNvbG9yQ291bnQgPSBuO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLm1heERpbWVuc2lvbiA9IGZ1bmN0aW9uKGQpIHtcbiAgICB0aGlzLm9wdHMubWF4RGltZW5zaW9uID0gZDtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5hZGRGaWx0ZXIgPSBmdW5jdGlvbihmKSB7XG4gICAgaWYgKHR5cGVvZiBmID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICB0aGlzLm9wdHMuZmlsdGVycy5wdXNoKGYpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5yZW1vdmVGaWx0ZXIgPSBmdW5jdGlvbihmKSB7XG4gICAgdmFyIGk7XG4gICAgaWYgKChpID0gdGhpcy5vcHRzLmZpbHRlcnMuaW5kZXhPZihmKSkgPiAwKSB7XG4gICAgICB0aGlzLm9wdHMuZmlsdGVycy5zcGxpY2UoaSk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmNsZWFyRmlsdGVycyA9IGZ1bmN0aW9uKCkge1xuICAgIHRoaXMub3B0cy5maWx0ZXJzID0gW107XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUucXVhbGl0eSA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMucXVhbGl0eSA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUubWluUG9wdWxhdGlvbiA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMubWluUG9wdWxhdGlvbiA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUubWluUmdiRGlmZiA9IGZ1bmN0aW9uKHEpIHtcbiAgICB0aGlzLm9wdHMubWluUmdiRGlmZiA9IHE7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH07XG5cbiAgQnVpbGRlci5wcm90b3R5cGUuY29tcGFyaW5nUG9wdWxhdGlvbkluZGV4ID0gZnVuY3Rpb24ocSkge1xuICAgIHRoaXMub3B0cy5jb21wYXJpbmdQb3B1bGF0aW9uSW5kZXggPSBxO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLnVzZUltYWdlID0gZnVuY3Rpb24oaW1hZ2UpIHtcbiAgICB0aGlzLm9wdHMuSW1hZ2UgPSBpbWFnZTtcbiAgICByZXR1cm4gdGhpcztcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS51c2VRdWFudGl6ZXIgPSBmdW5jdGlvbihxdWFudGl6ZXIpIHtcbiAgICB0aGlzLm9wdHMuUXVhbnRpemVyID0gcXVhbnRpemVyO1xuICAgIHJldHVybiB0aGlzO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmJ1aWxkID0gZnVuY3Rpb24oKSB7XG4gICAgaWYgKHRoaXMudiA9PSBudWxsKSB7XG4gICAgICB0aGlzLnYgPSBuZXcgVmlicmFudCh0aGlzLnNyYywgdGhpcy5vcHRzKTtcbiAgICB9XG4gICAgcmV0dXJuIHRoaXMudjtcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5nZXRTd2F0Y2hlcyA9IGZ1bmN0aW9uKGNiKSB7XG4gICAgcmV0dXJuIHRoaXMuYnVpbGQoKS5nZXRQYWxldHRlKGNiKTtcbiAgfTtcblxuICBCdWlsZGVyLnByb3RvdHlwZS5nZXRQYWxldHRlID0gZnVuY3Rpb24oY2IpIHtcbiAgICByZXR1cm4gdGhpcy5idWlsZCgpLmdldFBhbGV0dGUoY2IpO1xuICB9O1xuXG4gIEJ1aWxkZXIucHJvdG90eXBlLmZyb20gPSBmdW5jdGlvbihzcmMpIHtcbiAgICByZXR1cm4gbmV3IFZpYnJhbnQoc3JjLCB0aGlzLm9wdHMpO1xuICB9O1xuXG4gIHJldHVybiBCdWlsZGVyO1xuXG59KSgpO1xuXG5tb2R1bGUuZXhwb3J0cy5VdGlsID0gdXRpbDtcblxubW9kdWxlLmV4cG9ydHMuU3dhdGNoID0gU3dhdGNoO1xuXG5tb2R1bGUuZXhwb3J0cy5RdWFudGl6ZXIgPSByZXF1aXJlKCcuL3F1YW50aXplci8nKTtcblxubW9kdWxlLmV4cG9ydHMuR2VuZXJhdG9yID0gcmVxdWlyZSgnLi9nZW5lcmF0b3IvJyk7XG5cbm1vZHVsZS5leHBvcnRzLkZpbHRlciA9IHJlcXVpcmUoJy4vZmlsdGVyLycpO1xuXG4vLyMgc291cmNlTWFwcGluZ1VSTD1kYXRhOmFwcGxpY2F0aW9uL2pzb247YmFzZTY0LGV5SjJaWEp6YVc5dUlqb3pMQ0ptYVd4bElqb2lMMVZ6WlhKekwyTTBMMFJ2WTNWdFpXNTBjeTlRY205cVpXTjBjeTl6Wld4c1pXOHZibTlrWlMxc2IyZHZMV052Ykc5eWN5OXpjbU12ZG1saWNtRnVkQzVqYjJabVpXVWlMQ0p6YjNWeVkyVlNiMjkwSWpvaUlpd2ljMjkxY21ObGN5STZXeUl2VlhObGNuTXZZelF2Ukc5amRXMWxiblJ6TDFCeWIycGxZM1J6TDNObGJHeGxieTl1YjJSbExXeHZaMjh0WTI5c2IzSnpMM055WXk5MmFXSnlZVzUwTG1OdlptWmxaU0pkTENKdVlXMWxjeUk2VzEwc0ltMWhjSEJwYm1keklqb2lPMEZCUVVFN096czdPenM3T3pzN08wRkJRVUVzU1VGQlFTeDNSRUZCUVR0RlFVRkJPenRCUVZkQkxFMUJRVUVzUjBGQlV5eFBRVUZCTEVOQlFWRXNWVUZCVWpzN1FVRkRWQ3hKUVVGQkxFZEJRVThzVDBGQlFTeERRVUZSTEZGQlFWSTdPMEZCUTFBc1owSkJRVUVzUjBGQmJVSXNUMEZCUVN4RFFVRlJMR0ZCUVZJc1EwRkJjMElzUTBGQlF6czdRVUZETVVNc1RVRkJRU3hIUVVGVExFOUJRVUVzUTBGQlVTeFZRVUZTT3p0QlFVVlVMRTFCUVUwc1EwRkJReXhQUVVGUUxFZEJRMDA3UlVGRFNpeFBRVUZETEVOQlFVRXNWMEZCUkN4SFFVTkZPMGxCUVVFc1ZVRkJRU3hGUVVGWkxFVkJRVm83U1VGRFFTeFBRVUZCTEVWQlFWTXNRMEZFVkR0SlFVVkJMRk5CUVVFc1JVRkJWeXhKUVVGSkxHZENRVUZLTEVOQlFVRXNRMEZHV0R0SlFVZEJMRXRCUVVFc1JVRkJUeXhKUVVoUU8wbEJTVUVzVTBGQlFTeEZRVUZYTEU5QlFVRXNRMEZCVVN4aFFVRlNMRU5CUVhOQ0xFTkJRVU1zU1VGS2JFTTdTVUZMUVN4UFFVRkJMRVZCUVZNc1JVRk1WRHRKUVUxQkxHRkJRVUVzUlVGQlpTeEZRVTVtTzBsQlQwRXNWVUZCUVN4RlFVRlpMRVZCVUZvN1NVRlJRU3gzUWtGQlFTeEZRVUV3UWl4RFFWSXhRanM3TzBWQlZVWXNUMEZCUXl4RFFVRkJMRWxCUVVRc1IwRkJUeXhUUVVGRExFZEJRVVE3VjBGRFRDeEpRVUZKTEU5QlFVb3NRMEZCV1N4SFFVRmFPMFZCUkVzN08yOUNRVWRRTEZGQlFVRXNSMEZCVlN4UFFVRkJMRU5CUVZFc1ZVRkJVanM3YjBKQlJWWXNVMEZCUVN4SFFVRlhPenRGUVVWRkxHbENRVUZETEZkQlFVUXNSVUZCWlN4SlFVRm1PMGxCUVVNc1NVRkJReXhEUVVGQkxHTkJRVVE3TzAxQlFXTXNUMEZCVHpzN08wbEJRMnBETEVsQlFVTXNRMEZCUVN4SlFVRkVMRWRCUVZFc1NVRkJTU3hEUVVGRExGRkJRVXdzUTBGQll5eEpRVUZrTEVWQlFXOUNMRWxCUVVNc1EwRkJRU3hYUVVGWExFTkJRVU1zVjBGQmFrTTdTVUZEVWl4SlFVRkRMRU5CUVVFc1UwRkJSQ3hIUVVGaExFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTTdSVUZHVWpzN2IwSkJTV0lzVlVGQlFTeEhRVUZaTEZOQlFVTXNSVUZCUkR0QlFVTldMRkZCUVVFN1YwRkJRU3hMUVVGQkxFZEJRVkVzU1VGQlNTeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRXRCUVZZc1EwRkJaMElzU1VGQlF5eERRVUZCTEZkQlFXcENMRVZCUVRoQ0xFTkJRVUVzVTBGQlFTeExRVUZCTzJGQlFVRXNVMEZCUXl4SFFVRkVMRVZCUVUwc1MwRkJUanRCUVVOd1F5eFpRVUZCTzFGQlFVRXNTVUZCUnl4WFFVRklPMEZCUVdFc2FVSkJRVThzUlVGQlFTeERRVUZITEVkQlFVZ3NSVUZCY0VJN08wRkJRMEU3VlVGRFJTeExRVUZETEVOQlFVRXNVVUZCUkN4RFFVRlZMRXRCUVZZc1JVRkJhVUlzUzBGQlF5eERRVUZCTEVsQlFXeENPMmxDUVVOQkxFVkJRVUVzUTBGQlJ5eEpRVUZJTEVWQlFWTXNTMEZCUXl4RFFVRkJMRkZCUVVRc1EwRkJRU3hEUVVGVUxFVkJSa1k3VTBGQlFTeGpRVUZCTzFWQlIwMDdRVUZEU2l4cFFrRkJUeXhGUVVGQkxFTkJRVWNzUzBGQlNDeEZRVXBVT3p0TlFVWnZRenRKUVVGQkxFTkJRVUVzUTBGQlFTeERRVUZCTEVsQlFVRXNRMEZCT1VJN1JVRkVSVHM3YjBKQlUxb3NWMEZCUVN4SFFVRmhMRk5CUVVNc1JVRkJSRHRYUVVOWUxFbEJRVU1zUTBGQlFTeFZRVUZFTEVOQlFWa3NSVUZCV2p0RlFVUlhPenR2UWtGSFlpeFJRVUZCTEVkQlFWVXNVMEZCUXl4TFFVRkVMRVZCUVZFc1NVRkJVanRCUVVOU0xGRkJRVUU3U1VGQlFTeExRVUZMTEVOQlFVTXNVMEZCVGl4RFFVRm5RaXhKUVVGRExFTkJRVUVzU1VGQmFrSTdTVUZEUVN4VFFVRkJMRWRCUVZrc1MwRkJTeXhEUVVGRExGbEJRVTRzUTBGQlFUdEpRVVZhTEZOQlFVRXNSMEZCV1N4SlFVRkpMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zVTBGQlZpeERRVUZCTzBsQlExb3NVMEZCVXl4RFFVRkRMRlZCUVZZc1EwRkJjVUlzVTBGQlV5eERRVUZETEVsQlFTOUNMRVZCUVhGRExFbEJRVU1zUTBGQlFTeEpRVUYwUXp0SlFVVkJMRWxCUVVNc1EwRkJRU3hYUVVGRUxFZEJRV1VzVTBGQlV5eERRVUZETEd0Q1FVRldMRU5CUVVFN1YwRkZaaXhMUVVGTExFTkJRVU1zV1VGQlRpeERRVUZCTzBWQlZGRTdPMjlDUVZkV0xGRkJRVUVzUjBGQlZTeFRRVUZCTzBGQlExSXNVVUZCUVR0SlFVRkJMR0ZCUVVFc1IwRkJaMEk3U1VGRmFFSXNTVUZCUXl4RFFVRkJMRmRCUVVRc1IwRkJaU3hKUVVGRExFTkJRVUVzVjBGQlZ5eERRVUZETEVsQlFXSXNRMEZCYTBJc1UwRkJReXhEUVVGRUxFVkJRVWtzUTBGQlNqdGhRVU12UWl4RFFVRkRMRU5CUVVNc1lVRkJSaXhEUVVGQkxFTkJRVUVzUjBGQmIwSXNRMEZCUXl4RFFVRkRMR0ZCUVVZc1EwRkJRVHRKUVVSWExFTkJRV3hDTzBsQlIyWXNiVUpCUVVFc1IwRkJjMElzU1VGQlF5eERRVUZCTEhOQ1FVRkVMRU5CUVhkQ0xFbEJRVU1zUTBGQlFTeFhRVUY2UWl4RlFVRnpReXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEhkQ1FVRTFRenRCUVVWMFFqdEJRVUZCTEZOQlFVRXNjVU5CUVVFN08wMUJRMFVzU1VGQlJ5eEpRVUZETEVOQlFVRXNiMEpCUVVRc1EwRkJjMElzVFVGQlRTeERRVUZETEdGQlFWQXNRMEZCUVN4RFFVRjBRaXhGUVVFNFF5eHRRa0ZCT1VNc1EwRkJRU3hIUVVGeFJTeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMR0ZCUVRsRk8xRkJRMFVzWlVGQlFTeEhRVUZyUWp0QlFVVnNRaXhoUVVGQkxHbEVRVUZCT3p0VlFVTkZMRWxCUVVjc1QwRkJUeXhEUVVGRExFbEJRVWtzUTBGQlF5eFBRVUZpTEVOQlFYRkNMRmxCUVZrc1EwRkJReXhIUVVGc1F5eEZRVUYxUXl4TlFVRk5MRU5CUVVNc1IwRkJPVU1zUTBGQlFTeEhRVUZ4UkN4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGVkJRVGxFTzFsQlEwVXNaVUZCUVN4SFFVRnJRanRCUVVOc1FpeHJRa0ZHUmpzN1FVRkVSanRSUVV0QkxFbEJRVWNzWlVGQlNEdFZRVU5GTEdGQlFXRXNRMEZCUXl4SlFVRmtMRU5CUVcxQ0xFMUJRVzVDTEVWQlJFWTdVMEZTUmpzN1FVRkVSanRYUVZsQk8wVkJjRUpST3p0dlFrRnpRbFlzYjBKQlFVRXNSMEZCYzBJc1UwRkJReXhWUVVGRUxFVkJRV0VzYlVKQlFXSTdTVUZEY0VJc1NVRkJSeXh0UWtGQlFTeExRVUYxUWl4RFFVRXhRanROUVVORkxFOUJRVThzUTBGQlF5eEhRVUZTTEVOQlFWa3NaME5CUVZvN1FVRkRRU3hoUVVGUExFVkJSbFE3TzFkQlNVRXNRMEZCUXl4VlFVRkJMRWRCUVdFc2JVSkJRV1FzUTBGQlFTeEhRVUZ4UXp0RlFVeHFRanM3YjBKQlQzUkNMSE5DUVVGQkxFZEJRWGRDTEZOQlFVTXNVVUZCUkN4RlFVRlhMRXRCUVZnN1NVRkRkRUlzU1VGQlJ5eFJRVUZSTEVOQlFVTXNUVUZCVkN4SFFVRnJRaXhMUVVGeVFqdGhRVU5GTEZGQlFWTXNRMEZCUVN4TFFVRkJMRU5CUVUwc1EwRkJReXhoUVVGb1FpeERRVUZCTEVWQlJFWTdTMEZCUVN4TlFVRkJPMkZCUjBVc1NVRklSanM3UlVGRWMwSTdPenM3T3p0QlFVMHhRaXhOUVVGTkxFTkJRVU1zVDBGQlR5eERRVUZETEU5QlFXWXNSMEZEVFR0RlFVTlRMR2xDUVVGRExFbEJRVVFzUlVGQlR5eExRVUZRTzBsQlFVTXNTVUZCUXl4RFFVRkJMRTFCUVVRN1NVRkJUU3hKUVVGRExFTkJRVUVzZFVKQlFVUXNVVUZCVVR0SlFVTXhRaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEU5QlFVNHNSMEZCWjBJc1NVRkJTU3hEUVVGRExFdEJRVXdzUTBGQlZ5eFBRVUZQTEVOQlFVTXNWMEZCVnl4RFFVRkRMRTlCUVM5Q08wVkJSRXc3TzI5Q1FVZGlMR0ZCUVVFc1IwRkJaU3hUUVVGRExFTkJRVVE3U1VGRFlpeEpRVUZETEVOQlFVRXNTVUZCU1N4RFFVRkRMRlZCUVU0c1IwRkJiVUk3VjBGRGJrSTdSVUZHWVRzN2IwSkJTV1lzV1VGQlFTeEhRVUZqTEZOQlFVTXNRMEZCUkR0SlFVTmFMRWxCUVVNc1EwRkJRU3hKUVVGSkxFTkJRVU1zV1VGQlRpeEhRVUZ4UWp0WFFVTnlRanRGUVVaWk96dHZRa0ZKWkN4VFFVRkJMRWRCUVZjc1UwRkJReXhEUVVGRU8wbEJRMVFzU1VGQlJ5eFBRVUZQTEVOQlFWQXNTMEZCV1N4VlFVRm1PMDFCUTBVc1NVRkJReXhEUVVGQkxFbEJRVWtzUTBGQlF5eFBRVUZQTEVOQlFVTXNTVUZCWkN4RFFVRnRRaXhEUVVGdVFpeEZRVVJHT3p0WFFVVkJPMFZCU0ZNN08yOUNRVXRZTEZsQlFVRXNSMEZCWXl4VFFVRkRMRU5CUVVRN1FVRkRXaXhSUVVGQk8wbEJRVUVzU1VGQlJ5eERRVUZETEVOQlFVRXNSMEZCU1N4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExFOUJRVThzUTBGQlF5eFBRVUZrTEVOQlFYTkNMRU5CUVhSQ0xFTkJRVXdzUTBGQlFTeEhRVUZwUXl4RFFVRndRenROUVVORkxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNUMEZCVHl4RFFVRkRMRTFCUVdRc1EwRkJjVUlzUTBGQmNrSXNSVUZFUmpzN1YwRkZRVHRGUVVoWk96dHZRa0ZMWkN4WlFVRkJMRWRCUVdNc1UwRkJRVHRKUVVOYUxFbEJRVU1zUTBGQlFTeEpRVUZKTEVOQlFVTXNUMEZCVGl4SFFVRm5RanRYUVVOb1FqdEZRVVpaT3p0dlFrRkpaQ3hQUVVGQkxFZEJRVk1zVTBGQlF5eERRVUZFTzBsQlExQXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXhQUVVGT0xFZEJRV2RDTzFkQlEyaENPMFZCUms4N08yOUNRVWxVTEdGQlFVRXNSMEZCWlN4VFFVRkRMRU5CUVVRN1NVRkRZaXhKUVVGRExFTkJRVUVzU1VGQlNTeERRVUZETEdGQlFVNHNSMEZCYzBJN1YwRkRkRUk3UlVGR1lUczdiMEpCU1dZc1ZVRkJRU3hIUVVGWkxGTkJRVU1zUTBGQlJEdEpRVU5XTEVsQlFVTXNRMEZCUVN4SlFVRkpMRU5CUVVNc1ZVRkJUaXhIUVVGdFFqdFhRVU51UWp0RlFVWlZPenR2UWtGSldpeDNRa0ZCUVN4SFFVRXdRaXhUUVVGRExFTkJRVVE3U1VGRGVFSXNTVUZCUXl4RFFVRkJMRWxCUVVrc1EwRkJReXgzUWtGQlRpeEhRVUZwUXp0WFFVTnFRenRGUVVaM1FqczdiMEpCU1RGQ0xGRkJRVUVzUjBGQlZTeFRRVUZETEV0QlFVUTdTVUZEVWl4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExFdEJRVTRzUjBGQll6dFhRVU5rTzBWQlJsRTdPMjlDUVVsV0xGbEJRVUVzUjBGQll5eFRRVUZETEZOQlFVUTdTVUZEV2l4SlFVRkRMRU5CUVVFc1NVRkJTU3hEUVVGRExGTkJRVTRzUjBGQmEwSTdWMEZEYkVJN1JVRkdXVHM3YjBKQlNXUXNTMEZCUVN4SFFVRlBMRk5CUVVFN1NVRkRUQ3hKUVVGUExHTkJRVkE3VFVGRFJTeEpRVUZETEVOQlFVRXNRMEZCUkN4SFFVRkxMRWxCUVVrc1QwRkJTaXhEUVVGWkxFbEJRVU1zUTBGQlFTeEhRVUZpTEVWQlFXdENMRWxCUVVNc1EwRkJRU3hKUVVGdVFpeEZRVVJRT3p0WFFVVkJMRWxCUVVNc1EwRkJRVHRGUVVoSk96dHZRa0ZMVUN4WFFVRkJMRWRCUVdFc1UwRkJReXhGUVVGRU8xZEJRMWdzU1VGQlF5eERRVUZCTEV0QlFVUXNRMEZCUVN4RFFVRlJMRU5CUVVNc1ZVRkJWQ3hEUVVGdlFpeEZRVUZ3UWp0RlFVUlhPenR2UWtGSFlpeFZRVUZCTEVkQlFWa3NVMEZCUXl4RlFVRkVPMWRCUTFZc1NVRkJReXhEUVVGQkxFdEJRVVFzUTBGQlFTeERRVUZSTEVOQlFVTXNWVUZCVkN4RFFVRnZRaXhGUVVGd1FqdEZRVVJWT3p0dlFrRkhXaXhKUVVGQkxFZEJRVTBzVTBGQlF5eEhRVUZFTzFkQlEwb3NTVUZCU1N4UFFVRktMRU5CUVZrc1IwRkJXaXhGUVVGcFFpeEpRVUZETEVOQlFVRXNTVUZCYkVJN1JVRkVTVHM3T3pzN08wRkJSMUlzVFVGQlRTeERRVUZETEU5QlFVOHNRMEZCUXl4SlFVRm1MRWRCUVhOQ096dEJRVU4wUWl4TlFVRk5MRU5CUVVNc1QwRkJUeXhEUVVGRExFMUJRV1lzUjBGQmQwSTdPMEZCUTNoQ0xFMUJRVTBzUTBGQlF5eFBRVUZQTEVOQlFVTXNVMEZCWml4SFFVRXlRaXhQUVVGQkxFTkJRVkVzWTBGQlVqczdRVUZETTBJc1RVRkJUU3hEUVVGRExFOUJRVThzUTBGQlF5eFRRVUZtTEVkQlFUSkNMRTlCUVVFc1EwRkJVU3hqUVVGU096dEJRVU16UWl4TlFVRk5MRU5CUVVNc1QwRkJUeXhEUVVGRExFMUJRV1lzUjBGQmQwSXNUMEZCUVN4RFFVRlJMRmRCUVZJaWZRPT1cbiJdfQ==
