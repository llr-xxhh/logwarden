/* Small compatibility layer for current Chrome / Edge / Firefox and older Chromium shells. */
(function () {
  if (!Element.prototype.matches) {
    Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
  }
  if (!Element.prototype.closest) {
    Element.prototype.closest = function (selector) {
      var node = this;
      while (node && node.nodeType === 1) {
        if (node.matches(selector)) return node;
        node = node.parentElement || node.parentNode;
      }
      return null;
    };
  }
  if (window.NodeList && !NodeList.prototype.forEach) {
    NodeList.prototype.forEach = Array.prototype.forEach;
  }
  if (window.HTMLCollection && !HTMLCollection.prototype.forEach) {
    HTMLCollection.prototype.forEach = Array.prototype.forEach;
  }
  if (!Array.prototype.includes) {
    Array.prototype.includes = function (value) {
      return this.indexOf(value) !== -1;
    };
  }
  if (!String.prototype.includes) {
    String.prototype.includes = function (value) {
      return this.indexOf(value) !== -1;
    };
  }
  if (!String.prototype.startsWith) {
    String.prototype.startsWith = function (value) {
      return this.slice(0, value.length) === value;
    };
  }
  if (!String.prototype.endsWith) {
    String.prototype.endsWith = function (value) {
      return this.slice(-value.length) === value;
    };
  }
  if (!String.prototype.padStart) {
    String.prototype.padStart = function (length, fill) {
      var text = String(this);
      fill = fill === undefined ? " " : String(fill);
      while (text.length < length) text = fill + text;
      return text;
    };
  }
  if (!String.prototype.padEnd) {
    String.prototype.padEnd = function (length, fill) {
      var text = String(this);
      fill = fill === undefined ? " " : String(fill);
      while (text.length < length) text += fill;
      return text;
    };
  }
  if (!Object.assign) {
    Object.assign = function (target) {
      for (var i = 1; i < arguments.length; i++) {
        var source = arguments[i];
        if (!source) continue;
        for (var key in source) {
          if (Object.prototype.hasOwnProperty.call(source, key)) target[key] = source[key];
        }
      }
      return target;
    };
  }
  if (!Array.from) {
    Array.from = function (value) {
      return Array.prototype.slice.call(value);
    };
  }
})();
