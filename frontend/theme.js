"use strict";
/* Light / dark theme. Dark is the default. The choice is remembered in this browser only. */
(function () {
  var KEY = "phishguard-theme";
  function read() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function write(v) { try { localStorage.setItem(KEY, v); } catch (e) { /* storage blocked: theme just won't persist */ } }
  function apply(t) {
    document.documentElement.setAttribute("data-theme", t);
    var b = document.getElementById("themeBtn");
    if (b) {
      b.setAttribute("aria-pressed", t === "light" ? "true" : "false");
      b.setAttribute("aria-label", t === "light" ? "Switch to dark theme" : "Switch to light theme");
      b.title = b.getAttribute("aria-label");
      var i = b.querySelector(".ti"); if (i) i.textContent = t === "light" ? "☾" : "☀";
      var l = b.querySelector(".tl"); if (l) l.textContent = t === "light" ? "Dark" : "Light";
    }
  }
  var current = read() === "light" ? "light" : "dark";
  apply(current);                                   /* before first paint: no flash */
  document.addEventListener("DOMContentLoaded", function () {
    apply(current);
    var b = document.getElementById("themeBtn");
    if (b) b.addEventListener("click", function () {
      current = current === "light" ? "dark" : "light";
      write(current); apply(current);
    });
  });
})();
