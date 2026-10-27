// Adds a link back to the matsya landing page in the docs menu bar.
(function () {
  "use strict";
  function addHomeLink() {
    var bar = document.querySelector("#mdbook-menu-bar .left-buttons") ||
      document.querySelector(".menu-bar .left-buttons");
    if (!bar || document.querySelector(".matsya-home")) {
      return;
    }
    var root = (typeof path_to_root === "string") ? path_to_root : "";
    var a = document.createElement("a");
    a.className = "matsya-home";
    a.href = root + "../";
    a.title = "matsya home page";
    var img = document.createElement("img");
    img.src = root + "../assets/logo.svg";
    img.alt = "";
    img.width = 26;
    img.height = 26;
    var label = document.createElement("span");
    label.textContent = "matsya";
    a.appendChild(img);
    a.appendChild(label);
    bar.appendChild(a);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", addHomeLink);
  } else {
    addHomeLink();
  }
})();
