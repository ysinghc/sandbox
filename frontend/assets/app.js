(function () {
  "use strict";

  var toggle = document.querySelector(".menu-toggle");
  var nav = document.getElementById("site-nav");

  if (toggle && nav) {
    var setOpen = function (open) {
      toggle.setAttribute("aria-expanded", String(open));
      nav.classList.toggle("is-open", open);
      var label = toggle.querySelector(".sr-only");
      if (label) label.textContent = open ? "Close menu" : "Open menu";
    };

    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });

    nav.addEventListener("click", function (event) {
      if (event.target.closest("a")) setOpen(false);
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        toggle.focus();
      }
    });

    window.addEventListener("resize", function () {
      if (window.innerWidth > 820) setOpen(false);
    });
  }

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.getElementById(button.getAttribute("data-copy"));
      if (!target) return;

      var text = target.innerText;
      var done = function () {
        var original = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(function () {
          button.textContent = original;
        }, 1600);
      };

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {});
        return;
      }

      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        done();
      } finally {
        document.body.removeChild(area);
      }
    });
  });
})();
