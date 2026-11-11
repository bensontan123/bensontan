/* =======================================================================
   UI enhancements: section-header icons, mobile nav, scroll-spy active
   link, and scroll-reveal. Purely presentational; degrades gracefully.
   ===================================================================== */
(function () {
  "use strict";
  const byId = (id) => document.getElementById(id);

  function ready(fn) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }

  ready(function () {
    /* section-header icons */
    const SEC_ICON = {
      about: "user", skills: "grid", experience: "timeline", highlights: "star",
      vulns: "bug", cti: "radar", threatmodel: "target", news: "globe",
      education: "cap", contact: "mail",
    };
    Object.keys(SEC_ICON).forEach((id) => {
      const sec = byId(id); if (!sec) return;
      const head = sec.querySelector(".sec-head"); if (!head || head.querySelector(".sec-ico")) return;
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "ic sec-ico"); svg.setAttribute("aria-hidden", "true");
      svg.innerHTML = '<use href="#i-' + SEC_ICON[id] + '"></use>';
      head.insertBefore(svg, head.firstChild);
    });

    /* skill-card + project icons */
    const SKILL_ICON = { risk: "target", grc: "scale", frameworks: "grid", vuln: "bug", iam: "key", bcm: "refresh" };
    document.querySelectorAll("#skillGrid .skill-card h3").forEach((h) => {
      const key = (h.textContent || "").toLowerCase();
      let ic = "cpu";
      if (/risk assessment/.test(key)) ic = SKILL_ICON.risk;
      else if (/governance/.test(key)) ic = SKILL_ICON.grc;
      else if (/framework/.test(key)) ic = SKILL_ICON.frameworks;
      else if (/vulnerab|threat ops/.test(key)) ic = SKILL_ICON.vuln;
      else if (/iam|pam|tooling/.test(key)) ic = SKILL_ICON.iam;
      else if (/audit|bcm|emerging/.test(key)) ic = SKILL_ICON.bcm;
      if (h.querySelector(".ic")) return;
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "ic"); svg.setAttribute("aria-hidden", "true");
      svg.innerHTML = '<use href="#i-' + ic + '"></use>';
      h.insertBefore(svg, h.firstChild); h.insertBefore(document.createTextNode(" "), svg.nextSibling);
    });

    /* mobile nav toggle */
    const links = document.querySelector(".nav-links");
    const toggle = byId("navToggle");
    if (toggle && links) {
      toggle.addEventListener("click", () => {
        const open = links.classList.toggle("open");
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
      });
      links.addEventListener("click", (e) => { if (e.target.closest("a")) { links.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); } });
    }

    /* scroll-reveal */
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const reveals = document.querySelectorAll("section .wrap > .sec-head, section .card, .skill-card, .proj, .edu, .tcard, .cve, .news");
    if (!reduce && "IntersectionObserver" in window) {
      reveals.forEach((el) => el.classList.add("reveal"));
      const io = new IntersectionObserver((ents) => {
        ents.forEach((en) => { if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); } });
      }, { rootMargin: "0px 0px -8% 0px", threshold: 0.05 });
      reveals.forEach((el) => io.observe(el));
    }

    /* scroll-spy: highlight the nav link for the section in view */
    const navAnchors = [...document.querySelectorAll(".nav-links a")];
    const sections = navAnchors.map((a) => byId(a.getAttribute("href").slice(1))).filter(Boolean);
    if ("IntersectionObserver" in window && sections.length) {
      const spy = new IntersectionObserver((ents) => {
        ents.forEach((en) => {
          if (!en.isIntersecting) return;
          const id = en.target.id;
          navAnchors.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + id));
        });
      }, { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
      sections.forEach((s) => spy.observe(s));
    }
  });
})();
