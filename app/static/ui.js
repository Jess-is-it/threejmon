(() => {
  const qs = (sel, root = document) => root.querySelector(sel);
  const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const dispatch = (el, name, detail = {}) => {
    try {
      el.dispatchEvent(new CustomEvent(name, { bubbles: true, cancelable: false, detail }));
    } catch {
      // ignore
    }
  };

  const showTab = (linkEl) => {
    if (!linkEl) return;
    const href = (linkEl.getAttribute("href") || "").trim();
    if (!href || !href.startsWith("#")) return;
    const pane = qs(href);
    if (!pane) return;

    const nav = linkEl.closest(".nav-tabs") || linkEl.closest('[role="tablist"]');
    const allLinks = nav ? qsa('a[data-bs-toggle="tab"]', nav) : [];
    allLinks.forEach((a) => a.classList.remove("active"));
    linkEl.classList.add("active");

    const container = pane.parentElement;
    if (container && container.classList.contains("tab-content")) {
      qsa(".tab-pane", container).forEach((p) => p.classList.remove("active", "show"));
    }
    pane.classList.add("active", "show");

    dispatch(linkEl, "shown.bs.tab", { relatedTarget: null, target: pane });
  };

  const toggleDropdown = (btn) => {
    const wrap = btn.closest(".dropdown") || btn.parentElement;
    if (!wrap) return;
    const menu = qs(".dropdown-menu", wrap);
    if (!menu) return;
    const isOpen = menu.classList.contains("show");
    qsa(".dropdown-menu.show").forEach((m) => m.classList.remove("show"));
    if (!isOpen) menu.classList.add("show");
  };

  const closeDropdowns = () => {
    qsa(".dropdown-menu.show").forEach((m) => m.classList.remove("show"));
  };

  const getModalEl = (trigger) => {
    const target = (trigger.getAttribute("data-bs-target") || trigger.getAttribute("href") || "").trim();
    if (!target || !target.startsWith("#")) return null;
    return qs(target);
  };

  const showModal = (modalEl) => {
    if (!modalEl) return;
    if (modalEl.classList.contains("show")) return;
    modalEl.classList.add("show");
    modalEl.style.display = "block";
    modalEl.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");

    // backdrop
    if (!qs(".modal-backdrop", modalEl)) {
      const backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop";
      backdrop.addEventListener("click", () => hideModal(modalEl));
      modalEl.prepend(backdrop);
    }
    dispatch(modalEl, "shown.bs.modal");
  };

  const hideModal = (modalEl) => {
    if (!modalEl) return;
    modalEl.classList.remove("show");
    modalEl.style.display = "none";
    modalEl.setAttribute("aria-hidden", "true");
    document.body.classList.remove("modal-open");
    dispatch(modalEl, "hidden.bs.modal");
  };

  const toggleCollapse = (btn) => {
    const target = (btn.getAttribute("data-bs-target") || "").trim();
    if (!target || !target.startsWith("#")) return;
    const el = qs(target);
    if (!el) return;
    const isOpen = el.classList.contains("show");
    if (isOpen) el.classList.remove("show");
    else el.classList.add("show");
    btn.setAttribute("aria-expanded", String(!isOpen));

    if (target === "#sidebar-menu") {
      const sidebar = qs("aside.navbar-vertical");
      if (sidebar) {
        if (isOpen) sidebar.classList.remove("open");
        else sidebar.classList.add("open");
      }
    }
  };

  // Minimal bootstrap-like API used by templates (guards on window.bootstrap?.Tab/Modal).
  window.bootstrap = window.bootstrap || {};
  window.bootstrap.Tab = class Tab {
    constructor(el) { this._el = el; }
    show() { showTab(this._el); }
  };
  window.bootstrap.Modal = class Modal {
    constructor(el) { this._el = el; }
    show() { showModal(this._el); }
    hide() { hideModal(this._el); }
    static getInstance(el) { return el && el.__threej_modal ? el.__threej_modal : null; }
  };
  window.bootstrap.Tooltip = class Tooltip {
    static getOrCreateInstance() { return null; }
  };

  document.addEventListener("click", (event) => {
    const tabLink = event.target.closest('a[data-bs-toggle="tab"]');
    if (tabLink) {
      event.preventDefault();
      showTab(tabLink);
      return;
    }

    const ddBtn = event.target.closest('[data-bs-toggle="dropdown"]');
    if (ddBtn) {
      event.preventDefault();
      toggleDropdown(ddBtn);
      return;
    }

    const modalBtn = event.target.closest('[data-bs-toggle="modal"]');
    if (modalBtn) {
      event.preventDefault();
      const modalEl = getModalEl(modalBtn);
      if (modalEl) {
        modalEl.__threej_modal = modalEl.__threej_modal || new window.bootstrap.Modal(modalEl);
        modalEl.__threej_modal.show();
      }
      return;
    }

    const dismissModalBtn = event.target.closest('[data-bs-dismiss="modal"]');
    if (dismissModalBtn) {
      event.preventDefault();
      const modalEl = dismissModalBtn.closest(".modal");
      if (modalEl) hideModal(modalEl);
      return;
    }

    const collapseBtn = event.target.closest('[data-bs-toggle="collapse"]');
    if (collapseBtn) {
      event.preventDefault();
      toggleCollapse(collapseBtn);
      return;
    }

    // Click outside dropdown closes it.
    const clickedInDropdown = !!event.target.closest(".dropdown");
    if (!clickedInDropdown) closeDropdowns();

    // Click outside sidebar closes it on mobile.
    const sidebar = qs("aside.navbar-vertical");
    if (sidebar && sidebar.classList.contains("open")) {
      const clickedInSidebar = !!event.target.closest("aside.navbar-vertical");
      const clickedToggle = !!event.target.closest(".threej-sidebar-toggle");
      if (!clickedInSidebar && !clickedToggle) {
        sidebar.classList.remove("open");
        const menu = qs("#sidebar-menu");
        if (menu) menu.classList.remove("show");
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    closeDropdowns();
    qsa(".modal.show").forEach((m) => hideModal(m));
  });
})();
