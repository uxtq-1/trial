/*****************************************************
 * main.js
 * Handles language switching, side menu toggles,
 * services sub-menu, modals, form submissions, and
 * theme toggles (desktop & mobile).
 *****************************************************/

document.addEventListener("DOMContentLoaded", () => {
  
  // ================================================================
                // LANGUAGE TOGGLE (Desktop & Mobile)
  // =================================================================

  let currentLanguage = localStorage.getItem("language") || "en";
  const langToggleDesktop = document.getElementById("language-toggle-desktop");
  const langToggleMobile  = document.getElementById("language-toggle-mobile");

  // Helper: set text to either data-en or data-es
  function updateLanguage(lang) {
    const translatableElements = document.querySelectorAll("[data-en]");
    translatableElements.forEach((el) => {
      el.textContent = (lang === "en")
        ? el.getAttribute("data-en")
        : el.getAttribute("data-es");
    });
  }
  // ================================================================
                // Initialize language on load
  // ================================================================
  
  document.body.setAttribute("lang", currentLanguage);
  updateLanguage(currentLanguage);
  // ================================================================
                // Set initial button labels
  // ================================================================
 
  function setLanguageButtonLabels() {
    if (langToggleDesktop) {
      langToggleDesktop.textContent = (currentLanguage === "en") ? "ES" : "EN";
    }
    if (langToggleMobile) {
      const mobileSpan = langToggleMobile.querySelector("span") || langToggleMobile;
      mobileSpan.textContent = (currentLanguage === "en") ? "ES" : "EN";
    }
  }
  setLanguageButtonLabels();
  // ================================================================
                // Toggle function
  // ================================================================
 
  function toggleLanguage() {
    currentLanguage = (currentLanguage === "en") ? "es" : "en";
    localStorage.setItem("language", currentLanguage);
    document.body.setAttribute("lang", currentLanguage);
    updateLanguage(currentLanguage);
    setLanguageButtonLabels();
  }

  // Event listeners for language toggles
  if (langToggleDesktop) {
    langToggleDesktop.addEventListener("click", toggleLanguage);
  }
  if (langToggleMobile) {
    langToggleMobile.addEventListener("click", toggleLanguage);
  }
  // ================================================================
                // THEME TOGGLE (Desktop & Mobile)
  // ================================================================
  
  const themeToggleDesktop = document.getElementById("theme-toggle-desktop");
  const themeToggleMobile  = document.getElementById("theme-toggle-mobile");
  const bodyElement = document.body;
  const savedTheme = localStorage.getItem("theme") || "light";
   // =============================================================
                // Apply the saved theme on load
  // ==============================================================
 
  bodyElement.setAttribute("data-theme", savedTheme);
  
  // Helper to set up a single theme button
  function setupThemeToggle(button) {
    if (!button) return;
  // =============================================================
                // Helper to set up a single theme button
  // ==============================================================
    button.textContent = (savedTheme === "light") ? "Dark" : "Light";
    
    button.addEventListener("click", () => {
      const currentTheme = bodyElement.getAttribute("data-theme");
      if (currentTheme === "light") {
        bodyElement.setAttribute("data-theme", "dark");
        button.textContent = "Light"; // Next possible choice
        localStorage.setItem("theme", "dark");
      } else {
        bodyElement.setAttribute("data-theme", "light");
        button.textContent = "Dark"; // Next possible choice
        localStorage.setItem("theme", "light");
      }
    });
  }
  // =============================================================
                // Initialize desktop & mobile theme toggles
  // ==============================================================

  setupThemeToggle(themeToggleDesktop);
  setupThemeToggle(themeToggleMobile);

  // =============================================================
                // Right-Side Main Menu: Open/Close
  // ==============================================================
  const menuOpenBtn = document.getElementById('menu-open');
  const menuCloseBtn = document.getElementById('menu-close');
  const rightSideMenu = document.getElementById('rightSideMenu');
  
  if (menuOpenBtn && menuCloseBtn && rightSideMenu) {
    menuOpenBtn.addEventListener('click', () => {
      rightSideMenu.classList.add('open');
    });
    menuCloseBtn.addEventListener('click', () => {
      rightSideMenu.classList.remove('open');
    });
  }

  // ================================================================
                // Services Sub-Menu: Slide Up
// ==================================================================
  const servicesTrigger = document.querySelector('.services-trigger button');
  const servicesSubMenu = document.getElementById('servicesSubMenu');
  
  if (servicesTrigger && servicesSubMenu) {
    servicesTrigger.addEventListener('click', (e) => {
      e.stopPropagation();
      servicesSubMenu.classList.toggle('open');
    });
    document.addEventListener('click', (evt) => {
      const clickInsideTrigger = servicesTrigger.contains(evt.target);
      const clickInsideSubMenu = servicesSubMenu.contains(evt.target);
      if (!clickInsideTrigger && !clickInsideSubMenu) {
        servicesSubMenu.classList.remove('open');
      }
    });
  }
  // ================================================================
                // Modals (Join Us & Contact Us)
// ==================================================================

  const modalOverlays = document.querySelectorAll('.modal-overlay');
  const floatingIcons = document.querySelectorAll('.floating-icon');
  const closeModalButtons = document.querySelectorAll('[data-close]');

  // Open modal on floating icon click
  floatingIcons.forEach(icon => {
    icon.addEventListener('click', () => {
      const modalId = icon.getAttribute('data-modal');
      const targetModal = document.getElementById(modalId);
      if (targetModal) {
        targetModal.classList.add('active');
      }
    });
  });

  // Close modal via close button
  closeModalButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const parentModal = btn.closest('.modal-overlay');
      if (parentModal) {
        parentModal.classList.remove('active');
      }
    });
  });
  // ================================================================
                // Close modal on clicking outside or pressing ESC
// ==================================================================
 
  modalOverlays.forEach(overlay => {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) {
        overlay.classList.remove('active');
      }
    });
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        overlay.classList.remove('active');
      }
    });
  }

  // =======================================================================================
  // Sanitize input function Form Submissions: Alert + Reset + Input Sanitization
// =========================================================================================
    function sanitizeInput(input) {
    return input.replace(/<[^>]*>/g, '').trim(); // Basic XSS protection
  }

  // Join Us Form
  const joinForm = document.getElementById('join-form');
  if (joinForm) {
    joinForm.addEventListener('submit', (e) => {
      e.preventDefault();
  // ================================================================
                // Sanitize input fields
// ==================================================================
      const name = sanitizeInput(document.getElementById("join-name").value);
      const email = sanitizeInput(document.getElementById("join-email").value);
      const contact = sanitizeInput(document.getElementById("join-contact").value);
      const comment = sanitizeInput(document.getElementById("join-comment").value);

      console.log("Sanitized Join Form Submission →", { name, email, contact, comment });

      alert('Thank you for joining us! Your information has been safely received.');
      joinForm.reset();
      document.getElementById('join-modal').classList.remove('active');
    });
  }
  // ================================================================
                // Contact Us Form
// ==================================================================
  const contactForm = document.getElementById('contact-form');
  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();

      // Sanitize input fields
      const contactName = sanitizeInput(document.getElementById("contact-name").value);
      const contactEmail = sanitizeInput(document.getElementById("contact-email").value);
      const contactMessage = sanitizeInput(document.getElementById("contact-message").value);

      console.log("Sanitized Contact Form Submission →", { contactName, contactEmail, contactMessage });

      alert('Thank you for contacting us! We will get back to you soon.');
      contactForm.reset();
      document.getElementById('contact-modal').classList.remove('active');
    });
  }

}); 
