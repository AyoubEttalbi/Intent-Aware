"""
qa/page_model.py — extract a compact, LLM-friendly structured model of a rendered
page (forms + fields + buttons + links + headings) with stable selectors so the
executor can act on exactly what the planner reasoned about.
"""
from __future__ import annotations

# Runs in the page. Returns a JSON-able dict describing interactive structure.
_JS_EXTRACT = r"""
() => {
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const txt = (el) => ((el.innerText || el.value || el.textContent || '').trim().slice(0, 80));
  const cssEsc = (s) => (window.CSS && CSS.escape ? CSS.escape(s) : s);
  const attr = (el, a) => { const v = el.getAttribute(a); return v ? v.replace(/"/g, '\\"') : null; };
  // Robust selector chain so component frameworks (React/MUI/Tailwind/shadcn) that
  // render id-less, name-less inputs/buttons remain actionable.
  const sel = (el) => {
    const tag = el.tagName.toLowerCase();
    if (el.id) return '#' + cssEsc(el.id);
    if (attr(el, 'data-testid')) return '[data-testid="' + attr(el, 'data-testid') + '"]';
    if (el.name) return tag + '[name="' + el.name + '"]';
    if (attr(el, 'aria-label')) return tag + '[aria-label="' + attr(el, 'aria-label') + '"]';
    if (attr(el, 'placeholder')) return tag + '[placeholder="' + attr(el, 'placeholder') + '"]';
    if (attr(el, 'type')) return tag + '[type="' + attr(el, 'type') + '"]';
    return null;
  };

  const forms = [...document.querySelectorAll('form')].map((f, i) => {
    const fields = [...f.querySelectorAll('input,select,textarea')]
      .filter(e => e.type !== 'hidden')
      .map((e, j) => ({
        ref: e.id || e.name || (e.placeholder ? ('ph:' + e.placeholder) : ('field' + j)),
        selector: sel(e),
        tag: e.tagName.toLowerCase(),
        type: (e.type || 'text'),
        label: (e.labels && e.labels[0] ? e.labels[0].innerText.trim() : '') ||
               e.getAttribute('aria-label') || '',
        placeholder: e.placeholder || '',
        required: !!e.required,
        maxlength: e.maxLength > 0 ? e.maxLength : null,
        minlength: e.minLength > 0 ? e.minLength : null,
        pattern: e.getAttribute('pattern') || null,
      }));
    // Pick the REAL submit button, not a password-visibility toggle or a
    // secondary action. Prefer explicit submit, then login-intent text, then any
    // non-toggle button. (A login form's first button is often a "show password"
    // eye toggle — clicking that instead of "Sign in" silently breaks auto-login.)
    const TOGGLE = /afficher|masquer|montrer|show|hide|toggle|voir|œil|oeil|\beye\b|mot de passe|reveal/i;
    const SUBMIT = /log\s?in|sign\s?in|connexion|se connecter|connecter|continue|continuer|submit|valider|envoyer|entrer|s'identifier|s'inscrire|next|suivant/i;
    const allBtns = [...f.querySelectorAll('button,[role=button],input[type=submit],input[type=button]')];
    const blabel = (b) => ((b.innerText || b.value || '') + ' ' +
      (b.getAttribute('aria-label') || '') + ' ' + (b.getAttribute('title') || '')).trim();
    const btn = f.querySelector('button[type=submit], input[type=submit]')
      || allBtns.find(b => SUBMIT.test(blabel(b)) && !TOGGLE.test(blabel(b)))
      || allBtns.find(b => !TOGGLE.test(blabel(b)) && (b.getAttribute('type') || 'submit') !== 'button')
      || allBtns.find(b => !TOGGLE.test(blabel(b)))
      || allBtns[0] || null;
    return {
      index: i,
      action: f.getAttribute('action') || '',
      method: (f.getAttribute('method') || 'get').toLowerCase(),
      submit_selector: btn ? sel(btn) : null,
      submit_label: btn ? (txt(btn) || 'Submit') : 'Submit',
      fields,
    };
  });

  const buttons = [...document.querySelectorAll('button,[role=button],input[type=button]')]
    .filter(visible)
    .map((b, i) => ({
      index: i, ref: b.id || txt(b), selector: sel(b),
      text: txt(b), in_form: !!b.closest('form'),
    }))
    .slice(0, 40);

  const links = [...document.querySelectorAll('a[href]')]
    .filter(visible)
    .map((a) => ({ text: txt(a), href: a.href }))
    .filter(l => l.href && !l.href.startsWith('javascript:'))
    .slice(0, 80);

  const headings = [...document.querySelectorAll('h1,h2,h3')]
    .map(h => txt(h)).filter(Boolean).slice(0, 12);

  // Navigation triggered by buttons / JS (not just <a href>): onclick=location=…,
  // data-href, formaction — so SPA / button-driven nav is discoverable too.
  const navHints = [...document.querySelectorAll('[onclick],[data-href],[formaction],[role=button]')]
    .map(el => {
      const oc = el.getAttribute('onclick') || '';
      const m = oc.match(/(?:location(?:\.href)?\s*=\s*|location\.assign\(|window\.open\()\s*['"]([^'"]+)['"]/);
      return el.getAttribute('data-href') || el.getAttribute('formaction') || (m ? m[1] : '');
    })
    .filter(h => h && !h.startsWith('javascript:'))
    .slice(0, 40);

  const bodyText = (document.body ? document.body.innerText : '').replace(/\s+/g, ' ').trim().slice(0, 1500);

  return { url: location.href, title: document.title, headings, text_excerpt: bodyText, forms, buttons, links, nav_hints: navHints };
}
"""


async def extract_page_model(page) -> dict:
    """Return a structured model of the current page (best-effort)."""
    try:
        return await page.evaluate(_JS_EXTRACT)
    except Exception as e:
        return {"url": page.url, "title": "", "headings": [], "text_excerpt": "",
                "forms": [], "buttons": [], "links": [], "error": str(e)}


def form_by_index(model: dict, index: int) -> dict | None:
    for f in model.get("forms", []):
        if f.get("index") == index:
            return f
    return None


def field_selector(form: dict, ref: str) -> str | None:
    """Resolve a field 'ref' (as the planner referenced it) to a CSS selector."""
    for fld in form.get("fields", []):
        if fld.get("ref") == ref or fld.get("selector") == ref:
            return fld.get("selector")
    # planner may have used the placeholder/label text
    for fld in form.get("fields", []):
        if ref and (ref == fld.get("placeholder") or ref == fld.get("label")):
            return fld.get("selector")
    return None
