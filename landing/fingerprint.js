/**
 * Local-Eye Browser Fingerprint — Drop-in Client
 *
 * Usage:
 *   <script src="https://localeye.co/js/fingerprint.js"></script>
 *   <script>
 *     LocalEyeFP.send({ sourceApp: 'myapp', action: 'free_search' }).then(result => {
 *       console.log(result.fingerprint_hash, result.is_new, result.visit_count);
 *     });
 *   </script>
 *
 * Or check free tier limits:
 *   LocalEyeFP.check({ fingerprintHash: '...', sourceApp: 'myapp', action: 'free_search', limit: 5 })
 *     .then(result => {
 *       if (result.limit_reached) showPaywall();
 *     });
 */

const LOCALEYE_FP_API = 'https://localeye.co';

const LocalEyeFP = {
  _components: null,

  /**
   * Collect browser fingerprint components (no external dependencies).
   * Returns a dict of ~30 signals that uniquely identify this browser.
   */
  async collect() {
    if (this._components) return this._components;

    const components = {};

    // Screen & display
    components.screen_width = screen.width;
    components.screen_height = screen.height;
    components.color_depth = screen.colorDepth;
    components.pixel_ratio = window.devicePixelRatio;

    // Timezone
    components.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    components.timezone_offset = new Date().getTimezoneOffset();

    // Language
    components.language = navigator.language;
    components.languages = (navigator.languages || []).join(',');

    // Platform & hardware
    components.platform = navigator.platform || 'unknown';
    components.hardware_concurrency = navigator.hardwareConcurrency || 0;
    components.max_touch_points = navigator.maxTouchPoints || 0;
    components.device_memory = navigator.deviceMemory || 0;

    // Canvas fingerprint (deterministic across sessions)
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(50, 0, 100, 50);
      ctx.fillStyle = '#069';
      ctx.fillText('Local-Eye 🌐', 2, 15);
      ctx.fillStyle = 'rgba(102,204,0,0.7)';
      ctx.fillText('Local-Eye 🌐', 4, 17);
      components.canvas_hash = await this._hash(canvas.toDataURL());
    } catch (e) {
      components.canvas_hash = 'error';
    }

    // WebGL renderer
    try {
      const gl = document.createElement('canvas').getContext('webgl');
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      components.webgl_vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
      components.webgl_renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';
    } catch (e) {
      components.webgl_vendor = 'unknown';
      components.webgl_renderer = 'unknown';
    }

    // Available fonts (probe common fonts)
    const testFonts = ['Arial', 'Helvetica', 'Times New Roman', 'Courier', 'Georgia',
      'Verdana', 'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Palatino',
      'Lucida Console', 'Monaco', 'Segoe UI', 'Roboto', 'Open Sans'];
    const available = [];
    const testStr = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const body = document.body;
    const span = document.createElement('span');
    span.style.fontSize = testSize;
    span.innerHTML = testStr;
    const defaultWidth = body.appendChild(span).offsetWidth;
    for (const font of testFonts) {
      span.style.fontFamily = font;
      if (span.offsetWidth !== defaultWidth) available.push(font);
    }
    body.removeChild(span);
    components.fonts = available.sort().join(',');

    // Plugins
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
      plugins.push(navigator.plugins[i].name);
    }
    components.plugins = plugins.sort().join(',');

    // User agent (for OS/browser version)
    components.user_agent = navigator.userAgent;

    this._components = components;
    return components;
  },

  /**
   * Hash a string using SHA-256 (SubtleCrypto).
   */
  async _hash(data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Register a fingerprint with the Local-Eye API.
   * Returns { fingerprint_hash, is_new, visit_count, source_app, action_logged }.
   */
  async send(options = {}) {
    const components = await this.collect();
    const sourceApp = options.sourceApp || 'unknown';
    const action = options.action || null;

    try {
      const response = await fetch(`${LOCALEYE_FP_API}/v1/fingerprint`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ components, source_app: sourceApp, action }),
      });

      if (!response.ok) {
        // Fallback: compute hash locally
        const hash = await this._hash(JSON.stringify(components, Object.keys(components).sort()));
        return { fingerprint_hash: hash, is_new: true, visit_count: 1, source_app: sourceApp, action_logged: action, fallback: true };
      }

      return await response.json();
    } catch (e) {
      // Offline fallback: compute hash locally
      const hash = await this._hash(JSON.stringify(components, Object.keys(components).sort()));
      return { fingerprint_hash: hash, is_new: true, visit_count: 1, source_app: sourceApp, action_logged: action, fallback: true };
    }
  },

  /**
   * Check if a fingerprint has exceeded a free-tier limit.
   * Returns { fingerprint_hash, count, limit, remaining, limit_reached }.
   */
  async check(options = {}) {
    const fingerprintHash = options.fingerprintHash;
    if (!fingerprintHash) {
      throw new Error('fingerprintHash required. Call LocalEyeFP.send() first.');
    }

    const sourceApp = options.sourceApp || 'unknown';
    const action = options.action || null;
    const limit = options.limit || 5;

    try {
      const response = await fetch(`${LOCALEYE_FP_API}/v1/fingerprint/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fingerprint_hash: fingerprintHash,
          source_app: sourceApp,
          action,
          limit,
        }),
      });

      if (!response.ok) {
        return { fingerprint_hash: fingerprintHash, count: 0, limit, remaining: limit, limit_reached: false, fallback: true };
      }

      return await response.json();
    } catch (e) {
      return { fingerprint_hash: fingerprintHash, count: 0, limit, remaining: limit, limit_reached: false, fallback: true };
    }
  },

  /**
   * Convenience: register fingerprint + check limit in one call.
   * Returns { fingerprint_hash, is_new, visit_count, count, limit, remaining, limit_reached }.
   */
  async sendAndCheck(options = {}) {
    const result = await this.send({ sourceApp: options.sourceApp, action: options.action });
    const checkResult = await this.check({
      fingerprintHash: result.fingerprint_hash,
      sourceApp: options.sourceApp || 'unknown',
      action: options.action,
      limit: options.limit || 5,
    });
    return { ...result, ...checkResult };
  }
};

// Auto-collect on page load (non-blocking)
if (typeof window !== 'undefined') {
  LocalEyeFP.collect().catch(() => {});
}