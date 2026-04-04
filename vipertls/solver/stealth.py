import json


def build_stealth_script(identity: dict[str, object]) -> str:
    data = json.dumps(identity, separators=(",", ":"))
    return f"""
(function () {{
  const __vipertls = {data};

  Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});

  window.chrome = {{
    runtime: {{
      connect: () => {{}},
      sendMessage: () => {{}},
      onMessage: {{ addListener: () => {{}}, removeListener: () => {{}} }},
      onConnect: {{ addListener: () => {{}}, removeListener: () => {{}} }},
      PlatformOs: {{ MAC:'mac', WIN:'win', ANDROID:'android', CROS:'cros', LINUX:'linux' }},
      PlatformArch: {{ ARM:'arm', X86_32:'x86-32', X86_64:'x86-64' }},
      RequestUpdateCheckStatus: {{ THROTTLED:'throttled', NO_UPDATE:'no_update', UPDATE_AVAILABLE:'update_available' }},
      OnInstalledReason: {{ INSTALL:'install', UPDATE:'update', CHROME_UPDATE:'chrome_update' }},
    }},
    loadTimes: function() {{
      return {{
        requestTime: performance.timing.requestStart / 1000,
        startLoadTime: performance.timing.navigationStart / 1000,
        commitLoadTime: performance.timing.responseStart / 1000,
        finishDocumentLoadTime: performance.timing.domContentLoadedEventEnd / 1000,
        finishLoadTime: performance.timing.loadEventEnd / 1000,
        firstPaintTime: 0,
        firstPaintAfterLoadTime: 0,
        navigationType: 'Other',
        wasFetchedViaSpdy: true,
        wasNpnNegotiated: true,
        npnNegotiatedProtocol: 'h2',
        wasAlternateProtocolAvailable: false,
        connectionInfo: 'h2',
      }};
    }},
    csi: function() {{
      return {{
        startE: performance.timing.navigationStart,
        onloadT: performance.timing.loadEventEnd,
        pageT: performance.now(),
        tran: 15,
      }};
    }},
    app: {{ isInstalled: false }},
  }};

  const _plugins = [
    {{ name: 'PDF Viewer',                filename: 'internal-pdf-viewer', description: 'Portable Document Format', mimeTypes: [{{ type: 'application/pdf', suffixes: 'pdf', description: '' }}] }},
    {{ name: 'Chrome PDF Viewer',         filename: 'internal-pdf-viewer', description: '', mimeTypes: [{{ type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' }}] }},
    {{ name: 'Chromium PDF Viewer',       filename: 'internal-pdf-viewer', description: '', mimeTypes: [] }},
    {{ name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: '', mimeTypes: [] }},
    {{ name: 'WebKit built-in PDF',       filename: 'internal-pdf-viewer', description: '', mimeTypes: [] }},
  ];
  const pluginArr = [];
  _plugins.forEach((p, i) => {{
    const plugin = {{ name: p.name, filename: p.filename, description: p.description, length: p.mimeTypes.length }};
    p.mimeTypes.forEach((m, j) => {{ plugin[j] = m; }});
    pluginArr[i] = plugin;
    pluginArr[p.name] = plugin;
  }});
  pluginArr.length = _plugins.length;
  Object.defineProperty(navigator, 'plugins', {{ get: () => pluginArr }});

  const _mimes = [
    {{ type: 'application/pdf', suffixes: 'pdf', description: '', enabledPlugin: pluginArr[0] }},
    {{ type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format', enabledPlugin: pluginArr[1] }},
  ];
  const mimeArr = [];
  _mimes.forEach((m, i) => {{ mimeArr[i] = m; mimeArr[m.type] = m; }});
  mimeArr.length = _mimes.length;
  Object.defineProperty(navigator, 'mimeTypes', {{ get: () => mimeArr }});

  Object.defineProperty(navigator, 'languages', {{ get: () => ['en-US', 'en'] }});
  Object.defineProperty(navigator, 'language', {{ get: () => 'en-US' }});
  Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => 8 }});
  Object.defineProperty(navigator, 'deviceMemory', {{ get: () => 8 }});
  Object.defineProperty(navigator, 'platform', {{ get: () => 'Win32' }});

  if (navigator.userAgentData) {{
    const brands = __vipertls.brands || [];
    const fullVersionList = __vipertls.fullVersionList || brands.map((b) => {{
      return {{ brand: b.brand, version: (__vipertls.uaFullVersion || b.version || '0.0.0.0') }};
    }});
    Object.defineProperty(navigator, 'userAgentData', {{
      get: () => ({{
        brands,
        mobile: false,
        platform: 'Windows',
        getHighEntropyValues: () => Promise.resolve({{
          brands,
          mobile: false,
          platform: 'Windows',
          platformVersion: __vipertls.platformVersion || '10.0.0',
          architecture: 'x86',
          bitness: '64',
          model: '',
          uaFullVersion: __vipertls.uaFullVersion || '0.0.0.0',
          fullVersionList,
        }}),
      }}),
    }});
  }}

  try {{
    const _origQuery = window.Permissions.prototype.query;
    window.Permissions.prototype.query = function(params) {{
      if (params && params.name === 'notifications') {{
        return Promise.resolve({{ state: Notification.permission, onchange: null }});
      }}
      return _origQuery.call(this, params);
    }};
  }} catch(_) {{}}

  try {{
    const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function(type) {{
      const ctx = this.getContext('2d');
      if (ctx) {{
        const d = ctx.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < d.data.length; i += 200) {{ d.data[i] ^= 1; }}
        ctx.putImageData(d, 0, 0);
      }}
      return _origToDataURL.apply(this, arguments);
    }};
  }} catch(_) {{}}

  try {{
    const _gp = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(p) {{
      if (p === 37445) return 'Google Inc. (Intel)';
      if (p === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)';
      return _gp.call(this, p);
    }};
  }} catch(_) {{}}

  try {{
    const _gp2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(p) {{
      if (p === 37445) return 'Google Inc. (Intel)';
      if (p === 37446) return 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)';
      return _gp2.call(this, p);
    }};
  }} catch(_) {{}}

  Object.defineProperty(screen, 'width',       {{ get: () => 1920 }});
  Object.defineProperty(screen, 'height',      {{ get: () => 1080 }});
  Object.defineProperty(screen, 'availWidth',  {{ get: () => 1920 }});
  Object.defineProperty(screen, 'availHeight', {{ get: () => 1040 }});
  Object.defineProperty(screen, 'colorDepth',  {{ get: () => 24 }});
  Object.defineProperty(screen, 'pixelDepth',  {{ get: () => 24 }});

  try {{ delete navigator.__proto__.webdriver; }} catch(_) {{}}
  try {{ delete window.cdc_adoQpoasnfa76pfcZLmcfl_; }} catch(_) {{}}

  try {{
    Object.defineProperty(navigator, 'connection', {{
      get: () => ({{ rtt: 50, downlink: 10, effectiveType: '4g', saveData: false, onchange: null }}),
    }});
  }} catch(_) {{}}
}})();
"""


STEALTH_SCRIPT = build_stealth_script(
    {
        "brands": [
            {"brand": "Google Chrome", "version": "145"},
            {"brand": "Chromium", "version": "145"},
            {"brand": "Not_A Brand", "version": "24"},
        ],
        "fullVersionList": [
            {"brand": "Google Chrome", "version": "145.0.0.0"},
            {"brand": "Chromium", "version": "145.0.0.0"},
            {"brand": "Not_A Brand", "version": "24.0.0.0"},
        ],
        "platformVersion": "10.0.0",
        "uaFullVersion": "145.0.0.0",
    }
)
