/* SiteWarden guard: reports which script origins actually run on your pages, plus CSP violations,
   so the agent can alert you when a new (possibly injected) script appears.
   It sends origin + path only (never query strings, cookies or form data), and only for a sample of page views. */
;(function () {
  try {
    var me = document.currentScript
    if (!me || !navigator.sendBeacon) return
    var src = new URL(me.src)
    var site = src.searchParams.get('site')
    if (!site) return
    if (Math.random() >= __SAMPLE__) return

    var endpoint = src.origin + '/r/guard?site=' + encodeURIComponent(site)
    var seen = {}
    var scripts = []
    var violations = []
    var inline = 0
    var sent = false

    function strip(u) {
      try {
        var x = new URL(u, location.href)
        return x.origin + x.pathname
      } catch (e) {
        return ''
      }
    }
    function note(el) {
      if (!el || el.tagName !== 'SCRIPT') return
      if (!el.src) {
        inline++
        return
      }
      var s = strip(el.src)
      if (s && !seen[s] && scripts.length < 100) {
        seen[s] = 1
        scripts.push(s)
      }
    }

    var all = document.getElementsByTagName('script')
    for (var i = 0; i < all.length; i++) note(all[i])

    new MutationObserver(function (list) {
      for (var i = 0; i < list.length; i++) {
        var added = list[i].addedNodes
        for (var j = 0; j < added.length; j++) note(added[j])
      }
    }).observe(document.documentElement, { childList: true, subtree: true })

    document.addEventListener('securitypolicyviolation', function (e) {
      if (violations.length < 20) {
        violations.push({ d: e.effectiveDirective || e.violatedDirective, b: e.blockedURI ? strip(e.blockedURI) || e.blockedURI : '' })
      }
    })

    function send() {
      if (sent) return
      sent = true
      var body = JSON.stringify({ page: location.pathname, scripts: scripts, inline: inline, violations: violations })
      navigator.sendBeacon(endpoint, new Blob([body], { type: 'text/plain' }))
    }
    document.addEventListener('visibilitychange', function () {
      if (document.visibilityState === 'hidden') send()
    })
    setTimeout(send, 15000)
  } catch (e) {
    // never break the host page
  }
})()
