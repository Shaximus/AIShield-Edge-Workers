// AI Shield Rules + Stats Worker
// Security hardened: CORS whitelist, error sanitization, rate limiting, key format validation
// Returns rules ONLY with valid license - extension is useless without this
// Verifies licenses directly from LICENSES KV (no worker-to-worker fetch)

// RULES ARE INJECTED AT BUILD TIME FROM rules/blocklist.json
// Run: bash build.sh (or bash sync-rules.sh) to update
// DO NOT edit rules here - edit blocklist.json instead
const FULL_RULES = [
  { id: 1, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*statsig.anthropic.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 2, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*honeycomb.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 3, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*segment.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 4, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*segment.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 5, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*cloudflareinsights*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 6, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rum.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 7, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*amplitude.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 8, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mixpanel.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 9, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*posthog.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 10, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 11, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google-analytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 12, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googletagmanager.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 13, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 14, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 16, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/v1/traces*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 17, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/api/log_metric*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 18, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*featuregates.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 19, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*featureassets.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 20, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*assetsconfigcdn.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 21, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*prodregistryv2.org*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 22, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*nel.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 23, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*datadoghq.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 24, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ces/v1/t*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 25, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ces/statsc/flush*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 26, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*ab.chatgpt.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 27, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*csp.withgoogle.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 28, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ajax/bz*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 29, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ajax/relay-ef/*", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 30, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ajax/abra_error_reports/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 31, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*facebook.com/tr/*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping", "image"]} },
  { id: 32, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*facebook.com/browser_reporting/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 33, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*play.google.com/log*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 34, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*widget.intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 35, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*ogads-pa.clients6.google.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 36, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*waa-pa.clients6.google.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 37, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gator.volces.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 38, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-api.anthropic.com/v1/t*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 39, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-api.anthropic.com/v1/i*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 40, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-api.anthropic.com/v1/p*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 41, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-api.anthropic.com/v1/m*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 42, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*amplitude-plugins*", "resourceTypes": ["script", "other"]} },
  { id: 43, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google-ec-plugins*", "resourceTypes": ["script", "other"]} },
  { id: 44, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*reddit-plugins*", "resourceTypes": ["script", "other"]} },
  { id: 45, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*s-cdn.anthropic.com/s.js*", "resourceTypes": ["script"]} },
  { id: 46, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*realtime.chatgpt.com*", "resourceTypes": ["xmlhttprequest", "websocket", "other"]} },
  { id: 47, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*signaler-pa.clients6.google.com*", "resourceTypes": ["xmlhttprequest", "other", "ping", "websocket"]} },
  { id: 48, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*grok.com/_data/v1/events*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 49, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*res.wx.qq.com*", "resourceTypes": ["script", "other"]} },
  { id: 50, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/ces/v1/m*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 51, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gemini.google.com/_/BardChatUi/cspreport/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 52, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/sentry*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 53, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-api.anthropic.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 54, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*static.cloudflareinsights.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 55, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*grok.com/monitoring*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 56, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hmcdn.baidu.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 57, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hm.baidu.com*", "resourceTypes": ["script", "xmlhttprequest", "other", "ping"]} },
  { id: 58, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*volccdn.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 59, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*cstaticdun.126.net*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 60, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gtag/js*", "resourceTypes": ["script"]} },
  { id: 61, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gtm.js*", "resourceTypes": ["script"]} },
  { id: 62, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mapbox*eventData*", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 63, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gstatic.com/faviconV2*", "resourceTypes": ["image", "xmlhttprequest", "other"]} },
  { id: 64, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*gstatic.com*favicon*", "resourceTypes": ["image", "xmlhttprequest", "other"]} },
  { id: 65, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*s-cdn.anthropic.com/images/*", "resourceTypes": ["image", "other", "ping", "xmlhttprequest"]} },
  { id: 66, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-cdn.anthropic.com/*plugins*", "resourceTypes": ["script", "other"]} },
  { id: 67, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a.claude.ai/isolated-segment*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 68, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*claude.ai/sentry*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 69, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*sentry.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 71, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*launchdarkly.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 72, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*growthbook.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 73, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*fullstory.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 74, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hotjar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 75, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*logrocket.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 76, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*clarity.ms*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 77, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*newrelic.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 78, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*bugsnag.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 79, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rollbar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 80, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*heapanalytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 81, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*pendo.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 82, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*smartlook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 83, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mouseflow.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 84, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*crazyegg.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 85, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*inspectlet.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 86, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*optimizely.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 87, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*vwo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 88, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*lf3-data.volccdn.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 89, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*browser_reporting*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 90, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*log-sdk*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 91, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*beacon.min.js*", "resourceTypes": ["script"]} },
  { id: 92, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mapbox.com/events*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 93, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*split.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 94, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*appsflyer.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 95, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*branch.io*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 96, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adjust.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 97, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*singular.net*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 98, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*kochava.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 99, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*onesignal.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 100, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*braze.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 101, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*s-cdn.anthropic.com*", "resourceTypes": ["image", "script", "xmlhttprequest", "other", "ping"]} },
  { id: 102, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*a-cdn.anthropic.com*", "resourceTypes": ["image", "script", "xmlhttprequest", "other", "ping"]} },
  { id: 103, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*.gif?*ui=*", "resourceTypes": ["image", "other", "ping"]} },
  { id: 104, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*?*fad=*", "resourceTypes": ["image", "xmlhttprequest", "other", "ping"]} },
  { id: 105, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*?*fvch=*", "resourceTypes": ["image", "xmlhttprequest", "other", "ping"]} },
  { id: 106, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google.com/s2/favicons*", "resourceTypes": ["image", "xmlhttprequest", "other"]} },
  { id: 107, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google.com*favicon*domain=*", "resourceTypes": ["image", "xmlhttprequest", "other"]} },
  { id: 108, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*use_time_based_playback_tracking*", "resourceTypes": ["websocket", "xmlhttprequest", "other"]} },
  { id: 109, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*grok*.x.ai/ws/*tracking*", "resourceTypes": ["websocket", "xmlhttprequest", "other"]} },
  { id: 110, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*stream_audio*tracking*", "resourceTypes": ["websocket", "xmlhttprequest", "other"]} },
  { id: 111, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*__mpq_*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 112, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*xai-ff-bu*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 113, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*www.googletagmanager.com/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 114, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google.com/gtag/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 115, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googletagservices.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 116, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*tagmanager.google.com*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 117, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*youtube.com/youtubei/v1/player/heartbeat*", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 118, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*youtube.com/youtubei/v1/log_event*", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 119, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*youtube.com/ptracking*", "resourceTypes": ["xmlhttprequest", "ping", "other", "image"]} },
  { id: 120, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*clients4.google.com/chrome-sync/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 121, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*optimizationguide-pa.googleapis.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 122, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*safebrowsing.google.com/safebrowsing/clientreport*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 123, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*ingest.*.sentry.io*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 124, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*clientservices.googleapis.com/chrome-variations*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 125, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*content-autofill.googleapis.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 126, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*oauthaccountmanager.googleapis.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"], "excludedInitiatorDomains": ["kimi.com", "www.kimi.com", "moonshot.cn"]} },
  { id: 127, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*statsig.anthropic.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 128, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/api/web/domain_info*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 129, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/api/oauth/spotlight*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 130, priority: 2, action: {"type": "block"}, condition: {"urlFilter": "*/api/event_logging*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 131, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*youtube.com/api/stats/*", "resourceTypes": ["xmlhttprequest", "ping", "other", "image"]} },
  { id: 132, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*youtube.com/youtubei/v1/feedback*", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 133, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*easylist-downloads.adblockplus.org*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 200, priority: 10, action: {"type": "allow"}, condition: {"urlFilter": "*accounts.google.com*", "initiatorDomains": ["kimi.com", "www.kimi.com", "moonshot.cn"], "resourceTypes": ["sub_frame", "xmlhttprequest", "script", "other"]} },
  { id: 201, priority: 10, action: {"type": "allow"}, condition: {"urlFilter": "*volccdn.com*", "initiatorDomains": ["kimi.com", "www.kimi.com", "moonshot.cn"], "resourceTypes": ["script", "stylesheet", "image", "xmlhttprequest", "other", "sub_frame"]} },
  { id: 202, priority: 10, action: {"type": "allow"}, condition: {"urlFilter": "*cstaticdun.126.net*", "initiatorDomains": ["kimi.com", "www.kimi.com", "moonshot.cn"], "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 203, priority: 10, action: {"type": "allow"}, condition: {"urlFilter": "*oauthaccountmanager.googleapis.com*", "initiatorDomains": ["kimi.com", "www.kimi.com", "moonshot.cn"], "resourceTypes": ["xmlhttprequest", "other", "sub_frame"]} },
  { id: 204, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*lf3-data.volccdn.com/obj/data-static/log-sdk/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 205, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*apm.volccdn.com/mars-web/apmplus/*", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 206, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*apmplus.volces.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 207, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*tab.volces.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 208, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hif-dliq.deepseek.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 209, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*hif-leim.deepseek.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 210, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rangers.volces.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 211, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*tobapplog.volces.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 212, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adnexus.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 213, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*bidtellect.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 214, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*zenlayer.net*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 215, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*casalemedia.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 216, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*outbrain.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 217, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adsafeprotected.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 218, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adnxs.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 219, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*xandr.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 220, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*mopub.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 221, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*amazon-adsystem.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 222, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*adsystem.amazon.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 223, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*rubiconproject.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 224, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*openx.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 225, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*pubmatic.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"]} },
  { id: 226, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||claude.ai/_next/image*google.com*favicons*", "resourceTypes": ["image"]} },
  { id: 227, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||claude.ai/_next/image*s2*favicons*", "resourceTypes": ["image"]} },
  { id: 228, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||www.google.com/s2/favicons", "resourceTypes": ["image"]} },
  { id: 300, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/api/analytics", "resourceTypes": ["xmlhttprequest"]} },
  { id: 301, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/monitoring", "resourceTypes": ["xmlhttprequest"]} },
  { id: 302, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/_vercel/insights", "resourceTypes": ["xmlhttprequest", "script"]} },
  { id: 303, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/_vercel/speed-insights", "resourceTypes": ["xmlhttprequest", "script"]} },
  { id: 304, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/api/metaconfig/exposure", "resourceTypes": ["xmlhttprequest"]} },
  { id: 305, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/api/snapl", "resourceTypes": ["xmlhttprequest"]} },
  { id: 306, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||static.xx.fbcdn.net", "resourceTypes": ["image", "script"]} },
  { id: 307, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||meta.ai/api/cookies/upgrade", "resourceTypes": ["xmlhttprequest"]} },
  { id: 308, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||l.facebook.com/l.php", "resourceTypes": ["main_frame", "sub_frame"]} },
  { id: 309, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||claude.ai/sentry", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 310, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||snippet.maze.co", "resourceTypes": ["script"]} },
  { id: 311, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||app.maze.co", "resourceTypes": ["script", "xmlhttprequest"]} },
  { id: 312, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.maze.co", "resourceTypes": ["xmlhttprequest"]} },
  { id: 313, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||datadoghq.com", "resourceTypes": ["script", "xmlhttprequest", "ping", "other"]} },
  { id: 314, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||browser-intake-datadoghq.com", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 315, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||widget.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "sub_frame", "other"]} },
  { id: 316, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api-iam.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 317, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||intercomassets.com", "resourceTypes": ["script", "image", "font", "other"]} },
  { id: 318, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||qualtrics.com", "resourceTypes": ["sub_frame", "script", "xmlhttprequest", "image", "other"]} },
  { id: 319, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||siteintercept.qualtrics.com", "resourceTypes": ["script", "xmlhttprequest", "other"]} },
  { id: 320, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||pendo.io", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 321, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.amplitude.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 322, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||s-cdn.anthropic.com/s.js", "resourceTypes": ["script"]} },
  { id: 323, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 324, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||cdn.segment.com", "resourceTypes": ["script"]} },
  { id: 325, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/identify", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 326, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/track", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 327, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.segment.io/v1/page", "resourceTypes": ["xmlhttprequest", "ping", "other"]} },
  { id: 328, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||featuregates.org", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 329, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||statsigapi.net", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 330, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.statsig.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 331, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||cdn.growthbook.io", "resourceTypes": ["script", "xmlhttprequest"]} },
  { id: 332, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||growthbook.io/api", "resourceTypes": ["xmlhttprequest", "script"]} },
  { id: 333, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.deepsense.ai", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 334, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.dice.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 335, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.lastminute.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 336, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.blockscout.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 337, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.crypto.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 338, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.kiwi.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 339, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.trivago.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 340, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||pubmed.mcp.claude.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 341, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.benevity.org", "resourceTypes": ["xmlhttprequest"]} },
  { id: 342, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.mermaidchart.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 343, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||kg.mcp.learningcommons.org", "resourceTypes": ["xmlhttprequest"]} },
  { id: 344, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.hubspot.com/anthropic", "resourceTypes": ["xmlhttprequest"]} },
  { id: 345, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.indeed.com/claude", "resourceTypes": ["xmlhttprequest"]} },
  { id: 346, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||mcp.zoominfo.com", "resourceTypes": ["xmlhttprequest"]} },
  { id: 347, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||day.ai/api/mcp", "resourceTypes": ["xmlhttprequest"]} },
  { id: 348, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.fireflies.ai/mcp", "resourceTypes": ["xmlhttprequest"]} },
  { id: 349, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||accounts.google.com/gsi", "resourceTypes": ["script", "sub_frame", "xmlhttprequest"]} },
  { id: 350, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||googletagmanager.com/gtm.js", "resourceTypes": ["script"]} },
  { id: 351, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||pay.link.com", "resourceTypes": ["script", "sub_frame", "xmlhttprequest"], "excludedInitiatorDomains": ["buy.stripe.com", "checkout.stripe.com", "stripe.com", "reflexionsoftware.com"]} },
  { id: 353, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.healthex.io", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 354, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||api.demo.healthex.dev", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 355, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||services.functionhealth.com", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 400, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*grok.com/_data/v1/a/t/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 401, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*grok.com/_data/v1/a/engage/*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 402, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||proxsee.pscp.tv", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 403, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "||castle.io", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 404, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*castle.io/v1/risk*", "resourceTypes": ["xmlhttprequest", "other"]} },
  { id: 405, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"]} },
  { id: 406, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*devicer.socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other"]} },
  { id: 407, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*x.com/i/api/1.1/jot*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 408, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*x.com/i/api/1.1/user_flow*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 409, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*x.com/i/api/2/client_event*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 410, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*google.com/gsi/log*", "resourceTypes": ["xmlhttprequest", "other", "ping"]} },
  { id: 411, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other"]} },
  { id: 412, priority: 1, action: {"type": "block"}, condition: {"urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other", "ping"]} },
  { id: 1001, priority: 2, action: {"type": "modifyHeaders", "requestHeaders": [{"header": "x-client-data", "operation": "remove"}, {"header": "sec-ch-ua", "operation": "remove"}, {"header": "sec-ch-ua-mobile", "operation": "remove"}, {"header": "sec-ch-ua-platform", "operation": "remove"}, {"header": "sec-ch-ua-platform-version", "operation": "remove"}, {"header": "sec-ch-ua-arch", "operation": "remove"}, {"header": "sec-ch-ua-bitness", "operation": "remove"}, {"header": "sec-ch-ua-full-version", "operation": "remove"}, {"header": "sec-ch-ua-full-version-list", "operation": "remove"}, {"header": "sec-ch-ua-model", "operation": "remove"}, {"header": "sec-ch-ua-wow64", "operation": "remove"}]}, condition: {"urlFilter": "*://*.google.com/*", "resourceTypes": ["xmlhttprequest", "script", "main_frame", "sub_frame", "image", "font", "media", "other"]} },
  { id: 1002, priority: 2, action: {"type": "modifyHeaders", "requestHeaders": [{"header": "x-client-data", "operation": "remove"}, {"header": "sec-ch-ua", "operation": "remove"}, {"header": "sec-ch-ua-mobile", "operation": "remove"}, {"header": "sec-ch-ua-platform", "operation": "remove"}, {"header": "sec-ch-ua-platform-version", "operation": "remove"}, {"header": "sec-ch-ua-arch", "operation": "remove"}, {"header": "sec-ch-ua-bitness", "operation": "remove"}, {"header": "sec-ch-ua-full-version", "operation": "remove"}, {"header": "sec-ch-ua-full-version-list", "operation": "remove"}, {"header": "sec-ch-ua-model", "operation": "remove"}, {"header": "sec-ch-ua-wow64", "operation": "remove"}]}, condition: {"urlFilter": "*://*.googleapis.com/*", "resourceTypes": ["xmlhttprequest", "script", "main_frame", "sub_frame", "image", "font", "media", "other"]} },
  { id: 1003, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.google-analytics.com/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} },
  { id: 1004, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.googletagmanager.com/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} },
  { id: 1005, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.doubleclick.net/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} },
  { id: 1006, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.googlesyndication.com/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} },
  { id: 1007, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.facebook.com/tr/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} },
  { id: 1008, priority: 2, action: {"type": "modifyHeaders", "responseHeaders": [{"header": "set-cookie", "operation": "remove"}]}, condition: {"urlFilter": "*://*.facebook.com/browser_reporting/*", "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "script", "image", "other"]} }
];

function generateCanaryRules(licenseKey) {
  let hash = 5381;
  for (let i = 0; i < licenseKey.length; i++) {
    hash = ((hash << 5) + hash) + licenseKey.charCodeAt(i);
    hash = hash & 0x7FFFFFFF;
  }

  const canaries = [];
  for (let i = 0; i < 3; i++) {
    const canaryHash = ((hash * (i + 7)) & 0x7FFFFFFF).toString(36);
    canaries.push({
      id: 9000 + i,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: `||canary-${canaryHash}.reflexionsoftware.com`,
        resourceTypes: ["xmlhttprequest"]
      }
    });
  }

  return canaries;
}

async function encryptRules(rules, licenseKey, ruleSalt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(licenseKey + ruleSalt),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode("ai-shield-rules-v1"),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(JSON.stringify(rules))
  );

  return {
    payload: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    version: "2.0"
  };
}

const ALLOWED_ORIGINS = [
  'https://reflexionsoftware.com',
  'https://www.reflexionsoftware.com',
  'https://reflexionsoftware.pages.dev',
  'https://api.reflexionsoftware.com'
];

const LICENSE_KEY_FORMAT = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;

const RATE_LIMIT = 30;

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const isAllowed = ALLOWED_ORIGINS.includes(origin) ||
    origin.endsWith('.reflexionsoftware.pages.dev') ||
    origin.startsWith('chrome-extension://') ||
    origin.startsWith('moz-extension://');
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Key, X-Extension-ID, X-Timestamp, X-Signature",
    "Content-Type": "application/json",
    "Vary": "Origin"
  };
}

function errorResponse(corsHeaders, status, userMessage) {
  return new Response(JSON.stringify({ error: userMessage }), {
    status, headers: corsHeaders
  });
}

async function checkRateLimit(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const minute = Math.floor(Date.now() / 60000);
  const key = `rl:${ip}:${minute}`;

  const current = parseInt(await env.AI_SHIELD_DATA.get(key)) || 0;
  if (current >= RATE_LIMIT) return false;

  await env.AI_SHIELD_DATA.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (!await checkRateLimit(request, env)) {
      return errorResponse(corsHeaders, 429, "Too many requests. Please try again later.");
    }

    // === RULES ENDPOINT - REQUIRES VALID LICENSE + HMAC SIGNATURE ===
    if ((url.pathname === "/rules" || url.pathname === "/") && (request.method === "GET" || request.method === "POST")) {
      const licenseKey = request.headers.get("X-License-Key");

      if (!licenseKey) {
        return errorResponse(corsHeaders, 401, "License required");
      }

      if (!LICENSE_KEY_FORMAT.test(licenseKey)) {
        return errorResponse(corsHeaders, 401, "Invalid license key");
      }

      // HMAC signature verification (H-02)
      const timestamp = request.headers.get("X-Timestamp");
      const signature = request.headers.get("X-Signature");
      const extensionId = request.headers.get("X-Extension-ID");

      if (!timestamp || !signature || !extensionId) {
        return errorResponse(corsHeaders, 403, "Missing request signature");
      }

      // Reject if timestamp is more than 60 seconds old (anti-replay)
      const requestAge = Date.now() - parseInt(timestamp, 10);
      if (isNaN(requestAge) || requestAge > 60000 || requestAge < -5000) {
        return errorResponse(corsHeaders, 403, "Request expired");
      }

      // Recompute HMAC and compare
      const message = `${timestamp}:${licenseKey}:${extensionId}`;
      const encoder = new TextEncoder();
      const hmacKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(licenseKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );
      const signatureBytes = new Uint8Array(signature.match(/.{2}/g).map(b => parseInt(b, 16)));
      const valid = await crypto.subtle.verify(
        'HMAC',
        hmacKey,
        signatureBytes,
        encoder.encode(message)
      );
      if (!valid) {
        return errorResponse(corsHeaders, 403, "Invalid request signature");
      }

      try {
        const license = await env.LICENSES.get(licenseKey, "json");

        if (!license) {
          return errorResponse(corsHeaders, 403, "License key not found");
        }

        const now = Date.now();
        if (license.type !== "lifetime" && license.expiresAt && license.expiresAt < now) {
          return new Response(JSON.stringify({
            error: "License expired",
            renewUrl: "https://reflexionsoftware.com/#pricing"
          }), { status: 402, headers: corsHeaders });
        }

        const ruleSalt = license.ruleSalt;
        if (!ruleSalt) {
          return new Response(JSON.stringify({ error: "Please verify license first", code: "VERIFY_FIRST" }), { status: 403, headers: corsHeaders });
        }

        const canaries = generateCanaryRules(licenseKey);
        const watermarkedRules = [...FULL_RULES, ...canaries];
        const encrypted = await encryptRules(watermarkedRules, licenseKey, ruleSalt);
        // Store canary mapping for leak detection
        for (const canary of canaries) {
          const domain = canary.condition.urlFilter.replace('||', '');
          await env.AI_SHIELD_DATA.put(`canary:${domain}`, licenseKey, { expirationTtl: 86400 * 365 });
        }
        return new Response(JSON.stringify({
          ...encrypted,
          ruleSalt: ruleSalt,
          rulesCount: watermarkedRules.length,
          lastUpdated: new Date().toISOString(),
          licenseType: license.type
        }), { headers: corsHeaders });

      } catch (error) {
        console.error("Rules error:", error);
        return errorResponse(corsHeaders, 500, "License verification failed");
      }
    }

    // === PUBLIC: Get live stats for website ===
    if (url.pathname === "/live-stats" && request.method === "GET") {
      try {
        const statsJson = await env.AI_SHIELD_DATA.get("global_stats");
        const stats = statsJson ? JSON.parse(statsJson) : {
          totalBlocks: 0,
          activeUsers: 0,
          hourlyBlocks: 0,
          platforms: {}
        };

        const activeCountJson = await env.AI_SHIELD_DATA.get("active_users_count");
        stats.activeUsers = activeCountJson ? parseInt(activeCountJson) : 0;

        const lifetimeRemaining = await env.AI_SHIELD_DATA.get("lifetime_slots_remaining");
        stats.lifetimeRemaining = lifetimeRemaining ? parseInt(lifetimeRemaining) : 1000;
        stats.rulesCount = FULL_RULES.length;

        return new Response(JSON.stringify(stats), { headers: corsHeaders });
      } catch (error) {
        console.error("Stats error:", error);
        return new Response(JSON.stringify({
          totalBlocks: 0, activeUsers: 0
        }), { headers: corsHeaders });
      }
    }

    // === PUBLIC: Get lifetime slots remaining ===
    if (url.pathname === "/lifetime-remaining" && request.method === "GET") {
      const remaining = await env.AI_SHIELD_DATA.get("lifetime_slots_remaining");
      return new Response(JSON.stringify({
        remaining: remaining ? parseInt(remaining) : 1000,
        total: 1000
      }), { headers: corsHeaders });
    }

    // === EXTENSION: Report stats (requires valid license - H-03) ===
    if (url.pathname === "/report-stats" && request.method === "POST") {
      try {
        // Authenticate: require valid license key (H-03)
        const licenseKey = request.headers.get("X-License-Key");
        if (!licenseKey || !LICENSE_KEY_FORMAT.test(licenseKey)) {
          return errorResponse(corsHeaders, 401, "License required for stats reporting");
        }

        const license = await env.LICENSES.get(licenseKey, "json");
        if (!license) {
          return errorResponse(corsHeaders, 401, "Invalid license key");
        }

        // License must be active (not expired)
        if (license.type !== "lifetime" && license.expiresAt && license.expiresAt < Date.now()) {
          return errorResponse(corsHeaders, 401, "License expired");
        }

        const body = await request.json();

        if (!body.extensionId || typeof body.extensionId !== 'string' || body.extensionId.length > 40) {
          return errorResponse(corsHeaders, 400, "Invalid extension ID");
        }

        if (body.stats && typeof body.stats.totalBlocked === 'number') {
          body.stats.totalBlocked = Math.min(body.stats.totalBlocked, 10000);
        }

        const { extensionId, stats: extStats } = body;

        if (!extensionId || !extStats) {
          return errorResponse(corsHeaders, 400, "Missing data");
        }

        const extKey = `ext_stats_${extensionId}`;
        await env.AI_SHIELD_DATA.put(extKey, JSON.stringify({
          ...extStats,
          lastReport: Date.now()
        }), { expirationTtl: 90000 });

        await updateGlobalStats(env, extStats);
        await trackActiveUser(env, extensionId);

        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      } catch (error) {
        console.error("Report stats error:", error);
        return errorResponse(corsHeaders, 500, "Stats reporting failed");
      }
    }

    // === ADMIN: Set lifetime slots ===
    if (url.pathname === "/admin/set-slots" && request.method === "POST") {
      const authKey = request.headers.get("X-Admin-Key");
      if (!env.ADMIN_KEY || !authKey || authKey !== env.ADMIN_KEY) {
        return errorResponse(corsHeaders, 401, "Unauthorized");
      }

      const body = await request.json();
      await env.AI_SHIELD_DATA.put("lifetime_slots_remaining", body.slots.toString());
      return new Response(JSON.stringify({ success: true, slots: body.slots }), { headers: corsHeaders });
    }

    return errorResponse(corsHeaders, 404, "Not found");
  }
};

async function updateGlobalStats(env, extStats) {
  const statsJson = await env.AI_SHIELD_DATA.get("global_stats");
  let globalStats = statsJson ? JSON.parse(statsJson) : {
    totalBlocks: 0,
    hourlyBlocks: 0,
    platforms: {},
    lastHourReset: Date.now()
  };

  const blocksToAdd = extStats.totalBlocked || 0;
  globalStats.totalBlocks += blocksToAdd;
  globalStats.hourlyBlocks += blocksToAdd;

  if (Date.now() - globalStats.lastHourReset > 3600000) {
    globalStats.hourlyBlocks = blocksToAdd;
    globalStats.lastHourReset = Date.now();
  }

  if (extStats.blockedByDomain) {
    for (const [tracker, count] of Object.entries(extStats.blockedByDomain)) {
      const platform = trackerToPlatform(tracker);
      if (!globalStats.platforms[platform]) globalStats.platforms[platform] = 0;
      globalStats.platforms[platform] += count;
    }
  }

  await env.AI_SHIELD_DATA.put("global_stats", JSON.stringify(globalStats));
}

async function trackActiveUser(env, extensionId) {
  const activeKey = `active_${extensionId}`;
  const existing = await env.AI_SHIELD_DATA.get(activeKey);

  if (!existing) {
    const countJson = await env.AI_SHIELD_DATA.get("active_users_count");
    const count = countJson ? parseInt(countJson) : 0;
    await env.AI_SHIELD_DATA.put("active_users_count", (count + 1).toString());
  }

  await env.AI_SHIELD_DATA.put(activeKey, Date.now().toString(), { expirationTtl: 86400 });
}

function trackerToPlatform(tracker) {
  const mapping = {
    'Anthropic': 'claude', 'Segment': 'claude', 'Claude': 'claude',
    'OpenAI': 'chatgpt', 'Datadog': 'chatgpt', 'ChatGPT': 'chatgpt', 'CES': 'chatgpt',
    'xAI': 'grok', 'Statsig': 'grok', 'Honeycomb': 'grok', 'Grok': 'grok',
    'Google': 'gemini', 'Gemini': 'gemini',
    'Meta': 'meta', 'Facebook': 'meta',
    'ByteDance': 'deepseek', 'Moonshot': 'deepseek', 'Kimi': 'deepseek', 'Volc': 'deepseek',
    'Baidu': 'other', 'Tencent': 'other', 'NetEase': 'other', 'WeChat': 'other'
  };
  for (const [key, platform] of Object.entries(mapping)) {
    if (tracker.includes(key)) return platform;
  }
  return 'other';
}
