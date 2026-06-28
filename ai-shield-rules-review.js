// ai-shield-rules-worker-v3-full.js - 280 RULES (post-approval swap)
var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

var FULL_RULES = [
  { id: 2, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*honeycomb.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 3, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*segment.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 4, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*segment.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 5, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cloudflareinsights*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 6, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*rum.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 7, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*amplitude.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 8, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mixpanel.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 9, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*posthog.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 10, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 11, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*google-analytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 12, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googletagmanager.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 13, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 14, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 18, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*featuregates.org*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 19, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*featureassets.org*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 20, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*assetsconfigcdn.org*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 21, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*prodregistryv2.org*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 22, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*nel.cloudflare.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 23, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*datadoghq.com*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 31, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*facebook.com/tr/*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping", "image"] } },
  { id: 32, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*facebook.com/browser_reporting/*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 34, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*widget.intercom.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 54, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*static.cloudflareinsights.com*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 60, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*gtag/js*", "resourceTypes": ["script"] } },
  { id: 61, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*gtm.js*", "resourceTypes": ["script"] } },
  { id: 62, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mapbox*eventData*", "resourceTypes": ["xmlhttprequest", "other"] } },
  { id: 69, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*sentry.io*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 71, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*launchdarkly.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 72, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*growthbook.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 73, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*fullstory.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 74, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*hotjar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 75, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*logrocket.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 76, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*clarity.ms*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 77, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*newrelic.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 78, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bugsnag.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 79, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*rollbar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 80, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*heapanalytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 81, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*pendo.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 82, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*smartlook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 83, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mouseflow.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 84, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*crazyegg.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 85, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*inspectlet.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 86, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*optimizely.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 87, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*vwo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 90, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*log-sdk*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 91, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*beacon.min.js*", "resourceTypes": ["script"] } },
  { id: 92, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mapbox.com/events*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 93, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*split.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 94, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*appsflyer.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 95, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*branch.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 96, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adjust.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 97, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*singular.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 98, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*kochava.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 99, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*onesignal.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 100, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*braze.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 111, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*__mpq_*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 113, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*www.googletagmanager.com/*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 114, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*google.com/gtag/*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 115, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googletagservices.com*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 116, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*tagmanager.google.com*", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 123, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*ingest.*.sentry.io*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 133, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*easylist-downloads.adblockplus.org*", "resourceTypes": ["xmlhttprequest", "other", "ping"] } },
  { id: 212, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adnexus.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 213, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bidtellect.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 214, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*zenlayer.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 215, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*casalemedia.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 216, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*outbrain.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 217, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adsafeprotected.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 218, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adnxs.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 219, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*xandr.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 220, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mopub.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 221, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*amazon-adsystem.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 222, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adsystem.amazon.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 223, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*rubiconproject.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 224, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*openx.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 225, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*pubmatic.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 306, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||static.xx.fbcdn.net", "resourceTypes": ["image", "script"] } },
  { id: 308, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||l.facebook.com/l.php", "resourceTypes": ["main_frame", "sub_frame"] } },
  { id: 310, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||snippet.maze.co", "resourceTypes": ["script"] } },
  { id: 311, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||app.maze.co", "resourceTypes": ["script", "xmlhttprequest"] } },
  { id: 312, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.maze.co", "resourceTypes": ["xmlhttprequest"] } },
  { id: 313, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||datadoghq.com", "resourceTypes": ["script", "xmlhttprequest", "ping", "other"] } },
  { id: 314, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||browser-intake-datadoghq.com", "resourceTypes": ["xmlhttprequest", "ping", "other"] } },
  { id: 315, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||widget.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "sub_frame", "other"] } },
  { id: 316, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api-iam.intercom.io", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 317, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||intercomassets.com", "resourceTypes": ["script", "image", "font", "other"] } },
  { id: 318, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||qualtrics.com", "resourceTypes": ["sub_frame", "script", "xmlhttprequest", "image", "other"] } },
  { id: 319, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||siteintercept.qualtrics.com", "resourceTypes": ["script", "xmlhttprequest", "other"] } },
  { id: 320, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||pendo.io", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 321, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||mcp.amplitude.com", "resourceTypes": ["xmlhttprequest"] } },
  { id: 323, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.segment.io", "resourceTypes": ["xmlhttprequest", "ping", "other"] } },
  { id: 324, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||cdn.segment.com", "resourceTypes": ["script"] } },
  { id: 325, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.segment.io/v1/identify", "resourceTypes": ["xmlhttprequest", "ping", "other"] } },
  { id: 326, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.segment.io/v1/track", "resourceTypes": ["xmlhttprequest", "ping", "other"] } },
  { id: 327, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.segment.io/v1/page", "resourceTypes": ["xmlhttprequest", "ping", "other"] } },
  { id: 328, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||featuregates.org", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 329, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||statsigapi.net", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 330, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||api.statsig.com", "resourceTypes": ["xmlhttprequest", "other"] } },
  { id: 331, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||cdn.growthbook.io", "resourceTypes": ["script", "xmlhttprequest"] } },
  { id: 332, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||growthbook.io/api", "resourceTypes": ["xmlhttprequest", "script"] } },
  { id: 350, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||googletagmanager.com/gtm.js", "resourceTypes": ["script"] } },
  { id: 403, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "||castle.io", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 404, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*castle.io/v1/risk*", "resourceTypes": ["xmlhttprequest", "other"] } },
  { id: 405, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "ping"] } },
  { id: 406, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*devicer.socure.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 411, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googlesyndication.com*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other"] } },
  { id: 412, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*doubleclick.net*", "resourceTypes": ["xmlhttprequest", "script", "sub_frame", "image", "other", "ping"] } },
  { id: 500, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*byteoversea.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 501, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*tiktokv.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 502, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*tiktokcdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 503, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*douyincdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 504, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*hm.baidu.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 505, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*push.zhanzhang.baidu.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 506, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mtj.baidu.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 507, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*alog.umeng.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 508, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*alog.umengcloud.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 509, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cnzz.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 510, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cnzz.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 511, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*51.la*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 512, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*tanx.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 513, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*alimama.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 514, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*alimama.cn*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 515, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mmstat.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 516, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*atanx.alicdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 517, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*atdmt.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 518, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*acs4baichuan.m.taobao.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 519, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*umeng.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 520, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*uop.umeng.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 521, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mob.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 522, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*sharesdk.cn*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 523, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*io.cn*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 600, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*firebase.google.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 601, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*firebaseio.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 602, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*crashlytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 603, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*app-measurement.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 604, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googleoptimize.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 605, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*googleadservices.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 700, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adsrvr.org*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 701, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adsymptotic.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 702, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*advertising.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 703, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bidswitch.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 704, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bluekai.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 705, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*contextweb.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 706, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*crwdcntrl.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 707, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*demdex.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 708, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*dotomi.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 709, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*doubleverify.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 710, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*exelator.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 711, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*gemius.pl*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 712, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*gumgum.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 713, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*imrworldwide.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 714, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*innovid.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 715, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*krxd.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 716, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*liadm.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 717, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mathtag.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 718, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*media.net*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 719, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*moatads.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 720, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*quantserve.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 721, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*revcontent.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 722, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*rfihub.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 723, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*rlcdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 724, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*scorecardresearch.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 725, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*sharethrough.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 726, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*simpli.fi*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 727, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*smartadserver.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 728, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*spotxchange.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 729, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*taboola.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 730, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*teads.tv*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 731, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*tremorhub.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 732, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*turn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 733, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*verizonmedia.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 734, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*yieldmo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 735, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*zedo.com*", "resourceTypes": ["xmlhttprequest", "script", "other", "image"] } },
  { id: 736, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*33across.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 737, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*acuityplatform.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 738, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*addthis.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 739, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*addthisedge.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 740, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*addtoany.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 741, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adform.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 742, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adition.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 743, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adkernel.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 744, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*admixer.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 745, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adroll.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 800, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*analytics.twitter.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 801, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*static.ads-twitter.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 802, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*ads.linkedin.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 803, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*analytics.linkedin.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 804, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*dc.ads.linkedin.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 805, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*px.ads.linkedin.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 806, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*snap.licdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 807, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*log.pinterest.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 808, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*trk.pinterest.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 809, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*ct.pinterest.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 810, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*widgets.pinterest.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 811, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*events.reddit.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 812, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*ads.reddit.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 813, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*alb.reddit.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 814, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*connect.facebook.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 815, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*graph.facebook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 816, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*an.facebook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 900, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*omtrdc.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 901, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*2o7.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 902, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*everesttech.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 903, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "* demdex.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 904, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adobedtm.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 905, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*adobetag.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 906, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*assets.adobedtm.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 907, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*launch.adobe.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1000, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*browser.sentry-cdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1001, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.mxpnl.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1002, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.heapanalytics.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1003, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.amplitude.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1004, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.logrocket.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1005, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.pendo.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1006, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.hotjar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1007, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.fullstory.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1008, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.braze.eu*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1009, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.onesignal.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1010, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.branch.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1011, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.adjust.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1012, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.appsflyer.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1013, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.optimizely.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1014, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.mouseflow.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1015, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.smartlook.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1016, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.crazyegg.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1017, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.inspectlet.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1018, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.vwo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1019, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.livechatinc.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1020, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.zendesk.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1021, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.zopim.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1022, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*cdn.drift.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1100, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*js.hubspot.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1101, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*forms.hubspot.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1102, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*track.hubspot.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1103, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*api.hubapi.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1104, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*events.hubspot.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1105, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bat.bing.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1106, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*c.bing.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1200, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*analytics.yahoo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1201, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*geo.yahoo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1202, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*udc.yahoo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1203, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*ups.yahoo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1204, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*advertising.yahoo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1300, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*segment-cdn.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1301, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*segmentify.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1302, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*segment.com/v1*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1303, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*customer.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1304, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*clearbit.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1305, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*clearbitjs.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1306, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*6sense.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1307, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*6sc.co*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1308, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*demandbase.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1309, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*zoominfo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1310, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*bizible.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1311, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*marketo.net*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1312, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mktoresp.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1313, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*eloqua.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1314, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*en25.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1315, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*litmus.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1316, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*mailchimp.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1317, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*list-manage.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1318, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*privy.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1319, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*justuno.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1320, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*optinmonster.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1321, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*sumo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1322, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*hello-bar.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1323, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*proof-factor.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1324, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*useproof.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1325, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*fomo.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1326, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*beamer.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1327, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*intergram.xyz*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1328, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*nudgify.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1329, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*convertbox.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1330, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*convertflow.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1331, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*unbounce.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1332, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*instapage.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1333, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*landingi.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1334, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*getresponse.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1335, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*activehosted.com*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
  { id: 1348, priority: 1, action: { "type": "block" }, condition: { "urlFilter": "*plausible.io*", "resourceTypes": ["xmlhttprequest", "script", "other"] } },
];
function generateCanaryRules(licenseKey) {
  let hash = 5381;
  for (let i = 0; i < licenseKey.length; i++) {
    hash = (hash << 5) + hash + licenseKey.charCodeAt(i);
    hash = hash & 2147483647;
  }
  const canaries = [];
  for (let i = 0; i < 3; i++) {
    const canaryHash = (hash * (i + 7) & 2147483647).toString(36);
    canaries.push({
      id: 9e3 + i,
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
__name(generateCanaryRules, "generateCanaryRules");
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
      iterations: 1e5,
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
__name(encryptRules, "encryptRules");
var ALLOWED_ORIGINS = [
  "https://reflexionsoftware.com",
  "https://www.reflexionsoftware.com",
  "https://reflexionsoftware.pages.dev",
  "https://api.reflexionsoftware.com"
];
var LICENSE_KEY_FORMAT = /^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$/;
var RATE_LIMIT = 30;
function getCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const isAllowed = ALLOWED_ORIGINS.includes(origin) || origin.endsWith(".reflexionsoftware.pages.dev") || origin.startsWith("chrome-extension://") || origin.startsWith("moz-extension://");
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Key, X-Extension-ID, X-Timestamp, X-Signature",
    "Content-Type": "application/json",
    "Vary": "Origin"
  };
}
__name(getCorsHeaders, "getCorsHeaders");
function errorResponse(corsHeaders, status, userMessage) {
  return new Response(JSON.stringify({ error: userMessage }), {
    status,
    headers: corsHeaders
  });
}
__name(errorResponse, "errorResponse");
async function checkRateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const minute = Math.floor(Date.now() / 6e4);
  const key = `rl:${ip}:${minute}`;
  const current = parseInt(await env.AI_SHIELD_DATA.get(key)) || 0;
  if (current >= RATE_LIMIT) return false;
  await env.AI_SHIELD_DATA.put(key, String(current + 1), { expirationTtl: 120 });
  return true;
}
__name(checkRateLimit, "checkRateLimit");
var ai_shield_review_worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    if (!await checkRateLimit(request, env)) {
      return errorResponse(corsHeaders, 429, "Too many requests. Please try again later.");
    }
    if ((url.pathname === "/rules" || url.pathname === "/") && (request.method === "GET" || request.method === "POST")) {
      const licenseKey = request.headers.get("X-License-Key");
      if (!licenseKey) {
        return errorResponse(corsHeaders, 401, "License required");
      }
      if (!LICENSE_KEY_FORMAT.test(licenseKey)) {
        return errorResponse(corsHeaders, 401, "Invalid license key");
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
        for (const canary of canaries) {
          const domain = canary.condition.urlFilter.replace("||", "");
          await env.AI_SHIELD_DATA.put(`canary:${domain}`, licenseKey, { expirationTtl: 86400 * 365 });
        }
        return new Response(JSON.stringify({
          ...encrypted,
          rulesCount: watermarkedRules.length,
          lastUpdated: (/* @__PURE__ */ new Date()).toISOString(),
          licenseType: license.type
        }), { headers: corsHeaders });
      } catch (error) {
        console.error("Rules error:", error);
        return errorResponse(corsHeaders, 500, "License verification failed");
      }
    }
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
        stats.lifetimeRemaining = lifetimeRemaining ? parseInt(lifetimeRemaining) : 1e3;
        stats.rulesCount = FULL_RULES.length;
        return new Response(JSON.stringify(stats), { headers: corsHeaders });
      } catch (error) {
        console.error("Stats error:", error);
        return new Response(JSON.stringify({
          totalBlocks: 0,
          activeUsers: 0
        }), { headers: corsHeaders });
      }
    }
    if (url.pathname === "/lifetime-remaining" && request.method === "GET") {
      const remaining = await env.AI_SHIELD_DATA.get("lifetime_slots_remaining");
      return new Response(JSON.stringify({
        remaining: remaining ? parseInt(remaining) : 1e3,
        total: 1e3
      }), { headers: corsHeaders });
    }
    if (url.pathname === "/report-stats" && request.method === "POST") {
      try {
        const statsLicenseKey = request.headers.get("X-License-Key");
        if (!statsLicenseKey) {
          return errorResponse(corsHeaders, 401, "License key required");
        }
        const statsLicense = await env.LICENSES.get(`license:${statsLicenseKey}`);
        if (!statsLicense) {
          return errorResponse(corsHeaders, 401, "Invalid license key");
        }
        const body = await request.json();
        if (!body.extensionId || typeof body.extensionId !== "string" || body.extensionId.length > 40) {
          return errorResponse(corsHeaders, 400, "Invalid extension ID");
        }
        if (body.stats && typeof body.stats.totalBlocked === "number") {
          body.stats.totalBlocked = Math.min(body.stats.totalBlocked, 1e4);
        }
        const { extensionId, stats: extStats } = body;
        if (!extensionId || !extStats) {
          return errorResponse(corsHeaders, 400, "Missing data");
        }
        const extKey = `ext_stats_${extensionId}`;
        await env.AI_SHIELD_DATA.put(extKey, JSON.stringify({
          ...extStats,
          lastReport: Date.now()
        }), { expirationTtl: 9e4 });
        await updateGlobalStats(env, extStats);
        await trackActiveUser(env, extensionId);
        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      } catch (error) {
        console.error("Report stats error:", error);
        return errorResponse(corsHeaders, 500, "Stats reporting failed");
      }
    }
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
  if (Date.now() - globalStats.lastHourReset > 36e5) {
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
__name(updateGlobalStats, "updateGlobalStats");
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
__name(trackActiveUser, "trackActiveUser");
function trackerToPlatform(tracker) {
  const mapping = {
    "Anthropic": "claude",
    "Segment": "claude",
    "Claude": "claude",
    "OpenAI": "chatgpt",
    "Datadog": "chatgpt",
    "ChatGPT": "chatgpt",
    "CES": "chatgpt",
    "xAI": "grok",
    "Statsig": "grok",
    "Honeycomb": "grok",
    "Grok": "grok",
    "Google": "gemini",
    "Gemini": "gemini",
    "Meta": "meta",
    "Facebook": "meta",
    "ByteDance": "deepseek",
    "Moonshot": "deepseek",
    "Kimi": "deepseek",
    "Volc": "deepseek",
    "Baidu": "other",
    "Tencent": "other",
    "NetEase": "other",
    "WeChat": "other"
  };
  for (const [key, platform] of Object.entries(mapping)) {
    if (tracker.includes(key)) return platform;
  }
  return "other";
}
__name(trackerToPlatform, "trackerToPlatform");
addEventListener('fetch', (event) => {
  event.respondWith(ai_shield_review_worker_default.fetch(event.request, event.env || {}));
});

addEventListener('fetch', (event) => {
  event.respondWith(ai_shield_review_worker_default.fetch(event.request, event.env || {}));
});
