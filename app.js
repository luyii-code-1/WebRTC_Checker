"use strict";

const STUN_SERVERS = [{ urls: "stun:stun.l.google.com:19302" }];
const ICE_GATHERING_TIMEOUT_MS = 4500;
const HTTP_TIMEOUT_MS = 8000;

let currentReport = null;
let copyResetTimer = null;

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  $("startButton").addEventListener("click", runDetection);
  $("resetButton").addEventListener("click", runDetection);
  $("copyButton").addEventListener("click", copyReport);
  resetUI();
});

async function runDetection() {
  clearErrors();
  currentReport = null;
  renderEmptyState();
  setLoading(true);

  let httpInfo = null;
  let httpError = null;
  let rtcResult = null;

  try {
    httpInfo = await getHttpInfo();
  } catch (error) {
    httpError = normalizeError(error);
    showError(`HTTP 出口信息获取失败：${httpError}`);
  }

  try {
    rtcResult = await collectWebRTCCandidates();
    if (rtcResult.error) {
      showError(rtcResult.error);
    }
  } catch (error) {
    rtcResult = {
      available: false,
      rawCandidates: [],
      candidateErrors: [],
      elapsedMs: 0,
      error: normalizeError(error)
    };
    showError(`WebRTC 检测失败：${rtcResult.error}`);
  }

  currentReport = buildReport(httpInfo, rtcResult, { httpError });
  renderReport(currentReport);
  setLoading(false);
}

async function getHttpInfo() {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);

  try {
    const response = await fetch("/api/ip", {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      headers: {
        Accept: "application/json"
      },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`/api/ip 返回 HTTP ${response.status}`);
    }

    return await response.json();
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function collectWebRTCCandidates() {
  const PeerConnection =
    window.RTCPeerConnection ||
    window.webkitRTCPeerConnection ||
    window.mozRTCPeerConnection;

  if (!PeerConnection) {
    return {
      available: false,
      rawCandidates: [],
      candidateErrors: [],
      elapsedMs: 0,
      error: "当前浏览器不支持 RTCPeerConnection，无法进行 WebRTC ICE candidate 检测。"
    };
  }

  const startedAt = performance.now();
  const rawCandidates = [];
  const seenCandidates = new Set();
  const candidateErrors = [];
  let pc = null;
  let dataChannel = null;

  return new Promise(async (resolve, reject) => {
    let finished = false;
    const timeoutId = window.setTimeout(() => finish(), ICE_GATHERING_TIMEOUT_MS);

    const closeConnection = () => {
      try {
        if (dataChannel && dataChannel.readyState !== "closed") {
          dataChannel.close();
        }
      } catch (_) {
        // Closing a transient DataChannel can fail harmlessly in some browsers.
      }

      try {
        if (pc && pc.signalingState !== "closed") {
          pc.close();
        }
      } catch (_) {
        // The peer connection may already be closed by the browser.
      }
    };

    const addCandidate = (candidate) => {
      const raw = candidate && candidate.candidate ? candidate.candidate : "";
      if (!raw || seenCandidates.has(raw)) {
        return;
      }
      seenCandidates.add(raw);
      rawCandidates.push(raw);
    };

    function finish() {
      if (finished) {
        return;
      }
      finished = true;
      window.clearTimeout(timeoutId);
      closeConnection();
      resolve({
        available: true,
        rawCandidates,
        candidateErrors,
        elapsedMs: Math.round(performance.now() - startedAt)
      });
    }

    try {
      pc = new PeerConnection({
        iceServers: STUN_SERVERS,
        iceCandidatePoolSize: 0
      });

      pc.onicecandidate = (event) => {
        if (event.candidate) {
          addCandidate(event.candidate);
        } else {
          finish();
        }
      };

      pc.onicecandidateerror = (event) => {
        candidateErrors.push({
          url: event.url || null,
          errorCode: event.errorCode || null,
          errorText: event.errorText || null
        });
      };

      pc.onicegatheringstatechange = () => {
        if (pc && pc.iceGatheringState === "complete") {
          finish();
        }
      };

      dataChannel = pc.createDataChannel("webrtc-ip-leak-checker");
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
    } catch (error) {
      window.clearTimeout(timeoutId);
      closeConnection();
      reject(error);
    }
  });
}

function parseCandidate(rawCandidate) {
  const raw = String(rawCandidate || "").trim();
  const normalized = raw.replace(/^a=/i, "").replace(/^candidate:/i, "");
  const parts = normalized.split(/\s+/).filter(Boolean);

  const candidate = {
    raw,
    foundation: parts[0] || null,
    component: parseInteger(parts[1]),
    protocol: parts[2] ? parts[2].toLowerCase() : null,
    priority: parseInteger(parts[3]),
    address: parts[4] || null,
    port: parseInteger(parts[5]),
    type: null,
    relatedAddress: null,
    relatedPort: null,
    tcpType: null,
    isMdns: false,
    isIPv4: false,
    isIPv6: false,
    isPrivate: false,
    isPublic: false,
    isLoopback: false,
    isLinkLocal: false
  };

  for (let index = 6; index < parts.length; index += 1) {
    const key = parts[index].toLowerCase();
    const value = parts[index + 1] || null;

    if (key === "typ") {
      candidate.type = value ? value.toLowerCase() : null;
      index += 1;
    } else if (key === "raddr") {
      candidate.relatedAddress = value;
      index += 1;
    } else if (key === "rport") {
      candidate.relatedPort = parseInteger(value);
      index += 1;
    } else if (key === "tcptype") {
      candidate.tcpType = value ? value.toLowerCase() : null;
      index += 1;
    }
  }

  return {
    ...candidate,
    ...classifyAddress(candidate.address)
  };
}

function classifyAddress(address) {
  const value = normalizeAddress(address);
  const lower = value.toLowerCase();
  const isMdns = lower.endsWith(".local");
  const ipv4Octets = parseIPv4Octets(lower);
  const ipv6Bytes = ipv4Octets ? null : parseIPv6ToBytes(lower);

  const isIPv4 = Boolean(ipv4Octets);
  const isIPv6 = Boolean(ipv6Bytes);
  let isPrivate = false;
  let isLoopback = false;
  let isLinkLocal = false;

  if (ipv4Octets) {
    const [first, second] = ipv4Octets;
    isLoopback = first === 127;
    isLinkLocal = first === 169 && second === 254;
    isPrivate =
      first === 10 ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      isLinkLocal ||
      isLoopback;
  }

  if (ipv6Bytes) {
    isLoopback = ipv6Bytes.slice(0, 15).every((byte) => byte === 0) && ipv6Bytes[15] === 1;
    isLinkLocal = ipv6Bytes[0] === 0xfe && (ipv6Bytes[1] & 0xc0) === 0x80;
    const isUniqueLocal = (ipv6Bytes[0] & 0xfe) === 0xfc;
    isPrivate = isUniqueLocal || isLinkLocal || isLoopback;
  }

  return {
    isMdns,
    isIPv4,
    isIPv6,
    isPrivate,
    isPublic: (isIPv4 || isIPv6) && !isPrivate && !isLoopback && !isLinkLocal && !isMdns,
    isLoopback,
    isLinkLocal
  };
}

function evaluateRisk(httpInfo, candidates) {
  const httpIp = normalizeIpForCompare(httpInfo && httpInfo.ip);
  const publicCandidates = candidates.filter((candidate) => candidate.isPublic);
  const nonRelayPublicCandidates = publicCandidates.filter((candidate) => candidate.type !== "relay");
  const srflxPublicCandidates = candidates.filter(
    (candidate) => candidate.type === "srflx" && candidate.isPublic
  );
  const privateHostCandidates = candidates.filter(
    (candidate) => candidate.type === "host" && candidate.isPrivate && !candidate.isMdns
  );
  const mdnsHostCandidates = candidates.filter(
    (candidate) => candidate.type === "host" && candidate.isMdns
  );
  const srflxPublicIps = uniqueStrings(srflxPublicCandidates.map((candidate) => candidate.address));
  const mismatchedSrflxIps = httpIp
    ? srflxPublicIps.filter((ip) => normalizeIpForCompare(ip) !== httpIp)
    : [];

  const suggestions = [
    "Chrome / Edge：检查 VPN 是否防止 WebRTC 泄露。",
    "Chrome / Edge：可使用 WebRTC Leak Protection / WebRTC Network Limiter 类扩展。",
    "Chrome / Edge：检查代理是否覆盖 UDP / WebRTC。",
    "Firefox：检查 about:config 中的 WebRTC 相关设置。",
    "Firefox：可根据需求关闭 media.peerconnection.enabled。",
    "Brave：设置 → 隐私与安全 → WebRTC IP Handling Policy。",
    "Brave：建议限制非代理 UDP。",
    "通用：更换可信 VPN、禁用浏览器 WebRTC、使用更严格的浏览器隐私设置，并重新运行检测确认。"
  ];

  if (mismatchedSrflxIps.length > 0) {
    return {
      level: "high",
      label: "高风险",
      description: "WebRTC 公网出口与 HTTP 出口不一致，可能存在代理/VPN/WebRTC 泄露风险。",
      reasons: [
        `HTTP 出口 IP：${httpInfo && httpInfo.ip ? httpInfo.ip : "未提供"}`,
        `WebRTC srflx 公网 IP：${srflxPublicIps.join(", ")}`,
        `与 HTTP 出口不一致的 srflx IP：${mismatchedSrflxIps.join(", ")}`
      ],
      suggestions
    };
  }

  if (privateHostCandidates.length > 0) {
    return {
      level: "medium",
      label: "中风险",
      description: "WebRTC 暴露了本地私网地址。",
      reasons: [
        `发现 ${privateHostCandidates.length} 个私网 host candidate。`,
        `私网地址：${uniqueStrings(privateHostCandidates.map((candidate) => candidate.address)).join(", ")}`
      ],
      suggestions
    };
  }

  if (srflxPublicCandidates.length > 0 && !httpIp) {
    return {
      level: "medium",
      label: "中风险",
      description: "发现 WebRTC srflx 公网出口，但 HTTP 出口 IP 不可用，无法判断两者是否一致。",
      reasons: [
        `WebRTC srflx 公网 IP：${srflxPublicIps.join(", ")}`,
        "HTTP 出口信息获取失败或缺失。"
      ],
      suggestions
    };
  }

  if (nonRelayPublicCandidates.length > 0 && srflxPublicIps.some((ip) => normalizeIpForCompare(ip) === httpIp)) {
    return {
      level: "low",
      label: "低风险",
      description: "WebRTC srflx 公网出口与 HTTP 出口一致，未发现明显 WebRTC IP 泄露。",
      reasons: [
        `HTTP 出口 IP：${httpInfo && httpInfo.ip ? httpInfo.ip : "未提供"}`,
        `WebRTC srflx 公网 IP：${srflxPublicIps.join(", ")}`
      ],
      suggestions
    };
  }

  if (nonRelayPublicCandidates.length > 0) {
    return {
      level: "medium",
      label: "中风险",
      description: "发现 WebRTC 公网 candidate，但未发现与 HTTP 出口不一致的 srflx 证据。",
      reasons: [
        `WebRTC 公网 candidate 数量：${nonRelayPublicCandidates.length}`,
        "请结合 VPN、代理和浏览器设置复查网络出口。"
      ],
      suggestions
    };
  }

  if (mdnsHostCandidates.length > 0) {
    return {
      level: "medium-low",
      label: "中低风险",
      description: "浏览器通过 mDNS 隐藏了本地地址。",
      reasons: [
        `发现 ${mdnsHostCandidates.length} 个 mDNS .local host candidate。`,
        "未发现直接暴露私网 IP。",
        "未发现与 HTTP 出口不一致的 srflx 公网 IP。"
      ],
      suggestions
    };
  }

  const relayCandidates = candidates.filter((candidate) => candidate.type === "relay");
  const lowReasons = [];
  if (publicCandidates.length === 0) {
    lowReasons.push("没有发现公网 WebRTC candidate。");
  }
  if (publicCandidates.length > 0 && relayCandidates.length === publicCandidates.length) {
    lowReasons.push("只发现 relay candidate。");
  }
  if (candidates.length === 0) {
    lowReasons.push("未收集到 WebRTC candidate。");
  }
  lowReasons.push("未发现明显 WebRTC IP 泄露。");

  return {
    level: "low",
    label: "低风险",
    description: "未发现明显 WebRTC IP 泄露。",
    reasons: lowReasons,
    suggestions
  };
}

function buildReport(httpInfo, rtcResult, options = {}) {
  const parsedCandidates = (rtcResult && rtcResult.rawCandidates ? rtcResult.rawCandidates : [])
    .map(parseCandidate)
    .filter((candidate) => candidate.raw);
  const summary = summarizeCandidates(parsedCandidates, rtcResult);
  const stun = buildStunCheck(parsedCandidates, rtcResult);
  const ipGroups = buildIpGroups(httpInfo, parsedCandidates);
  const risk = evaluateRisk(httpInfo, parsedCandidates);

  return {
    meta: {
      project: "webrtc-ip-leak-checker",
      generatedAt: new Date().toISOString(),
      note: "本报告只用于检测 WebRTC 可能暴露的网络出口信息；srflx IP 不一定等于真实家庭宽带 IP。"
    },
    http: httpInfo,
    httpError: options.httpError || null,
    webrtc: {
      available: Boolean(rtcResult && rtcResult.available),
      stunServers: STUN_SERVERS.map((server) => server.urls),
      elapsedMs: rtcResult && Number.isFinite(rtcResult.elapsedMs) ? rtcResult.elapsedMs : null,
      error: (rtcResult && rtcResult.error) || null,
      candidateErrors: (rtcResult && rtcResult.candidateErrors) || [],
      stun,
      summary,
      ipGroups,
      candidates: parsedCandidates
    },
    risk
  };
}

function renderReport(report) {
  renderHttpInfo(report);
  renderStunInfo(report);
  renderCandidateSummary(report);
  renderIpGroups(report.webrtc.ipGroups);
  renderRisk(report.risk);
  renderCandidates(report.webrtc.candidates);
  $("jsonReport").textContent = JSON.stringify(report, null, 2);
  $("candidatesDetails").open = false;
  $("jsonDetails").open = false;
}

async function copyReport() {
  if (!currentReport) {
    return;
  }

  const text = JSON.stringify(currentReport, null, 2);
  const button = $("copyButton");

  try {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
      } catch (_) {
        fallbackCopy(text);
      }
    } else {
      fallbackCopy(text);
    }
    button.textContent = "已复制";
    window.clearTimeout(copyResetTimer);
    copyResetTimer = window.setTimeout(() => {
      button.textContent = "复制 JSON 报告";
    }, 1800);
  } catch (error) {
    showError(`复制失败：${normalizeError(error)}`);
  }
}

function resetUI() {
  currentReport = null;
  clearErrors();
  setLoading(false);
  renderEmptyState();
  $("candidatesDetails").open = false;
  $("jsonDetails").open = false;
}

function setLoading(isLoading) {
  $("loadingBox").hidden = !isLoading;
  $("startButton").disabled = isLoading;
  $("resetButton").disabled = isLoading || !currentReport;
  $("copyButton").disabled = isLoading || !currentReport;
  $("startButton").textContent = isLoading ? "检测中..." : "开始检测";
}

function showError(message) {
  const container = $("errorMessage");
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  container.appendChild(paragraph);
  container.hidden = false;
}

function renderEmptyState() {
  renderKeyValueList($("httpInfo"), [
    ["HTTP 出口 IP", null],
    ["User-Agent", null],
    ["国家/地区", null],
    ["ASN", null],
    ["AS Organization", null],
    ["Cloudflare Colo", null],
    ["City", null],
    ["Region", null],
    ["Timezone", null],
    ["HTTP Protocol", null],
    ["TLS Version", null]
  ]);

  renderKeyValueList($("stunInfo"), [
    ["STUN 服务器", STUN_SERVERS.map((server) => server.urls).join(", ")],
    ["STUN 检测状态", "未检测"],
    ["是否获得 srflx", null],
    ["srflx 公网出口数量", 0],
    ["srflx 公网出口", null],
    ["ICE 错误数量", 0],
    ["检测耗时", null],
    ["说明", "点击“开始检测”后执行 STUN 检测。"]
  ]);

  renderKeyValueList($("candidateSummary"), [
    ["WebRTC 是否可用", null],
    ["总 candidate 数量", 0],
    ["host candidate 数量", 0],
    ["srflx candidate 数量", 0],
    ["relay candidate 数量", 0],
    ["prflx candidate 数量", 0],
    ["IPv4 数量", 0],
    ["IPv6 数量", 0],
    ["私网地址数量", 0],
    ["公网地址数量", 0],
    ['mDNS ".local" 数量', 0],
    ["relay 数量", 0]
  ]);

  renderIpGroups({
    http: [],
    webrtcPublic: [],
    webrtcPrivate: [],
    webrtcIPv6: [],
    mdns: [],
    relay: []
  });

  renderRisk({
    level: "",
    label: "未检测",
    description: "点击“开始检测”后生成风险说明。",
    reasons: [],
    suggestions: []
  });

  $("candidateList").innerHTML = '<p class="muted">尚未检测。</p>';
  $("jsonReport").textContent = "{}";
  $("copyButton").textContent = "复制 JSON 报告";
}

function renderHttpInfo(report) {
  const http = report.http || {};
  renderKeyValueList($("httpInfo"), [
    ["HTTP 出口 IP", http.ip],
    ["User-Agent", http.userAgent],
    ["国家/地区", http.country],
    ["ASN", http.asn],
    ["AS Organization", http.asOrganization],
    ["Cloudflare Colo", http.colo],
    ["City", http.city],
    ["Region", http.region],
    ["Timezone", http.timezone],
    ["HTTP Protocol", http.httpProtocol],
    ["TLS Version", http.tlsVersion],
    ["Timestamp", http.timestamp]
  ]);
}

function renderStunInfo(report) {
  const stun = report.webrtc.stun;
  renderKeyValueList($("stunInfo"), [
    ["STUN 服务器", stun.servers.join(", ")],
    ["STUN 检测状态", stun.label],
    ["是否获得 srflx", stun.hasSrflx ? "是" : "否"],
    ["srflx 公网出口数量", stun.publicSrflxCount],
    ["srflx 公网出口", stun.publicSrflxIps.length ? stun.publicSrflxIps.join(", ") : null],
    ["ICE 错误数量", stun.errorCount],
    ["检测耗时", stun.elapsedMs === null ? null : `${stun.elapsedMs} ms`],
    ["说明", stun.description]
  ]);
}

function renderCandidateSummary(report) {
  const summary = report.webrtc.summary;
  renderKeyValueList($("candidateSummary"), [
    ["WebRTC 是否可用", summary.available ? "是" : "否"],
    ["总 candidate 数量", summary.total],
    ["host candidate 数量", summary.host],
    ["srflx candidate 数量", summary.srflx],
    ["relay candidate 数量", summary.relay],
    ["prflx candidate 数量", summary.prflx],
    ["IPv4 数量", summary.ipv4],
    ["IPv6 数量", summary.ipv6],
    ["私网地址数量", summary.private],
    ["公网地址数量", summary.public],
    ['mDNS ".local" 数量', summary.mdns],
    ["relay 数量", summary.relay],
    ["收集耗时", summary.elapsedMs === null ? null : `${summary.elapsedMs} ms`]
  ]);
}

function renderIpGroups(groups) {
  const definitions = [
    ["HTTP IP", groups.http],
    ["WebRTC 公网 IP", groups.webrtcPublic],
    ["WebRTC 私网 IP", groups.webrtcPrivate],
    ["WebRTC IPv6", groups.webrtcIPv6],
    ["mDNS candidate", groups.mdns],
    ["relay candidate", groups.relay]
  ];

  $("ipGroups").innerHTML = definitions
    .map(([title, items]) => {
      const safeItems = Array.isArray(items) ? items : [];
      const body = safeItems.length
        ? `<ul class="ip-list">${safeItems.map(renderIpItem).join("")}</ul>`
        : '<p class="muted">未发现</p>';

      return `
        <section class="ip-group">
          <h3>${escapeHtml(title)} <span class="count-pill">${safeItems.length}</span></h3>
          ${body}
        </section>
      `;
    })
    .join("");
}

function renderRisk(risk) {
  const card = $("riskCard");
  const badge = $("riskBadge");
  card.className = `card risk-card${risk.level ? ` risk-${risk.level}` : ""}`;
  badge.className = `risk-badge${risk.level ? ` risk-${risk.level}` : ""}`;
  badge.textContent = risk.label || "未检测";
  $("riskDescription").textContent = risk.description || "点击“开始检测”后生成风险说明。";
  renderList($("riskReasons"), risk.reasons || [], "暂无。");
  renderList($("riskSuggestions"), risk.suggestions || [], "暂无。");
}

function renderCandidates(candidates) {
  const container = $("candidateList");
  if (!candidates.length) {
    container.innerHTML = '<p class="muted">未收集到 candidate。</p>';
    return;
  }

  container.innerHTML = candidates
    .map((candidate, index) => {
      const fields = [
        ["type", candidate.type],
        ["protocol", candidate.protocol],
        ["address", candidate.address],
        ["port", candidate.port],
        ["foundation", candidate.foundation],
        ["component", candidate.component],
        ["priority", candidate.priority],
        ["relatedAddress", candidate.relatedAddress],
        ["relatedPort", candidate.relatedPort],
        ["tcpType", candidate.tcpType],
        ["是否 mDNS", yesNo(candidate.isMdns)],
        ["是否 IPv4", yesNo(candidate.isIPv4)],
        ["是否 IPv6", yesNo(candidate.isIPv6)],
        ["是否私网", yesNo(candidate.isPrivate)],
        ["是否公网", yesNo(candidate.isPublic)],
        ["是否回环", yesNo(candidate.isLoopback)],
        ["是否链路本地", yesNo(candidate.isLinkLocal)]
      ];

      return `
        <article class="candidate-item">
          <h3>
            Candidate ${index + 1}
            ${candidate.type ? `<span class="tag">${escapeHtml(candidate.type)}</span>` : ""}
            ${candidate.protocol ? `<span class="tag">${escapeHtml(candidate.protocol)}</span>` : ""}
          </h3>
          <dl class="kv-grid">
            ${fields
              .map(
                ([label, value]) => `
                  <div class="kv-row">
                    <dt>${escapeHtml(label)}</dt>
                    <dd>${formatValue(value)}</dd>
                  </div>
                `
              )
              .join("")}
          </dl>
          <pre class="candidate-raw">${escapeHtml(candidate.raw)}</pre>
        </article>
      `;
    })
    .join("");
}

function renderKeyValueList(container, rows) {
  container.innerHTML = rows
    .map(
      ([label, value]) => `
        <div class="kv-row">
          <dt>${escapeHtml(label)}</dt>
          <dd>${formatValue(value)}</dd>
        </div>
      `
    )
    .join("");
}

function renderList(container, items, emptyText) {
  container.innerHTML = items.length
    ? items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")
    : `<li class="muted">${escapeHtml(emptyText)}</li>`;
}

function renderIpItem(item) {
  const endpoint = item.port ? `${item.address}:${item.port}` : item.address;
  const meta = [item.type, item.protocol, item.note].filter(Boolean).join(" / ");
  return `
    <li>
      <span class="mono">${formatValue(endpoint)}</span>
      ${meta ? `<span class="item-meta">${escapeHtml(meta)}</span>` : ""}
    </li>
  `;
}

function summarizeCandidates(candidates, rtcResult) {
  return {
    available: Boolean(rtcResult && rtcResult.available),
    total: candidates.length,
    host: countBy(candidates, (candidate) => candidate.type === "host"),
    srflx: countBy(candidates, (candidate) => candidate.type === "srflx"),
    relay: countBy(candidates, (candidate) => candidate.type === "relay"),
    prflx: countBy(candidates, (candidate) => candidate.type === "prflx"),
    ipv4: countBy(candidates, (candidate) => candidate.isIPv4),
    ipv6: countBy(candidates, (candidate) => candidate.isIPv6),
    private: countBy(candidates, (candidate) => candidate.isPrivate),
    public: countBy(candidates, (candidate) => candidate.isPublic),
    mdns: countBy(candidates, (candidate) => candidate.isMdns),
    elapsedMs: rtcResult && Number.isFinite(rtcResult.elapsedMs) ? rtcResult.elapsedMs : null
  };
}

function buildIpGroups(httpInfo, candidates) {
  return {
    http: httpInfo && httpInfo.ip ? [{ address: httpInfo.ip, type: "http", note: "HTTP 出口" }] : [],
    webrtcPublic: uniqueCandidateItems(
      candidates.filter((candidate) => candidate.isPublic && candidate.type !== "relay")
    ),
    webrtcPrivate: uniqueCandidateItems(
      candidates.filter((candidate) => candidate.isPrivate && !candidate.isMdns)
    ),
    webrtcIPv6: uniqueCandidateItems(candidates.filter((candidate) => candidate.isIPv6)),
    mdns: uniqueCandidateItems(candidates.filter((candidate) => candidate.isMdns)),
    relay: uniqueCandidateItems(candidates.filter((candidate) => candidate.type === "relay"))
  };
}

function buildStunCheck(candidates, rtcResult) {
  const available = Boolean(rtcResult && rtcResult.available);
  const errors = (rtcResult && rtcResult.candidateErrors) || [];
  const srflxCandidates = candidates.filter((candidate) => candidate.type === "srflx");
  const publicSrflxIps = uniqueStrings(
    srflxCandidates
      .filter((candidate) => candidate.isPublic)
      .map((candidate) => candidate.address)
  );
  const elapsedMs = rtcResult && Number.isFinite(rtcResult.elapsedMs) ? rtcResult.elapsedMs : null;

  if (!available) {
    return {
      status: "unsupported",
      label: "WebRTC 不可用",
      description: (rtcResult && rtcResult.error) || "当前浏览器不支持 RTCPeerConnection，无法执行 STUN 检测。",
      servers: STUN_SERVERS.map((server) => server.urls),
      hasSrflx: false,
      srflxCount: 0,
      publicSrflxCount: 0,
      publicSrflxIps,
      errorCount: errors.length,
      errors,
      elapsedMs
    };
  }

  if (publicSrflxIps.length > 0) {
    return {
      status: "ok",
      label: "STUN 可用，已获得 srflx",
      description: "STUN 返回了 srflx candidate，说明浏览器可通过 WebRTC 看到一个或多个网络出口。",
      servers: STUN_SERVERS.map((server) => server.urls),
      hasSrflx: true,
      srflxCount: srflxCandidates.length,
      publicSrflxCount: publicSrflxIps.length,
      publicSrflxIps,
      errorCount: errors.length,
      errors,
      elapsedMs
    };
  }

  if (srflxCandidates.length > 0) {
    return {
      status: "partial",
      label: "STUN 有响应，但未识别公网 srflx",
      description: "检测到了 srflx candidate，但地址未被识别为公网出口；可能受浏览器、网络策略或地址类型影响。",
      servers: STUN_SERVERS.map((server) => server.urls),
      hasSrflx: true,
      srflxCount: srflxCandidates.length,
      publicSrflxCount: 0,
      publicSrflxIps,
      errorCount: errors.length,
      errors,
      elapsedMs
    };
  }

  if (errors.length > 0) {
    return {
      status: "error",
      label: "STUN 可能不可达",
      description: "WebRTC ICE 收集过程中出现错误，可能是 STUN 被网络、代理、VPN 或浏览器策略拦截。",
      servers: STUN_SERVERS.map((server) => server.urls),
      hasSrflx: false,
      srflxCount: 0,
      publicSrflxCount: 0,
      publicSrflxIps,
      errorCount: errors.length,
      errors,
      elapsedMs
    };
  }

  return {
    status: "no-srflx",
    label: "未获得 srflx",
    description: "未从 STUN 获得 srflx candidate；可能是浏览器隐私策略、VPN/代理限制 UDP，或当前网络未暴露可见的 STUN 出口。",
    servers: STUN_SERVERS.map((server) => server.urls),
    hasSrflx: false,
    srflxCount: 0,
    publicSrflxCount: 0,
    publicSrflxIps,
    errorCount: 0,
    errors,
    elapsedMs
  };
}

function uniqueCandidateItems(candidates) {
  const seen = new Set();
  const items = [];

  candidates.forEach((candidate) => {
    const key = [
      candidate.address || "",
      candidate.port || "",
      candidate.type || "",
      candidate.protocol || ""
    ].join("|");
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    items.push({
      address: candidate.address || "未知地址",
      port: candidate.port,
      type: candidate.type,
      protocol: candidate.protocol
    });
  });

  return items;
}

function parseIPv4Octets(value) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) {
    return null;
  }

  const octets = value.split(".").map((part) => Number(part));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return null;
  }

  return octets;
}

function parseIPv6ToBytes(value) {
  let address = value.toLowerCase().split("%")[0];
  if (!address.includes(":") || /[^0-9a-f:.]/i.test(address)) {
    return null;
  }

  if (address.includes(".")) {
    const lastColonIndex = address.lastIndexOf(":");
    const ipv4Part = address.slice(lastColonIndex + 1);
    const octets = parseIPv4Octets(ipv4Part);
    if (!octets) {
      return null;
    }
    const firstGroup = ((octets[0] << 8) | octets[1]).toString(16);
    const secondGroup = ((octets[2] << 8) | octets[3]).toString(16);
    address = `${address.slice(0, lastColonIndex + 1)}${firstGroup}:${secondGroup}`;
  }

  const doubleColonParts = address.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const left = doubleColonParts[0] ? doubleColonParts[0].split(":") : [];
  const right = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(":") : [];
  if (left.concat(right).some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
    return null;
  }

  const missingGroups = 8 - left.length - right.length;
  let groups;
  if (doubleColonParts.length === 2) {
    if (missingGroups < 1) {
      return null;
    }
    groups = left.concat(new Array(missingGroups).fill("0"), right);
  } else {
    if (missingGroups !== 0) {
      return null;
    }
    groups = left;
  }

  const bytes = [];
  groups.forEach((group) => {
    const number = parseInt(group, 16);
    bytes.push((number >> 8) & 0xff, number & 0xff);
  });

  return bytes.length === 16 ? bytes : null;
}

function normalizeAddress(address) {
  return String(address || "")
    .trim()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
}

function normalizeIpForCompare(ip) {
  const value = normalizeAddress(ip).toLowerCase();
  return value || null;
}

function parseInteger(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function countBy(items, predicate) {
  return items.reduce((count, item) => count + (predicate(item) ? 1 : 0), 0);
}

function uniqueStrings(values) {
  return [...new Set(values.filter(Boolean).map((value) => String(value)))];
}

function yesNo(value) {
  return value ? "是" : "否";
}

function formatValue(value) {
  if (value === null || value === undefined || value === "") {
    return '<span class="muted">未提供</span>';
  }
  return escapeHtml(String(value));
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function normalizeError(error) {
  if (error && error.name === "AbortError") {
    return "请求超时";
  }
  return error && error.message ? error.message : String(error);
}

function fallbackCopy(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "readonly");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.appendChild(textarea);
  textarea.select();
  const success = document.execCommand("copy");
  document.body.removeChild(textarea);
  if (!success) {
    throw new Error("浏览器拒绝剪贴板写入");
  }
}

function clearErrors() {
  const container = $("errorMessage");
  container.innerHTML = "";
  container.hidden = true;
}
