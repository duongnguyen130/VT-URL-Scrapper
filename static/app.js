/* URL Bench — client */

const $ = (id) => document.getElementById(id);

const el = {
  input: $("input"),
  scanBtn: $("scanBtn"),
  resetBtn: $("resetBtn"),
  delay: $("delay"),
  urlCount: $("urlCount"),
  run: $("run"),
  runFill: $("runFill"),
  runCount: $("runCount"),
  runText: $("runText"),
  board: $("board"),
  stats: $("stats"),
  notice: $("notice"),
  noticeCount: $("noticeCount"),
  noticeRest: $("noticeRest"),
  filter: $("filter"),
  expandAll: $("expandAll"),
  exportBtn: $("exportBtn"),
  rows: $("rows"),
  blank: $("blank"),
};

const CATS = ["malicious", "suspicious", "harmless", "undetected"];

let collected = [];
let scanning = false;
let mode = "all";

/* -------------------------------------------------------------- quips --
   Shown only in dead air: while Chrome boots and clears Cloudflare, and
   during the pause between lookups. The moment there is real status to
   report, the quip is replaced by it. Nothing funny ever covers a fact. */

const QUIPS = {
  boot: [
    "Starting a browser that will never be seen",
    "Convincing Cloudflare there is a human here",
    "Teaching headless Chrome to act natural",
    "Checking the profile jar for an old cookie",
    "No window is going to open. That part is deliberate.",
    "Assembling a plausible number of fake plugins",
  ],
  pause: [
    "Counting to six, as promised",
    "Waiting so the rate limiter stays friendly",
    "Being deliberately boring for a moment",
    "Not hammering anything",
    "Letting the connection cool off",
    "Pacing ourselves, unlike the phishing kit",
  ],
  slow: [
    "Ninety-odd engines, all with opinions",
    "Somewhere a sandbox is detonating something",
    "Checking whether that hyphen is load-bearing",
    "Squinting at homoglyphs",
    "The vendors are still arguing",
    "This URL is being judged by strangers",
    "Waiting on the slowest engine in the batch",
  ],
};

let quipTimer = null;
let slowTimer = null;

function showQuips(pool) {
  stopQuips();
  const lines = QUIPS[pool];
  let i = Math.floor(Math.random() * lines.length);
  const tick = () => {
    el.runText.classList.remove("is-quip");
    void el.runText.offsetWidth;
    el.runText.textContent = lines[i % lines.length];
    el.runText.classList.add("is-quip");
    i += 1;
  };
  tick();
  quipTimer = setInterval(tick, 2800);
}

function stopQuips() {
  clearInterval(quipTimer);
  quipTimer = null;
}

function showFact(text) {
  stopQuips();
  el.runText.classList.remove("is-quip");
  el.runText.textContent = text;
}

/* --------------------------------------------------------------- setup */

fetch("/api/config")
  .then((r) => r.json())
  .then((c) => {
    el.delay.value = c.delay;
  })
  .catch(() => {});

el.input.addEventListener("input", updateCount);

el.input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") startScan();
});

function countUrls() {
  return el.input.value
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#")).length;
}

function updateCount() {
  const n = countUrls();
  el.urlCount.textContent = n ? `${n} ${n === 1 ? "URL" : "URLs"}` : "";
}

/* ----------------------------------------------------------------- scan */

el.scanBtn.addEventListener("click", startScan);

async function startScan() {
  if (scanning) return;

  if (!countUrls()) {
    el.run.hidden = false;
    el.runCount.textContent = "";
    showFact("Paste at least one URL first.");
    return;
  }

  scanning = true;
  collected = [];
  el.rows.innerHTML = "";
  el.scanBtn.disabled = true;
  el.scanBtn.textContent = "Scanning";
  el.blank.hidden = true;
  el.board.hidden = false;
  el.run.hidden = false;
  el.runFill.style.width = "0%";
  el.runCount.textContent = "";
  showQuips("boot");
  renderStats();

  let total = 0;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: el.input.value,
        delay: Number(el.delay.value) || 0,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let nl;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;

        const msg = JSON.parse(line);

        if (msg.event === "start") {
          total = msg.total;
        } else if (msg.event === "progress") {
          el.runCount.textContent = `${msg.index + 1} / ${total}`;
          showFact(msg.url);
          // A lookup that drags on has nothing new to report, so hand the
          // line back to the quips until the result lands.
          clearTimeout(slowTimer);
          slowTimer = setTimeout(() => showQuips("slow"), 9000);
        } else if (msg.event === "result") {
          clearTimeout(slowTimer);
          if (msg.index < total - 1) showQuips("pause");
          collected.push(msg);
          el.rows.appendChild(buildCard(msg));
          el.runFill.style.width = `${((msg.index + 1) / total) * 100}%`;
          renderStats();
          applyFilter();
        } else if (msg.event === "done") {
          showFact(`Finished ${total} ${total === 1 ? "URL" : "URLs"}`);
        }
      }
    }
  } catch (err) {
    showFact(err.message);
  } finally {
    clearTimeout(slowTimer);
    stopQuips();
    el.runText.classList.remove("is-quip");
    scanning = false;
    el.scanBtn.disabled = false;
    el.scanBtn.textContent = "Scan URLs";
  }
}

/* --------------------------------------------------------------- render */

function severity(res) {
  if (res.error || !res.stats) return "none";
  if (res.stats.malicious > 0) return "high";
  if (res.stats.suspicious > 0) return "medium";
  return "clean";
}

const BADGE = {
  high: "malicious",
  medium: "suspicious",
  clean: "no detections",
  none: "no result",
};

function buildCard(res) {
  const sev = severity(res);
  const card = document.createElement("article");
  card.className = `find ${sev}`;
  card.dataset.sev = sev;

  if (res.error) {
    card.innerHTML = `
      <div class="find-head">
        <span class="badge">${BADGE.none}</span>
        <span class="locus">—</span>
      </div>
      <div class="find-body">
        <div class="excerpt">${esc(res.url)}</div>
        <p class="find-error">${esc(res.error)}</p>
      </div>`;
    return card;
  }

  const stats = res.stats || {};
  const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
  const total = CATS.reduce((a, c) => a + (stats[c] || 0), 0);

  // Sort by severity so findings pack against the left edge of the strip.
  const entries = Object.entries(res.vendors).sort(
    (a, b) =>
      CATS.indexOf(a[1].category) - CATS.indexOf(b[1].category) ||
      a[0].localeCompare(b[0])
  );

  const ticks = entries.map(([, v]) => `<i class="${cls(v.category)}"></i>`).join("");

  const engines = entries
    .map(
      ([name, v]) => `
      <div class="engine ${cls(v.category)}">
        <span class="name">${esc(name)}</span>
        <span class="verdict">${esc(v.result)}</span>
      </div>`
    )
    .join("");

  card.innerHTML = `
    <div class="find-head">
      <span class="badge ${sev === "clean" || sev === "none" ? "" : sev}">${BADGE[sev]}</span>
      <span class="locus">${flagged} of ${total} engines</span>
      <div class="right">
        <button class="btn btn-ghost btn-sm toggle" type="button">Engines</button>
      </div>
    </div>
    <div class="find-body">
      <div class="excerpt">${esc(res.url)}</div>
      <div class="strip">${ticks}</div>
      <div class="engines"><div class="engines-inner">${engines}</div></div>
    </div>`;

  card.querySelector(".toggle").addEventListener("click", () => {
    card.classList.toggle("open");
  });

  return card;
}

function cls(c) {
  return CATS.includes(c) ? c : "undetected";
}

function renderStats() {
  const n = collected.length;
  const high = collected.filter((r) => severity(r) === "high").length;
  const med = collected.filter((r) => severity(r) === "medium").length;
  const failed = collected.filter((r) => severity(r) === "none").length;
  const clean = n - high - med - failed;

  el.stats.innerHTML = `
    <div class="stat"><b>${n}</b><span>Scanned</span></div>
    <div class="stat is-high"><b>${high}</b><span>Malicious</span></div>
    <div class="stat is-medium"><b>${med}</b><span>Suspicious</span></div>
    <div class="stat"><b>${clean}</b><span>No detections</span></div>`;

  const flagged = high + med;
  el.notice.hidden = flagged === 0;
  if (flagged) {
    el.noticeCount.textContent = `${flagged} of ${n}`;
    el.noticeRest.textContent =
      flagged === 1
        ? "URL was flagged by at least one engine."
        : "URLs were flagged by at least one engine.";
  }

  el.exportBtn.disabled = n === 0;
}

/* --------------------------------------------------------------- filter */

el.filter.addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-f]");
  if (!btn) return;
  mode = btn.dataset.f;
  el.filter.querySelectorAll("button").forEach((b) => {
    b.setAttribute("aria-pressed", String(b === btn));
  });
  applyFilter();
});

function applyFilter() {
  el.rows.querySelectorAll(".find").forEach((card) => {
    const sev = card.dataset.sev;
    const show =
      mode === "all" ||
      (mode === "flagged" && (sev === "high" || sev === "medium")) ||
      (mode === "clean" && sev === "clean");
    card.classList.toggle("hide", !show);
  });
}

el.expandAll.addEventListener("change", () => {
  el.rows.querySelectorAll(".find").forEach((card) => {
    card.classList.toggle("open", el.expandAll.checked);
  });
});

/* --------------------------------------------------------------- extras */

el.exportBtn.addEventListener("click", () => {
  if (!collected.length) return;
  const blob = new Blob([JSON.stringify(collected, null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `url-scan-${new Date().toISOString().slice(0, 19)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

el.resetBtn.addEventListener("click", () => {
  clearTimeout(slowTimer);
  stopQuips();
  collected = [];
  el.rows.innerHTML = "";
  el.board.hidden = true;
  el.run.hidden = true;
  el.blank.hidden = false;
  el.input.value = "";
  el.input.focus();
  updateCount();
});

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
