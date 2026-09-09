/* URL Reputation Bench — client */

const $ = (id) => document.getElementById(id);

const el = {
  input: $("input"),
  scanBtn: $("scanBtn"),
  delay: $("delay"),
  urlCount: $("urlCount"),
  modeBadge: $("modeBadge"),
  run: $("run"),
  runFill: $("runFill"),
  runText: $("runText"),
  runCount: $("runCount"),
  board: $("board"),
  rows: $("rows"),
  tally: $("tally"),
  blank: $("blank"),
  flaggedOnly: $("flaggedOnly"),
  exportBtn: $("exportBtn"),
  resetBtn: $("resetBtn"),
};

const CATS = ["malicious", "suspicious", "harmless", "undetected"];
let collected = [];
let scanning = false;

/* ---------------------------------------------------------------- setup */

fetch("/api/config")
  .then((r) => r.json())
  .then((c) => {
    el.modeBadge.textContent = "headless chrome";
    el.delay.value = c.delay;
  })
  .catch(() => {
    el.modeBadge.textContent = "server unreachable";
  });

el.input.addEventListener("input", updateCount);

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

/* ----------------------------------------------------------------- scan */

el.scanBtn.addEventListener("click", startScan);

el.input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") startScan();
});

async function startScan() {
  if (scanning) return;
  const text = el.input.value;
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
  renderTally();

  let total = 0;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, delay: Number(el.delay.value) || 0 }),
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
          el.rows.appendChild(buildRow(msg));
          el.runFill.style.width = `${((msg.index + 1) / total) * 100}%`;
          renderTally();
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

function verdictOf(stats) {
  if (!stats) return "unknown";
  if (stats.malicious > 0) return "malicious";
  if (stats.suspicious > 0) return "suspicious";
  return "harmless";
}

function buildRow(res) {
  const li = document.createElement("li");
  li.className = "row";

  if (res.error) {
    li.innerHTML = `
      <div class="row-top">
        <span class="row-url"><i class="marker"></i>${escapeHtml(res.url)}</span>
        <span></span>
        <span class="row-score">—</span>
        <span class="row-error">${escapeHtml(res.error)}</span>
      </div>`;
    return li;
  }

  const stats = res.stats || {};
  const flagged = (stats.malicious || 0) + (stats.suspicious || 0);
  const total = CATS.reduce((a, c) => a + (stats[c] || 0), 0);
  li.classList.add("is-" + verdictOf(stats));

  // One tick per engine, ordered so findings cluster at the left edge.
  const entries = Object.entries(res.vendors).sort(
    (a, b) => CATS.indexOf(a[1].category) - CATS.indexOf(b[1].category)
  );
  const ticks = entries
    .map(([, v]) => `<i class="${cls(v.category)}"></i>`)
    .join("");

  const engines = entries
    .map(
      ([name, v]) => `
      <div class="engine ${cls(v.category)}">
        <span class="name">${escapeHtml(name)}</span>
        <span class="verdict">${escapeHtml(v.result)}</span>
      </div>`
    )
    .join("");

  li.innerHTML = `
    <button class="row-top" type="button">
      <span class="row-url"><i class="marker"></i>${escapeHtml(res.url)}</span>
      <span class="strip">${ticks}</span>
      <span class="row-score">${flagged} / ${total}</span>
    </button>
    <div class="detail"><div class="detail-inner">${engines}</div></div>`;

  li.querySelector(".row-top").addEventListener("click", () =>
    li.classList.toggle("open")
  );

  li.dataset.flagged = flagged > 0 ? "1" : "0";
  return li;
}

function cls(c) {
  return CATS.includes(c) ? c : "undetected";
}

function renderTally() {
  const n = collected.length;
  const flagged = collected.filter(
    (r) => r.stats && (r.stats.malicious || r.stats.suspicious)
  ).length;
  const failed = collected.filter((r) => r.error).length;

  const parts = [`<span><b>${n}</b> scanned</span>`];
  if (flagged) parts.push(`<span><b>${flagged}</b> flagged</span>`);
  if (n - flagged - failed > 0)
    parts.push(`<span><b>${n - flagged - failed}</b> clean</span>`);
  if (failed) parts.push(`<span><b>${failed}</b> no result</span>`);

  el.tally.innerHTML = parts.join("");
}

function applyFilter() {
  const only = el.flaggedOnly.checked;
  el.rows.querySelectorAll(".row").forEach((row) => {
    row.classList.toggle("hide", only && row.dataset.flagged !== "1");
  });
}

el.flaggedOnly.addEventListener("change", applyFilter);

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

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
