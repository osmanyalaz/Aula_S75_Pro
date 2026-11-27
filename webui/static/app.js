(() => {
  "use strict";

  const state = {
    meta: null,
    layout: null,
    status: null,
    keyColors: {}, // matrix_id -> [r, g, b]
    keyElements: new Map(), // matrix_id -> HTMLElement
    screenDecalEl: null,
    brushHex: "#FF3B30",
    tool: "paint", // 'paint' | 'erase'
    isPainting: false,
    loadedWiredDefaults: false,
    selectedFile: null,
    lastPreviewUrl: null,
    toastTimer: null,
  };

  const DIR_LABELS = {
    0: "0 (Right/Down)",
    1: "1 (Left)",
    2: "2 (Up)",
  };

  const $ = (id) => document.getElementById(id);

  function showToast(msg, kind = "info") {
    const el = $("toast");
    el.textContent = msg;
    el.className = `toast toast-${kind}`;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      el.className = "toast hidden";
    }, kind === "error" ? 6000 : 3500);
  }

  function rgbToHex(r, g, b) {
    const c = (n) => Math.max(0, Math.min(255, n | 0)).toString(16).padStart(2, "0");
    return `#${c(r)}${c(g)}${c(b)}`.toUpperCase();
  }

  function hexToRgb(hex) {
    const clean = (hex || "").trim();
    const m = /^#?([0-9a-f]{6})$/i.exec(clean);
    if (!m) return null;
    const v = parseInt(m[1], 16);
    return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
  }

  async function apiJson(url, opts = {}) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  // ---- KLE Coordinate Parser (mirrors webui/server.py parse_kle_layout) ----
  function parseKleLayout(rawKle) {
    let y = -1.0;
    let rx = 0.0;
    let ry = 0.0;
    let c = "#cccccc";
    let t = "#000000";
    let a = 4;
    let f = 3;
    let r = 0.0;

    const keys = [];
    const decals = [];
    let maxX = 0;
    let maxY = 0;

    rawKle.forEach((row, idx) => {
      if (idx === 0 && !Array.isArray(row)) return;
      y += 1.0;
      let x = rx;
      let w = 1.0;
      let h = 1.0;
      let decal = false;

      for (const item of row) {
        if (typeof item === "object" && item !== null) {
          if ("rx" in item) { rx = Number(item.rx); x = rx; }
          if ("ry" in item) { ry = Number(item.ry); y = ry; }
          if ("r" in item) r = Number(item.r);
          if ("x" in item) x += Number(item.x);
          if ("y" in item) y += Number(item.y);
          if ("w" in item) w = Number(item.w);
          if ("h" in item) h = Number(item.h);
          if ("c" in item) c = String(item.c);
          if ("t" in item) t = String(item.t);
          if ("a" in item) a = Number(item.a);
          if ("f" in item) f = Number(item.f);
          if ("d" in item) decal = Boolean(item.d);
        } else if (typeof item === "string") {
          const entry = { x, y, w, h, c, t, a, f, r, label: item, decal };
          maxX = Math.max(maxX, x + w);
          maxY = Math.max(maxY, y + h);
          if (decal) {
            decals.push(entry);
          } else {
            entry.kleIndex = keys.length;
            keys.push(entry);
          }
          x += w;
          w = 1.0;
          h = 1.0;
          decal = false;
        }
      }
    });

    return { keys, decals, width: maxX, height: maxY };
  }

  function applyKeyVisual(matrixId, rgb) {
    const el = state.keyElements.get(matrixId);
    if (!el) return;
    const [r, g, b] = rgb || [0, 0, 0];
    if (r === 0 && g === 0 && b === 0) {
      el.style.background = "";
      el.style.borderColor = "";
      el.style.boxShadow = "";
      el.style.color = "";
    } else {
      el.style.background = `linear-gradient(180deg, rgba(${r},${g},${b},0.48), rgba(${r},${g},${b},0.28))`;
      el.style.borderColor = `rgb(${r},${g},${b})`;
      el.style.boxShadow = `0 0 10px rgba(${r},${g},${b},0.42), inset 0 0 6px rgba(${r},${g},${b},0.25)`;
      const luma = 0.299 * r + 0.587 * g + 0.114 * b;
      el.style.color = luma > 185 ? "#ffffff" : "#f1f5f9";
    }
    const name = state.meta?.matrix_to_name?.[String(matrixId)] || `Key ${matrixId}`;
    el.title = `${name} (matrix ${matrixId}) — ${rgbToHex(r, g, b)}`;
  }

  function paintMatrixKey(matrixId) {
    const rgb = state.tool === "erase" ? [0, 0, 0] : (hexToRgb(state.brushHex) || [255, 59, 48]);
    state.keyColors[matrixId] = rgb;
    applyKeyVisual(matrixId, rgb);
    updateLitCounter();
  }

  function clearMatrixKey(matrixId) {
    state.keyColors[matrixId] = [0, 0, 0];
    applyKeyVisual(matrixId, [0, 0, 0]);
    updateLitCounter();
  }

  function updateLitCounter() {
    let lit = 0;
    for (const id of state.meta.kle_to_matrix) {
      const [r, g, b] = state.keyColors[id] || [0, 0, 0];
      if (r || g || b) lit += 1;
    }
    $("perkey-info").textContent = `${lit} / ${state.meta.kle_to_matrix.length} keys lit`;
  }

  function switchTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      const active = btn.dataset.tab === tabName;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll(".panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `panel-${tabName}`);
    });
  }

  function renderKeyboard() {
    const stage = $("keyboard-stage");
    stage.innerHTML = "";
    state.keyElements.clear();

    const { keys, decals, width, height } = state.layout;
    const kleToMatrix = state.meta.kle_to_matrix;
    if (keys.length !== kleToMatrix.length) {
      stage.innerHTML = `<div class="keyboard-loading">Layout key count (${keys.length}) does not match matrix (${kleToMatrix.length}).</div>`;
      return;
    }

    const pad = 0.25;
    stage.style.width = `calc(${width + pad * 2} * var(--u))`;
    stage.style.height = `calc(${height + pad * 2} * var(--u))`;

    // Render decals first (bezel beneath SCREEN, plus KNOB and clickable SCREEN)
    for (const dec of decals) {
      const label = (dec.label || "").trim().toUpperCase();
      if (label === "SCREEN") {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "kle-decal kle-screen";
        btn.title = "Open TFT Screen uploader (135×240)";
        positionKleItem(btn, dec, pad, 0);
        btn.innerHTML = `<span class="kle-screen-label">TFT<br>135×240</span>`;
        btn.addEventListener("click", () => {
          switchTab("screen");
          $("panel-screen").scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
        state.screenDecalEl = btn;
        stage.appendChild(btn);
      } else {
        const div = document.createElement("div");
        div.className = "kle-decal";
        if (label === "KNOB") {
          div.classList.add("kle-knob");
          div.textContent = "KNOB";
          positionKleItem(div, dec, pad, 0.04);
        } else {
          div.classList.add("kle-bezel");
          positionKleItem(div, dec, pad, 0);
        }
        stage.appendChild(div);
      }
    }

    // Render 80 non-decal keys mapped 1:1 by ordered index
    keys.forEach((k, idx) => {
      const matrixId = kleToMatrix[idx];
      const keyEl = document.createElement("div");
      keyEl.className = "kle-key";
      if ((k.a & 4) === 0 || k.a === 7) keyEl.classList.add("align-center");
      if (k.label === "") keyEl.classList.add("is-space");
      positionKleItem(keyEl, k, pad, 0.04);

      const parts = k.label.split("\n");
      const mainSpan = document.createElement("span");
      mainSpan.className = "legend-main";
      mainSpan.textContent = parts[0] || "";
      keyEl.appendChild(mainSpan);
      if (parts.length > 1 && parts[1]) {
        const subSpan = document.createElement("span");
        subSpan.className = "legend-sub";
        subSpan.textContent = parts[1];
        keyEl.appendChild(subSpan);
      }

      keyEl.addEventListener("pointerdown", (ev) => {
        if (ev.button === 2) {
          ev.preventDefault();
          clearMatrixKey(matrixId);
          return;
        }
        if (ev.button !== 0) return;
        state.isPainting = true;
        paintMatrixKey(matrixId);
      });

      keyEl.addEventListener("pointerenter", () => {
        if (state.isPainting) paintMatrixKey(matrixId);
      });

      keyEl.addEventListener("contextmenu", (ev) => ev.preventDefault());

      stage.appendChild(keyEl);
      state.keyElements.set(matrixId, keyEl);
      applyKeyVisual(matrixId, state.keyColors[matrixId] || [0, 0, 0]);
    });

    fitKeyboardScale();
    updateLitCounter();
  }

  function positionKleItem(el, item, pad, gap) {
    el.style.left = `calc(${item.x + pad + gap} * var(--u))`;
    el.style.top = `calc(${item.y + pad + gap} * var(--u))`;
    el.style.width = `calc(${Math.max(0.2, item.w - gap * 2)} * var(--u))`;
    el.style.height = `calc(${Math.max(0.2, item.h - gap * 2)} * var(--u))`;
  }

  function fitKeyboardScale() {
    if (!state.layout) return;
    const vp = $("keyboard-viewport");
    const avail = Math.max(320, vp.clientWidth - 16);
    const totalUnits = state.layout.width + 0.5;
    const unitPx = Math.max(22, Math.min(58, Math.floor(avail / totalUnits)));
    document.documentElement.style.setProperty("--u", `${unitPx}px`);
  }

  // ---- Status & Capabilities ----
  async function refreshStatus({ loadDefaults = false } = {}) {
    try {
      const st = await apiJson("/api/status");
      state.status = st;
      renderStatus(st);
      if (loadDefaults && !state.loadedWiredDefaults && st.capabilities?.can_read) {
        state.loadedWiredDefaults = true;
        await preloadWiredDefaults();
      }
    } catch (err) {
      showToast(`Status query failed: ${err.message}`, "error");
    }
  }

  function renderStatus(st) {
    const connBadge = $("conn-badge");
    const devBadge = $("device-id-badge");
    const fwBadge = $("fw-badge");
    const battBar = $("battery-bar");
    const battText = $("battery-text");
    const errBanner = $("conn-error-banner");

    if (!st.connected) {
      connBadge.className = "pill pill-offline";
      connBadge.textContent = "Disconnected";
      devBadge.textContent = "VID:PID —";
      fwBadge.textContent = "FW —";
      battBar.style.width = "0%";
      battText.textContent = "—";
      errBanner.textContent = st.error || "Keyboard not detected (connect wired USB or 2.4GHz dongle).";
      errBanner.classList.remove("hidden");
    } else {
      errBanner.classList.add("hidden");
      if (st.mode === "dongle") {
        connBadge.className = "pill pill-dongle";
        connBadge.textContent = "2.4GHz Dongle";
      } else {
        connBadge.className = "pill pill-usb";
        connBadge.textContent = "Wired USB";
      }
      devBadge.textContent = `${st.device.vid}:${st.device.pid} (if${st.device.interface})`;
      fwBadge.textContent = `FW v${st.info.fw_version}`;

      if (st.battery.percent !== null && st.battery.percent !== undefined) {
        battBar.style.width = `${st.battery.percent}%`;
        battText.textContent = `${st.battery.percent}% (${st.battery.level}/5)`;
      } else {
        const approxPct = [3, 18, 40, 65, 85, 98][st.battery.level] ?? 0;
        battBar.style.width = `${approxPct}%`;
        battText.textContent = `${st.battery.level}/5 (${st.battery.percent_range})`;
      }
    }

    const canRead = Boolean(st.capabilities?.can_read);
    const canUpload = Boolean(st.capabilities?.can_upload_screen);

    document.querySelectorAll(".wired-only-read").forEach((btn) => {
      btn.disabled = !canRead;
      btn.title = canRead
        ? ""
        : "Wired USB only (flash/RAM read-back is not supported over 2.4GHz dongle)";
    });

    const uploadBtn = $("btn-upload-screen");
    uploadBtn.disabled = !state.selectedFile || !canUpload;
    uploadBtn.title = canUpload
      ? ""
      : "TFT screen uploads (0x7204) require wired USB mode";

    const showDongleScreenWarn = st.connected && !canUpload;
    $("screen-dongle-banner").classList.toggle("hidden", !showDongleScreenWarn);
  }

  async function preloadWiredDefaults() {
    try {
      const lit = await apiJson("/api/lighting");
      if (!lit.erased && !lit.zeroed && lit.effect <= 19) {
        $("light-effect").value = String(lit.effect);
        updateEffectNote();
        const hex = rgbToHex(lit.rgb[0], lit.rgb[1], lit.rgb[2]);
        $("light-color-picker").value = hex;
        $("light-color-hex").value = hex;
        $("light-option").value = String(lit.option ? 1 : 0);
        $("light-brightness").value = String(Math.min(5, lit.brightness));
        $("light-speed").value = String(Math.min(5, lit.speed));
        $("light-direction").value = String(Math.min(2, lit.direction));
        syncLightingLabels();
      }
    } catch (_) {
      /* ignore non-fatal preload error */
    }
    try {
      const cfg = await apiJson("/api/settings");
      if (!cfg.erased && !cfg.zeroed) {
        if (cfg.key_response_time >= 1 && cfg.key_response_time <= 5) {
          $("set-key-resp").value = String(cfg.key_response_time);
        }
        $("set-sleep-time").value = String(Math.min(3, cfg.sleep_time));
        $("set-fn-switch").checked = Boolean(cfg.fn_switch);
        $("set-alt-tab").checked = Boolean(cfg.disable_alt_tab);
        $("set-alt-f4").checked = Boolean(cfg.disable_alt_f4);
        $("set-win-lock").checked = Boolean(cfg.win_lock);
      }
    } catch (_) {
      /* ignore non-fatal preload error */
    }
  }

  // ---- Control Handlers ----
  function syncLightingLabels() {
    $("light-bri-val").textContent = $("light-brightness").value;
    $("light-spd-val").textContent = $("light-speed").value;
    const dir = Number($("light-direction").value);
    $("light-dir-val").textContent = DIR_LABELS[dir] || String(dir);
  }

  function updateEffectNote() {
    const eid = Number($("light-effect").value);
    const eff = state.meta.effects.find((e) => e.id === eid);
    $("light-effect-note").textContent = eff ? eff.note : "";
  }

  function setupColorInputs() {
    const setBrush = (hex) => {
      const norm = hex.startsWith("#") ? hex.toUpperCase() : `#${hex.toUpperCase()}`;
      state.brushHex = norm;
      state.tool = "paint";
      $("btn-tool-paint").classList.add("active");
      $("btn-tool-erase").classList.remove("active");
      $("key-color-picker").value = norm;
      $("key-color-hex").value = norm;
      $("active-paint-badge").textContent = `Brush: ${norm}`;
    };

    $("key-color-picker").addEventListener("input", (e) => setBrush(e.target.value));
    $("key-color-hex").addEventListener("change", (e) => {
      const rgb = hexToRgb(e.target.value);
      if (rgb) setBrush(rgbToHex(...rgb));
    });
    $("key-swatches").addEventListener("click", (e) => {
      const sw = e.target.closest(".swatch");
      if (sw) setBrush(sw.dataset.hex);
    });

    $("btn-tool-paint").addEventListener("click", () => {
      state.tool = "paint";
      $("btn-tool-paint").classList.add("active");
      $("btn-tool-erase").classList.remove("active");
      $("active-paint-badge").textContent = `Brush: ${state.brushHex}`;
    });
    $("btn-tool-erase").addEventListener("click", () => {
      state.tool = "erase";
      $("btn-tool-erase").classList.add("active");
      $("btn-tool-paint").classList.remove("active");
      $("active-paint-badge").textContent = "Brush: Eraser (Off)";
    });

    $("custom-brightness").addEventListener("input", (e) => {
      $("custom-bri-val").textContent = e.target.value;
    });

    $("light-color-picker").addEventListener("input", (e) => {
      $("light-color-hex").value = e.target.value.toUpperCase();
    });
    $("light-color-hex").addEventListener("change", (e) => {
      const rgb = hexToRgb(e.target.value);
      if (rgb) {
        const h = rgbToHex(...rgb);
        $("light-color-picker").value = h;
        $("light-color-hex").value = h;
      }
    });
    $("light-brightness").addEventListener("input", syncLightingLabels);
    $("light-speed").addEventListener("input", syncLightingLabels);
    $("light-direction").addEventListener("input", syncLightingLabels);
    $("light-effect").addEventListener("change", updateEffectNote);
  }

  function setupActionButtons() {
    window.addEventListener("pointerup", () => { state.isPainting = false; });

    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => switchTab(btn.dataset.tab));
    });

    $("btn-refresh").addEventListener("click", () => refreshStatus());

    $("btn-fill-all").addEventListener("click", () => {
      const rgb = hexToRgb(state.brushHex) || [255, 59, 48];
      for (const id of state.meta.kle_to_matrix) {
        state.keyColors[id] = [...rgb];
        applyKeyVisual(id, rgb);
      }
      updateLitCounter();
    });

    $("btn-clear-all").addEventListener("click", () => {
      for (const id of state.meta.kle_to_matrix) {
        state.keyColors[id] = [0, 0, 0];
        applyKeyVisual(id, [0, 0, 0]);
      }
      updateLitCounter();
    });

    $("btn-load-custom").addEventListener("click", async () => {
      try {
        const data = await apiJson("/api/custom-table");
        for (const id of state.meta.kle_to_matrix) {
          const rgb = data.keys[String(id)] || [0, 0, 0];
          state.keyColors[id] = rgb;
          applyKeyVisual(id, rgb);
        }
        updateLitCounter();
        showToast("Loaded per-key table from keyboard", "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-save-custom").addEventListener("click", async () => {
      const litMap = {};
      for (const id of state.meta.kle_to_matrix) {
        const rgb = state.keyColors[id] || [0, 0, 0];
        if (rgb[0] || rgb[1] || rgb[2]) {
          litMap[String(id)] = rgb;
        }
      }
      const brightness = Number($("custom-brightness").value);
      try {
        const res = await apiJson("/api/custom-table", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ keys: litMap, brightness }),
        });
        showToast(`Saved custom per-key RGB (${res.key_count} lit keys, ${res.mode})`, "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-load-lighting").addEventListener("click", async () => {
      try {
        await preloadWiredDefaults();
        showToast("Loaded wired flash lighting & settings", "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-apply-lighting").addEventListener("click", async () => {
      const rgb = hexToRgb($("light-color-hex").value) || [0, 199, 190];
      const payload = {
        effect: Number($("light-effect").value),
        r: rgb[0],
        g: rgb[1],
        b: rgb[2],
        option: Number($("light-option").value),
        brightness: Number($("light-brightness").value),
        speed: Number($("light-speed").value),
        direction: Number($("light-direction").value),
      };
      try {
        const res = await apiJson("/api/lighting", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        showToast(`Applied effect ${res.effect} (${res.mode})`, "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("underglow-buttons").addEventListener("click", async (e) => {
      const btn = e.target.closest(".underglow-btn");
      if (!btn) return;
      const preserve = $("ug-preserve").checked;
      try {
        const res = await apiJson("/api/underglow", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: btn.dataset.mode, preserve_lighting: preserve }),
        });
        showToast(`Underglow set to ${res.mode_name}`, "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-load-settings").addEventListener("click", async () => {
      try {
        const cfg = await apiJson("/api/settings");
        if (!cfg.erased && !cfg.zeroed) {
          if (cfg.key_response_time >= 1 && cfg.key_response_time <= 5) {
            $("set-key-resp").value = String(cfg.key_response_time);
          }
          $("set-sleep-time").value = String(Math.min(3, cfg.sleep_time));
          $("set-fn-switch").checked = Boolean(cfg.fn_switch);
          $("set-alt-tab").checked = Boolean(cfg.disable_alt_tab);
          $("set-alt-f4").checked = Boolean(cfg.disable_alt_f4);
          $("set-win-lock").checked = Boolean(cfg.win_lock);
          showToast("Loaded settings from flash 0x9000", "ok");
        } else {
          showToast("Settings page is currently erased/empty", "info");
        }
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-apply-settings").addEventListener("click", async () => {
      const payload = {
        key_response_time: Number($("set-key-resp").value),
        sleep_time: Number($("set-sleep-time").value),
        fn_switch: $("set-fn-switch").checked ? 1 : 0,
        disable_alt_tab: $("set-alt-tab").checked,
        disable_alt_f4: $("set-alt-f4").checked,
        win_lock: $("set-win-lock").checked,
      };
      try {
        const res = await apiJson("/api/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        showToast(`Settings saved (${res.mode})`, "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });

    $("btn-sync-clock").addEventListener("click", async () => {
      try {
        const res = await apiJson("/api/sync-clock", { method: "POST" });
        $("sync-clock-result").textContent = `Last synced (${res.mode}): ${res.synced_at}`;
        showToast(`Keyboard RTC synced at ${res.synced_at}`, "ok");
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  }

  // ---- TFT Screen Upload & Preview ----
  function buildScreenQuery(file) {
    const q = new URLSearchParams();
    q.set("filename", file.name || "upload.png");
    if ($("screen-fit").checked) q.set("fit", "1");
    const delay = $("screen-delay").value.trim();
    if (delay) q.set("delay", delay);
    const fps = $("screen-fps").value.trim();
    if (fps) q.set("fps", fps);
    const maxF = $("screen-max-frames").value.trim();
    if (maxF) q.set("max_frames", maxF);
    return q.toString();
  }

  async function requestScreenPreview() {
    const file = state.selectedFile;
    if (!file) return;
    try {
      const res = await apiJson(`/api/screen/preview?${buildScreenQuery(file)}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      const imgEl = $("screen-preview-img");
      imgEl.src = res.preview_data_url;
      imgEl.classList.remove("hidden");
      $("screen-preview-empty").classList.add("hidden");

      if (state.screenDecalEl) {
        state.screenDecalEl.innerHTML = `<img src="${res.preview_data_url}" alt="TFT preview">`;
      }

      $("stat-res").textContent = `${res.width} × ${res.height}`;
      $("stat-frames").textContent = `${res.frame_count} / ${state.meta.screen.max_frames}`;
      $("stat-chunks").textContent = `${res.chunk_count} chunks`;
      $("stat-bytes").textContent = `${(res.total_bytes / 1024).toFixed(0)} KB`;
      const uniqDelays = [...new Set(res.delays_ms)];
      $("stat-delays").textContent = uniqDelays.slice(0, 4).join(", ") + (uniqDelays.length > 4 ? "…" : "") + " ms";
      $("stat-eta").textContent = `~${res.estimated_upload_seconds} s`;
      $("stat-truncated").classList.toggle("hidden", !res.truncated);
      $("btn-preview-screen").disabled = false;
      renderStatus(state.status || { connected: false, capabilities: {} });
    } catch (err) {
      showToast(`Preview failed: ${err.message}`, "error");
    }
  }

  function setupScreenPanel() {
    const dropzone = $("dropzone");
    const fileInput = $("screen-file-input");

    const selectFile = (file) => {
      if (!file) return;
      state.selectedFile = file;
      const badge = $("selected-filename");
      badge.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      badge.classList.remove("hidden");
      $("btn-preview-screen").disabled = false;
      requestScreenPreview();
    };

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        fileInput.click();
      }
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files?.length) selectFile(fileInput.files[0]);
    });

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-over");
    });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag-over"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-over");
      if (e.dataTransfer?.files?.length) selectFile(e.dataTransfer.files[0]);
    });

    ["screen-fit", "screen-delay", "screen-fps", "screen-max-frames"].forEach((id) => {
      $(id).addEventListener("change", () => {
        if (state.selectedFile) requestScreenPreview();
      });
    });

    $("btn-preview-screen").addEventListener("click", requestScreenPreview);

    $("btn-upload-screen").addEventListener("click", async () => {
      const file = state.selectedFile;
      if (!file) return;
      const btn = $("btn-upload-screen");
      const prevText = btn.textContent;
      btn.disabled = true;
      btn.textContent = "Uploading…";
      try {
        const res = await apiJson(`/api/screen/upload?${buildScreenQuery(file)}`, {
          method: "POST",
          headers: { "Content-Type": "application/octet-stream" },
          body: file,
        });
        showToast(`Uploaded ${res.frame_count} frame(s) (${res.chunk_count} chunks) to TFT`, "ok");
      } catch (err) {
        showToast(`TFT upload failed: ${err.message}`, "error");
      } finally {
        btn.textContent = prevText;
        await refreshStatus();
      }
    });
  }

  function startClockTicker() {
    const tick = () => {
      const now = new Date();
      $("local-clock-display").textContent = now.toLocaleTimeString([], { hour12: false }) +
        " · " + now.toLocaleDateString();
    };
    tick();
    setInterval(tick, 1000);
  }

  async function init() {
    startClockTicker();
    setupColorInputs();
    setupActionButtons();
    setupScreenPanel();

    const ro = new ResizeObserver(() => fitKeyboardScale());
    ro.observe($("keyboard-viewport"));

    try {
      const [meta, rawKle] = await Promise.all([
        apiJson("/api/meta"),
        apiJson("/static/keyboard-layout.json"),
      ]);
      state.meta = meta;
      state.layout = parseKleLayout(rawKle);

      const effSel = $("light-effect");
      effSel.innerHTML = "";
      for (const eff of meta.effects) {
        const opt = document.createElement("option");
        opt.value = String(eff.id);
        opt.textContent = `${eff.id} — ${eff.name}`;
        effSel.appendChild(opt);
      }
      effSel.value = "1";
      updateEffectNote();
      syncLightingLabels();

      renderKeyboard();
      await refreshStatus({ loadDefaults: true });
    } catch (err) {
      showToast(`Startup failed: ${err.message}`, "error");
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
