(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {
    vaultType: "standard", // "standard" | "deniable"
    files: new Map(), // Standard vault files
    outerFiles: new Map(), // Deniable cover files
    hiddenFiles: new Map(), // Deniable private files
    vaults: [],
    sessionId: null,
    sessionMode: null,
    busy: false,
    sizeTouched: false,
  };

  const icons = {
    file: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3.5h8l4 4V20a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 6 20V3.5Z"/><path d="M14 3.5v4h4M9 13h6M9 16.5h6"/></svg>',
    download: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4v11m0 0 4.5-4.5M12 15l-4.5-4.5"/><path d="M5 15v4.5A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V15"/></svg>',
    vault: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7.5h6l1.8 2H20v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-11Z"/><path d="M4 10h16"/></svg>',
  };

  function formatBytes(value) {
    if (!Number.isFinite(Number(value)) || Number(value) <= 0) return "0 B";
    const size = Number(value);
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    const index = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
    const digits = index === 0 ? 0 : (size >= 10 ** (index * 3) ? 1 : 2);
    return `${(size / (1024 ** index)).toFixed(digits)} ${units[index]}`;
  }

  function setBusy(active, title = "Working on your vault…", copy = "Keep this window open while DenyFS prepares your encrypted space.", eyebrow = "SECURE OPERATION") {
    state.busy = active;
    const overlay = $("#busy-overlay");
    overlay.hidden = !active;
    $("#busy-title").textContent = title;
    $("#busy-copy").textContent = copy;
    $("#busy-eyebrow").textContent = eyebrow;
    const bar = $("#busy-overlay .progress-track > span");
    bar.classList.add("indeterminate");
    bar.style.width = "36%";
    $$('button').forEach(button => {
      if (button.closest("#busy-overlay")) return;
      if (active) {
        if (!button.disabled) button.dataset.wasEnabled = "true";
        button.disabled = true;
      } else if (button.dataset.wasEnabled === "true") {
        button.disabled = false;
        delete button.dataset.wasEnabled;
      }
    });
  }

  function setBusyProgress(value, label) {
    const bar = $("#busy-overlay .progress-track > span");
    bar.classList.remove("indeterminate");
    bar.style.width = `${Math.max(0, Math.min(100, value))}%`;
    if (label) $("#busy-copy").textContent = label;
  }

  function toast(message, kind = "success") {
    const node = document.createElement("div");
    node.className = `toast${kind === "error" ? " is-error" : ""}`;
    const mark = document.createElement("span");
    mark.className = "toast-mark";
    mark.textContent = kind === "error" ? "!" : "✓";
    const text = document.createElement("span");
    text.textContent = message;
    node.append(mark, text);
    $("#toast-region").append(node);
    window.setTimeout(() => node.remove(), 4600);
  }

  function showError(selector, message) {
    const element = $(selector);
    element.textContent = message;
    element.hidden = false;
  }

  function clearError(selector) {
    const element = $(selector);
    element.textContent = "";
    element.hidden = true;
  }

  async function requestJSON(url, options = {}) {
    const response = await fetch(url, {
      cache: "no-store",
      ...options,
      headers: { ...(options.headers || {}) },
    });
    let result;
    try { result = await response.json(); }
    catch { throw new Error("The local dashboard returned an unreadable response."); }
    if (!response.ok) throw new Error(result.error || `The request failed (${response.status}).`);
    return result;
  }

  function jsonPost(url, data, headers = {}) {
    return requestJSON(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(data),
    });
  }

  function setView(name) {
    const valid = ["overview", "encrypt", "decrypt", "library"].includes(name) ? name : "overview";
    $$(".page-view").forEach(view => view.classList.toggle("is-visible", view.id === `view-${valid}`));
    $$(".nav-item").forEach(item => item.classList.toggle("is-active", item.dataset.view === valid));
    const labels = { overview: "Overview", encrypt: "Encrypt files", decrypt: "Unlock vault", library: "Vault library" };
    $("#breadcrumb-current").textContent = labels[valid];
    document.title = `${labels[valid]} — DenyFS`;
    if (valid === "library") refreshVaults();
    if (valid === "decrypt") refreshVaults();
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function prettyDate(timestamp) {
    const date = new Date(Number(timestamp) * 1000);
    if (Number.isNaN(date.getTime())) return "Saved locally";
    return `Updated ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date)}`;
  }

  function makeVaultRow(vault) {
    const row = document.createElement("div");
    row.className = "vault-row";

    const identity = document.createElement("div");
    identity.className = "vault-identity";
    const symbol = document.createElement("span");
    symbol.className = "vault-symbol";
    symbol.innerHTML = icons.vault;
    const copy = document.createElement("span");
    const name = document.createElement("strong");
    name.textContent = vault.name;
    const date = document.createElement("small");
    date.textContent = prettyDate(vault.modified);
    copy.append(name, date);
    identity.append(symbol, copy);

    const meta = document.createElement("div");
    meta.className = "vault-meta";
    const sizeLabel = document.createElement("span");
    sizeLabel.textContent = "Container size";
    const size = document.createElement("strong");
    size.textContent = formatBytes(vault.size);
    meta.append(sizeLabel, size);

    const actions = document.createElement("div");
    actions.className = "vault-actions";
    const open = document.createElement("button");
    open.type = "button";
    open.className = "vault-action primary-vault-action";
    open.textContent = "Unlock";
    open.addEventListener("click", () => {
      $("#decrypt-vault").value = vault.name;
      setView("decrypt");
      $("#decrypt-password").focus({ preventScroll: true });
    });
    const exportButton = document.createElement("a");
    exportButton.className = "vault-action";
    exportButton.href = `/api/vaults/download?name=${encodeURIComponent(vault.name)}`;
    exportButton.download = vault.name;
    exportButton.innerHTML = `${icons.download}<span>Export</span>`;
    actions.append(open, exportButton);
    row.append(identity, meta, actions);
    return row;
  }

  async function refreshVaults() {
    try {
      const result = await requestJSON("/api/vaults");
      state.vaults = result.vaults || [];
      $("#nav-vault-count").textContent = String(state.vaults.length);
      const select = $("#decrypt-vault");
      const current = select.value;
      select.replaceChildren();
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = state.vaults.length ? "Choose a local vault…" : "No vaults — import one below";
      select.append(placeholder);
      state.vaults.forEach(vault => {
        const option = document.createElement("option");
        option.value = vault.name;
        option.textContent = `${vault.name} · ${formatBytes(vault.size)}`;
        select.append(option);
      });
      if (state.vaults.some(vault => vault.name === current)) select.value = current;

      const library = $("#library-list");
      library.replaceChildren();
      if (!state.vaults.length) {
        const empty = document.createElement("div");
        empty.className = "library-empty";
        empty.innerHTML = `<span class="empty-orbit">${icons.vault}</span><h3>No vaults yet</h3><p>Create a vault to encrypt files, or import an existing container.</p><button class="primary-button small-primary" data-view="encrypt" type="button">Create a vault <span>→</span></button>`;
        empty.querySelector("[data-view]").addEventListener("click", () => setView("encrypt"));
        library.append(empty);
      } else {
        state.vaults.forEach(vault => library.append(makeVaultRow(vault)));
      }

      const mini = $("#mini-vaults");
      mini.replaceChildren();
      if (!state.vaults.length) {
        const empty = document.createElement("span");
        empty.className = "empty-mini";
        empty.textContent = "Your local vaults will show here.";
        mini.append(empty);
      } else {
        state.vaults.slice(0, 3).forEach(vault => {
          const chip = document.createElement("span");
          chip.className = "mini-vault-chip";
          chip.textContent = vault.name;
          mini.append(chip);
        });
        if (state.vaults.length > 3) {
          const more = document.createElement("span");
          more.className = "mini-vault-chip";
          more.textContent = `+${state.vaults.length - 3} more`;
          mini.append(more);
        }
      }
    } catch (error) {
      console.warn("DenyFS library could not refresh:", error.message);
    }
  }

  function setConnection(connected, label) {
    const pill = $("#connection-pill");
    pill.classList.toggle("is-online", connected);
    pill.classList.toggle("is-offline", !connected);
    $("#connection-label").textContent = label;
  }

  function setSession(sessionId, mode, vaultName) {
    state.sessionId = sessionId || null;
    state.sessionMode = mode || null;
    const button = $("#top-lock-button");
    button.hidden = !sessionId;
    button.title = sessionId ? `Lock ${vaultName || "the open vault"}` : "";
    setConnection(true, sessionId ? "Vault unlocked" : "Local & ready");
  }

  async function refreshStatus() {
    try {
      const status = await requestJSON("/api/status");
      if (!status.linux) {
        setConnection(false, "Linux + FUSE required");
        toast("Run the dashboard inside Linux or WSL2 with FUSE enabled.", "error");
        return;
      }
      if (!status.available) {
        setConnection(false, "Build DenyFS first");
        toast("Build the release CLI with `make release`, then restart the dashboard.", "error");
        return;
      }
      if (!status.fuse || !status.fusermount) {
        setConnection(false, "FUSE setup needed");
        toast("Enable /dev/fuse and install fusermount3 before using the vault workflows.", "error");
        return;
      }
      setSession(status.session_id, status.session_mode, status.vault_name);
      if (status.busy) setConnection(true, "Preparing vault…");
      if (status.session_id && status.session_mode === "decrypt") {
        const opened = await requestJSON("/api/session/files", { headers: { "X-DenyFS-Session": status.session_id } });
        showDecryptedFiles(opened.files, opened.vault_name, opened.volume_type, opened.protect_active);
      } else if (status.session_id && status.session_mode === "encrypt") {
        toast("An encryption session was open when the dashboard reconnected. Lock it when ready to save the files already added.");
      }
    } catch {
      setConnection(false, "Dashboard disconnected");
      toast("The local dashboard service is not responding. Start dashboard/server.py in your project folder.", "error");
    }
  }

  function validateIncomingFiles(fileList, targetMap, label = "vault") {
    const incoming = [...fileList];
    const errors = [];
    for (const file of incoming) {
      if (targetMap.size >= 63 && !targetMap.has(file.name)) {
        errors.push(`DenyFS supports at most 63 files in the ${label}.`);
        break;
      }
      if (file.name.includes("/") || file.name.includes("\\") || file.name === "." || file.name === ".." || /[\x00-\x1f\x7f]/.test(file.name)) {
        errors.push(`${file.name} contains a folder path. This DenyFS version stores files in one flat folder.`);
        continue;
      }
      if (new TextEncoder().encode(file.name).length > 250) {
        errors.push(`${file.name} is too long for DenyFS.`);
        continue;
      }
      if (file.size > 4 * 1024 ** 3) {
        errors.push(`${file.name} exceeds the 4 GiB per-file limit.`);
        continue;
      }
      if (targetMap.has(file.name)) {
        errors.push(`A file named ${file.name} is already selected in the ${label}.`);
        continue;
      }
      targetMap.set(file.name, file);
    }
    return errors;
  }

  function addFiles(fileList) {
    const errors = validateIncomingFiles(fileList, state.files, "vault");
    renderSelectedFiles();
    if (errors.length) toast(errors[0], "error");
  }

  function addOuterFiles(fileList) {
    const errors = validateIncomingFiles(fileList, state.outerFiles, "outer volume");
    renderOuterFiles();
    if (errors.length) toast(errors[0], "error");
  }

  function addHiddenFiles(fileList) {
    const errors = validateIncomingFiles(fileList, state.hiddenFiles, "hidden volume");
    renderHiddenFiles();
    if (errors.length) toast(errors[0], "error");
  }

  function renderFileList(targetMap, listId, wrapId, countId, totalId, countLabel, onRemove) {
    const container = $(listId);
    container.replaceChildren();
    const files = [...targetMap.values()];
    $(wrapId).hidden = !files.length;
    $(countId).textContent = `${files.length} ${countLabel}${files.length === 1 ? "" : "s"}`;
    const total = files.reduce((sum, file) => sum + file.size, 0);
    $(totalId).textContent = formatBytes(total);
    files.forEach(file => {
      const row = document.createElement("li");
      row.className = "selected-file";
      const icon = document.createElement("span");
      icon.className = "file-type-icon";
      icon.innerHTML = icons.file;
      const info = document.createElement("span");
      info.className = "selected-file-info";
      const fileName = document.createElement("strong");
      fileName.textContent = file.name;
      const fileType = document.createElement("span");
      fileType.textContent = file.type || "File";
      info.append(fileName, fileType);
      const size = document.createElement("span");
      size.className = "selected-file-size";
      size.textContent = formatBytes(file.size);
      const remove = document.createElement("button");
      remove.className = "remove-file";
      remove.type = "button";
      remove.setAttribute("aria-label", `Remove ${file.name}`);
      remove.textContent = "×";
      remove.addEventListener("click", () => {
        targetMap.delete(file.name);
        onRemove();
      });
      row.append(icon, info, size, remove);
      container.append(row);
    });
    return total;
  }

  function renderSelectedFiles() {
    const total = renderFileList(
      state.files,
      "#selected-files",
      "#selected-files-wrap",
      "#selected-count",
      "#selected-total",
      "selected file",
      renderSelectedFiles
    );
    if (!state.sizeTouched && state.vaultType === "standard" && state.files.size) {
      const reserve = 5.5 * 1024 ** 2;
      const recommended = Math.max(8, Math.ceil(((total + reserve) * 2) / (1024 ** 2)));
      $("#vault-size").value = String(recommended);
    }
    updateCapacityHint();
  }

  function renderOuterFiles() {
    renderFileList(
      state.outerFiles,
      "#selected-outer-files",
      "#selected-outer-files-wrap",
      "#selected-outer-count",
      "#selected-outer-total",
      "cover file",
      renderOuterFiles
    );
    adjustDeniableRecommendedSize();
    updateCapacityHint();
  }

  function renderHiddenFiles() {
    renderFileList(
      state.hiddenFiles,
      "#selected-hidden-files",
      "#selected-hidden-files-wrap",
      "#selected-hidden-count",
      "#selected-hidden-total",
      "private file",
      renderHiddenFiles
    );
    adjustDeniableRecommendedSize();
    updateCapacityHint();
  }

  function adjustDeniableRecommendedSize() {
    if (state.sizeTouched || state.vaultType !== "deniable") return;
    if (!state.outerFiles.size && !state.hiddenFiles.size) return;
    const totalOuter = [...state.outerFiles.values()].reduce((sum, f) => sum + f.size, 0);
    const totalHidden = [...state.hiddenFiles.values()].reduce((sum, f) => sum + f.size, 0);
    const reqOuterMiB = Math.ceil(((totalOuter + 5.5 * 1024 ** 2) * 2) / (1024 ** 2));
    const reqHiddenMiB = Math.ceil(((totalHidden + 6.5 * 1024 ** 2) * 2) / (1024 ** 2)) + 2;
    const recommended = Math.max(16, Math.max(reqOuterMiB, reqHiddenMiB));
    $("#vault-size").value = String(recommended);
  }

  function updateCapacityHint() {
    const raw = Number($("#vault-size").value);
    const hint = $("#capacity-hint");
    if (!Number.isFinite(raw) || raw <= 0) {
      hint.textContent = "Enter a container size in MiB.";
      hint.classList.remove("capacity-short");
      return;
    }

    if (state.vaultType === "standard") {
      const approximate = Math.max(0, raw * 1024 ** 2 / 2 - 5.5 * 1024 ** 2);
      const total = [...state.files.values()].reduce((sum, file) => sum + file.size, 0);
      hint.textContent = `About ${formatBytes(approximate)} available for file data.`;
      hint.classList.toggle("capacity-short", total > approximate);
    } else {
      const outerVolumeBytes = Math.floor(raw / 2) * 1024 ** 2;
      const outerApprox = Math.max(0, outerVolumeBytes - 5.5 * 1024 ** 2);
      const hiddenVolumeBytes = Math.max(0, (Math.floor(raw / 2) - 1) * 1024 ** 2);
      const hiddenApprox = Math.max(0, hiddenVolumeBytes - 6.5 * 1024 ** 2);
      const totalOuter = [...state.outerFiles.values()].reduce((sum, f) => sum + f.size, 0);
      const totalHidden = [...state.hiddenFiles.values()].reduce((sum, f) => sum + f.size, 0);
      const isShort = totalOuter > outerApprox || totalHidden > hiddenApprox;
      hint.textContent = `Available: ~${formatBytes(outerApprox)} for cover files · ~${formatBytes(hiddenApprox)} for hidden files.`;
      hint.classList.toggle("capacity-short", isShort);
    }
  }

  function setVaultType(type) {
    state.vaultType = type;
    const isStandard = type === "standard";
    $("#vault-type-standard").classList.toggle("is-active", isStandard);
    $("#vault-type-standard").setAttribute("aria-selected", isStandard ? "true" : "false");
    $("#vault-type-deniable").classList.toggle("is-active", !isStandard);
    $("#vault-type-deniable").setAttribute("aria-selected", !isStandard ? "true" : "false");

    $("#standard-files-section").hidden = !isStandard;
    $("#deniable-files-section").hidden = isStandard;
    $("#standard-password-fields").hidden = !isStandard;
    $("#deniable-password-fields").hidden = isStandard;

    const noteText = $("#capacity-note-text");
    const submitText = $("#encrypt-submit-text");
    if (isStandard) {
      noteText.textContent = "DenyFS uses about half of the container for this vault. Actual free space is slightly lower because filesystem metadata also needs room.";
      submitText.textContent = "Encrypt files";
      if (!state.sizeTouched && state.files.size) {
        const total = [...state.files.values()].reduce((sum, f) => sum + f.size, 0);
        const reserve = 5.5 * 1024 ** 2;
        $("#vault-size").value = String(Math.max(8, Math.ceil(((total + reserve) * 2) / (1024 ** 2))));
      }
    } else {
      noteText.textContent = "DenyFS splits the container into an outer decoy volume (front half) and an invisible hidden volume (rear half). Both volumes are individually formatted and encrypted.";
      submitText.textContent = "Create double volume vault";
      adjustDeniableRecommendedSize();
    }
    updateCapacityHint();
  }

  function uploadFile(file, sessionId, index, count, priorBytes, totalBytes, phaseLabel = "Encrypting file") {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/encrypt/file");
      xhr.setRequestHeader("X-DenyFS-Session", sessionId);
      xhr.setRequestHeader("X-File-Name", encodeURIComponent(file.name));
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = event => {
        if (!event.lengthComputable) return;
        const percent = totalBytes ? ((priorBytes + event.loaded) / totalBytes) * 100 : (index / count) * 100;
        setBusyProgress(percent, `${phaseLabel} ${index} of ${count}: ${file.name}`);
      };
      xhr.onload = () => {
        let result = {};
        try { result = JSON.parse(xhr.responseText || "{}"); } catch { /* handled below */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(result);
        else reject(new Error(result.error || `Could not add ${file.name}.`));
      };
      xhr.onerror = () => reject(new Error(`The upload of ${file.name} was interrupted.`));
      xhr.onabort = () => reject(new Error(`The upload of ${file.name} was cancelled.`));
      xhr.send(file);
    });
  }

  async function encryptFiles() {
    clearError("#encrypt-error");
    const name = $("#vault-name").value.trim();
    if (!name) return showError("#encrypt-error", "Give this vault a name.");
    const sizeMiB = Number($("#vault-size").value);
    if (!Number.isInteger(sizeMiB) || sizeMiB < 8 || sizeMiB > 65536) {
      return showError("#encrypt-error", "Choose a container size between 8 and 65,536 MiB.");
    }

    if (state.vaultType === "standard") {
      await encryptStandardVault(name, sizeMiB);
    } else {
      await encryptDeniableVault(name, sizeMiB);
    }
  }

  async function encryptStandardVault(name, sizeMiB) {
    if (!state.files.size) return showError("#encrypt-error", "Choose at least one file to encrypt.");
    const passwordField = $("#encrypt-password");
    const confirmField = $("#confirm-password");
    const password = passwordField.value;
    const confirm = confirmField.value;
    const passwordBytes = new TextEncoder().encode(password).length;
    if (passwordBytes < 12) {
      return showError("#encrypt-error", "Use a passphrase with at least 12 UTF-8 bytes.");
    }
    if (passwordBytes > 511) return showError("#encrypt-error", "Passphrases can contain at most 511 UTF-8 bytes.");
    if (password !== confirm) return showError("#encrypt-error", "The passphrases do not match.");

    const files = [...state.files.values()];
    const totalBytes = files.reduce((sum, file) => sum + file.size, 0);
    setBusy(true, "Creating your encrypted vault…", "DenyFS is randomizing the full container and preparing its filesystem. Larger vaults take longer.", "STEP 1 OF 2 · PREPARING VAULT");
    let sessionId = null;
    let activeVaultName = null;
    try {
      const created = await jsonPost("/api/encrypt", {
        name,
        size_mib: sizeMiB,
        vault_type: "standard",
        password,
        files: files.map(file => ({ name: file.name, size: file.size })),
      });
      sessionId = created.session_id;
      activeVaultName = created.vault_name;
      setSession(sessionId, "encrypt", created.vault_name);
      passwordField.value = "";
      confirmField.value = "";
      $("#busy-title").textContent = "Encrypting your files…";
      $("#busy-eyebrow").textContent = "STEP 2 OF 2 · WRITING FILES";
      let priorBytes = 0;
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index];
        await uploadFile(file, sessionId, index + 1, files.length, priorBytes, totalBytes, "Encrypting file");
        priorBytes += file.size;
        setBusyProgress(totalBytes ? (priorBytes / totalBytes) * 100 : ((index + 1) / files.length) * 100,
          `Encrypted ${index + 1} of ${files.length} files.`);
      }
      await jsonPost("/api/encrypt/finish", {}, { "X-DenyFS-Session": sessionId });
      setSession(null, null, null);
      state.files.clear();
      state.sizeTouched = false;
      $("#vault-name").value = "My private vault";
      $("#vault-size").value = "64";
      renderSelectedFiles();
      await refreshVaults();
      setBusy(false);
      setView("library");
      toast(`“${created.vault_name}” is encrypted and locked.`);
    } catch (error) {
      await handleEncryptError(error, sessionId, activeVaultName, [passwordField, confirmField]);
    }
  }

  async function encryptDeniableVault(name, sizeMiB) {
    if (!state.outerFiles.size) return showError("#encrypt-error", "Select at least one cover file for the outer volume.");
    if (!state.hiddenFiles.size) return showError("#encrypt-error", "Select at least one private file for the hidden volume.");

    const outerPassField = $("#encrypt-outer-password");
    const confirmOuterField = $("#confirm-outer-password");
    const hiddenPassField = $("#encrypt-hidden-password");
    const confirmHiddenField = $("#confirm-hidden-password");

    const outerPassword = outerPassField.value;
    const confirmOuter = confirmOuterField.value;
    const hiddenPassword = hiddenPassField.value;
    const confirmHidden = confirmHiddenField.value;

    const outerBytes = new TextEncoder().encode(outerPassword).length;
    if (outerBytes < 12) return showError("#encrypt-error", "Outer passphrase must have at least 12 UTF-8 bytes.");
    if (outerBytes > 511) return showError("#encrypt-error", "Outer passphrase cannot exceed 511 UTF-8 bytes.");
    if (outerPassword !== confirmOuter) return showError("#encrypt-error", "Outer passphrases do not match.");

    const hiddenBytes = new TextEncoder().encode(hiddenPassword).length;
    if (hiddenBytes < 12) return showError("#encrypt-error", "Hidden passphrase must have at least 12 UTF-8 bytes.");
    if (hiddenBytes > 511) return showError("#encrypt-error", "Hidden passphrase cannot exceed 511 UTF-8 bytes.");
    if (hiddenPassword !== confirmHidden) return showError("#encrypt-error", "Hidden passphrases do not match.");

    if (outerPassword === hiddenPassword) {
      return showError("#encrypt-error", "Outer and hidden passphrases must be completely distinct.");
    }

    const outerFiles = [...state.outerFiles.values()];
    const hiddenFiles = [...state.hiddenFiles.values()];
    const totalOuterBytes = outerFiles.reduce((sum, f) => sum + f.size, 0);
    const totalHiddenBytes = hiddenFiles.reduce((sum, f) => sum + f.size, 0);

    setBusy(true, "Embedding double volumes…", "DenyFS is creating outer volume and initializing the hidden volume with separate Argon2id keys.", "STEP 1 OF 3 · PREPARING DUAL VOLUMES");
    let sessionId = null;
    let activeVaultName = null;
    try {
      const created = await jsonPost("/api/encrypt", {
        name,
        size_mib: sizeMiB,
        vault_type: "deniable",
        password: outerPassword,
        hidden_password: hiddenPassword,
        outer_files: outerFiles.map(f => ({ name: f.name, size: f.size })),
        hidden_files: hiddenFiles.map(f => ({ name: f.name, size: f.size })),
      });
      sessionId = created.session_id;
      activeVaultName = created.vault_name;
      setSession(sessionId, "encrypt", created.vault_name);
      outerPassField.value = "";
      confirmOuterField.value = "";
      hiddenPassField.value = "";
      confirmHiddenField.value = "";

      // Phase 1: Upload Outer / Cover Files
      $("#busy-title").textContent = "Encrypting cover files (outer volume)…";
      $("#busy-eyebrow").textContent = "STEP 2 OF 3 · COVER FILES";
      let outerPrior = 0;
      for (let i = 0; i < outerFiles.length; i += 1) {
        const file = outerFiles[i];
        await uploadFile(file, sessionId, i + 1, outerFiles.length, outerPrior, totalOuterBytes, "Cover file");
        outerPrior += file.size;
        setBusyProgress(totalOuterBytes ? (outerPrior / totalOuterBytes) * 100 : ((i + 1) / outerFiles.length) * 100,
          `Encrypted ${i + 1} of ${outerFiles.length} cover files.`);
      }

      // Transition to Hidden Volume Phase
      setBusy(true, "Switching to hidden volume…", "DenyFS is safely unmounting outer volume and mounting the hidden volume.", "SWITCHING ENCRYPTION PHASE");
      await jsonPost("/api/encrypt/switch-phase", {}, { "X-DenyFS-Session": sessionId });

      // Phase 2: Upload Hidden / Private Files
      $("#busy-title").textContent = "Encrypting private files (hidden volume)…";
      $("#busy-eyebrow").textContent = "STEP 3 OF 3 · PRIVATE FILES";
      let hiddenPrior = 0;
      for (let i = 0; i < hiddenFiles.length; i += 1) {
        const file = hiddenFiles[i];
        await uploadFile(file, sessionId, i + 1, hiddenFiles.length, hiddenPrior, totalHiddenBytes, "Private file");
        hiddenPrior += file.size;
        setBusyProgress(totalHiddenBytes ? (hiddenPrior / totalHiddenBytes) * 100 : ((i + 1) / hiddenFiles.length) * 100,
          `Encrypted ${i + 1} of ${hiddenFiles.length} private files.`);
      }

      // Finish session
      await jsonPost("/api/encrypt/finish", {}, { "X-DenyFS-Session": sessionId });
      setSession(null, null, null);
      state.outerFiles.clear();
      state.hiddenFiles.clear();
      state.sizeTouched = false;
      $("#vault-name").value = "My private vault";
      $("#vault-size").value = "64";
      renderOuterFiles();
      renderHiddenFiles();
      await refreshVaults();
      setBusy(false);
      setView("library");
      toast(`Deniable vault “${created.vault_name}” created with 2 independent volumes.`);
    } catch (error) {
      await handleEncryptError(error, sessionId, activeVaultName, [outerPassField, confirmOuterField, hiddenPassField, confirmHiddenField]);
    }
  }

  async function handleEncryptError(error, sessionId, activeVaultName, passFields) {
    let locked = false;
    if (sessionId) {
      try {
        await jsonPost("/api/session/lock", { session_id: sessionId });
        locked = true;
      } catch { /* preserve session token */ }
    }
    passFields.forEach(f => { if (f) f.value = ""; });
    setBusy(false);
    if (sessionId && locked) {
      setSession(null, null, null);
      await refreshVaults();
      showError("#encrypt-error", `${error.message} The vault was cleanly closed and locked.`);
    } else if (sessionId) {
      setSession(sessionId, "encrypt", activeVaultName);
      showError("#encrypt-error", `${error.message} The vault is still mounted; use Lock vault in the top bar.`);
    } else {
      await refreshVaults();
      showError("#encrypt-error", error.message);
    }
  }

  function showDecryptedFiles(files, vaultName, volumeType = "OUTER", protectActive = false) {
    $("#opened-vault-name").textContent = vaultName;
    $("#decrypt-submit").hidden = true;
    $("#opened-vault").hidden = false;

    // Badges & notification
    const badge = $("#opened-volume-badge");
    const protectBadge = $("#opened-protect-badge");
    const notice = $("#opened-volume-notice");
    const noticeText = $("#opened-volume-notice-text");

    const isHidden = volumeType === "HIDDEN";
    badge.textContent = isHidden ? "Hidden Volume" : "Outer Volume";
    badge.className = `vol-badge ${isHidden ? "vol-hidden" : "vol-outer"}`;

    protectBadge.hidden = !protectActive;

    if (isHidden) {
      notice.className = "volume-notice-bar is-hidden";
      noticeText.textContent = "Mounted hidden volume directly. Decoy cover files are invisible and unmounted.";
    } else if (protectActive) {
      notice.className = "volume-notice-bar is-protected";
      noticeText.textContent = "Mounted outer volume. Hidden volume sectors are write-protected against overwrite.";
    } else {
      notice.className = "volume-notice-bar";
      noticeText.textContent = "Mounted outer volume. (Hidden volume protection is off).";
    }

    const list = $("#decrypted-files");
    list.replaceChildren();
    if (!files.length) {
      const empty = document.createElement("li");
      empty.className = "empty-decrypted";
      empty.textContent = "This volume is empty.";
      list.append(empty);
      return;
    }
    files.forEach(file => {
      const row = document.createElement("li");
      row.className = "decrypted-file";
      const icon = document.createElement("span");
      icon.className = "file-type-icon";
      icon.innerHTML = icons.file;
      const info = document.createElement("span");
      info.className = "decrypted-file-info";
      const name = document.createElement("strong");
      name.textContent = file.name;
      const size = document.createElement("span");
      size.textContent = formatBytes(file.size);
      info.append(name, size);
      const link = document.createElement("a");
      link.className = "download-button";
      link.href = `/api/session/download?session_id=${encodeURIComponent(state.sessionId)}&name=${encodeURIComponent(file.name)}`;
      link.download = file.name;
      link.innerHTML = `${icons.download}<span>Decrypt & save</span>`;
      link.addEventListener("click", () => toast(`Decrypting “${file.name}”. Your browser will save the plaintext file.`));
      row.append(icon, info, link);
      list.append(row);
    });
  }

  async function decryptVault() {
    clearError("#decrypt-error");
    const vaultName = $("#decrypt-vault").value;
    const passwordField = $("#decrypt-password");
    const password = passwordField.value;
    if (!vaultName) return showError("#decrypt-error", "Choose a vault from your library, or import one first.");
    if (!password) return showError("#decrypt-error", "Enter the passphrase for this vault.");

    const protectCheckbox = $("#protect-hidden-checkbox");
    const protectPassField = $("#decrypt-hidden-password");
    const protectHidden = protectCheckbox ? protectCheckbox.checked : false;
    let hiddenPassword = null;
    if (protectHidden) {
      hiddenPassword = protectPassField.value;
      if (!hiddenPassword) {
        return showError("#decrypt-error", "Enter the hidden passphrase to enable sector protection.");
      }
      if (password === hiddenPassword) {
        return showError("#decrypt-error", "Outer and hidden passphrases must be distinct to protect hidden volume.");
      }
    }

    setBusy(true, "Unlocking your vault…", "DenyFS is deriving the key and mounting your encrypted files locally.", "AUTHENTICATING LOCALLY");
    try {
      const payload = { vault_name: vaultName, password };
      if (protectHidden) {
        payload.protect_hidden = true;
        payload.hidden_password = hiddenPassword;
      }
      const result = await jsonPost("/api/decrypt", payload);
      passwordField.value = "";
      if (protectPassField) protectPassField.value = "";
      setSession(result.session_id, "decrypt", result.vault_name);
      showDecryptedFiles(result.files, result.vault_name, result.volume_type, result.protect_active);
      setBusy(false);
      const volName = result.volume_type === "HIDDEN" ? "Hidden volume" : "Outer volume";
      toast(`“${result.vault_name}” is unlocked (${volName}). Choose a file to decrypt and save.`);
    } catch (error) {
      passwordField.value = "";
      if (protectPassField) protectPassField.value = "";
      setBusy(false);
      showError("#decrypt-error", error.message);
    }
  }

  async function lockVault() {
    if (!state.sessionId) return;
    const id = state.sessionId;
    const previousMode = state.sessionMode;
    setBusy(true, "Locking your vault…", "DenyFS is flushing changes and unmounting this vault.", "CLOSING SECURE SESSION");
    try {
      await jsonPost("/api/session/lock", { session_id: id });
      setSession(null, null, null);
      $("#opened-vault").hidden = true;
      $("#decrypt-submit").hidden = false;
      $("#decrypt-password").value = "";
      const protectPassField = $("#decrypt-hidden-password");
      if (protectPassField) protectPassField.value = "";
      if (previousMode === "encrypt") await refreshVaults();
      setBusy(false);
      toast("Vault locked. Its encrypted container remains in your local library.");
    } catch (error) {
      setBusy(false);
      toast(error.message, "error");
    }
  }

  function importVaultFile(file) {
    if (!file) return;
    const progress = $("#import-progress");
    const bar = $("#import-progress-bar");
    const label = $("#import-progress-label");
    const percent = $("#import-progress-percent");
    progress.hidden = false;
    label.textContent = `Importing ${file.name}…`;
    percent.textContent = "0%";
    bar.style.width = "0%";
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/vaults/import?name=${encodeURIComponent(file.name)}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = event => {
      if (!event.lengthComputable) return;
      const value = Math.round((event.loaded / event.total) * 100);
      bar.style.width = `${value}%`;
      percent.textContent = `${value}%`;
    };
    xhr.onload = async () => {
      let result = {};
      try { result = JSON.parse(xhr.responseText || "{}"); } catch { /* display generic response below */ }
      progress.hidden = true;
      if (xhr.status < 200 || xhr.status >= 300) {
        toast(result.error || "Could not import that container.", "error");
        return;
      }
      await refreshVaults();
      $("#decrypt-vault").value = result.name;
      toast(`${result.name} added to your local vault library.`);
    };
    xhr.onerror = () => {
      progress.hidden = true;
      toast("The container import was interrupted.", "error");
    };
    xhr.send(file);
  }

  function updateNavFromStatus() {
    $("#top-lock-button").addEventListener("click", lockVault);
  }

  // Bind view navigation and reveal buttons
  $$("[data-view]").forEach(button => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-reveal]").forEach(button => button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.reveal);
    if (!input) return;
    input.type = input.type === "password" ? "text" : "password";
    button.setAttribute("aria-label", input.type === "password" ? "Show passphrase" : "Hide passphrase");
  }));

  // Vault architecture tabs
  $("#vault-type-standard").addEventListener("click", () => setVaultType("standard"));
  $("#vault-type-deniable").addEventListener("click", () => setVaultType("deniable"));

  // Standard File Dropzone
  const fileInput = $("#encrypt-file-input");
  const dropzone = $("#dropzone");
  $("#browse-files").addEventListener("click", event => { event.stopPropagation(); fileInput.click(); });
  dropzone.addEventListener("click", event => { if (event.target !== $("#browse-files")) fileInput.click(); });
  dropzone.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });
  $("#clear-files").addEventListener("click", () => { state.files.clear(); renderSelectedFiles(); });
  ["dragenter", "dragover"].forEach(name => dropzone.addEventListener(name, event => {
    event.preventDefault();
    dropzone.classList.add("is-dragging");
  }));
  ["dragleave", "drop"].forEach(name => dropzone.addEventListener(name, event => {
    event.preventDefault();
    dropzone.classList.remove("is-dragging");
  }));
  dropzone.addEventListener("drop", event => addFiles(event.dataTransfer.files));

  // Deniable Outer Dropzone
  const outerFileInput = $("#encrypt-outer-input");
  const dropzoneOuter = $("#dropzone-outer");
  $("#browse-outer-files").addEventListener("click", event => { event.stopPropagation(); outerFileInput.click(); });
  dropzoneOuter.addEventListener("click", event => { if (event.target !== $("#browse-outer-files")) outerFileInput.click(); });
  dropzoneOuter.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); outerFileInput.click(); }
  });
  outerFileInput.addEventListener("change", () => { addOuterFiles(outerFileInput.files); outerFileInput.value = ""; });
  $("#clear-outer-files").addEventListener("click", () => { state.outerFiles.clear(); renderOuterFiles(); });
  ["dragenter", "dragover"].forEach(name => dropzoneOuter.addEventListener(name, event => {
    event.preventDefault();
    dropzoneOuter.classList.add("is-dragging");
  }));
  ["dragleave", "drop"].forEach(name => dropzoneOuter.addEventListener(name, event => {
    event.preventDefault();
    dropzoneOuter.classList.remove("is-dragging");
  }));
  dropzoneOuter.addEventListener("drop", event => addOuterFiles(event.dataTransfer.files));

  // Deniable Hidden Dropzone
  const hiddenFileInput = $("#encrypt-hidden-input");
  const dropzoneHidden = $("#dropzone-hidden");
  $("#browse-hidden-files").addEventListener("click", event => { event.stopPropagation(); hiddenFileInput.click(); });
  dropzoneHidden.addEventListener("click", event => { if (event.target !== $("#browse-hidden-files")) hiddenFileInput.click(); });
  dropzoneHidden.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); hiddenFileInput.click(); }
  });
  hiddenFileInput.addEventListener("change", () => { addHiddenFiles(hiddenFileInput.files); hiddenFileInput.value = ""; });
  $("#clear-hidden-files").addEventListener("click", () => { state.hiddenFiles.clear(); renderHiddenFiles(); });
  ["dragenter", "dragover"].forEach(name => dropzoneHidden.addEventListener(name, event => {
    event.preventDefault();
    dropzoneHidden.classList.add("is-dragging");
  }));
  ["dragleave", "drop"].forEach(name => dropzoneHidden.addEventListener(name, event => {
    event.preventDefault();
    dropzoneHidden.classList.remove("is-dragging");
  }));
  dropzoneHidden.addEventListener("drop", event => addHiddenFiles(event.dataTransfer.files));

  // Protect Hidden Volume checkbox
  const protectCheckbox = $("#protect-hidden-checkbox");
  if (protectCheckbox) {
    protectCheckbox.addEventListener("change", () => {
      $("#protect-hidden-pass-wrap").hidden = !protectCheckbox.checked;
      if (protectCheckbox.checked) {
        $("#decrypt-hidden-password").focus();
      }
    });
  }

  // Vault size input
  $("#vault-size").addEventListener("input", () => {
    state.sizeTouched = true;
    updateCapacityHint();
  });

  // Action buttons
  $("#encrypt-submit").addEventListener("click", encryptFiles);
  $("#decrypt-submit").addEventListener("click", decryptVault);
  $("#lock-vault").addEventListener("click", lockVault);
  $("#import-vault-button").addEventListener("click", () => $("#import-vault-input").click());
  $("#library-import-button").addEventListener("click", () => $("#import-vault-input").click());
  $("#import-vault-input").addEventListener("change", event => {
    importVaultFile(event.target.files[0]);
    event.target.value = "";
  });
  $(".mini-heading button").addEventListener("click", () => setView("library"));

  updateNavFromStatus();
  updateCapacityHint();
  refreshVaults();
  refreshStatus();
})();
