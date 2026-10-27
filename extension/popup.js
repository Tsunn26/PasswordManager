
// Lay cac phan tu giao dien theo ID.
const $ = (id) => document.getElementById(id);

let editingId = null;
let accounts = [];

// ID tai khoan dang yeu cau xem mat khau.
let revealingId = null;

// Bo dem tu dong an mat khau.
let revealTimer = null;

// Ten Native Host phai trung voi host.json.
const HOST_NAME = "com.passwordmanager.host";

// Ket noi Native Messaging va hang doi phan hoi.
let nativePort = null;
let pendingRequests = [];

// Bien luu bo dem thoi gian an thong bao.
let messageTimer = null;

// Hien thi thong bao va tu dong an sau 3 giay.
function showMessage(text, success = false) {
    const el = $("message");

    // Huy bo dem cu neu co thong bao moi.
    if (messageTimer !== null) {
        clearTimeout(messageTimer);
        messageTimer = null;
    }

    el.textContent = text;
    el.className = success ? "success" : "error";

    // Neu xoa thong bao thi khong can hen gio.
    if (!text) {
        return;
    }

    messageTimer = setTimeout(() => {
        el.textContent = "";
        el.className = "";
        messageTimer = null;
    }, 3000);
}

// Hien thi man hinh theo trang thai Vault.
function showScreen(screen) {
    console.log("Chuyen man hinh sang:", screen);
    console.trace("Vi tri goi showScreen");

    for (const id of [
        "create-screen",
        "unlock-screen",
        "vault-screen"
    ]) {
        $(id).hidden = id !== screen;
    }
}

// Tao ket noi truc tiep tu Popup den Python Native Host.
// Ket noi chi ton tai trong phien Popup hien tai.
function connectHost() {
    if (nativePort) {
        return nativePort;
    }

    const port = chrome.runtime.connectNative(HOST_NAME);
    nativePort = port;

    // Nhan phan hoi tu Python va xu ly request dang cho.
    port.onMessage.addListener((response) => {
        const pending = pendingRequests.shift();

        if (pending) {
            pending.resolve(response);
        }
    });

    // Xu ly loi khi Native Host ngat ket noi.
    port.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError?.message
            || "Mất kết nối với Python.";

        if (nativePort === port) {
            nativePort = null;
        }

        const requests = pendingRequests;
        pendingRequests = [];

        for (const pending of requests) {
            pending.reject(new Error(error));
        }
    });

    return port;
}


// Gui request den Python va cho phan hoi.
// Bao loi neu Backend tu choi hoac khong ket noi duoc.
async function sendRequest(request) {
    const port = connectHost();

    const response = await new Promise((resolve, reject) => {
        const pending = { resolve, reject };
        pendingRequests.push(pending);

        try {
            port.postMessage(request);
        } catch (error) {
            pendingRequests = pendingRequests.filter(
                (item) => item !== pending
            );
            reject(error);
        }
    });

    if (!response || response.success !== true) {
        throw new Error(
            response?.error || "Không kết nối được Backend."
        );
    }

    return response;
}

// Tao nut chuyen doi giua man hinh Tao Vault va Mo khoa.
// Mac dinh hien man hinh Mo khoa.
function setupNavigation() {
    const toCreate = document.createElement("button");
    toCreate.type = "button";
    toCreate.className = "secondary";
    toCreate.textContent = "Chưa có Vault? Tạo mới";
    toCreate.onclick = () => {
        showMessage("");
        showScreen("create-screen");
    };

    $("unlock-screen").appendChild(toCreate);

    const toUnlock = document.createElement("button");
    toUnlock.type = "button";
    toUnlock.className = "secondary";
    toUnlock.textContent = "Đã có Vault? Mở khóa";
    toUnlock.onclick = () => {
        showMessage("");
        showScreen("unlock-screen");
    };

    $("create-screen").appendChild(toUnlock);
    showScreen("unlock-screen");
}

// Tao Vault bang Master Password.
async function createVault(event) {
    event.preventDefault();

    try {
        await sendRequest({
            action: "create_vault",
            master_password: $("create-master").value
        });

        $("create-master").value = "";
        showScreen("unlock-screen");
        showMessage("Tạo Vault thành công. Hãy mở khóa.", true);
    } catch (error) {
        showMessage(error.message);
    }
}


 // Mo khoa Vault bang Master Password.
 // Xoa thong bao loi cu khi mo khoa thanh cong.
async function unlockVault(event) {
    event.preventDefault();

    try {
        await sendRequest({
            action: "unlock_vault",
            master_password: $("unlock-master").value
        });

        // Xoa Master Password khoi o nhap.
        $("unlock-master").value = "";

        // Chuyen sang man hinh quan ly tai khoan.
        showScreen("vault-screen");

        // Xoa thong bao loi cu.
        showMessage("");

        // Tai danh sach tai khoan.
        await loadAccounts();

        // Thong bao mo khoa thanh cong.
        showMessage("Mở khóa Vault thành công.", true);

    } catch (error) {
        showMessage(error.message);
    }
}


// Khoa Vault va xoa du lieu dang hien thi.
async function lockVault() {
    try {
        await sendRequest({
            action: "lock_vault"
        });

        // Xoa du lieu tai khoan tren giao dien.
        accounts = [];
        $("account-list").replaceChildren();

        // Xoa form dang nhap va chinh sua.
        $("unlock-master").value = "";
        resetForm();

        // Chuyen ve man hinh mo khoa.
        showScreen("unlock-screen");

        // Cap nhat thong bao.
        showMessage("Đã khóa Vault.", true);

    } catch (error) {
        showMessage(error.message);
    }
}

// Lay danh sach tai khoan tu Backend.
async function loadAccounts(keyword = "") {
    try {
        const request = keyword.trim()
            ? { action: "search_password", keyword }
            : { action: "get_passwords" };

        const result = await sendRequest(request);

        // Kiem tra so luong tai khoan Backend tra ve.
        console.log("So tai khoan:", result.accounts?.length);
        console.log(
            "Cac truong du lieu:",
            result.accounts?.[0]
                ? Object.keys(result.accounts[0])
                : []
        );

        accounts = result.accounts;
        renderAccounts();
    } catch (error) {
        showMessage(error.message);
    }
}

// Tao danh sach tai khoan bang DOM an toan.
// Khong dung innerHTML voi du lieu nguoi dung.
function renderAccounts() {
    const list = $("account-list");
    list.replaceChildren();

    if (accounts.length === 0) {
        const empty = document.createElement("li");
        empty.textContent = "Chưa có tài khoản.";
        list.appendChild(empty);
        return;
    }

    for (const account of accounts) {
        const item = document.createElement("li");
        item.className = "account-item";
        item.dataset.accountId = String(account.id);

        const title = document.createElement("strong");
        title.textContent = account.website;

        const info = document.createElement("p");
        info.textContent = `${account.username} | ••••••••`;
        info.className = "account-info";

        const actions = document.createElement("div");
        actions.className = "account-actions";

        const editBtn = document.createElement("button");
        editBtn.type = "button";
        editBtn.textContent = "Sửa";
        editBtn.onclick = () => editAccount(account);

        // Tao nut Xem mat khau.
        const viewBtn = document.createElement("button");
        viewBtn.type = "button";
        viewBtn.className = "secondary";
        viewBtn.textContent = "👁 Xem";

        viewBtn.onclick = () => {
            showRevealForm(account.id);
        };

        const deleteBtn = document.createElement("button");
        deleteBtn.type = "button";
        deleteBtn.className = "secondary";
        deleteBtn.textContent = "Xóa";
        deleteBtn.onclick = () => deleteAccount(account.id);

        actions.append(viewBtn, editBtn, deleteBtn);
        item.append(title, info, actions);
        list.appendChild(item);
    }
}

// Hien form nhap lai Master Password.
function showRevealForm(accountId) {
    // Huy bo dem hien thi mat khau cu.
    clearTimeout(revealTimer);
    revealTimer = null;

    revealingId = accountId;

    // Xoa Master Password da nhap truoc do.
    $("reveal-master").value = "";

    // Hien form xac minh.
    $("reveal-section").hidden = false;

    // Dua con tro vao o nhap.
    $("reveal-master").focus();

    showMessage("");
}


// Huy thao tac xem mat khau.
function cancelReveal() {
    revealingId = null;

    clearTimeout(revealTimer);
    revealTimer = null;

    $("reveal-master").value = "";
    $("reveal-section").hidden = true;

    // Tai lai danh sach de che mat khau.
    renderAccounts();
}

// Xac minh Master Password va hien mat khau.
async function revealPassword(event) {
    // Ngan form tai lai trang.
    event.preventDefault();

    if (revealingId === null) {
        showMessage("Chưa chọn tài khoản cần xem.");
        return;
    }

    const accountId = revealingId;
    const masterPassword = $("reveal-master").value;

    try {
        const result = await sendRequest({
            action: "reveal_password",
            id: accountId,
            master_password: masterPassword
        });

        // Xoa Master Password khoi o nhap.
        $("reveal-master").value = "";

        // Dong form xac minh.
        $("reveal-section").hidden = true;
        revealingId = null;

        // Tim tai khoan dang hien thi.
        const account = accounts.find(a => a.id === accountId);

        if (!account) {
            showMessage("Không tìm thấy tài khoản.");
            return;
        }

        // Tim dung dong tai khoan theo ID.
        const item = [...$("account-list").children].find(
            li => li.dataset.accountId === String(accountId)
        );

        if (!item) {
            showMessage("Không tìm thấy tài khoản trên giao diện.");
            return;
        }

        const info = item.querySelector(".account-info");

        if (!info) {
            showMessage("Không tìm thấy vị trí hiển thị mật khẩu.");
            return;
        }

        // Hien mat khau trong 10 giay.
        info.textContent = `${account.username} | ${result.password}`;

        clearTimeout(revealTimer);

        revealTimer = setTimeout(() => {
            info.textContent = `${account.username} | ••••••••`;
            revealTimer = null;
        }, 10000);

    } catch (error) {
        $("reveal-master").value = "";
        showMessage(error.message);
    }
}

// Chuyen form sang che do chinh sua tai khoan.
function editAccount(account) {
    editingId = account.id;

    $("website").value = account.website;
    $("username").value = account.username;
    $("password").value = account.password;
    $("note").value = account.note || "";

    $("form-title").textContent = "Sửa tài khoản";
    $("save-btn").textContent = "Cập nhật";
    $("cancel-btn").hidden = false;
}

// Xoa noi dung form va quay lai che do them moi.
function resetForm() {
    editingId = null;

    $("account-form").reset();
    $("form-title").textContent = "Thêm tài khoản";
    $("save-btn").textContent = "Lưu tài khoản";
    $("cancel-btn").hidden = true;
}

// Them moi hoac cap nhat tai khoan.
async function saveAccount(event) {
    event.preventDefault();

    const request = {
        action: editingId === null
            ? "add_password"
            : "update_password",
        website: $("website").value,
        username: $("username").value,
        password: $("password").value,
        note: $("note").value
    };

    if (editingId !== null) {
        request.id = editingId;
    }

    try {
        const result = await sendRequest(request);

        // Chi khi them moi Backend moi tra ve trang thai kiem tra trung.
        if (editingId === null) {
            // Trung ca website, username va password: chi bao, khong luu.
            if (result.status === "duplicate_same_password") {
                showMessage(
                    "Tài khoản này đã tồn tại với cùng mật khẩu."
                );
                return;
            }

            // Trung website + username nhung khac password: hoi cap nhat.
            if (result.status === "duplicate_diff_password") {
                await confirmUpdateExisting(result.id, request);
                return;
            }
        }

        resetForm();
        await loadAccounts($("search-input").value);
        showMessage("Lưu tài khoản thành công.", true);
    } catch (error) {
        showMessage(error.message);
    }
}

// Hoi nguoi dung co muon cap nhat mat khau cua tai khoan da ton tai.
// existingId la ID ban ghi trung do Backend tra ve.
async function confirmUpdateExisting(existingId, request) {
    const agreed = confirm(
        "Tài khoản này (cùng website và username) đã tồn tại " +
        "nhưng khác mật khẩu.\n\nBạn có muốn cập nhật mật khẩu mới không?"
    );

    if (!agreed) {
        showMessage("Đã giữ nguyên mật khẩu cũ.");
        return;
    }

    const updateRequest = {
        action: "update_password",
        id: existingId,
        password: request.password
    };

    // Chi ghi de ghi chu khi nguoi dung co nhap ghi chu moi.
    if (request.note) {
        updateRequest.note = request.note;
    }

    await sendRequest(updateRequest);

    resetForm();
    await loadAccounts($("search-input").value);
    showMessage("Đã cập nhật mật khẩu.", true);
}

// Xoa tai khoan sau khi nguoi dung xac nhan.
async function deleteAccount(id) {
    if (!confirm("Bạn có chắc muốn xóa tài khoản?")) {
        return;
    }

    try {
        await sendRequest({
            action: "delete_password",
            id
        });

        resetForm();
        await loadAccounts($("search-input").value);
        showMessage("Đã xóa tài khoản.", true);
    } catch (error) {
        showMessage(error.message);
    }
}

// Dang ky su kien cho cac form va nut bam.
function init() {
    setupNavigation();

    $("create-form").addEventListener("submit", createVault);
    $("unlock-form").addEventListener("submit", unlockVault);
    $("account-form").addEventListener("submit", saveAccount);
    $("lock-btn").addEventListener("click", lockVault);
    $("cancel-btn").addEventListener("click", resetForm);
    $("cancel-reveal").addEventListener("click", cancelReveal);
    $("reveal-form").addEventListener("submit", revealPassword);

    $("search-input").addEventListener("input", (event) => {
        loadAccounts(event.target.value);
    });
}

document.addEventListener("DOMContentLoaded", init);
