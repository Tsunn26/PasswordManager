
// Native Host name - phai trung voi host.json
const HOST_NAME = "com.passwordmanager.host";

// Ket noi lau dai voi Python Native Host.
let nativePort = null;
let pendingRequests = [];

// Tao ket noi Native Messaging neu chua co.
function connectHost() {
    if (nativePort) return nativePort;

    const port = chrome.runtime.connectNative(HOST_NAME);
    nativePort = port;

    // Nhan ket qua tu Python va chuyen ve Popup.
    port.onMessage.addListener((response) => {
        const callback = pendingRequests.shift();

        if (callback) {
            callback(response);
        }
    });

    // Xu ly khi mat ket noi Native Host.
    port.onDisconnect.addListener(() => {
        const error = chrome.runtime.lastError?.message
            || "Mất kết nối với Python Native Host.";

        if (nativePort === port) {
            nativePort = null;
        }

        const requests = pendingRequests;
        pendingRequests = [];

        for (const callback of requests) {
            callback({
                success: false,
                error
            });
        }
    });

    return port;
}

// Nhan yeu cau tu popup.js va chuyen cho Python.
chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {
        // Chi nhan thong diep tu chinh Extension.
        if (sender.id !== chrome.runtime.id) {
            return false;
        }

        try {
            const port = connectHost();

            pendingRequests.push(sendResponse);
            port.postMessage(request);

        } catch (error) {
            sendResponse({
                success: false,
                error: error.message
            });
            return false;
        }

        // Giu kenh phan hoi bat dong bo.
        return true;
    }
);
