/*
 * AAG_Sandbox.cpp — A.A.G Overlay System Security Sandbox
 * Target:    ESP32-2432S028 (CYD) running Marauder firmware
 * Purpose:   SHA-256 signature verification + memory-safe app loading
 *
 * All crypto uses ESP32 hardware-accelerated mbedtls.
 * All file I/O is streaming (512-byte chunks) to protect heap.
 * Verification task runs at LOW PRIORITY (tskIDLE_PRIORITY + 1)
 * to avoid starving the Marauder's Wi-Fi / RF sniffing tasks.
 *
 * Security model: VERIFY BEFORE LOAD — fail-closed.
 * All signature comparisons are constant-time to prevent timing attacks.
 * All file paths are sanitized — directory traversal is rejected.
 *
 * Dependencies (already present in ESP32 Arduino core / Marauder build):
 *   - mbedtls/sha256.h  (ESP32 hardware-accelerated)
 *   - FS.h, SD.h        (Marauder platformio.ini)
 *   - FreeRTOS          (ESP32 Arduino core)
 */

#include "AAG_System_Wrapper.h"

#ifdef ENABLE_AAG_OVERLAY

#include <mbedtls/sha256.h>
#include <FS.h>
#include <SD.h>

/* ============================================================
 * Constants (uses AAG_HEAP_MARGIN from header = 10240)
 * ============================================================ */

// Streaming read chunk size for hash computation
#define AAG_CHUNK_SIZE         512

// Maximum allowed file path length (including null terminator)
#define AAG_MAX_PATH_LEN       128

// Sandbox verification queue depth
#define AAG_SANDBOX_QUEUE_LEN  4

// Maximum length of a queued file path
#define AAG_QUEUE_PATH_LEN     128

// ============================================================
// Forward declarations
// ============================================================

static bool aag_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);
static int  aag_hex_char_to_val(char c);
static bool aag_sanitize_path(const char* path);
static void aag_hash_to_hex(const uint8_t hash[32], char out[65]);

// ============================================================
// Internal types
// ============================================================

// Queue item for asynchronous verification requests
struct aag_verify_request_t {
    char bin_path[AAG_QUEUE_PATH_LEN];  // Path to .bin file
    char sig_path[AAG_QUEUE_PATH_LEN];  // Path to .sig file
    bool result;                         // Set by sandbox task on completion
    volatile bool completed;             // Set true when processing done
    TaskHandle_t caller_handle;          // For xTaskNotify() in blocking verify
};

// ============================================================
// Module state
// ============================================================

static QueueHandle_t s_sandbox_queue = NULL;
static TaskHandle_t  s_sandbox_task  = NULL;
static bool          s_sandbox_ready = false;

/* ============================================================
 * Static helper: convert hex character to 4-bit nibble
 * Returns -1 for non-hex characters.
 * ============================================================ */
static int aag_hex_char_to_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;  // invalid hex character
}

/* ============================================================
 * Static helper: binary hash to hex string (for debug output)
 * out must be at least 65 bytes (64 hex chars + '\0').
 * ============================================================ */
static void aag_hash_to_hex(const uint8_t hash[32], char out[65])
{
    static const char hex_lut[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex_lut[hash[i] >> 4];
        out[i * 2 + 1] = hex_lut[hash[i] & 0x0F];
    }
    out[64] = '\0';
}

/* ============================================================
 * Static helper: constant-time byte comparison
 * Do NOT use memcmp() — it short-circuits on mismatch.
 * XOR accumulate ensures identical execution time regardless
 * of where (or if) bytes differ.
 * ============================================================ */
static bool aag_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len)
{
    if (!a || !b) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (diff == 0);
}

/* ============================================================
 * Static helper: sanitize file path
 * Rejects:
 *   - NULL or empty paths
 *   - Paths exceeding AAG_MAX_PATH_LEN
 *   - Directory traversal sequences ("..")
 *   - Null bytes
 * Only allows printable ASCII characters.
 * ============================================================ */
static bool aag_sanitize_path(const char* path)
{
    if (!path || path[0] == '\0') return false;

    size_t len = strlen(path);
    if (len == 0 || len >= AAG_MAX_PATH_LEN) return false;

    for (size_t i = 0; i < len; i++) {
        char c = path[i];
        // Reject non-printable characters (null already excluded by strlen)
        if (c < 32 || c > 126) return false;
    }

    // Reject directory traversal patterns
    if (strstr(path, "..") != NULL) return false;

    return true;
}

/* ============================================================
 * aag_check_heap()
 * Verify sufficient free heap before any allocation-heavy op.
 * Always leave AAG_HEAP_MARGIN available for system/Wi-Fi use.
 * ============================================================ */
bool aag_check_heap(size_t required)
{
    size_t free_heap = xPortGetFreeHeapSize();
    return (free_heap >= (required + AAG_HEAP_MARGIN));
}

/* ============================================================
 * aag_read_sig_file()
 * Read a .sig file containing exactly 64 hex characters and
 * convert to raw 32-byte binary hash.
 * Returns false on any I/O error or malformed content.
 * ============================================================ */
/* Forward declaration not in header (internal helper) */
static bool aag_sanitize_path(const char* path);

/* ============================================================
 * aag_read_sig_file()
 * ============================================================ */
bool aag_read_sig_file(const char* sig_path, uint8_t out_hash[32])
{
    if (!sig_path || !out_hash) return false;
    if (!aag_sanitize_path(sig_path)) {
        Serial.println("[AAG] Signature file path rejected by sanitizer");
        return false;
    }

    File f = SD.open(sig_path, FILE_READ);
    if (!f) {
        Serial.printf("[AAG] Failed to open sig file: %s\n", sig_path);
        return false;
    }

    // Signature file must contain exactly 64 hex chars
    size_t file_size = f.size();
    if (file_size < 64) {
        Serial.printf("[AAG] Signature file too small (%d bytes)\n", (int)file_size);
        f.close();
        return false;
    }

    char hex_buf[65];
    memset(hex_buf, 0, sizeof(hex_buf));

    size_t read = f.read((uint8_t*)hex_buf, 64);
    f.close();

    if (read != 64) {
        Serial.printf("[AAG] Short read on sig file (%d bytes)\n", (int)read);
        return false;
    }

    // Parse 64 hex characters into 32 bytes
    for (int i = 0; i < 32; i++) {
        int hi = aag_hex_char_to_val(hex_buf[i * 2]);
        int lo = aag_hex_char_to_val(hex_buf[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            Serial.println("[AAG] Invalid hex character in signature file");
            return false;
        }
        out_hash[i] = (uint8_t)((hi << 4) | lo);
    }

    return true;
}

/* ============================================================
 * aag_verify_app_signature()
 * SYNCHRONOUS (blocking) SHA-256 verification of a .bin file.
 *
 * 1. Validate and sanitize paths
 * 2. Verify .sig file exists
 * 3. Stream .bin in 512-byte chunks, compute SHA-256
 * 4. Yield (vTaskDelay) between blocks to protect RF tasks
 * 5. Read expected hash from .sig file
 * 6. Constant-time compare
 *
 * Returns true only if signature is valid and all I/O succeeded.
 * ============================================================ */
bool aag_verify_app_signature(const char* bin_path, const char* sig_path)
{
    if (!bin_path || !sig_path) return false;

    // --- Path sanitization ---
    if (!aag_sanitize_path(bin_path)) {
        Serial.println("[AAG] Binary path rejected by sanitizer");
        return false;
    }
    if (!aag_sanitize_path(sig_path)) {
        Serial.println("[AAG] Signature path rejected by sanitizer");
        return false;
    }

    // --- Check that .sig file exists and is readable ---
    if (!SD.exists(sig_path)) {
        Serial.printf("[AAG] Signature file not found: %s\n", sig_path);
        return false;
    }

    // --- Read expected hash from signature file ---
    uint8_t expected_hash[32];
    if (!aag_read_sig_file(sig_path, expected_hash)) {
        Serial.println("[AAG] Failed to read/parse signature file");
        return false;
    }

    // --- Open binary file for streaming hash ---
    File bin_file = SD.open(bin_path, FILE_READ);
    if (!bin_file) {
        Serial.printf("[AAG] Failed to open binary: %s\n", bin_path);
        return false;
    }

    size_t bin_size = bin_file.size();
    if (bin_size == 0) {
        Serial.println("[AAG] Binary file is empty");
        bin_file.close();
        return false;
    }

    Serial.printf("[AAG] Verifying %s (%d bytes)...\n", bin_path, (int)bin_size);

    // --- Streaming SHA-256 using hardware-accelerated mbedtls ---
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts_ret(&ctx, 0);  // 0 = SHA-256
    if (ret != 0) {
        Serial.printf("[AAG] mbedtls_sha256_starts_ret failed: %d\n", ret);
        mbedtls_sha256_free(&ctx);
        bin_file.close();
        return false;
    }

    uint8_t buffer[AAG_CHUNK_SIZE];
    size_t total_read = 0;
    uint32_t block_count = 0;

    while (bin_file.available()) {
        size_t n = bin_file.read(buffer, sizeof(buffer));
        if (n == 0) break;

        ret = mbedtls_sha256_update_ret(&ctx, buffer, n);
        if (ret != 0) {
            Serial.printf("[AAG] mbedtls_sha256_update_ret failed: %d\n", ret);
            mbedtls_sha256_free(&ctx);
            bin_file.close();
            return false;
        }

        total_read += n;
        block_count++;

        // Yield to Wi-Fi/RF tasks every block — critical for system stability
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    bin_file.close();

    // Finalize hash
    uint8_t computed_hash[32];
    ret = mbedtls_sha256_finish_ret(&ctx, computed_hash);
    mbedtls_sha256_free(&ctx);

    if (ret != 0) {
        Serial.printf("[AAG] mbedtls_sha256_finish_ret failed: %d\n", ret);
        return false;
    }

    Serial.printf("[AAG] Hashed %d bytes in %lu blocks\n", (int)total_read, block_count);

    // Debug: print hashes (only in non-constant-time context)
#if AAG_DEBUG_HASH
    char hash_hex[65];
    aag_hash_to_hex(computed_hash, hash_hex);
    Serial.printf("[AAG] Computed: %s\n", hash_hex);
    aag_hash_to_hex(expected_hash, hash_hex);
    Serial.printf("[AAG] Expected: %s\n", hash_hex);
#endif

    // --- Constant-time signature comparison ---
    bool valid = aag_constant_time_compare(computed_hash, expected_hash, 32);

    if (valid) {
        Serial.println("[AAG] Signature VALID");
    } else {
        Serial.println("[AAG] Signature MISMATCH — binary has been modified");
    }

    // Zero sensitive data from stack
    memset(computed_hash, 0, sizeof(computed_hash));
    memset(buffer, 0, sizeof(buffer));

    return valid;
}

/* ============================================================
 * aag_sandbox_task()
 * FreeRTOS background task that processes the verification queue.
 *
 * Runs continuously at tskIDLE_PRIORITY + 1 to avoid
 * interfering with Marauder's Wi-Fi/RF work.
 *
 * When a request is received:
 *   - Calls aag_verify_app_signature() synchronously
 *   - Writes result back into request struct
 *   - Marks request as completed
 * ============================================================ */
void aag_sandbox_task(void* pvParameters)
{
    (void)pvParameters;

    Serial.println("[AAG] Sandbox verification task started");

    aag_verify_request_t req;

    for (;;) {
        // Block indefinitely waiting for a verification request
        BaseType_t rc = xQueueReceive(s_sandbox_queue, &req, portMAX_DELAY);

        if (rc == pdPASS) {
            Serial.printf("[AAG] Sandbox processing: %s\n", req.bin_path);

            // Perform the actual verification (blocking within this task)
            bool ok = aag_verify_app_signature(req.bin_path, req.sig_path);

            // Write result back and mark completed
            req.result    = ok;
            req.completed = true;

            // Notify blocking caller if present
            if (req.caller_handle != NULL) {
                xTaskNotify(req.caller_handle, ok ? 1 : 0, eSetValueWithOverwrite);
            }

            // Update overlay app status via callback
            extern void aag_report_verification_result(const char* bin_path, bool verified);
            aag_report_verification_result(req.bin_path, ok);

            Serial.printf("[AAG] Sandbox result for %s: %s\n",
                          req.bin_path, ok ? "VALID" : "INVALID");
        }

        // Brief yield at end of each loop iteration
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

/* ============================================================
 * aag_init_sandbox()
 * Initialize the sandbox subsystem.
 * Creates the verification queue and starts the background task.
 * Call once during system boot (from aag_system_init() or setup()).
 * ============================================================ */
bool aag_init_sandbox(void)
{
    if (s_sandbox_ready) return true;

    s_sandbox_queue = xQueueCreate(AAG_SANDBOX_QUEUE_LEN, sizeof(aag_verify_request_t));
    if (s_sandbox_queue == NULL) {
        Serial.println("[AAG] Failed to create sandbox queue");
        return false;
    }

    BaseType_t rc = xTaskCreatePinnedToCore(
        aag_sandbox_task,         // Task function
        "aag_sandbox",            // Task name
        AAG_VERIFY_STACK_SIZE,    // Stack size (8 KB from header)
        NULL,                     // Task parameter
        tskIDLE_PRIORITY + 1,     // LOW PRIORITY — below Wi-Fi/RF
        &s_sandbox_task,          // Task handle
        1                         // Pin to APP core (core 1)
    );

    if (rc != pdPASS) {
        Serial.println("[AAG] Failed to create sandbox task");
        vQueueDelete(s_sandbox_queue);
        s_sandbox_queue = NULL;
        return false;
    }

    s_sandbox_ready = true;
    Serial.println("[AAG] Sandbox subsystem initialized");
    return true;
}

/* ============================================================
 * aag_verify_app_async()
 * Queue an asynchronous verification request.
 * NON-BLOCKING — returns immediately.
 *
 * The sandbox task will process the request in background and
 * set request->completed = true when done.
 *
 * Returns false if queue is full or sandbox not initialized.
 * ============================================================ */
bool aag_verify_app_async(const char* bin_path, const char* sig_path)
{
    if (!bin_path || !sig_path) return false;
    if (!aag_sanitize_path(bin_path) || !aag_sanitize_path(sig_path)) return false;

    if (!s_sandbox_ready || s_sandbox_queue == NULL) {
        Serial.println("[AAG] Sandbox not initialized");
        return false;
    }

    aag_verify_request_t req;
    memset(&req, 0, sizeof(req));

    strncpy(req.bin_path, bin_path, AAG_QUEUE_PATH_LEN - 1);
    strncpy(req.sig_path, sig_path, AAG_QUEUE_PATH_LEN - 1);
    req.bin_path[AAG_QUEUE_PATH_LEN - 1] = '\0';
    req.sig_path[AAG_QUEUE_PATH_LEN - 1] = '\0';
    req.result    = false;
    req.completed = false;

    BaseType_t rc = xQueueSend(s_sandbox_queue, &req, 0);  // 0 = don't block

    if (rc != pdPASS) {
        Serial.println("[AAG] Sandbox queue full — async request dropped");
        return false;
    }

    Serial.printf("[AAG] Queued async verify: %s\n", bin_path);
    return true;
}

/* ============================================================
 * aag_load_app()
 * Memory-safe app loader with signature verification.
 *
 * 1. Open file and check size
 * 2. Verify heap is sufficient (size + AAG_HEAP_MARGIN)
 * 3. Verify digital signature before any load
 * 4. Only return true if ALL checks pass
 *
 * SECURITY: Signature is verified BEFORE any data is loaded
 * into RAM. This is a fail-closed design.
 * ============================================================ */
bool aag_load_app(const char* path)
{
    if (!path) return false;

    // --- Path sanitization ---
    if (!aag_sanitize_path(path)) {
        Serial.println("[AAG] App path rejected by sanitizer");
        return false;
    }

    // --- Open and check file size ---
    File f = SD.open(path, FILE_READ);
    if (!f) {
        Serial.printf("[AAG] Failed to open app: %s\n", path);
        return false;
    }

    size_t size = f.size();
    f.close();

    if (size == 0) {
        Serial.println("[AAG] App file is empty");
        return false;
    }

    // --- Heap guard: ensure enough free memory ---
    if (!aag_check_heap(size)) {
        Serial.printf("[AAG] Insufficient heap to load app (need %d, have %d)\n",
                      (int)(size + AAG_HEAP_MARGIN),
                      (int)xPortGetFreeHeapSize());
        return false;
    }

    // --- Derive signature file path: replace .bin with .sig ---
    char sig_path[AAG_MAX_PATH_LEN];
    strncpy(sig_path, path, sizeof(sig_path) - 1);
    sig_path[sizeof(sig_path) - 1] = '\0';

    char* dot = strrchr(sig_path, '.');
    if (dot && (dot - sig_path) < (int)(sizeof(sig_path) - 5)) {
        strncpy(dot, ".sig", sizeof(sig_path) - (dot - sig_path) - 1);
        dot[sizeof(sig_path) - (dot - sig_path) - 1] = '\0';
    } else {
        // No extension found — append .sig
        size_t slen = strlen(sig_path);
        if (slen + 4 < sizeof(sig_path)) {
            strncat(sig_path, ".sig", sizeof(sig_path) - slen - 1);
        } else {
            Serial.println("[AAG] Path too long to append .sig extension");
            return false;
        }
    }

    // --- Verify signature BEFORE loading (fail-closed) ---
    if (!aag_verify_app_signature(path, sig_path)) {
        Serial.println("[AAG] Signature verification failed — app BLOCKED");
        return false;
    }

    // --- All checks passed ---
    Serial.println("[AAG] App verified and cleared for launch");
    return true;
}

/* ============================================================
 * aag_shutdown_sandbox()
 * Clean up sandbox resources.
 * Call during system shutdown or before deep sleep.
 * ============================================================ */
void aag_shutdown_sandbox(void)
{
    if (s_sandbox_task != NULL) {
        vTaskDelete(s_sandbox_task);
        s_sandbox_task = NULL;
    }
    if (s_sandbox_queue != NULL) {
        vQueueDelete(s_sandbox_queue);
        s_sandbox_queue = NULL;
    }
    s_sandbox_ready = false;
    Serial.println("[AAG] Sandbox subsystem shut down");
}

/* ============================================================
 * aag_is_sandbox_ready()
 * Query whether the sandbox subsystem is initialized.
 * ============================================================ */
bool aag_is_sandbox_ready(void)
{
    return s_sandbox_ready;
}

/* ============================================================
 * aag_get_sandbox_queue_spaces()
 * Return number of free slots in the verification queue.
 * Useful for UI "pending verifications" display.
 * ============================================================ */
int aag_get_sandbox_queue_spaces(void)
{
    if (!s_sandbox_ready || s_sandbox_queue == NULL) return 0;
    return (int)uxQueueSpacesAvailable(s_sandbox_queue);
}

/* ============================================================
 * aag_blocking_verify_with_timeout()
 * Convenience wrapper: verify with a FreeRTOS task notification
 * wait so the caller can block with a timeout.
 *
 * Internally allocates a request, posts to queue, and blocks
 * on the current task's notification value until completion or
 * timeout.
 *
 * timeout_ms: maximum time to wait (0 = wait forever).
 * Returns true only on verified + valid within timeout.
 * ============================================================ */
bool aag_blocking_verify_with_timeout(const char* bin_path,
                                       const char* sig_path,
                                       uint32_t timeout_ms)
{
    if (!bin_path || !sig_path) return false;
    if (!aag_sanitize_path(bin_path) || !aag_sanitize_path(sig_path)) return false;
    if (!s_sandbox_ready || s_sandbox_queue == NULL) return false;

    // Build request on caller's stack — safe as long as we block
    aag_verify_request_t req;
    memset(&req, 0, sizeof(req));

    strncpy(req.bin_path, bin_path, AAG_QUEUE_PATH_LEN - 1);
    strncpy(req.sig_path, sig_path, AAG_QUEUE_PATH_LEN - 1);
    req.bin_path[AAG_QUEUE_PATH_LEN - 1] = '\0';
    req.sig_path[AAG_QUEUE_PATH_LEN - 1] = '\0';
    req.result         = false;
    req.completed      = false;
    req.caller_handle  = xTaskGetCurrentTaskHandle();

    // Use the current task's notification as a completion signal
    xTaskNotifyStateClear(NULL);

    BaseType_t rc = xQueueSend(s_sandbox_queue, &req, pdMS_TO_TICKS(100));
    if (rc != pdPASS) {
        Serial.println("[AAG] Queue full in blocking verify");
        return false;
    }

    // Wait for the sandbox task to signal completion via notification
    uint32_t notified_value = 0;
    rc = xTaskNotifyWait(0, ULONG_MAX, &notified_value,
                         (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms));

    if (rc != pdPASS) {
        Serial.println("[AAG] Blocking verify timed out");
        return false;
    }

    return req.result && req.completed;
}

/* ============================================================
 * aag_zero_buffer()
 * Explicit secure memory wipe.
 * Use after handling sensitive data to prevent leakage through
 * uninitialized reads or stack inspection.
 * ============================================================ */
void aag_zero_buffer(void* buf, size_t len)
{
    if (!buf || len == 0) return;
    volatile unsigned char* p = (volatile unsigned char*)buf;
    while (len--) *p++ = 0;
}

/* ============================================================
 * aag_quick_hash_file()
 * One-shot helper: compute SHA-256 of any file and return
 * the hash as a 64-character hex string.
 * Returns false on any error.
 *
 * NOTE: This is a synchronous call that will block for the
 * duration of the file read. Large files will take time.
 * ============================================================ */
bool aag_quick_hash_file(const char* path, char out_hex[65])
{
    if (!path || !out_hex) return false;
    if (!aag_sanitize_path(path)) return false;

    File f = SD.open(path, FILE_READ);
    if (!f) return false;

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        f.close();
        return false;
    }

    uint8_t buf[AAG_CHUNK_SIZE];
    while (f.available()) {
        size_t n = f.read(buf, sizeof(buf));
        if (n == 0) break;
        mbedtls_sha256_update_ret(&ctx, buf, n);
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    f.close();

    uint8_t hash[32];
    ret = mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    if (ret != 0) {
        aag_zero_buffer(hash, sizeof(hash));
        aag_zero_buffer(buf, sizeof(buf));
        return false;
    }

    aag_hash_to_hex(hash, out_hex);

    // Wipe sensitive buffers
    aag_zero_buffer(hash, sizeof(hash));
    aag_zero_buffer(buf, sizeof(buf));

    return true;
}

/* ============================================================
 * aag_verify_raw_hash()
 * Verify a pre-computed binary hash against a .sig file.
 * Useful when the hash was already computed by a prior pass.
 *
 * hash: 32-byte SHA-256 digest
 * sig_path: path to .sig file containing expected hash
 * Returns true on match.
 * ============================================================ */
bool aag_verify_raw_hash(const uint8_t hash[32], const char* sig_path)
{
    if (!hash || !sig_path) return false;
    if (!aag_sanitize_path(sig_path)) return false;

    uint8_t expected[32];
    if (!aag_read_sig_file(sig_path, expected)) return false;

    bool match = aag_constant_time_compare(hash, expected, 32);

#if AAG_DEBUG_HASH
    char hex_buf[65];
    aag_hash_to_hex(hash, hex_buf);
    Serial.printf("[AAG] Raw hash:  %s\n", hex_buf);
    aag_hash_to_hex(expected, hex_buf);
    Serial.printf("[AAG] Expected:  %s\n", hex_buf);
    Serial.printf("[AAG] Match:     %s\n", match ? "YES" : "NO");
#endif

    aag_zero_buffer(expected, sizeof(expected));
    return match;
}

/* ============================================================
 * Optional: simple self-test on startup
 * Call after aag_init_sandbox() to verify crypto integrity.
 * Uses the NIST test vector for "abc":
 *   SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223
 *                    b00361a396177a9cb410ff61f20015ad
 * ============================================================ */
bool aag_selftest_sandbox(void)
{
    const uint8_t abc[] = {'a', 'b', 'c'};
    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9b,
        0xcb, 0x41, 0x0f, 0xf6, 0x1f, 0x20, 0x01, 0x5ad
    };

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    int ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        Serial.println("[AAG] Self-test: starts failed");
        return false;
    }

    ret = mbedtls_sha256_update_ret(&ctx, abc, sizeof(abc));
    if (ret != 0) {
        mbedtls_sha256_free(&ctx);
        Serial.println("[AAG] Self-test: update failed");
        return false;
    }

    uint8_t hash[32];
    ret = mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    if (ret != 0) {
        Serial.println("[AAG] Self-test: finish failed");
        return false;
    }

    bool pass = aag_constant_time_compare(hash, expected, 32);

    if (pass) {
        Serial.println("[AAG] Self-test: PASS");
    } else {
        char hex[65];
        aag_hash_to_hex(hash, hex);
        Serial.printf("[AAG] Self-test: FAIL (got %s)\n", hex);
    }

    aag_zero_buffer(hash, sizeof(hash));
    return pass;
}

#endif /* ENABLE_AAG_OVERLAY */
