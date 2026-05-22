#pragma once

#ifdef ENABLE_AAG_OVERLAY

// ---------------------------------------------------------------------------
//  A.A.G OS System Wrapper — ESP32 Marauder Overlay Header
//  Platform: ESP32-2432S028 (CYD) with ILI9341 + XPT2046
//  Display:  TFT_eSPI (NOT LVGL)
// ---------------------------------------------------------------------------

#include "configs.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <freertos/queue.h>
#include <TFT_eSPI.h>

#ifdef HAS_CYD_TOUCH
  #include <XPT2046_Touchscreen.h>
#endif

#include <FS.h>
#include <SD.h>

// ===========================================================================
//  SECTION 1 — AAG Version and Constants
// ===========================================================================

/** Overlay semantic version string. */
constexpr const char* AAG_VERSION = "1.0.0";

/** Overlay panel dimensions (centered on 240x320 portrait screen). */
constexpr uint16_t AAG_OVERLAY_WIDTH   = 200;
constexpr uint16_t AAG_OVERLAY_HEIGHT  = 260;
constexpr uint16_t AAG_OVERLAY_X       = 20;   // (240 - 200) / 2
constexpr uint16_t AAG_OVERLAY_Y       = 30;   // (320 - 260) / 2

/** Touch-gesture timing threshold (milliseconds). */
constexpr uint16_t AAG_LONG_PRESS_MS   = 1500;

/** Maximum number of sandbox apps discoverable on SD card. */
constexpr uint8_t  AAG_MAX_APPS        = 20;

/** Path to sandbox apps directory on SD card. */
constexpr const char* AAG_APP_PATH     = "/apps";

/** File extensions for app binaries and their detached signatures. */
constexpr const char* AAG_SIG_EXT      = ".sig";
constexpr const char* AAG_BIN_EXT      = ".bin";

/** Minimum free heap margin (bytes) before AAG operations are gated. */
constexpr size_t AAG_HEAP_MARGIN       = 10240;  // 10 KiB above MEM_LOWER_LIM

/** Frame-loop delay for overlay rendering (10 FPS). */
constexpr TickType_t AAG_FRAME_DELAY_MS = 100;

/** FreeRTOS task stack sizes (bytes).  Conservative for 520 KiB total SRAM. */
constexpr uint32_t AAG_TASK_STACK_SIZE   = 4096;   // Overlay gesture + render task
constexpr uint32_t AAG_VERIFY_STACK_SIZE = 8192;   // Signature verification task

/** FreeRTOS task priority — one above idle so it yields gracefully. */
constexpr UBaseType_t AAG_TASK_PRIORITY  = 1;  // tskIDLE_PRIORITY + 1


// ===========================================================================
//  SECTION 2 — Enums
// ===========================================================================

/** High-level lifecycle state of the AAG overlay subsystem. */
enum aag_state_t {
    AAG_STATE_IDLE,              // Waiting for activation gesture
    AAG_STATE_GESTURE_DETECTING, // Monitoring touch for trigger pattern
    AAG_STATE_OVERLAY_ACTIVE,    // Overlay menu rendered and accepting input
    AAG_STATE_APP_LAUNCHING,     // Verification + hand-off to sandbox
    AAG_STATE_APP_RUNNING        // Sandbox app executing; overlay hidden
};

/** Trust status of a discovered sandbox application binary. */
enum aag_app_status_t {
    AAG_APP_UNKNOWN,      // Status not yet determined
    AAG_APP_VERIFIED,     // Signature valid and binary hash matches
    AAG_APP_UNVERIFIED,   // No .sig file present; trust level unknown
    AAG_APP_INVALID_SIG   // Signature present but verification FAILED
};

/** Recognized touch-gesture identifiers used to trigger the overlay. */
enum aag_gesture_t {
    AAG_GESTURE_NONE,      // No recognized gesture
    AAG_GESTURE_LONG_PRESS // Touch held continuously >= AAG_LONG_PRESS_MS
};


// ===========================================================================
//  SECTION 3 — Structs
// ===========================================================================

/**
 * @brief Represents a single sandbox application discovered on the SD card.
 *
 * All string fields use fixed-size char buffers to avoid dynamic allocation
 * inside FreeRTOS tasks (no Arduino String class).
 */
struct aag_app_entry_t {
    char           name[32];     // Human-readable app name (from filename)
    char           path[64];     // Full filesystem path to .bin file
    char           sig_path[68]; // Full filesystem path to .sig file
    aag_app_status_t status;     // Current verification status
    size_t         size_bytes;   // Binary file size on disk
};

/**
 * @brief Shared runtime context for the overlay subsystem.
 *
 * This struct is owned by the overlay task and accessed by sandbox helpers
 * under the aag_display_mutex.  All fields are plain scalars / fixed arrays
 * to avoid heap fragmentation.
 */
struct aag_overlay_ctx_t {
    aag_state_t    state;             // Current overlay lifecycle state
    uint8_t        app_count;         // Number of entries populated in apps[]
    int8_t         selected_idx;      // Currently highlighted menu item (-1 = none)
    int8_t         scroll_offset;     // First visible item index for scrolling
    uint16_t       touch_x;           // Last raw touch X coordinate
    uint16_t       touch_y;           // Last raw touch Y coordinate
    bool           touch_pressed;     // True while touch is down
    unsigned long  gesture_start_ms;  // millis() snapshot when touch began
    aag_app_entry_t apps[AAG_MAX_APPS]; // Fixed-size app registry
};

/**
 * @brief Heap-safety utility — prevents AAG operations from exhausting RAM.
 *
 * All methods are static so no instantiation (and therefore no heap) is
 * required.  call before every heavy operation (render pass, SD scan, etc.).
 */
struct AAG_MemGuard {
    /**
     * @brief  Verify that at least (required + AAG_HEAP_MARGIN) bytes are free.
     * @param  required  Bytes the caller intends to allocate or consume.
     * @return true if heap is safe, false if operation should be aborted.
     */
    static bool check_heap(size_t required) {
        return (xPortGetFreeHeapSize() > (required + AAG_HEAP_MARGIN));
    }
};


// ===========================================================================
//  SECTION 4 — Display Mutex (Shared with Marauder main loop)
// ===========================================================================

/**
 * @brief Global mutex protecting TFT_eSPI draw operations.
 *
 * Both the Marauder main loop and the AAG overlay task must hold this mutex
 * before calling any TFT_eSPI drawing primitive to prevent display corruption.
 */
extern SemaphoreHandle_t aag_display_mutex;

/**
 * @brief Acquire the display mutex with a bounded wait.
 * @param  timeout  Max ticks to block (default 100 ms).
 * @return true if mutex was taken, false on timeout.
 *
 * @note ALWAYS check the return value.  Never draw if this returns false.
 */
inline bool aag_lock_display(TickType_t timeout = pdMS_TO_TICKS(100)) {
    return (xSemaphoreTake(aag_display_mutex, timeout) == pdTRUE);
}

/**
 * @brief Release the display mutex.
 *
 * @note Call exactly once for every successful aag_lock_display().
 *       Safe to call even if take failed (xSemaphoreGive handles it).
 */
inline void aag_unlock_display() {
    xSemaphoreGive(aag_display_mutex);
}


// ===========================================================================
//  SECTION 5 — Color Definitions for Overlay
// ===========================================================================

/** Background fill for the overlay panel area.  Dark blue-gray. */
constexpr uint16_t AAG_COLOR_PANEL_BG   = 0x18E3;
/** Title bar / header text color. */
constexpr uint16_t AAG_COLOR_TITLE      = TFT_CYAN;
/** Default (unselected) menu item text color. */
constexpr uint16_t AAG_COLOR_MENU_ITEM  = TFT_WHITE;
/** Highlighted / selected menu item text color. */
constexpr uint16_t AAG_COLOR_MENU_SEL   = TFT_YELLOW;
/** Indicator for apps with valid cryptographic signature. */
constexpr uint16_t AAG_COLOR_VERIFIED   = TFT_GREEN;
/** Indicator for apps lacking a signature file. */
constexpr uint16_t AAG_COLOR_UNVERIFIED = TFT_ORANGE;
/** Indicator for apps whose signature verification failed. */
constexpr uint16_t AAG_COLOR_INVALID    = TFT_RED;
/** "Close" button fill / border color. */
constexpr uint16_t AAG_COLOR_CLOSE_BTN  = TFT_RED;
/** Decorative border around the overlay panel.  Medium gray. */
constexpr uint16_t AAG_COLOR_BORDER     = 0x7BEF;


// ===========================================================================
//  SECTION 6 — Function Prototypes
// ===========================================================================

/*
 * The following functions are implemented in AAG_System_Wrapper.cpp
 * (and AAG_Sandbox.cpp for sandbox/verification helpers).
 */

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/** One-time setup: create mutex, scan SD /apps, register overlay task. */
void aag_init();

/** Called from the main Marauder loop each iteration; non-blocking. */
void aag_loop();

// ---------------------------------------------------------------------------
// FreeRTOS Task Entry Points
// ---------------------------------------------------------------------------

/** Overlay task body — gesture detection + rendering loop. */
void aag_overlay_task(void* pvParameters);

/** Sandbox task body — launched when an app is selected for execution. */
void aag_sandbox_task(void* pvParameters);

// ---------------------------------------------------------------------------
// Gesture Detection
// ---------------------------------------------------------------------------

/**
 * @brief Poll touchscreen state and classify current gesture.
 * @return Recognized gesture, or AAG_GESTURE_NONE.
 *
 * @note This is a non-blocking poll; it does NOT wait for a gesture.
 *       Must be called frequently (each frame) from the overlay task.
 */
aag_gesture_t aag_detect_gesture();

// ---------------------------------------------------------------------------
// Overlay Rendering (all require display mutex held)
// ---------------------------------------------------------------------------

/** Draw the full overlay panel: border, title, app list, close button. */
void aag_render_overlay();

/** Re-draw only the scrollable app menu portion (optimization). */
void aag_render_menu();

/** Restore the screen area beneath the overlay (before hiding). */
void aag_clear_overlay();

/** Transition from OVERLAY_ACTIVE back to IDLE; cleans up state. */
void aag_close_overlay();

// ---------------------------------------------------------------------------
// App Management
// ---------------------------------------------------------------------------

/**
 * @brief Scan SD_CARD:/apps for .bin files and populate ctx.apps[].
 * @note Implemented as static void in AAG_Task.cpp (module-local).
 *       Not exposed externally; called internally by overlay task.
 */

/**
 * @brief Move selection highlight to a new index (bounds-checked).
 * @param idx  Zero-based app index, or -1 to clear selection.
 */
void aag_select_app(int8_t idx);

/**
 * @brief Verify and launch the app at the given index.
 * @param idx  Index into ctx.apps[].
 * @return true if sandbox task was started successfully.
 */
bool aag_launch_app(int8_t idx);

/** Force-stop the currently running sandbox app (if any). */
void aag_stop_app();

// ---------------------------------------------------------------------------
// Sandbox / Verification Helpers (implemented in AAG_Sandbox.cpp)
// ---------------------------------------------------------------------------

/**
 * @brief Synchronously verify an Ed25519 detached signature.
 * @param bin_path  Path to the .bin file.
 * @param sig_path  Path to the corresponding .sig file.
 * @return true if signature is cryptographically valid.
 */
bool aag_verify_app_signature(const char* bin_path, const char* sig_path);

/**
 * @brief Launch signature verification in a dedicated high-stack task.
 * @param bin_path  Path to the .bin file.
 * @param sig_path  Path to the corresponding .sig file.
 * @return true if the verification task was created successfully.
 *
 * @note This is the preferred entry point; it avoids starving the overlay
 *       task during the CPU-intensive signature check.
 */
bool aag_verify_app_async(const char* bin_path, const char* sig_path);

/**
 * @brief Query the trust status of an app by its binary path.
 * @param path  Filesystem path to the .bin file.
 * @return Current status enum value.
 */
aag_app_status_t aag_get_app_status(const char* path);

/**
 * @brief Legacy heap-check wrapper (delegates to AAG_MemGuard).
 * @param required  Bytes caller needs available.
 * @return true if enough headroom exists.
 */
bool aag_check_heap(size_t required);

/** Initialize sandbox: create queue + start background verify task. */
bool aag_init_sandbox(void);

/** Tear down sandbox: delete task and queue. */
void aag_shutdown_sandbox(void);

/** Query if sandbox subsystem is ready. */
bool aag_is_sandbox_ready(void);

/** Read .sig file (64 hex chars) into 32-byte binary hash. */
bool aag_read_sig_file(const char* sig_path, uint8_t out_hash[32]);

/** Zero memory securely (volatile pointer, prevents compiler elision). */
void aag_zero_buffer(void* buf, size_t len);

/** Self-test SHA-256 against NIST test vector. Call after init. */
bool aag_selftest_sandbox(void);

/** Load app from SD with heap guard + signature verification (fail-closed). */
bool aag_load_app(const char* path);

/** Blocking verify with timeout using task notifications. */
bool aag_blocking_verify_with_timeout(const char* bin_path,
                                       const char* sig_path,
                                       uint32_t timeout_ms);

/** Compute SHA-256 of file, return as hex string. */
bool aag_quick_hash_file(const char* path, char out_hex[65]);

/** Verify pre-computed hash against .sig file. */
bool aag_verify_raw_hash(const uint8_t hash[32], const char* sig_path);

/** Callback from sandbox task to report verification result. */
void aag_report_verification_result(const char* bin_path, bool verified);


#endif /* ENABLE_AAG_OVERLAY */
