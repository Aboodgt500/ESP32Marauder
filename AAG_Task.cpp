/*
 * AAG_Task.cpp -- A.A.G OS Overlay System for ESP32 Marauder
 * FreeRTOS overlay task (pinned to Core 0) for CYD (ESP32-2432S028)
 *
 * TFT_eSPI-based overlay rendered by a dedicated task.
 * No blocking calls. No String objects. Mutex-protected display.
 */

#include "AAG_System_Wrapper.h"

#ifdef ENABLE_AAG_OVERLAY

/* ============================================================
   DISPLAY MUTEX DEFINITION (extern declared in header)
   ============================================================ */
SemaphoreHandle_t aag_display_mutex = NULL;

/* ============================================================
 * CONSTANTS (module-local, do not conflict with header)
 * ============================================================ */

#define AAG_MENU_VISIBLE_ITEMS      6u
#define AAG_MAX_APP_NAME_LEN        32u
#define AAG_MAX_APP_PATH_LEN        64u

/* ---- Overlay geometry (must match header values) ---- */
#define AAG_PANEL_X                 20
#define AAG_PANEL_Y                 30
#define AAG_PANEL_W                 200
#define AAG_PANEL_H                 260

/* ============================================================
 * STATIC GLOBALS
 * ============================================================ */

static TaskHandle_t      aag_task_handle = NULL;
static aag_overlay_ctx_t aag_ctx;

/* Gesture tracking (accessed only by overlay task) */
static unsigned long     gesture_start_ms = 0;
static bool              gesture_active   = false;

/* ============================================================
 * FORWARD DECLARATIONS (module-local helpers)
 * ============================================================ */

static aag_gesture_t aag_detect_gesture(void);
static void aag_render_overlay(void);
static void aag_render_menu(void);
static void aag_scan_apps(void);
static void aag_clear_overlay(void);
static void aag_close_overlay(void);
static bool aag_check_heap_local(uint32_t required_bytes);
static void aag_draw_app_entry(uint8_t slot_idx, uint8_t app_idx, bool selected);
static void aag_handle_overlay_touch(uint16_t x, uint16_t y);
static void aag_handle_running_touch(uint16_t x, uint16_t y);

/* ============================================================
 * HELPER: SAFE STRINGS
 * ============================================================ */

/* Safe strncpy that always null-terminates */
static inline void aag_strncpy(char* dst, const char* src, size_t n)
{
    if (dst == NULL || n == 0) return;
    if (src == NULL) { dst[0] = '\0'; return; }
    size_t i;
    for (i = 0; i < n - 1 && src[i] != '\0'; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static inline uint8_t aag_min_u8(uint8_t a, uint8_t b) { return (a < b) ? a : b; }

/* ============================================================
 * PUBLIC API
 * ============================================================ */

/* -- aag_init ------------------------------------------------ */
void aag_init(void)
{
    /* 1. Create display mutex (defined in header as extern) */
    if (aag_display_mutex == NULL) {
        aag_display_mutex = xSemaphoreCreateMutex();
    }
    if (aag_display_mutex == NULL) {
        Serial.println("[AAG] FATAL: display mutex creation failed");
        return;
    }

    /* 2. Zero context */
    memset(&aag_ctx, 0, sizeof(aag_ctx));
    aag_ctx.state          = AAG_STATE_IDLE;
    aag_ctx.selected_idx   = -1;
    aag_ctx.scroll_offset  = 0;

    /* 3. Create overlay task pinned to Core 0 (Protocol / Wi-Fi core).
     *    Priority 1 so it never starves Wi-Fi/RF tasks running at 2+. */
    if (aag_task_handle == NULL) {
        BaseType_t rc = xTaskCreatePinnedToCore(
            (TaskFunction_t)aag_overlay_task,
            "aag_overlay",
            AAG_TASK_STACK_SIZE,
            NULL,
            AAG_TASK_PRIORITY,
            &aag_task_handle,
            0 /* Core 0 */
        );
        if (rc != pdPASS) {
            Serial.println("[AAG] FATAL: overlay task creation failed");
            vSemaphoreDelete(aag_display_mutex);
            aag_display_mutex = NULL;
            return;
        }
    }

    Serial.println("[AAG] Overlay system initialised");
}

/* -- aag_loop ------------------------------------------------ */
void aag_loop(void)
{
    /* Minimal heartbeat -- verify the task is alive.
     * Non-blocking.  Returns immediately. */
    if (aag_task_handle == NULL) {
        Serial.println("[AAG] WARN: overlay task not running");
    }
}

/* ============================================================
 * OVERLAY TASK  (FreeRTOS task entry point)
 * ============================================================ */

void aag_overlay_task(void* pvParameters)
{
    (void)pvParameters;

    Serial.printf("[AAG] Overlay task started on Core %d\n", (int)xPortGetCoreID());

    for (;;) {
        /* ---- WDT yield every iteration ---- */
        vTaskDelay(pdMS_TO_TICKS(10));

        switch (aag_ctx.state) {

        /* -- AAG_STATE_IDLE ---------------------------------- */
        case AAG_STATE_IDLE: {
            aag_gesture_t g = aag_detect_gesture();
            if (g == AAG_GESTURE_LONG_PRESS) {
                aag_scan_apps();
                aag_ctx.state         = AAG_STATE_OVERLAY_ACTIVE;
                aag_ctx.scroll_offset = 0;
                aag_ctx.selected_idx  = (aag_ctx.app_count > 0) ? 0 : -1;
                Serial.println("[AAG] Overlay activated");
            }
            vTaskDelay(pdMS_TO_TICKS(50)); /* 20 Hz idle poll */
            break;
        }

        /* -- AAG_STATE_OVERLAY_ACTIVE ------------------------ */
        case AAG_STATE_OVERLAY_ACTIVE: {
            aag_render_overlay();

            uint16_t tx = 0, ty = 0;
            if (display_obj.updateTouch(&tx, &ty)) {
                aag_handle_overlay_touch(tx, ty);
                vTaskDelay(pdMS_TO_TICKS(200)); /* debounce */
            }

            vTaskDelay(pdMS_TO_TICKS(AAG_FRAME_DELAY_MS));
            break;
        }

        /* -- AAG_STATE_APP_LAUNCHING ------------------------- */
        case AAG_STATE_APP_LAUNCHING: {
            int8_t sel = aag_ctx.selected_idx;
            if (sel < 0 || sel >= (int8_t)aag_ctx.app_count) {
                aag_ctx.state = AAG_STATE_OVERLAY_ACTIVE;
                break;
            }

            size_t need = aag_ctx.apps[sel].size_bytes;
            if (!aag_check_heap_local(need)) {
                Serial.printf("[AAG] Heap check failed for %s (%u bytes)\n",
                              aag_ctx.apps[sel].name, (unsigned)need);
                aag_ctx.state = AAG_STATE_OVERLAY_ACTIVE;
                break;
            }

            /* App cleared for launch -- transition to RUNNING */
            aag_ctx.state = AAG_STATE_APP_RUNNING;
            Serial.printf("[AAG] Launched: %s\n", aag_ctx.apps[sel].name);
            break;
        }

        /* -- AAG_STATE_APP_RUNNING --------------------------- */
        case AAG_STATE_APP_RUNNING: {
            /* Render minimal kill-overlay */
            if (aag_lock_display(pdMS_TO_TICKS(100))) {
                display_obj.tft.fillRect(0, 0, 60, 24, TFT_RED);
                display_obj.tft.setTextColor(TFT_WHITE, TFT_RED);
                display_obj.tft.setTextDatum(TC_DATUM);
                display_obj.tft.drawString("KILL", 30, 4, 2);
                aag_unlock_display();
            }

            uint16_t tx = 0, ty = 0;
            if (display_obj.updateTouch(&tx, &ty)) {
                aag_handle_running_touch(tx, ty);
                vTaskDelay(pdMS_TO_TICKS(200));
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            break;
        }

        /* -- AAG_STATE_GESTURE_DETECTING --------------------- */
        case AAG_STATE_GESTURE_DETECTING: {
            uint16_t tx = 0, ty = 0;
            if (display_obj.updateTouch(&tx, &ty)) {
                if (millis() - aag_ctx.gesture_start_ms >= AAG_LONG_PRESS_MS) {
                    gesture_active = false;
                    aag_scan_apps();
                    aag_ctx.state         = AAG_STATE_OVERLAY_ACTIVE;
                    aag_ctx.scroll_offset = 0;
                    aag_ctx.selected_idx  = (aag_ctx.app_count > 0) ? 0 : -1;
                    break;
                }
            } else {
                gesture_active = false;
                aag_ctx.state  = AAG_STATE_IDLE;
            }
            vTaskDelay(pdMS_TO_TICKS(50));
            break;
        }

        default:
            aag_ctx.state = AAG_STATE_IDLE;
            break;

        } /* switch */
    } /* for (;;) */

    vTaskDelete(NULL);
}

/* ============================================================
 * GESTURE DETECTION
 * ============================================================ */

static aag_gesture_t aag_detect_gesture(void)
{
    uint16_t x = 0, y = 0;

    if (display_obj.updateTouch(&x, &y)) {
        if (!gesture_active) {
            gesture_start_ms = millis();
            gesture_active   = true;
        } else if (millis() - gesture_start_ms >= AAG_LONG_PRESS_MS) {
            gesture_active = false;
            return AAG_GESTURE_LONG_PRESS;
        }
    } else {
        gesture_active = false;
    }
    return AAG_GESTURE_NONE;
}

/* ============================================================
 * OVERLAY RENDERING
 * ============================================================ */

static void aag_render_overlay(void)
{
    if (!aag_lock_display(pdMS_TO_TICKS(200))) return;

    TFT_eSPI& tft = display_obj.tft;

    /* 1. Semi-transparent panel background */
    tft.fillRect(AAG_PANEL_X, AAG_PANEL_Y, AAG_PANEL_W, AAG_PANEL_H, AAG_COLOR_PANEL_BG);

    /* 2. Border */
    tft.drawRect(AAG_PANEL_X, AAG_PANEL_Y, AAG_PANEL_W, AAG_PANEL_H, AAG_COLOR_BORDER);

    /* 3. Title "A.A.G OS" centred at top */
    tft.setTextColor(AAG_COLOR_TITLE, AAG_COLOR_PANEL_BG);
    tft.setTextDatum(TC_DATUM);
    tft.drawString("A.A.G OS", AAG_PANEL_X + AAG_PANEL_W / 2, AAG_PANEL_Y + 6, 4);

    /* 4. Close button "X" top-right */
    const int16_t btn_s  = 20;
    const int16_t btn_x0 = AAG_PANEL_X + AAG_PANEL_W - btn_s - 6;
    const int16_t btn_y0 = AAG_PANEL_Y + 6;
    tft.fillRect(btn_x0, btn_y0, btn_s, btn_s, AAG_COLOR_CLOSE_BTN);
    tft.setTextColor(TFT_WHITE, AAG_COLOR_CLOSE_BTN);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("X", btn_x0 + btn_s / 2, btn_y0 + btn_s / 2, 2);

    /* 5. Horizontal separator under title */
    tft.drawFastHLine(AAG_PANEL_X + 4, AAG_PANEL_Y + 34, AAG_PANEL_W - 8, AAG_COLOR_BORDER);

    /* 6. Menu entries */
    aag_render_menu();

    aag_unlock_display();
}

/* ============================================================
 * MENU RENDERING
 * ============================================================ */

/* PRECONDITION: caller must hold aag_display_mutex */
static void aag_render_menu(void)
{
    TFT_eSPI& tft = display_obj.tft;

    if (aag_ctx.app_count == 0) {
        tft.setTextColor(TFT_LIGHTGREY, AAG_COLOR_PANEL_BG);
        tft.setTextDatum(MC_DATUM);
        tft.drawString("No apps in /apps", AAG_PANEL_X + AAG_PANEL_W / 2,
                       AAG_PANEL_Y + AAG_PANEL_H / 2, 2);
        return;
    }

    uint8_t visible = aag_min_u8(AAG_MENU_VISIBLE_ITEMS,
                                 aag_ctx.app_count - aag_ctx.scroll_offset);

    int16_t entry_y0 = AAG_PANEL_Y + 40;
    int16_t entry_h  = 24;

    for (uint8_t i = 0; i < visible; i++) {
        uint8_t app_idx = aag_ctx.scroll_offset + i;
        bool selected   = ((int8_t)app_idx == aag_ctx.selected_idx);
        aag_draw_app_entry(i, app_idx, selected);
    }

    /* Scroll indicators */
    if (aag_ctx.scroll_offset > 0) {
        tft.fillTriangle(AAG_PANEL_X + AAG_PANEL_W - 16, entry_y0 - 8,
                         AAG_PANEL_X + AAG_PANEL_W - 12, entry_y0 - 4,
                         AAG_PANEL_X + AAG_PANEL_W - 20, entry_y0 - 4,
                         TFT_LIGHTGREY);
    }
    if (aag_ctx.scroll_offset + AAG_MENU_VISIBLE_ITEMS < aag_ctx.app_count) {
        int16_t last_y = entry_y0 + visible * entry_h;
        tft.fillTriangle(AAG_PANEL_X + AAG_PANEL_W - 16, last_y + 4,
                         AAG_PANEL_X + AAG_PANEL_W - 12, last_y,
                         AAG_PANEL_X + AAG_PANEL_W - 20, last_y,
                         TFT_LIGHTGREY);
    }
}

/* PRECONDITION: caller must hold aag_display_mutex */
static void aag_draw_app_entry(uint8_t slot_idx, uint8_t app_idx, bool selected)
{
    TFT_eSPI& tft = display_obj.tft;

    int16_t x0 = AAG_PANEL_X + 6;
    int16_t y0 = AAG_PANEL_Y + 40 + slot_idx * 24;
    int16_t w  = AAG_PANEL_W - 28;
    int16_t h  = 22;

    uint16_t bg = selected ? 0x3186 : AAG_COLOR_PANEL_BG; /* 0x3186 = darker cyan */

    /* Background */
    tft.fillRect(x0, y0, w, h, bg);
    if (selected) tft.drawRect(x0, y0, w, h, TFT_CYAN);

    /* Icon placeholder */
    tft.fillRect(x0 + 4, y0 + 5, 12, 12, selected ? TFT_CYAN : TFT_LIGHTGREY);

    /* App name */
    char label[AAG_MAX_APP_NAME_LEN];
    aag_strncpy(label, aag_ctx.apps[app_idx].name, sizeof(label));
    tft.setTextColor(AAG_COLOR_MENU_ITEM, bg);
    tft.setTextDatum(TL_DATUM);
    tft.drawString(label, x0 + 22, y0 + 4, 2);

    /* Verification status dot */
    int16_t dot_x = x0 + w - 12;
    int16_t dot_y = y0 + h / 2;
    uint16_t dot_col;
    switch (aag_ctx.apps[app_idx].status) {
        case AAG_APP_VERIFIED:   dot_col = AAG_COLOR_VERIFIED;   break;
        case AAG_APP_INVALID_SIG:dot_col = AAG_COLOR_INVALID;    break;
        default:                 dot_col = AAG_COLOR_UNVERIFIED; break;
    }
    tft.fillCircle(dot_x, dot_y, 4, dot_col);
}

/* ============================================================
 * TOUCH HANDLERS
 * ============================================================ */

static void aag_handle_overlay_touch(uint16_t x, uint16_t y)
{
    /* -- Close button? -- */
    const int16_t btn_s  = 20;
    const int16_t btn_x0 = AAG_PANEL_X + AAG_PANEL_W - btn_s - 6;
    const int16_t btn_y0 = AAG_PANEL_Y + 6;

    if (x >= btn_x0 && x <= btn_x0 + btn_s && y >= btn_y0 && y <= btn_y0 + btn_s) {
        aag_close_overlay();
        return;
    }

    /* -- Menu item touch? -- */
    int16_t entry_y0 = AAG_PANEL_Y + 40;
    int16_t entry_h  = 24;
    int16_t x0       = AAG_PANEL_X + 6;
    int16_t w        = AAG_PANEL_W - 28;

    for (uint8_t i = 0; i < AAG_MENU_VISIBLE_ITEMS; i++) {
        uint8_t app_idx = aag_ctx.scroll_offset + i;
        if (app_idx >= aag_ctx.app_count) break;
        int16_t iy0 = entry_y0 + i * entry_h;
        if (x >= x0 && x <= x0 + w && y >= iy0 && y <= iy0 + entry_h) {
            aag_ctx.selected_idx = (int8_t)app_idx;
            aag_ctx.state = AAG_STATE_APP_LAUNCHING;
            return;
        }
    }

    /* -- Scroll area (right edge)? -- */
    int16_t scroll_x0 = AAG_PANEL_X + AAG_PANEL_W - 24;
    if (x >= scroll_x0) {
        int16_t mid_y = AAG_PANEL_Y + AAG_PANEL_H / 2;
        if (y < mid_y && aag_ctx.scroll_offset > 0) {
            aag_ctx.scroll_offset--;
        } else if (y >= mid_y &&
                   aag_ctx.scroll_offset + AAG_MENU_VISIBLE_ITEMS < aag_ctx.app_count) {
            aag_ctx.scroll_offset++;
        }
    }
}

static void aag_handle_running_touch(uint16_t x, uint16_t y)
{
    /* Kill button: top-left 60x24 */
    if (x < 60 && y < 24) {
        aag_clear_overlay();
        aag_ctx.state       = AAG_STATE_IDLE;
        aag_ctx.selected_idx = -1;
        Serial.println("[AAG] App killed by user");
    }
}

/* ============================================================
 * APP SCANNING
 * ============================================================ */

static void aag_scan_apps(void)
{
    memset(aag_ctx.apps, 0, sizeof(aag_ctx.apps));
    aag_ctx.app_count = 0;

    File root = SD.open("/apps");
    if (!root || !root.isDirectory()) {
        if (root) root.close();
        Serial.println("[AAG] WARN: /apps not found on SD");
        return;
    }

    File entry = root.openNextFile();
    while (entry && aag_ctx.app_count < AAG_MAX_APPS) {
        if (!entry.isDirectory()) {
            const char* fname = entry.name();
            size_t flen = strlen(fname);
            if (flen > 4 && strcasecmp(fname + flen - 4, ".bin") == 0) {
                uint8_t idx = aag_ctx.app_count;

                /* Name (strip .bin) */
                size_t nl = (flen - 4 < sizeof(aag_ctx.apps[idx].name))
                                ? flen - 4
                                : sizeof(aag_ctx.apps[idx].name) - 1;
                memcpy(aag_ctx.apps[idx].name, fname, nl);
                aag_ctx.apps[idx].name[nl] = '\0';

                /* Full path */
                snprintf(aag_ctx.apps[idx].path, sizeof(aag_ctx.apps[idx].path),
                         "/apps/%s", fname);

                /* Signature path */
                snprintf(aag_ctx.apps[idx].sig_path, sizeof(aag_ctx.apps[idx].sig_path),
                         "/apps/%.*s.sig", (int)(flen - 4), fname);

                aag_ctx.apps[idx].size_bytes = entry.size();
                aag_ctx.apps[idx].status     = AAG_APP_UNKNOWN;

                aag_ctx.app_count++;

                /* Trigger async background verification */
                aag_verify_app_async(aag_ctx.apps[idx].path,
                                     aag_ctx.apps[idx].sig_path);
            }
        }
        entry.close();
        entry = root.openNextFile();
    }
    root.close();

    Serial.printf("[AAG] Scanned %u app(s)\n", aag_ctx.app_count);
}

/* ============================================================
 * OVERLAY CLEARING
 * ============================================================ */

static void aag_clear_overlay(void)
{
    if (!aag_lock_display(pdMS_TO_TICKS(200))) return;
    display_obj.tft.fillRect(AAG_PANEL_X, AAG_PANEL_Y, AAG_PANEL_W, AAG_PANEL_H, TFT_BLACK);
    aag_unlock_display();
}

static void aag_close_overlay(void)
{
    aag_clear_overlay();
    aag_ctx.state        = AAG_STATE_IDLE;
    aag_ctx.selected_idx = -1;
    aag_ctx.scroll_offset = 0;
    Serial.println("[AAG] Overlay closed");
}

/* ============================================================
 * HEAP CHECK  (module-local, delegates to header MemGuard)
 * ============================================================ */

static bool aag_check_heap_local(uint32_t required_bytes)
{
    return AAG_MemGuard::check_heap((size_t)required_bytes);
}

/* ============================================================
   ASYNC VERIFICATION CALLBACK
   Called by sandbox task to report verification results.
   ============================================================ */
void aag_report_verification_result(const char* bin_path, bool verified)
{
    if (!bin_path) return;
    for (uint8_t i = 0; i < aag_ctx.app_count; i++) {
        if (strcmp(aag_ctx.apps[i].path, bin_path) == 0) {
            aag_ctx.apps[i].status = verified ? AAG_APP_VERIFIED : AAG_APP_INVALID_SIG;
            return;
        }
    }
}

#endif /* ENABLE_AAG_OVERLAY */
