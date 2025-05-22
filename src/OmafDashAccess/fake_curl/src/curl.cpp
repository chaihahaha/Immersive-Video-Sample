#include <curl/curl.h>
#include <emscripten/fetch.h>
#include <emscripten/emscripten.h>
#include <emscripten/threading.h>

#include <vector>
#include <string>
#include <map>
#include <list>
#include <mutex>
#include <algorithm>
#include <cstring> // For strcpy, memcpy, strdup
#include <sstream>
#include <chrono>
#include <iostream> // For FAKE_CURL_LOG
#include <cmath>    // For INFINITY
#include <atomic>   // For unique IDs

// --- Enhanced Logging Macros ---
#define FAKE_CURL_LOG_ERROR(x) do { \
    std::ostringstream ss_err; \
    ss_err << "[FakeCurl ERROR] (" << timestamp_ms() << "ms) " << __FILE__ << ":" << __LINE__ << " " << x; \
    std::cerr << ss_err.str() << std::endl; \
} while(0)

#define FAKE_CURL_LOG_INFO(x) do { \
    std::ostringstream ss_info; \
    ss_info << "[FakeCurl INFO] (" << timestamp_ms() << "ms) " << x; \
    std::cout << ss_info.str() << std::endl; \
} while(0)

// Helper for timestamp
long long timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Forward declaration
struct CurlMultiHandleState;
static std::atomic<uintptr_t> g_easy_handle_id_counter(1);

struct CurlEasyHandleState {
    uintptr_t unique_id;
    std::string url;
    curl_write_callback write_function = nullptr;
    void* write_data = nullptr;
    bool opt_ssl_verify_peer = true;
    bool opt_ssl_verify_host = true;
    long opt_connect_timeout_ms = 0;
    long opt_timeout_ms = 0;
    std::string opt_proxy_url;
    curl_proxytype opt_proxy_type = CURLPROXY_HTTP;
    std::string opt_no_proxy;
    std::string opt_proxy_username;
    std::string opt_proxy_password;
    std::string opt_username;
    std::string opt_password;
    std::string opt_range_header_value;
    bool opt_nobody = false;
    void* opt_private_data = nullptr;
    char error_buffer[CURL_ERROR_SIZE] = {0};
    char* user_provided_error_buffer = nullptr;

    long info_response_code = 0;
    curl_off_t info_content_length_download_t = -1;
    curl_off_t info_speed_download_t = 0;
    curl_off_t info_total_time_t = 0;
    curl_off_t info_namelookup_time_t = 0;
    curl_off_t info_connect_time_t = 0;
    curl_off_t info_appconnect_time_t = 0;
    curl_off_t info_pretransfer_time_t = 0;
    curl_off_t info_starttransfer_time_t = 0;
    curl_off_t info_redirect_time_t = 0;

    emscripten_fetch_t* current_fetch_ptr = nullptr;
    CURLcode last_curl_result = CURLE_OK;
    CurlMultiHandleState* multi_parent = nullptr;
    std::chrono::steady_clock::time_point operation_start_time;

    std::vector<std::string> request_headers_storage;
    std::vector<const char*> request_headers_cstrings;

    std::mutex internal_mutex;
    std::atomic<bool> cleanup_initiated{false};
    std::atomic<bool> fetch_closed_by_callback{false};
    std::atomic<bool> transfer_completed_awaiting_msg{false};

    CurlEasyHandleState() : unique_id(g_easy_handle_id_counter++),
                            cleanup_initiated(false),
                            fetch_closed_by_callback(false),
                            transfer_completed_awaiting_msg(false){
      opt_timeout_ms = 300000;
      current_fetch_ptr = nullptr;
      multi_parent = nullptr;
      user_provided_error_buffer = nullptr;
      FAKE_CURL_LOG_INFO("CurlEasyHandleState CREATED: ID " + std::to_string(unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ")");
    }

    ~CurlEasyHandleState() {
        FAKE_CURL_LOG_INFO("CurlEasyHandleState DESTROYED: ID " + std::to_string(unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ")");
        if (current_fetch_ptr && !cleanup_initiated.load(std::memory_order_acquire)) {
            FAKE_CURL_LOG_ERROR("~CurlEasyHandleState: ID " + std::to_string(unique_id) + " still has active fetch " + std::to_string(reinterpret_cast<uintptr_t>(current_fetch_ptr)) + " and cleanup was not initiated via API! This is a bug or unexpected destruction.");
            current_fetch_ptr->userData = nullptr;
            emscripten_fetch_close(current_fetch_ptr);
            // current_fetch_ptr = nullptr; // Object is being destroyed
        }
    }

    void reset_for_new_transfer() {
        FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(unique_id) + ": reset_for_new_transfer called.");
        // Lock not strictly needed if this is only called when no concurrent access,
        // but good practice if state might be shared or callbacks could race.
        // std::lock_guard<std::mutex> lock(internal_mutex); // Consider if needed
        info_response_code = 0;
        info_content_length_download_t = -1;
        info_speed_download_t = 0;
        info_total_time_t = 0;
        info_namelookup_time_t = 0;
        info_connect_time_t = 0;
        info_appconnect_time_t = 0;
        info_pretransfer_time_t = 0;
        info_starttransfer_time_t = 0;
        info_redirect_time_t = 0;
        last_curl_result = CURLE_OK;
        fetch_closed_by_callback.store(false, std::memory_order_release);
        transfer_completed_awaiting_msg.store(false, std::memory_order_relaxed);

        if (current_fetch_ptr) {
            FAKE_CURL_LOG_ERROR("EasyHandle ID " + std::to_string(unique_id) +
                                ": reset_for_new_transfer called with an active fetch " +
                                std::to_string(reinterpret_cast<uintptr_t>(current_fetch_ptr)) +
                                "! This will orphan or cancel the fetch.");
            current_fetch_ptr->userData = nullptr; // Defang callbacks
            emscripten_fetch_close(current_fetch_ptr);
            current_fetch_ptr = nullptr;
        }
    }

    void reset_options() {
        FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(unique_id) + ": reset_options called.");
        // std::lock_guard<std::mutex> lock(internal_mutex); // Consider if needed
        write_function = nullptr;
        write_data = nullptr;
        opt_ssl_verify_peer = true;
        opt_ssl_verify_host = true;
        opt_connect_timeout_ms = 0;
        opt_timeout_ms = 300000;
        opt_proxy_url.clear();
        opt_proxy_type = CURLPROXY_HTTP;
        opt_no_proxy.clear();
        opt_proxy_username.clear();
        opt_proxy_password.clear();
        opt_username.clear();
        opt_password.clear();
        opt_range_header_value.clear();
        opt_nobody = false;
        // opt_private_data = nullptr; // Not typically reset by curl_easy_reset
        // user_provided_error_buffer = nullptr; // Not reset
        error_buffer[0] = '\0';
        request_headers_storage.clear();
        request_headers_cstrings.clear();
        reset_for_new_transfer(); // This will also reset fetch_closed_by_callback
    }

    void set_error(CURLcode err, const char* message) {
        // std::lock_guard<std::mutex> lock(internal_mutex); // Error buffer is usually not contended heavily
        last_curl_result = err;
        const char* err_str_to_use = message ? message : curl_easy_strerror(err);
        std::string full_message;
        if (err_str_to_use) {
            full_message = err_str_to_use;
        } else {
            full_message = "Unknown libcurl error code " + std::to_string(err);
        }
        FAKE_CURL_LOG_ERROR("EasyHandle ID " + std::to_string(unique_id) + " set_error: " + std::to_string(err) + " - " + full_message);
        strncpy(error_buffer, full_message.c_str(), sizeof(error_buffer) - 1);
        error_buffer[sizeof(error_buffer) - 1] = '\0';
        if (user_provided_error_buffer) {
            strncpy(user_provided_error_buffer, full_message.c_str(), CURL_ERROR_SIZE - 1);
            user_provided_error_buffer[CURL_ERROR_SIZE - 1] = '\0';
        }
    }

    void prepare_fetch_headers() {
        // std::lock_guard<std::mutex> lock(internal_mutex); // Header setup is usually before transfer starts
        request_headers_storage.clear();
        request_headers_cstrings.clear();
        if (!opt_range_header_value.empty()) {
            request_headers_storage.push_back("Range");
            request_headers_storage.push_back("bytes=" + opt_range_header_value);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(unique_id) + ": Prepared Range header: bytes=" + opt_range_header_value);
        }
        // TODO: Add CURLOPT_HTTPHEADER processing here if needed
        if (request_headers_storage.empty()) {
            request_headers_cstrings.push_back(nullptr);
        } else {
            for(const auto& s : request_headers_storage) {
                request_headers_cstrings.push_back(s.c_str());
            }
            request_headers_cstrings.push_back(nullptr);
        }
    }
};

static std::atomic<uintptr_t> g_multi_handle_id_counter(1);

struct CurlMultiHandleState {
    uintptr_t unique_id;
    std::list<CurlEasyHandleState*> easy_handles_managed;
    std::map<emscripten_fetch_t*, CurlEasyHandleState*> active_fetches;

    std::list<CURLMsg> completed_messages_queue;
    std::mutex queue_mutex;   // Protects completed_messages_queue
    std::mutex general_mutex; // Protects easy_handles_managed and active_fetches

    long mopt_max_connects = 0;
    CURLMsg last_message_popped; // Add this
    bool last_message_valid;    // Add this

    CurlMultiHandleState() : unique_id(g_multi_handle_id_counter++) {
        FAKE_CURL_LOG_INFO("CurlMultiHandleState CREATED: ID " + std::to_string(unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ")");
    }
    ~CurlMultiHandleState() {
        FAKE_CURL_LOG_INFO("CurlMultiHandleState DESTROYED: ID " + std::to_string(unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(this)) + ")");
    }
};

// --- Fetch Callbacks ---
void common_fetch_onsuccess(emscripten_fetch_t *fetch) {
    uintptr_t fetch_ptr_val = reinterpret_cast<uintptr_t>(fetch);
    FAKE_CURL_LOG_INFO("ONSUCCESS_ENTER: fetch=" + std::to_string(fetch_ptr_val));

    CurlEasyHandleState* easy_state = static_cast<CurlEasyHandleState*>(fetch->userData);

    if (!easy_state || easy_state->cleanup_initiated.load(std::memory_order_acquire)) {
        FAKE_CURL_LOG_ERROR("onsuccess: easy_state is null or cleanup_initiated for fetch " + std::to_string(fetch_ptr_val) + ". Closing and returning.");
        emscripten_fetch_close(fetch);
        return;
    }
    FAKE_CURL_LOG_INFO("onsuccess: Processing for EasyID " + std::to_string(easy_state->unique_id) + ", incoming fetch ptr " + std::to_string(fetch_ptr_val) +
                       ", stored CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)));

    std::unique_lock<std::mutex> easy_lock(easy_state->internal_mutex);

    if (easy_state->cleanup_initiated.load(std::memory_order_acquire)) { // Re-check after lock
        easy_lock.unlock();
        FAKE_CURL_LOG_ERROR("onsuccess: EasyID " + std::to_string(easy_state->unique_id) + " cleanup_initiated (after lock). Ignoring callback for fetch " + std::to_string(fetch_ptr_val) + ". Closing incoming fetch.");
        emscripten_fetch_close(fetch);
        return;
    }
    if (easy_state->current_fetch_ptr != fetch) {
        easy_lock.unlock();
        FAKE_CURL_LOG_ERROR("onsuccess: Stale/mismatched fetch! EasyID " + std::to_string(easy_state->unique_id) +
                            " stored current_fetch_ptr (" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)) +
                            ") != incoming fetch (" + std::to_string(fetch_ptr_val) + "). Ignoring & closing incoming fetch.");
        emscripten_fetch_close(fetch);
        return;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - easy_state->operation_start_time);
    easy_state->info_total_time_t = duration.count();
    easy_state->info_response_code = fetch->status;
    easy_state->info_content_length_download_t = fetch->numBytes;
    // ... (speed calculation) ...

    if (easy_state->write_function && fetch->data && fetch->numBytes > 0) {
        easy_lock.unlock(); // Unlock before user callback
        size_t written = easy_state->write_function(const_cast<char*>(fetch->data), 1, fetch->numBytes, easy_state->write_data);
        easy_lock.lock();   // Re-lock
        if (easy_state->current_fetch_ptr != fetch || easy_state->cleanup_initiated.load(std::memory_order_acquire)) { // State might have changed during callback
             easy_lock.unlock(); FAKE_CURL_LOG_ERROR("onsuccess: State changed during write_cb for EasyID " + std::to_string(easy_state->unique_id)); return;
        }
        if (written < fetch->numBytes) {
            easy_state->set_error(CURLE_WRITE_ERROR, "Callback returned less than available data");
        } else {
            easy_state->last_curl_result = CURLE_OK;
        }
    } else {
        easy_state->last_curl_result = CURLE_OK;
    }

    if (easy_state->multi_parent) {
        CurlMultiHandleState* multi_state = easy_state->multi_parent;
        std::lock_guard<std::mutex> m_general_lock(multi_state->general_mutex);
        std::lock_guard<std::mutex> m_queue_lock(multi_state->queue_mutex);
        CURLMsg msg;
        msg.msg = CURLMSG_DONE;
        msg.easy_handle = reinterpret_cast<CURL*>(easy_state);
        msg.data.result = easy_state->last_curl_result;
        multi_state->completed_messages_queue.push_back(msg);
        multi_state->active_fetches.erase(fetch);
    }

    FAKE_CURL_LOG_INFO("ONSUCCESS_PRE_NULLIFY: EasyID=" + std::to_string(easy_state->unique_id) +
                       ", easy_state->CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)));
    easy_state->current_fetch_ptr = nullptr;
    easy_state->fetch_closed_by_callback.store(true, std::memory_order_release);
    easy_state->transfer_completed_awaiting_msg.store(true, std::memory_order_release);
    FAKE_CURL_LOG_INFO("ONSUCCESS_POST_NULLIFY: EasyID=" + std::to_string(easy_state->unique_id) +
                       ", easy_state->CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)) +
                       ", fetch_closed_by_cb=" + std::to_string(easy_state->fetch_closed_by_callback.load(std::memory_order_acquire)));


    easy_lock.unlock();
    FAKE_CURL_LOG_INFO("onsuccess: Callback closing fetch " + std::to_string(fetch_ptr_val) + " for EasyID " + std::to_string(easy_state->unique_id));
    emscripten_fetch_close(fetch);
    FAKE_CURL_LOG_INFO("ONSUCCESS_EXIT: EasyID=" + std::to_string(easy_state->unique_id));
}

void common_fetch_onerror(emscripten_fetch_t *fetch) {
    uintptr_t fetch_ptr_val = reinterpret_cast<uintptr_t>(fetch);
    FAKE_CURL_LOG_INFO("ONERROR_ENTER: fetch=" + std::to_string(fetch_ptr_val));
    CurlEasyHandleState* easy_state = static_cast<CurlEasyHandleState*>(fetch->userData);

    if (!easy_state || easy_state->cleanup_initiated.load(std::memory_order_acquire)) {
        FAKE_CURL_LOG_ERROR("onerror: easy_state is null or cleanup_initiated for fetch " + std::to_string(fetch_ptr_val) + ". Closing and returning.");
        emscripten_fetch_close(fetch);
        return;
    }
    FAKE_CURL_LOG_INFO("onerror: Processing for EasyID " + std::to_string(easy_state->unique_id) + ", incoming fetch ptr " + std::to_string(fetch_ptr_val) +
                       ", stored CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)));

    std::unique_lock<std::mutex> easy_lock(easy_state->internal_mutex);

    if (easy_state->cleanup_initiated.load(std::memory_order_acquire)) { // Re-check
        easy_lock.unlock();
        FAKE_CURL_LOG_ERROR("onerror: EasyID " + std::to_string(easy_state->unique_id) + " cleanup_initiated (after lock). Ignoring callback for fetch " + std::to_string(fetch_ptr_val) + ". Closing incoming fetch.");
        emscripten_fetch_close(fetch);
        return;
    }
    if (easy_state->current_fetch_ptr != fetch) {
        easy_lock.unlock();
        FAKE_CURL_LOG_ERROR("onerror: Stale/mismatched fetch! EasyID " + std::to_string(easy_state->unique_id) +
                            " stored current_fetch_ptr (" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)) +
                            ") != incoming fetch (" + std::to_string(fetch_ptr_val) + "). Ignoring & closing incoming fetch.");
        emscripten_fetch_close(fetch);
        return;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - easy_state->operation_start_time);
    easy_state->info_total_time_t = duration.count();
    easy_state->info_response_code = fetch->status;
    easy_state->info_content_length_download_t = 0;
    easy_state->info_speed_download_t = 0;

    std::string error_message_str;
    if (fetch->statusText[0] != '\0') {
        error_message_str = fetch->statusText;
    } else {
        error_message_str = "Network error (no status text)";
    }

    bool is_likely_internal_timeout = false;
    if (easy_state->opt_timeout_ms > 0 && (duration.count()/1000) > easy_state->opt_timeout_ms) {
        if (fetch->status == 0 && fetch->readyState == 4) { is_likely_internal_timeout = true; }
    }

    if (is_likely_internal_timeout) { easy_state->set_error(CURLE_OPERATION_TIMEDOUT, "Fetch operation likely timed out"); }
    else if (fetch->status >= 400) { easy_state->set_error(CURLE_HTTP_RETURNED_ERROR, error_message_str.c_str()); }
    else if (fetch->status == 0 && fetch->readyState == 4) { easy_state->set_error(CURLE_COULDNT_CONNECT, error_message_str.c_str()); }
    else if (fetch->status == 0 && strstr(error_message_str.c_str(), "timeout")) { easy_state->set_error(CURLE_OPERATION_TIMEDOUT, "Fetch operation timed out (statusText)");}
    else { easy_state->set_error(CURLE_GOT_NOTHING, error_message_str.c_str()); }

    if (easy_state->multi_parent) {
        CurlMultiHandleState* multi_state = easy_state->multi_parent;
        std::lock_guard<std::mutex> m_general_lock(multi_state->general_mutex);
        std::lock_guard<std::mutex> m_queue_lock(multi_state->queue_mutex);
        CURLMsg msg;
        msg.msg = CURLMSG_DONE;
        msg.easy_handle = reinterpret_cast<CURL*>(easy_state);
        msg.data.result = easy_state->last_curl_result;
        multi_state->completed_messages_queue.push_back(msg);
        multi_state->active_fetches.erase(fetch);
    }

    FAKE_CURL_LOG_INFO("ONERROR_PRE_NULLIFY: EasyID=" + std::to_string(easy_state->unique_id) +
                       ", easy_state->CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)));
    easy_state->current_fetch_ptr = nullptr;
    easy_state->fetch_closed_by_callback.store(true, std::memory_order_release);
    FAKE_CURL_LOG_INFO("ONERROR_POST_NULLIFY: EasyID=" + std::to_string(easy_state->unique_id) +
                       ", easy_state->CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(easy_state->current_fetch_ptr)) +
                       ", fetch_closed_by_cb=" + std::to_string(easy_state->fetch_closed_by_callback.load(std::memory_order_acquire)));

    easy_lock.unlock();
    FAKE_CURL_LOG_INFO("onerror: Callback closing fetch " + std::to_string(fetch_ptr_val) + " for EasyID " + std::to_string(easy_state->unique_id));
    emscripten_fetch_close(fetch);
    FAKE_CURL_LOG_INFO("ONERROR_EXIT: EasyID=" + std::to_string(easy_state->unique_id));
}

// --- Global Init/Cleanup ---
CURLcode curl_global_init(long flags) {
    (void)flags;
    FAKE_CURL_LOG_INFO("curl_global_init called with flags: " + std::to_string(flags));
    return CURLE_OK;
}

void curl_global_cleanup(void) {
    FAKE_CURL_LOG_INFO("curl_global_cleanup called");
}

// --- Easy Interface ---
CURL *curl_easy_init(void) {
    CurlEasyHandleState *state = new (std::nothrow) CurlEasyHandleState();
    if (!state) {
        FAKE_CURL_LOG_ERROR("curl_easy_init: Failed to allocate CurlEasyHandleState");
        return nullptr;
    }
    FAKE_CURL_LOG_INFO("curl_easy_init: Created EasyHandle ID " + std::to_string(state->unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(state)) + ")");
    return reinterpret_cast<CURL*>(state);
}

void curl_easy_reset(CURL *handle) {
    if (!handle) return;
    CurlEasyHandleState *state = reinterpret_cast<CurlEasyHandleState*>(handle);
    FAKE_CURL_LOG_INFO("curl_easy_reset: Called for EasyHandle ID " + std::to_string(state->unique_id));
    std::lock_guard<std::mutex> lock(state->internal_mutex); // Protect state during reset

    if (state->current_fetch_ptr) {
         FAKE_CURL_LOG_ERROR("curl_easy_reset: EasyHandle ID " + std::to_string(state->unique_id) +
                             " called on a handle with an active transfer " +
                             std::to_string(reinterpret_cast<uintptr_t>(state->current_fetch_ptr)) +
                             ". Aborting it.");
         state->current_fetch_ptr->userData = nullptr; // Defang
         emscripten_fetch_close(state->current_fetch_ptr); // Close
         state->current_fetch_ptr = nullptr;
    }
    state->reset_options(); // This will call reset_for_new_transfer which also handles current_fetch_ptr
}

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...) {
    if (!handle) return CURLE_BAD_FUNCTION_ARGUMENT;
    CurlEasyHandleState *state = reinterpret_cast<CurlEasyHandleState*>(handle);
    // Most setopts don't need to lock internal_mutex as they are usually called before a transfer
    // or on an idle handle. If called mid-transfer for specific options, care would be needed.
    // For this fake, assuming typical usage.
    va_list arg;
    va_start(arg, option);
    CURLcode result = CURLE_OK;
    // ... (switch statement for options as before) ...
    // (Ensure no race conditions if an option could affect an ongoing async op)
        switch (option) {
        case CURLOPT_URL: {
            const char* url_str = va_arg(arg, const char*);
            state->url = url_str ? url_str : "";
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_URL set to '" + state->url + "'");
            break;
        }
        case CURLOPT_WRITEFUNCTION:
            state->write_function = va_arg(arg, curl_write_callback);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_WRITEFUNCTION " + (state->write_function ? "set" : "cleared"));
            break;
        case CURLOPT_WRITEDATA:
            state->write_data = va_arg(arg, void*);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_WRITEDATA set");
            break;
        case CURLOPT_SSL_VERIFYPEER:
            state->opt_ssl_verify_peer = (va_arg(arg, long) == 1L);
            break;
        case CURLOPT_SSL_VERIFYHOST:
            state->opt_ssl_verify_host = (va_arg(arg, long) != 0L) ; 
            break;
        case CURLOPT_CONNECTTIMEOUT_MS:
            state->opt_connect_timeout_ms = va_arg(arg, long);
             FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_CONNECTTIMEOUT_MS set to " + std::to_string(state->opt_connect_timeout_ms));
            break;
        case CURLOPT_TIMEOUT_MS:
            state->opt_timeout_ms = va_arg(arg, long);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_TIMEOUT_MS set to " + std::to_string(state->opt_timeout_ms));
            break;
        case CURLOPT_PROXY: {
            const char* proxy_str = va_arg(arg, const char*);
            state->opt_proxy_url = proxy_str ? proxy_str : "";
            break;
        }
        case CURLOPT_PROXYTYPE:
            state->opt_proxy_type = (curl_proxytype)va_arg(arg, long);
            break;
        case CURLOPT_NOPROXY:{
            const char* noproxy_str = va_arg(arg, const char*);
            state->opt_no_proxy = noproxy_str ? noproxy_str : "";
            break;
        }
        case CURLOPT_USERNAME: {
            const char* user_str = va_arg(arg, const char*);
            state->opt_username = user_str ? user_str : "";
            break;
        }
        case CURLOPT_PASSWORD: {
            const char* pass_str = va_arg(arg, const char*);
            state->opt_password = pass_str ? pass_str : "";
            break;
        }
        case CURLOPT_PROXYUSERNAME:{
             const char* puser_str = va_arg(arg, const char*);
             state->opt_proxy_username = puser_str ? puser_str : "";
             break;
        }
        case CURLOPT_PROXYPASSWORD:{
             const char* ppass_str = va_arg(arg, const char*);
             state->opt_proxy_password = ppass_str ? ppass_str : "";
             break;
        }
        case CURLOPT_RANGE: {
            const char* range_str_arg = va_arg(arg, const char*);
            if (range_str_arg && strlen(range_str_arg) > 0) {
                state->opt_range_header_value = std::string(range_str_arg); 
                FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_RANGE set to '" + state->opt_range_header_value + "'");
            } else {
                state->opt_range_header_value.clear();
                 FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_RANGE cleared");
            }
            break;
        }
        case CURLOPT_NOBODY: 
            state->opt_nobody = (va_arg(arg, long) == 1L);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_NOBODY set to " + std::to_string(state->opt_nobody));
            break;
        case CURLOPT_PRIVATE:
            state->opt_private_data = va_arg(arg, void*);
             FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_PRIVATE set.");
            break;
        case CURLOPT_ERRORBUFFER:
            state->user_provided_error_buffer = va_arg(arg, char*);
            FAKE_CURL_LOG_INFO("EasyHandle ID " + std::to_string(state->unique_id) + ": CURLOPT_ERRORBUFFER set.");
            if (state->user_provided_error_buffer) state->user_provided_error_buffer[0] = '\0';
            break;
        default:
            result = CURLE_UNKNOWN_OPTION;
    }
    va_end(arg);
    return result;
}

CURLcode curl_easy_perform(CURL *handle) {
    if (!handle) return CURLE_BAD_FUNCTION_ARGUMENT;
    CurlEasyHandleState *state = reinterpret_cast<CurlEasyHandleState*>(handle);
    FAKE_CURL_LOG_INFO("curl_easy_perform: ENTER for EasyHandle ID " + std::to_string(state->unique_id));

    std::unique_lock<std::mutex> lock(state->internal_mutex);

    if (state->multi_parent) {
        FAKE_CURL_LOG_ERROR("curl_easy_perform on multi handle EasyID " + std::to_string(state->unique_id));
        lock.unlock(); state->set_error(CURLE_FAILED_INIT, "easy_perform on multi handle"); return state->last_curl_result;
    }
    if (state->current_fetch_ptr) {
        FAKE_CURL_LOG_ERROR("curl_easy_perform with active transfer EasyID " + std::to_string(state->unique_id));
        lock.unlock(); state->set_error(CURLE_FAILED_INIT, "easy_perform with active transfer"); return state->last_curl_result;
    }
    if (state->url.empty()) {
        FAKE_CURL_LOG_ERROR("curl_easy_perform no URL EasyID " + std::to_string(state->unique_id));
        lock.unlock(); state->set_error(CURLE_URL_MALFORMAT, "No URL set"); return state->last_curl_result;
    }

    state->reset_for_new_transfer();
    state->operation_start_time = std::chrono::steady_clock::now();

    emscripten_fetch_attr_t attr;
    emscripten_fetch_attr_init(&attr);
    if (state->opt_nobody) strcpy(attr.requestMethod, "HEAD"); else strcpy(attr.requestMethod, "GET");
    attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY | EMSCRIPTEN_FETCH_WAITABLE;
    state->prepare_fetch_headers();
    if (!state->request_headers_cstrings.empty() && state->request_headers_cstrings[0] != nullptr) {
        attr.requestHeaders = state->request_headers_cstrings.data();
    } else {
        attr.requestHeaders = nullptr;
    }
    attr.timeoutMSecs = state->opt_timeout_ms > 0 ? state->opt_timeout_ms : 0;
    attr.onsuccess = common_fetch_onsuccess;
    attr.onerror = common_fetch_onerror;
    attr.userData = state;

    FAKE_CURL_LOG_INFO("curl_easy_perform: EasyID " + std::to_string(state->unique_id) + " starting WAITABLE fetch for: " + state->url);
    state->current_fetch_ptr = emscripten_fetch(&attr, state->url.c_str());

    if (!state->current_fetch_ptr) {
        FAKE_CURL_LOG_ERROR("curl_easy_perform: emscripten_fetch init failed for EasyID " + std::to_string(state->unique_id));
        lock.unlock(); if(state->last_curl_result == CURLE_OK) state->set_error(CURLE_FAILED_INIT, "emscripten_fetch init failed"); return state->last_curl_result;
    }

    // Unlock before blocking call
    lock.unlock();
    double timeout_for_wait_double = state->opt_timeout_ms > 0 ? static_cast<double>(state->opt_timeout_ms) : INFINITY;
    EMSCRIPTEN_RESULT wait_res = emscripten_fetch_wait(state->current_fetch_ptr, timeout_for_wait_double);
    // Callbacks should have managed current_fetch_ptr and closed the fetch.
    // Re-acquire lock to check/update final state based on wait_res.
    lock.lock();

    // If current_fetch_ptr is still set here, it means callbacks didn't run or didn't nullify it.
    // This is a problem state. emscripten_fetch_wait should ensure callbacks run or it errors.
    if (state->current_fetch_ptr) {
        FAKE_CURL_LOG_ERROR("curl_easy_perform: EasyID " + std::to_string(state->unique_id) +
                           ": Post emscripten_fetch_wait, current_fetch_ptr is still set. This is unexpected.");
        // The fetch object is managed by emscripten_fetch_wait; do not close it here.
        // Mark our state to reflect it's no longer the active fetch for this handle.
        state->current_fetch_ptr = nullptr;
    }

    if (wait_res == EMSCRIPTEN_RESULT_TIMED_OUT) {
        if (state->last_curl_result == CURLE_OK || state->last_curl_result == CURLE_AGAIN ) {
             state->set_error(CURLE_OPERATION_TIMEDOUT, "emscripten_fetch_wait timed out");
        }
    } else if (wait_res != EMSCRIPTEN_RESULT_SUCCESS && (state->last_curl_result == CURLE_OK || state->last_curl_result == CURLE_AGAIN)) {
        state->set_error(CURLE_FAILED_INIT, ("emscripten_fetch_wait failed: " + std::to_string(wait_res)).c_str());
    }
    // If wait_res was SUCCESS, last_curl_result should be set by callbacks.
    CURLcode final_res = state->last_curl_result; // Read before unlock
    lock.unlock();
    FAKE_CURL_LOG_INFO("curl_easy_perform: EXIT for EasyID " + std::to_string(state->unique_id) + " with result: " + curl_easy_strerror(final_res));
    return final_res;
}

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO info, ...) {
    if (!handle) return CURLE_BAD_FUNCTION_ARGUMENT;
    CurlEasyHandleState *state = reinterpret_cast<CurlEasyHandleState*>(handle);
    // Most getinfo calls are on completed handles or for static options.
    // If getting info that callbacks modify (like response_code), lock might be needed
    // if getinfo can race with callback. For this fake, assume typical usage.
    // std::lock_guard<std::mutex> lock(state->internal_mutex); // If needed
    va_list arg;
    va_start(arg, info);
    CURLcode result = CURLE_OK;
    // ... (switch statement for info as before) ...
    switch (info) {
        case CURLINFO_RESPONSE_CODE: *va_arg(arg, long*) = state->info_response_code; break;
        case CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: *va_arg(arg, curl_off_t*) = state->info_content_length_download_t; break;
        case CURLINFO_SPEED_DOWNLOAD_T: *va_arg(arg, curl_off_t*) = state->info_speed_download_t; break;
        case CURLINFO_TOTAL_TIME_T: *va_arg(arg, curl_off_t*) = state->info_total_time_t; break;
        case CURLINFO_PRIVATE: *va_arg(arg, void**) = state->opt_private_data; break;
        case CURLINFO_EFFECTIVE_URL: { char **url_ptr_out = va_arg(arg, char**); if (url_ptr_out) *url_ptr_out = const_cast<char*>(state->url.c_str()); break; }
        default: FAKE_CURL_LOG_ERROR("EasyHandle ID " + std::to_string(state->unique_id) + ": Unsupported CURLINFO option: " + std::to_string(info)); result = CURLE_UNKNOWN_OPTION;
    }
    va_end(arg);
    return result;
}

// --- Multi Interface ---
void curl_multi_cleanup(CURLM *multi_handle) {
    if (!multi_handle) { FAKE_CURL_LOG_INFO("curl_multi_cleanup: called with NULL handle."); return; }
    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    FAKE_CURL_LOG_INFO("curl_multi_cleanup: ENTER for MultiHandle ID " + std::to_string(mstate->unique_id));

    std::unique_lock<std::mutex> m_general_lock(mstate->general_mutex);
    // No need to lock queue_mutex yet, just clearing lists under general_mutex first

    if (!mstate->active_fetches.empty()) {
        FAKE_CURL_LOG_INFO("MultiID " + std::to_string(mstate->unique_id) + ": " + std::to_string(mstate->active_fetches.size()) + " active fetches to close.");
    }
    // Iterate a copy of keys if map modification during iteration is an issue, but should be fine here.
    std::vector<emscripten_fetch_t*> fetches_to_close;
    for (auto const& [fetch_ptr, easy_state_ptr] : mstate->active_fetches) {
        fetches_to_close.push_back(fetch_ptr);
        if (easy_state_ptr) {
            std::lock_guard<std::mutex> easy_lock(easy_state_ptr->internal_mutex);
            if (easy_state_ptr->current_fetch_ptr == fetch_ptr) { // Check if it's still the one
                easy_state_ptr->current_fetch_ptr = nullptr;
            }
        }
    }
    mstate->active_fetches.clear();
    m_general_lock.unlock(); // Unlock before closing fetches

    for (emscripten_fetch_t* fetch_ptr : fetches_to_close) {
        FAKE_CURL_LOG_INFO("MultiID " + std::to_string(mstate->unique_id) + ": Closing active fetch " + std::to_string(reinterpret_cast<uintptr_t>(fetch_ptr)));
        if (fetch_ptr) {
            fetch_ptr->userData = nullptr;
            emscripten_fetch_close(fetch_ptr);
        }
    }
    fetches_to_close.clear(); // Not strictly needed but good practice

    m_general_lock.lock(); // Re-lock for easy_handles_managed
    for (CurlEasyHandleState* estate : mstate->easy_handles_managed) {
        if (estate) {
            std::lock_guard<std::mutex> easy_lock(estate->internal_mutex);
            FAKE_CURL_LOG_INFO("MultiID " + std::to_string(mstate->unique_id) + ": Unlinking EasyID " + std::to_string(estate->unique_id));
            estate->multi_parent = nullptr;
        }
    }
    mstate->easy_handles_managed.clear();
    m_general_lock.unlock();

    std::lock_guard<std::mutex> m_queue_lock(mstate->queue_mutex);
    mstate->completed_messages_queue.clear();
    // m_queue_lock released

    delete mstate;
    FAKE_CURL_LOG_INFO("curl_multi_cleanup: EXIT for MultiHandle (" + std::to_string(reinterpret_cast<uintptr_t>(multi_handle)) + ")");
}

CURLMcode curl_multi_add_handle(CURLM *multi_handle, CURL *easy_handle_generic) {
    if (!multi_handle) return CURLM_BAD_HANDLE;
    if (!easy_handle_generic) return CURLM_BAD_EASY_HANDLE;

    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    CurlEasyHandleState *estate = reinterpret_cast<CurlEasyHandleState*>(easy_handle_generic);
    FAKE_CURL_LOG_INFO("curl_multi_add_handle: MultiID " + std::to_string(mstate->unique_id) + ", EasyID " + std::to_string(estate->unique_id));

    std::lock_guard<std::mutex> m_general_lock(mstate->general_mutex);
    std::lock_guard<std::mutex> easy_lock(estate->internal_mutex);

    if (estate->multi_parent) {
        FAKE_CURL_LOG_ERROR("EasyID " + std::to_string(estate->unique_id) + " already in multi " + (estate->multi_parent == mstate ? "this" : "another"));
        return CURLM_ADDED_ALREADY;
    }
    if (estate->current_fetch_ptr) {
        FAKE_CURL_LOG_ERROR("EasyID " + std::to_string(estate->unique_id) + " has active transfer, cannot add.");
        // This is not strictly what libcurl would do, but good for a fake.
        // Libcurl might allow adding but perform would fail or behave unexpectedly.
        return CURLM_BAD_EASY_HANDLE;
    }

    estate->multi_parent = mstate;
    mstate->easy_handles_managed.push_back(estate);
    return CURLM_OK;
}

CURLMcode curl_multi_remove_handle(CURLM *multi_handle, CURL *easy_handle_generic) {
    if (!multi_handle) return CURLM_BAD_HANDLE;
    if (!easy_handle_generic) return CURLM_BAD_EASY_HANDLE;

    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    CurlEasyHandleState *estate = reinterpret_cast<CurlEasyHandleState*>(easy_handle_generic);
    FAKE_CURL_LOG_INFO("REMOVE_HANDLE_ENTER: EasyID=" + std::to_string(estate->unique_id));

    std::unique_lock<std::mutex> m_general_lock(mstate->general_mutex);
    std::unique_lock<std::mutex> easy_lock(estate->internal_mutex);
    FAKE_CURL_LOG_INFO("REMOVE_HANDLE_LOCKED: EasyID=" + std::to_string(estate->unique_id) +
                       ", estate->CPTR=" + std::to_string(reinterpret_cast<uintptr_t>(estate->current_fetch_ptr)) +
                       ", estate->cleanup_initiated=" + std::to_string(estate->cleanup_initiated.load(std::memory_order_acquire)) +
                       ", estate->fetch_closed_by_cb=" + std::to_string(estate->fetch_closed_by_callback.load(std::memory_order_acquire)));


    if (estate->cleanup_initiated.load(std::memory_order_acquire)) {
        FAKE_CURL_LOG_INFO("REMOVE_HANDLE: EasyID " + std::to_string(estate->unique_id) + " cleanup_initiated. Bypassing.");
        easy_lock.unlock(); m_general_lock.unlock();
        return CURLM_OK;
    }
    if (estate->multi_parent != mstate) {
        FAKE_CURL_LOG_ERROR("REMOVE_HANDLE: EasyID " + std::to_string(estate->unique_id) + " not part of this MultiID " + std::to_string(mstate->unique_id));
        easy_lock.unlock(); m_general_lock.unlock();
        return CURLM_BAD_EASY_HANDLE;
    }

    mstate->easy_handles_managed.remove(estate); // Needs m_general_lock
    estate->multi_parent = nullptr;

    emscripten_fetch_t* current_fetch_on_handle = estate->current_fetch_ptr;
    FAKE_CURL_LOG_INFO("REMOVE_HANDLE_CHECK_CPTR: EasyID=" + std::to_string(estate->unique_id) +
                       ", current_fetch_on_handle=" + std::to_string(reinterpret_cast<uintptr_t>(current_fetch_on_handle)));

    if (current_fetch_on_handle) { // If easy_state thinks a fetch is active for it
        // This means a callback has not yet run for this fetch to nullify current_fetch_ptr.
        // We are aborting it.
        FAKE_CURL_LOG_INFO("REMOVE_HANDLE_ABORTING: EasyID=" + std::to_string(estate->unique_id) +
                           ", fetch=" + std::to_string(reinterpret_cast<uintptr_t>(current_fetch_on_handle)));
        
        mstate->active_fetches.erase(current_fetch_on_handle); // Remove from multi's tracking
        
        current_fetch_on_handle->userData = nullptr; // Defang any late callback
        estate->current_fetch_ptr = nullptr;         // This easy handle no longer tracks this fetch
        // Do not set fetch_closed_by_callback = true, because *we* are closing it, not the callback.
        
        easy_lock.unlock();
        m_general_lock.unlock(); // Unlock before potentially slow/reentrant close

        emscripten_fetch_close(current_fetch_on_handle);
        estate->transfer_completed_awaiting_msg.store(false, std::memory_order_release);
    } else {
        // current_fetch_ptr was already null. Callback (onsuccess/onerror) likely handled it.
        FAKE_CURL_LOG_INFO("REMOVE_HANDLE_NO_ABORT: EasyID=" + std::to_string(estate->unique_id) + ", CPTR was null. Callback likely handled.");
        FAKE_CURL_LOG_INFO("REMOVE_HANDLE_NO_ABORT: EasyID=" + std::to_string(estate->unique_id) +
                           ", CPTR was null. transfer_completed_awaiting_msg=" +
                           std::to_string(estate->transfer_completed_awaiting_msg.load(std::memory_order_acquire)));
        easy_lock.unlock();
        m_general_lock.unlock();
    }

    std::lock_guard<std::mutex> m_queue_lock(mstate->queue_mutex);
    mstate->completed_messages_queue.remove_if(
        [ptr_to_match = easy_handle_generic](const CURLMsg& msg){ return msg.easy_handle == ptr_to_match; }
    );
    // m_queue_lock released

    return CURLM_OK;
}

CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles_out) {
    if (!multi_handle) return CURLM_BAD_HANDLE;
    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);

    std::lock_guard<std::mutex> m_general_lock(mstate->general_mutex);

    for (CurlEasyHandleState* easy_state : mstate->easy_handles_managed) {
        std::lock_guard<std::mutex> easy_lock(easy_state->internal_mutex);

        if (easy_state->current_fetch_ptr == nullptr && !easy_state->url.empty() && !easy_state->cleanup_initiated.load(std::memory_order_acquire) && !easy_state->transfer_completed_awaiting_msg.load(std::memory_order_acquire)) {
            // Max connects check would go here if implemented:
            // if (mstate->mopt_max_connects > 0 && mstate->active_fetches.size() >= (size_t)mstate->mopt_max_connects) {
            //     FAKE_CURL_LOG_INFO("MultiPerform: Max connects reached (" + std::to_string(mstate->active_fetches.size()) + "/" + std::to_string(mstate->mopt_max_connects) + ")");
            //     continue; 
            // }

            FAKE_CURL_LOG_INFO("MultiPerform: EasyID " + std::to_string(easy_state->unique_id) + " ready. URL: " + easy_state->url);
            easy_state->reset_for_new_transfer(); // Resets fetch_closed_by_callback to false
            easy_state->operation_start_time = std::chrono::steady_clock::now();

            emscripten_fetch_attr_t attr;
            emscripten_fetch_attr_init(&attr);
            if (easy_state->opt_nobody) strcpy(attr.requestMethod, "HEAD"); else strcpy(attr.requestMethod, "GET");
            attr.attributes = EMSCRIPTEN_FETCH_LOAD_TO_MEMORY;
            attr.timeoutMSecs = easy_state->opt_timeout_ms > 0 ? easy_state->opt_timeout_ms : 0;
            easy_state->prepare_fetch_headers();
            if (!easy_state->request_headers_cstrings.empty() && easy_state->request_headers_cstrings[0] != nullptr) {
                attr.requestHeaders = easy_state->request_headers_cstrings.data();
            } else {
                attr.requestHeaders = nullptr;
            }
            attr.onsuccess = common_fetch_onsuccess;
            attr.onerror = common_fetch_onerror;
            attr.userData = easy_state;

            FAKE_CURL_LOG_INFO("MultiPerform: Initiating fetch for EasyID " + std::to_string(easy_state->unique_id) + " URL " + easy_state->url);
            emscripten_fetch_t* new_fetch = emscripten_fetch(&attr, easy_state->url.c_str());

            if (new_fetch) {
                easy_state->current_fetch_ptr = new_fetch;
                mstate->active_fetches[new_fetch] = easy_state;
                FAKE_CURL_LOG_INFO("MultiPerform: emscripten_fetch SUCCEEDED for EasyID " + std::to_string(easy_state->unique_id) + ", fetch_ptr " + std::to_string(reinterpret_cast<uintptr_t>(new_fetch)));
            } else {
                FAKE_CURL_LOG_ERROR("MultiPerform: emscripten_fetch() returned NULL for EasyID " + std::to_string(easy_state->unique_id));
                easy_state->set_error(CURLE_FAILED_INIT, "emscripten_fetch init failed (returned null)");
                std::lock_guard<std::mutex> q_lock(mstate->queue_mutex);
                CURLMsg msg;
                msg.msg = CURLMSG_DONE;
                msg.easy_handle = reinterpret_cast<CURL*>(easy_state);
                msg.data.result = easy_state->last_curl_result;
                mstate->completed_messages_queue.push_back(msg);
            }
        }
    }

    if (running_handles_out) {
        *running_handles_out = mstate->active_fetches.size();
    }
    return CURLM_OK;
}

void curl_easy_cleanup(CURL *handle) {
    if (!handle) { FAKE_CURL_LOG_INFO("curl_easy_cleanup: called with NULL handle."); return; }
    CurlEasyHandleState *state = reinterpret_cast<CurlEasyHandleState*>(handle);
    FAKE_CURL_LOG_INFO("curl_easy_cleanup: ENTER for EasyHandle ID " + std::to_string(state->unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(handle)) + ")");

    std::unique_lock<std::mutex> lock(state->internal_mutex);
    if (state->cleanup_initiated.exchange(true, std::memory_order_acq_rel)) {
        state->transfer_completed_awaiting_msg.store(false, std::memory_order_release);
        lock.unlock();
        FAKE_CURL_LOG_INFO("curl_easy_cleanup: EasyID " + std::to_string(state->unique_id) + " cleanup already initiated. Skipping.");
        return;
    }

    if (state->multi_parent) {
        FAKE_CURL_LOG_ERROR("curl_easy_cleanup: EasyID " + std::to_string(state->unique_id) +
                            " still associated with MultiID " + std::to_string(state->multi_parent->unique_id) + ". Should be removed first.");
        // Attempt to remove it from multi_parent if possible, though this is fixing client error
        // This requires locking multi_parent's general_mutex. This can lead to deadlocks if not careful.
        // Best to just log and proceed with cleaning this easy handle.
        state->multi_parent = nullptr; // Just sever the link from this side.
    }

    emscripten_fetch_t* fetch_to_manage = state->current_fetch_ptr;
    if (fetch_to_manage) { // Check if there's a fetch pointer
        // if (!state->fetch_closed_by_callback.load(std::memory_order_acquire)) { // Check if callback already closed it
            FAKE_CURL_LOG_INFO("curl_easy_cleanup: EasyID " + std::to_string(state->unique_id) +
                               " has active fetch " + std::to_string(reinterpret_cast<uintptr_t>(fetch_to_manage)) +
                               ". Aborting it (callback might not have run or completed).");
            fetch_to_manage->userData = nullptr;
            // Unlock before close
            // state->current_fetch_ptr = nullptr; // Set before unlock
            // lock.unlock();
            // emscripten_fetch_close(fetch_to_manage);
            // lock.lock(); // Re-lock if more state to modify
        // } else {
        //     FAKE_CURL_LOG_INFO("curl_easy_cleanup: EasyID " + std::to_string(state->unique_id) +
        //                        " fetch " + std::to_string(reinterpret_cast<uintptr_t>(fetch_to_manage)) +
        //                        " was already closed by CB. Just nullifying CPTR.");
        // }
        // Simplified: cleanup always ensures its current_fetch_ptr is handled if set.
        // Callbacks are responsible for their own fetch objects.
        fetch_to_manage->userData = nullptr;
        emscripten_fetch_close(fetch_to_manage); // Close it if it was ours
        state->current_fetch_ptr = nullptr;
    }
    lock.unlock();
    delete state;
    FAKE_CURL_LOG_INFO("curl_easy_cleanup: EXIT for EasyHandle (" + std::to_string(reinterpret_cast<uintptr_t>(handle)) + ")");
}

CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue_out) {
    if (!multi_handle) {
        if (msgs_in_queue_out) *msgs_in_queue_out = 0;
        return nullptr;
    }
    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    std::lock_guard<std::mutex> lock(mstate->queue_mutex);

    if (mstate->completed_messages_queue.empty()) {
        mstate->last_message_valid = false;
        if (msgs_in_queue_out) *msgs_in_queue_out = 0;
        return nullptr;
    }
    mstate->last_message_popped = mstate->completed_messages_queue.front();
    mstate->completed_messages_queue.pop_front();
    if (msgs_in_queue_out) {
        *msgs_in_queue_out = mstate->completed_messages_queue.size();
    }
    CurlEasyHandleState* eh_state = reinterpret_cast<CurlEasyHandleState*>(mstate->last_message_popped.easy_handle);
    if (eh_state) {
        std::lock_guard<std::mutex> easy_lock(eh_state->internal_mutex); // Lock to modify its state
        eh_state->transfer_completed_awaiting_msg.store(false, std::memory_order_release); // Now truly idle
        FAKE_CURL_LOG_INFO("curl_multi_info_read: MultiID " + std::to_string(mstate->unique_id) +
                       " - Popped DONE for EasyID " + std::to_string(eh_state->unique_id) +
                       ". Marked transfer_completed_awaiting_msg=false.");
        FAKE_CURL_LOG_INFO("curl_multi_info_read: MultiID " + std::to_string(mstate->unique_id) +
                       " - Popped DONE for EasyID " + std::to_string(eh_state->unique_id) +
                       " (result: " + curl_easy_strerror(mstate->last_message_popped.data.result) + "). " +
                       std::to_string(msgs_in_queue_out ? *msgs_in_queue_out : 0) + " msgs left.");
    } else {
        FAKE_CURL_LOG_ERROR("curl_multi_info_read: Popped DONE message with NULL easy_handle!");
    }
    return &(mstate->last_message_popped);
}

// curl_multi_wait, curl_multi_setopt, slist functions, strerrors as before
// Ensure they don't have locking conflicts if they access shared state.
// For example, curl_multi_setopt for CURLMOPT_MAXCONNECTS needs mstate->general_mutex.
// curl_multi_wait might need mstate->queue_mutex and mstate->general_mutex to check active_fetches and completed_messages_queue.

CURLM *curl_multi_init(void) { /* ... as before ... */ 
    CurlMultiHandleState *mstate = new (std::nothrow) CurlMultiHandleState();
    if (!mstate) { FAKE_CURL_LOG_ERROR("curl_multi_init: Failed to allocate CurlMultiHandleState"); return nullptr; }
    FAKE_CURL_LOG_INFO("curl_multi_init: Created MultiHandle ID " + std::to_string(mstate->unique_id) + " (" + std::to_string(reinterpret_cast<uintptr_t>(mstate)) +")");
    return reinterpret_cast<CURLM*>(mstate);
}

CURLMcode curl_multi_setopt(CURLM *multi_handle, CURLMoption option, ...) {
    if (!multi_handle) return CURLM_BAD_HANDLE;
    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    va_list arg;
    va_start(arg, option);  
    CURLMcode result = CURLM_OK;
    FAKE_CURL_LOG_INFO("curl_multi_setopt: MultiHandle ID " + std::to_string(mstate->unique_id) + ", Option: " + std::to_string(option));

    switch (option) {
        case CURLMOPT_MAXCONNECTS: 
            mstate->mopt_max_connects = va_arg(arg, long);
            FAKE_CURL_LOG_INFO("MultiHandle ID " + std::to_string(mstate->unique_id) + ": CURLMOPT_MAXCONNECTS set to: " + std::to_string(mstate->mopt_max_connects));
            // Note: Actual enforcement of this limit needs to be added to curl_multi_perform.
            // Emscripten_fetch doesn't have a global concurrent request limit controllable this way;
            // the browser imposes its own (typically 6-10 per domain).
            // This option would be for the fake libcurl to throttle its own initiation of fetches.
            break;
        // CURLMOPT_PIPELINING - emscripten_fetch doesn't support HTTP/1.1 pipelining explicitly. HTTP/2+ handles this.
        // CURLMOPT_TIMERFUNCTION, CURLMOPT_SOCKETFUNCTION - Not applicable for emscripten_fetch abstraction.
        default:
            FAKE_CURL_LOG_ERROR("MultiHandle ID " + std::to_string(mstate->unique_id) + ": Unsupported CURLMOPT option: " + std::to_string(option));
            result = CURLM_UNKNOWN_OPTION;
    }
    va_end(arg);
    return result;
}
CURLMcode curl_multi_wait(CURLM *multi_handle, struct curl_waitfd extra_fds[], unsigned int extra_nfds, int timeout_ms, int *numfds_out) {
    (void)extra_fds; (void)extra_nfds; 
    if (!multi_handle) return CURLM_BAD_HANDLE;
    CurlMultiHandleState *mstate = reinterpret_cast<CurlMultiHandleState*>(multi_handle);
    // FAKE_CURL_LOG_INFO("curl_multi_wait: ENTER for MultiHandle ID " + std::to_string(mstate->unique_id) + ", timeout_ms: " + std::to_string(timeout_ms));


    // This function is called from OMAF's worker thread.
    // Its purpose is to block until activity or timeout.
    // With emscripten_fetch, activity (callbacks) is driven by the browser's event loop.
    // The `proxyToWorker=EM_TRUE` for fetch means callbacks will likely come from a fetch worker thread
    // and then post messages to the main thread or the initiating pthread if that's how Emscripten marshals them.

    // If there are active fetches, we are "waiting" for them.
    // If there are no active fetches AND no messages in queue, we might sleep.
    bool has_pending_messages;
    {
        std::lock_guard<std::mutex> lock(mstate->queue_mutex);
        has_pending_messages = !mstate->completed_messages_queue.empty();
    }

    if (numfds_out) {
        // numfds should indicate if there's something to process (completed) or still running.
        // If messages in queue, numfds should be >0. If active fetches, also >0.
        *numfds_out = mstate->active_fetches.size() + (has_pending_messages ? 1 : 0);
        // FAKE_CURL_LOG_INFO("MultiHandle ID " + std::to_string(mstate->unique_id) + ": numfds_out set to " + std::to_string(*numfds_out));
    }

    // If OMAF calls with timeout_ms > 0 AND there are no active_fetches AND no completed_messages_queue,
    // it might expect a true wait.
    // Since OMAF's loop itself has `curl_multi_perform` and `retriveDoneTask` (which calls `curl_multi_info_read`),
    // this `curl_multi_wait` is primarily a way to yield/sleep if there's nothing immediate.
    // OMAF's `threadRunner` calls this with timeout_ms=100.
    if (mstate->active_fetches.empty() && !has_pending_messages && timeout_ms > 0) {
        if (emscripten_has_threading_support() && !emscripten_is_main_browser_thread()) {
            long sleep_duration = std::min(timeout_ms, 100); // Cap sleep
             // FAKE_CURL_LOG_INFO("MultiHandle ID " + std::to_string(mstate->unique_id) + ": No active fetches or queued msgs. Sleeping for " + std::to_string(sleep_duration) + "ms.");
            emscripten_sleep(sleep_duration);
        } else {
            // FAKE_CURL_LOG_INFO("MultiHandle ID " + std::to_string(mstate->unique_id) + ": On main thread or no threading, cannot sleep in wait.");
        }
    } else if (timeout_ms == 0) {
        // Non-blocking check, just return status.
    } else {
        // Active fetches or messages in queue, or negative timeout (block indefinitely - not really applicable here)
        // Minimal yield might be good if OMAF expects this to block if there are active handles.
        // However, the OMAF loop itself will call perform/info_read.
        // emscripten_sleep(1); // Minimal yield
    }
    // FAKE_CURL_LOG_INFO("curl_multi_wait: EXIT for MultiHandle ID " + std::to_string(mstate->unique_id));
    return CURLM_OK;
}
const char *curl_easy_strerror(CURLcode errornum) {
    switch (errornum) {
        case CURLE_OK: return "No error";
        case CURLE_UNSUPPORTED_PROTOCOL: return "Unsupported protocol";
        case CURLE_FAILED_INIT: return "Failed initialization";
        case CURLE_URL_MALFORMAT: return "URL using bad/illegal format or missing URL";
        case CURLE_COULDNT_RESOLVE_HOST: return "Couldn't resolve host name";
        case CURLE_COULDNT_CONNECT: return "Couldn't connect to server";
        case CURLE_HTTP_RETURNED_ERROR: return "HTTP response code said error";
        case CURLE_WRITE_ERROR: return "Error writing received data to disk/application";
        case CURLE_READ_ERROR: return "Error reading local file";
        case CURLE_OUT_OF_MEMORY: return "Out of memory";
        case CURLE_OPERATION_TIMEDOUT: return "Operation timeout";
        case CURLE_RANGE_ERROR: return "Invalid range in Range: header";
        case CURLE_UNKNOWN_OPTION: return "Unknown option specified to libcurl";
        case CURLE_GOT_NOTHING: return "Server returned nothing (no headers, no data)";
        case CURLE_SEND_ERROR: return "Failed sending data to the peer";
        case CURLE_RECV_ERROR: return "Failure when receiving data from the peer";
        case CURLE_AGAIN: return "Transfer again, later";
        default: 
            static char unknown_buf[64];
            snprintf(unknown_buf, sizeof(unknown_buf), "Unknown error code %d", errornum);
            return unknown_buf;
    }
}

const char *curl_multi_strerror(CURLMcode errornum) {
    switch (errornum) {
        case CURLM_CALL_MULTI_PERFORM: return "Call multi_perform again";
        case CURLM_OK: return "No error";
        case CURLM_BAD_HANDLE: return "Invalid multi handle";
        case CURLM_BAD_EASY_HANDLE: return "Invalid easy handle";
        case CURLM_OUT_OF_MEMORY: return "Out of memory";
        case CURLM_INTERNAL_ERROR: return "Internal error";
        case CURLM_BAD_SOCKET: return "Invalid socket argument";
        case CURLM_UNKNOWN_OPTION: return "Unknown option for multi handle";
        case CURLM_ADDED_ALREADY: return "Easy handle already added to multi handle";
        default:
            static char unknown_multi_buf[64];
            snprintf(unknown_multi_buf, sizeof(unknown_multi_buf), "Unknown multi error code %d", errornum);
            return unknown_multi_buf;
    }
}
