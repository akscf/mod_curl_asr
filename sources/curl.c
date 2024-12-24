/*
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2014, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Module Contributor(s):
 *  Konstantin Alexandrin <akscfx@gmail.com>
 *
 *
 */
#include "mod_curl_asr.h"

static const char *ctype_by_file_ext(char *filename) {
    if(!filename) {
        return "Content-Type: application/octet-stream";
    }

    if(strstr(filename, ".txt")) {
        return "Content-Type: text/plain";
    } else if(strstr(filename, ".raw")) {
        return "Content-Type: application/octet-stream";
    } else if(strstr(filename, ".bin")) {
        return "Content-Type: application/octet-stream";
    } else if(strstr(filename, ".mp3")) {
        return "Content-Type: audio/mp3";
    } else if(strstr(filename, ".wav")) {
        return "Content-Type: audio/wav";
    }

    return "Content-Type: application/octet-stream";
}

static size_t curl_io_write_callback(char *buffer, size_t size, size_t nitems, void *user_data) {
    switch_buffer_t *recv_buffer = (switch_buffer_t *)user_data;
    size_t len = (size * nitems);

    if(len > 0 && recv_buffer) {
        switch_buffer_write(recv_buffer, buffer, len);
    }

    return len;
}

static size_t curl_io_read_callback(char *buffer, size_t size, size_t nitems, void *user_data) {
    FILE *fh = (FILE *)user_data;
    size_t rc = 0;

    rc = fread(buffer, size, nitems, fh);

    return rc;
}

switch_status_t curl_post_upload_perform(char *api_url, char *api_key, switch_buffer_t *recv_buffer, switch_hash_t *params, char *filename, globals_t *globals) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    CURL *curl_handle = NULL;
    curl_mime *form = NULL;
    curl_mimepart *field_file=NULL;
    switch_curl_slist_t *headers = NULL;
    switch_CURLcode curl_ret = 0;
    long http_resp = 0;

    if(!api_url) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "api_url not determined\n");
        return SWITCH_STATUS_FALSE;
    }

    curl_handle = switch_curl_easy_init();
    headers = switch_curl_slist_append(headers, "Content-Type: multipart/form-data");

    switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    switch_curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
    switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_io_write_callback);
    switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)recv_buffer);

    if(globals->connect_timeout > 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, globals->connect_timeout);
    }
    if(globals->request_timeout > 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, globals->request_timeout);
    }
    if(globals->user_agent) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, globals->user_agent);
    }
    if(strncasecmp(api_url, "https", 5) == 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
        switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if(globals->proxy) {
        if(globals->proxy_credentials != NULL) {
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXYUSERPWD, globals->proxy_credentials);
        }
        if(strncasecmp(globals->proxy, "https", 5) == 0) {
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXY_SSL_VERIFYPEER, 0);
        }
        switch_curl_easy_setopt(curl_handle, CURLOPT_PROXY, globals->proxy);
    }

    if(api_key) {
        curl_easy_setopt(curl_handle, CURLOPT_XOAUTH2_BEARER, api_key);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
    }

    if((form = curl_mime_init(curl_handle))) {
        if(params && !switch_core_hash_empty(params)) {
            const void *hkey = NULL; void *hval = NULL;
            switch_hash_index_t *hidx = NULL;
            for(hidx = switch_core_hash_first_iter(params, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                if(hkey && hval) {
                    curl_mimepart *field = NULL;
                    if((field = curl_mime_addpart(form))) {
                        curl_mime_name(field, (char *)hkey);
                        curl_mime_data(field, (char *)hval, CURL_ZERO_TERMINATED);
                    }
                }
            }
        }
        if((field_file = curl_mime_addpart(form))) {
            curl_mime_name(field_file, "file");
            curl_mime_filedata(field_file, filename);
        }
        switch_curl_easy_setopt(curl_handle, CURLOPT_MIMEPOST, form);
    }

    headers = switch_curl_slist_append(headers, "Expect:");
    switch_curl_easy_setopt(curl_handle, CURLOPT_URL, api_url);

    curl_ret = switch_curl_easy_perform(curl_handle);
    if(!curl_ret) {
        switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_resp);
        if(!http_resp) { switch_curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CONNECTCODE, &http_resp); }
    } else {
        http_resp = curl_ret;
    }

    if(http_resp != 200) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "http-error=[%ld] (%s)\n", http_resp, api_url);
        status = SWITCH_STATUS_FALSE;
    }

    if(recv_buffer) {
        if(switch_buffer_inuse(recv_buffer) > 0) {
            switch_buffer_write(recv_buffer, "\0", 1);
        }
    }

    if(curl_handle) {
        switch_curl_easy_cleanup(curl_handle);
    }
    if(form) {
        curl_mime_free(form);
    }
    if(headers) {
        switch_curl_slist_free_all(headers);
    }

    return status;
}

switch_status_t curl_put_upload_perform(char *api_url, char *api_key, switch_buffer_t *recv_buffer, switch_hash_t *params, char *filename, globals_t *globals) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    struct stat file_info = {0};
    FILE *fh = NULL;
    CURL *curl_handle = NULL;
    switch_curl_slist_t *headers = NULL;
    switch_CURLcode curl_ret = 0;
    long http_resp = 0;
    char *xopts_json = NULL;
    char *xopts_hdr = NULL;

    if(!api_url) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "api_url not determined\n");
        return SWITCH_STATUS_FALSE;
    }
    if(stat(filename, &file_info)) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "stat()\n");
        return SWITCH_STATUS_FALSE;
    }
    if((fh = fopen(filename, "rb")) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unable to open file: (%s)\n", filename);
        return SWITCH_STATUS_FALSE;
    }

    curl_handle = switch_curl_easy_init();
    headers = switch_curl_slist_append(headers, ctype_by_file_ext(filename));

    switch_curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
    switch_curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    switch_curl_easy_setopt(curl_handle, CURLOPT_UPLOAD, 1);
    switch_curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

    switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_io_write_callback);
    switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)recv_buffer);
    switch_curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, curl_io_read_callback);
    switch_curl_easy_setopt(curl_handle, CURLOPT_READDATA, (void *)fh);

    if(globals->connect_timeout > 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, globals->connect_timeout);
    }
    if(globals->request_timeout > 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, globals->request_timeout);
    }
    if(globals->user_agent) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, globals->user_agent);
    }
    if(strncasecmp(api_url, "https", 5) == 0) {
        switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
        switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
    }
    if(globals->proxy) {
        if(globals->proxy_credentials != NULL) {
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXYAUTH, CURLAUTH_ANY);
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXYUSERPWD, globals->proxy_credentials);
        }
        if(strncasecmp(globals->proxy, "https", 5) == 0) {
            switch_curl_easy_setopt(curl_handle, CURLOPT_PROXY_SSL_VERIFYPEER, 0);
        }
        switch_curl_easy_setopt(curl_handle, CURLOPT_PROXY, globals->proxy);
    }

    if(api_key) {
        curl_easy_setopt(curl_handle, CURLOPT_XOAUTH2_BEARER, api_key);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
    }

    if(params && !switch_core_hash_empty(params)) {
        const void *hkey = NULL; void *hval = NULL;
        switch_hash_index_t *hidx = NULL;
        cJSON *jopts = NULL;

        jopts = cJSON_CreateObject();
        for(hidx = switch_core_hash_first_iter(params, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
            switch_core_hash_this(hidx, &hkey, NULL, &hval);
            if(hkey && hval) {
                cJSON_AddItemToObject(jopts, (char *)hkey, cJSON_CreateString((char *)hval));
            }
        }

        xopts_json = cJSON_PrintUnformatted(jopts);
        xopts_hdr = switch_mprintf("X-ASR-OPTIONS: %s", xopts_json);
        headers = switch_curl_slist_append(headers, xopts_hdr);

        cJSON_Delete(jopts);
    }

    headers = switch_curl_slist_append(headers, "Expect:");
    switch_curl_easy_setopt(curl_handle, CURLOPT_URL, api_url);

    curl_ret = switch_curl_easy_perform(curl_handle);
    if(!curl_ret) {
        switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_resp);
        if(!http_resp) { switch_curl_easy_getinfo(curl_handle, CURLINFO_HTTP_CONNECTCODE, &http_resp); }
    } else {
        http_resp = curl_ret;
    }

    if(http_resp != 200) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "http-error=[%ld] (%s)\n", http_resp, api_url);
        status = SWITCH_STATUS_FALSE;
    }

    if(recv_buffer) {
        if(switch_buffer_inuse(recv_buffer) > 0) {
            switch_buffer_write(recv_buffer, "\0", 1);
        }
    }

    if(curl_handle) {
        switch_curl_easy_cleanup(curl_handle);
    }
    if(headers) {
        switch_curl_slist_free_all(headers);
    }
    if(fh) {
        fclose(fh);
    }

    switch_safe_free(xopts_json);
    switch_safe_free(xopts_hdr);

    return status;
}
