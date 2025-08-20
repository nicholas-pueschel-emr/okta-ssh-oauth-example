/**************
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
**********/

/*******************************************************************************
 * author:      Huan Liu
 * description: PAM module to use device flow with syslog
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* needed for base64 decoder */
#include <openssl/pem.h>

#define DEVICE_AUTHORIZE_URL  "https://emerson.okta.com/oauth2/default/v1/device/authorize"
#define TOKEN_URL "https://emerson.okta.com/oauth2/default/v1/token"
#define CLIENT_ID "0oa16cs53v5lEcC3X2p8"

/* structure used for curl return */
struct MemoryStruct {
  char *memory;
  size_t size;
};

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;
    char *base64_decoded = calloc((decode_this_many_bytes*3)/4+1, sizeof(char));
    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_byte_index = 0;
    while (0 < BIO_read(b64_bio, base64_decoded + decoded_byte_index, 1)) {
        decoded_byte_index++;
    }
    BIO_free_all(b64_bio);
    return base64_decoded;
}

/* function to write curl output */
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        syslog(LOG_ERR, "Not enough memory (realloc returned NULL)");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/* parse JSON output for a key (assume string value) */
char *getValueForKey(char *in, const char *key) {
    char *token = strtok(in, "\"");
    while (token != NULL) {
        if (!strcmp(token, key)) {
            token = strtok(NULL, "\""); /* skip : */
            token = strtok(NULL, "\"");
            return token;
        }
        token = strtok(NULL, "\"");
    }
    return NULL;
}

CURL *curl;
struct MemoryStruct chunk;

void issuePost(char *url, char *data) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_perform(curl);
}

void sendPAMMessage(pam_handle_t *pamh, char *prompt_message) {
    int retval;
    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;
    struct pam_conv *conv;

    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_TEXT_INFO;
    msg[0].msg = prompt_message;

    resp = NULL;

    retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (retval == PAM_SUCCESS) {
        retval = conv->conv(1, (const struct pam_message **)pmsg, &resp, conv->appdata_ptr);
    }
    if (resp) free(resp);
}

extern char *getQR(char *str);

/* expected hooks */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,int argc, const char **argv) {
    char postData[1024];

    openlog("pam_okta_deviceflow", LOG_PID | LOG_CONS, LOG_AUTH);
    syslog(LOG_INFO, "Starting PAM authentication");

    /* memory for curl return */
    chunk.memory = malloc(1);
    chunk.size = 0;

    /* init Curl handle */
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();

    char str1[4096], str2[1024], str3[1024];

    /* call authorize endpoint */
    sprintf(postData, "client_id=%s&scope=openid profile offline_access", CLIENT_ID);
    issuePost(DEVICE_AUTHORIZE_URL, postData);

    strcpy(str1, chunk.memory);
    char *usercode = getValueForKey(str1, "user_code");
    strcpy(str2, chunk.memory);
    char *devicecode = getValueForKey(str2, "device_code");
    strcpy(str3, chunk.memory);
    char *activateUrl = getValueForKey(str3, "verification_uri");

    syslog(LOG_INFO, "Received auth codes: usercode=%s devicecode=%s", usercode, devicecode);

    char prompt_message[2000];
    char *qrc = getQR(activateUrl);
    sprintf(prompt_message, "\n\nPlease login at %s or scan the QRCode below:\nThen input code %s\n\n%s", activateUrl, usercode, qrc);
    free(qrc);
    sendPAMMessage(pamh, prompt_message);

    /* work around SSH PAM bug that buffers PAM_TEXT_INFO */
    char *resp;
    pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp, "Press Enter to continue:");

    int waitingForActivate = 1;
    sprintf(postData, "device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s", devicecode, CLIENT_ID);

    while (waitingForActivate) {
        chunk.size = 0;
        issuePost(TOKEN_URL, postData);

        strcpy(str1, chunk.memory);
        char *errormsg = getValueForKey(str1, "error");
        if (errormsg == NULL) {
            char *idtoken = getValueForKey(chunk.memory, "id_token");
            char *header = strtok(idtoken, ".");
            char *payload = strtok(NULL, ".");
            char *decoded = base64decode(payload, strlen(payload));
            char *name = getValueForKey(decoded, "name");

            sprintf(prompt_message, "\n\n*********************************\n  Welcome, %s\n*********************************\n\n\n", name);
            sendPAMMessage(pamh, prompt_message);

            syslog(LOG_INFO, "User %s successfully authenticated", name);

            if (curl) curl_easy_cleanup(curl);
            curl_global_cleanup();
            closelog();
            return PAM_SUCCESS;
        }

        syslog(LOG_INFO, "Waiting for user activation: %s", errormsg);
        sleep(5);
    }

    if (curl) curl_easy_cleanup(curl);
    curl_global_cleanup();
    closelog();

    return PAM_AUTH_ERR;
}
