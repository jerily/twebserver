/**
 * Copyright Jerily LTD. All Rights Reserved.
 * SPDX-FileCopyrightText: 2023 Neofytos Dimitriou (neo@jerily.cy)
 * SPDX-License-Identifier: MIT.
 */

#include <sys/time.h>
#include "common.h"

static Tcl_HashTable tws_ServerNameToInternal_HT;
static Tcl_Mutex tws_ServerNameToInternal_HT_Mutex;

static Tcl_HashTable tws_ConnNameToInternal_HT;
static Tcl_Mutex tws_ConnNameToInternal_HT_Mutex;

static Tcl_HashTable tws_HostNameToInternal_HT;
static Tcl_Mutex tws_HostNameToInternal_HT_Mutex;

static Tcl_HashTable tws_RouterNameToInternal_HT;
static Tcl_Mutex tws_RouterNameToInternal_HT_Mutex;

int tws_RegisterServerName(const char *name, tws_server_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ServerNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterServerName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

int tws_UnregisterServerName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterServerName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

tws_server_t * tws_GetInternalFromServerName(const char *name) {
    tws_server_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ServerNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tws_server_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);

    return internal;
}

int tws_RegisterConnName(const char *name, tws_conn_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_ConnNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterConnName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

int tws_UnregisterConnName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterConnName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

tws_conn_t *tws_GetInternalFromConnName(const char *name) {
    tws_conn_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_ConnNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tws_conn_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);

    return internal;
}

int tws_RegisterHostName(const char *name, SSL_CTX *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_HostNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterHostName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

int tws_UnregisterHostName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_HostNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterHostName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

SSL_CTX *tws_GetInternalFromHostName(const char *name) {
    SSL_CTX *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_HostNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (SSL_CTX *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);

    return internal;
}

int tws_RegisterRouterName(const char *name, tws_router_t *internal) {

    Tcl_HashEntry *entryPtr;
    int newEntry;
    Tcl_MutexLock(&tws_RouterNameToInternal_HT_Mutex);
    entryPtr = Tcl_CreateHashEntry(&tws_RouterNameToInternal_HT, (char *) name, &newEntry);
    if (newEntry) {
        Tcl_SetHashValue(entryPtr, (ClientData) internal);
    }
    Tcl_MutexUnlock(&tws_RouterNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> RegisterRouterName: name=%s internal=%p %s\n", name, internal,
                newEntry ? "entered into" : "already in"));

    return newEntry;
}

int tws_UnregisterRouterName(const char *name) {

    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_RouterNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_RouterNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        Tcl_DeleteHashEntry(entryPtr);
    }
    Tcl_MutexUnlock(&tws_RouterNameToInternal_HT_Mutex);

    DBG(fprintf(stderr, "--> UnregisterRouterName: name=%s entryPtr=%p\n", name, entryPtr));

    return entryPtr != NULL;
}

tws_router_t *tws_GetInternalFromRouterName(const char *name) {
    tws_router_t *internal = NULL;
    Tcl_HashEntry *entryPtr;

    Tcl_MutexLock(&tws_RouterNameToInternal_HT_Mutex);
    entryPtr = Tcl_FindHashEntry(&tws_RouterNameToInternal_HT, (char *) name);
    if (entryPtr != NULL) {
        internal = (tws_router_t *) Tcl_GetHashValue(entryPtr);
    }
    Tcl_MutexUnlock(&tws_RouterNameToInternal_HT_Mutex);

    return internal;
}

void tws_InitServerNameHT() {
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    Tcl_InitHashTable(&tws_ServerNameToInternal_HT, TCL_STRING_KEYS);
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);
}

void tws_InitConnNameHT() {
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    Tcl_InitHashTable(&tws_ConnNameToInternal_HT, TCL_STRING_KEYS);
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);
}

void tws_InitHostNameHT() {
    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    Tcl_InitHashTable(&tws_HostNameToInternal_HT, TCL_STRING_KEYS);
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);
}

void tws_InitRouterNameHT() {
    Tcl_MutexLock(&tws_RouterNameToInternal_HT_Mutex);
    Tcl_InitHashTable(&tws_RouterNameToInternal_HT, TCL_STRING_KEYS);
    Tcl_MutexUnlock(&tws_RouterNameToInternal_HT_Mutex);
}

void tws_DeleteServerNameHT() {
    Tcl_MutexLock(&tws_ServerNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_ServerNameToInternal_HT);
    Tcl_MutexUnlock(&tws_ServerNameToInternal_HT_Mutex);
}

void tws_DeleteConnNameHT() {
    Tcl_MutexLock(&tws_ConnNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_ConnNameToInternal_HT);
    Tcl_MutexUnlock(&tws_ConnNameToInternal_HT_Mutex);
}

void tws_DeleteHostNameHT() {
    Tcl_MutexLock(&tws_HostNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_HostNameToInternal_HT);
    Tcl_MutexUnlock(&tws_HostNameToInternal_HT_Mutex);
}

void tws_DeleteRouterNameHT() {
    Tcl_MutexLock(&tws_RouterNameToInternal_HT_Mutex);
    Tcl_DeleteHashTable(&tws_RouterNameToInternal_HT);
    Tcl_MutexUnlock(&tws_RouterNameToInternal_HT_Mutex);
}

char *tws_strndup(const char *s, size_t n) {
    if (s == NULL) {
        return NULL;
    }
    size_t l = strnlen(s, n);
    char *result = (char *) Tcl_Alloc(l + 1);
    if (result == NULL) {
        return NULL;
    }
    memcpy(result, s, l);
    result[l] = '\0';
    return result;
}

int tws_IsBinaryType(const char *content_type, Tcl_Size content_type_length) {
    int is_binary_type = 0;
    if (content_type_length >= 5 && content_type[0] == 't' && content_type[1] == 'e' && content_type[2] == 'x' && content_type[3] == 't' && content_type[4] == '/') {
        // text/*
        is_binary_type = 0;
    } else if (content_type_length >= 33 && content_type[0] == 'a' && content_type[11] == '/' && content_type[18] == 'f' && strncmp(content_type, "application/x-www-form-urlencoded", 33) == 0) {
        // application/x-www-form-urlencoded
        is_binary_type = 0;
    } else if (content_type_length >= 16 && content_type[0] == 'a' && content_type[11] == '/' && content_type[12] == 'j' && strncmp(content_type, "application/json", 16) == 0) {
        // application/json
        is_binary_type = 0;
    } else if (content_type_length >= 15 && content_type[0] == 'a' && content_type[11] == '/' && content_type[12] == 'x' && strncmp(content_type, "application/xml", 15) == 0) {
        // application/xml
        is_binary_type = 0;
    } else if (content_type_length >= 19 && content_type[0] == 'm' && content_type[9] == '/' && content_type[10] == 'f' && strncmp(content_type, "multipart/form-data", 19) == 0) {
        // multipart/form-data
        is_binary_type = 1;
    } else if (content_type_length >= 12 && content_type[0] == 'a' && content_type[11] == '/' && strncmp(content_type, "application/", 12) == 0) {
        // application/*
        is_binary_type = 1;
    } else if (content_type_length >= 6 && content_type[0] == 'i' && content_type[5] == '/' && strncmp(content_type, "image/", 6) == 0) {
        // image/*
        is_binary_type = 1;
    } else if (content_type_length >= 6 && content_type[0] == 'a' && content_type[5] == '/' && strncmp(content_type, "audio/", 6) == 0) {
        // audio/*
        is_binary_type = 1;
    } else if (content_type_length >= 6 && content_type[0] == 'v' && content_type[5] == '/' && strncmp(content_type, "video/", 6) == 0) {
        // video/*
        is_binary_type = 1;
    }
    return is_binary_type;
}


long long current_time_in_millis() {
    // get current tv
    struct timeval tv;
    gettimeofday(&tv, NULL);
    // convert tv to milliseconds
    long long milliseconds = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000LL);
    return milliseconds;
}

void tws_DecrRefCountUntilZero(Tcl_Obj *obj) {
    while (Tcl_IsShared(obj)) {
        Tcl_DecrRefCount(obj);
    }
    Tcl_DecrRefCount(obj);
}
