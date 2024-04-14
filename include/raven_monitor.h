#ifndef RAVEN_MONITOR_H
#define RAVEN_MONITOR_H

#include "Raven.h"

typedef enum {
    TYPE_BYTE,
    TYPE_STRING,
    TYPE_INT16,
    TYPE_INT32,
    TYPE_INT64,
    TYPE_POINTER
} RavenType;

/**
 * @brief Used to run a thread which manages all of the current monitoring windows
 * 
 */
DWORD WINAPI window_monitor_thread();

#endif