#ifndef TR101290_TYPES_H
#define TR101290_TYPES_H

#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <libltntstools/stats.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "libltntstools/tr101290.h"
#include "libltntstools/time.h"

/* Set to 1 to include code that triggers test routines when certain files are present in /tmp.
 * Production builds should ALWAYS be sero to zero.
 */
#define ENABLE_TESTING 1

/* TR101290 isn't supported on MAC Yet, but keep the compiler happy. */
#if defined(__APPLE__)
typedef unsigned int timer_t;
#endif

struct tr_event_s
{
	int enabled;
	int priorityNr;	/* 1, 2 are the only permissable values. These related to 101290 p1, p2 or p3 levels. */
	enum ltntstools_tr101290_event_e id;
	char name[64];

	int raised;    /* Boolean */
	int reportXX;  /*: TODO, this can be removed, if the events defaults table is edited to remove it. */
	struct timeval lastChanged;	/* When the raised state changes, we bump this timestamp. */
	struct timeval lastReported;	/* Last time we sent this alarm via the user callback. */
	struct timeval nextReportXX;    /*: TODO, this can be removed, if the events defaults table is edited to remove it. */
	struct timeval reportInterval;
	int autoClearAlarmAfterReport;  /* Number of seconds. Automatically clear the alarm, if possible, zero implies never autoclear. */

	/* One timer per event, used to ensure time based events are properly tracked.
	 * Timers are used per event, and fire when an event that was supposed to occur every
	 * Nms doesn't occur, so the timer fires and an alarm condition is raised.
	 */
	int timerRequired; /* Boolean */
	int timerAlarmPeriodms; /* If the timer isn't cancelled within this period (ms), it fires and an alarm is raised. */
	timer_t timerId;
};

struct ltntstools_tr101290_s
{
	pthread_t threadId;
	int threadTerminate, threadTerminated, threadRunning;

	ltntstools_tr101290_notification cb_notify;
	void *userContext;

	/* A cloned and modified version of the tr_events_tbl. The original table contains
	 * context default, sane static settings.
	 * We dup the table into our context then tamper/modify it to trace state.
	 */
	pthread_mutex_t mutex;
	struct tr_event_s *event_tbl;

	/* Alarm list for reporting to user. This is a dymanic table
	 * maintained by the event thread. It's resized according to
	 * conditions. A COPY of this allocation is made and passed
	 * to the applications upper layers for inspection.
	 */
	int alarmCount;
	struct ltntstools_tr101290_alarm_s *alarm_tbl;

	/* Vars to help track alarm stats */
	int consecutiveSyncBytes;
	struct timeval now; /* Updated when a _write call arrives. */
	struct timeval lastWriteCall;

	struct ltntstools_stream_statistics_s streamStatistics;
	uint64_t PATCountLastTimer;
	uint64_t CCCounterLastWrite;

	/* handle to a running PSIP stream modelling collector.
	 * The streammodel parses pats, PMTs, and pulls apart
	 * service metadata. We use this to find missing pids and such.
	 */
	void *smHandle;
};

#include "tr101290-events.h"
#include "tr101290-alarms.h"
#include "tr101290-timers.h"
#include "tr101290-p1.h"

#ifdef __cplusplus
};
#endif

#endif /* TR101290_TYPES_H */
