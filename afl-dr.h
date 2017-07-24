#ifndef _AFL_DR_H_
#define _AFL_DR_H_

#include <dr_api.h>

#define EXIT_IF_FAILED(isOk, msg, code) \
    if (!(isOk)) { \
        dr_fprintf(STDERR, (msg)); \
        dr_exit_process((code)); \
    }

void start_forkserver(void);
void trace_bb_instrumentation(app_pc pc, bool for_trace);

#endif
