// Based on dr_annotations.h from DynamoRIO sources

#ifndef _AFL_DR_ANNOTATIONS_H_
#define _AFL_DR_ANNOTATIONS_H_ 1

#include "annotations/dr_annotations_asm.h"

/* To simplify project configuration, this pragma excludes the file from GCC warnings. */
#ifdef __GNUC__
# pragma GCC system_header
#endif

#define RUN_FORKSERVER() \
    DR_ANNOTATION(run_forkserver)

#ifdef __cplusplus
extern "C" {
#endif

DR_DECLARE_ANNOTATION(void, run_forkserver, ());

#ifdef __cplusplus
}
#endif

#endif
