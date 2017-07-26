project(afl-dr)

# Test executables. In fact, you may need to compile them manually
# to use afl-gcc instead of plain gcc (not for execution under DynamoRIO)
add_executable(example-bug-libc example-bug-libc.c)
add_executable(example-bug      example-bug.c)

# Static library with custom DynamoRIO annotations
# to be linked to tested applications
add_library(afl-annotations STATIC afl-annotations.c)

add_dependencies(example-bug      afl-annotations)
add_dependencies(example-bug-libc afl-annotations)
target_link_libraries(example-bug      afl-annotations)
target_link_libraries(example-bug-libc afl-annotations)

# The DynamoRIO client that performs dynamic instrumentation
add_library(afl-dr SHARED afl-dr.cpp afl-forksrv.cpp module-filter.cpp)
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)
configure_DynamoRIO_client(afl-dr)

option(BB_PREPOPULATE "Enable basic block prepopulation in the parent forkserver process" ON)
if (BB_PREPOPULATE)
    add_definitions(-DBB_PREPOPULATE)
endif(BB_PREPOPULATE)

# The droption extension seems not to be available through this command,
# so using this kludge to add the include path
use_DynamoRIO_extension(afl-dr drutil)
