#include <dr_api.h>
#include <droption.h>

#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>

#include "afl-annotations.h"

static const int FROM_FUZZER_FD = 198;
static const int TO_FUZZER_FD   = 199;

typedef int (*fork_fun_t)();

#define EXIT_IF_FAILED(isOk, msg, code) \
    if (!(isOk)) { \
        dr_fprintf(STDERR, (msg)); \
        dr_exit_process((code)); \
    }

static droption_t<bool> opt_private_fork(DROPTION_SCOPE_CLIENT, "private-fork", false,
                                         "Use fork function from the private libc",
                                         "Use fork function from the private libc");

static void parse_options(int argc, const char *argv[]) {
    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, NULL)) {
        dr_fprintf(STDERR, "Incorrect client options: %s\n", parse_err.c_str());
        dr_exit_process(1);
    }
}

static void start_forkserver() {
    // For references, see https://lcamtuf.blogspot.ru/2014/10/fuzzing-binaries-without-execve.html
    // and __afl_start_forkserver in llvm_mode/afl-llvm-rt.o.c from AFL sources

    static bool forkserver_is_running = false;

    uint32_t unused_four_bytes = 0;
    uint32_t was_killed;

    if (!forkserver_is_running) {
        dr_printf("Running forkserver...\n");
        forkserver_is_running = true;
    } else {
        dr_printf("Warning: Attempt to re-run forkserver ignored.\n");
        return;
    }

    if (write(TO_FUZZER_FD, &unused_four_bytes, 4) != 4) {
        dr_printf("Cannot connect to fuzzer.\n");
        return;
    }

    fork_fun_t fork_ptr;
    // Lookup the fork function from target application, so both DynamoRIO
    // and application's copy of libc know about fork
    // Currently causes crashes sometimes, in that case use the private libc's fork.
    if (!opt_private_fork.get_value()) {
        module_data_t *module = dr_lookup_module_by_name("libc.so.6");
        EXIT_IF_FAILED(module != NULL, "Cannot lookup libc.\n", 1)
        fork_ptr = (fork_fun_t)dr_get_proc_address(module->handle, "fork");
        EXIT_IF_FAILED(fork_ptr != NULL, "Cannot get fork function from libc.\n", 1)
        dr_free_module_data(module);
    } else {
        fork_ptr = fork;
    }

    while (true) {
        EXIT_IF_FAILED(read(FROM_FUZZER_FD, &was_killed, 4) == 4, "Incorrect spawn command from fuzzer.\n", 1)
        int child_pid = fork_ptr();
        EXIT_IF_FAILED(child_pid >= 0, "Cannot fork.\n", 1)

        if (child_pid == 0) {
            close(TO_FUZZER_FD);
            close(FROM_FUZZER_FD);
            return;
        } else {
            int status;
            EXIT_IF_FAILED(write(TO_FUZZER_FD, &child_pid, 4) == 4, "Cannot write child PID.\n", 1)
            EXIT_IF_FAILED(waitpid(child_pid, &status, 0) >= 0,     "Wait for child failed.\n", 1)
            EXIT_IF_FAILED(write(TO_FUZZER_FD, &status, 4) == 4,    "Cannot write child exit status.\n", 1)
        }
    }
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    parse_options(argc, argv);
    EXIT_IF_FAILED(
        dr_annotation_register_call("run_forkserver", (void *)start_forkserver, false, 0, DR_ANNOTATION_CALL_TYPE_FASTCALL),
        "Cannot register forkserver annotation.\n", 1);
}
