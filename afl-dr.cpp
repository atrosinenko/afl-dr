#include <dr_api.h>
#include <droption.h>

#include <stdint.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/shm.h>

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

static const int MAP_SIZE = 1 << 16;
static uint8_t *shmem;

static bool init_shmem(bool allow_dummy) {
    const char *id_str = getenv("__AFL_SHM_ID");
    if (!id_str) {
        dr_fprintf(STDERR, "Cannot get SHM id from the environment.\n");
        if (allow_dummy) {
            dr_fprintf(STDERR, "Creating dummy map.\n");
            shmem = (uint8_t *)dr_global_alloc(MAP_SIZE);
            return true;
        }
        return false;
    }
    shmem = (uint8_t *)shmat(atoi(id_str), NULL, 0);
    EXIT_IF_FAILED(shmem != (void*)-1, "Cannot acquire SHM.\n", 1);
    dr_fprintf(STDERR, "SHM = %p\n", shmem);
    return true;
}

typedef struct {
    uint64_t scratch;
    uint8_t map[MAP_SIZE];
} thread_data;

static void *lock;

static void event_thread_init(void *drcontext) {
    void *data = dr_thread_alloc(drcontext, sizeof(thread_data));
    memset(data, 0, sizeof(thread_data));
    dr_set_tls_field(drcontext, data);
}

static void event_thread_exit(void *drcontext) {
    thread_data *data = (thread_data *) dr_get_tls_field(drcontext);

    dr_mutex_lock(lock);
    for (int i = 0; i < MAP_SIZE; ++i) {
        shmem[i] += data->map[i];
    }
    dr_mutex_unlock(lock);
    dr_thread_free(drcontext, data, sizeof(thread_data));
}

static void event_exit() {
    if (lock) {
        dr_mutex_destroy(lock);
        lock = NULL;
    }
}

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating) {
    app_pc pc = dr_fragment_app_pc(tag);

    uint32_t cur_location = (((uint32_t)(uintptr_t)pc) * (uint32_t)33533) & 0xFFFF;
    instr_t *where = instrlist_first(bb);

    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);

    reg_id_t tls_reg = DR_REG_XDI, offset_reg = DR_REG_XDX;

    dr_save_reg(drcontext, bb, where, tls_reg, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, offset_reg, SPILL_SLOT_3);

    dr_insert_read_tls_field(drcontext, bb, where, tls_reg);

    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_load(drcontext,
                          opnd_create_reg(offset_reg),
                          OPND_CREATE_MEM64(tls_reg, offsetof(thread_data, scratch))));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_xor(drcontext,
                         opnd_create_reg(offset_reg),
                         OPND_CREATE_INT32(cur_location)));
    instrlist_meta_preinsert(bb, where,
        XINST_CREATE_store(drcontext,
                           OPND_CREATE_MEM32(tls_reg, offsetof(thread_data, scratch)),
                           OPND_CREATE_INT32(cur_location >> 1)));
    instrlist_meta_preinsert(bb, where,
        INSTR_CREATE_inc(drcontext,
                         opnd_create_base_disp(tls_reg, offset_reg, 1, offsetof(thread_data, map), OPSZ_1)));

    dr_restore_reg(drcontext, bb, where, offset_reg, SPILL_SLOT_3);
    dr_restore_reg(drcontext, bb, where, tls_reg, SPILL_SLOT_2);

    dr_restore_arith_flags(drcontext, bb, where, SPILL_SLOT_1);

    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    parse_options(argc, argv);

    if (init_shmem(true)) {
        lock = dr_mutex_create();
        dr_register_thread_init_event(event_thread_init);
        dr_register_thread_exit_event(event_thread_exit);
        dr_register_bb_event(event_basic_block);
        dr_register_exit_event(event_exit);
    }

    EXIT_IF_FAILED(
        dr_annotation_register_call("run_forkserver", (void *)start_forkserver, false, 0, DR_ANNOTATION_CALL_TYPE_FASTCALL),
        "Cannot register forkserver annotation.\n", 1);
}
