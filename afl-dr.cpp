#include <dr_api.h>
#include <droption.h>

#include <stdint.h>
#include <sys/shm.h>

#include "afl-annotations.h"
#include "afl-dr.h"

static droption_t<bool> opt_instrument_everything(DROPTION_SCOPE_CLIENT, "instrument-everything", false,
                                                  "Instrument everything",
                                                  "Instrument all executable code instead of just the main module");

static void parse_options(int argc, const char *argv[]) {
    std::string parse_err;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, NULL)) {
        dr_fprintf(STDERR, "Incorrect client options: %s\n", parse_err.c_str());
        dr_exit_process(1);
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

module_data_t *main_module;

static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating) {
    app_pc pc = dr_fragment_app_pc(tag);

    if (!translating) {
        trace_bb_instrumentation(pc, for_trace);
    }

    if (!opt_instrument_everything.get_value() && !dr_module_contains_addr(main_module, pc)) {
        return DR_EMIT_DEFAULT;
    }

    uint32_t cur_location = (((uint32_t)(uintptr_t)pc) * (uint32_t)33533) & 0xFFFF;
    instr_t *where = instrlist_first(bb);

    dr_save_arith_flags(drcontext, bb, where, SPILL_SLOT_1);

    reg_id_t tls_reg = DR_REG_XDI, offset_reg = DR_REG_XDX;

    dr_save_reg(drcontext, bb, where, tls_reg, SPILL_SLOT_2);
    dr_save_reg(drcontext, bb, where, offset_reg, SPILL_SLOT_3);

    if (dr_using_all_private_caches()) {
        instrlist_meta_preinsert(bb, where,
            INSTR_CREATE_mov_imm(drcontext,
                                 opnd_create_reg(tls_reg),
                                 OPND_CREATE_INTPTR(dr_get_tls_field(drcontext))));
    } else {
        dr_insert_read_tls_field(drcontext, bb, where, tls_reg);
    }

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

    main_module = dr_get_main_module();

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
