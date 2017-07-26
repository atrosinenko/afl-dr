#include "afl-dr.h"

#include <dr_api.h>
#include <droption.h>

static droption_t<bool> opt_instrument_everything(DROPTION_SCOPE_CLIENT, "instrument-everything", false,
                                                  "Instrument everything",
                                                  "Instrument all executable code instead of just the main module");

module_data_t *main_module;

bool need_instrument_pc(app_pc pc) {
    return opt_instrument_everything.get_value() || dr_module_contains_addr(main_module, pc);
}

void init_module_filter(void) {
    main_module = dr_get_main_module();
}
