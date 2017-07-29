#include "afl-dr.h"

#include <dr_api.h>
#include <droption.h>

static const std::string MAIN_MODULE_NAME = "<main>";

static droption_t<std::string> opt_instrument_modules(DROPTION_SCOPE_CLIENT, "instrument-modules", MAIN_MODULE_NAME,
                                                      "Modules to instrument",
                                                      "Modules to instrument, f.e. \"libc.so.6:<main>\", default: <main>");

static std::vector<std::string> module_names;
static std::vector<const module_data_t *> modules;

bool need_instrument_pc(app_pc pc) {
    for (size_t i = 0; i < modules.size(); ++i) {
        if (dr_module_contains_addr(modules[i], pc))
            return true;
    }
    return false;
}

static void register_module(const std::string &name) {
    if (name == MAIN_MODULE_NAME) {
        modules.push_back(dr_get_main_module());
    } else {
        module_names.push_back(name);
    }
}

static void event_module_load(void *drcontext, const module_data_t *info,
                              bool loaded) {
    std::string name = dr_module_preferred_name(info);
    dr_printf("Loading module %s... ", name.c_str());
    for (size_t i = 0; i < module_names.size(); ++i) {
        if (module_names[i] == name) {
            modules.push_back(dr_copy_module_data(info));
            dr_printf("will be instrumented");
        }
    }
    dr_printf("\n");
}

void init_module_filter(void) {
    int start = 0;
    const std::string &names = opt_instrument_modules.get_value();
    for (size_t i = 0; i < names.length(); ++i) {
        if (names[i] == ':') {
            register_module(names.substr(start, i - start));
            start = i + 1;
        }
    }
    register_module(names.substr(start));
    dr_register_module_load_event(event_module_load);
}
