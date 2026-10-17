// Credential Broker entry point (§5.8). All request-handling logic lives in
// the broker core (src/broker/{core,http,credentials}.c) so it is testable
// in-process; this shim only initialises libcurl and runs the accept loop.

#include "broker.h"
#include "log.h"

#include <curl/curl.h>

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    log_init();  // §10.12: honour SANDBOX_LOG_LEVEL
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        return 1;
    }
    int rc = broker_run();
    curl_global_cleanup();
    return rc == 0 ? 0 : 1;
}
