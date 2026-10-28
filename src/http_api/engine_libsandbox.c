// SPDX-License-Identifier: GPL-2.0-only
// The production engine: the libsandbox client, as-is.

#include "http_api.h"

const api_engine_ops_t api_engine_libsandbox = {
    .create = sandbox_create,
    .destroy = sandbox_destroy,
    .renew = sandbox_session_renew,
    .exec = sandbox_exec,
    .exec_free = sandbox_exec_result_free,
    .read_file = sandbox_read_file,
    .write_file = sandbox_write_file,
    .list_dir = sandbox_list_dir,
    .stat = sandbox_stat,
    .mkdir = sandbox_mkdir,
    .remove = sandbox_remove,
};
