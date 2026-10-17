#ifndef SANDBOX_VERSION_H
#define SANDBOX_VERSION_H

// Single source of truth for the engine version. Overridable at build time via
// -DSANDBOX_VERSION=\"x.y.z\" (see CMakeLists.txt), which is what a release
// build does; the fallback keeps ad-hoc builds honest.
#ifndef SANDBOX_VERSION
#define SANDBOX_VERSION "0.12.0"
#endif

#endif // SANDBOX_VERSION_H
