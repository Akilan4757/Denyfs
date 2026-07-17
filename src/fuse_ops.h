#ifndef DENYFS_FUSE_OPS_H
#define DENYFS_FUSE_OPS_H

#include "fs.h"

// Start FUSE main loop for the given volume at mount_point.
// Runs in foreground, single-threaded. Returns fuse_main's exit code.
int denyfs_fuse_run(denyfs_volume_t *vol, const char *mount_point);

#endif // DENYFS_FUSE_OPS_H
