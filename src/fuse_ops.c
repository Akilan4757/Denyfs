#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include "fuse_ops.h"
#include "fs.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static denyfs_volume_t *get_vol(void) {
    return (denyfs_volume_t *)fuse_get_context()->private_data;
}

// Extract filename from FUSE path. Returns NULL for root, pointer past '/'
// for flat filenames, and NULL for nested paths (which we reject).
static const char *path_to_name(const char *path) {
    if (strcmp(path, "/") == 0) return NULL;
    if (path[0] != '/') return NULL;
    if (strchr(path + 1, '/') != NULL) return NULL;  // nested path
    return path + 1;
}

// ---------------------------------------------------------------------------
// FUSE callbacks
// ---------------------------------------------------------------------------

static int denyfs_fuse_getattr(const char *path, struct stat *stbuf,
                                struct fuse_file_info *fi) {
    (void)fi;
    denyfs_volume_t *vol = get_vol();
    memset(stbuf, 0, sizeof(*stbuf));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode  = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_mtime = (time_t)vol->inodes[0].mtime;
        stbuf->st_atime = stbuf->st_mtime;
        stbuf->st_ctime = stbuf->st_mtime;
        return 0;
    }

    const char *name = path_to_name(path);
    if (!name) return -ENOENT;

    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    denyfs_inode_t *inode = &vol->inodes[ino];
    stbuf->st_mode   = S_IFREG | 0644;
    stbuf->st_nlink  = 1;
    stbuf->st_size   = inode->size;
    stbuf->st_blocks = ((off_t)inode->size + 511) / 512;
    stbuf->st_mtime  = (time_t)inode->mtime;
    stbuf->st_atime  = stbuf->st_mtime;
    stbuf->st_ctime  = stbuf->st_mtime;
    return 0;
}

struct readdir_ctx {
    void *buf;
    fuse_fill_dir_t filler;
};

static int readdir_cb(const char *name, uint32_t ino, void *userdata) {
    (void)ino;
    struct readdir_ctx *ctx = (struct readdir_ctx *)userdata;
    ctx->filler(ctx->buf, name, NULL, 0, 0);
    return 0;
}

static int denyfs_fuse_readdir(const char *path, void *buf,
                                fuse_fill_dir_t filler, off_t offset,
                                struct fuse_file_info *fi,
                                enum fuse_readdir_flags flags) {
    (void)offset; (void)fi; (void)flags;
    if (strcmp(path, "/") != 0) return -ENOENT;

    denyfs_volume_t *vol = get_vol();

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    struct readdir_ctx ctx = { .buf = buf, .filler = filler };
    denyfs_vol_readdir(vol, readdir_cb, &ctx);
    return 0;
}

static int denyfs_fuse_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;
    return 0;
}

static int denyfs_fuse_read(const char *path, char *buf, size_t size,
                             off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    return denyfs_vol_read(vol, ino, buf, size, (uint64_t)offset);
}

static int denyfs_fuse_write(const char *path, const char *buf, size_t size,
                              off_t offset, struct fuse_file_info *fi) {
    (void)fi;
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    return denyfs_vol_write(vol, ino, buf, size, (uint64_t)offset);
}

static int denyfs_fuse_create(const char *path, mode_t mode,
                               struct fuse_file_info *fi) {
    (void)mode; (void)fi;
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    uint32_t ino;
    return denyfs_vol_create(vol, name, &ino);
}

static int denyfs_fuse_unlink(const char *path) {
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    return denyfs_vol_unlink(vol, name);
}

static int denyfs_fuse_truncate(const char *path, off_t size,
                                 struct fuse_file_info *fi) {
    (void)fi;
    const char *name = path_to_name(path);
    if (!name) return -EISDIR;

    denyfs_volume_t *vol = get_vol();
    uint32_t ino;
    if (denyfs_vol_lookup(vol, name, &ino) != 0) return -ENOENT;

    return denyfs_vol_truncate(vol, ino, (uint32_t)size);
}

static void denyfs_fuse_destroy(void *private_data) {
    denyfs_volume_t *vol = (denyfs_volume_t *)private_data;
    if (vol) {
        denyfs_vol_flush(vol);
        denyfs_vol_close(vol);
    }
}

// ---------------------------------------------------------------------------
// Public: run FUSE main loop
// ---------------------------------------------------------------------------

static const struct fuse_operations denyfs_ops = {
    .getattr  = denyfs_fuse_getattr,
    .readdir  = denyfs_fuse_readdir,
    .open     = denyfs_fuse_open,
    .read     = denyfs_fuse_read,
    .write    = denyfs_fuse_write,
    .create   = denyfs_fuse_create,
    .unlink   = denyfs_fuse_unlink,
    .truncate = denyfs_fuse_truncate,
    .destroy  = denyfs_fuse_destroy,
};

int denyfs_fuse_run(denyfs_volume_t *vol, const char *mount_point) {
    // Build FUSE args: foreground (-f) + single-threaded (-s)
    char *fuse_argv[] = {
        "denyfs",
        (char *)mount_point,
        "-f",
        "-s",
        NULL
    };
    int fuse_argc = 4;

    return fuse_main(fuse_argc, fuse_argv, &denyfs_ops, vol);
}
