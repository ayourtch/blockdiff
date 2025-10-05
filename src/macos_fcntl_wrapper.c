#include <fcntl.h>

// Wrapper for F_LOG2PHYS_EXT fcntl call
// This is needed because fcntl is variadic and doesn't work correctly when called
// directly from Rust - the struct fields get corrupted during the call.
// By calling from C, we ensure the correct ABI is used.
int fcntl_log2phys_ext(int fd, struct log2phys *ph) {
    return fcntl(fd, F_LOG2PHYS_EXT, ph);
}
