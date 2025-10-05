use std::fs::File;
use std::io::Error;
use std::os::unix::io::AsRawFd;

// Simplified extent structure compatible with fiemap::FiemapExtent
#[derive(Debug, Clone)]
pub struct Extent {
    pub fe_logical: u64,
    pub fe_physical: u64,
    pub fe_length: u64,
    pub fe_flags: ExtentFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExtentFlags: u32 {
        const SHARED = 0x00002000;
        const LAST = 0x00000001;
    }
}

// macOS F_LOG2PHYS_EXT structures
// From sys/fcntl.h with #pragma pack(4) - results in 20-byte struct
#[repr(C, packed(4))]
struct Log2PhysExt {
    l2p_flags: u32,       // 4 bytes at offset 0
    l2p_contigbytes: i64,  // 8 bytes at offset 4
    l2p_devoffset: i64,    // 8 bytes at offset 12
}

const F_LOG2PHYS_EXT: libc::c_int = 49;

// C wrapper function that calls fcntl correctly
// (variadic functions don't work properly when called directly from Rust)
extern "C" {
    fn fcntl_log2phys_ext(fd: libc::c_int, ph: *mut Log2PhysExt) -> libc::c_int;
}

/// Get file extents on macOS using F_LOG2PHYS_EXT
/// Based on Mario Wolczko's implementation: https://researcher.watson.ibm.com/researcher/view_group_subpage.php?id=9769
pub fn get_file_extents(path: &str) -> Result<Vec<Extent>, Error> {
    let file = File::open(path)?;
    let fd = file.as_raw_fd();
    let file_size = file.metadata()?.len();

    let mut extents = Vec::new();
    let mut offset: i64 = 0;

    while (offset as u64) < file_size {
        // Allocate on heap to ensure proper alignment
        let mut log2phys = Box::new(Log2PhysExt {
            l2p_flags: 0,
            l2p_contigbytes: (file_size as i64) - offset,
            l2p_devoffset: offset,
        });

        // Call C wrapper function (variadic fcntl doesn't work correctly from Rust)
        let result = unsafe {
            let ptr = &mut *log2phys as *mut Log2PhysExt;
            fcntl_log2phys_ext(fd, ptr)
        };

        if result < 0 {
            let err = Error::last_os_error();
            // ERANGE means we hit a hole (sparse region with no physical storage)
            if err.raw_os_error() == Some(libc::ERANGE) {
                // Skip to next data using SEEK_DATA
                let next_data = unsafe {
                    libc::lseek(fd, offset, libc::SEEK_DATA)
                };

                if next_data < 0 {
                    // No more data in file
                    break;
                }
                offset = next_data;
                continue;
            } else {
                return Err(err);
            }
        }

        // After fcntl:
        // l2p_devoffset = physical device offset (OUTPUT)
        // l2p_contigbytes = number of contiguous bytes at this physical location (OUTPUT)
        let physical = log2phys.l2p_devoffset;
        let contig_bytes = log2phys.l2p_contigbytes;

        if contig_bytes <= 0 {
            return Err(Error::new(
                std::io::ErrorKind::InvalidData,
                format!("F_LOG2PHYS_EXT returned invalid contig_bytes: {}", contig_bytes)
            ));
        }

        extents.push(Extent {
            fe_logical: offset as u64,
            fe_physical: physical as u64,
            fe_length: contig_bytes as u64,
            fe_flags: if (offset + contig_bytes) as u64 >= file_size {
                ExtentFlags::LAST
            } else {
                ExtentFlags::empty()
            },
        });

        // Move to the next extent
        offset += contig_bytes;
    }

    Ok(extents)
}
