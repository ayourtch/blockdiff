use clap::{Parser, Subcommand};
use std::io::{Error, Write, Read, Seek};
use std::fs::File;
use nix::fcntl::copy_file_range;
use std::os::fd::AsRawFd;
use serde::{Serialize, Deserialize};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a block-level diff between two files
    Create {
        /// Path to the target file to diff
        target_file: String,
        /// Path to the base file to compare against
        base_file: String,
        /// Path where to write the bdiff output
        bdiff_output: String,
    },
    /// Apply a block-level diff to create a new file
    Apply {
        /// Path where to create the target file
        target_file: String,
        /// Path to the base file
        base_file: String,
        /// Path to the bdiff file to apply
        bdiff_input: String,
    },
}

/// Represents a range in the target file that's different from the base file (as indicated by the CoW metadata)
#[derive(Debug, Serialize, Deserialize)]
struct DiffRange {
    logical_offset: u64,
    length: u64,
}

/// Magic string for bdiff files ("BDIFFv1\0")
const MAGIC: &[u8; 8] = b"BDIFFv1\0";

/// Standard block size used for alignment (4 KiB)
const BLOCK_SIZE: usize = 4096;

/// Represents the header of a bdiff file. The file format is:
/// - Header:
///   - 8 bytes: magic string ("BDIFFv1\0")
///   - 8 bytes: target file size (little-endian)
///   - 8 bytes: base file size (little-endian)
///   - 8 bytes: number of ranges (little-endian)
///   - Ranges array, each range containing:
///     - 8 bytes: logical offset (little-endian)
///     - 8 bytes: length (little-endian)
/// - Padding to next block boundary (4 KiB)
/// - Range data (contiguous blocks of data)
#[derive(Debug, Serialize, Deserialize)]
struct BDiffHeader {
    magic: [u8; 8],
    target_size: u64,
    base_size: u64,
    ranges: Vec<DiffRange>,
}

impl BDiffHeader {
    fn new(target_size: u64, base_size: u64, ranges: Vec<DiffRange>) -> Self {
        Self {
            magic: *MAGIC,
            target_size,
            base_size,
            ranges,
        }
    }

    fn write_to(&self, writer: impl Write) -> Result<(), Error> {
        bincode::serialize_into(writer, self)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))
    }

    fn read_from(reader: impl Read) -> Result<Self, Error> {
        let header: Self = bincode::deserialize_from(reader)
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e))?;
        
        if header.magic != *MAGIC {
            return Err(Error::new(std::io::ErrorKind::InvalidData, "Invalid bdiff file format"));
        }
        
        Ok(header)
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }

    // Find the appropriate unit (how many times can we divide by 1024)
    let exp = (bytes as f64).ln() / 1024_f64.ln();
    let exp = exp.floor() as usize;
    let exp = exp.min(UNITS.len() - 1); // Don't exceed available units

    // Convert to the chosen unit
    let bytes = bytes as f64 / (1024_u64.pow(exp as u32) as f64);
    
    // Format with 1 decimal place if >= 1024 bytes, otherwise no decimal
    if exp == 0 {
        format!("{} {}", bytes.round(), UNITS[exp])
    } else {
        format!("{:.1} {}", bytes, UNITS[exp])
    }
}

fn get_different_ranges(target_file: &str, base_file: &str) -> Result<Vec<DiffRange>, Error> {
    let mut diff_ranges = Vec::new();
    
    // Get fiemaps for both files, sorted by logical offset
    let mut target_extents: Vec<_> = fiemap::fiemap(target_file)?.collect::<Result<Vec<_>, _>>()?;
    let mut base_extents: Vec<_> = fiemap::fiemap(base_file)?.collect::<Result<Vec<_>, _>>()?;
    target_extents.sort_by_key(|e| e.fe_logical);
    base_extents.sort_by_key(|e| e.fe_logical);

    // Total size of target file
    let total_size: u64 = target_extents.iter().map(|e| e.fe_length).sum();
    println!("Size of target file: {}", format_size(total_size));

    // Total size of base file
    let total_size: u64 = base_extents.iter().map(|e| e.fe_length).sum();
    println!("Size of base file: {}", format_size(total_size));

    // A helper closure for getting the end of any extent quickly
    let extent_end = |e: &fiemap::FiemapExtent| e.fe_logical + e.fe_length;

    // Index for base_extents
    let mut i = 0;

    'target_loop: for target_extent in target_extents {
        let mut current_start = target_extent.fe_logical;
        let mut current_remaining = target_extent.fe_length;

        // If this is a non-shared extent, it's entirely different.
        if !target_extent.fe_flags.contains(fiemap::FiemapExtentFlags::SHARED) {
            diff_ranges.push(DiffRange {
                logical_offset: current_start,
                length: current_remaining,
            });
            continue;
        }

        // Shared extent: we need to check partial overlaps with base_extents
        while current_remaining > 0 {
            // Skip any base extents that end before our current offset
            while i < base_extents.len() && extent_end(&base_extents[i]) <= current_start {
                i += 1;
            }
            // If we've consumed all base extents, everything left is different
            if i >= base_extents.len() {
                diff_ranges.push(DiffRange {
                    logical_offset: current_start,
                    length: current_remaining,
                });
                continue 'target_loop; // Move on to the next target extent
            }

            // Now, base_extents[i] is the first base extent that could overlap our target_extent
            let base_extent = &base_extents[i];
            let base_start = base_extent.fe_logical;
            let base_end = extent_end(base_extent);

            // Compute overlap boundaries
            let overlap_start = current_start.max(base_start);
            let overlap_end = (current_start + current_remaining).min(base_end);

            // If there's no overlap, then the remainder of target_extent is all different
            if overlap_start >= overlap_end {
                diff_ranges.push(DiffRange {
                    logical_offset: current_start,
                    length: current_remaining,
                });
                continue 'target_loop;
            }

            // Physical offset for each file at overlap_start
            let current_physical_start =
                target_extent.fe_physical + (overlap_start - target_extent.fe_logical);
            let base_physical_start =
                base_extent.fe_physical + (overlap_start - base_extent.fe_logical);
            let overlap_len = overlap_end - overlap_start;

            // If physical offsets match, we consider that region "the same" and skip it
            if current_physical_start == base_physical_start {
                // "Consume" this overlap (not added to diff)
                current_start = overlap_end;
                current_remaining -= overlap_len;
            } else {
                // This overlap is different
                diff_ranges.push(DiffRange {
                    logical_offset: overlap_start,
                    length: overlap_len,
                });
                // Move past the overlap in the target
                current_start = overlap_end;
                current_remaining -= overlap_len;
            }

            // If we've consumed the entire base extent in that overlap, move on
            if overlap_end == base_end {
                i += 1;
            }
        }
    }

    Ok(diff_ranges)
}


fn create_diff(target_file: &str, base_file: &str, bdiff_output: &str) -> Result<(), Error> {
    // 1) Open the target file so we can copy bytes from it later
    let target = File::open(target_file)?;
    let base = File::open(base_file)?;
    let target_size = target.metadata()?.len();
    let base_size = base.metadata()?.len();

    // 2) Compute the diff ranges
    let diff_ranges = get_different_ranges(target_file, base_file)?;
    let total_size: u64 = diff_ranges.iter().map(|range| range.length).sum();
    println!("Size of blockdiff: {}", format_size(total_size));

    // 3) Create the bdiff file
    let mut diff_out = File::create(bdiff_output)?;

    // 4) Create and write the header
    let header = BDiffHeader::new(target_size, base_size, diff_ranges);
    header.write_to(&mut diff_out)?;

    // 5) Pad with zeros to align header to block boundary
    let header_size = bincode::serialized_size(&header)     
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))? as usize;
    let padding_size = (BLOCK_SIZE - (header_size % BLOCK_SIZE)) % BLOCK_SIZE;
    let padding = vec![0u8; padding_size];
    diff_out.write_all(&padding)?;

    // 6) Write all data blocks contiguously after the header
    for range in &header.ranges {
        let mut off_in = range.logical_offset as i64;

        let copied = copy_file_range(
            target.as_raw_fd(),
            Some(&mut off_in),
            diff_out.as_raw_fd(),
            None, // Write to the end of the file
            range.length as usize,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

        if copied != range.length as usize {
            return Err(Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Failed to copy all requested bytes for range {:?}: copied {} bytes, expected {}", 
                    range, copied, range.length)
            ));
        }
    }

    println!("Successfully created blockdiff file at {}", bdiff_output);

    Ok(())
}

fn apply_diff(target_file: &str, base_file: &str, bdiff_input: &str) -> Result<(), Error> {
    // First, create a reflink copy of the base file as our target
    let src = File::open(base_file)?;
    let dst = File::create(target_file)?;
    let total_len = src.metadata()?.len() as usize;
    let mut copied_total = 0;
    while copied_total < total_len {
        let copied = copy_file_range(
            src.as_raw_fd(),
            None,
            dst.as_raw_fd(),
            None,
            total_len - copied_total
        ).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        
        if copied == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Failed to create target file {} as copy of base file {}: copied {} bytes, expected {}", 
                    target_file, base_file, copied_total, total_len)
            ));
        }
        
        copied_total += copied;
    }

    println!("Created target file at {}", target_file);
    
    // Open the diff file and read header
    let mut diff_in = File::open(bdiff_input)?;
    let header = BDiffHeader::read_from(&mut diff_in)?;
    
    // Skip padding to align with block boundary
    let header_size = bincode::serialized_size(&header)
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e))? as usize;
    let padding_size = (BLOCK_SIZE - (header_size % BLOCK_SIZE)) % BLOCK_SIZE;
    diff_in.seek(std::io::SeekFrom::Current(padding_size as i64))?;
    
    // Open target file for writing
    let target = File::options().write(true).open(target_file)?;
    
    // Apply each range
    for range in header.ranges {
        let mut off_out = range.logical_offset as i64;
        let copied = copy_file_range(
            diff_in.as_raw_fd(),
            None,
            target.as_raw_fd(),
            Some(&mut off_out),
            range.length as usize,
        ).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
        
        if copied != range.length as usize {
            return Err(Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("Failed to copy all requested bytes for range {:?}: copied {} bytes, expected {}", 
                    range, copied, range.length)
            ));
        }
    }

    println!("Successfully applied {} to target file", bdiff_input);

    Ok(())
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Create { target_file, base_file, bdiff_output } => {
            create_diff(target_file, base_file, bdiff_output)
        }
        Commands::Apply { target_file, base_file, bdiff_input } => {
            apply_diff(target_file, base_file, bdiff_input)
        }
    }
}