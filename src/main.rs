use std::env::args;
use std::io::{Error, Write};
use std::fs::File;
use nix::fcntl::copy_file_range;
use std::os::fd::AsRawFd;

// Represents a range in the target file that's different from the base file (as indicated by the CoW metadata)
#[derive(Debug)]
struct DiffRange {
    logical_offset: u64,
    length: u64,
}

// We'll define a simple file format:
// - 8 bytes: magic string b"BDIFFv1\0"
// - 8 bytes (u64): number of diff ranges
// - For each diff range: 16 bytes (two u64s: logical_offset, length)
// - Followed by contiguous block data for each range
//
// We'll write the parser for this format later.

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

fn get_different_ranges(target_path: &str, base_path: &str) -> Result<Vec<DiffRange>, Error> {
    let mut diff_ranges = Vec::new();
    
    // Get fiemaps for both files, sorted by logical offset
    let mut target_extents: Vec<_> = fiemap::fiemap(target_path)?.collect::<Result<Vec<_>, _>>()?;
    let mut base_extents: Vec<_> = fiemap::fiemap(base_path)?.collect::<Result<Vec<_>, _>>()?;
    target_extents.sort_by_key(|e| e.fe_logical);
    base_extents.sort_by_key(|e| e.fe_logical);

    println!("target_extents:");
    for extent in &target_extents {
        println!("  {:?}", extent);
    }
    // Total size of target file
    let total_size = target_extents.last().unwrap().fe_logical + target_extents.last().unwrap().fe_length;
    println!("Total size of target file: {}", format_size(total_size));

    println!("base_extents:");
    for extent in &base_extents {
        println!("  {:?}", extent);
    }
    // Total size of base file
    let total_size = base_extents.last().unwrap().fe_logical + base_extents.last().unwrap().fe_length;
    println!("Total size of base file: {}", format_size(total_size));

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

fn main() -> Result<(), Error> {
    // Parse command line args
    let args: Vec<String> = args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <target_file> <base_file> <bdiff_output_file>", args[0]);
        std::process::exit(1);
    }

    let target_path = &args[1];
    let base_path = &args[2];
    let diff_output_path = &args[3];

    // 1) Open the target file so we can copy bytes from it later
    let target = File::open(target_path)?;

    // 2) Compute the diff ranges.
    let diff_ranges = get_different_ranges(target_path, base_path)?;

    println!("diff_ranges:");
    let mut total_size = 0;
    for range in &diff_ranges {
        println!("  {:?}", range);
        total_size += range.length;
    }
    println!("Total size of diff ranges: {}", format_size(total_size));

    // 3) Create the bdiff file
    let mut diff_out = File::create(diff_output_path)?;

    // 4) Write the header.
    let magic = b"BDIFFv1\0"; // 8 bytes
    diff_out.write_all(magic)?;
    let num_ranges = diff_ranges.len() as u64;
    diff_out.write_all(&num_ranges.to_le_bytes())?;

    // 5) Write each diff range's original offset/length as a header block.
    //    Each range is 16 bytes: offset (u64), length (u64).
    for range in &diff_ranges {
        diff_out.write_all(&range.logical_offset.to_le_bytes())?;
        diff_out.write_all(&range.length.to_le_bytes())?;
    }

    // 6) Write all data blocks contiguously after the header.
    for range in &diff_ranges {
        let mut off_in = range.logical_offset as i64;

        let copied = copy_file_range(
            target.as_raw_fd(),
            Some(&mut off_in),
            diff_out.as_raw_fd(),
            None, // Write to the end of the file
            range.length as usize,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

        if copied == 0 {
            return Err(Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to copy all requested bytes"
            ));
        }
    }

    // Ensure all data is written to disk
    diff_out.sync_all()?;

    Ok(())
}