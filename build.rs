fn main() {
    #[cfg(target_os = "macos")]
    {
        // Compile the C wrapper for macOS
        cc::Build::new()
            .file("src/macos_fcntl_wrapper.c")
            .compile("macos_fcntl_wrapper");
    }
}
