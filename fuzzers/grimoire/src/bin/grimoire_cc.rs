use libafl_cc::{ClangWrapper, CompilerWrapper, LLVMPasses};
use std::env;

pub fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let mut dir = env::current_exe().unwrap();
        let wrapper_name = dir.file_name().unwrap().to_str().unwrap();

        let is_cpp = match wrapper_name[wrapper_name.len()-2..].to_lowercase().as_str() {
            "cc" => false,
            "++" | "pp" | "xx" => true,
            _ => panic!("Could not figure out if c or c++ warpper was called. Expected {:?} to end with c or cxx", dir),
        };

        dir.pop();

        let mut cc = ClangWrapper::new();

        #[cfg(target_os = "linux")]
        cc.add_pass(LLVMPasses::AutoTokens);

        if let Some(code) = cc
            .cpp(is_cpp)
            // silence the compiler wrapper output, needed for some configure scripts.
            .silence(true)
            // add arguments only if --libafl or --libafl-no-link are present
            .need_libafl_arg(true)
            .parse_args(&args)
            .expect("Failed to parse the command line")
            .link_staticlib(&dir, env!("CARGO_PKG_NAME"))
            .add_arg("-fsanitize-coverage=trace-pc-guard,trace-cmp")
            .add_pass(LLVMPasses::CmpLogRtn)
            // needed by Nautilus
            .add_link_arg("-Wl,--push-state,-Bstatic")
            .add_link_arg("-L/usr/local/lib/python3.8/config-3.8-x86_64-linux-gnu/")
            .add_link_arg("-L/usr/lib/python3.8/config-3.8-x86_64-linux-gnu/")
            .add_link_arg("-lpython3.8")
            .add_link_arg("-Wl,--pop-state")
            .add_link_arg("-lutil")
            .run()
            .expect("Failed to run the wrapped compiler")
        {
            std::process::exit(code);
        }
    } else {
        panic!("LibAFL CC: No Arguments given");
    }
}
