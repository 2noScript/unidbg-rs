use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(has_dynarmic)");
    println!("cargo:rerun-if-env-changed=DYNARMIC_HOME");
    println!("cargo:rerun-if-env-changed=DYNARMIC_BUILD");

    let Ok(home) = env::var("DYNARMIC_HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let build = env::var("DYNARMIC_BUILD")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join("build"));

    if !build.join("src/dynarmic/libdynarmic.a").is_file() {
        return;
    }

    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .file("native/dynarmic_capi.cpp")
        .include(home.join("src"))
        .include(home.join("externals/fmt/include"))
        .compile("unidbg_dynarmic_capi");

    println!("cargo:rustc-link-search=native={}", build.join("src/dynarmic").display());
    println!("cargo:rustc-link-search=native={}", build.join("externals/mcl/src").display());
    println!("cargo:rustc-link-search=native={}", build.join("externals/fmt").display());
    println!("cargo:rustc-link-lib=static=dynarmic");
    println!("cargo:rustc-link-lib=static=mcl");
    println!("cargo:rustc-link-lib=static=fmt");
    println!("cargo:rustc-cfg=has_dynarmic");
}
