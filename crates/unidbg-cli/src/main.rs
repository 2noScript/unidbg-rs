use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use unidbg_android::dvm::vm::DalvikVM;
use unidbg_android::emulator::AndroidEmulatorBuilder;
use unidbg_android::resolver::AndroidResolver;
use unidbg_api::arm::{Arch, ArmMode};
use unidbg_api::debugger::gdb::GdbServer;
use unidbg_api::emulator::Emulator;
use unidbg_unicorn2::unicorn_backend::UnicornBackend;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliArch {
    Arm32,
    Arm64,
}

impl From<CliArch> for Arch {
    fn from(a: CliArch) -> Self {
        match a {
            CliArch::Arm32 => Arch::Arm32,
            CliArch::Arm64 => Arch::Arm64,
        }
    }
}

#[derive(Parser)]
#[command(name = "unidbg-cli", about = "Rust ARM32/ARM64 Android emulator CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute an ELF binary from its entry point
    Exec {
        bin: PathBuf,
        #[arg(long, value_enum, default_value_t = CliArch::Arm64)]
        arch: CliArch,
        #[arg(long)]
        sdk: Option<PathBuf>,
        #[arg(long)]
        sdk_version: Option<u32>,
    },
    /// Load a shared library (.so) and call JNI_OnLoad and/or a Java_* export
    Jni {
        so: PathBuf,
        #[arg(long, value_enum, default_value_t = CliArch::Arm64)]
        arch: CliArch,
        #[arg(long)]
        sdk: Option<PathBuf>,
        #[arg(long, default_value_t = 23)]
        sdk_version: u32,
        #[arg(long)]
        onload: bool,
        #[arg(long)]
        call: Option<String>,
    },
    /// Start a GDB Remote Serial Protocol (RSP) server for a binary/library
    Gdb {
        target: PathBuf,
        #[arg(long, value_enum, default_value_t = CliArch::Arm64)]
        arch: CliArch,
        #[arg(long)]
        sdk: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:23946")]
        listen: String,
    },
}

fn build_emu(arch: Arch, sdk: Option<PathBuf>, sdk_ver: u32) -> Result<unidbg_android::emulator::AndroidEmulator> {
    let mode = match arch {
        Arch::Arm32 => ArmMode::Arm32,
        Arch::Arm64 => ArmMode::Arm64,
    };
    let backend = Box::new(UnicornBackend::new(arch, mode)?);
    let mut builder = match arch {
        Arch::Arm32 => AndroidEmulatorBuilder::for_32_bit(),
        Arch::Arm64 => AndroidEmulatorBuilder::for_64_bit(),
    };
    if let Some(dir) = sdk {
        builder = builder.resolver(AndroidResolver::new(sdk_ver, arch, dir));
    }
    Ok(builder.build(backend)?)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Exec {
            bin,
            arch,
            sdk,
            sdk_version,
        } => {
            let mut emu = build_emu(arch.into(), sdk, sdk_version.unwrap_or(23))?;
            let module = emu.load_library(&bin, true)?;
            let name = module.name.clone();
            let code = emu.call_entry(&module, &[&name])?;
            let out = emu.fs().borrow().stdout.as_string();
            if !out.is_empty() {
                print!("{out}");
            }
            println!("exit({code})");
        }
        Command::Jni {
            so,
            arch,
            sdk,
            sdk_version,
            onload,
            call,
        } => {
            let mut emu = build_emu(arch.into(), sdk, sdk_version)?;
            let vm = DalvikVM::init(&mut emu)?;
            let module = emu.load_library(&so, true)?;
            emu.call_init_functions(&module)?;
            if onload {
                let ver = vm.call_jni_onload(&mut emu, &module)?;
                println!("JNI_OnLoad => {ver:#x}");
            }
            if let Some(sym) = call {
                let addr = module
                    .find_symbol_addr(&sym)
                    .with_context(|| format!("symbol {sym} not found"))?;
                let cls = vm.resolve_class("com/example/Main") as u64;
                let ret = emu.call_function(addr, &[vm.jni_env_ptr(), cls])?;
                if let Some(obj) = vm.get_object(ret as i32 as i64) {
                    if let Some(s) = obj.as_str() {
                        println!("{sym} => \"{s}\"");
                        return Ok(());
                    }
                }
                println!("{sym} => {ret:#x}");
            }
        }
        Command::Gdb {
            target,
            arch,
            sdk,
            listen,
        } => {
            let a: Arch = arch.into();
            let mut emu = build_emu(a, sdk, 23)?;
            let _module = emu.load_library(&target, true)?;
            let mut gdb = GdbServer::new(a);
            println!("GDB RSP listening on {listen}");
            gdb.serve_one(&listen, emu.core_mut().backend_mut())?;
        }
    }
    Ok(())
}
