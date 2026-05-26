use zkm_build::build_program;
fn main() {
    println!("cargo:rerun-if-env-changed=FIXED_WATCHTOWER_XONLY_PUBLIC_KEYS");
    build_program("../guest");
}
