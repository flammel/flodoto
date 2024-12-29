[private]
default:
    just --list --unsorted

dev:
    PORT=8080 watchexec -r cargo run

format:
    cargo fmt

check:
    cargo clippy

fix:
    cargo clippy --fix

build:
    cargo build --release
