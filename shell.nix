{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    gcc
    glib
    # glibc
    rake
    pkg-config
    libseccomp
    cmake
    ninja
  ];
}
