{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    mount
    gnugrep

    gcc
    glib
    rake
    pkg-config
    # libseccomp
    libseccomp.dev
    cmake
    ninja
  ];
  shellHook = ''
    export PATH=$PATH:`pwd`/cmake-build-debug
  '';
}
