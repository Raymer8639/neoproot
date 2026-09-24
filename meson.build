project('neoproot', 'c', version: '5.10.8', meson_version: '>=0.61.0', default_options: ['warning_level=2'])

# Phase 1 delegates to the battle-tested GNUmakefile. It preserves the
# freestanding ARM64 loader, probes, per-directory flags and source graph.
sh = find_program('sh')
root = meson.project_source_root()
src_dir = join_paths(root, 'src')
build_dir = meson.current_build_dir()
march = get_option('march')
custom_target('neoproot',
  output: 'neoproot',
  depend_files: files('src/GNUmakefile'),
  command: [sh, '-c', 'cd "' + src_dir + '" && make neoproot V=1 CC=clang CXX=clang++ MARCH="' + march + '" && cp -f neoproot "' + join_paths(build_dir, 'neoproot') + '"'],
  build_by_default: true,
  console: true,
  install: true,
  install_dir: get_option('bindir'))
