# zig-fat

A little FAT reader (and potentially writer) library I chew away at when I'm
bored.

Not meant to be a serious project.

Feel free to contribute if you want.

## Testing

The tests in `src/fat.zig` expect both a `testFat16.iso` and a `testFat32.iso`
in the `cwd`. Provide them yourself by using `dd`, `mkfs.fat -F16`, and `mkfs.fat -F32`

