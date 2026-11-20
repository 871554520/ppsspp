#!/usr/bin/env python3
"""Structural check for an unsigned .ipa: is it actually installable-shaped?

Checks, in order:
  1. zip readable, has a Payload/ directory
  2. exactly one Payload/<something>.app
  3. that .app has Info.plist (parseable plist)
  4. CFBundleExecutable points at a real file
  5. that file starts with a Mach-O magic (64-bit LE / 32-bit LE / fat)
  6. the Mach-O actually contains an arm64 slice  (device-installable)
Exits non-zero with a plain-language reason, so CI fails before uploading junk.
"""
import sys, zipfile, plistlib, struct

MACHO = {0xFEEDFACF: "macho64", 0xFEEDFACE: "macho32", 0xCAFEBABE: "fat"}
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM = 12


def die(msg):
    print(f"FAIL  {msg}")
    sys.exit(1)


def slices(raw):
    """Yield (cputype, cpusubtype, name) for each arch in a Mach-O header."""
    magic = struct.unpack(">I", raw[:4])[0]
    if magic == 0xCAFEBABE:  # fat, big-endian header
        n = struct.unpack(">I", raw[4:8])[0]
        for i in range(n):
            off = 8 + i * 20
            cputype, cpusub, offset, size, align = struct.unpack(">5I", raw[off:off + 20])
            yield cputype, cpusub, offset, size
    else:
        le = struct.unpack("<I", raw[:4])[0]
        if le not in (0xFEEDFACF, 0xFEEDFACE):
            die(f"not a Mach-O first 4 bytes: 0x{raw[:4].hex()}")
        cputype, cpusub = struct.unpack("<2I", raw[4:12])
        yield cputype, cpusub, 0, len(raw)


def main(path):
    try:
        z = zipfile.ZipFile(path)
    except Exception as e:
        die(f"{path} is not a readable zip ({e})")

    names = z.namelist()
    if not any(n.startswith("Payload/") for n in names):
        die("no Payload/ directory (this is not an .ipa layout; an App Store .ipa has Payload/*.app)")

    apps = sorted({n.split("/")[1] for n in names
                   if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app")})
    if not apps:
        die("Payload/ has no *.app bundle")
    if len(apps) > 1:
        print(f"WARN  more than one .app: {apps} (using {apps[0]})")
    app = apps[0]

    info_path = f"Payload/{app}/Info.plist"
    if info_path not in names:
        die(f"missing {info_path} (this is the #1 sign of a fake/broken ipa)")
    try:
        info = plistlib.loads(z.read(info_path))
    except Exception as e:
        die(f"Info.plist is not a parseable plist ({e})")

    bundle_id = info.get("CFBundleIdentifier")
    if not bundle_id:
        die("Info.plist has no CFBundleIdentifier")
    exe = info.get("CFBundleExecutable") or app[:-4]
    if not exe:
        die("Info.plist has no CFBundleExecutable")

    bin_path = f"Payload/{app}/{exe}"
    if bin_path not in names:
        die(f"missing executable {bin_path} (shell-only app: nothing to install)")

    raw = z.read(bin_path)
    if len(raw) < 32:
        die(f"{bin_path} is only {len(raw)} bytes - truncated")
    found = list(slices(raw))
    if not found:
        die(f"{bin_path} has no Mach-O slices")
    has_arm64 = any(c == CPU_TYPE_ARM64 for c, _, _, _ in found)
    if not has_arm64:
        die(f"{bin_path} has no arm64 slice (cannot run on a real iPhone/iPad)")

    exe_size = len(raw)
    if exe_size < 64 * 1024:
        print(f"WARN  main binary is only {exe_size / 1024:.0f} KB - real games are bigger, but tool apps can be small")

    total = sum(i.file_size for i in z.infolist())
    print("OK    bundle      :", app)
    print("OK    bundle id   :", bundle_id)
    print("OK    version     :", info.get("CFBundleShortVersionString"),
          f"({info.get('CFBundleVersion')})")
    print("OK    min iOS     :", info.get("MinimumOSVersion", "unset"))
    print("OK    device arch :", ", ".join(f"0x{c:08x}" for c, _, _, _ in found))
    print("OK    executable  :", f"{exe}  {exe_size / 1048576:.1f} MB")
    print("OK    entries     :", f"{len(names)} files, {total / 1048576:.1f} MB uncompressed")
    print(f"PASS  {path}")



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    main(sys.argv[1])
