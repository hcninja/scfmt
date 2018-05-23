# scfmt

_Shellcode formatter_ is a tool for extracting the shellcode from an `objdump` output (tested on macho64 dump) and prints the output directly in a nice go copypasteable string.

## Usage

Simply pipe your `objdump` to `scfmt`:

```bash
> objdump -d test.macho64 | scfmt
< var shellcode string = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\xb8\x04\x00\x00\x02\xbf\x01\x00\x00\x00\x48\xbe\x00\x20\x00\x00\x00\x00\x00\x00\xba\x12\x00\x00\x00\x0f\x05\xb8\x01\x00\x00\x02\xbf\x00\x00\x00\x00\x0fx05"
```