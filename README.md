# btcparse
A simple Bitcoin blockchain parser.

## Usage:
```
Usage: btcparse [-j|-J] <file|directory> [output-directory]
       btcparse < <file>
       <input-stream> | btcparse

Notes: - Outputs to current working directory (CWD) by default.
       - If output-directory is given then it must exist.
       - Output is in text format by default.
       - Flag -j for output as minified JSON.
       - Flag -J for output as human readable JSON.

Examples:
      btcparse blocks/blk00000.dat
          Outputs blk00000.out file in CWD.

      btcparse -J blocks/blk00000.dat
          Outputs blk00000.json file (human-readable) in CWD.

      btcparse -j blocks/blk00000.dat
          Outputs blk00000.json file (minified) in CWD.

      btcparse blocks 
          Parses all .dat files in "blocks" directory.
          Outputs corresponding .out files in CWD.  

      btcparse blocks/blk00000.dat outdir
          Same as above except outputs are stored in outdir.
 
      cat blocks/blk00000.dat | btcparse
          Parses input stream and outputs to stdout.

      btcparse < blocks/blk00000.dat
          Pareses file and outputs to stdout.
```
## General Info:
### Zig Version: 0.11.0
This is my first zig project, mainly aimed at learning zig and making something useful at the same time. It's developed and tested on a Linux x86-64 platform. It assumes a little-endian platform and will probably give incorrect results on a big-endian platform. The tests were also only done on the early block files, but should in theory work on later ones as well.
