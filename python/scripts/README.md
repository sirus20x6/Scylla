# Scylla Python Automation Scripts

Automated unpacking and analysis workflows using Scylla's Python bindings.

## Scripts

### auto_unpack.py
Automated unpacking with debugger integration and OEP detection.

```bash
# Auto-detect and unpack
python auto_unpack.py packed.exe

# Use specific debugger
python auto_unpack.py packed.exe --debugger x64dbg

# Batch unpack
python auto_unpack.py *.exe --batch

# Static unpacking only (no debugger)
python auto_unpack.py packed.exe --debugger none
```

**Features:**
- Automatic packer detection (UPX, ASPack, Themida, VMProtect, etc.)
- OEP detection using multiple heuristics
- Debugger integration (x64dbg, GDB)
- Batch processing support
- Static unpacking for simple packers

### batch_analyze.py
Batch analysis of multiple binaries with comprehensive reporting.

```bash
# Analyze directory
python batch_analyze.py /path/to/binaries

# Recursive with JSON report
python batch_analyze.py /path --recursive --format json -o report.json

# Filter by packer
python batch_analyze.py /path --filter-packer UPX

# CSV output for spreadsheet analysis
python batch_analyze.py /path --format csv -o analysis.csv
```

**Features:**
- Batch binary analysis
- Multiple report formats (text, JSON, CSV)
- Packer detection and statistics
- Architecture distribution
- Security feature analysis
- Recursive directory scanning

### gdb_unpack.py
GDB-assisted unpacking for Linux/macOS binaries.

```bash
# Auto-detect OEP and dump
python gdb_unpack.py packed_binary

# Connect to remote gdbserver
python gdb_unpack.py packed_binary --remote localhost:1234

# Specify known OEP
python gdb_unpack.py packed_binary --oep 0x401000

# Generate GDB script for manual unpacking
python gdb_unpack.py packed_binary --generate-script -o unpack.gdb
gdb -x unpack.gdb
```

**Features:**
- GDB/MI integration
- Automated OEP detection
- Memory dumping
- Import fixing
- Remote debugging support
- GDB script generation

## Prerequisites

### Build Scylla Python Bindings

```bash
cd /home/user/Scylla
mkdir build && cd build
cmake .. -DBUILD_PYTHON_BINDINGS=ON
make
```

### Install Dependencies

```bash
# For x64dbg integration (Windows)
# - Install x64dbg from https://x64dbg.com/
# - Run x64dbg bridge server (if using remote mode)

# For GDB integration (Linux/macOS)
sudo apt-get install gdb  # Linux
brew install gdb          # macOS

# For UPX static unpacking
sudo apt-get install upx  # Linux
brew install upx          # macOS
```

## Workflow Examples

### Example 1: Simple UPX Unpacking

```bash
# UPX binaries can be unpacked statically
python auto_unpack.py upx_packed.exe --debugger none
```

### Example 2: Complex Packer with x64dbg

```bash
# 1. Start x64dbg
# 2. Load x64dbg bridge server (optional)
# 3. Run unpacking script
python auto_unpack.py themida_packed.exe --debugger x64dbg
```

### Example 3: Linux Binary with GDB

```bash
# Unpack Linux binary using GDB
python gdb_unpack.py packed_elf --verbose

# Or generate script for manual analysis
python gdb_unpack.py packed_elf --generate-script -o analyze.gdb
gdb -x analyze.gdb
```

### Example 4: Batch Analysis

```bash
# Analyze entire malware sample collection
python batch_analyze.py /samples --recursive --format json -o report.json

# Filter for packed samples
python batch_analyze.py /samples | grep -i "packed: true"

# Get statistics
python batch_analyze.py /samples | grep -A 10 "STATISTICS"
```

### Example 5: Automated Pipeline

```bash
#!/bin/bash
# Automated unpacking pipeline

SAMPLE_DIR="/path/to/samples"
OUTPUT_DIR="/path/to/unpacked"

# 1. Analyze and identify packed samples
python batch_analyze.py "$SAMPLE_DIR" --format json -o analysis.json

# 2. Extract packed samples list
# (parse JSON and extract files where is_packed=true)

# 3. Batch unpack
python auto_unpack.py "$SAMPLE_DIR"/*.exe --batch

# 4. Re-analyze unpacked samples
python batch_analyze.py "$OUTPUT_DIR" --format json -o unpacked_analysis.json
```

## Integration with Scylla CLI

The Python scripts complement Scylla's CLI tools:

```bash
# 1. Use Python for automation
python auto_unpack.py sample.exe

# 2. Use CLI for detailed analysis
scylla-cli analyze sample_unpacked.exe --format xml -o analysis.xml

# 3. Use CLI for IAT fixing
scylla-cli fix-iat sample_unpacked.exe --oep 0x401000
```

## Troubleshooting

### "scylla module not found"
Build Python bindings:
```bash
cd /home/user/Scylla/build
cmake .. -DBUILD_PYTHON_BINDINGS=ON && make
```

### "x64dbg connection failed"
- Ensure x64dbg is running
- Check if bridge server is enabled
- Verify connection string (default: 127.0.0.1:1337)

### "GDB not found"
Install GDB:
```bash
sudo apt-get install gdb  # Linux
brew install gdb          # macOS
```

### "Permission denied" on scripts
Make scripts executable:
```bash
chmod +x *.py
```

## Advanced Usage

### Custom Debugger Scripts

Create custom automation by extending the base classes:

```python
from scripts.auto_unpack import AutoUnpacker

class CustomUnpacker(AutoUnpacker):
    def detect_custom_packer(self, file_path):
        # Custom packer detection logic
        pass

    def unpack_custom(self, file_path):
        # Custom unpacking logic
        pass
```

### Integration with Other Tools

```bash
# Combine with radare2
python gdb_unpack.py sample.exe
r2 sample_unpacked.exe

# Combine with IDA Pro
python auto_unpack.py sample.exe
ida64 sample_unpacked.exe

# Combine with YARA scanning
python batch_analyze.py /samples --format json | \
    jq '.results[] | select(.is_packed == true) | .file' | \
    xargs -I {} yara rules.yar {}
```

## Contributing

To add new automation scripts:

1. Follow the existing script structure
2. Add comprehensive help text
3. Update this README
4. Test on multiple platforms (Windows/Linux/macOS)
5. Submit PR with examples

## License

Same as Scylla main project.
