# Scylla x64dbg Plugin

Integrates Scylla's IAT reconstruction and unpacking capabilities directly into the x64dbg debugger.

## Features

- **Memory Dumping**: One-click process memory dump
- **IAT Reconstruction**: Automatic Import Address Table fixing
- **OEP Detection**: Find Original Entry Point using heuristics
- **Packer Analysis**: Detect and analyze packed executables
- **Seamless Integration**: Works within x64dbg's UI

## Building

### Prerequisites

1. **Visual Studio** (2019 or later)
2. **x64dbg** installed
3. **x64dbg Plugin SDK** (optional for full integration)

### Build Steps

```bash
# From Scylla root directory
mkdir build && cd build

# For 32-bit plugin
cmake .. -A Win32 -DBUILD_X64DBG_PLUGIN=ON
cmake --build . --config Release

# For 64-bit plugin
cmake .. -A x64 -DBUILD_X64DBG_PLUGIN=ON
cmake --build . --config Release
```

### Build Outputs

- **32-bit**: `ScyllaX64Dbg.dp32`
- **64-bit**: `ScyllaX64Dbg.dp64`

## Installation

### Automatic Installation

```bash
cmake --install . --prefix "C:/Program Files/x64dbg"
```

### Manual Installation

1. Locate x64dbg plugins directory:
   - **32-bit**: `x64dbg/x32/plugins/`
   - **64-bit**: `x64dbg/x64/plugins/`

2. Copy plugin file:
   - For x32dbg: Copy `ScyllaX64Dbg.dp32` to `x64dbg/x32/plugins/`
   - For x64dbg: Copy `ScyllaX64Dbg.dp64` to `x64dbg/x64/plugins/`

3. Restart x64dbg

## Usage

### Menu Location

After installation, Scylla menu appears in x64dbg:

```
Plugins → Scylla →
  ├─ Dump Process
  ├─ Fix IAT
  ├─ Find OEP
  └─ About
```

### Workflow Example

#### 1. Load Packed Executable

```
File → Open → select packed.exe
```

#### 2. Run to OEP

**Option A: Automatic OEP Detection**
```
1. Plugins → Scylla → Find OEP
2. Review breakpoint suggestions in log
3. F9 (Run) to reach OEP
```

**Option B: Manual OEP Finding**
```
1. Set breakpoint on suspicious code
2. F9 (Run) until unpacking code executes
3. Look for POPAD instruction
4. Step over (F8) to reach OEP
```

#### 3. Dump Process

```
1. Plugins → Scylla → Dump Process
2. Choose output filename
3. Save dump (unpacked executable)
```

#### 4. Fix IAT

```
1. Plugins → Scylla → Fix IAT
2. Review IAT reconstruction in log
3. Dumped file now has fixed imports
```

#### 5. Verify Unpacked Binary

```
1. Open dumped file in PE editor
2. Verify imports are correct
3. Test execution
```

## Advanced Features

### OEP Detection Heuristics

The plugin uses multiple techniques to find the OEP:

1. **PUSHAD/POPAD Pattern**
   - Searches for `POPAD; JMP` sequences
   - Common in UPX, ASPack, and similar packers

2. **Tail Jump Detection**
   - Identifies large forward jumps
   - Typical unpacker behavior

3. **API Monitoring**
   - Breakpoint on VirtualProtect
   - Monitors memory permission changes

### Integration with Scylla Bridge

The plugin can communicate with Scylla's debugger bridge:

```cpp
// Enable bridge mode
Plugins → Scylla → Settings → Enable Bridge Server

// Python/CLI can then connect
python auto_unpack.py sample.exe --debugger x64dbg --remote localhost:1337
```

### Custom Scripts

Create x64dbg scripts that leverage Scylla:

```javascript
// unpack.txt - x64dbg script
bp VirtualProtect
run
log "VirtualProtect called at: {cip}"

// Call Scylla plugin
ScyllaFindOEP()
ScyllaDumpProcess("dump.exe")
ScyllaFixIAT()
```

## Keyboard Shortcuts

You can assign keyboard shortcuts in x64dbg:

```
Options → Shortcuts → Plugins → Scylla
  - Dump Process: Ctrl+Alt+D
  - Fix IAT: Ctrl+Alt+I
  - Find OEP: Ctrl+Alt+O
```

## Troubleshooting

### Plugin Not Loading

**Symptom**: Scylla menu doesn't appear

**Solutions**:
1. Check x64dbg log for errors: `View → Log`
2. Verify plugin file is in correct directory
3. Ensure 32/64-bit match (dp32 for x32dbg, dp64 for x64dbg)
4. Check plugin isn't blocked: Right-click → Properties → Unblock

### Memory Dump Failed

**Symptom**: "Failed to read process memory"

**Solutions**:
1. Ensure debuggee is loaded and running
2. Check memory permissions
3. Try dumping at different execution point
4. Verify sufficient disk space

### IAT Reconstruction Errors

**Symptom**: "IAT reconstruction failed"

**Solutions**:
1. Ensure process is at OEP before fixing IAT
2. Check if imports are encrypted/virtualized
3. For VMProtect/Themida: Manual IAT reconstruction needed
4. Review log for specific error messages

## Development

### Adding New Features

1. **Add Menu Entry**:
```cpp
// In plugsetup()
_plugin_menuaddentry(setupStruct->hMenu, MENU_NEW_FEATURE, "&New Feature");
```

2. **Implement Handler**:
```cpp
void MenuEntryNewFeature()
{
    _plugin_logputs("[Scylla] Executing new feature...");
    // Implementation here
}
```

3. **Register Callback**:
```cpp
// In CBMENUENTRY()
case MENU_NEW_FEATURE:
    MenuEntryNewFeature();
    break;
```

### Integrating with ScyllaLib

For full functionality, link against ScyllaLib:

```cpp
#ifdef SCYLLA_LIB_AVAILABLE
#include <OEPDetector.h>
#include <DebuggerBridge.h>

void MenuEntryOEPAdvanced()
{
    scylla::OEPDetector detector;
    // Use full OEP detection capabilities
}
#endif
```

### Building with x64dbg SDK

1. Download x64dbg plugin SDK:
```bash
git clone https://github.com/x64dbg/x64dbg.git
```

2. Update CMakeLists.txt:
```cmake
include_directories("path/to/x64dbg/src/plugin_bridge")
```

3. Replace stub headers with real SDK headers

## Comparison with Standalone Scylla

| Feature | x64dbg Plugin | Standalone Scylla |
|---------|--------------|-------------------|
| Memory Dumping | ✓ | ✓ |
| IAT Reconstruction | ✓ | ✓ |
| OEP Detection | ✓ (Integrated) | ✓ (Manual) |
| GUI | x64dbg UI | Separate GUI |
| Debugger Control | ✓ | ✗ |
| Batch Processing | ✗ | ✓ |
| Python Scripting | ✗ | ✓ |
| Cross-Platform | Windows only | Windows/Linux/macOS |

## Examples

### Example 1: UPX Unpacking

```
1. Load UPX packed executable
2. Plugins → Scylla → Find OEP
   Output: "OEP pattern found at: 0x401520"
3. F9 to run to breakpoint
4. Plugins → Scylla → Dump Process
5. Plugins → Scylla → Fix IAT
6. Done! Unpacked binary saved.
```

### Example 2: Themida Unpacking

```
1. Load Themida protected executable
2. Manual analysis to find unpacking code
3. Set breakpoints on suspicious transitions
4. Step through until original code visible
5. Plugins → Scylla → Dump Process
6. Plugins → Scylla → Fix IAT
7. Manual import fixing may be needed
```

### Example 3: Automated Workflow

```python
# Combine with Python automation
import subprocess

# 1. Start x64dbg with Scylla plugin
subprocess.run(["x64dbg", "packed.exe"])

# 2. Connect to bridge
from scylla.debugger import X64DbgBridge
bridge = X64DbgBridge()
bridge.connect("localhost:1337")

# 3. Automate unpacking
bridge.execute_command("ScyllaFindOEP")
bridge.continue_execution()
bridge.wait_for_event()
bridge.execute_command("ScyllaDumpProcess")
bridge.execute_command("ScyllaFixIAT")
```

## References

- **x64dbg**: https://x64dbg.com/
- **Plugin SDK**: https://github.com/x64dbg/x64dbg/tree/development/src/plugin_bridge
- **Scylla**: https://github.com/NtQuery/Scylla
- **Plugin Development**: https://x64dbg.readthedocs.io/en/latest/developers/plugins/

## License

Same as Scylla main project.

## Credits

- x64dbg by mrexodia and contributors
- Original Scylla by NtQuery
- Plugin integration by Scylla contributors
