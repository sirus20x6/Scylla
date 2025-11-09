# Scylla Dear ImGui GUI

Modern cross-platform graphical interface for Scylla using Dear ImGui.

## Features

- **Cross-Platform** - Works on Windows, Linux, and macOS
- **Modern UI** - Clean, responsive Dear ImGui interface
- **Real-Time Analysis** - Live IAT scanning with progress tracking
- **Security Visualization** - Interactive security score gauges
- **Symbol Browser** - Search and browse loaded symbols
- **Theme Support** - Dark, Light, and Classic themes
- **Docking** - Flexible window layout with docking support
- **Performance** - Lightweight and fast

## Screenshots

### Process Selection
![Process Selector](screenshots/process-selector.png)

### IAT Analysis
![IAT Analysis](screenshots/iat-analysis.png)

### Security Analysis
![Security Analysis](screenshots/security-analysis.png)

## Building

### Prerequisites

- CMake 3.15+
- C++17 compiler
- OpenGL 3.3+

The build system will automatically download:
- Dear ImGui 1.90.0
- GLFW 3.3.8

### Build Instructions

#### Windows (Visual Studio)
```batch
mkdir build
cd build
cmake -DBUILD_GUI=ON ..
cmake --build . --config Release
```

#### Linux
```bash
# Install OpenGL development libraries
sudo apt-get install libgl1-mesa-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev

mkdir build && cd build
cmake -DBUILD_GUI=ON ..
make -j$(nproc)
```

#### macOS
```bash
mkdir build && cd build
cmake -DBUILD_GUI=ON ..
make -j$(sysctl -n hw.ncpu)
```

## Usage

### Launch
```bash
# Windows
ScyllaGUI.exe

# Linux/macOS
./ScyllaGUI
```

### Workflow

1. **Select Process**
   - File → Attach to Process (Ctrl+O)
   - Search/filter processes
   - Double-click or select and click "Attach"

2. **IAT Analysis**
   - Navigate to "IAT Analysis" tab
   - Click "Start IAT Scan" (F5)
   - Monitor progress and results
   - Export results if needed

3. **Security Analysis**
   - Navigate to "Security Analysis" tab
   - Click "Analyze Security" (F6)
   - Review security score and mitigations
   - Check weaknesses and recommendations

4. **Symbol Browser**
   - Navigate to "Symbol Browser" tab
   - Click "Load Symbols" (F7)
   - Search symbols by name
   - View addresses, types, and modules

5. **Export Results**
   - File → Export Results (Ctrl+E)
   - Choose format (JSON, XML, CSV)

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Attach to Process |
| `Ctrl+D` | Detach from Process |
| `Ctrl+E` | Export Results |
| `F5` | Start IAT Scan |
| `F6` | Security Analysis |
| `F7` | Load Symbols |
| `Esc` | Stop Analysis |
| `Alt+F4` | Exit |

## Themes

Scylla GUI supports three built-in themes:

### Dark Theme (Default)
Modern dark theme optimized for extended use and low-light environments.

### Light Theme
Clean light theme for bright environments.

### Classic Theme
Traditional Dear ImGui color scheme.

Change themes via: **View → Theme**

## UI Components

### Main Menu Bar
- **File** - Process management, export, exit
- **Analysis** - IAT scan, security analysis, symbols
- **View** - Theme selection, window visibility
- **Help** - Documentation, about

### Process Selector
- Real-time process list
- Search/filter functionality
- Auto-refresh option
- Process details (PID, arch, .NET detection)

### IAT Analysis
- Progress tracking
- Results categorization (Valid, Suspect, Invalid)
- Detailed API table
- Export capabilities

### Security Analysis
- Visual security score gauge
- Mitigation checkboxes (DEP, ASLR, CFG, Signed)
- Risk level indicator
- Weakness and recommendation lists

### Symbol Browser
- Symbol search
- Sortable table
- Type and module filtering
- Address display

### Log Console
- Real-time operation log
- Auto-scroll
- Clear function

## Configuration

Settings are accessible via: **View → Settings**

### General Settings
- Auto-refresh process list
- Refresh interval
- Theme selection

### Analysis Settings
- IAT scan depth
- Symbol resolution options
- Security analysis preferences

### Advanced Settings
- Performance tuning
- Cache configuration
- Export formats

## Architecture

### Components

```
ScyllaGUI
├── Main Window (Docking Space)
├── Menu Bar
├── Process Selector Tab
├── IAT Analysis Tab
├── Security Analysis Tab
├── Symbol Browser Tab
├── Settings Dialog
├── About Dialog
└── Log Console
```

### Technology Stack

- **UI Framework**: Dear ImGui 1.90.0
- **Windowing**: GLFW 3.3.8
- **Graphics**: OpenGL 3.3
- **Language**: C++17

### Integration

The GUI integrates with Scylla's core libraries:

- `SecurityAnalyzer` - Security mitigation detection
- `SymbolResolver` - PDB and symbol resolution
- `PackerDetector` - Packer detection
- `IATScanner` - IAT reconstruction
- `DotNetAnalyzer` - .NET assembly analysis
- `ELFAnalyzer` - Linux binary analysis

## Performance

- **Memory Usage**: ~50MB base + analysis overhead
- **Startup Time**: <1 second
- **Frame Rate**: 60 FPS (VSync enabled)
- **Process List**: Minimal impact on system

## Troubleshooting

### GUI doesn't start
- Ensure OpenGL 3.3+ drivers are installed
- Check graphics drivers are up to date
- Try running from terminal to see error messages

### Process list empty
- Run as Administrator/root on some systems
- Check process enumeration permissions

### Symbols not loading
- Ensure PDB files are in the same directory as executable
- Configure symbol search paths
- Download symbols from Microsoft symbol server

### High DPI displays
- GLFW automatically handles DPI scaling
- If text appears too small/large, check system DPI settings

## Dependencies

### Bundled (Auto-Downloaded)
- Dear ImGui 1.90.0
- GLFW 3.3.8

### System Requirements
- OpenGL 3.3+
- C++ Runtime

### Platform Libraries

**Windows:**
- No additional libraries required

**Linux:**
- libgl1-mesa-dev
- libxrandr-dev
- libxinerama-dev
- libxcursor-dev
- libxi-dev

**macOS:**
- System frameworks (automatically linked)

## Development

### Custom Themes

Add custom themes by extending `Themes` namespace:

```cpp
namespace scylla::gui::Themes {
    void ApplyCustomTheme() {
        ImGuiStyle& style = ImGui::GetStyle();
        ImVec4* colors = style.Colors;

        // Customize colors
        colors[ImGuiCol_WindowBg] = ImVec4(0.1f, 0.1f, 0.1f, 1.0f);
        // ...
    }
}
```

### Adding New Tabs

1. Add rendering function in `ScyllaGUI.h`:
```cpp
void RenderCustomTab();
```

2. Implement in `ScyllaGUI.cpp`:
```cpp
void ScyllaGUI::RenderCustomTab() {
    ImGui::Begin("Custom Tab");
    // Tab content
    ImGui::End();
}
```

3. Call in main rendering loop

### Custom Widgets

Use `UIUtils` namespace for reusable widgets:

```cpp
namespace scylla::gui::UIUtils {
    void CustomWidget(const char* label) {
        // Widget implementation
    }
}
```

## Future Enhancements

- [ ] Hex viewer for memory/file data
- [ ] Disassembly view
- [ ] Graph visualization for call flow
- [ ] Plugin system for extensions
- [ ] Configuration import/export
- [ ] Diff view for comparing analyses
- [ ] Network analysis integration
- [ ] Scripting support (Python/Lua)

## License

This GUI component is part of Scylla and shares the same license as the main project.

Dear ImGui is licensed under the MIT License.
GLFW is licensed under the zlib/libpng license.

## Credits

- **Dear ImGui** - Omar Cornut (ocornut)
- **GLFW** - Marcus Geelnard, Camilla Löwy
- **Scylla** - Original authors + modernization contributors

## Support

- **Documentation**: See main Scylla docs
- **Issues**: Report at GitHub Issues
- **Discussion**: GitHub Discussions

## Changelog

### Version 2.0.0 (Current)
- Initial Dear ImGui implementation
- Cross-platform support (Windows, Linux, macOS)
- Process selection with search
- IAT analysis with progress tracking
- Security analysis visualization
- Symbol browser
- Theme support (Dark, Light, Classic)
- Docking layout support
- Real-time log console

---

**Note**: This is a complete rewrite of the original Scylla GUI using modern Dear ImGui for better cross-platform support and maintainability.
