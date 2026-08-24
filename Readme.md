# OOP Analyst

**Version:** 1.0.0  
**Developer:** ExEintel  
**Platforms:** Windows, Linux  

## About

OOP Analyst is a lightweight command-line tool for analyzing executable files (.exe, ELF binaries) to detect Object-Oriented Programming (OOP) patterns in compiled code. The tool examines binary files for indicators of C++ OOP features such as RTTI, virtual tables, inheritance patterns, and more.

**Note:** This program uses heuristic-based pattern matching and may not be 100% accurate. It is intended as an educational and exploratory tool, not a definitive analysis method.

## Features

- Detects RTTI (Run-Time Type Information)
- Identifies virtual tables (vtables) for polymorphism
- Recognizes C++ runtime imports
- Detects exception handling mechanisms
- Identifies template usage
- Analyzes inheritance and polymorphism patterns
- Supports both Windows PE and Linux ELF formats

## Project Structure

```
oop analyst/
├── oop_analyst.exe        # Compiled program (Windows)
├── Readme.md             # This documentation
└── sourse/
    └── main.c            # Source code
```

## Compilation

### Windows (MinGW)

```bash
gcc sourse/main.c -o oop_analyst.exe
```

### Linux

```bash
gcc sourse/main.c -o oop_analyst
```

## Usage

### Show Help

```bash
oop_analyst --help
```

### Show Version

```bash
oop_analyst --version
```

### Analyze File for OOP Patterns

```bash
oop_analyst -t path/to/file.exe
```

### Show File Information

```bash
oop_analyst -i path/to/file.exe
```

## Command Reference

| Command | Description |
|---------|-------------|
| `-t <file>` | Analyze file for OOP patterns |
| `-i <file>` | Show file information |
| `--version` | Show version information |
| `--help` | Show help message |

## Detection Methods

The tool uses the following techniques to detect OOP patterns:

1. **RTTI Detection**: Looks for Run-Time Type Information symbols (_ZTI, _ZTS)
2. **Virtual Table Detection**: Identifies vtable symbols (_ZTV)
3. **C++ Import Analysis**: Checks for C++ mangled names and runtime functions
4. **Pattern Matching**: Searches for characteristic byte sequences

## Output Example

```
OOP Analysis for: program.exe
==========================================

  RTTI (Run-Time Type Information)       [DETECTED]
  Virtual Tables (vtables)               [DETECTED]
  C++ Imports                            [DETECTED]
  Exception Handling                     [NOT DETECTED]
  Templates                              [NOT DETECTED]
  Inheritance                            [DETECTED]
  Polymorphism                           [DETECTED]
  Encapsulation                          [NOT DETECTED]
  Abstraction                            [NOT DETECTED]
  Namespaces                             [NOT DETECTED]
  Class Definitions                      [NOT DETECTED]
  Virtual Destructors                    [NOT DETECTED]

==========================================
Summary:
  OOP Features Detected: 5/12
  Verdict: MODERATE OOP Usage

Note: This analysis is heuristic-based and may not be 100% accurate.
      The tool uses pattern matching to detect OOP indicators.
```

## Limitations

- Detection is based on pattern matching, not semantic analysis
- May produce false positives or false negatives
- Only analyzes compiled binaries, not source code
- Limited to common OOP patterns in C++ compiled code
- Does not work with obfuscated or packed executables

## License

This software is provided as-is for educational purposes.

## Developer

Created by ExEintel (2024)
