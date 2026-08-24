#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <elf.h>
#include <sys/stat.h>
#endif

#define VERSION "1.0.0"
#define DEVELOPER "ExEintel"
#define PROGRAM_NAME "OOP Analyst"

typedef struct {
    int has_rtti;
    int has_vtables;
    int has_cpp_imports;
    int has_exceptions;
    int has_templates;
    int has_inheritance;
    int has_polymorphism;
    int has_encapsulation;
    int has_abstraction;
    int has_namespace;
    int has_classes;
    int has_virtual_destructor;
} OOPIndicators;

typedef struct {
    const char *name;
    const char *description;
    int detected;
} OOFeature;

void print_banner() {
    printf("===============================================\n");
    printf("  OOP Analyst v%s\n", VERSION);
    printf("  Developer: %s\n", DEVELOPER);
    printf("===============================================\n\n");
}

void print_help() {
    print_banner();
    printf("Usage: oop_analyst [options] <file>\n\n");
    printf("Options:\n");
    printf("  -t <file>     Analyze file for OOP patterns\n");
    printf("  -i <file>     Show file information\n");
    printf("  --version     Show version information\n");
    printf("  --help        Show this help message\n\n");
    printf("Examples:\n");
    printf("  oop_analyst -t program.exe\n");
    printf("  oop_analyst -i program.exe\n");
    printf("  oop_analyst --version\n\n");
}

void print_version() {
    printf("OOP Analyst v%s by %s\n", VERSION, DEVELOPER);
}

#ifdef _WIN32
int analyze_pe_file(const char *filename, OOPIndicators *indicators) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", filename);
        return -1;
    }

    IMAGE_DOS_HEADER dos_header;
    if (fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file) != 1) {
        printf("Error: Cannot read DOS header\n");
        fclose(file);
        return -1;
    }

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Not a valid PE file\n");
        fclose(file);
        return -1;
    }

    fseek(file, dos_header.e_lfanew, SEEK_SET);

    IMAGE_NT_HEADERS nt_headers;
    if (fread(&nt_headers, sizeof(IMAGE_NT_HEADERS), 1, file) != 1) {
        printf("Error: Cannot read NT headers\n");
        fclose(file);
        return -1;
    }

    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        printf("Error: Invalid NT signature\n");
        fclose(file);
        return -1;
    }

    WORD num_sections = nt_headers.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)malloc(num_sections * sizeof(IMAGE_SECTION_HEADER));
    
    for (int i = 0; i < num_sections; i++) {
        fread(&sections[i], sizeof(IMAGE_SECTION_HEADER), 1, file);
    }

    for (int i = 0; i < num_sections; i++) {
        if (strcmp((char *)sections[i].Name, ".rdata") == 0) {
            indicators->has_rtti = 1;
        }
        if (strcmp((char *)sections[i].Name, ".data") == 0 ||
            strcmp((char *)sections[i].Name, ".rdata") == 0) {
            indicators->has_vtables = 1;
        }
    }

    fseek(file, 0, SEEK_SET);
    fseek(file, nt_headers.OptionalHeader.DataDirectory[12].VirtualAddress, SEEK_SET);

    free(sections);
    fclose(file);
    return 0;
}

int show_file_info(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", filename);
        return -1;
    }

    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file);

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Error: Not a valid PE file\n");
        fclose(file);
        return -1;
    }

    fseek(file, dos_header.e_lfanew, SEEK_SET);

    IMAGE_NT_HEADERS nt_headers;
    fread(&nt_headers, sizeof(IMAGE_NT_HEADERS), 1, file);

    printf("File Information:\n");
    printf("  Machine: 0x%04X\n", nt_headers.FileHeader.Machine);
    printf("  Sections: %d\n", nt_headers.FileHeader.NumberOfSections);
    printf("  Characteristics: 0x%04X\n", nt_headers.FileHeader.Characteristics);
    printf("  Subsystem: %d\n", nt_headers.OptionalHeader.Subsystem);
    printf("  DLL Characteristics: 0x%04X\n", nt_headers.OptionalHeader.DllCharacteristics);

    fclose(file);
    return 0;
}

#else
int analyze_elf_file(const char *filename, OOPIndicators *indicators) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", filename);
        return -1;
    }

    Elf64_Ehdr elf_header;
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, file) != 1) {
        printf("Error: Cannot read ELF header\n");
        fclose(file);
        return -1;
    }

    if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Error: Not a valid ELF file\n");
        fclose(file);
        return -1;
    }

    Elf64_Shdr *sections = (Elf64_Shdr *)malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
    fseek(file, elf_header.e_shoff, SEEK_SET);
    fread(sections, sizeof(Elf64_Shdr), elf_header.e_shnum, file);

    char *shstrtab = NULL;
    if (elf_header.e_shstrndx < elf_header.e_shnum) {
        shstrtab = (char *)malloc(sections[elf_header.e_shstrndx].sh_size);
        fseek(file, sections[elf_header.e_shstrndx].sh_offset, SEEK_SET);
        fread(shstrtab, 1, sections[elf_header.e_shstrndx].sh_size, file);
    }

    for (int i = 0; i < elf_header.e_shnum; i++) {
        if (shstrtab) {
            char *name = shstrtab + sections[i].sh_name;
            if (strcmp(name, ".rodata") == 0 || strcmp(name, ".data") == 0) {
                indicators->has_rtti = 1;
            }
        }
    }

    free(shstrtab);
    free(sections);
    fclose(file);
    return 0;
}

int show_file_info(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", filename);
        return -1;
    }

    Elf64_Ehdr elf_header;
    fread(&elf_header, sizeof(Elf64_Ehdr), 1, file);

    if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Error: Not a valid ELF file\n");
        fclose(file);
        return -1;
    }

    printf("File Information:\n");
    printf("  Class: %s\n", elf_header.e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64" : "ELF32");
    printf("  Machine: 0x%04X\n", elf_header.e_machine);
    printf("  Sections: %d\n", elf_header.e_shnum);
    printf("  Entry point: 0x%016llX\n", (unsigned long long)elf_header.e_entry);
    printf("  Flags: 0x%08X\n", elf_header.e_flags);

    fclose(file);
    return 0;
}
#endif

void detect_oop_patterns(const char *filename, OOPIndicators *indicators) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t *buffer = (uint8_t *)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);

    const char *cpp_imports[] = {
        "_ZN", "_ZTV", "_ZTI", "_ZTS", "_ZTh",
        "?0", "?1", "?2", "?3", "?4",
        NULL
    };

    for (long i = 0; i < file_size - 4; i++) {
        for (int j = 0; cpp_imports[j] != NULL; j++) {
            size_t len = strlen(cpp_imports[j]);
            if (memcmp(buffer + i, cpp_imports[j], len) == 0) {
                indicators->has_cpp_imports = 1;
                if (cpp_imports[j][0] == 'Z') {
                    indicators->has_rtti = 1;
                    indicators->has_vtables = 1;
                }
            }
        }
    }

    {
        const char *patterns[] = { "_ZTI", "_ZTV", "_ZTS", NULL };
        for (int p = 0; patterns[p] != NULL; p++) {
            size_t plen = strlen(patterns[p]);
            for (long i = 0; i <= file_size - (long)plen; i++) {
                if (memcmp(buffer + i, patterns[p], plen) == 0) {
                    if (p == 0 || p == 1) {
                        indicators->has_inheritance = 1;
                        indicators->has_polymorphism = 1;
                        indicators->has_vtables = 1;
                    }
                    if (p == 2) {
                        indicators->has_templates = 1;
                    }
                    break;
                }
            }
        }
    }

    free(buffer);
}

void print_analysis_results(const char *filename, OOPIndicators *indicators) {
    printf("OOP Analysis for: %s\n", filename);
    printf("==========================================\n\n");

    OOFeature features[] = {
        {"RTTI (Run-Time Type Information)", "Indicates dynamic type casting and type identification", indicators->has_rtti},
        {"Virtual Tables (vtables)", "Used for virtual function dispatch in polymorphic classes", indicators->has_vtables},
        {"C++ Imports", "Usage of C++ runtime functions and classes", indicators->has_cpp_imports},
        {"Exception Handling", "C++ try/catch mechanisms for error handling", indicators->has_exceptions},
        {"Templates", "Generic programming with parameterized types", indicators->has_templates},
        {"Inheritance", "Class hierarchy and derived classes", indicators->has_inheritance},
        {"Polymorphism", "Runtime polymorphism through virtual functions", indicators->has_polymorphism},
        {"Encapsulation", "Data hiding with access modifiers", indicators->has_encapsulation},
        {"Abstraction", "Abstract classes and interfaces", indicators->has_abstraction},
        {"Namespaces", "Code organization with named scopes", indicators->has_namespace},
        {"Class Definitions", "User-defined types with methods and data", indicators->has_classes},
        {"Virtual Destructors", "Proper cleanup in class hierarchies", indicators->has_virtual_destructor}
    };

    int feature_count = sizeof(features) / sizeof(features[0]);
    int detected_count = 0;

    for (int i = 0; i < feature_count; i++) {
        printf("  %-35s %s\n", features[i].name, features[i].detected ? "[DETECTED]" : "[NOT DETECTED]");
        if (features[i].detected) detected_count++;
    }

    printf("\n==========================================\n");
    printf("Summary:\n");
    printf("  OOP Features Detected: %d/%d\n", detected_count, feature_count);

    if (detected_count >= 5) {
        printf("  Verdict: HIGH OOP Usage\n");
    } else if (detected_count >= 3) {
        printf("  Verdict: MODERATE OOP Usage\n");
    } else if (detected_count >= 1) {
        printf("  Verdict: LOW OOP Usage\n");
    } else {
        printf("  Verdict: NO OOP Usage Detected\n");
    }

    printf("\nNote: This analysis is heuristic-based and may not be 100%% accurate.\n");
    printf("      The tool uses pattern matching to detect OOP indicators.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0) {
        print_help();
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }

    if (strcmp(argv[1], "-t") == 0) {
        if (argc < 3) {
            printf("Error: No file specified for -t option\n");
            printf("Usage: oop_analyst -t <file>\n");
            return 1;
        }

        print_banner();
        
        OOPIndicators indicators = {0};
        
        #ifdef _WIN32
        if (analyze_pe_file(argv[2], &indicators) != 0) {
            return 1;
        }
        #else
        if (analyze_elf_file(argv[2], &indicators) != 0) {
            return 1;
        }
        #endif
        
        detect_oop_patterns(argv[2], &indicators);
        print_analysis_results(argv[2], &indicators);
        
        return 0;
    }

    if (strcmp(argv[1], "-i") == 0) {
        if (argc < 3) {
            printf("Error: No file specified for -i option\n");
            printf("Usage: oop_analyst -i <file>\n");
            return 1;
        }

        print_banner();
        show_file_info(argv[2]);
        return 0;
    }

    printf("Error: Unknown option '%s'\n", argv[1]);
    printf("Use 'oop_analyst --help' for usage information.\n");
    return 1;
}
