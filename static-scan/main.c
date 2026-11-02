#include <windows.h> // Windows API and PE-realted structures
#include <stdio.h>
#include <stdlib.h>  // memory allocation functions
#include <string.h>  // string manipulation functions

// convert RVA (Relative Virtual Address) to file offset using section table
DWORD rva_to_offset(
    IMAGE_SECTION_HEADER* sections, // pointer to section table
    int num_sections,               // number of sections in the table
    DWORD rva                       // RVA to convert
){
    for (int i = 0; i < num_sections; i++) {
        IMAGE_SECTION_HEADER* section = &sections[i];
        DWORD section_start = section->VirtualAddress;
        DWORD section_end = section_start + section->Misc.VirtualSize;

        if (rva >= section_start && rva < section_end) {
            return rva - section_start + section->PointerToRawData;
        }
    }
    return 0; // RVA not found in any section
}

// extract folder form full path
void get_dir(const char* path, char* out, size_t out_size) {
    strncpy(out, path, out_size);
    char* last_slash = strrchr(out, '\\');
    if (!last_slash) {
        last_slash = strrchr(out, '/');
    }
    if (last_slash) {
        *(last_slash + 1) = '\0'; // terminate string at last slash
    } else {
        out[0] = '\0'; // no directory found, return empty string
    }
}

void scan(const char* file_path) {
    printf("Scanning file: %s\n", file_path);
    
    // Open the file in binary mode
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s\n", file_path);
        return;
    }

    // Read the DOS header
    IMAGE_DOS_HEADER dos_header;
    fread(&dos_header, sizeof(IMAGE_DOS_HEADER), 1, file);
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Error: Invalid DOS signature in %s\n", file_path);
        fclose(file);
        return;
    }

    // Move to the PE header
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read the PE header
    IMAGE_NT_HEADERS nt_headers;
    fread(&nt_headers, sizeof(IMAGE_NT_HEADERS), 1, file);
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Error: Invalid PE signature in %s\n", file_path);
        fclose(file);
        return;
    }

    // Read the section headers
    IMAGE_SECTION_HEADER* sections = malloc(nt_headers.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    fread(sections, sizeof(IMAGE_SECTION_HEADER), nt_headers.FileHeader.NumberOfSections, file);

    // Scan for DLL hijacking vulnerabilities (placeholder for actual scanning logic)
    printf("Scanning %s for DLL hijacking vulnerabilities...\n", file_path);

    // Clean up
    free(sections);
    fclose(file);
}
