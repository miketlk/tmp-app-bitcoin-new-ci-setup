#pragma once

void debug_write(const char *buf);
void debug_write_hex(unsigned int word, unsigned int bytes);
void debug_write_dec(unsigned int word);

int semihosted_printf(const char *format, ...);

void print_stack_pointer(const char *file, int line, const char *func_name);
void print_hash(const char *msg, const void *sha256_context);
void print_hex(const char *msg, const void *buf, unsigned int len);

// Helper macro
#ifdef HAVE_PRINT_STACK_POINTER
#define PRINT_STACK_POINTER() print_stack_pointer(__FILE__, __LINE__, __func__)
#else
#define PRINT_STACK_POINTER()
#endif

#ifdef HAVE_PRINTF
#define PRINT_HASH(msg, sha256_context) print_hash(msg, sha256_context)
#define PRINT_HEX(msg, buf, len) print_hex(msg, buf, len)
#else
#define PRINT_HASH(msg, sha256_context)
#define PRINT_HEX(msg, buf, len)
#endif // HAVE_PRINTF