#pragma once

#include "os.h"

#include "apdu_parser.h"

#include "common/buffer.h"

// Forward declaration
struct dispatcher_context_s;
typedef struct dispatcher_context_s dispatcher_context_t;

typedef void (*command_handler_t)(dispatcher_context_t *, uint8_t p2);

/**
 * TODO: docs
 */
struct dispatcher_context_s {
    buffer_t read_buffer;

    void (*set_ui_dirty)(void);
    void (*add_to_response)(const void *rdata, size_t rdata_len);
    void (*finalize_response)(uint16_t sw);
    void (*send_response)(void);
    int (*process_interruption)(dispatcher_context_t *dispatcher_context);
};

static inline void SEND_SW(struct dispatcher_context_s *dc, uint16_t sw) {
    dc->finalize_response(sw);
    dc->send_response();
}

static inline void SET_RESPONSE(struct dispatcher_context_s *dc,
                                void *rdata,
                                size_t rdata_len,
                                uint16_t sw) {
    dc->add_to_response(rdata, rdata_len);
    dc->finalize_response(sw);
}

static inline void SEND_RESPONSE(struct dispatcher_context_s *dc,
                                 void *rdata,
                                 size_t rdata_len,
                                 uint16_t sw) {
    dc->add_to_response(rdata, rdata_len);
    dc->finalize_response(sw);
    dc->send_response();
}

/**
 * Describes a command that can be processed by the dispatcher.
 */
typedef struct {
    command_handler_t handler;
    uint8_t cla;
    uint8_t ins;
} command_descriptor_t;

/**
 * Dispatch APDU command received to the right handler.
 * @param[in] cmd_descriptors
 *   Array of command descriptors.
 * @param[in] n_descriptors
 *   Length of the command_descriptors array.
 * @param[in] termination_cb
 *   If not NULL, a callback that will be executed once the command handler is done.
 * @param[in] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 */
void apdu_dispatcher(command_descriptor_t const cmd_descriptors[],
                     int n_descriptors,
                     void (*termination_cb)(void),
                     const command_t *cmd);

// Debug utilities

#if defined(HAVE_CCMD_PRINTF) && defined(HAVE_LOG_PROCESSOR)
#define LOG_PROCESSOR(dc) ccmd_printf(dc, "->%s", __func__)
#elif defined(HAVE_LOG_PROCESSOR)

void print_dispatcher_info(const char *file, int line, const char *func);

#define LOG_PROCESSOR() print_dispatcher_info(__FILE__, __LINE__, __func__)
#else
#define LOG_PROCESSOR()
#endif

#ifdef HAVE_CCMD_PRINTF
extern int ccmd_printf(dispatcher_context_t *dc, const char *format, ...);
#define CCMD_PRINTF ccmd_printf
#else
#define CCMD_PRINTF(...)
#endif

#ifdef HAVE_APDU_LOG
extern void log_apdu(const command_t *cmd);
#define LOG_APDU(cmd) log_apdu(cmd)
#else
#define LOG_APDU(cmd)
#endif
