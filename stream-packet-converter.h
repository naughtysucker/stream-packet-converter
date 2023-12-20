#include "stream-packet-converter-config.h"

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

enum stream_packet_converter_match_t
{
    stream_packet_converter_match_none,
    stream_packet_converter_match_header,
    stream_packet_converter_match_escape,
    stream_packet_converter_match_tailer,
};

enum stream_packet_converter_escape_mode_t
{
    stream_packet_converter_not_in_escape,
    stream_packet_converter_in_escape,
};

enum stream_packet_converter_packet_mode_t
{
    stream_packet_converter_not_in_packet,
    stream_packet_converter_in_packet,
};

enum stream_packet_converter_escape_event_t
{
    stream_packet_converter_event_idle_escape_mode,
    stream_packet_converter_event_enter_escape_mode,
    stream_packet_converter_event_leave_escape_mode,
};

enum stream_packet_converter_packet_event_t
{
    stream_packet_converter_event_idle_packet,
    stream_packet_converter_event_enter_packet,
    stream_packet_converter_event_leave_packet,
    stream_packet_converter_event_reset_packet,
    stream_packet_converter_event_abort_packet,
};

enum stream_packet_converter_exception_t
{
    stream_packet_converter_exception_everything_is_ok,
    stream_packet_converter_exception_out_of_range,
    stream_packet_converter_exception_memory_run_out,
    stream_packet_converter_exception_get_one_packet,
};

enum stream_packet_converter_get_byte_result_t
{
    stream_packet_converter_get_byte_result_none,
    stream_packet_converter_get_byte_result_one,
};

// implement
typedef enum stream_packet_converter_get_byte_result_t (*stream_packet_converter_get_stream_byte_func)(void *data, byte_t *output);

struct stream_packet_converter_t
{
// definitions
    void *header;
    size_t header_size;
    void *escape;
    size_t escape_size;
    void *tailer;
    size_t tailer_size;

// memory
    void *pack_buffer;
    size_t pack_buffer_size;
    size_t pack_data_size;
    void *unpack_buffer;
    size_t unpack_buffer_size;
    size_t unpack_data_size;

// states
    size_t header_match_cursor;
    size_t escape_match_cursor;
    size_t tailer_match_cursor;

    size_t previous_header_match_cursor;
    size_t previous_escape_match_cursor;
    size_t previous_tailer_match_cursor;
    
    size_t current_escape_content_cursor;

    size_t unpack_data_cursor;

    enum stream_packet_converter_escape_mode_t if_in_escape;
    enum stream_packet_converter_packet_mode_t if_in_packet;

// events
    enum stream_packet_converter_escape_event_t event_escape;
    enum stream_packet_converter_packet_event_t event_packet;
};

extern enum stream_packet_converter_exception_t stream_packet_converter_init(struct stream_packet_converter_t *instance, void *header, size_t header_size, void *escape, size_t escape_size, void *tailer, size_t tailer_size, void *pack_buffer, size_t pack_buffer_size, void *unpack_buffer, size_t unpack_buffer_size);

extern enum stream_packet_converter_exception_t stream_packet_converter_pack(struct stream_packet_converter_t *instance, void *data, size_t data_size);
extern enum stream_packet_converter_exception_t stream_packet_converter_get_packed_data(struct stream_packet_converter_t *instance, void **data, size_t *data_size);

extern enum stream_packet_converter_exception_t stream_packet_converter_unpack(struct stream_packet_converter_t *instance, stream_packet_converter_get_stream_byte_func func_ptr, void *data);
extern enum stream_packet_converter_exception_t stream_packet_converter_get_unpacked_data(struct stream_packet_converter_t *instance, void **data, size_t *data_size);

#ifdef __cplusplus
}
#endif
