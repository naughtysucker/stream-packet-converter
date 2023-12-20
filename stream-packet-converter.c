#include "stream-packet-converter.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum stream_packet_converter_exception_t stream_packet_converter_init(struct stream_packet_converter_t *instance, void *header, size_t header_size, void *escape, size_t escape_size, void *tailer, size_t tailer_size, void *pack_buffer, size_t pack_buffer_size, void *unpack_buffer, size_t unpack_buffer_size)
{
    instance->header = header;
    instance->header_size = header_size;
    instance->escape = escape;
    instance->escape_size = escape_size;
    instance->tailer = tailer;
    instance->tailer_size = tailer_size;
    instance->pack_buffer = pack_buffer;
    instance->pack_buffer_size = pack_buffer_size;
    instance->unpack_buffer = unpack_buffer;
    instance->unpack_buffer_size = unpack_buffer_size;

    instance->header_match_cursor = 0;
    instance->escape_match_cursor = 0;
    instance->tailer_match_cursor = 0;

    instance->if_in_escape = stream_packet_converter_not_in_escape;
    instance->if_in_packet = stream_packet_converter_not_in_packet;

    return stream_packet_converter_exception_everything_is_ok;
}

enum find_pattern_result_t
{
    find_pattern_none,
    find_pattern_one,
};

static enum find_pattern_result_t find_pattern(struct stream_packet_converter_t *instance, void *data, size_t data_size, size_t *found_pos_begin, size_t *found_pos_end)
{
    enum find_pattern_result_t result = find_pattern_none;

    size_t header_match_cursor = 0;
    size_t escape_match_cursor = 0;
    size_t tailer_match_cursor = 0;

    byte_t *bytes = (byte_t*)data;
    byte_t *header = (byte_t*)instance->header;
    size_t header_size = instance->header_size;
    byte_t *escape = (byte_t*)instance->escape;
    size_t escape_size = instance->escape_size;
    byte_t *tailer = (byte_t*)instance->tailer;
    size_t tailer_size = instance->tailer_size;

    size_t header_begin_pos = 0;
    size_t escape_begin_pos = 0;
    size_t tailer_begin_pos = 0;

    for (size_t i = 0; i < data_size; i++)
    {
        byte_t byte = bytes[i];
        if (byte == header[header_match_cursor])
        {
            header_match_cursor++;
        }
        else if (byte == header[0])
        {
            header_match_cursor = 1;
        }
        else
        {
            header_match_cursor = 0;
        }
        if (header_match_cursor == 1)
        {
            header_begin_pos = i;
        }

        if (byte == escape[escape_match_cursor])
        {
            escape_match_cursor++;
        }
        else if (byte == escape[0])
        {
            escape_match_cursor = 1;
        }
        else
        {
            escape_match_cursor = 0;
        }
        if (escape_match_cursor == 1)
        {
            escape_begin_pos = i;
        }

        if (byte == tailer[tailer_match_cursor])
        {
            tailer_match_cursor++;
        }
        else if (byte == tailer[0])
        {
            tailer_match_cursor = 1;
        }
        else
        {
            tailer_match_cursor = 0;
        }
        if (tailer_match_cursor == 1)
        {
            tailer_begin_pos = i;
        }

        if (header_match_cursor == header_size)
        {
            result = find_pattern_one;
            *found_pos_begin = header_begin_pos;
            *found_pos_end = i + 1;
            break;
        }

        if (escape_match_cursor == escape_size)
        {
            result = find_pattern_one;
            *found_pos_begin = escape_begin_pos;
            *found_pos_end = i + 1;
            break;
        }

        if (tailer_match_cursor == tailer_size)
        {
            result = find_pattern_one;
            *found_pos_begin = tailer_begin_pos;
            *found_pos_end = i + 1;
            break;
        }
    }
func_end:
    return result;
}

enum stream_packet_converter_exception_t stream_packet_converter_pack(struct stream_packet_converter_t *instance, void *data, size_t data_size)
{
    enum stream_packet_converter_exception_t result = stream_packet_converter_exception_everything_is_ok;
    
    enum find_pattern_result_t find_result;
    size_t found_pos_begin = 0;
    size_t found_pos_end = 0;
    size_t buffer_filled_pos = 0;
    size_t previous_pos_end = 0;

    memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, instance->header, instance->header_size);
    buffer_filled_pos += instance->header_size;

    do
    {
        find_result = find_pattern(instance, (byte_t *)data + previous_pos_end, data_size - previous_pos_end, &found_pos_begin, &found_pos_end);
        if (find_result == find_pattern_one)
        {
            size_t copy_size = found_pos_begin;
            if (buffer_filled_pos + copy_size > instance->pack_buffer_size)
            {
                result = stream_packet_converter_exception_memory_run_out;
                goto func_end;
            }
            memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, (byte_t *)data + previous_pos_end, copy_size);
            buffer_filled_pos += copy_size;

            if (buffer_filled_pos + instance->escape_size > instance->pack_buffer_size)
            {
                result = stream_packet_converter_exception_memory_run_out;
                goto func_end;
            }
            memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, instance->escape, instance->escape_size);
            buffer_filled_pos += instance->escape_size;

            copy_size = found_pos_end - found_pos_begin;
            if (buffer_filled_pos + copy_size > instance->pack_buffer_size)
            {
                result = stream_packet_converter_exception_memory_run_out;
                goto func_end;
            }
            memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, (byte_t *)data + previous_pos_end + found_pos_begin, copy_size);
            buffer_filled_pos += copy_size;

            previous_pos_end += found_pos_end;
        }
        else
        {
            size_t copy_size = data_size - previous_pos_end;
            if (buffer_filled_pos + copy_size > instance->pack_buffer_size)
            {
                result = stream_packet_converter_exception_memory_run_out;
                goto func_end;
            }
            memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, (byte_t *)data + previous_pos_end, copy_size);
            buffer_filled_pos += copy_size;
        }
    } while (find_result == find_pattern_one);
    
    if (buffer_filled_pos + instance->tailer_size > instance->pack_buffer_size)
    {
        result = stream_packet_converter_exception_memory_run_out;
            goto func_end;
    }
    memcpy((byte_t *)instance->pack_buffer + buffer_filled_pos, instance->tailer, instance->tailer_size);
    buffer_filled_pos += instance->tailer_size;

    instance->pack_data_size = buffer_filled_pos;

func_end:
    return result;
}

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

enum stream_packet_converter_exception_t stream_packet_converter_unpack(struct stream_packet_converter_t *instance, stream_packet_converter_get_stream_byte_func get_byte_func, void *data)
{
    enum stream_packet_converter_exception_t exception = stream_packet_converter_exception_everything_is_ok;

    byte_t byte;

    byte_t *header = (byte_t*)instance->header;
    byte_t *escape = (byte_t*)instance->escape;
    byte_t *tailer = (byte_t*)instance->tailer;
    while (get_byte_func(data, &byte) == stream_packet_converter_get_byte_result_one)
    {
        instance->event_packet = stream_packet_converter_event_idle_packet;
        instance->event_escape = stream_packet_converter_event_idle_escape_mode;

#ifdef _DEBUG
        printf("byte: %c\n", byte);
#endif
        if (byte == header[instance->header_match_cursor])
        {
            instance->header_match_cursor++;
        }
        else if (byte == header[0])
        {
            instance->header_match_cursor = 1;
        }
        else
        {
            instance->header_match_cursor = 0;
        }

        if (instance->if_in_packet == stream_packet_converter_in_packet)
        {
            if (byte == escape[instance->escape_match_cursor])
            {
                instance->escape_match_cursor++;
            }
            else if (byte == escape[0])
            {
                instance->escape_match_cursor = 1;
            }
            else
            {
                instance->escape_match_cursor = 0;
            }

            if (byte == tailer[instance->tailer_match_cursor])
            {
                instance->tailer_match_cursor++;
            }
            else if (byte == tailer[0])
            {
                instance->tailer_match_cursor = 1;
            }
            else
            {
                instance->tailer_match_cursor = 0;
            }
        }

        size_t max_previous_match_cursor = max(max(instance->previous_header_match_cursor, instance->previous_escape_match_cursor), instance->previous_tailer_match_cursor);
        size_t max_match_cursor = max(max(instance->header_match_cursor, instance->escape_match_cursor), instance->tailer_match_cursor);

        if (instance->if_in_escape == stream_packet_converter_in_escape)
        {
            instance->current_escape_content_cursor++;
            if (instance->current_escape_content_cursor == max_match_cursor)
            {
            }
            else
            {
                // Packet Error
                instance->event_packet = stream_packet_converter_event_abort_packet;
            }
        }
        else if (instance->if_in_packet == stream_packet_converter_in_packet)
        {
            if (max_match_cursor < 2)
            {
                if (instance->previous_header_match_cursor == max_previous_match_cursor)
                {
                    if (instance->unpack_data_cursor + instance->previous_header_match_cursor > instance->unpack_buffer_size)
                    {
                        exception = stream_packet_converter_exception_memory_run_out;
                        goto func_end;
                    }
                    memcpy((byte_t *)instance->unpack_buffer + instance->unpack_data_cursor, header, instance->previous_header_match_cursor);
                    instance->unpack_data_cursor += instance->previous_header_match_cursor;
                }
                else if (instance->previous_escape_match_cursor == max_previous_match_cursor)
                {
                    if (instance->unpack_data_cursor + instance->previous_escape_match_cursor > instance->unpack_buffer_size)
                    {
                        exception = stream_packet_converter_exception_memory_run_out;
                        goto func_end;
                    }
                    memcpy((byte_t *)instance->unpack_buffer + instance->unpack_data_cursor, escape, instance->previous_escape_match_cursor);
                    instance->unpack_data_cursor += instance->previous_escape_match_cursor;
                }
                else if (instance->previous_tailer_match_cursor == max_previous_match_cursor)
                {
                    if (instance->unpack_data_cursor + instance->previous_tailer_match_cursor > instance->unpack_buffer_size)
                    {
                        exception = stream_packet_converter_exception_memory_run_out;
                        goto func_end;
                    }
                    memcpy((byte_t *)instance->unpack_buffer + instance->unpack_data_cursor, tailer, instance->previous_tailer_match_cursor);
                    instance->unpack_data_cursor += instance->previous_tailer_match_cursor;
                }
            }
            if (max_match_cursor == 0)
            {
                if (instance->unpack_data_cursor + 1 > instance->unpack_buffer_size)
                {
                    exception = stream_packet_converter_exception_memory_run_out;
                    goto func_end;
                }
                ((byte_t*)instance->unpack_buffer)[instance->unpack_data_cursor] = byte;
                instance->unpack_data_cursor++;
            }
        }

        instance->previous_header_match_cursor = instance->header_match_cursor;
        instance->previous_escape_match_cursor = instance->escape_match_cursor;
        instance->previous_tailer_match_cursor = instance->tailer_match_cursor;

        if (instance->header_match_cursor == instance->header_size)
        {
            if (instance->if_in_escape == stream_packet_converter_in_escape)
            {
                instance->event_escape = stream_packet_converter_event_leave_escape_mode;
            }
            else if (instance->if_in_packet == stream_packet_converter_in_packet)
            {
                // Packet Error
                instance->event_packet = stream_packet_converter_event_reset_packet;
            }
            else
            {
                instance->event_packet = stream_packet_converter_event_enter_packet;
            }
        }
        else if (instance->escape_match_cursor == instance->escape_size)
        {
            if (instance->if_in_escape == stream_packet_converter_in_escape)
            {
                instance->event_escape = stream_packet_converter_event_leave_escape_mode;
            }
            else
            {
                instance->event_escape = stream_packet_converter_event_enter_escape_mode;
            }
        }
        else if (instance->tailer_match_cursor == instance->tailer_size)
        {
            if (instance->if_in_escape == stream_packet_converter_in_escape)
            {
                instance->event_escape = stream_packet_converter_event_leave_escape_mode;
            }
            else
            {
                instance->event_packet = stream_packet_converter_event_leave_packet;
            }
        }

        // Event Handler
        if (instance->event_packet == stream_packet_converter_event_enter_packet)
        {
            instance->unpack_data_cursor = 0;
            instance->if_in_packet = stream_packet_converter_in_packet;
            instance->if_in_escape = stream_packet_converter_not_in_escape;

            instance->previous_header_match_cursor = 0;
            instance->previous_escape_match_cursor = 0;
            instance->previous_tailer_match_cursor = 0;
            instance->header_match_cursor = 0;
            instance->escape_match_cursor = 0;
            instance->tailer_match_cursor = 0;
        }
        else if (instance->event_packet == stream_packet_converter_event_leave_packet)
        {
            instance->unpack_data_size = instance->unpack_data_cursor;
            instance->if_in_packet = stream_packet_converter_not_in_packet;
            exception = stream_packet_converter_exception_get_one_packet;

            instance->header_match_cursor = 0;
            instance->escape_match_cursor = 0;
            instance->tailer_match_cursor = 0;

            break;
        }
        else if (instance->event_packet == stream_packet_converter_event_abort_packet)
        {
            instance->if_in_escape = stream_packet_converter_not_in_escape;
            instance->if_in_packet = stream_packet_converter_not_in_packet;
        }
        else if (instance->event_packet == stream_packet_converter_event_reset_packet)
        {
            instance->unpack_data_cursor = 0;
            instance->previous_header_match_cursor = 0;
            instance->previous_escape_match_cursor = 0;
            instance->previous_tailer_match_cursor = 0;
            instance->header_match_cursor = 0;
            instance->escape_match_cursor = 0;
            instance->tailer_match_cursor = 0;
        }
        else if (instance->event_escape == stream_packet_converter_event_enter_escape_mode)
        {
            instance->if_in_escape = stream_packet_converter_in_escape;
            instance->current_escape_content_cursor = 0;

            instance->header_match_cursor = 0;
            instance->escape_match_cursor = 0;
            instance->tailer_match_cursor = 0;
        }
        else if (instance->event_escape == stream_packet_converter_event_leave_escape_mode)
        {
            instance->if_in_escape = stream_packet_converter_not_in_escape;

            instance->header_match_cursor = 0;
            instance->escape_match_cursor = 0;
            instance->tailer_match_cursor = 0;
        }
    }

func_end:
    return exception;
}


enum stream_packet_converter_exception_t stream_packet_converter_get_packed_data(struct stream_packet_converter_t *instance, void **data, size_t *data_size)
{
    *data = instance->pack_buffer;
    *data_size = instance->pack_data_size;
    return stream_packet_converter_exception_everything_is_ok;
}

enum stream_packet_converter_exception_t stream_packet_converter_get_unpacked_data(struct stream_packet_converter_t *instance, void **data, size_t *data_size)
{
    *data = instance->unpack_buffer;
    *data_size = instance->unpack_data_size;
    return stream_packet_converter_exception_everything_is_ok;
}

#ifdef __cplusplus
}
#endif