#include "stream-packet-converter.h"

#include <stdio.h>
#include <string.h>

char *str = NULL;
enum stream_packet_converter_get_byte_result_t get_byte(void *data, byte_t *output)
{
    static int a = 0;

    if (a < strlen(str))
    {
        *output = str[a];
        a++;
        return stream_packet_converter_get_byte_result_one;
    }
    return stream_packet_converter_get_byte_result_none;
}

int main(int argc, char **argv)
{
    struct stream_packet_converter_t ins;

    char *h = "_H_";
    char *e = "_E_";
    char *t = "_T_";

    uint8_t pack_buffer[1024];
    uint8_t unpack_buffer[1024];

    char *a = "Hello_H_E_E_T_";
    // char *a = "Hello_H_EEE__T_World";

    enum stream_packet_converter_exception_t res = stream_packet_converter_init(&ins, h, strlen(h), e, strlen(e), t, strlen(t), pack_buffer, sizeof(pack_buffer), unpack_buffer, sizeof(unpack_buffer));
    printf("init: %d\n", res);

    res = stream_packet_converter_pack(&ins, a, strlen(a));
    printf("pack: %d\n", res);
    printf("pack-data: %s\n", ins.pack_buffer);
    str = ins.pack_buffer;

    res = stream_packet_converter_unpack(&ins, get_byte, NULL);
    printf("unpack: %d\n", res);
    printf("origin-data: %s\n", a);
    printf("unpack-data: %s\n", ins.unpack_buffer);

    return 0;
}