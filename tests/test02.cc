#include <string>
#include <vector>
#include <random>
#include "stream-packet-converter.h"

std::string g_str;

std::vector<std::string> g_data;

extern "C"
{
enum stream_packet_converter_get_byte_result_t get_byte(void *data, byte_t *output)
{
    enum stream_packet_converter_get_byte_result_t res = stream_packet_converter_get_byte_result_none;
    static int32_t i = 0;
    if (i < g_str.size())
    {
        *output = g_str[i];
        i++;
        res = stream_packet_converter_get_byte_result_one;
    }
    return res;
}
}

int main(int argc, char **argv)
{

    struct stream_packet_converter_t ins;

    const char *h = "_H";
    const char *e = "_E";
    const char *t = "_T";

    uint8_t pack_buffer[1024];
    uint8_t unpack_buffer[1024];

    enum stream_packet_converter_exception_t res = stream_packet_converter_init(&ins, (void *)h, strlen(h), (void *)e, strlen(e), (void *)t, strlen(t), (void *)pack_buffer, sizeof(pack_buffer), (void *)unpack_buffer, sizeof(unpack_buffer));
    printf("init: %d\n", res);

    std::vector<std::string> list = 
    {
        h,
        e,
        t,
        "__",
        "_",
        "_T",
        "_E",
        "_H",
        "H",
        "E",
        "T",
        "HH",
        "EE",
        "TT",
        "H_",
        "E_",
        "T_",
    };

    std::vector<std::string> list_no_e = 
    {
        "__",
        "_",
        "_H",
        "H",
        "HH",
        "H_",
        "X",
    };

    std::random_device rd;
    std::default_random_engine re(rd());
    std::uniform_int_distribution<int32_t> urd(0, list.size() - 1);
    std::uniform_int_distribution<int32_t> urd1(0, 256);
    std::uniform_int_distribution<int32_t> urd2(0, list_no_e.size() - 1);

    constexpr int32_t test_count = 1000000;

    for (int32_t i = 0; i < test_count; i++)
    {
        std::string a;
        int32_t len = urd1(re);
        while (1)
        {
            int32_t r = urd(re);
            a += list[r];
            if (a.size() > len)
            {
                break;
            }
        }

        res = stream_packet_converter_pack(&ins, (void *)a.c_str(), a.size());
        printf("Round %d\n", i);
        printf("pack: %d\n", res);
        printf("origin-data: %s\n", a.c_str());
        ((char*)ins.pack_buffer)[ins.pack_data_size] = 0;
        printf("pack-data: %s\n", (const char *)ins.pack_buffer);

        if (res != stream_packet_converter_exception_everything_is_ok)
        {
            printf("Pack Error\n");
            exit(0);
        }

        g_data.push_back(a);
        for (int32_t i = 0; i < ins.pack_data_size; i++)
        {
            g_str += ((const char*)ins.pack_buffer)[i];
        }

        len = urd1(re);
        std::string b;
        while (1)
        {
            int32_t r = urd2(re);
            b += list_no_e[r];
            if (b.size() > len)
            {
                break;
            }
        }
        g_str += b;
    }

    printf("g_str:\n%s\n", g_str.c_str());

    for (int32_t i = 0; i < test_count; i++)
    {
        res = stream_packet_converter_unpack(&ins, get_byte, NULL);
        printf("Round %d\n", i);
        printf("unpack: %d\n", res);
        printf("origin-data: %s\n", g_data[i].c_str());
        ((char *)ins.unpack_buffer)[ins.unpack_data_size] = 0;
        printf("unpack-data: %s\n", (const char *)ins.unpack_buffer);

        int cmp = memcmp(g_data[i].c_str(), ins.unpack_buffer, g_data[i].size());
        if (cmp || g_data[i].size() != ins.unpack_data_size)
        {
            printf("Compare Error\n");
            exit(0);
        }
    }
    printf("Tests Passed\n");
    return 0;
}