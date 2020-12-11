#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include "cdns.h"

static void usage()
{
    fprintf(stderr, "cdns2line -- a tool for ITHI data extraction\n"
                    "Version 0.2\n"
                    "Usage: cdns2line <options> -[h?] <input-file>\n"
                    "  -? -h              Print this page.\n"
                    "\n output: address,domain,rcode,RD\n"
                    "             rcode   = the RCODE of the response\n"
                    "             RD      = Value of the RD bit.\n");
}

uint8_t MakePrintable(uint8_t c)
{
    switch (c)
    {
        case 'A' ... 'Z':
             return c += 32; // make character lowercase
        case 0 ... 32:
        case 44:
        case 127 ... 255:
             return '?';
        default:
             return c;
     }
}

bool IsAlpha(unsigned c)
{
    return ((c - 97) <= 25 );
}

void ParsePackets(cdns* blob)
{
    for (size_t qr_index = 0; qr_index < blob->block.queries.size(); qr_index++) {
        cdns_query* qr = &blob->block.queries[qr_index];
        cdns_query_signature* sig = NULL;

        if (
            (sig = &blob->block.tables.q_sigs[qr->query_signature_index - blob->index_offset]) == NULL || 
            sig->query_opcode        ||   
            !sig->is_query_present() ||
            !sig->is_response_present() ||
            sig->is_query_present_with_no_question() ) continue;


        uint8_t *name = blob->block.tables.name_rdata[qr->query_name_index - blob->index_offset].v;

        size_t pos = 0, prev_pos = 0, idx = 0;
        uint8_t tld[256] = ".";
        while (name[pos]) { 
           pos += name[prev_pos = pos] + 1;
           for (size_t i= prev_pos + 1; i < pos; i++)
           {
               tld[idx++] = MakePrintable(name[i]);
           }
           tld[idx++] = 46;
        }
        size_t ti = qr->client_address_index - blob->index_offset;
        uint8_t* ip = blob->block.tables.addresses[ti].v;
        if (blob->block.tables.addresses[ti].l == 4)
            printf("%d.%d.%d.0",ip[0],ip[1],ip[2]);
        else
            printf("%02x%02x:%02x%02x:%02x%02x::",ip[0],ip[1],ip[2],ip[3],ip[4],ip[5]);
        printf(",%s,%d,%d,%d\n",
                tld,
                sig->response_rcode,
		blob->block.tables.class_ids[sig->query_classtype_index - blob->index_offset].rr_type,
                (sig->qr_dns_flags & 16) == 16);
    }
}

bool LoadFile(char const* fileName)
{
    cdns blob;
    int err;
    bool ret = blob.open(fileName);
    while (ret)
    {
        if (!blob.open_block(&err))
        {
            ret = err == CBOR_END_OF_ARRAY;
            break;
        }
        ParsePackets(&blob);
    }
    return ret;
}

int main(int argc, char ** argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "h?")) != -1)
    {
        switch (opt)
        {
            case 'h':
            case '?':
                usage();
                exit(1);
                break;
            default:
                fprintf(stderr, "Unsupported option = %c\n", opt);
                usage();
                exit(1);
                break;
        }
    }
    if (optind >= argc)
    {
        fprintf(stderr, "No file to analyze!\n");
        usage();
        exit(1);
    }
    else
    {
        if (!LoadFile((char const*) argv[optind]))
        {
            fprintf(stderr, "Can't process CBOR input file.\n");
            exit(1);
        }
    }
    return 0;
}
