#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include "cdns.h"

static void usage() {
    fprintf(stderr, "cdns2sig -- a tool for ITHI data extraction\n"
                    "Version 0.2\n"
                    "Usage: cdns2sig <options> -[h?] <input-file>\n"
                    "  -? -h              Print this page.\n"
                    "\n output: address,hopcnt,hoplimit,tld,AGBfail,subs,rcode,RD\n"
                    "             AGBfail = string fails Applicant Guidebook Rules\n"
                    "             subs    = this TLD had subdomains\n"
                    "             rcode   = the RCODE of the response\n"
                    "             RD      = Value of the RD bit.\n");
}

void ParsePackets(cdns* blob) {
    int offset = blob->index_offset;
// loop through all of the query-response data items
    for (size_t qr_index = offset; qr_index < blob->block.queries.size() + offset; qr_index++) {

// get the query-response data item.
        cdns_query* qr = &blob->block.queries[qr_index]; 

// get the query-response signature.
        cdns_query_signature* sig = NULL; 

        if (
            (sig = &blob->block.tables.q_sigs[qr->query_signature_index - offset]) == NULL || // the index must point to an existing sig
            sig->query_opcode ||   // the opcode of the query must be 0 (QUERY)
            !sig->is_query_present() ||
 	    !sig->is_response_present() ||
            sig->is_query_present_with_no_question() ) continue;  


// get the query name
        size_t ti     = qr->query_name_index - offset;
        size_t l      = blob->block.tables.name_rdata[ti].l;
        uint8_t *name = blob->block.tables.name_rdata[ti].v;
           
// find top level label
        size_t pos = 0;
        size_t prev_pos = 0;
        while (name[pos]) pos += name[prev_pos = pos] + 1;

// parse the top level label        
        bool AGBfail=false;
        uint8_t tld[64] = "."; // maximum label length is 63, plus the \0 to terminate the string.
        size_t idx = 0;
        for (size_t i = prev_pos + 1; i < pos; i++) {
            uint8_t c=name[i];
            if ('A' <= c && c <= 'Z') c |= 32; // make character lowercase
            else if (c < 33 || c  == ',' || c > 126) c = '?'; // make unprintables and comma printable
            AGBfail |= c < 'a' || c > 'z';
            tld[idx++] = c;
	}
             
        AGBfail |= pos - prev_pos < 4;
            
        ti = qr->client_address_index - offset;
        l = blob->block.tables.addresses[ti].l;
        uint8_t* ip = blob->block.tables.addresses[ti].v;

        if (l == 4) 
            printf("%d.%d.%d.0",
                   ip[0],ip[1],ip[2]);
        else 
            printf("%02x%02x:%02x%02x:%02x%02x::",
                    ip[0],ip[1],ip[2],ip[3],ip[4],ip[5]);

        uint8_t hops = qr->client_hoplimit;
        printf(",%d,%d,%s,%d,%d,%d,%d\n",
                32-(hops&31), 
                hops, 
                tld, 
                AGBfail, 
                prev_pos != 0, 
                sig->response_rcode, 
                (sig->qr_dns_flags & 16) == 16);
    }
}

bool LoadFile(char const* fileName) {
    cdns blob;
    int err;
    bool ret = blob.open(fileName); 
    while (ret) {
        if (!blob.open_block(&err)) {
            ret = err == CBOR_END_OF_ARRAY;
            break;
        }
        ParsePackets(&blob);
    }
    return ret;
}

int main(int argc, char ** argv) {   
    int opt;
    while ((opt = getopt(argc, argv, "h?")) != -1) {   
        switch (opt) {
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
    if (optind >= argc) {   
        fprintf(stderr, "No file to analyze!\n");
        usage();
        exit(1);
    }
    else {  
        if (!LoadFile((char const*) argv[optind])) {
            fprintf(stderr, "Can't process CBOR input file.\n");
            exit(1);
        }
    }
    return 0;
}
